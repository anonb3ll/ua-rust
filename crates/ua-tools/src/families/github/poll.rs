//! Polling fallback for hubs GitHub cannot reach with a webhook.
//!
//! Every `github_poll_interval_s` seconds (0, the default, is off) `ua serve`
//! lists each bound repository's open pull requests
//! (`GET /repos/{repo}/pulls?state=open&per_page=100`) with the ETag from the
//! previous poll, so an unchanged list is a 304 that costs no rate limit.
//! On a changed list:
//!
//! - a pull request that left the open list is looked up; when it merged,
//!   the close-on-merge rules run for it,
//! - an open pull request with a new head has the checks recorded at that
//!   head re-verified.
//!
//! Only the first page (100 newest open PRs) is compared; a PR older than
//! the page's oldest is never taken for closed. The list, its ETag, the poll
//! time and the last failure (a fixed code such as `unauthorized`,
//! `rate_limited`, `network`, `decode` or `http_<status>`: never library
//! error text, a URL or a value) are kept
//! per organization and repository in `github_poll_repos`. A poll that
//! changes something appends `agent.github.polled`.
//!
//! **Per organization.** Each pass polls every organization that has a
//! GitHub token ([`credentials::orgs_holding`], then
//! [`credentials::github_credential_for`]): the default organization with
//! the hub configuration's token, another with its own managed secret. Each
//! organization's bound repositories are polled with its own token, and its
//! effects (re-verification, close-on-merge) touch only its own tasks. An
//! organization without a token is skipped (no fallback to any other
//! token), and one whose stored token is unusable is reported `unusable`
//! and skipped. One organization's failure (a refused token, a rate limit,
//! a database error) is recorded for that organization and never stops the
//! others; `system_doctor` counts repositories whose last poll failed,
//! among those still bound in an organization that still holds a usable
//! token. A rate limit blocks only the organization whose token hit it;
//! setting or clearing that organization's token lifts the block.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use ua_core::UaResult;

use super::client::{BoundRepo, GhError, GitHub, Got, full_sha};
use super::credentials::{self, CredentialKind};
use super::{GITHUB_ACTOR, github_caller_for, reverify_head};
use crate::Hub;
use crate::families::continuity::merged::{close_merged, merged_from_api};
use crate::families::tasks::{emit, ledger_text};

const PAGE: usize = 100;

type OpenPrs = BTreeMap<u64, String>;

/// Poll every organization's bound repositories once, each with its own
/// token. `Ok` with a per-organization report (`polled`, `skipped`,
/// `unusable` or `failed`) and, for backward compatibility, every polled
/// repository's report in `repos`; `skipped` at the top when no
/// organization has a token.
pub async fn poll_once(hub: &Hub) -> UaResult<Value> {
    let cfg = hub.cfg().clone();
    // Every organization that may hold a token, each resolved to its own
    // client (or why it has none). Built per organization: no client holds
    // another organization's token.
    let plan: Vec<(String, Result<Option<GitHub>, GhError>)> = hub
        .db()
        .read_async(move |c| {
            let mut out = Vec::new();
            for org in credentials::orgs_holding(c, CredentialKind::Token)? {
                let gh = GitHub::for_org(c, &cfg, &org);
                out.push((org, gh));
            }
            Ok(out)
        })
        .await?;
    let mut orgs = Vec::new();
    let mut all_repos = Vec::new();
    let mut any = false;
    for (org, gh) in plan {
        let gh = match gh {
            Ok(Some(gh)) => gh,
            Ok(None) => {
                orgs.push(json!({ "org_id": org, "state": "skipped", "reason": "no GitHub token" }));
                continue;
            }
            Err(e) => {
                let state = if matches!(e, GhError::Unusable(_)) { "unusable" } else { "skipped" };
                orgs.push(json!({ "org_id": org, "state": state, "reason": e.detail() }));
                continue;
            }
        };
        any = true;
        // One organization's failure is its own: recorded and reported, and
        // the next organization is polled regardless.
        match poll_org(hub, &gh).await {
            Ok(repos) => {
                all_repos.extend(repos.iter().cloned());
                orgs.push(json!({ "org_id": org, "state": "polled", "repos": repos }));
            }
            Err(e) => {
                tracing::warn!(org = %org, code = e.code(), "GitHub poll of an organization failed");
                orgs.push(json!({ "org_id": org, "state": "failed", "reason": e.code() }));
            }
        }
    }
    if !any {
        return Ok(json!({ "skipped": "no GitHub token configured", "orgs": orgs }));
    }
    Ok(json!({ "orgs": orgs, "repos": all_repos }))
}

/// Poll every repository `gh`'s organization binds.
async fn poll_org(hub: &Hub, gh: &GitHub) -> UaResult<Vec<Value>> {
    let org = gh.org().to_string();
    let repos = hub.db().read_async(move |c| BoundRepo::all(c, &org)).await?;
    let mut reports = Vec::new();
    for repo in repos {
        reports.push(poll_repo(hub, gh, &repo).await?);
    }
    Ok(reports)
}

async fn poll_repo(hub: &Hub, gh: &GitHub, repo: &BoundRepo) -> UaResult<Value> {
    let org = gh.org().to_string();
    let name = repo.as_str().to_string();
    let (o2, n2) = (org.clone(), name.clone());
    let state: Option<(Option<String>, String)> = hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row(
                "SELECT etag, open_json FROM github_poll_repos WHERE org_id = ?1 AND repo = ?2",
                [&o2, &n2],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok())
        })
        .await?;
    let (etag, before): (Option<String>, Option<OpenPrs>) = match state {
        Some((etag, open)) => (etag, serde_json::from_str(&open).ok()),
        None => (None, None),
    };
    let got = gh.get(repo, &format!("pulls?state=open&per_page={PAGE}"), etag.as_deref()).await;
    let now = ua_core::time::now();
    let (new_etag, list) = match got {
        Ok(Got::NotModified) => {
            let (o, n, t) = (org.clone(), name.clone(), now.clone());
            hub.db()
                .write_async(move |tx| {
                    tx.execute(
                        "UPDATE github_poll_repos SET polled_at = ?3, last_error = NULL \
                         WHERE org_id = ?1 AND repo = ?2",
                        [&o, &n, &t],
                    )?;
                    Ok(())
                })
                .await?;
            return Ok(json!({ "repo": name, "not_modified": true }));
        }
        Ok(Got::Fresh { etag, body }) => (etag, body.as_array().cloned().unwrap_or_default()),
        Err(e) => {
            // Recorded for the doctor: a fixed code, never library text or
            // a value. A repository never listed keeps no open list
            // (`null`), so its first successful poll re-verifies nothing, as
            // before.
            let (o, n, t, why) = (org.clone(), name.clone(), now.clone(), e.code());
            hub.db()
                .write_async(move |tx| {
                    tx.execute(
                        "INSERT INTO github_poll_repos (org_id, repo, open_json, polled_at, last_error) \
                         VALUES (?1, ?2, 'null', ?3, ?4) \
                         ON CONFLICT (org_id, repo) DO UPDATE SET polled_at = excluded.polled_at, \
                         last_error = excluded.last_error",
                        [&o, &n, &t, &why],
                    )?;
                    Ok(())
                })
                .await?;
            return Ok(json!({ "repo": name, "error": e.detail() }));
        }
    };
    let full = list.len() >= PAGE;
    let now_open: OpenPrs = list
        .iter()
        .filter_map(|p| Some((p["number"].as_u64()?, full_sha(p["head"]["sha"].as_str()?)?)))
        .collect();
    let oldest = now_open.keys().next().copied().unwrap_or(0);

    // Heads that are new since the last poll: re-verify what is recorded there.
    let mut reverified = Vec::new();
    if let Some(before) = &before {
        for (number, head) in &now_open {
            if before.get(number) != Some(head) {
                let checks = reverify_head(hub, &org, &name, head, "poll").await?;
                if !checks.is_empty() {
                    reverified.push(json!({ "pr": number, "head_sha": head, "checks": checks }));
                }
            }
        }
    }
    // Pull requests that left the open list: merged ones close their tasks.
    let mut merged = Vec::new();
    let mut lookups = Vec::new();
    if let Some(before) = &before {
        for number in before.keys().filter(|n| !now_open.contains_key(n) && (!full || **n >= oldest)) {
            match gh.get_json(repo, &format!("pulls/{number}")).await {
                Ok(pr) => {
                    if let Some(m) = merged_from_api(&name, &pr) {
                        merged.push(m);
                    }
                }
                Err(e) => lookups.push(json!({ "pr": number, "error": e.detail() })),
            }
        }
    }
    let merged_numbers: Vec<u64> = merged.iter().map(|m| m.number).collect();
    let closure = if merged.is_empty() {
        Value::Null
    } else {
        close_merged(hub, &github_caller_for(&org), merged, false).await?
    };
    let changed = !reverified.is_empty() || !merged_numbers.is_empty();
    let report = json!({
        "repo": name,
        "open": now_open.len(),
        "reverified": reverified,
        "merged": merged_numbers,
        "closure": closure,
        "lookup_errors": lookups,
    });
    let open_json = serde_json::to_string(&now_open).unwrap_or_else(|_| "{}".into());
    // Another organization's event carries counts and numbers, never its
    // repository name or closure text (`ledger_text`).
    let event = if org == ua_core::DEFAULT_ORG {
        let mut e = report.clone();
        e["org_id"] = json!(org);
        e
    } else {
        json!({
            "org_id": org, "repo": ledger_text(&org, &name), "open": now_open.len(),
            "reverified": reverified.len(), "merged": merged_numbers,
            "closed": closure["closed"].as_array().map_or(0, Vec::len),
            "lookup_errors": lookups.len(),
        })
    };
    hub.db()
        .write_async(move |tx| {
            tx.execute(
                "INSERT INTO github_poll_repos (org_id, repo, etag, open_json, polled_at, changed_at, last_error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL) \
                 ON CONFLICT (org_id, repo) DO UPDATE SET etag = excluded.etag, open_json = excluded.open_json, \
                 polled_at = excluded.polled_at, changed_at = excluded.changed_at, last_error = NULL",
                rusqlite::params![org, name, new_etag, open_json, now],
            )?;
            if changed {
                emit(tx, &org, "agent.github.polled", event, GITHUB_ACTOR)?;
            }
            Ok(())
        })
        .await?;
    Ok(report)
}

/// Run [`poll_once`] every `github_poll_interval_s` seconds (0: never), until
/// `ct` is cancelled; a poll in progress finishes first.
pub fn spawn_poller(
    hub: &Hub,
    ct: tokio_util::sync::CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    let every = hub.cfg().github_poll_interval_s;
    if every == 0 {
        return None;
    }
    let hub = hub.clone();
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(every.max(10)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = ct.cancelled() => return,
                _ = tick.tick() => {}
            }
            if let Err(e) = poll_once(&hub).await {
                tracing::warn!(error = %e, "GitHub poll failed");
            }
        }
    }))
}
