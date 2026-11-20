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
//! the page's oldest is never taken for closed. The list, its ETag and the
//! poll time are kept in `github_poll_state`. A poll that changes something
//! appends `agent.github.polled`.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use ua_core::UaResult;

use super::client::{BoundRepo, GitHub, Got, full_sha};
use super::{GITHUB_ACTOR, github_caller, reverify_head};
use crate::Hub;
use crate::families::continuity::merged::{close_merged, merged_from_api};
use crate::families::tasks::emit;

const PAGE: usize = 100;

type OpenPrs = BTreeMap<u64, String>;

/// Poll every bound repository once. `Ok` with a per-repository report;
/// `skipped` when no token is configured.
pub async fn poll_once(hub: &Hub) -> UaResult<Value> {
    let gh = match GitHub::from_config(hub.cfg()) {
        Ok(Some(gh)) => gh,
        Ok(None) => return Ok(json!({ "skipped": "no GitHub token configured" })),
        Err(e) => return Ok(json!({ "skipped": e.detail() })),
    };
    let repos = hub.db().read_async(BoundRepo::all).await?;
    let mut reports = Vec::new();
    for repo in repos {
        reports.push(poll_repo(hub, &gh, &repo).await?);
    }
    Ok(json!({ "repos": reports }))
}

async fn poll_repo(hub: &Hub, gh: &GitHub, repo: &BoundRepo) -> UaResult<Value> {
    let name = repo.as_str().to_string();
    let n2 = name.clone();
    let state: Option<(Option<String>, String)> = hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row("SELECT etag, open_json FROM github_poll_state WHERE repo = ?1", [&n2], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
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
            let (n, t) = (name.clone(), now.clone());
            hub.db()
                .write_async(move |tx| {
                    tx.execute("UPDATE github_poll_state SET polled_at = ?2 WHERE repo = ?1", [&n, &t])?;
                    Ok(())
                })
                .await?;
            return Ok(json!({ "repo": name, "not_modified": true }));
        }
        Ok(Got::Fresh { etag, body }) => (etag, body.as_array().cloned().unwrap_or_default()),
        Err(e) => return Ok(json!({ "repo": name, "error": e.detail() })),
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
                let checks = reverify_head(hub, &name, head, "poll").await?;
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
        close_merged(hub, &github_caller(), merged, false).await?
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
    let event = report.clone();
    hub.db()
        .write_async(move |tx| {
            tx.execute(
                "INSERT INTO github_poll_state (repo, etag, open_json, polled_at, changed_at) VALUES (?1, ?2, ?3, ?4, ?4) \
                 ON CONFLICT (repo) DO UPDATE SET etag = excluded.etag, open_json = excluded.open_json, \
                 polled_at = excluded.polled_at, changed_at = excluded.changed_at",
                rusqlite::params![name, new_etag, open_json, now],
            )?;
            if changed {
                emit(tx, "agent.github.polled", event, GITHUB_ACTOR)?;
            }
            Ok(())
        })
        .await?;
    Ok(report)
}

/// Run [`poll_once`] every `github_poll_interval_s` seconds (0: never).
pub fn spawn_poller(hub: &Hub) -> Option<tokio::task::JoinHandle<()>> {
    let every = hub.cfg().github_poll_interval_s;
    if every == 0 {
        return None;
    }
    let hub = hub.clone();
    Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(every.max(10)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(e) = poll_once(&hub).await {
                tracing::warn!(error = %e, "GitHub poll failed");
            }
        }
    }))
}
