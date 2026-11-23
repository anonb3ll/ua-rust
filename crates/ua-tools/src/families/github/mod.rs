//! The native GitHub connector.
//!
//! - [`client`]: the REST client, pinned to `github_api_url`, bound
//!   repositories only, no redirects, bounded and rate-limit aware.
//! - CI verification: [`crate::ci::GitHubCiVerifier`] looks a check's run up
//!   through the client, so a check can earn `verified`.
//! - [`webhook`]: `POST /api/github/webhook` ingestion. HMAC-SHA256
//!   signature check, replay protection by delivery id and body hash (on
//!   `ua_ingress::inbound`), then effects:
//!   re-verify recorded checks at a completed head, close tasks a merged PR
//!   finishes ([`crate::families::continuity::merged`]).
//! - [`poll`]: the same effects without a public endpoint, polling the bound
//!   repositories' open pull requests with ETags under `ua serve`.
//! - [`credentials`]: each organization's GitHub token and webhook secret
//!   (the default organization's are the hub's configuration, another's
//!   its own managed secrets, never a fallback) and the tools that set,
//!   clear and report them.
//! - [`authz`]: `policy_authorization_record` and `policy_authorization_list`,
//!   a human's standing-policy authorization to merge one exact head, which
//!   `git_merge_task` accepts in place of a one-time approval.
//!
//! Every path runs per organization: a webhook delivery belongs to the
//! organizations whose webhook secret verifies it, the poller polls each
//! organization that has a token with that token, and CI lookups and merged
//! reconciliation use the task's (or caller's) organization's token and
//! bindings. Nothing falls back to another organization's credential.
//!
//! Every effect is a governed registry call (`task_update`,
//! `coordination_manage` `task_check_verify`) made as the hub identity
//! [`GITHUB_ACTOR`] in the organization it acts for ([`github_caller_for`]),
//! and is ledgered on an `agent.github.*` channel. That
//! identity holds a narrow grant the registry enforces before anything else
//! ([`grant_refusal`]): `task_update` closing a task with a merge commit as
//! evidence, and `coordination_manage(action="task_check_verify")`. Nothing
//! else is callable as it, whatever its profile says. See `docs/github.md`.

pub(crate) mod authz;
pub(crate) mod client;
pub mod credentials;
pub mod poll;
pub mod webhook;

#[cfg(test)]
mod org_automation_tests;

use serde_json::{Value, json};
use ua_core::{Caller, UaResult};
use ua_store::{Procedure, SchemaPart};

use crate::Hub;
use crate::families::tasks::{emit, ledger_text};
use crate::registry::Registry;

pub use poll::{poll_once, spawn_poller};
pub use webhook::{WebhookDelivery, WebhookError, receive, signature_for};

/// The identity GitHub-driven effects are recorded under.
pub const GITHUB_ACTOR: &str = "hub-github";
/// Checks one head re-verifies at most per event.
const REVERIFY_CAP: i64 = 50;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "github.v1",
    sql: "
CREATE TABLE IF NOT EXISTS github_deliveries (
    delivery_id TEXT PRIMARY KEY,
    event TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_github_deliveries_received ON github_deliveries(received_at);

CREATE TABLE IF NOT EXISTS github_poll_state (
    repo TEXT PRIMARY KEY,
    etag TEXT,
    open_json TEXT NOT NULL DEFAULT '{}',
    polled_at TEXT NOT NULL,
    changed_at TEXT
);

CREATE TABLE IF NOT EXISTS policy_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    pr INTEGER,
    head_sha TEXT NOT NULL CHECK (length(head_sha) = 40),
    task_id INTEGER NOT NULL,
    policy_ref TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    task_claimant TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','consumed','revoked')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    consumed_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_policy_authorizations_head ON policy_authorizations(repo, head_sha);
CREATE INDEX IF NOT EXISTS idx_policy_authorizations_task ON policy_authorizations(task_id);
",
};

/// `github.inbound.v1.copy`: carries the delivery ids and body hashes in
/// `github_deliveries` and `github_delivery_bodies` into
/// `inbound_deliveries` (source `github`, kinds `delivery_id` and
/// `body_sha256`) as `finished`, keeping their receipt times and the
/// 30-day retention, so a hub upgraded between two copies of one delivery
/// still refuses the second. It must run after `ingress.inbound.v1` and
/// `organization.v1.ingress`. Rows already in the new table are left
/// alone, so it changes nothing when run again. The old tables stay in the
/// schema, unread and unwritten, until a later release retires them.
pub const INBOUND_COPY: Procedure = Procedure {
    name: "github.inbound.v1.copy",
    version: 1,
    standalone: false,
    run: copy_deliveries,
    args: &[],
};

fn copy_deliveries(conn: &rusqlite::Connection, _: &'static [&'static str]) -> anyhow::Result<String> {
    let org = ua_core::DEFAULT_ORG.replace('\'', "''");
    let ttl = webhook::KEEP_DAYS * 86_400;
    let copy = |table: &str, key: &str, kind: &str, detail: &str| {
        format!(
            "INSERT INTO inbound_deliveries \
             (org_id, source, kind, delivery_key, state, received_at, updated_at, expires_at, detail) \
             SELECT '{org}', 'github', '{kind}', k, 'finished', t, t, t + {ttl}, d FROM ( \
               SELECT {key} AS k, {detail} AS d, \
                      COALESCE(unixepoch(received_at), unixepoch('now')) AS t FROM {table}) \
             WHERE length(k) BETWEEN 1 AND 256 \
             ON CONFLICT (org_id, source, kind, delivery_key) DO NOTHING;"
        )
    };
    let sql = [
        copy("github_deliveries", "delivery_id", "delivery_id", "event"),
        copy("github_delivery_bodies", "body_sha256", "body_sha256", "delivery_id"),
    ]
    .join("\n");
    conn.execute_batch(&sql)?;
    Ok(sql)
}

/// Replay protection by body hash, and the policy-authorization fields the
/// merge path and `policy_authorization_revoke` need.
pub const HARDENING_SCHEMA: SchemaPart = SchemaPart {
    name: "github.hardening.v1",
    sql: "
CREATE TABLE IF NOT EXISTS github_delivery_bodies (
    body_sha256 TEXT PRIMARY KEY,
    delivery_id TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_github_delivery_bodies_received ON github_delivery_bodies(received_at);
ALTER TABLE policy_authorizations ADD COLUMN allow_in_flight INTEGER NOT NULL DEFAULT 0;
ALTER TABLE policy_authorizations ADD COLUMN revoked_at TEXT;
ALTER TABLE policy_authorizations ADD COLUMN revoked_by TEXT;
ALTER TABLE policy_authorizations ADD COLUMN revoke_reason TEXT;
",
};

/// `github.v2.poll_repos`: the poller's state per organization and
/// repository (`github_poll_repos`), so a repository two organizations
/// bind is polled for each with its own ETag and open list. Every row of the
/// old, hub-wide `github_poll_state` is copied in under the default
/// organization (the only one that was polled), so nothing is dropped; the
/// old table stays in the schema, unread and unwritten, until a later
/// release retires it. It must run after `organization.v1.store`; the
/// table's organization triggers come from [`POLL_REPOS_TENANT_PART`].
pub const POLL_REPOS_SCHEMA: SchemaPart = SchemaPart {
    name: "github.v2.poll_repos",
    sql: "
CREATE TABLE IF NOT EXISTS github_poll_repos (
    org_id TEXT NOT NULL DEFAULT 'default',
    repo TEXT NOT NULL,
    etag TEXT,
    open_json TEXT NOT NULL DEFAULT 'null',
    polled_at TEXT NOT NULL,
    changed_at TEXT,
    last_error TEXT,
    PRIMARY KEY (org_id, repo)
);
INSERT INTO github_poll_repos (org_id, repo, etag, open_json, polled_at, changed_at)
    SELECT 'default', repo, etag, open_json, polled_at, changed_at FROM github_poll_state
    WHERE true ON CONFLICT (org_id, repo) DO NOTHING;
",
};

/// The organization triggers of `github_poll_repos`.
pub const POLL_REPOS_TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.github_poll", &["github_poll_repos"]);

pub fn register(r: &mut Registry) {
    authz::register(r);
    credentials::register(r);
}

/// The hub identity GitHub effects run as, in the default organization.
pub fn github_caller() -> Caller {
    github_caller_for(ua_core::DEFAULT_ORG)
}

/// The hub identity GitHub effects run as, acting for organization `org`:
/// a system job working on that organization's rows only. Its reach is the
/// grant [`grant_refusal`] enforces. The `operator` profile here only
/// selects the tool surface; a profile grants no authority, and as a system
/// caller it holds neither `Operator` nor `LifecycleOperator`.
pub fn github_caller_for(org: &str) -> Caller {
    Caller { label: GITHUB_ACTOR.into(), profile: ua_core::Profile::Operator, ..Caller::system_for(org) }
}

/// `task_update` arguments the GitHub identity may pass: a close with evidence.
const CLOSE_KEYS: [&str; 5] = ["id", "status", "evidence_ref", "append_note", "expected_updated_at"];

/// Why the GitHub identity may not make this call, or `None` when its grant
/// covers it. The registry checks this first for any caller labelled
/// [`GITHUB_ACTOR`], whatever its kind, profile or `enforce_profile`.
pub(crate) fn grant_refusal(caller: &Caller, tool: &str, args: &Value) -> Option<String> {
    if !caller.label.trim().eq_ignore_ascii_case(GITHUB_ACTOR) {
        return None;
    }
    match tool {
        "task_update" => {
            let Some(obj) = args.as_object() else {
                return Some("task_update needs an argument object".into());
            };
            if let Some(k) = obj.keys().find(|k| !CLOSE_KEYS.contains(&k.as_str())) {
                return Some(format!(
                    "{GITHUB_ACTOR} may only close a task with evidence; argument {k:?} is outside its grant"
                ));
            }
            if obj.get("status").and_then(Value::as_str) != Some("done") {
                return Some(format!("{GITHUB_ACTOR} may only set status done"));
            }
            if obj.get("evidence_ref").and_then(Value::as_str).and_then(client::full_sha).is_none() {
                return Some(format!(
                    "{GITHUB_ACTOR} closes a task only with a merge commit (40 hex) as evidence_ref"
                ));
            }
            None
        }
        "coordination_manage" if args.get("action").and_then(Value::as_str) == Some("task_check_verify") => {
            None
        }
        _ => Some(format!(
            "{GITHUB_ACTOR} holds a narrow grant (task_update closing with evidence, coordination_manage \
             task_check_verify); {tool} is outside it"
        )),
    }
}

/// Re-verify every check organization `org`'s tasks recorded with a CI
/// reference in `repo` at `head`, through the governed `task_check_verify`
/// as [`github_caller_for`] `org` (which looks the run up with `org`'s own
/// token). Returns one entry per check. Another organization's checks at
/// the same head are never touched.
pub(crate) async fn reverify_head(
    hub: &Hub,
    org: &str,
    repo: &str,
    head: &str,
    source: &str,
) -> UaResult<Vec<Value>> {
    let (r, h, o) = (repo.to_ascii_lowercase(), head.to_ascii_lowercase(), org.to_string());
    let rows: Vec<(i64, String)> = hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT k.task_id, k.name FROM task_checks k JOIN tasks t ON t.id = k.task_id AND t.org_id = ?4 \
                 WHERE k.org_id = ?4 AND lower(k.repo) = ?1 AND lower(k.head_sha) = ?2 AND k.ref_kind = 'ci_run' ORDER BY k.id LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![r, h, REVERIFY_CAP, o], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let caller = github_caller_for(org);
    let mut out = Vec::new();
    for (task_id, name) in rows {
        let args = json!({
            "action": "task_check_verify",
            "params": { "task_id": task_id, "name": name, "head_sha": head },
        });
        let entry =
            match crate::builtin_registry_shared().call(hub, &caller, "coordination_manage", args).await {
                Ok(v) => {
                    let check = v["checks"]
                        .as_array()
                        .and_then(|cs| cs.iter().find(|c| c["name"] == name.as_str()))
                        .cloned()
                        .unwrap_or_default();
                    json!({
                        "task_id": task_id, "name": name, "grade": check["grade"],
                        "verdict": check["verification"]["verdict"],
                    })
                }
                Err(e) => json!({ "task_id": task_id, "name": name, "error": e.to_string() }),
            };
        out.push(entry);
    }
    let payload = json!({
        "org_id": org, "repo": ledger_text(org, repo), "head_sha": head, "source": source,
        "checks": redacted_checks(org, &out),
    });
    let org = org.to_string();
    hub.db()
        .write_async(move |tx| emit(tx, &org, "agent.github.checks_reverified", payload, GITHUB_ACTOR))
        .await?;
    Ok(out)
}

/// The re-verified checks as another organization's event carries them: ids,
/// grades and verdicts, no check names or error text.
fn redacted_checks(org: &str, checks: &[Value]) -> Value {
    if org == ua_core::DEFAULT_ORG {
        return json!(checks);
    }
    json!(
        checks
            .iter()
            .map(|c| json!({
                "task_id": c["task_id"], "grade": c["grade"], "verdict": c["verdict"],
                "error": c.get("error").is_some(),
            }))
            .collect::<Vec<_>>()
    )
}

#[cfg(test)]
mod authority_tests {
    use super::*;

    /// The GitHub caller carries the operator profile for its tool surface,
    /// but that profile grants nothing: it is not an operator for dispatch
    /// (which an operator-profile caller used to be), nor for the hub view.
    #[test]
    fn the_github_caller_holds_no_operator_authority() {
        let cfg = ua_core::Config { human_identities: vec!["operator".into()], ..ua_core::Config::default() };
        let gh = github_caller();
        assert_eq!(gh.profile, ua_core::Profile::Operator);
        assert!(!crate::families::dispatch::is_operator(&cfg, &gh));
        assert!(!crate::families::capability::is_operator(&gh, &cfg));
        assert!(!ua_org::authz::Authz::new(&cfg).holds(
            &gh,
            &[ua_org::authz::Authority::Operator, ua_org::authz::Authority::LifecycleOperator],
            ua_core::DEFAULT_ORG,
        ));
    }
}
