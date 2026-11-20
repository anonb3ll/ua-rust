//! The native GitHub connector.
//!
//! - [`client`]: the REST client, pinned to `github_api_url`, bound
//!   repositories only, no redirects, bounded and rate-limit aware.
//! - CI verification: [`crate::ci::GitHubCiVerifier`] looks a check's run up
//!   through the client, so a check can earn `verified`.
//! - [`webhook`]: `POST /api/github/webhook` ingestion. HMAC-SHA256
//!   signature check, replay protection by delivery id, then effects:
//!   re-verify recorded checks at a completed head, close tasks a merged PR
//!   finishes ([`crate::families::continuity::merged`]).
//! - [`poll`]: the same effects without a public endpoint, polling the bound
//!   repositories' open pull requests with ETags under `ua serve`.
//! - [`authz`]: `policy_authorization_record` and `policy_authorization_list`,
//!   a human's standing-policy authorization to merge one exact head, which
//!   `git_merge_task` accepts in place of a one-time approval.
//!
//! Every effect is a governed registry call (`task_update`,
//! `coordination_manage` `task_check_verify`) made as the hub identity
//! [`GITHUB_ACTOR`], and is ledgered on an `agent.github.*` channel. That
//! identity holds a narrow grant the registry enforces before anything else
//! ([`grant_refusal`]): `task_update` closing a task with a merge commit as
//! evidence, and `coordination_manage(action="task_check_verify")`. Nothing
//! else is callable as it, whatever its profile says. See `docs/github.md`.

pub(crate) mod authz;
pub(crate) mod client;
pub mod poll;
pub mod webhook;

use serde_json::{Value, json};
use ua_core::{Caller, UaResult};
use ua_store::SchemaPart;

use crate::Hub;
use crate::families::tasks::emit;
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

pub fn register(r: &mut Registry) {
    authz::register(r);
}

/// The hub identity GitHub effects run as. Its reach is the grant
/// [`grant_refusal`] enforces, not its profile.
pub fn github_caller() -> Caller {
    Caller { label: GITHUB_ACTOR.into(), profile: ua_core::Profile::Operator, ..Caller::system() }
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

/// Re-verify every check recorded with a CI reference in `repo` at `head`,
/// through the governed `task_check_verify`. Returns one entry per check.
pub(crate) async fn reverify_head(hub: &Hub, repo: &str, head: &str, source: &str) -> UaResult<Vec<Value>> {
    let (r, h) = (repo.to_ascii_lowercase(), head.to_ascii_lowercase());
    let rows: Vec<(i64, String)> = hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT task_id, name FROM task_checks WHERE lower(repo) = ?1 AND lower(head_sha) = ?2 \
                 AND ref_kind = 'ci_run' ORDER BY id LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![r, h, REVERIFY_CAP], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await?;
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let caller = github_caller();
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
    let payload = json!({ "repo": repo, "head_sha": head, "source": source, "checks": out });
    hub.db().write_async(move |tx| emit(tx, "agent.github.checks_reverified", payload, GITHUB_ACTOR)).await?;
    Ok(out)
}
