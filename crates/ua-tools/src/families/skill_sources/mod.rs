//! `skill_sources`: org-scoped Git skill source allowlist and hardened fetch
//! plumbing (slice D2a; see `docs/skill-sources.md`).
//!
//! Actions exposed under `skill_registry`:
//! - `source_add` `{url, tracking_ref?, pinned_sha, allowed_subpaths?}`:
//!   human operator only (`Authority::Operator`), behind a one-time human
//!   approval bound to the §1 fields, ledgered on `skill.source_added` in the
//!   same write transaction.
//! - `source_revoke` `{source_id, reason?}`: human operator only, behind a
//!   one-time human approval, terminal on the row, ledgered on
//!   `skill.source_revoked`.
//! - `source_list` `{status?}`: lists the caller's organization's sources
//!   (`active` by default, or `revoked` / `all`).
//!
//! `source_discover`, `source_refresh`, `source_import`, `yank`, and catalog
//! `install` arrive in slices D2b and D2c.

pub mod fetch;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_org::authz::{Authority, Authz};
use ua_store::{Procedure, SchemaPart};

use self::fetch::{validate_allowed_subpaths, validate_sha, validate_source_url, validate_tracking_ref};
use super::agents::verified;
use super::plans::ledger_text;
use super::skill_registry::{emit, gate_pass, pending};
use crate::registry::ToolCtx;

const MAX_REVOKE_REASON_BYTES: usize = 500;

/// `skill_sources.v1`: org-scoped Git skill source allowlist (`docs/skill-sources.md` §1).
/// Born tenant-scoped (`org_id NOT NULL DEFAULT 'default'`); its generated
/// `_org_exists` and `_org_immutable` triggers come from [`TENANT_PART`].
pub const SCHEMA: SchemaPart = SchemaPart {
    name: "skill_sources.v1",
    sql: "
CREATE TABLE IF NOT EXISTS skill_sources (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'default',
    canonical_url TEXT NOT NULL,
    host TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    allowed_subpaths TEXT NOT NULL DEFAULT '[]',
    tracking_ref TEXT NOT NULL,
    pinned_sha TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')) DEFAULT 'active',
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    approval_id INTEGER,
    revoked_by TEXT,
    revoked_at TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_skill_sources_org_status
    ON skill_sources(org_id, status, added_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_skill_sources_org_url_active
    ON skill_sources(org_id, canonical_url) WHERE status = 'active';
",
};

/// `organization.v1.tools.skill_sources`: installs `skill_sources_org_exists`
/// and `skill_sources_org_immutable` triggers after `skill_sources.v1` and
/// `organization.v1.store`.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.tools.skill_sources", &["skill_sources"]);

const SOURCE_COLS: &str = "id, canonical_url, host, repo_path, allowed_subpaths, tracking_ref, pinned_sha, \
                           status, added_by, added_at, approval_id, revoked_by, revoked_at, revoke_reason";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceAddParams {
    pub url: String,
    /// Tracking branch, tag, or `HEAD` (default: `"HEAD"`).
    #[serde(default)]
    pub tracking_ref: Option<String>,
    /// Exact 40-character lowercase hex commit SHA to pin.
    pub pinned_sha: String,
    /// Optional repository-relative subpath prefixes allowed for skill discovery.
    #[serde(default)]
    pub allowed_subpaths: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceRevokeParams {
    pub source_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceListParams {
    /// `active` (default), `revoked`, or `all`.
    #[serde(default)]
    pub status: Option<String>,
}

struct SourceRow {
    id: String,
    canonical_url: String,
    tracking_ref: String,
    pinned_sha: String,
    allowed_subpaths: Vec<String>,
    status: String,
    public: Value,
}

fn source_row(r: &Row<'_>) -> rusqlite::Result<SourceRow> {
    let id: String = r.get(0)?;
    let canonical_url: String = r.get(1)?;
    let host: String = r.get(2)?;
    let repo_path: String = r.get(3)?;
    let subpaths_raw: String = r.get(4)?;
    let allowed_subpaths: Vec<String> = serde_json::from_str(&subpaths_raw).unwrap_or_default();
    let tracking_ref: String = r.get(5)?;
    let pinned_sha: String = r.get(6)?;
    let status: String = r.get(7)?;
    let public = json!({
        "id": id,
        "canonical_url": canonical_url,
        "host": host,
        "repo_path": repo_path,
        "allowed_subpaths": allowed_subpaths,
        "tracking_ref": tracking_ref,
        "pinned_sha": pinned_sha,
        "status": status,
        "added_by": r.get::<_, String>(8)?,
        "added_at": r.get::<_, String>(9)?,
        "approval_id": r.get::<_, Option<i64>>(10)?,
        "revoked_by": r.get::<_, Option<String>>(11)?,
        "revoked_at": r.get::<_, Option<String>>(12)?,
        "revoke_reason": r.get::<_, Option<String>>(13)?,
    });
    Ok(SourceRow { id, canonical_url, tracking_ref, pinned_sha, allowed_subpaths, status, public })
}

/// Human operator authority check for `skill_sources` mutations
/// (`docs/skill-sources.md` §1): requires an existing org in `orgs`, a verified
/// identity, and [`Authority::Operator`] (human-only; never an agent or
/// lifecycle operator).
fn human_operator(ctx: &ToolCtx, what: &str) -> UaResult<String> {
    let org = ctx.caller.org_id.as_str();
    let known = ctx
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?))?;
    if known.is_none() {
        return Err(UaError::invalid(format!(
            "unknown organization {org:?}; skill sources were not changed"
        )));
    }
    let who = verified(&ctx.caller).map(str::to_string).ok_or_else(|| {
        UaError::denied("identity_required", "managing skill sources requires an authenticated identity")
    })?;
    if !Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::Operator], org) {
        return Err(UaError::denied(
            "operator_required",
            format!("{what} requires a human operator of this organization"),
        ));
    }
    Ok(who)
}

fn load_source(c: &Connection, org: &str, id: &str) -> UaResult<Option<SourceRow>> {
    Ok(c.query_row(
        &format!("SELECT {SOURCE_COLS} FROM skill_sources WHERE org_id = ?1 AND id = ?2"),
        params![org, id],
        source_row,
    )
    .optional()?)
}

/// `skill_registry { action: "source_add", params }`.
pub(crate) fn source_add(ctx: &ToolCtx, p: SourceAddParams) -> UaResult<Value> {
    let who = human_operator(ctx, "adding a skill source")?;
    source_add_as(ctx, who, p)
}

pub(crate) fn source_add_as(ctx: &ToolCtx, who: String, p: SourceAddParams) -> UaResult<Value> {
    let parsed = validate_source_url(&p.url, false)?;
    let tracking_ref = validate_tracking_ref(p.tracking_ref.as_deref().unwrap_or("HEAD"))?;
    let pinned_sha = validate_sha(&p.pinned_sha)?;
    let allowed_subpaths = validate_allowed_subpaths(p.allowed_subpaths)?;
    let subpaths_json = serde_json::to_string(&allowed_subpaths)
        .map_err(|e| UaError::internal(format!("serialize allowed_subpaths: {e}")))?;
    let org = ctx.caller.org_id.as_str();

    ctx.hub
        .db()
        .write(|tx| {
            let existing: Option<SourceRow> = tx
                .query_row(
                    &format!(
                        "SELECT {SOURCE_COLS} FROM skill_sources \
                         WHERE org_id = ?1 AND canonical_url = ?2 AND status = 'active' LIMIT 1"
                    ),
                    params![org, parsed.canonical_url],
                    source_row,
                )
                .optional()?;
            if let Some(row) = existing {
                if row.tracking_ref == tracking_ref
                    && row.pinned_sha == pinned_sha
                    && row.allowed_subpaths == allowed_subpaths
                {
                    return Ok(Ok(json!({ "ok": true, "idempotent": true, "source": row.public })));
                }
                return Err(UaError::conflict(format!(
                    "an active skill source ({}) already exists for {:?}; revoke it before adding a replacement",
                    row.id, parsed.canonical_url
                )));
            }

            let payload = json!({
                "action": "source_add",
                "org_id": org,
                "canonical_url": parsed.canonical_url,
                "tracking_ref": tracking_ref,
                "pinned_sha": pinned_sha,
                "allowed_subpaths": allowed_subpaths,
            });
            let approval_id = match gate_pass(tx, ctx, &payload)? {
                Ok(id) => id,
                Err(pending_id) => return Ok(Err(pending_id)),
            };

            let id = format!("src-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO skill_sources (org_id, id, canonical_url, host, repo_path, allowed_subpaths, \
                 tracking_ref, pinned_sha, status, added_by, added_at, approval_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?10, ?11)",
                params![
                    org,
                    id,
                    parsed.canonical_url,
                    parsed.host,
                    parsed.repo_path,
                    subpaths_json,
                    tracking_ref,
                    pinned_sha,
                    who,
                    now,
                    approval_id,
                ],
            )?;
            emit(
                tx,
                org,
                "skill.source_added",
                json!({
                    "source_id": id,
                    "canonical_url": ledger_text(org, &parsed.canonical_url),
                    "host": ledger_text(org, &parsed.host),
                    "tracking_ref": ledger_text(org, &tracking_ref),
                    "pinned_sha": ledger_text(org, &pinned_sha),
                    "approval_id": approval_id,
                    "added_at": now,
                }),
                &who,
            )?;
            let created = load_source(tx, org, &id)?
                .ok_or_else(|| UaError::internal("inserted skill source row vanished"))?;
            Ok(Ok(json!({ "ok": true, "idempotent": false, "source": created.public })))
        })
        .and_then(pending)
}

/// `skill_registry { action: "source_revoke", params }`.
pub(crate) fn source_revoke(ctx: &ToolCtx, p: SourceRevokeParams) -> UaResult<Value> {
    let who = human_operator(ctx, "revoking a skill source")?;
    source_revoke_as(ctx, who, p)
}

pub(crate) fn source_revoke_as(ctx: &ToolCtx, who: String, p: SourceRevokeParams) -> UaResult<Value> {
    let id = p.source_id.trim().to_string();
    if id.is_empty() {
        return Err(UaError::invalid("source_id is required"));
    }
    let reason = match p.reason {
        None => None,
        Some(raw) => {
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() {
                None
            } else if trimmed.len() > MAX_REVOKE_REASON_BYTES {
                return Err(UaError::invalid(format!(
                    "revoke reason exceeds the {MAX_REVOKE_REASON_BYTES}-byte limit"
                )));
            } else {
                Some(trimmed)
            }
        }
    };
    let org = ctx.caller.org_id.as_str();

    ctx.hub
        .db()
        .write(|tx| {
            // Another organization's source_id answers identically to missing (`not_found`).
            let row = load_source(tx, org, &id)?
                .ok_or_else(|| UaError::not_found(format!("unknown skill source {id:?}")))?;
            if row.status == "revoked" {
                return Err(UaError::conflict(format!(
                    "skill source {id:?} is already revoked; revocation is terminal"
                )));
            }
            let payload = json!({
                "action": "source_revoke",
                "org_id": org,
                "source_id": row.id,
                "canonical_url": row.canonical_url,
                "reason": reason,
            });
            if let Err(pending_id) = gate_pass(tx, ctx, &payload)? {
                return Ok(Err(pending_id));
            }
            let now = ua_core::time::now();
            tx.execute(
                "UPDATE skill_sources SET status = 'revoked', revoked_by = ?3, revoked_at = ?4, \
                 revoke_reason = ?5 WHERE org_id = ?1 AND id = ?2 AND status = 'active'",
                params![org, row.id, who, now, reason],
            )?;
            emit(
                tx,
                org,
                "skill.source_revoked",
                json!({
                    "source_id": row.id,
                    "canonical_url": ledger_text(org, &row.canonical_url),
                    "reason": reason.as_deref().map(|r| ledger_text(org, r)).unwrap_or(Value::Null),
                    "revoked_at": now,
                }),
                &who,
            )?;
            let updated = load_source(tx, org, &row.id)?
                .ok_or_else(|| UaError::internal("revoked skill source row vanished"))?;
            Ok(Ok(json!({ "ok": true, "source": updated.public })))
        })
        .and_then(pending)
}

/// `skill_registry { action: "source_list", params }`.
pub(crate) fn source_list(ctx: &ToolCtx, p: SourceListParams) -> UaResult<Value> {
    let _who = verified(&ctx.caller).ok_or_else(|| {
        UaError::denied("identity_required", "listing skill sources requires an authenticated identity")
    })?;
    let status = match p.status.as_deref().map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("active") => Some("active"),
        Some("revoked") => Some("revoked"),
        Some("all") => None,
        Some(_) => return Err(UaError::invalid("status must be one of active, revoked, all")),
    };
    let org = ctx.caller.org_id.as_str();
    ctx.hub.db().read(|c| {
        let mut stmt = c.prepare(&format!(
            "SELECT {SOURCE_COLS} FROM skill_sources \
             WHERE org_id = ?1 AND (?2 IS NULL OR status = ?2) \
             ORDER BY added_at DESC, id DESC"
        ))?;
        let sources: Vec<Value> = stmt
            .query_map(params![org, status], source_row)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|r| r.public)
            .collect();
        Ok(json!({ "sources": sources }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ua_core::{ActorKind, Caller, Config, Profile, identity::Transport};

    #[tokio::test]
    async fn org_b_writes_bind_org_id_and_redact_default_ledger() {
        let home = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into()];
        let hub = crate::Hub::in_memory(cfg).unwrap();
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES ('org-b', 'org-b', 'Org B', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();

        let b_ctx = ToolCtx {
            hub: hub.clone(),
            caller: Caller {
                label: "operator".into(),
                kind: ActorKind::Human,
                profile: Profile::Operator,
                enforce_profile: true,
                session_key: Some("s1".into()),
                transport: Transport::Mcp,
                org_id: "org-b".into(),
            },
        };
        let sha = "a".repeat(40);
        let add_params = SourceAddParams {
            url: "https://github.com/org-b-private/skills".into(),
            tracking_ref: Some("main".into()),
            pinned_sha: sha.clone(),
            allowed_subpaths: Some(vec!["skills".into()]),
        };

        // Parks an approval bound to org-b.
        let req_id = match source_add_as(&b_ctx, "operator".into(), add_params) {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected pending approval: {other:?}"),
        };
        let (a_org, a_payload): (String, Value) = hub
            .db()
            .read(move |c| {
                let (o, p): (String, String) =
                    c.query_row("SELECT org_id, payload FROM approvals WHERE id = ?1", [req_id], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })?;
                Ok((o, serde_json::from_str(&p)?))
            })
            .unwrap();
        assert_eq!(a_org, "org-b");
        assert_eq!(a_payload["org_id"], "org-b");
        assert_eq!(a_payload["canonical_url"], "https://github.com/org-b-private/skills");

        // Approve in SQL (human approvals outside default org are not wired yet).
        hub.db()
            .write(move |tx| {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2, \
                     updated_at = ?2 WHERE id = ?1",
                    params![req_id, ua_core::time::now()],
                )?;
                Ok(())
            })
            .unwrap();
        let added = source_add_as(
            &b_ctx,
            "operator".into(),
            SourceAddParams {
                url: "https://github.com/org-b-private/skills".into(),
                tracking_ref: Some("main".into()),
                pinned_sha: sha.clone(),
                allowed_subpaths: Some(vec!["skills".into()]),
            },
        )
        .unwrap();
        let source_id = added["source"]["id"].as_str().unwrap().to_string();
        assert_eq!(added["source"]["approval_id"], req_id);

        // Revoke org-b source and confirm ORG-EVENT-DEFAULT redaction on both ledger events.
        let rev_id = match source_revoke_as(
            &b_ctx,
            "operator".into(),
            SourceRevokeParams {
                source_id: source_id.clone(),
                reason: Some("compromised-secret-note".into()),
            },
        ) {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected pending approval: {other:?}"),
        };
        hub.db()
            .write(move |tx| {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2, \
                     updated_at = ?2 WHERE id = ?1",
                    params![rev_id, ua_core::time::now()],
                )?;
                Ok(())
            })
            .unwrap();
        let revoked = source_revoke_as(
            &b_ctx,
            "operator".into(),
            SourceRevokeParams {
                source_id: source_id.clone(),
                reason: Some("compromised-secret-note".into()),
            },
        )
        .unwrap();
        assert_eq!(revoked["source"]["status"], "revoked");

        let events: Vec<(String, String, String)> = hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT channel, COALESCE(originator, ''), payload FROM event_log \
                     WHERE channel LIKE 'skill.source_%' ORDER BY seq",
                )?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap();
        assert_eq!(events.len(), 2, "{events:?}");
        for (ch, orig, payload) in &events {
            assert_eq!(orig, crate::approvals::NEUTRAL_ORIGINATOR, "{ch}");
            for secret in ["org-b-private", "github.com", sha.as_str(), "compromised-secret-note", "operator"]
            {
                assert!(!payload.contains(secret), "{ch} leaked {secret}: {payload}");
            }
            let p: Value = serde_json::from_str(payload).unwrap();
            assert_eq!(p["source_id"], source_id);
            assert_eq!(p["canonical_url"], Value::Null);
        }
    }
}
