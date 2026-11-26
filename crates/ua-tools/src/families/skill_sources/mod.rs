//! `skill_sources`: org-scoped Git skill source allowlist, hardened fetch
//! plumbing, discovery, refresh, and staged import (slices D2a + D2b; see
//! `docs/skill-sources.md`).
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
//! - `source_refresh` `{source_id, tracking_ref?}`: resolves `tracking_ref` to
//!   a candidate SHA and reports what changed without moving `pinned_sha`,
//!   creating a version, or updating assignments.
//! - `source_discover` `{source_id, sha?}`: lists candidate skill packages
//!   under `allowed_subpaths` at `pinned_sha` (or explicit 40-char `sha`) via
//!   `ls-tree -r -l -z` only; symlinks, gitlinks and non-regular modes are
//!   refused.
//! - `source_import` `{source_id, path, name?, sha?}`: reads blobs at the exact
//!   SHA by object id, runs the full D1 review/screening pipeline, copies bytes
//!   into `skill_publish_staging` with `git:<canonical_url>@<sha>:<path>`
//!   provenance, and parks the D1 publish approval (with member diff on upgrade).
//!
//! Version `yank` and catalog `install` live alongside the registry core in
//! [`super::skill_registry`].

pub mod fetch;
pub mod plumbing;

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{Procedure, SchemaPart};

use self::fetch::{
    FetchOptions, ParsedSourceUrl, SystemDnsResolver, url_uniqueness_key, validate_allowed_subpaths,
    validate_sha, validate_source_url, validate_tracking_ref,
};
use self::plumbing::{
    SourceFetchCtx, discover_source, read_package_from_source, refresh_source, validate_skill_repo_path,
};
use super::agents::verified;
use super::plans::ledger_text;
use super::skill_registry::{
    check_name, emit, frontmatter, gate_pass, human_operator, operator, pending, stage_members,
};
use super::skills::review_in_memory;
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
    ON skill_sources(
        org_id,
        CASE
            WHEN lower(canonical_url) LIKE '%.git'
            THEN substr(lower(canonical_url), 1, length(canonical_url) - 4)
            ELSE lower(canonical_url)
        END
    ) WHERE status = 'active';
CREATE TRIGGER IF NOT EXISTS skill_sources_revoke_terminal
BEFORE UPDATE ON skill_sources
WHEN OLD.status = 'revoked'
BEGIN
    SELECT RAISE(ABORT, 'revoked skill sources are terminal and cannot be modified');
END;
CREATE TRIGGER IF NOT EXISTS skill_sources_revoke_no_delete
BEFORE DELETE ON skill_sources
WHEN OLD.status = 'revoked'
BEGIN
    SELECT RAISE(ABORT, 'revoked skill sources are terminal and cannot be deleted');
END;
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceRefreshParams {
    pub source_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceDiscoverParams {
    pub source_id: String,
    /// Optional exact 40-char commit SHA; defaults to the source's `pinned_sha`.
    #[serde(default)]
    pub sha: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceImportParams {
    pub source_id: String,
    /// Repository-relative directory containing `SKILL.md` (or `"."` for repo root).
    pub path: String,
    /// Optional skill name override; defaults to `SKILL.md` frontmatter `name` or directory leaf.
    #[serde(default)]
    pub name: Option<String>,
    /// Optional exact 40-char commit SHA; defaults to the source's `pinned_sha`.
    #[serde(default)]
    pub sha: Option<String>,
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

const SQL_URL_KEY_EXPR: &str = "CASE \
    WHEN lower(canonical_url) LIKE '%.git' \
    THEN substr(lower(canonical_url), 1, length(canonical_url) - 4) \
    ELSE lower(canonical_url) \
END";

pub(crate) fn source_add_as(ctx: &ToolCtx, who: String, p: SourceAddParams) -> UaResult<Value> {
    let parsed = validate_source_url(&p.url)?;
    let url_key = url_uniqueness_key(&parsed.canonical_url);
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
                         WHERE org_id = ?1 AND ({SQL_URL_KEY_EXPR}) = ?2 AND status = 'active' LIMIT 1"
                    ),
                    params![org, url_key],
                    source_row,
                )
                .optional()?;
            if let Some(row) = existing {
                if row.canonical_url == parsed.canonical_url
                    && row.tracking_ref == tracking_ref
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

            // §1 "fresh pinned_sha": refuse re-adding a previously revoked commit SHA
            // for this repository in this organization.
            let revoked_same_sha: Option<String> = tx
                .query_row(
                    &format!(
                        "SELECT id FROM skill_sources \
                         WHERE org_id = ?1 AND ({SQL_URL_KEY_EXPR}) = ?2 \
                         AND pinned_sha = ?3 AND status = 'revoked' LIMIT 1"
                    ),
                    params![org, url_key, pinned_sha],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(prev_id) = revoked_same_sha {
                return Err(UaError::conflict(format!(
                    "pinned_sha {pinned_sha} was previously revoked on source {prev_id}; re-adding requires a fresh pinned_sha"
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

fn source_url_and_opts(canonical_url: &str) -> UaResult<(ParsedSourceUrl, FetchOptions)> {
    #[cfg(any(test, feature = "test-util"))]
    if canonical_url.starts_with("file://") {
        let parsed = self::fetch::validate_file_source_url_for_test(canonical_url)?;
        return Ok((parsed, FetchOptions::for_local_file_test()));
    }
    let parsed = validate_source_url(canonical_url)?;
    Ok((parsed, FetchOptions::production()))
}

fn load_active_source(ctx: &ToolCtx, raw_id: &str, action: &str) -> UaResult<SourceRow> {
    let id = raw_id.trim();
    if id.is_empty() {
        return Err(UaError::invalid("source_id is required"));
    }
    let org = ctx.caller.org_id.as_str();
    let row = ctx
        .hub
        .db()
        .read(|c| load_source(c, org, id))?
        .ok_or_else(|| UaError::not_found(format!("unknown skill source {id:?}")))?;
    if row.status == "revoked" {
        return Err(UaError::conflict(format!("skill source {id:?} is revoked; {action} is refused")));
    }
    Ok(row)
}

/// `skill_registry { action: "source_refresh", params }`.
pub(crate) fn source_refresh(ctx: &ToolCtx, p: SourceRefreshParams) -> UaResult<Value> {
    let _who = verified(&ctx.caller).ok_or_else(|| {
        UaError::denied("identity_required", "refreshing a skill source requires an authenticated identity")
    })?;
    let row = load_active_source(ctx, &p.source_id, "refresh")?;
    let (parsed_url, opts) = source_url_and_opts(&row.canonical_url)?;
    let src = SourceFetchCtx {
        data_home: &ctx.hub.cfg().home,
        org_id: &ctx.caller.org_id,
        url: &parsed_url,
        allowed_subpaths: &row.allowed_subpaths,
        resolver: &SystemDnsResolver,
        opts: &opts,
    };
    let report = refresh_source(&src, &row.tracking_ref, &row.pinned_sha)?;
    Ok(json!({
        "ok": true,
        "source_id": row.id,
        "canonical_url": row.canonical_url,
        "tracking_ref": report.tracking_ref,
        "pinned_sha": report.pinned_sha,
        "candidate_sha": report.candidate_sha,
        "changed": report.changed,
        "diff_available": report.diff_available,
        "diff_note": report.diff_note,
        "changed_files": report.changed_files.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        "changed_packages": report.changed_packages,
        "truncated": report.truncated,
    }))
}

/// `skill_registry { action: "source_discover", params }`.
pub(crate) fn source_discover(ctx: &ToolCtx, p: SourceDiscoverParams) -> UaResult<Value> {
    let _who = verified(&ctx.caller).ok_or_else(|| {
        UaError::denied("identity_required", "discovering skills requires an authenticated identity")
    })?;
    let row = load_active_source(ctx, &p.source_id, "discover")?;
    let target_sha = match p.sha.as_deref() {
        Some(s) => validate_sha(s)?,
        None => row.pinned_sha.clone(),
    };
    // Default (`pinned_sha`): fetch the approved pin directly by SHA even if
    // upstream has moved `tracking_ref`. An explicit different `sha` is allowed
    // only when it equals the current `tracking_ref` tip.
    let verify_ref = (target_sha != row.pinned_sha).then_some(row.tracking_ref.as_str());
    let (parsed_url, opts) = source_url_and_opts(&row.canonical_url)?;
    let src = SourceFetchCtx {
        data_home: &ctx.hub.cfg().home,
        org_id: &ctx.caller.org_id,
        url: &parsed_url,
        allowed_subpaths: &row.allowed_subpaths,
        resolver: &SystemDnsResolver,
        opts: &opts,
    };
    let packages = discover_source(&src, &target_sha, verify_ref)?;
    Ok(json!({
        "ok": true,
        "source_id": row.id,
        "canonical_url": row.canonical_url,
        "sha": target_sha,
        "allowed_subpaths": row.allowed_subpaths,
        "packages": packages.iter().map(|pkg| pkg.to_json()).collect::<Vec<_>>(),
    }))
}

/// `skill_registry { action: "source_import", params }`.
pub(crate) fn source_import(ctx: &ToolCtx, p: SourceImportParams) -> UaResult<Value> {
    let who = operator(ctx, "importing a skill from a source")?;
    source_import_as(ctx, &who, p)
}

pub(crate) fn source_import_as(ctx: &ToolCtx, who: &str, p: SourceImportParams) -> UaResult<Value> {
    let row = load_active_source(ctx, &p.source_id, "import")?;
    let clean_path = validate_skill_repo_path(&p.path, &row.allowed_subpaths)?;
    let target_sha = match p.sha.as_deref() {
        Some(s) => validate_sha(s)?,
        None => row.pinned_sha.clone(),
    };
    // Default (`pinned_sha`): import the approved pin directly by SHA even if
    // upstream has moved `tracking_ref`. An explicit different `sha` is allowed
    // only as an explicit upgrade equal to the current `tracking_ref` tip.
    let verify_ref = (target_sha != row.pinned_sha).then_some(row.tracking_ref.as_str());
    let (parsed_url, opts) = source_url_and_opts(&row.canonical_url)?;
    let src = SourceFetchCtx {
        data_home: &ctx.hub.cfg().home,
        org_id: &ctx.caller.org_id,
        url: &parsed_url,
        allowed_subpaths: &row.allowed_subpaths,
        resolver: &SystemDnsResolver,
        opts: &opts,
    };
    let members = read_package_from_source(&src, &target_sha, verify_ref, &clean_path)?;

    let md_text = std::str::from_utf8(&members["SKILL.md"].bytes)
        .map_err(|_| UaError::invalid("SKILL.md must be valid UTF-8"))?;
    let inferred_name = frontmatter(md_text)
        .and_then(|fm| fm.get("name").and_then(Value::as_str).map(str::to_string))
        .or_else(|| if clean_path == "." { None } else { clean_path.rsplit('/').next().map(str::to_string) });
    let raw_name = p.name.or(inferred_name).unwrap_or_default();
    let name = check_name(&raw_name)?;

    let dir_name = if clean_path == "." {
        name.as_str()
    } else {
        clean_path.rsplit('/').next().unwrap_or(name.as_str())
    };
    let member_paths: BTreeSet<String> = members.keys().cloned().collect();
    let review = review_in_memory(dir_name, md_text, &member_paths, "info");
    let provenance = format!("git:{}@{}:{clean_path}", row.canonical_url, target_sha);
    stage_members(ctx, who, name, provenance, Some(row.id), members, review)
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

    #[tokio::test]
    async fn org_b_source_import_and_publish_redacts_default_ledger() {
        use std::process::Command;

        let home = tempfile::tempdir().unwrap();
        let remote = tempfile::tempdir().unwrap();
        let git_ok = |args: &[&str]| -> String {
            let out = Command::new("git")
                .current_dir(remote.path())
                .env("GIT_AUTHOR_NAME", "test")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "test")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        git_ok(&["init", "-b", "main"]);
        let skill_dir = remote.path().join("skills/orgb-skill");
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: orgb-skill\ndescription: Org B private skill. Use when asked to check org-b tasks.\n---\n\n\
             # Org B Skill\n\nStep one.\nStep two.\nStep three.\n",
        )
        .unwrap();
        git_ok(&["add", "."]);
        git_ok(&["commit", "-m", "v1"]);
        let sha = git_ok(&["rev-parse", "HEAD"]);

        let mut cfg = Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into()];
        let hub = crate::Hub::in_memory(cfg).unwrap();
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES ('org-b', 'org-b', 'Org B', '[\"developer\", \"operator\"]', '2026-01-01T00:00:00+00:00')",
                    [],
                )?;
                tx.execute(
                    "INSERT INTO skill_sources (org_id, id, canonical_url, host, repo_path, allowed_subpaths, \
                     tracking_ref, pinned_sha, status, added_by, added_at, approval_id) \
                     VALUES ('org-b', 'src-orgb-import', ?1, '', ?2, '[\"skills\"]', 'main', ?3, 'active', \
                     'operator', '2026-01-01T00:00:00+00:00', NULL)",
                    params![format!("file://{}", remote.path().display()), remote.path().display().to_string(), sha],
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
        let staged = source_import_as(
            &b_ctx,
            "operator",
            SourceImportParams {
                source_id: "src-orgb-import".into(),
                path: "skills/orgb-skill".into(),
                name: None,
                sha: None,
            },
        )
        .unwrap();
        assert_eq!(staged["status"], "approval_pending", "{staged}");
        let approval_id = staged["approval_id"].as_i64().unwrap();
        let staging_id = staged["staging_id"].as_str().unwrap().to_string();

        // Approve in SQL and publish from staging.
        hub.db()
            .write(move |tx| {
                tx.execute(
                    "UPDATE approvals SET status = 'approved', resolved_by = 'reviewer', resolved_at = ?2, \
                     updated_at = ?2 WHERE id = ?1",
                    params![approval_id, ua_core::time::now()],
                )?;
                Ok(())
            })
            .unwrap();
        let published =
            crate::families::skill_registry::publish_staged_for_test(&b_ctx, "operator", &staging_id)
                .unwrap();
        assert_eq!(published["ok"], true, "{published}");
        assert_eq!(published["skill"]["version"], 1);

        // Verify ORG-EVENT-DEFAULT redaction on the skill.published ledger event.
        let (orig, payload): (String, String) = hub
            .db()
            .read(|c| {
                Ok(c.query_row(
                    "SELECT COALESCE(originator, ''), payload FROM event_log \
                     WHERE channel = 'skill.published' ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(orig, crate::approvals::NEUTRAL_ORIGINATOR);
        for secret in ["orgb-skill", sha.as_str(), "skills/orgb-skill", "operator"] {
            assert!(!payload.contains(secret), "skill.published leaked {secret}: {payload}");
        }
        let p: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(p["name"], Value::Null);
        assert_eq!(p["source"], Value::Null);
        assert_eq!(p["content_hash"], Value::Null);
        assert_eq!(p["staging_id"], staging_id);
    }
}
