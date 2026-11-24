//! `skill_registry`: the skills registry kernel of the Python hub.
//!
//! A skill version is immutable: `(name, version)` with the SHA-256 of its
//! content, never updated or deleted (triggers refuse both). Publishing the
//! same content again returns the existing version. A skill is assigned to an
//! agent label or a profile, always pinned to the version that was approved;
//! an agent assignment wins over a profile assignment of the same skill. The
//! harness config bundle served to a node carries the skills resolved for the
//! node's agent (see [`super::harness_config`]).
//!
//! Actions (`action` + `params`, as in the Python hub):
//! - `publish` {name, path}: review one skill (`SKILL.md`, or a skill
//!   directory holding only `SKILL.md`) in the workspace, copy it into the
//!   hub's staging table and ask for a human approval that shows the full
//!   text; `publish` {staging_id}: after approval, version that staged copy
//!   (the workspace file is never read again);
//! - `list` {name?}, `get` {name, version?};
//! - `assign` {skill_name, target, target_type?, version?}, `unassign`;
//! - `resolve` {agent_label, profile?}: what an agent is assigned (the
//!   caller's own, or any agent's for an operator);
//! - `drift` {surface_dir, agent_label?, profile?}: a read-only comparison of
//!   a skills directory in the workspace with the registry.
//!
//! A skill's text lands in the harness of every node it reaches, so it is a
//! prompt-injection path: publish, assign and unassign are operator actions
//! (a human or a lifecycle operator), and each needs a one-time human
//! approval bound to the content (publish: the staged text and its review
//! findings; assign: target, pinned version and hash; unassign: the target).
//! `skill_review` refuses permission-bearing front matter and hidden text.
//! Paths are resolved inside the workspace without following symlinks, and
//! outputs never carry the hub's filesystem paths. Events: `skill.published`,
//! `skill.assigned` and `skill.unassigned`, in the same transaction.
//!
//! Organizations: every version, assignment and staged publish belongs to
//! one organization (`org_id`, `skill_registry.v2.tenant_keys` and
//! `organization.v1.tools.skills`). Every read and write is scoped to the
//! caller's organization: another organization's skill, version, assignment
//! or staging id answers exactly as a missing one, two organizations may
//! publish and assign the same name and version independently, and the
//! skills a node is served are its caller's organization's. A write by a
//! caller whose organization `orgs` does not hold is refused before anything
//! is read or written.
//!
//! Not ported: multi-file skill packages (a publish source with supporting
//! files is refused), the catalog and team installs, and git skill sources.
//! Versions imported from the Python hub keep their package manifest; their
//! `SKILL.md` and manifest hash are verified on read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use ua_core::{Profile, UaError, UaResult};
use ua_store::{EventInput, Procedure, SchemaPart, ledger};

use super::agents::verified;
use super::harness_config::render::{content_hash, py_dumps};
use crate::approvals::{self, GateOutcome};
use crate::registry::{Registry, ToolCtx, blocking, tool};
use ua_org::authz::{Authority, Authz};

/// The approval tool name `publish` and `assign` park under.
pub const GATE: &str = "skill_registry";

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "skill_registry.v1",
    sql: "
CREATE TABLE IF NOT EXISTS skill_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    published_by TEXT,
    published_at TEXT NOT NULL,
    package_manifest TEXT,
    package_payload TEXT,
    UNIQUE(name, version)
);
CREATE INDEX IF NOT EXISTS idx_skill_versions_name ON skill_versions(name);
CREATE INDEX IF NOT EXISTS idx_skill_versions_name_hash ON skill_versions(name, content_hash);
CREATE TABLE IF NOT EXISTS skill_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    skill_name TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('agent','profile')),
    target TEXT NOT NULL,
    pinned_version INTEGER,
    assigned_by TEXT,
    assigned_at TEXT NOT NULL,
    UNIQUE(skill_name, target_type, target)
);
CREATE INDEX IF NOT EXISTS idx_skill_assignments_target ON skill_assignments(target_type, target);
-- A publish request's own copy of the SKILL.md: approved and published
-- from here, never re-read from the workspace.
CREATE TABLE IF NOT EXISTS skill_publish_staging (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    findings_json TEXT NOT NULL DEFAULT '[]',
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    published_version INTEGER
);
CREATE TRIGGER IF NOT EXISTS skill_versions_immutable_update BEFORE UPDATE ON skill_versions
BEGIN SELECT RAISE(ABORT, 'skill versions and provenance are immutable'); END;
CREATE TRIGGER IF NOT EXISTS skill_versions_immutable_delete BEFORE DELETE ON skill_versions
BEGIN SELECT RAISE(ABORT, 'skill versions and provenance are immutable'); END;
",
};

/// `skill_registry.v2.tenant_keys`: rebuild `skill_versions` around
/// `UNIQUE(org_id, name, version)` and `skill_assignments` around
/// `UNIQUE(org_id, skill_name, target_type, target)`, each with
/// `org_id TEXT NOT NULL DEFAULT 'default'`. Both keep their AUTOINCREMENT ids
/// (and the sequence), their indexes and triggers (the `skill_versions`
/// immutability triggers included), and gain an index led by `org_id`.
/// `skill_publish_staging` is keyed by a hub-global random id, so it needs no
/// rebuild: `organization.v1.tools.skills` adds its `org_id`.
///
/// Runs standalone outside the shared migration transaction so
/// `PRAGMA foreign_keys = OFF` takes effect before the rebuild transaction and
/// `PRAGMA foreign_keys = ON` is restored afterwards (`docs/organization.md`,
/// "Global keys and table rebuilds"). Safe to re-run after a crash before
/// recording: an existing `org_id` is kept (`COALESCE(org_id, 'default')`).
pub const TENANT_KEYS: Procedure = Procedure {
    name: "skill_registry.v2.tenant_keys",
    version: 1,
    standalone: true,
    run: rebuild_tenant_keys,
    args: &["skill_versions", "skill_assignments"],
};

/// `organization.v1.tools.skills`: installs the `*_org_exists` and
/// `*_org_immutable` triggers of the three skill tables (and `org_id` on
/// `skill_publish_staging`) after `skill_registry.v2.tenant_keys` and
/// `organization.v1.store`.
pub const TENANT_PART: Procedure = ua_store::org::tenant_part(
    "organization.v1.tools.skills",
    &["skill_versions", "skill_assignments", "skill_publish_staging"],
);

/// One table the rebuild re-creates.
struct Rebuild {
    table: &'static str,
    /// The new table's body (after `CREATE TABLE <table>_new`).
    body: &'static str,
    /// Every column but `org_id`, copied by name.
    cols: &'static str,
    /// The index led by `org_id`.
    org_index: &'static str,
}

const REBUILDS: [Rebuild; 2] = [
    Rebuild {
        table: "skill_versions",
        body: "(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL DEFAULT 'default',
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    content TEXT NOT NULL,
    published_by TEXT,
    published_at TEXT NOT NULL,
    package_manifest TEXT,
    package_payload TEXT,
    UNIQUE(org_id, name, version)
)",
        cols: "id, name, version, content_hash, source, content, published_by, published_at, \
               package_manifest, package_payload",
        org_index: "CREATE INDEX IF NOT EXISTS idx_skill_versions_org_name ON skill_versions(org_id, name);",
    },
    Rebuild {
        table: "skill_assignments",
        body: "(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id TEXT NOT NULL DEFAULT 'default',
    skill_name TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('agent','profile')),
    target TEXT NOT NULL,
    pinned_version INTEGER,
    assigned_by TEXT,
    assigned_at TEXT NOT NULL,
    UNIQUE(org_id, skill_name, target_type, target)
)",
        cols: "id, skill_name, target_type, target, pinned_version, assigned_by, assigned_at",
        org_index: "CREATE INDEX IF NOT EXISTS idx_skill_assignments_org_target \
                    ON skill_assignments(org_id, target_type, target);",
    },
];

fn rebuild_tenant_keys(conn: &Connection, _args: &'static [&'static str]) -> anyhow::Result<String> {
    anyhow::ensure!(conn.is_autocommit(), "skill_registry.v2.tenant_keys must run outside a transaction");
    let mut log = Vec::new();
    conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
    log.push("PRAGMA foreign_keys = OFF;".to_string());

    let res = (|| -> anyhow::Result<()> {
        conn.execute_batch("BEGIN IMMEDIATE;")?;
        log.push("BEGIN IMMEDIATE;".to_string());
        rebuild_body(conn, &mut log)?;
        conn.execute_batch("COMMIT;")?;
        log.push("COMMIT;".to_string());
        Ok(())
    })();

    if res.is_err() && !conn.is_autocommit() {
        let _ = conn.execute_batch("ROLLBACK;");
    }
    let fk_res = conn.execute_batch("PRAGMA foreign_keys = ON;");
    res?;
    fk_res?;
    log.push("PRAGMA foreign_keys = ON;".to_string());
    Ok(log.join("\n"))
}

fn names(conn: &Connection, sql: &str, table: Option<&str>) -> anyhow::Result<BTreeSet<String>> {
    let mut stmt = conn.prepare(sql)?;
    let rows = match table {
        Some(t) => stmt.query_map([t], |r| r.get(0))?.collect::<Result<_, _>>()?,
        None => stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?,
    };
    Ok(rows)
}

fn named_sql(conn: &Connection, kind: &str, table: &str) -> anyhow::Result<Vec<(String, String)>> {
    Ok(conn
        .prepare(
            "SELECT name, sql FROM sqlite_master \
             WHERE type = ?1 AND tbl_name = ?2 AND sql IS NOT NULL ORDER BY name",
        )?
        .query_map([kind, table], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?)
}

fn step(conn: &Connection, log: &mut Vec<String>, stmt: &str) -> anyhow::Result<()> {
    let stmt = format!("{};", stmt.trim().trim_end_matches(';'));
    conn.execute_batch(&stmt)?;
    log.push(stmt);
    Ok(())
}

fn rebuild_body(conn: &Connection, log: &mut Vec<String>) -> anyhow::Result<()> {
    const ALL_TRIGGERS: &str = "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name";
    const ALL_VIEWS: &str = "SELECT name FROM sqlite_master WHERE type = 'view' ORDER BY name";
    let triggers_before = names(conn, ALL_TRIGGERS, None)?;
    // Views are dropped before the tables are swapped (SQLite's
    // `ALTER TABLE ... RENAME` validates every view and fails on one that
    // names a dropped table) and re-created, in their original order, after.
    let views: Vec<(String, String)> = conn
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'view' AND sql IS NOT NULL ORDER BY rowid",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let views_before = names(conn, ALL_VIEWS, None)?;
    for (name, _) in &views {
        step(conn, log, &format!("DROP VIEW \"{}\"", name.replace('"', "\"\"")))?;
    }

    for rb in &REBUILDS {
        let t = rb.table;
        let exists: bool = conn
            .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [t], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        anyhow::ensure!(exists, "{t} does not exist; apply skill_registry.v1 first");
        let indexes = named_sql(conn, "index", t)?;
        let triggers = named_sql(conn, "trigger", t)?;
        let seq: Option<i64> = conn
            .query_row("SELECT seq FROM sqlite_sequence WHERE name = ?1", [t], |r| r.get(0))
            .optional()?;
        let has_org_id: bool = conn
            .query_row("SELECT 1 FROM pragma_table_info(?1) WHERE name = 'org_id'", [t], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        let org_expr = if has_org_id { "COALESCE(org_id, 'default')" } else { "'default'" };

        step(conn, log, &format!("CREATE TABLE {t}_new {}", rb.body))?;
        step(
            conn,
            log,
            &format!(
                "INSERT INTO {t}_new (org_id, {cols}) SELECT {org_expr}, {cols} FROM {t}",
                cols = rb.cols
            ),
        )?;
        step(conn, log, &format!("DROP TABLE {t}"))?;
        step(conn, log, &format!("ALTER TABLE {t}_new RENAME TO {t}"))?;
        // Keep the AUTOINCREMENT high-water mark, so an id freed by a delete
        // is never handed out again.
        if let Some(seq) = seq {
            step(conn, log, &format!("DELETE FROM sqlite_sequence WHERE name IN ('{t}', '{t}_new')"))?;
            step(
                conn,
                log,
                &format!(
                    "INSERT INTO sqlite_sequence (name, seq) \
                     SELECT '{t}', MAX({seq}, COALESCE((SELECT MAX(id) FROM {t}), 0))"
                ),
            )?;
        }
        for (_, sql) in &indexes {
            step(conn, log, sql)?;
        }
        step(conn, log, rb.org_index)?;
        for (_, sql) in &triggers {
            step(conn, log, sql)?;
        }
        let after = names(
            conn,
            "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = ?1 AND sql IS NOT NULL",
            Some(t),
        )?;
        for (name, _) in &indexes {
            anyhow::ensure!(after.contains(name), "index {name} missing after the {t} rebuild");
        }
    }

    for (_, sql) in &views {
        step(conn, log, sql)?;
    }

    for rb in &REBUILDS {
        let t = rb.table;
        let fk_violations: Vec<(String, Option<i64>, String, i64)> = conn
            .prepare(&format!("PRAGMA foreign_key_check({t})"))?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<Result<_, _>>()?;
        anyhow::ensure!(
            fk_violations.is_empty(),
            "PRAGMA foreign_key_check({t}) reported {} violation(s): {fk_violations:?}",
            fk_violations.len(),
        );
    }
    let triggers_after = names(conn, ALL_TRIGGERS, None)?;
    anyhow::ensure!(
        triggers_after == triggers_before,
        "trigger set changed across the skill table rebuild (before: {triggers_before:?}, after: {triggers_after:?})"
    );
    let views_after = names(conn, ALL_VIEWS, None)?;
    anyhow::ensure!(
        views_after == views_before,
        "view set changed across the skill table rebuild (before: {views_before:?}, after: {views_after:?})"
    );
    Ok(())
}

const NAME_MAX: usize = 64;
/// Skills one resolution returns.
pub const MAX_RESOLVED_SKILLS: usize = 20;
/// Characters of each skill's content a `resolve` answer carries.
const CONTENT_CAP: usize = 4000;
pub const MAX_SKILL_FILE_BYTES: usize = 64 * 1024;
const MAX_DRIFT_SKILLS: usize = 100;
const MAX_DRIFT_ENTRIES: usize = 10_000;

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

fn check_name(raw: &str) -> UaResult<String> {
    let name = raw.trim();
    if valid_name(name) {
        Ok(name.to_string())
    } else {
        Err(UaError::invalid(format!(
            "skill name {raw:?} must be kebab-case (lowercase letters, digits, hyphens), at most {NAME_MAX} chars"
        )))
    }
}

fn check_target_type(raw: Option<&str>) -> UaResult<&'static str> {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("agent") => Ok("agent"),
        Some("profile") => Ok("profile"),
        Some(_) => Err(UaError::invalid("target_type must be one of agent, profile")),
    }
}

/// A profile target in its current name.
fn profile_target(raw: &str) -> UaResult<String> {
    Profile::canonical_name(raw.trim()).map(str::to_string).ok_or_else(|| {
        let names: Vec<&str> = Profile::ALL.iter().map(|p| p.as_str()).collect();
        UaError::invalid(format!("unknown profile {raw:?}; choose from {}", names.join(", ")))
    })
}

/// The names a profile's assignments may be stored under: its current name
/// and its legacy alias (rows imported from the Python hub).
fn profile_keys(profile: &str) -> Vec<String> {
    match profile.parse::<Profile>() {
        Ok(p) => {
            let mut v = vec![p.as_str().to_string()];
            v.extend(p.legacy_alias().map(str::to_string));
            v
        }
        Err(_) => vec![profile.to_ascii_lowercase()],
    }
}

/// The YAML front matter of a `SKILL.md`, when it has a readable one.
pub(crate) fn frontmatter(text: &str) -> Option<Map<String, Value>> {
    let rest = text.strip_prefix("---\n")?;
    let end = rest.find("\n---\n")?;
    match serde_saphyr::from_str::<Value>(&rest[..end]) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

// --- rows -------------------------------------------------------------------------

const LIST_COLS: &str =
    "id, name, version, content_hash, source, published_by, published_at, package_manifest";
const FULL_COLS: &str =
    "id, name, version, content_hash, source, published_by, published_at, package_manifest, content";

fn version_row(r: &Row<'_>) -> rusqlite::Result<Value> {
    let manifest: Option<String> = r.get(7)?;
    let mut v = json!({
        "id": r.get::<_, i64>(0)?,
        "name": r.get::<_, String>(1)?,
        "version": r.get::<_, i64>(2)?,
        "content_hash": r.get::<_, String>(3)?,
        "published_by": r.get::<_, Option<String>>(5)?,
        "published_at": r.get::<_, String>(6)?,
        "package_manifest": manifest.and_then(|m| serde_json::from_str::<Value>(&m).ok()),
    });
    if let Ok(content) = r.get::<_, String>(8) {
        v["content"] = json!(content);
    }
    Ok(v)
}

/// Check a stored version's attestation: the content hash, and for an
/// imported package its manifest (`SKILL.md` member and package hash).
fn verify(row: &Value) -> UaResult<()> {
    let content = row["content"].as_str().unwrap_or_default();
    let hash = row["content_hash"].as_str().unwrap_or_default();
    let skill_md = content_hash(content);
    let ok = match &row["package_manifest"] {
        Value::Null => skill_md == hash,
        manifest => {
            let files = manifest["files"].as_array().cloned().unwrap_or_default();
            let md_ok = files.iter().any(|f| f["path"] == "SKILL.md" && f["sha256"] == json!(skill_md));
            let package =
                if files.len() == 1 { skill_md.clone() } else { content_hash(&py_dumps(manifest, None)) };
            md_ok && package == hash
        }
    };
    if ok {
        Ok(())
    } else {
        Err(UaError::conflict("skill content hash does not match the reviewed registry version"))
    }
}

/// A version of `name` in `org` (the latest when `version` is `None`),
/// verified. Another organization's version reads as missing.
fn load_version(c: &Connection, org: &str, name: &str, version: Option<i64>) -> UaResult<Option<Value>> {
    let row = match version {
        Some(v) => c
            .query_row(
                &format!(
                    "SELECT {FULL_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 AND version = ?3"
                ),
                params![org, name, v],
                version_row,
            )
            .optional()?,
        None => c
            .query_row(
                &format!(
                    "SELECT {FULL_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 \
                     ORDER BY version DESC LIMIT 1"
                ),
                params![org, name],
                version_row,
            )
            .optional()?,
    };
    if let Some(r) = &row {
        verify(r)?;
    }
    Ok(row)
}

fn assignment_row(r: &Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": r.get::<_, i64>(0)?,
        "skill_name": r.get::<_, String>(1)?,
        "target_type": r.get::<_, String>(2)?,
        "target": r.get::<_, String>(3)?,
        "pinned_version": r.get::<_, Option<i64>>(4)?,
        "assigned_by": r.get::<_, Option<String>>(5)?,
        "assigned_at": r.get::<_, String>(6)?,
    }))
}

const ASSIGN_COLS: &str = "id, skill_name, target_type, target, pinned_version, assigned_by, assigned_at";

// --- resolution -------------------------------------------------------------------

/// One skill resolved for an agent.
#[derive(Debug, Clone)]
pub(crate) struct Resolved {
    pub name: String,
    pub version: i64,
    pub hash: String,
    pub content: String,
    /// `agent` or `profile`: which assignment matched.
    pub via: &'static str,
}

/// The skills assigned to `agent` in `org` directly or through `profile`: direct
/// assignments first (each source sorted by name), a direct one winning over
/// a profile one of the same skill, at most [`MAX_RESOLVED_SKILLS`]. A pinned
/// version that is missing, or a version that fails verification, is skipped.
pub(crate) fn resolve(
    c: &Connection,
    org: &str,
    agent: &str,
    profile: Option<&str>,
) -> UaResult<Vec<Resolved>> {
    let agent = agent.trim();
    if agent.is_empty() {
        return Ok(Vec::new());
    }
    let rows = |target_type: &str, targets: &[String]| -> UaResult<Vec<(String, Option<i64>)>> {
        let mut out: Vec<(String, Option<i64>)> = Vec::new();
        for t in targets {
            let mut stmt = c.prepare(
                "SELECT skill_name, pinned_version FROM skill_assignments \
                 WHERE org_id = ?1 AND target_type = ?2 AND target = ?3 ORDER BY skill_name",
            )?;
            out.extend(
                stmt.query_map(params![org, target_type, t], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    };
    let mut picked: Vec<(String, Option<i64>, &'static str)> = Vec::new();
    let mut seen = BTreeSet::new();
    for (name, pin) in rows("agent", &[agent.to_string()])? {
        if seen.insert(name.clone()) {
            picked.push((name, pin, "agent"));
        }
    }
    if let Some(p) = profile {
        for (name, pin) in rows("profile", &profile_keys(p))? {
            if seen.insert(name.clone()) {
                picked.push((name, pin, "profile"));
            }
        }
    }
    let mut out = Vec::new();
    for (name, pin, via) in picked.into_iter().take(MAX_RESOLVED_SKILLS) {
        let Ok(Some(row)) = load_version(c, org, &name, pin) else { continue };
        out.push(Resolved {
            version: row["version"].as_i64().unwrap_or_default(),
            hash: row["content_hash"].as_str().unwrap_or_default().to_string(),
            content: row["content"].as_str().unwrap_or_default().to_string(),
            name,
            via,
        });
    }
    Ok(out)
}

// --- actions ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillRegistryArgs {
    /// `publish`, `list`, `get`, `assign`, `unassign`, `resolve` or `drift`.
    pub action: String,
    /// The action's parameters (see the tool description).
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishParams {
    #[serde(default)]
    name: Option<String>,
    /// Stage the skill at this workspace path and ask for approval.
    #[serde(default)]
    path: Option<String>,
    /// Publish this approved staged copy.
    #[serde(default)]
    staging_id: Option<String>,
    /// Accepted for compatibility; the verified caller is always the author.
    #[serde(default)]
    #[allow(dead_code)]
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListParams {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetParams {
    name: String,
    #[serde(default)]
    version: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignParams {
    #[serde(default)]
    skill_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
    target: String,
    #[serde(default)]
    target_type: Option<String>,
    #[serde(default)]
    version: Option<i64>,
    #[serde(default)]
    #[allow(dead_code)]
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveParams {
    agent_label: String,
    #[serde(default)]
    profile: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DriftParams {
    surface_dir: String,
    #[serde(default)]
    agent_label: Option<String>,
    #[serde(default)]
    profile: Option<String>,
}

fn params<T: DeserializeOwned>(raw: Option<Value>) -> UaResult<T> {
    let raw = match raw {
        None | Some(Value::Null) => json!({}),
        Some(v) => v,
    };
    serde_json::from_value(raw).map_err(|e| UaError::invalid(format!("params: {e}")))
}

fn author(ctx: &ToolCtx) -> UaResult<String> {
    verified(&ctx.caller).map(str::to_string).ok_or_else(|| {
        UaError::denied("identity_required", "changing the skill registry requires an authenticated identity")
    })
}

/// An operator (a human or a lifecycle operator) of the caller's
/// organization: what changes the skills every node of an agent or profile
/// is served. An organization `orgs` does not hold is refused first, before
/// anything is read or written (organizations are never deleted, so the
/// check cannot go stale).
fn operator(ctx: &ToolCtx, what: &str) -> UaResult<String> {
    let org = ctx.caller.org_id.as_str();
    let known = ctx
        .hub
        .db()
        .read(|c| Ok(c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?))?;
    if known.is_none() {
        return Err(UaError::invalid(format!(
            "unknown organization {org:?}; the skill registry was not changed"
        )));
    }
    let who = author(ctx)?;
    if !Authz::new(ctx.hub.cfg()).holds(
        &ctx.caller,
        &[Authority::Operator, Authority::LifecycleOperator],
        org,
    ) {
        return Err(UaError::denied(
            "operator_required",
            format!("{what} is an operator action (a human or a lifecycle operator)"),
        ));
    }
    Ok(who)
}

/// Evaluate the one-time human approval for `payload` inside `tx`.
/// `Ok(Some(id))` when it is pending (the caller commits and reports it).
fn gate(tx: &mut ua_store::WriteTx<'_>, ctx: &ToolCtx, payload: &Value) -> UaResult<Option<i64>> {
    match approvals::gate(tx, ctx.hub.cfg(), &ctx.caller, GATE, payload)? {
        GateOutcome::Pass { .. } => Ok(None),
        GateOutcome::Pending { approval_id } => Ok(Some(approval_id)),
        GateOutcome::Denied { approval_id, reason } => Err(UaError::denied(
            "approval_denied",
            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
        )),
    }
}

fn pending(out: Result<Value, i64>) -> UaResult<Value> {
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: GATE.into(), approval_id })
}

fn positive(version: Option<i64>) -> UaResult<Option<i64>> {
    match version {
        Some(v) if v < 1 => Err(UaError::invalid("version must be a positive integer")),
        other => Ok(other),
    }
}

/// Resolve `raw` inside the workspace without following any symlink: every
/// component is checked with `symlink_metadata`. A path that is missing and
/// one outside the workspace get the same refusal. Returns the absolute path
/// and its workspace-relative form.
fn workspace_target(ctx: &ToolCtx, raw: &str) -> UaResult<(PathBuf, String)> {
    let not_found = || UaError::not_found(format!("{raw:?} does not exist inside the workspace"));
    let raw_t = raw.trim();
    if raw_t.contains('\0') {
        return Err(not_found());
    }
    let ws = ctx.hub.cfg().workspace_root();
    let ws_real = ws.canonicalize().map_err(|_| not_found())?;
    let p = Path::new(if raw_t.is_empty() { "." } else { raw_t });
    let rel: PathBuf = if p.is_absolute() {
        p.strip_prefix(&ws_real).or_else(|_| p.strip_prefix(&ws)).map_err(|_| not_found())?.to_path_buf()
    } else {
        p.to_path_buf()
    };
    let mut cur = ws_real;
    let mut parts = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(seg) => {
                cur.push(seg);
                parts.push(seg.to_string_lossy().into_owned());
                let meta = std::fs::symlink_metadata(&cur).map_err(|_| not_found())?;
                if meta.file_type().is_symlink() {
                    return Err(UaError::invalid(format!(
                        "{raw:?} passes through a symlink; symlinks are not followed"
                    )));
                }
            }
            Component::CurDir => {}
            _ => return Err(not_found()),
        }
    }
    Ok((cur, parts.join("/")))
}

fn is_regular_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}

fn is_real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
}

/// The single `SKILL.md` a publish reads (a `SKILL.md` file, or a skill
/// directory holding nothing else), with its workspace-relative path.
fn skill_md(target: &Path, rel: &str, shown: &str) -> UaResult<(PathBuf, String)> {
    let (dir, rel_dir) = if is_regular_file(target) {
        if target.file_name().is_none_or(|n| n != "SKILL.md") {
            return Err(UaError::invalid(format!("{shown:?} is a file but not a SKILL.md")));
        }
        let parent = target.parent().map(Path::to_path_buf).unwrap_or_default();
        (parent, rel.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default())
    } else if is_real_dir(target) {
        (target.to_path_buf(), rel.to_string())
    } else {
        return Err(UaError::invalid(format!("{shown:?} is neither a SKILL.md nor a skill directory")));
    };
    let md = dir.join("SKILL.md");
    match std::fs::symlink_metadata(&md) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(UaError::invalid("SKILL.md is a symlink; symlinks are not followed"));
        }
        Ok(m) if m.file_type().is_file() => {}
        _ => {
            return Err(UaError::invalid(format!(
                "{shown:?} has no SKILL.md at its root; publish takes one skill directory or SKILL.md file"
            )));
        }
    }
    let others: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|_| UaError::invalid(format!("cannot read {shown:?}")))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "SKILL.md")
        .collect();
    if !others.is_empty() {
        return Err(UaError::invalid(
            "this hub versions SKILL.md-only skills; the skill directory has supporting files \
             (multi-file packages are not ported)",
        ));
    }
    let rel_md = if rel_dir.is_empty() { "SKILL.md".to_string() } else { format!("{rel_dir}/SKILL.md") };
    Ok((md, rel_md))
}

fn read_bounded(md: &Path) -> UaResult<String> {
    if !is_regular_file(md) {
        return Err(UaError::invalid("SKILL.md could not be read"));
    }
    let bytes = std::fs::read(md).map_err(|_| UaError::invalid("SKILL.md could not be read"))?;
    if bytes.len() > MAX_SKILL_FILE_BYTES {
        return Err(UaError::invalid(format!("SKILL.md exceeds the {MAX_SKILL_FILE_BYTES}-byte limit")));
    }
    String::from_utf8(bytes).map_err(|_| UaError::invalid("SKILL.md must be valid UTF-8"))
}

/// One staged publish: the hub's own copy of a `SKILL.md`, taken when the
/// publish was requested. The approval shows and binds this copy, and an
/// approved publish versions it without reading the workspace again.
struct Staged {
    id: String,
    name: String,
    content: String,
    content_hash: String,
    source: String,
    findings: Value,
    requested_by: String,
    published_version: Option<i64>,
}

fn load_staged(c: &Connection, org: &str, id: &str) -> UaResult<Option<Staged>> {
    Ok(c.query_row(
        "SELECT id, name, content, content_hash, source, findings_json, requested_by, published_version \
         FROM skill_publish_staging WHERE org_id = ?1 AND id = ?2",
        params![org, id],
        |r| {
            let findings: String = r.get(5)?;
            Ok(Staged {
                id: r.get(0)?,
                name: r.get(1)?,
                content: r.get(2)?,
                content_hash: r.get(3)?,
                source: r.get(4)?,
                findings: serde_json::from_str(&findings).unwrap_or_else(|_| json!([])),
                requested_by: r.get(6)?,
                published_version: r.get(7)?,
            })
        },
    )
    .optional()?)
}

/// What a publish approval shows and binds: the organization, the full
/// staged text (at most 64 KiB), its hash and the review's findings.
fn staged_payload(org: &str, s: &Staged) -> Value {
    json!({
        "action": "publish",
        "org_id": org,
        "staging_id": s.id,
        "name": s.name,
        "content_hash": s.content_hash,
        "content": s.content,
        "review_findings": s.findings,
    })
}

fn existing_version(c: &Connection, org: &str, name: &str, hash: &str) -> UaResult<Option<Value>> {
    Ok(c.query_row(
        &format!(
            "SELECT {LIST_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 AND content_hash = ?3 \
             ORDER BY version DESC LIMIT 1"
        ),
        params![org, name, hash],
        version_row,
    )
    .optional()?)
}

/// `publish {name, path}`: review the skill, copy it into the hub's staging
/// table and ask for the approval. It never publishes; after approval,
/// `publish {staging_id}` versions the staged copy.
fn stage(ctx: &ToolCtx, who: &str, name: Option<String>, path: &str) -> UaResult<Value> {
    let name = check_name(name.as_deref().unwrap_or_default())?;
    let (target, rel) = workspace_target(ctx, path)?;
    let (md, rel_md) = skill_md(&target, &rel, path)?;
    let text = read_bounded(&md)?;
    let dir = md.parent().map(Path::to_path_buf).unwrap_or_default();
    let review = super::skills::review_dirs(vec![dir.clone()], &dir, "info");
    if review["status"] == "fail" {
        return Ok(json!({ "ok": false, "blocked": true, "name": name, "review": review }));
    }
    if let Some(fm) = frontmatter(&text)
        && let Some(fm_name) = fm.get("name").and_then(Value::as_str)
        && fm_name != name
    {
        return Err(UaError::invalid(format!(
            "publish name {name:?} does not match the SKILL.md frontmatter name {fm_name:?}"
        )));
    }
    let hash = content_hash(&text);
    let findings: Vec<Value> = review["findings"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|f| json!({ "rule": f["rule"], "severity": f["severity"], "message": f["message"], "line": f["line"] }))
        .collect();
    let caller = ctx.caller.clone();
    let cfg = ctx.hub.cfg().clone();
    let who = who.to_string();
    let org = ctx.caller.org_id.as_str();
    ctx.hub.db().write(|tx| {
        if let Some(skill) = existing_version(tx, org, &name, &hash)? {
            return Ok(json!({ "ok": true, "idempotent": true, "skill": skill, "review": review }));
        }
        let reuse: Option<String> = tx
            .query_row(
                "SELECT id FROM skill_publish_staging WHERE org_id = ?1 AND name = ?2 AND content_hash = ?3 \
                 AND requested_by = ?4 AND published_version IS NULL ORDER BY created_at DESC LIMIT 1",
                params![org, name, hash, who],
                |r| r.get(0),
            )
            .optional()?;
        let id = match reuse {
            Some(id) => id,
            None => {
                let id = format!("sk-{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
                tx.execute(
                    "INSERT INTO skill_publish_staging (org_id, id, name, content, content_hash, source, \
                     findings_json, requested_by, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        org,
                        id,
                        name,
                        text,
                        hash,
                        rel_md,
                        json!(findings).to_string(),
                        who,
                        ua_core::time::now()
                    ],
                )?;
                id
            }
        };
        let staged = load_staged(tx, org, &id)?.ok_or_else(|| UaError::internal("staged row vanished"))?;
        let state = approvals::request(tx, &cfg, &caller, GATE, &staged_payload(org, &staged))?;
        Ok(json!({
            "ok": false,
            "status": format!("approval_{}", state.status()),
            "approval_id": state.approval_id(),
            "staging_id": id,
            "name": name,
            "content_hash": hash,
            "review": review,
            "next": "once a human approves, call publish {staging_id}; the staged copy is published, not the file",
        }))
    })
}

/// `publish {staging_id}`: version the staged copy behind its approval.
fn publish_staged(ctx: &ToolCtx, who: &str, id: &str) -> UaResult<Value> {
    let org = ctx.caller.org_id.as_str();
    ctx.hub
        .db()
        .write(|tx| {
            // Another organization's staged copy answers exactly as a missing one.
            let missing = || UaError::not_found(format!("no staged publish {id:?} of yours"));
            let staged = load_staged(tx, org, id.trim())?.ok_or_else(missing)?;
            if staged.requested_by != who {
                return Err(missing());
            }
            if let Some(skill) = existing_version(tx, org, &staged.name, &staged.content_hash)? {
                return Ok(Ok(json!({ "ok": true, "idempotent": true, "skill": skill })));
            }
            if staged.published_version.is_some() {
                return Err(UaError::conflict("this staged publish was already used"));
            }
            if let Some(approval) = gate(tx, ctx, &staged_payload(org, &staged))? {
                return Ok(Err(approval));
            }
            let next: i64 = tx.query_row(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM skill_versions WHERE org_id = ?1 AND name = ?2",
                params![org, staged.name],
                |r| r.get(0),
            )?;
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO skill_versions (org_id, name, version, content_hash, source, content, \
                 published_by, published_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![org, staged.name, next, staged.content_hash, staged.source, staged.content, who, now],
            )?;
            tx.execute(
                "UPDATE skill_publish_staging SET published_version = ?3 WHERE org_id = ?1 AND id = ?2",
                params![org, staged.id, next],
            )?;
            // ORG-EVENT-DEFAULT: use the skill's organization once callers
            // can resolve to other organizations and org_guard allows it.
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "skill.published",
                    json!({
                        "name": staged.name,
                        "version": next,
                        "content_hash": staged.content_hash,
                        "source": staged.source,
                        "staging_id": staged.id,
                        "published_at": now,
                    }),
                )
                .by(who.to_string()),
            )?;
            let skill = tx.query_row(
                &format!(
                    "SELECT {LIST_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 AND version = ?3"
                ),
                params![org, staged.name, next],
                version_row,
            )?;
            Ok(Ok(json!({ "ok": true, "idempotent": false, "skill": skill })))
        })
        .and_then(pending)
}

fn publish(ctx: &ToolCtx, p: PublishParams) -> UaResult<Value> {
    let who = operator(ctx, "publishing a skill")?;
    match (p.staging_id.as_deref(), p.path.as_deref()) {
        (Some(id), None) => publish_staged(ctx, &who, id),
        (None, Some(path)) => stage(ctx, &who, p.name, path),
        _ => Err(UaError::invalid(
            "publish takes {name, path} to stage and request approval, or {staging_id} to publish an approved \
             staged copy",
        )),
    }
}

fn list(ctx: &ToolCtx, p: ListParams) -> UaResult<Value> {
    let name = p.name.filter(|n| !n.trim().is_empty());
    let org = ctx.caller.org_id.as_str();
    ctx.hub.db().read(|c| {
        let mut stmt = c.prepare(&format!(
            "SELECT {LIST_COLS} FROM skill_versions WHERE org_id = ?1 AND (?2 IS NULL OR name = ?2) \
             ORDER BY name, version DESC"
        ))?;
        let skills = stmt.query_map(params![org, name], version_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(json!({ "skills": skills }))
    })
}

fn get(ctx: &ToolCtx, p: GetParams) -> UaResult<Value> {
    let version = positive(p.version)?;
    ctx.hub
        .db()
        .read(|c| load_version(c, &ctx.caller.org_id, &p.name, version))?
        .ok_or_else(|| UaError::not_found(format!("unknown skill: {:?}", p.name)))
}

fn assign(ctx: &ToolCtx, p: AssignParams) -> UaResult<Value> {
    let who = operator(ctx, "assigning a skill")?;
    assign_as(ctx, who, p)
}

/// `assign` for `who`, an operator of the caller's organization.
fn assign_as(ctx: &ToolCtx, who: String, p: AssignParams) -> UaResult<Value> {
    let name = check_name(p.skill_name.as_deref().or(p.name.as_deref()).unwrap_or_default())?;
    let ttype = check_target_type(p.target_type.as_deref())?;
    let mut target = p.target.trim().to_string();
    if target.is_empty() {
        return Err(UaError::invalid("target is required"));
    }
    if ttype == "profile" {
        target = profile_target(&target)?;
    }
    let pin = positive(p.version)?;
    let org = ctx.caller.org_id.as_str();
    ctx.hub.db().write(|tx| {
        // The approved version is always the pin: a later version reaches
        // nobody until it is assigned (and approved) itself.
        let found: Option<(i64, String)> = match pin {
            Some(v) => tx
                .query_row(
                    "SELECT version, content_hash FROM skill_versions \
                     WHERE org_id = ?1 AND name = ?2 AND version = ?3",
                    params![org, name, v],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?,
            None => tx
                .query_row(
                    "SELECT version, content_hash FROM skill_versions WHERE org_id = ?1 AND name = ?2 \
                     ORDER BY version DESC LIMIT 1",
                    params![org, name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?,
        };
        let Some((pin, hash)) = found else {
            return Err(match pin {
                Some(v) => UaError::not_found(format!("unknown version {v} for skill {name:?}")),
                None => UaError::not_found(format!("skill {name:?} has no published version yet")),
            });
        };
        // The skill rides into the harness of every node of this agent or
        // profile: a human approves the assignment of this content first.
        // The payload binds the organization, so a pass is never consumed
        // across organizations.
        let payload = json!({
            "action": "assign",
            "org_id": org,
            "skill_name": name,
            "target_type": ttype,
            "target": target,
            "version": pin,
            "content_hash": hash,
        });
        if let Some(id) = gate(tx, ctx, &payload)? {
            return Ok(Err(id));
        }
        let now = ua_core::time::now();
        tx.execute(
            "INSERT INTO skill_assignments (org_id, skill_name, target_type, target, pinned_version, assigned_by, \
             assigned_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) \
             ON CONFLICT(org_id, skill_name, target_type, target) DO UPDATE SET \
             pinned_version = excluded.pinned_version, assigned_by = excluded.assigned_by, \
             assigned_at = excluded.assigned_at",
            params![org, name, ttype, target, pin, who, now],
        )?;
        // ORG-EVENT-DEFAULT: use the assignment's organization once callers
        // can resolve to other organizations and org_guard allows it.
        ledger::append(
            tx,
            EventInput::new(ua_core::DEFAULT_ORG,
                "skill.assigned",
                json!({ "name": name, "target_type": ttype, "target": target, "version": pin }),
            )
            .by(who.clone()),
        )?;
        let row = tx.query_row(
            &format!(
                "SELECT {ASSIGN_COLS} FROM skill_assignments \
                 WHERE org_id = ?1 AND skill_name = ?2 AND target_type = ?3 AND target = ?4"
            ),
            params![org, name, ttype, target],
            assignment_row,
        )?;
        Ok(Ok(json!({ "assignment": row })))
    })
    .and_then(pending)
}

fn unassign(ctx: &ToolCtx, p: AssignParams) -> UaResult<Value> {
    let who = operator(ctx, "unassigning a skill")?;
    unassign_as(ctx, who, p)
}

/// `unassign` for `who`, an operator of the caller's organization.
fn unassign_as(ctx: &ToolCtx, who: String, p: AssignParams) -> UaResult<Value> {
    let name = check_name(p.skill_name.as_deref().or(p.name.as_deref()).unwrap_or_default())?;
    let ttype = check_target_type(p.target_type.as_deref())?;
    let target = p.target.trim().to_string();
    if target.is_empty() {
        return Err(UaError::invalid("target is required"));
    }
    // Unassigning is idempotent and also clears a profile's rows stored
    // under its legacy name.
    let targets = if ttype == "profile" { profile_keys(&target) } else { vec![target.clone()] };
    let org = ctx.caller.org_id.as_str();
    ctx.hub
        .db()
        .write(|tx| {
            let mut present = 0;
            for t in &targets {
                present += tx.query_row(
                    "SELECT COUNT(*) FROM skill_assignments \
                     WHERE org_id = ?1 AND skill_name = ?2 AND target_type = ?3 AND target = ?4",
                    params![org, name, ttype, t],
                    |r| r.get::<_, i64>(0),
                )?;
            }
            if present == 0 {
                return Ok(Ok(json!({ "removed": false })));
            }
            // Removing a skill changes what every node of the target is served:
            // a human approves it too.
            let payload = json!({
                "action": "unassign",
                "org_id": org,
                "skill_name": name,
                "target_type": ttype,
                "target": target,
            });
            if let Some(id) = gate(tx, ctx, &payload)? {
                return Ok(Err(id));
            }
            let mut removed = 0;
            for t in &targets {
                removed += tx.execute(
                    "DELETE FROM skill_assignments \
                     WHERE org_id = ?1 AND skill_name = ?2 AND target_type = ?3 AND target = ?4",
                    params![org, name, ttype, t],
                )?;
            }
            if removed > 0 {
                // ORG-EVENT-DEFAULT: use the assignment's organization once callers
                // can resolve to other organizations and org_guard allows it.
                ledger::append(
                    tx,
                    EventInput::new(
                        ua_core::DEFAULT_ORG,
                        "skill.unassigned",
                        json!({ "name": name, "target_type": ttype, "target": target }),
                    )
                    .by(who.clone()),
                )?;
            }
            Ok(Ok(json!({ "removed": removed > 0 })))
        })
        .and_then(pending)
}

fn resolve_action(ctx: &ToolCtx, p: ResolveParams) -> UaResult<Value> {
    let who = author(ctx)?;
    let label = p.agent_label.trim().to_string();
    if label != who
        && !Authz::new(ctx.hub.cfg()).holds(
            &ctx.caller,
            &[Authority::Operator, Authority::LifecycleOperator],
            &ctx.caller.org_id,
        )
    {
        return Err(UaError::denied(
            "not_own_agent",
            "resolve shows the caller's own skills; an operator may resolve any agent's",
        ));
    }
    let profile = match p.profile.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(profile_target(raw)?),
        None if label.is_empty() => None,
        None => {
            Some(crate::sessions::default_profile(&ctx.hub, &ctx.caller.org_id, &label).as_str().to_string())
        }
    };
    let skills = ctx.hub.db().read(|c| resolve(c, &ctx.caller.org_id, &label, profile.as_deref()))?;
    let skills: Vec<Value> = skills
        .into_iter()
        .map(|s| {
            json!({
                "name": s.name,
                "version": s.version,
                "hash": s.hash,
                "via": s.via,
                "content": s.content.chars().take(CONTENT_CAP).collect::<String>(),
            })
        })
        .collect();
    Ok(json!({ "agent_label": label, "profile": profile, "skills": skills }))
}

fn drift(ctx: &ToolCtx, p: DriftParams) -> UaResult<Value> {
    let (root, _) = workspace_target(ctx, &p.surface_dir)?;
    if !is_real_dir(&root) {
        return Err(UaError::invalid(format!("not a directory: {:?}", p.surface_dir)));
    }
    let mut on_disk: BTreeMap<String, String> = BTreeMap::new();
    let mut entries = 0;
    let mut dirs = Vec::new();
    for e in std::fs::read_dir(&root)
        .map_err(|e| UaError::invalid(format!("cannot read {:?}: {e}", p.surface_dir)))?
    {
        let Ok(e) = e else { continue };
        entries += 1;
        if entries > MAX_DRIFT_ENTRIES {
            return Err(UaError::invalid(format!(
                "drift scan exceeds the {MAX_DRIFT_ENTRIES}-entry work limit"
            )));
        }
        // No symlink is followed: neither a linked skill directory nor a
        // linked SKILL.md counts.
        let path = e.path();
        if is_real_dir(&path) && is_regular_file(&path.join("SKILL.md")) {
            dirs.push(path);
            if dirs.len() > MAX_DRIFT_SKILLS {
                return Err(UaError::invalid(format!(
                    "drift scan exceeds the {MAX_DRIFT_SKILLS}-skill directory limit"
                )));
            }
        }
    }
    dirs.sort();
    for d in dirs {
        let text = read_bounded(&d.join("SKILL.md"))?;
        on_disk.insert(d.file_name().unwrap_or_default().to_string_lossy().into_owned(), content_hash(&text));
    }
    let label = p.agent_label.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let profile = match (p.profile.as_deref().map(str::trim).filter(|s| !s.is_empty()), &label) {
        (Some(raw), _) => Some(profile_target(raw)?),
        (None, Some(l)) => {
            Some(crate::sessions::default_profile(&ctx.hub, &ctx.caller.org_id, l).as_str().to_string())
        }
        (None, None) => None,
    };
    // The registry side: every skill's latest version, and with an agent the
    // versions it resolves to (pins honoured).
    let org = ctx.caller.org_id.as_str();
    let (all_latest, resolved) = ctx.hub.db().read(|c| {
        let mut stmt = c.prepare(
            "SELECT sv.name, sv.version, sv.content_hash, sv.package_manifest, sv.content FROM skill_versions sv \
             JOIN (SELECT name, MAX(version) AS version FROM skill_versions WHERE org_id = ?1 GROUP BY name) latest \
             ON sv.name = latest.name AND sv.version = latest.version WHERE sv.org_id = ?1",
        )?;
        let rows = stmt
            .query_map([org], |r| {
                let name: String = r.get(0)?;
                let version: i64 = r.get(1)?;
                let hash: String = r.get(2)?;
                let manifest: Option<String> = r.get(3)?;
                let content: String = r.get(4)?;
                Ok((name, version, hash, manifest, content))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let resolved = match &label {
            Some(l) => Some(resolve(c, org, l, profile.as_deref())?),
            None => None,
        };
        Ok((rows, resolved))
    })?;
    // The hash a SKILL.md-only copy on disk is compared with: the version's
    // SKILL.md hash (for an imported package, its SKILL.md member's).
    let md_hash = |hash: &str, manifest: Option<&str>, content: &str| -> String {
        if manifest.is_some() { content_hash(content) } else { hash.to_string() }
    };
    let latest_all: BTreeMap<String, (i64, String)> =
        all_latest.iter().map(|(n, v, h, m, c)| (n.clone(), (*v, md_hash(h, m.as_deref(), c)))).collect();
    let scoped = resolved.is_some();
    let latest: BTreeMap<String, (i64, String)> = match &resolved {
        Some(list) => list.iter().map(|s| (s.name.clone(), (s.version, content_hash(&s.content)))).collect(),
        None => latest_all.clone(),
    };
    let mut names: BTreeSet<String> = on_disk.keys().cloned().collect();
    names.extend(latest.keys().cloned());
    let (mut missing, mut stale, mut unregistered, mut unassigned, mut synced) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for name in names {
        let disk = on_disk.get(&name);
        let reg = latest.get(&name);
        match (disk, reg) {
            (None, Some((v, _))) => missing.push(json!({ "name": name, "registry_version": v })),
            (None, None) => {}
            (Some(h), None) => match (scoped, latest_all.get(&name)) {
                (true, Some((v, _))) => {
                    unassigned.push(json!({ "name": name, "on_disk_hash": h, "registry_version": v }));
                }
                _ => unregistered.push(json!({ "name": name, "on_disk_hash": h })),
            },
            (Some(h), Some((v, rh))) if h != rh => stale.push(json!({
                "name": name, "on_disk_hash": h, "registry_hash": rh, "registry_version": v,
            })),
            (Some(_), Some((v, _))) => synced.push(json!({ "name": name, "version": v })),
        }
    }
    Ok(json!({
        "root": p.surface_dir,
        "comparison": if label.is_some() { "resolved_assignments" } else { "latest_published" },
        "missing": missing,
        "stale": stale,
        "unregistered": unregistered,
        "unassigned": unassigned,
        "synced": synced,
    }))
}

async fn skill_registry(ctx: ToolCtx, a: SkillRegistryArgs) -> UaResult<Value> {
    let raw = a.action.trim().to_ascii_lowercase();
    let action = crate::routes::action_of("skill_registry", Some(&a.action))?;
    blocking(move || match action {
        "publish" => publish(&ctx, params(a.params)?),
        "list" => list(&ctx, params(a.params)?),
        "get" => get(&ctx, params(a.params)?),
        "assign" => assign(&ctx, params(a.params)?),
        "unassign" => unassign(&ctx, params(a.params)?),
        "resolve" => resolve_action(&ctx, params(a.params)?),
        "drift" => drift(&ctx, params(a.params)?),
        "catalog" | "install" | "team_install" | "starter_preview" | "starter_install" => {
            Err(UaError::invalid(format!("action {raw:?} (the skill catalog) is not ported to this hub")))
        }
        "source_" => {
            Err(UaError::invalid(format!("action {raw:?} (git skill sources) is not ported to this hub")))
        }
        other => Err(crate::routes::unhandled("skill_registry", other)),
    })
    .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "skill_registry",
            "The skills registry: immutable content-hash versions of agent skills, assigned to an agent label or a \
             profile and pinned to the approved version. publish, assign and unassign are operator actions, each \
             behind a one-time human approval. Actions: publish {name, path} (review a SKILL.md-only skill in the \
             workspace, stage the hub's copy and ask for approval; refused when skill_review finds a high-severity \
             issue, including permission front matter or hidden text), publish {staging_id} (version the approved \
             staged copy), list {name?}, get {name, version?}, assign {skill_name, target, target_type: \
             agent|profile, version?} (an agent assignment wins over a profile one), unassign {skill_name, target, \
             target_type}, resolve {agent_label, profile?} (own skills, or any agent's for an operator), drift \
             {surface_dir, agent_label?, profile?} (read-only: missing, stale, unregistered, unassigned and synced \
             skills). The harness config bundle served to a node carries the skills resolved for its agent.",
            skill_registry,
        )
        .gates_in_handler()
        .family("skills"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_kebab_case() {
        assert!(valid_name("review-diff"));
        assert!(valid_name("a1"));
        for bad in ["", "-a", "a-", "a--b", "A", "a_b", &"x".repeat(65)] {
            assert!(!valid_name(bad), "{bad}");
        }
    }

    #[test]
    fn frontmatter_is_read() {
        let fm = frontmatter("---\nname: x\ndescription: Does a thing.\n---\nbody\n").unwrap();
        assert_eq!(fm["description"], "Does a thing.");
        assert!(frontmatter("no front matter").is_none());
    }

    /// Organization B's write paths (stage, publish, assign, unassign) and the
    /// organization binding of their approvals. `ua_org::authz` refuses B's
    /// callers operator authority until memberships exist, so the tool
    /// entry points cannot reach these paths for B; this test calls the
    /// functions behind the operator check with an organization-B caller,
    /// and approves B's requests in SQL (no human can approve outside the
    /// default organization yet).
    #[tokio::test]
    async fn organization_b_writes_and_approvals_bind_its_organization() {
        use ua_core::{ActorKind, Caller, Profile, identity::Transport};
        let ws = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let mut cfg = ua_core::Config::for_home(home.path());
        cfg.human_identities = vec!["operator".into()];
        cfg.workspace = Some(ws.path().to_path_buf());
        let hub = crate::Hub::in_memory(cfg).unwrap();
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES \
                     ('org-b', 'org-b', 'Org B', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                    [],
                )?;
                Ok(())
            })
            .unwrap();
        let dir = ws.path().join("skills").join("review-diff");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: review-diff\ndescription: Check a change for correctness. Use when asked to review a \
             diff before it lands.\n---\n\n# Check a change\n\nRead the whole diff.\n",
        )
        .unwrap();
        let ctx = |org: &str| ToolCtx {
            hub: hub.clone(),
            caller: Caller {
                label: "ops-bot".into(),
                kind: ActorKind::Agent,
                profile: Profile::Developer,
                enforce_profile: true,
                session_key: Some("s1".into()),
                transport: Transport::Mcp,
                org_id: org.into(),
            },
        };
        let (b, a) = (ctx("org-b"), ctx(ua_core::DEFAULT_ORG));
        let who = "ops-bot";
        let approval = |id: i64| -> (String, Value) {
            hub.db()
                .read(move |c| {
                    let (org, payload): (String, String) =
                        c.query_row("SELECT org_id, payload FROM approvals WHERE id = ?1", [id], |r| {
                            Ok((r.get(0)?, r.get(1)?))
                        })?;
                    Ok((org, serde_json::from_str(&payload)?))
                })
                .unwrap()
        };
        let approve = |id: i64| {
            hub.db()
                .write(move |tx| {
                    tx.execute(
                        "UPDATE approvals SET status = 'approved', resolved_by = 'operator', resolved_at = ?2, \
                         updated_at = ?2 WHERE id = ?1",
                        params![id, ua_core::time::now()],
                    )?;
                    Ok(())
                })
                .unwrap()
        };
        let parked = |r: UaResult<Value>| match r {
            Err(UaError::ApprovalRequired { approval_id, .. }) => approval_id,
            other => panic!("expected an approval: {other:?}"),
        };
        let params_of = |target: &str| AssignParams {
            skill_name: Some("review-diff".into()),
            name: None,
            target: target.into(),
            target_type: None,
            version: None,
            author: None,
        };

        // B stages: the request is B's and its payload binds B.
        let staged_b = stage(&b, who, Some("review-diff".into()), "skills/review-diff").unwrap();
        let b_req = staged_b["approval_id"].as_i64().unwrap();
        let (org, payload) = approval(b_req);
        assert_eq!((org.as_str(), payload["org_id"].as_str()), ("org-b", Some("org-b")), "{payload}");
        let b_staging = staged_b["staging_id"].as_str().unwrap().to_string();

        // The default organization stages identical content under the same
        // label: it never reuses B's unpublished staged row.
        let staged_a = stage(&a, who, Some("review-diff".into()), "skills/review-diff").unwrap();
        assert_ne!(staged_a["staging_id"].as_str().unwrap(), b_staging, "{staged_a}");
        let (org, payload) = approval(staged_a["approval_id"].as_i64().unwrap());
        assert_eq!((org.as_str(), payload["org_id"].as_str()), ("default", Some("default")), "{payload}");

        // B publishes its approved staged copy.
        approve(b_req);
        let published = publish_staged(&b, who, &b_staging).unwrap();
        assert_eq!(
            (published["idempotent"].as_bool(), published["skill"]["version"].as_i64()),
            (Some(false), Some(1))
        );
        let versions = |org: &'static str| {
            hub.db()
                .read(move |c| {
                    Ok(c.query_row("SELECT COUNT(*) FROM skill_versions WHERE org_id = ?1", [org], |r| {
                        r.get::<_, i64>(0)
                    })?)
                })
                .unwrap()
        };
        assert_eq!((versions("org-b"), versions("default")), (1, 0));

        // Identical content staged in the default organization after B
        // published it is not idempotent: B's version is not the default's.
        let again = stage(&a, who, Some("review-diff".into()), "skills/review-diff").unwrap();
        assert_ne!(again["idempotent"], true, "{again}");
        assert_eq!(again["status"], "approval_pending", "{again}");

        // B assigns and unassigns; each approval binds B.
        let req = parked(assign_as(&b, who.into(), params_of("builder-1")));
        assert_eq!(approval(req).1["org_id"], "org-b");
        approve(req);
        let assigned = assign_as(&b, who.into(), params_of("builder-1")).unwrap();
        assert_eq!(assigned["assignment"]["pinned_version"], 1, "{assigned}");
        let req = parked(unassign_as(&b, who.into(), params_of("builder-1")));
        assert_eq!(approval(req).1["org_id"], "org-b");
        approve(req);
        assert_eq!(unassign_as(&b, who.into(), params_of("builder-1")).unwrap()["removed"], true);
    }
}
