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
//!   directory with `SKILL.md` and supporting files such as `scripts/`,
//!   `templates/`, `references/`) in the workspace, copy every file into the
//!   hub's staging table and ask for a human approval that shows `SKILL.md` in
//!   full plus the canonical package manifest and the text of every supporting
//!   text file; `publish` {staging_id}: after approval, version that staged
//!   copy (the workspace is never read again);
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
//! approval bound to the content (publish: the staged `SKILL.md`, package
//! manifest, supporting text files and review findings; assign: target, pinned
//! version and hash; unassign: the target). `skill_review` refuses
//! permission-bearing front matter and hidden text; supporting text files are
//! screened for hidden Unicode and credential material, executable bits are
//! never honoured, and nothing executes at publish or install time.
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
//! Multi-file skill packages reuse the Python hub's canonical `package_manifest`
//! (schema version 1) and base64 `package_payload` format; every member's hash
//! and size are verified on read (`get`, `resolve`, and harness config bundles),
//! and imported Python-hub packages continue to verify. See `docs/skills.md`.
//!
//! Not ported: the catalog and team installs, and git skill sources.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use icu_normalizer::ComposingNormalizer;
use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ua_core::{Profile, UaError, UaResult};
use ua_store::{EventInput, Procedure, SchemaPart, ledger};

use super::agents::verified;
use super::audit::rules::{check_private_key, check_secrets};
use super::harness_config::render::{content_hash, py_dumps};
use super::skills::hidden_chars;
use crate::approvals::{self, GateOutcome};
use crate::families::plans::ledger_text;
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

/// `skill_registry.v3.packages`: add `package_manifest` and `package_payload`
/// columns to `skill_publish_staging` so multi-file packages are copied into
/// the hub at staging time and never re-read from the workspace.
pub const PACKAGES_SCHEMA: SchemaPart = SchemaPart {
    name: "skill_registry.v3.packages",
    sql: "
ALTER TABLE skill_publish_staging ADD COLUMN package_manifest TEXT;
ALTER TABLE skill_publish_staging ADD COLUMN package_payload TEXT;
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
/// Characters of each skill's `SKILL.md` preview a `resolve` answer carries in `content`.
const CONTENT_CAP: usize = 4000;
/// Maximum byte size of `SKILL.md`.
pub const MAX_SKILL_FILE_BYTES: usize = 64 * 1024;
/// Maximum number of files in a skill package (including `SKILL.md`).
pub const MAX_PACKAGE_FILES: usize = 128;
/// Maximum directory entries visited while walking a skill package.
pub const MAX_PACKAGE_ENTRIES: usize = 512;
/// Maximum byte size of a single supporting file in a skill package.
pub const MAX_PACKAGE_FILE_BYTES: usize = 512 * 1024;
/// Maximum total raw bytes across every file in a skill package.
pub const MAX_PACKAGE_BYTES: usize = 2 * 1024 * 1024;
/// Maximum length in bytes of a relative file path inside a skill package.
pub const MAX_PACKAGE_PATH: usize = 240;
/// Maximum path segment depth inside a skill package (e.g. `a/b/...`).
pub const MAX_PACKAGE_DEPTH: usize = 8;
/// Maximum total bytes of supporting UTF-8 text files shown in a publish
/// approval payload. Staging fails closed above this cap so a human never
/// approves text that was truncated out of the approval payload.
pub const MAX_APPROVAL_TEXT_BYTES: usize = 256 * 1024;
/// Canonical manifest schema version (matches the Python hub).
pub const PACKAGE_SCHEMA_VERSION: u64 = 1;
/// File mode recorded for every file published by this hub (`0o644`).
/// Executable bits are never honoured.
const MODE_FILE: u64 = 0o644;
/// Supporting-file mode accepted when verifying packages imported from the
/// Python hub (`0o755`), never honoured as executable and never accepted on
/// `SKILL.md`.
const MODE_EXEC_IMPORTED: u64 = 0o755;
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

// --- packages & rows --------------------------------------------------------------

/// One verified file member of a skill package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackageMember {
    pub path: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub mode: u64,
}

impl PackageMember {
    pub fn text(&self) -> Option<&str> {
        if self.bytes.contains(&0) { None } else { std::str::from_utf8(&self.bytes).ok() }
    }

    pub fn to_wire_json(&self) -> Value {
        if let Some(text) = self.text() {
            json!({
                "path": self.path,
                "bytes": self.bytes.len(),
                "sha256": self.sha256,
                "encoding": "utf-8",
                "content": text,
            })
        } else {
            json!({
                "path": self.path,
                "bytes": self.bytes.len(),
                "sha256": self.sha256,
                "encoding": "base64",
                "content": BASE64.encode(&self.bytes),
            })
        }
    }

    pub fn to_approval_json(&self) -> Value {
        if let Some(text) = self.text() {
            json!({
                "path": self.path,
                "bytes": self.bytes.len(),
                "sha256": self.sha256,
                "encoding": "utf-8",
                "content": text,
            })
        } else {
            json!({
                "path": self.path,
                "bytes": self.bytes.len(),
                "sha256": self.sha256,
                "encoding": "binary",
                "content": Value::Null,
            })
        }
    }
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical relative member path inside a skill package: no absolute paths,
/// no `..`/`.` segments, no hidden files or directories (leading `.`), no
/// backslashes, colons or control characters, within depth and length limits.
pub(crate) fn validate_package_path(value: &str) -> UaResult<String> {
    if value.is_empty()
        || value.len() > MAX_PACKAGE_PATH
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains(':')
        || value.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(UaError::invalid(format!("unsafe supporting file path {value:?}")));
    }
    let parts: Vec<&str> = value.split('/').collect();
    if parts.len() > MAX_PACKAGE_DEPTH {
        return Err(UaError::invalid(format!(
            "supporting file path {value:?} exceeds the {MAX_PACKAGE_DEPTH}-level depth limit"
        )));
    }
    for part in &parts {
        if part.is_empty() || *part == "." || *part == ".." {
            return Err(UaError::invalid(format!("unsafe supporting file path {value:?}")));
        }
        if part.starts_with('.') {
            return Err(UaError::invalid(format!(
                "hidden file or directory {value:?} is not allowed in a skill package"
            )));
        }
    }
    Ok(value.to_string())
}

fn portable_collision_key(path: &str) -> String {
    ComposingNormalizer::new_nfc().normalize(path).to_lowercase()
}

pub(crate) fn build_manifest(members: &BTreeMap<String, PackageMember>) -> Value {
    let files: Vec<Value> = members
        .values()
        .map(|m| {
            json!({
                "path": m.path,
                "sha256": m.sha256,
                "bytes": m.bytes.len(),
                "mode": m.mode,
            })
        })
        .collect();
    json!({
        "schema_version": PACKAGE_SCHEMA_VERSION,
        "files": files,
    })
}

/// Version content hash: for a `SKILL.md`-only package, the SHA-256 of
/// `SKILL.md` (preserving single-file compatibility); for a multi-file
/// package, the SHA-256 of the canonical JSON manifest (`py_dumps`).
pub(crate) fn package_hash(manifest: &Value) -> String {
    let files = manifest["files"].as_array();
    if let Some(files) = files
        && files.len() == 1
        && files[0]["path"] == "SKILL.md"
        && let Some(sha) = files[0]["sha256"].as_str()
    {
        return sha.to_string();
    }
    content_hash(&py_dumps(manifest, None))
}

fn encode_payload(members: &BTreeMap<String, PackageMember>) -> String {
    let mut map = Map::new();
    for (path, member) in members {
        map.insert(path.clone(), Value::String(BASE64.encode(&member.bytes)));
    }
    py_dumps(&Value::Object(map), None)
}

const LIST_COLS: &str =
    "id, name, version, content_hash, source, published_by, published_at, package_manifest";
const FULL_COLS: &str = "id, name, version, content_hash, source, published_by, published_at, package_manifest, content, package_payload";

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

struct RawVersionRow {
    public: Value,
    content: String,
    content_hash: String,
    manifest_raw: Option<String>,
    payload_raw: Option<String>,
}

fn raw_version_row(r: &Row<'_>) -> rusqlite::Result<RawVersionRow> {
    let public = version_row(r)?;
    Ok(RawVersionRow {
        public,
        content_hash: r.get(3)?,
        manifest_raw: r.get(7)?,
        content: r.get(8)?,
        payload_raw: r.get(9)?,
    })
}

/// Verify a persisted skill package (both `SKILL.md` and every supporting file)
/// against its stored manifest and version hash, returning all verified members.
/// Legacy single-file rows without a manifest verify `SKILL.md` directly.
fn verify_and_decode(
    content: &str,
    stored_hash: &str,
    manifest_raw: Option<&str>,
    payload_raw: Option<&str>,
) -> UaResult<Vec<PackageMember>> {
    let bad = || UaError::conflict("skill content hash does not match the reviewed registry version");
    let skill_md_hash = content_hash(content);
    let Some(m_str) = manifest_raw else {
        if content.len() > MAX_SKILL_FILE_BYTES || skill_md_hash != stored_hash {
            return Err(bad());
        }
        return Ok(vec![PackageMember {
            path: "SKILL.md".into(),
            bytes: content.as_bytes().to_vec(),
            sha256: skill_md_hash,
            mode: MODE_FILE,
        }]);
    };
    if m_str.len() > MAX_PACKAGE_FILES * 1024 {
        return Err(bad());
    }
    let p_str = payload_raw.ok_or_else(bad)?;
    if p_str.len() > MAX_PACKAGE_BYTES * 2 {
        return Err(bad());
    }
    let manifest: Value = serde_json::from_str(m_str).map_err(|_| bad())?;
    let payload: Map<String, Value> = serde_json::from_str(p_str).map_err(|_| bad())?;
    if manifest["schema_version"].as_u64() != Some(PACKAGE_SCHEMA_VERSION) {
        return Err(bad());
    }
    let items = manifest["files"].as_array().ok_or_else(bad)?;
    if items.is_empty() || items.len() > MAX_PACKAGE_FILES {
        return Err(bad());
    }
    let mut members: BTreeMap<String, PackageMember> = BTreeMap::new();
    let mut portable_names: BTreeSet<String> = BTreeSet::new();
    let mut total = 0usize;
    for item in items {
        let raw_path = item["path"].as_str().ok_or_else(bad)?;
        let path = validate_package_path(raw_path).map_err(|_| bad())?;
        if !portable_names.insert(portable_collision_key(&path)) || members.contains_key(&path) {
            return Err(bad());
        }
        let mode = item["mode"].as_u64().ok_or_else(bad)?;
        let mode_ok = if path == "SKILL.md" {
            mode == MODE_FILE
        } else {
            mode == MODE_FILE || mode == MODE_EXEC_IMPORTED
        };
        if !mode_ok {
            return Err(bad());
        }
        let expected_sha = item["sha256"].as_str().ok_or_else(bad)?;
        let expected_bytes = item["bytes"].as_u64().ok_or_else(bad)?;
        let b64 = payload.get(&path).and_then(Value::as_str).ok_or_else(bad)?;
        let bytes = BASE64.decode(b64).map_err(|_| bad())?;
        let cap = if path == "SKILL.md" { MAX_SKILL_FILE_BYTES } else { MAX_PACKAGE_FILE_BYTES };
        total = total.saturating_add(bytes.len());
        if bytes.len() > cap || bytes.len() as u64 != expected_bytes || total > MAX_PACKAGE_BYTES {
            return Err(bad());
        }
        let actual_sha = sha256_bytes(&bytes);
        if actual_sha != expected_sha {
            return Err(bad());
        }
        members.insert(path.clone(), PackageMember { path, bytes, sha256: actual_sha, mode });
    }
    if payload.len() != members.len() {
        return Err(bad());
    }
    let Some(md) = members.get("SKILL.md") else {
        return Err(bad());
    };
    if md.bytes != content.as_bytes() {
        return Err(bad());
    }
    let rebuilt = build_manifest(&members);
    if py_dumps(&rebuilt, None) != py_dumps(&manifest, None) || package_hash(&rebuilt) != stored_hash {
        return Err(bad());
    }
    Ok(members.into_values().collect())
}

struct LoadedVersion {
    public: Value,
    members: Vec<PackageMember>,
}

/// A version of `name` in `org` (the latest when `version` is `None`),
/// verified end-to-end across every package member. Another organization's
/// version reads as missing; a tampered stored file is refused.
fn load_version(
    c: &Connection,
    org: &str,
    name: &str,
    version: Option<i64>,
) -> UaResult<Option<LoadedVersion>> {
    let raw = match version {
        Some(v) => c
            .query_row(
                &format!(
                    "SELECT {FULL_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 AND version = ?3"
                ),
                params![org, name, v],
                raw_version_row,
            )
            .optional()?,
        None => c
            .query_row(
                &format!(
                    "SELECT {FULL_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 \
                     ORDER BY version DESC LIMIT 1"
                ),
                params![org, name],
                raw_version_row,
            )
            .optional()?,
    };
    let Some(raw) = raw else {
        return Ok(None);
    };
    let members = verify_and_decode(
        &raw.content,
        &raw.content_hash,
        raw.manifest_raw.as_deref(),
        raw.payload_raw.as_deref(),
    )?;
    let mut public = raw.public;
    public["files"] = Value::Array(members.iter().map(PackageMember::to_wire_json).collect());
    Ok(Some(LoadedVersion { public, members }))
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
    pub package_manifest: Option<Value>,
    pub files: Vec<PackageMember>,
    /// `agent` or `profile`: which assignment matched.
    pub via: &'static str,
}

/// The skills assigned to `agent` in `org` directly or through `profile`: direct
/// assignments first (each source sorted by name), a direct one winning over
/// a profile one of the same skill, at most [`MAX_RESOLVED_SKILLS`]. A pinned
/// version that is missing is skipped; a stored version whose hash or member
/// attestation fails is refused, never served.
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
        let Some(loaded) = load_version(c, org, &name, pin)? else { continue };
        let manifest = match &loaded.public["package_manifest"] {
            Value::Null => None,
            other => Some(other.clone()),
        };
        out.push(Resolved {
            version: loaded.public["version"].as_i64().unwrap_or_default(),
            hash: loaded.public["content_hash"].as_str().unwrap_or_default().to_string(),
            content: loaded.public["content"].as_str().unwrap_or_default().to_string(),
            package_manifest: manifest,
            files: loaded.members,
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

/// Append a skill registry event about a row of organization `org`.
///
/// ORG-EVENT-DEFAULT: the ledger row stays in the default organization (the
/// `org_guard` test admits no other value). For another organization the
/// caller passes the skill name, target, source path and content hash
/// through [`ledger_text`], so they are `null` there (a content hash is an
/// unsalted digest of the skill text, which a guess could confirm), and the
/// originator is the neutral `system`, never the acting label. Only the
/// version, the target type, the hub-generated staging id and timestamps
/// reach the default ledger.
fn emit(tx: &mut ua_store::WriteTx<'_>, org: &str, channel: &str, payload: Value, by: &str) -> UaResult<()> {
    ledger::append(
        tx,
        EventInput::new(ua_core::DEFAULT_ORG, channel, payload)
            .by(crate::approvals::ledger_originator(org, by)),
    )?;
    Ok(())
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
    // The hub workspace is the default organization's (see
    // `workspace::sandbox`): another organization reads nothing there.
    if ctx.caller.org_id != ua_core::DEFAULT_ORG {
        return Err(crate::families::workspace::workspace_org_unsupported());
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

/// Resolve the skill directory and workspace-relative `SKILL.md` path from a
/// publish target (either a `SKILL.md` file or a skill directory). Refuses
/// symlinks, missing `SKILL.md`, and publishing directly from the workspace
/// root.
fn skill_dir(target: &Path, rel: &str, shown: &str) -> UaResult<(PathBuf, String)> {
    let (dir, rel_dir) = if is_regular_file(target) {
        if target.file_name().is_none_or(|n| n != "SKILL.md") {
            return Err(UaError::invalid(format!("{shown:?} is a file but not a SKILL.md")));
        }
        let parent = target.parent().map(Path::to_path_buf).unwrap_or_default();
        let rel_dir = rel.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
        if rel_dir.is_empty() {
            return Err(UaError::invalid(
                "SKILL.md must live inside its own skill directory, not at the workspace root",
            ));
        }
        (parent, rel_dir)
    } else if is_real_dir(target) {
        if rel.is_empty() {
            return Err(UaError::invalid(
                "publish takes one skill directory inside the workspace, not the workspace root",
            ));
        }
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
    let rel_md = format!("{rel_dir}/SKILL.md");
    Ok((dir, rel_md))
}

/// Read a regular non-symlink file up to `cap` bytes without blocking on
/// special files or following a symlink swapped into place.
fn read_regular_nofollow(path: &Path, label: &str, cap: usize) -> UaResult<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| UaError::invalid(format!("{label} could not be read")))?;
    if meta.file_type().is_symlink() {
        return Err(UaError::invalid(format!("{label} is a symlink; symlinks are not followed")));
    }
    if !meta.file_type().is_file() {
        return Err(UaError::invalid(format!("{label} is a special file and cannot be packaged")));
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.raw_os_error() == Some(libc::ELOOP) {
            UaError::invalid(format!("{label} is a symlink; symlinks are not followed"))
        } else {
            UaError::invalid(format!("{label} could not be read"))
        }
    })?;
    let opened = file.metadata().map_err(|_| UaError::invalid(format!("{label} could not be read")))?;
    if !opened.is_file() {
        return Err(UaError::invalid(format!("{label} is a special file and cannot be packaged")));
    }
    let mut buf = Vec::new();
    (&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|_| UaError::invalid(format!("{label} could not be read")))?;
    if buf.len() > cap {
        return Err(UaError::invalid(format!("{label} exceeds the {cap}-byte limit")));
    }
    Ok(buf)
}

/// Capture every regular file inside `dir` (without following symlinks) into
/// an in-memory map keyed by canonical POSIX relative path. Every file is
/// recorded with mode `0o644` (executable bits on disk are never honoured).
fn capture_package(dir: &Path, shown: &str) -> UaResult<BTreeMap<String, PackageMember>> {
    if !is_real_dir(dir) {
        return Err(UaError::invalid(format!("{shown:?} is not a skill directory")));
    }
    let mut members: BTreeMap<String, PackageMember> = BTreeMap::new();
    let mut portable_names: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<(PathBuf, String)> = vec![(dir.to_path_buf(), String::new())];
    let mut entries_seen = 0usize;
    let mut total_bytes = 0usize;

    while let Some((cur_dir, rel_prefix)) = todo.pop() {
        let mut children: Vec<std::fs::DirEntry> = std::fs::read_dir(&cur_dir)
            .map_err(|_| UaError::invalid(format!("cannot read {shown:?}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| UaError::invalid(format!("cannot read {shown:?}")))?;
        children.sort_by_key(|e| e.file_name());

        for entry in children {
            entries_seen += 1;
            if entries_seen > MAX_PACKAGE_ENTRIES {
                return Err(UaError::invalid(format!(
                    "skill package exceeds the {MAX_PACKAGE_ENTRIES}-entry directory limit"
                )));
            }
            let file_name = entry
                .file_name()
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| UaError::invalid("skill package contains a non-UTF-8 file name"))?;
            let rel = if rel_prefix.is_empty() { file_name } else { format!("{rel_prefix}/{file_name}") };
            let rel = validate_package_path(&rel)?;
            if !portable_names.insert(portable_collision_key(&rel)) {
                return Err(UaError::invalid(format!(
                    "skill package refuses case-insensitive or Unicode path collision at {rel:?}"
                )));
            }
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)
                .map_err(|_| UaError::invalid(format!("cannot inspect {rel:?}")))?;
            if meta.file_type().is_symlink() {
                return Err(UaError::invalid(format!(
                    "supporting path {rel:?} is a symlink; symlinks are not followed"
                )));
            }
            if meta.file_type().is_dir() {
                todo.push((path, rel));
                continue;
            }
            if !meta.file_type().is_file() {
                return Err(UaError::invalid(format!(
                    "supporting path {rel:?} is a special file and cannot be packaged"
                )));
            }
            if members.len() >= MAX_PACKAGE_FILES {
                return Err(UaError::invalid(format!(
                    "skill package exceeds the {MAX_PACKAGE_FILES}-file limit"
                )));
            }
            let cap = if rel == "SKILL.md" { MAX_SKILL_FILE_BYTES } else { MAX_PACKAGE_FILE_BYTES };
            let bytes = read_regular_nofollow(&path, &rel, cap)?;
            total_bytes = total_bytes.saturating_add(bytes.len());
            if total_bytes > MAX_PACKAGE_BYTES {
                return Err(UaError::invalid(format!(
                    "skill package exceeds the {MAX_PACKAGE_BYTES}-byte total size limit"
                )));
            }
            let sha256 = sha256_bytes(&bytes);
            members.insert(rel.clone(), PackageMember { path: rel, bytes, sha256, mode: MODE_FILE });
        }
    }

    let Some(md) = members.get("SKILL.md") else {
        return Err(UaError::invalid(format!(
            "{shown:?} has no SKILL.md at its root; publish takes one skill directory or SKILL.md file"
        )));
    };
    if std::str::from_utf8(&md.bytes).is_err() {
        return Err(UaError::invalid("SKILL.md must be valid UTF-8"));
    }
    Ok(members)
}

/// Audit captured supporting files for credential material, hidden Unicode and
/// the approval review text cap. Returns any hidden-text findings (blocking
/// review) or refuses immediately on credentials or text cap overflow.
fn audit_supporting_files(members: &BTreeMap<String, PackageMember>) -> UaResult<Vec<Value>> {
    let mut findings = Vec::new();
    let mut text_bytes = 0usize;
    for (path, member) in members {
        if path == "SKILL.md" {
            continue;
        }
        let Some(text) = member.text() else {
            continue;
        };
        text_bytes = text_bytes.saturating_add(text.len());
        if text_bytes > MAX_APPROVAL_TEXT_BYTES {
            return Err(UaError::invalid(format!(
                "supporting text files exceed the {MAX_APPROVAL_TEXT_BYTES}-byte approval review limit"
            )));
        }
        if !check_secrets("skill-package-payload", text).is_empty()
            || !check_private_key(path, text).is_empty()
        {
            return Err(UaError::invalid(format!(
                "supporting file {path:?} contains credential material and cannot be published"
            )));
        }
        for (line, ch) in hidden_chars(text) {
            findings.push(json!({
                "rule": "SKILL-HIDDEN-TEXT",
                "severity": "high",
                "file": path,
                "line": line,
                "message": format!("hidden Unicode code point U+{:04X} in supporting file {path:?}", ch as u32),
            }));
        }
    }
    Ok(findings)
}

/// One staged publish: the hub's own copy of `SKILL.md` and every supporting
/// file, taken when the publish was requested. The approval shows and binds
/// this copy, and an approved publish versions it without reading the
/// workspace again.
struct Staged {
    id: String,
    name: String,
    content: String,
    content_hash: String,
    source: String,
    findings: Value,
    requested_by: String,
    published_version: Option<i64>,
    package_manifest: Option<String>,
    package_payload: Option<String>,
}

fn load_staged(c: &Connection, org: &str, id: &str) -> UaResult<Option<Staged>> {
    Ok(c.query_row(
        "SELECT id, name, content, content_hash, source, findings_json, requested_by, published_version, \
         package_manifest, package_payload \
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
                package_manifest: r.get(8)?,
                package_payload: r.get(9)?,
            })
        },
    )
    .optional()?)
}

/// What a publish approval shows and binds: the organization, the full staged
/// `SKILL.md` (at most 64 KiB), its hash, the review's findings, and for
/// staged packages the canonical manifest (every file's path, size, hash and
/// mode) plus every supporting file's full text (within `MAX_APPROVAL_TEXT_BYTES`).
fn staged_payload(org: &str, s: &Staged) -> UaResult<Value> {
    let members = verify_and_decode(
        &s.content,
        &s.content_hash,
        s.package_manifest.as_deref(),
        s.package_payload.as_deref(),
    )?;
    let mut payload = json!({
        "action": "publish",
        "org_id": org,
        "staging_id": s.id,
        "name": s.name,
        "content_hash": s.content_hash,
        "content": s.content,
        "review_findings": s.findings,
    });
    if let Some(m_str) = &s.package_manifest {
        let manifest: Value =
            serde_json::from_str(m_str).map_err(|_| UaError::conflict("staged skill manifest is corrupt"))?;
        let mut supporting_text = 0usize;
        let mut package_files = Vec::new();
        for member in &members {
            if member.path == "SKILL.md" {
                continue;
            }
            if let Some(text) = member.text() {
                supporting_text = supporting_text.saturating_add(text.len());
                if supporting_text > MAX_APPROVAL_TEXT_BYTES {
                    return Err(UaError::invalid(format!(
                        "supporting text files exceed the {MAX_APPROVAL_TEXT_BYTES}-byte approval review limit"
                    )));
                }
            }
            package_files.push(member.to_approval_json());
        }
        payload["package_manifest"] = manifest;
        payload["package_files"] = Value::Array(package_files);
    }
    Ok(payload)
}

fn existing_version(c: &Connection, org: &str, name: &str, hash: &str) -> UaResult<Option<Value>> {
    let raw = c
        .query_row(
            &format!(
                "SELECT {FULL_COLS} FROM skill_versions WHERE org_id = ?1 AND name = ?2 AND content_hash = ?3 \
                 ORDER BY version DESC LIMIT 1"
            ),
            params![org, name, hash],
            raw_version_row,
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    verify_and_decode(
        &raw.content,
        &raw.content_hash,
        raw.manifest_raw.as_deref(),
        raw.payload_raw.as_deref(),
    )?;
    let mut public = raw.public;
    if let Some(obj) = public.as_object_mut() {
        obj.remove("content");
    }
    Ok(Some(public))
}

/// `publish {name, path}`: review the skill, copy every file into the hub's
/// staging table and ask for the approval. It never publishes; after approval,
/// `publish {staging_id}` versions the staged copy without reading the
/// workspace again.
fn stage(ctx: &ToolCtx, who: &str, name: Option<String>, path: &str) -> UaResult<Value> {
    let name = check_name(name.as_deref().unwrap_or_default())?;
    let (target, rel) = workspace_target(ctx, path)?;
    let (dir, rel_md) = skill_dir(&target, &rel, path)?;
    let members = capture_package(&dir, path)?;
    let text = std::str::from_utf8(&members["SKILL.md"].bytes)
        .map_err(|_| UaError::invalid("SKILL.md must be valid UTF-8"))?
        .to_string();
    let support_findings = audit_supporting_files(&members)?;
    let mut review = super::skills::review_dirs(vec![dir.clone()], &dir, "info");
    if !support_findings.is_empty() {
        if let Some(arr) = review["findings"].as_array_mut() {
            arr.extend(support_findings.iter().cloned());
        }
        review["status"] = json!("fail");
    }
    if review["status"] == "fail" {
        return Ok(json!({ "ok": false, "blocked": true, "name": name, "review": review }));
    }
    // Re-check SKILL.md did not change while skill_review read it from disk.
    let md_after = read_regular_nofollow(&dir.join("SKILL.md"), "SKILL.md", MAX_SKILL_FILE_BYTES)?;
    if md_after != members["SKILL.md"].bytes {
        return Err(UaError::conflict("skill changed while it was being reviewed; retry publish"));
    }
    if let Some(fm) = frontmatter(&text)
        && let Some(fm_name) = fm.get("name").and_then(Value::as_str)
        && fm_name != name
    {
        return Err(UaError::invalid(format!(
            "publish name {name:?} does not match the SKILL.md frontmatter name {fm_name:?}"
        )));
    }
    let manifest = build_manifest(&members);
    let manifest_json = py_dumps(&manifest, None);
    let payload_json = encode_payload(&members);
    let hash = package_hash(&manifest);
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
                     findings_json, requested_by, created_at, package_manifest, package_payload) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    params![
                        org,
                        id,
                        name,
                        text,
                        hash,
                        rel_md,
                        json!(findings).to_string(),
                        who,
                        ua_core::time::now(),
                        manifest_json,
                        payload_json
                    ],
                )?;
                id
            }
        };
        let staged = load_staged(tx, org, &id)?.ok_or_else(|| UaError::internal("staged row vanished"))?;
        let approval_payload = staged_payload(org, &staged)?;
        let state = approvals::request(tx, &cfg, &caller, GATE, &approval_payload)?;
        Ok(json!({
            "ok": false,
            "status": format!("approval_{}", state.status()),
            "approval_id": state.approval_id(),
            "staging_id": id,
            "name": name,
            "content_hash": hash,
            "package_manifest": manifest,
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
            let approval_payload = staged_payload(org, &staged)?;
            if let Some(skill) = existing_version(tx, org, &staged.name, &staged.content_hash)? {
                return Ok(Ok(json!({ "ok": true, "idempotent": true, "skill": skill })));
            }
            if staged.published_version.is_some() {
                return Err(UaError::conflict("this staged publish was already used"));
            }
            if let Some(approval) = gate(tx, ctx, &approval_payload)? {
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
                 published_by, published_at, package_manifest, package_payload) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    org,
                    staged.name,
                    next,
                    staged.content_hash,
                    staged.source,
                    staged.content,
                    who,
                    now,
                    staged.package_manifest,
                    staged.package_payload
                ],
            )?;
            tx.execute(
                "UPDATE skill_publish_staging SET published_version = ?3 WHERE org_id = ?1 AND id = ?2",
                params![org, staged.id, next],
            )?;
            emit(
                tx,
                org,
                "skill.published",
                json!({
                    "name": ledger_text(org, &staged.name),
                    "version": next,
                    "content_hash": ledger_text(org, &staged.content_hash),
                    "source": ledger_text(org, &staged.source),
                    "staging_id": staged.id,
                    "published_at": now,
                }),
                who,
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
        .map(|loaded| loaded.public)
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
        emit(
            tx,
            org,
            "skill.assigned",
            json!({
                "name": ledger_text(org, &name),
                "target_type": ttype,
                "target": ledger_text(org, &target),
                "version": pin,
            }),
            &who,
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
                emit(
                    tx,
                    org,
                    "skill.unassigned",
                    json!({
                        "name": ledger_text(org, &name),
                        "target_type": ttype,
                        "target": ledger_text(org, &target),
                    }),
                    &who,
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
                "package_manifest": s.package_manifest,
                "files": s.files.iter().map(PackageMember::to_wire_json).collect::<Vec<_>>(),
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
        let name = d.file_name().unwrap_or_default().to_string_lossy().into_owned();
        let members = capture_package(&d, &name)?;
        let hash = package_hash(&build_manifest(&members));
        on_disk.insert(name, hash);
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
            "SELECT sv.name, sv.version, sv.content_hash FROM skill_versions sv \
             JOIN (SELECT name, MAX(version) AS version FROM skill_versions WHERE org_id = ?1 GROUP BY name) latest \
             ON sv.name = latest.name AND sv.version = latest.version WHERE sv.org_id = ?1",
        )?;
        let rows = stmt
            .query_map([org], |r| {
                let name: String = r.get(0)?;
                let version: i64 = r.get(1)?;
                let hash: String = r.get(2)?;
                Ok((name, version, hash))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let resolved = match &label {
            Some(l) => Some(resolve(c, org, l, profile.as_deref())?),
            None => None,
        };
        Ok((rows, resolved))
    })?;
    let latest_all: BTreeMap<String, (i64, String)> =
        all_latest.iter().map(|(n, v, h)| (n.clone(), (*v, h.clone()))).collect();
    let scoped = resolved.is_some();
    let latest: BTreeMap<String, (i64, String)> = match &resolved {
        Some(list) => list.iter().map(|s| (s.name.clone(), (s.version, s.hash.clone()))).collect(),
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
            "The skills registry: immutable content-hash versions of agent skills (single-file SKILL.md or \
             multi-file packages with supporting files such as scripts/, templates/, references/), assigned to an \
             agent label or a profile and pinned to the approved version. publish, assign and unassign are operator \
             actions, each behind a one-time human approval. Actions: publish {name, path} (review a skill directory \
             or SKILL.md in the workspace, stage every file into the hub and ask for approval showing SKILL.md, the \
             manifest and supporting text files; refused when skill_review finds a high-severity issue, including \
             permission front matter, hidden text or credentials), publish {staging_id} (version the approved staged \
             copy without re-reading the workspace), list {name?}, get {name, version?}, assign {skill_name, target, \
             target_type: agent|profile, version?} (an agent assignment wins over a profile one), unassign \
             {skill_name, target, target_type}, resolve {agent_label, profile?} (own skills, or any agent's for an \
             operator), drift {surface_dir, agent_label?, profile?} (read-only: missing, stale, unregistered, \
             unassigned and synced skills). The harness config bundle served to a node carries the verified skill \
             packages resolved for its agent.",
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
    /// default organization yet). B cannot stage from the hub workspace,
    /// which is the default organization's (`workspace::sandbox`), so its
    /// staged row is made in SQL from the default organization's.
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

        // B may not read the hub workspace at all: nothing is staged.
        let e = stage(&b, who, Some("review-diff".into()), "skills/review-diff").unwrap_err();
        assert_eq!(e.reason_code(), Some("org_unsupported"), "{e:?}");
        let staged_rows = |org: &'static str| {
            hub.db()
                .read(move |c| {
                    Ok(c.query_row(
                        "SELECT COUNT(*) FROM skill_publish_staging WHERE org_id = ?1",
                        [org],
                        |r| r.get::<_, i64>(0),
                    )?)
                })
                .unwrap()
        };
        assert_eq!(staged_rows("org-b"), 0);

        // The default organization stages; its request binds the default.
        let staged_a = stage(&a, who, Some("review-diff".into()), "skills/review-diff").unwrap();
        let a_staging = staged_a["staging_id"].as_str().unwrap().to_string();
        let (org, payload) = approval(staged_a["approval_id"].as_i64().unwrap());
        assert_eq!((org.as_str(), payload["org_id"].as_str()), ("default", Some("default")), "{payload}");

        // B's staged copy of the same content (SQL; see above).
        let b_staging = "sk-orgb-not-real".to_string();
        let (from, to) = (a_staging.clone(), b_staging.clone());
        hub.db()
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO skill_publish_staging (org_id, id, name, content, content_hash, source, \
                     findings_json, requested_by, created_at) SELECT 'org-b', ?2, name, content, content_hash, \
                     source, findings_json, requested_by, created_at FROM skill_publish_staging WHERE id = ?1",
                    params![from, to],
                )?;
                Ok(())
            })
            .unwrap();
        // The default organization never reuses B's unpublished row.
        assert_ne!(a_staging, b_staging);

        // B publishes its staged copy behind an approval that binds B.
        let b_req = parked(publish_staged(&b, who, &b_staging));
        let (org, payload) = approval(b_req);
        assert_eq!((org.as_str(), payload["org_id"].as_str()), ("org-b", Some("org-b")), "{payload}");
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

        // B's registry events reach the default ledger with no name, target,
        // source or content hash, and the neutral originator.
        let events: Vec<(String, String, String)> = hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT channel, COALESCE(originator, ''), payload FROM event_log \
                     WHERE channel LIKE 'skill.%' ORDER BY seq",
                )?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap();
        let channels: Vec<&str> = events.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(channels, ["skill.published", "skill.assigned", "skill.unassigned"], "{events:?}");
        let b_hash = hub
            .db()
            .read(|c| {
                Ok(c.query_row("SELECT content_hash FROM skill_versions WHERE org_id = 'org-b'", [], |r| {
                    r.get::<_, String>(0)
                })?)
            })
            .unwrap();
        for (channel, originator, payload) in &events {
            assert_eq!(originator, crate::approvals::NEUTRAL_ORIGINATOR, "{channel}");
            for secret in ["review-diff", "builder-1", "SKILL.md", "ops-bot", b_hash.as_str()] {
                assert!(!payload.contains(secret), "{channel} carries {secret}: {payload}");
            }
            let p: Value = serde_json::from_str(payload).unwrap();
            assert_eq!(p["name"], Value::Null, "{payload}");
        }
        let published: Value = serde_json::from_str(&events[0].2).unwrap();
        assert_eq!((published["version"].as_i64(), published["content_hash"].is_null()), (Some(1), true));
        assert_eq!(published["staging_id"], b_staging.as_str());
        let assigned: Value = serde_json::from_str(&events[1].2).unwrap();
        assert_eq!((assigned["target_type"].as_str(), assigned["target"].is_null()), (Some("agent"), true));

        // The default organization's own events keep their names.
        let staged = again["staging_id"].as_str().unwrap().to_string();
        approve(again["approval_id"].as_i64().unwrap());
        publish_staged(&a, who, &staged).unwrap();
        let (originator, payload): (String, String) = hub
            .db()
            .read(|c| {
                Ok(c.query_row(
                    "SELECT originator, payload FROM event_log WHERE channel = 'skill.published' \
                     ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .unwrap();
        assert_eq!(originator, who);
        let p: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(p["name"], "review-diff", "{payload}");
        assert!(p["content_hash"].is_string(), "{payload}");
    }
}
