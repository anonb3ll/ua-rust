//! `skill_registry`: the skills registry kernel of the Python hub.
//!
//! A skill version is immutable: `(name, version)` with the SHA-256 of its
//! content, never updated or deleted (triggers refuse both). Publishing the
//! same content again returns the existing version. A skill is assigned to an
//! agent label or a profile, optionally pinned to a version (else the latest
//! when resolved); an agent assignment wins over a profile assignment of the
//! same skill. The harness config bundle served to a node carries the skills
//! resolved for the node's agent (see [`super::harness_config`]).
//!
//! Actions (`action` + `params`, as in the Python hub):
//! - `publish` {name, path}: version one skill (`SKILL.md`, or a skill
//!   directory holding only `SKILL.md`) from the workspace, after
//!   `skill_review` passes without a high-severity finding;
//! - `list` {name?}, `get` {name, version?};
//! - `assign` {skill_name, target, target_type?, version?}, `unassign`;
//! - `resolve` {agent_label, profile?}: what an agent is assigned;
//! - `drift` {surface_dir, agent_label?, profile?}: a read-only comparison of
//!   a skills directory with the registry.
//!
//! Publish, assign and unassign are operator actions (a human or a lifecycle
//! operator): a skill's text lands in the harness of every node it reaches,
//! so it is a prompt-injection path. A new version (`publish`) and an
//! assignment (`assign`) each also need a one-time human approval, bound to
//! the content hash (and, for an assignment, the target and pin). They append
//! `skill.published`, `skill.assigned` and `skill.unassigned` events in the
//! same transaction.
//!
//! Not ported: multi-file skill packages (a publish source with supporting
//! files is refused), the catalog and team installs, and git skill sources.
//! Versions imported from the Python hub keep their package manifest; their
//! `SKILL.md` and manifest hash are verified on read.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use ua_core::{Profile, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use super::agents::verified;
use super::audit::resolve_target;
use super::harness_config::render::{content_hash, py_dumps};
use super::node_queue::is_operator;
use crate::approvals::{self, GateOutcome};
use crate::registry::{Registry, ToolCtx, blocking, tool};

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
CREATE TRIGGER IF NOT EXISTS skill_versions_immutable_update BEFORE UPDATE ON skill_versions
BEGIN SELECT RAISE(ABORT, 'skill versions and provenance are immutable'); END;
CREATE TRIGGER IF NOT EXISTS skill_versions_immutable_delete BEFORE DELETE ON skill_versions
BEGIN SELECT RAISE(ABORT, 'skill versions and provenance are immutable'); END;
",
};

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
        "source": r.get::<_, String>(4)?,
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

fn load_version(c: &Connection, name: &str, version: Option<i64>) -> UaResult<Option<Value>> {
    let row = match version {
        Some(v) => c
            .query_row(
                &format!("SELECT {FULL_COLS} FROM skill_versions WHERE name = ?1 AND version = ?2"),
                params![name, v],
                version_row,
            )
            .optional()?,
        None => c
            .query_row(
                &format!(
                    "SELECT {FULL_COLS} FROM skill_versions WHERE name = ?1 ORDER BY version DESC LIMIT 1"
                ),
                [name],
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
    pub source: String,
    pub content: String,
    /// `agent` or `profile`: which assignment matched.
    pub via: &'static str,
}

/// The skills assigned to `agent` directly or through `profile`: direct
/// assignments first (each source sorted by name), a direct one winning over
/// a profile one of the same skill, at most [`MAX_RESOLVED_SKILLS`]. A pinned
/// version that is missing, or a version that fails verification, is skipped.
pub(crate) fn resolve(c: &Connection, agent: &str, profile: Option<&str>) -> UaResult<Vec<Resolved>> {
    let agent = agent.trim();
    if agent.is_empty() {
        return Ok(Vec::new());
    }
    let rows = |target_type: &str, targets: &[String]| -> UaResult<Vec<(String, Option<i64>)>> {
        let mut out: Vec<(String, Option<i64>)> = Vec::new();
        for t in targets {
            let mut stmt = c.prepare(
                "SELECT skill_name, pinned_version FROM skill_assignments WHERE target_type = ?1 AND target = ?2 \
                 ORDER BY skill_name",
            )?;
            out.extend(
                stmt.query_map(params![target_type, t], |r| Ok((r.get(0)?, r.get(1)?)))?
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
        let Ok(Some(row)) = load_version(c, &name, pin) else { continue };
        out.push(Resolved {
            version: row["version"].as_i64().unwrap_or_default(),
            hash: row["content_hash"].as_str().unwrap_or_default().to_string(),
            source: row["source"].as_str().unwrap_or_default().to_string(),
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
    name: String,
    path: String,
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

/// An operator (a human or a lifecycle operator): what changes the skills
/// every node of an agent or profile is served.
fn operator(ctx: &ToolCtx, what: &str) -> UaResult<String> {
    let who = author(ctx)?;
    if !is_operator(&ctx.hub, &ctx.caller, &who) {
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

/// The single `SKILL.md` a publish reads: a `SKILL.md` file, or a skill
/// directory holding nothing else.
fn skill_md(resolved: &Path, shown: &str) -> UaResult<PathBuf> {
    let dir = if resolved.is_file() {
        if resolved.file_name().is_none_or(|n| n != "SKILL.md") {
            return Err(UaError::invalid(format!("{shown:?} is a file but not a SKILL.md")));
        }
        resolved.parent().map(Path::to_path_buf).unwrap_or_default()
    } else if resolved.join("SKILL.md").is_file() {
        resolved.to_path_buf()
    } else {
        return Err(UaError::invalid(format!(
            "{shown:?} has no SKILL.md at its root; publish takes one skill directory or SKILL.md file"
        )));
    };
    let md = dir.join("SKILL.md");
    if std::fs::symlink_metadata(&md).map(|m| m.file_type().is_symlink()).unwrap_or(true) {
        return Err(UaError::invalid("skill package refuses symlink sources"));
    }
    let others: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| UaError::invalid(format!("cannot read {shown:?}: {e}")))?
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
    Ok(md)
}

fn read_bounded(md: &Path) -> UaResult<String> {
    let bytes = std::fs::read(md).map_err(|_| UaError::invalid("SKILL.md could not be read"))?;
    if bytes.len() > MAX_SKILL_FILE_BYTES {
        return Err(UaError::invalid(format!("SKILL.md exceeds the {MAX_SKILL_FILE_BYTES}-byte limit")));
    }
    String::from_utf8(bytes).map_err(|_| UaError::invalid("SKILL.md must be valid UTF-8"))
}

fn publish(ctx: &ToolCtx, p: PublishParams) -> UaResult<Value> {
    let who = operator(ctx, "publishing a skill")?;
    let name = check_name(&p.name)?;
    let target = resolve_target(ctx, &p.path, false, false)?;
    let ws = ctx.hub.cfg().workspace_root();
    let ws = ws.canonicalize().unwrap_or(ws);
    if !target.path.starts_with(&ws) {
        return Err(UaError::denied(
            "outside_workspace",
            format!(
                "publish source {:?} is outside the workspace; read roots are audit sources only",
                p.path
            ),
        ));
    }
    let md = skill_md(&target.path, &p.path)?;
    let text = read_bounded(&md)?;
    let dir = md.parent().map(Path::to_path_buf).unwrap_or_default();
    let review = super::skills::review_dirs(vec![dir.clone()], &dir, "info");
    if review["status"] == "fail" {
        return Ok(json!({ "ok": false, "blocked": true, "name": name, "review": review }));
    }
    if read_bounded(&md)? != text {
        return Err(UaError::conflict("skill package changed while it was being reviewed; retry publish"));
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
    let source = target.path.to_string_lossy().into_owned();
    ctx.hub.db().write(|tx| {
        let existing = tx
            .query_row(
                &format!(
                    "SELECT {LIST_COLS} FROM skill_versions WHERE name = ?1 AND content_hash = ?2 \
                     ORDER BY version DESC LIMIT 1"
                ),
                params![name, hash],
                version_row,
            )
            .optional()?;
        if let Some(skill) = existing {
            return Ok(Ok(json!({ "ok": true, "idempotent": true, "skill": skill, "review": review })));
        }
        // A new version reaches every node its skill is assigned to: a human
        // approves this exact content first.
        let payload = json!({ "action": "publish", "name": name, "content_hash": hash, "source": source });
        if let Some(id) = gate(tx, ctx, &payload)? {
            return Ok(Err(id));
        }
        let next: i64 = tx.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM skill_versions WHERE name = ?1",
            [&name],
            |r| r.get(0),
        )?;
        let now = ua_core::time::now();
        tx.execute(
            "INSERT INTO skill_versions (name, version, content_hash, source, content, published_by, published_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![name, next, hash, source, text, who, now],
        )?;
        ledger::append(
            tx,
            EventInput::new(
                "skill.published",
                json!({ "name": name, "version": next, "content_hash": hash, "source": source, "published_at": now }),
            )
            .by(who.clone()),
        )?;
        let skill = tx.query_row(
            &format!("SELECT {LIST_COLS} FROM skill_versions WHERE name = ?1 AND version = ?2"),
            params![name, next],
            version_row,
        )?;
        Ok(Ok(json!({ "ok": true, "idempotent": false, "skill": skill, "review": review })))
    })
    .and_then(pending)
}

fn list(ctx: &ToolCtx, p: ListParams) -> UaResult<Value> {
    let name = p.name.filter(|n| !n.trim().is_empty());
    ctx.hub.db().read(|c| {
        let mut stmt = c.prepare(&format!(
            "SELECT {LIST_COLS} FROM skill_versions WHERE (?1 IS NULL OR name = ?1) ORDER BY name, version DESC"
        ))?;
        let skills = stmt.query_map([name], version_row)?.collect::<Result<Vec<_>, _>>()?;
        Ok(json!({ "skills": skills }))
    })
}

fn get(ctx: &ToolCtx, p: GetParams) -> UaResult<Value> {
    let version = positive(p.version)?;
    ctx.hub
        .db()
        .read(|c| load_version(c, &p.name, version))?
        .ok_or_else(|| UaError::not_found(format!("unknown skill: {:?}", p.name)))
}

fn assign(ctx: &ToolCtx, p: AssignParams) -> UaResult<Value> {
    let who = operator(ctx, "assigning a skill")?;
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
    ctx.hub.db().write(|tx| {
        let hash: Option<String> = match pin {
            Some(v) => tx
                .query_row(
                    "SELECT content_hash FROM skill_versions WHERE name = ?1 AND version = ?2",
                    params![name, v],
                    |r| r.get(0),
                )
                .optional()?,
            None => tx
                .query_row(
                    "SELECT content_hash FROM skill_versions WHERE name = ?1 ORDER BY version DESC LIMIT 1",
                    [&name],
                    |r| r.get(0),
                )
                .optional()?,
        };
        let Some(hash) = hash else {
            return Err(match pin {
                Some(v) => UaError::not_found(format!("unknown version {v} for skill {name:?}")),
                None => UaError::not_found(format!("skill {name:?} has no published version yet")),
            });
        };
        // The skill rides into the harness of every node of this agent or
        // profile: a human approves the assignment of this content first.
        let payload = json!({
            "action": "assign",
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
            "INSERT INTO skill_assignments (skill_name, target_type, target, pinned_version, assigned_by, assigned_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(skill_name, target_type, target) DO UPDATE SET \
             pinned_version = excluded.pinned_version, assigned_by = excluded.assigned_by, \
             assigned_at = excluded.assigned_at",
            params![name, ttype, target, pin, who, now],
        )?;
        ledger::append(
            tx,
            EventInput::new(
                "skill.assigned",
                json!({ "name": name, "target_type": ttype, "target": target, "version": pin }),
            )
            .by(who.clone()),
        )?;
        let row = tx.query_row(
            &format!(
                "SELECT {ASSIGN_COLS} FROM skill_assignments WHERE skill_name = ?1 AND target_type = ?2 AND target = ?3"
            ),
            params![name, ttype, target],
            assignment_row,
        )?;
        Ok(Ok(json!({ "assignment": row })))
    })
    .and_then(pending)
}

fn unassign(ctx: &ToolCtx, p: AssignParams) -> UaResult<Value> {
    let who = operator(ctx, "unassigning a skill")?;
    let name = check_name(p.skill_name.as_deref().or(p.name.as_deref()).unwrap_or_default())?;
    let ttype = check_target_type(p.target_type.as_deref())?;
    let target = p.target.trim().to_string();
    if target.is_empty() {
        return Err(UaError::invalid("target is required"));
    }
    // Unassigning is idempotent and also clears a profile's rows stored
    // under its legacy name.
    let targets = if ttype == "profile" { profile_keys(&target) } else { vec![target.clone()] };
    ctx.hub.db().write(|tx| {
        let mut removed = 0;
        for t in &targets {
            removed += tx.execute(
                "DELETE FROM skill_assignments WHERE skill_name = ?1 AND target_type = ?2 AND target = ?3",
                params![name, ttype, t],
            )?;
        }
        if removed > 0 {
            ledger::append(
                tx,
                EventInput::new(
                    "skill.unassigned",
                    json!({ "name": name, "target_type": ttype, "target": target }),
                )
                .by(who.clone()),
            )?;
        }
        Ok(json!({ "removed": removed > 0 }))
    })
}

fn resolve_action(ctx: &ToolCtx, p: ResolveParams) -> UaResult<Value> {
    let label = p.agent_label.trim().to_string();
    let profile = match p.profile.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(raw) => Some(profile_target(raw)?),
        None if label.is_empty() => None,
        None => Some(crate::sessions::default_profile(&ctx.hub, &label).as_str().to_string()),
    };
    let skills = ctx.hub.db().read(|c| resolve(c, &label, profile.as_deref()))?;
    let skills: Vec<Value> = skills
        .into_iter()
        .map(|s| {
            json!({
                "name": s.name,
                "version": s.version,
                "hash": s.hash,
                "source": s.source,
                "via": s.via,
                "content": s.content.chars().take(CONTENT_CAP).collect::<String>(),
            })
        })
        .collect();
    Ok(json!({ "agent_label": label, "profile": profile, "skills": skills }))
}

fn drift(ctx: &ToolCtx, p: DriftParams) -> UaResult<Value> {
    let root = resolve_target(ctx, &p.surface_dir, false, false)?.path;
    if !root.is_dir() {
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
        let path = e.path();
        if path.is_dir() && path.join("SKILL.md").is_file() {
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
        (None, Some(l)) => Some(crate::sessions::default_profile(&ctx.hub, l).as_str().to_string()),
        (None, None) => None,
    };
    // The registry side: every skill's latest version, and with an agent the
    // versions it resolves to (pins honoured).
    let (all_latest, resolved) = ctx.hub.db().read(|c| {
        let mut stmt = c.prepare(
            "SELECT sv.name, sv.version, sv.content_hash, sv.package_manifest, sv.content FROM skill_versions sv \
             JOIN (SELECT name, MAX(version) AS version FROM skill_versions GROUP BY name) latest \
             ON sv.name = latest.name AND sv.version = latest.version",
        )?;
        let rows = stmt
            .query_map([], |r| {
                let name: String = r.get(0)?;
                let version: i64 = r.get(1)?;
                let hash: String = r.get(2)?;
                let manifest: Option<String> = r.get(3)?;
                let content: String = r.get(4)?;
                Ok((name, version, hash, manifest, content))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let resolved = match &label {
            Some(l) => Some(resolve(c, l, profile.as_deref())?),
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
        "root": root.to_string_lossy(),
        "comparison": if label.is_some() { "resolved_assignments" } else { "latest_published" },
        "missing": missing,
        "stale": stale,
        "unregistered": unregistered,
        "unassigned": unassigned,
        "synced": synced,
    }))
}

async fn skill_registry(ctx: ToolCtx, a: SkillRegistryArgs) -> UaResult<Value> {
    let action = a.action.trim().to_ascii_lowercase();
    blocking(move || match action.as_str() {
        "publish" => publish(&ctx, params(a.params)?),
        "list" => list(&ctx, params(a.params)?),
        "get" => get(&ctx, params(a.params)?),
        "assign" => assign(&ctx, params(a.params)?),
        "unassign" => unassign(&ctx, params(a.params)?),
        "resolve" => resolve_action(&ctx, params(a.params)?),
        "drift" => drift(&ctx, params(a.params)?),
        "catalog" | "install" | "team_install" | "starter_preview" | "starter_install" => {
            Err(UaError::invalid(format!("action {action:?} (the skill catalog) is not ported to this hub")))
        }
        a if a.starts_with("source_") => {
            Err(UaError::invalid(format!("action {a:?} (git skill sources) is not ported to this hub")))
        }
        other => Err(UaError::invalid(format!(
            "action must be one of publish, list, get, assign, unassign, resolve, drift; got {other:?}"
        ))),
    })
    .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "skill_registry",
            "The skills registry: immutable content-hash versions of agent skills, assigned to an agent label or a \
             profile. publish, assign and unassign are operator actions; publish and assign each need a \
             one-time human approval bound to the content hash. Actions: publish {name, path} (one SKILL.md-only skill from the workspace, refused when \
             skill_review finds a high-severity issue; identical content returns the existing version), list \
             {name?}, get {name, version?}, assign {skill_name, target, target_type: agent|profile, version?} (an \
             agent assignment wins over a profile one), unassign {skill_name, target, target_type}, resolve \
             {agent_label, profile?}, drift {surface_dir, agent_label?, profile?} (read-only: missing, stale, \
             unregistered, unassigned and synced skills). The harness config bundle served to a node carries the \
             skills resolved for its agent.",
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
}
