//! The planning canvas: an Excalidraw scene per board, and a deterministic
//! parse of its labeled shapes and arrows into task and dependency
//! suggestions.
//!
//! Tools: `graph_canvas_read` (the scene plus its parse),
//! `graph_canvas_write` (store a scene, attributed to the verified caller),
//! `graph_canvas_history` (the board's earlier scenes) and
//! `graph_canvas_restore` (write an earlier scene back as a new write).
//!
//! Nothing here creates a task, a dependency or a delegation. The parse is a
//! proposal for a human; acting on it goes through the ordinary task and
//! approval tools. A write may name the `expected_updated_at` it read, so two
//! editors cannot silently overwrite each other.
//!
//! Bounds: a scene is at most [`SCENE_MAX_BYTES`] and [`SCENE_MAX_ELEMENTS`].
//! Creating a new board is refused (`canvas_limit`) once its creator holds
//! `graph_canvas_max_boards_per_agent` boards or the hub holds
//! `graph_canvas_max_boards`; updating an existing board is never capped.
//! Every overwrite first copies the scene it replaces into
//! `graph_canvas_revisions`, keeping the newest `graph_canvas_history_max`
//! per board within `graph_canvas_history_max_bytes` of scenes per board
//! (the oldest go first), so an overwrite can be undone with
//! `graph_canvas_restore`.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use super::agents::verified;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "graph_canvas.v1",
    sql: "
CREATE TABLE IF NOT EXISTS graph_canvas_scenes (
    board_id TEXT PRIMARY KEY,
    scene_json TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_graph_canvas_scenes_created_by ON graph_canvas_scenes(created_by);
CREATE TABLE IF NOT EXISTS graph_canvas_revisions (
    board_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    scene_json TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    replaced_at TEXT NOT NULL,
    replaced_by TEXT NOT NULL,
    PRIMARY KEY (board_id, revision)
);
",
};

/// A stored scene is at most this many bytes of JSON.
pub const SCENE_MAX_BYTES: usize = 2_000_000;
/// A scene holds at most this many elements.
pub const SCENE_MAX_ELEMENTS: usize = 1000;
const TITLE_MAX_CHARS: usize = 200;
const NODE_TYPES: [&str; 3] = ["rectangle", "ellipse", "diamond"];
const EDGE_TYPES: [&str; 2] = ["arrow", "line"];

/// `[a-z0-9][a-z0-9._-]{0,63}`, case-folded.
fn board_id(raw: Option<&str>) -> UaResult<String> {
    let b = raw.unwrap_or("default").trim().to_ascii_lowercase();
    let mut chars = b.chars();
    let ok = b.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(b)
    } else {
        Err(UaError::invalid("board_id must match [a-z0-9][a-z0-9._-]{0,63} (e.g. 'default', 'sprint-42')"))
    }
}

fn elements(scene: &Value) -> Vec<&Map<String, Value>> {
    scene
        .get("elements")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_object).collect())
        .unwrap_or_default()
}

fn s<'a>(el: &'a Map<String, Value>, key: &str) -> &'a str {
    el.get(key).and_then(Value::as_str).unwrap_or("")
}

fn title(text: &str) -> String {
    text.trim().lines().next().unwrap_or("").trim().chars().take(TITLE_MAX_CHARS).collect()
}

/// Parse labeled shapes into task suggestions and bound arrows between them
/// into dependency suggestions (`to` depends on `from`). Standalone text is
/// annotation; unlabeled shapes and unbound arrows are counted as unparsed,
/// so nothing silently disappears. Elements the editor deleted
/// (`isDeleted: true`, kept in the export as tombstones) are not on the
/// board and are skipped, though they still count toward the element bound.
pub fn parse(scene: &Value) -> UaResult<Value> {
    let mut els = elements(scene);
    if els.len() > SCENE_MAX_ELEMENTS {
        return Err(UaError::invalid(format!(
            "scene exceeds {SCENE_MAX_ELEMENTS} elements; split the board"
        )));
    }
    els.retain(|el| el.get("isDeleted").and_then(Value::as_bool) != Some(true));
    let mut label_of: HashMap<&str, &str> = HashMap::new();
    let mut unparsed = 0usize;
    for el in &els {
        if s(el, "type") != "text" {
            continue;
        }
        let text = s(el, "text").trim();
        if text.is_empty() {
            continue;
        }
        match s(el, "containerId") {
            "" => unparsed += 1,
            container => {
                label_of.insert(container, text);
            }
        }
    }
    let mut nodes: Vec<Value> = Vec::new();
    let mut by_id: HashMap<&str, String> = HashMap::new();
    let mut node_count = 0;
    for el in &els {
        if !NODE_TYPES.contains(&s(el, "type")) {
            continue;
        }
        node_count += 1;
        let id = s(el, "id");
        let label = label_of.get(id).copied().unwrap_or_else(|| s(el, "label").trim());
        if id.is_empty() || label.is_empty() {
            unparsed += 1;
            continue;
        }
        let t = title(label);
        if by_id.insert(id, t.clone()).is_none() {
            nodes.push(json!({ "id": id, "title": t, "excalidraw_id": id }));
        }
    }
    let mut deps: Vec<Value> = Vec::new();
    let mut edge_count = 0;
    for el in &els {
        if !EDGE_TYPES.contains(&s(el, "type")) {
            continue;
        }
        edge_count += 1;
        let end = |k: &str| el.get(k).and_then(|b| b.get("elementId")).and_then(Value::as_str).unwrap_or("");
        let (from, to) = (end("startBinding"), end("endBinding"));
        match (by_id.get(from), by_id.get(to)) {
            (Some(ft), Some(tt)) if from != to => deps.push(json!({
                "from_id": from, "from_title": ft, "to_id": to, "to_title": tt,
            })),
            _ => unparsed += 1,
        }
    }
    Ok(json!({
        "node_count": node_count,
        "edge_count": edge_count,
        "unparsed_count": unparsed,
        "task_suggestions": nodes,
        "dependency_suggestions": deps,
    }))
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    /// Board id, `[a-z0-9][a-z0-9._-]{0,63}` (default `default`).
    pub board_id: Option<String>,
}

/// A stored scene as `(scene, corrupt)`: one that is not a JSON object reads
/// as `(null, true)` instead of passing for an empty board.
fn stored_scene(raw: &str) -> (Value, bool) {
    match serde_json::from_str::<Value>(raw) {
        Ok(v) if v.is_object() => (v, false),
        _ => (Value::Null, true),
    }
}

async fn graph_canvas_read(ctx: ToolCtx, a: ReadArgs) -> UaResult<Value> {
    let board = board_id(a.board_id.as_deref())?;
    ctx.hub
        .db()
        .read_async(move |c| {
            let row: Option<(String, String, String)> = c
                .query_row(
                    "SELECT scene_json, updated_by, updated_at FROM graph_canvas_scenes WHERE board_id = ?1",
                    [&board],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok(match row {
                None => json!({
                    "board_id": board, "exists": false, "updated_by": null, "updated_at": null,
                    "corrupt": false, "scene": {}, "parsed": parse(&json!({}))?,
                }),
                Some((scene, by, at)) => {
                    let (scene, corrupt) = stored_scene(&scene);
                    let parsed = if corrupt { parse(&json!({}))? } else { parse(&scene)? };
                    json!({
                        "board_id": board, "exists": true, "updated_by": by, "updated_at": at,
                        "corrupt": corrupt, "parsed": parsed, "scene": scene,
                    })
                }
            })
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WriteArgs {
    /// Board id (default `default`).
    pub board_id: Option<String>,
    /// The Excalidraw scene export: a JSON object with an optional `elements`
    /// array (at most 1000 elements, 2 MB).
    pub scene: Value,
    /// Must equal your verified identity when given.
    pub agent: Option<String>,
    /// The `updated_at` you read; the write is refused if the board changed
    /// since. Omit to overwrite unconditionally.
    pub expected_updated_at: Option<String>,
}

/// The verified caller, matching `agent` when one is named.
fn writer(ctx: &ToolCtx, agent: Option<&str>, doing: &str) -> UaResult<String> {
    let Some(actor) = verified(&ctx.caller).map(str::to_string) else {
        return Err(UaError::denied(
            "identity_required",
            format!("{doing} requires an authenticated identity"),
        ));
    };
    if let Some(agent) = agent.map(str::trim).filter(|s| !s.is_empty())
        && agent != actor
    {
        return Err(UaError::denied("identity_mismatch", "agent must match the authenticated caller"));
    }
    Ok(actor)
}

/// The configured board caps and history depth.
#[derive(Debug, Clone, Copy)]
struct Limits {
    per_agent: i64,
    total: i64,
    history: i64,
    history_bytes: i64,
}

impl Limits {
    fn of(cfg: &ua_core::Config) -> Self {
        Self {
            per_agent: i64::from(cfg.graph_canvas_max_boards_per_agent),
            total: i64::from(cfg.graph_canvas_max_boards),
            history: i64::from(cfg.graph_canvas_history_max),
            history_bytes: i64::try_from(cfg.graph_canvas_history_max_bytes).unwrap_or(i64::MAX),
        }
    }
}

/// Validate a scene for storage: an object whose `elements` (when present)
/// is an array, within the element and byte bounds. Returns its parse and
/// its serialized text.
fn checked_scene(scene: &Value) -> UaResult<(Value, String)> {
    if !scene.is_object() {
        return Err(UaError::invalid("scene must be a JSON object (Excalidraw scene export)"));
    }
    match scene.get("elements") {
        None | Some(Value::Array(_)) => {}
        Some(_) => return Err(UaError::invalid("scene.elements must be an array of Excalidraw elements")),
    }
    let parsed = parse(scene)?;
    let text = serde_json::to_string(scene)?;
    if text.len() > SCENE_MAX_BYTES {
        return Err(UaError::invalid(format!(
            "scene too large: {} bytes (limit {SCENE_MAX_BYTES})",
            text.len()
        )));
    }
    Ok((parsed, text))
}

/// What [`store`] did.
struct Stored {
    updated_at: String,
    created: bool,
    /// The revision the replaced scene was kept as, if any.
    kept_revision: Option<i64>,
}

/// Store `text` as `board`'s scene inside `tx`: check the precondition, cap
/// new boards, keep the replaced scene as a revision, and upsert.
fn store(
    tx: &mut WriteTx<'_>,
    lim: Limits,
    board: &str,
    text: &str,
    actor: &str,
    expected: Option<&str>,
) -> UaResult<Stored> {
    let current: Option<(String, String, String)> = tx
        .query_row(
            "SELECT updated_at, scene_json, updated_by FROM graph_canvas_scenes WHERE board_id = ?1",
            [board],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let current_at = current.as_ref().map(|c| c.0.as_str());
    if let Some(e) = expected
        && current_at != Some(e)
    {
        return Err(UaError::conflict_code(
            "stale_canvas",
            format!(
                "board {board:?} changed since {e} (now {}); read it again and merge",
                current_at.unwrap_or("absent")
            ),
        ));
    }
    if current.is_none() {
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM graph_canvas_scenes", [], |r| r.get(0))?;
        if total >= lim.total {
            return Err(UaError::denied(
                "canvas_limit",
                format!(
                    "the hub holds {total} canvas boards (graph_canvas_max_boards = {}); reuse a board",
                    lim.total
                ),
            ));
        }
        let mine: i64 =
            tx.query_row("SELECT COUNT(*) FROM graph_canvas_scenes WHERE created_by = ?1", [actor], |r| {
                r.get(0)
            })?;
        if mine >= lim.per_agent {
            return Err(UaError::denied(
                "canvas_limit",
                format!(
                    "{actor} created {mine} canvas boards (graph_canvas_max_boards_per_agent = {}); reuse a board",
                    lim.per_agent
                ),
            ));
        }
    }
    // Strictly increasing per board, so the precondition is exact.
    let mut now = ua_core::time::now();
    if current_at.is_some_and(|c| c >= now.as_str()) {
        now = ua_core::time::format_ts(
            current_at.and_then(ua_core::time::parse_ts).unwrap_or_else(jiff::Timestamp::now)
                + jiff::SignedDuration::from_secs(1),
        );
    }
    let mut kept_revision = None;
    if let Some((prev_at, prev_scene, prev_by)) = &current
        && lim.history > 0
    {
        let rev: i64 = tx.query_row(
            "SELECT COALESCE(MAX(revision), 0) + 1 FROM graph_canvas_revisions WHERE board_id = ?1",
            [board],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO graph_canvas_revisions \
             (board_id, revision, scene_json, updated_by, updated_at, replaced_at, replaced_by) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![board, rev, prev_scene, prev_by, prev_at, now, actor],
        )?;
        tx.execute(
            "DELETE FROM graph_canvas_revisions WHERE board_id = ?1 AND revision <= ?2",
            params![board, rev - lim.history],
        )?;
        // The byte budget: keep the newest revisions whose scenes fit in it
        // together; drop the rest, oldest first.
        tx.execute(
            "DELETE FROM graph_canvas_revisions WHERE board_id = ?1 AND revision IN ( \
               SELECT revision FROM ( \
                 SELECT revision, SUM(length(CAST(scene_json AS BLOB))) OVER (ORDER BY revision DESC) AS kept \
                 FROM graph_canvas_revisions WHERE board_id = ?1 \
               ) WHERE kept > ?2 \
             )",
            params![board, lim.history_bytes],
        )?;
        let still: Option<i64> = tx
            .query_row(
                "SELECT revision FROM graph_canvas_revisions WHERE board_id = ?1 AND revision = ?2",
                params![board, rev],
                |r| r.get(0),
            )
            .optional()?;
        kept_revision = still;
    }
    tx.execute(
        "INSERT INTO graph_canvas_scenes (board_id, scene_json, updated_by, updated_at, created_by) \
         VALUES (?1, ?2, ?3, ?4, ?3) \
         ON CONFLICT(board_id) DO UPDATE SET scene_json = excluded.scene_json, \
         updated_by = excluded.updated_by, updated_at = excluded.updated_at",
        params![board, text, actor, now],
    )?;
    Ok(Stored { updated_at: now, created: current.is_none(), kept_revision })
}

async fn graph_canvas_write(ctx: ToolCtx, a: WriteArgs) -> UaResult<Value> {
    let actor = writer(&ctx, a.agent.as_deref(), "writing a canvas")?;
    let board = board_id(a.board_id.as_deref())?;
    let (parsed, text) = checked_scene(&a.scene)?;
    let expected = a.expected_updated_at.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let lim = Limits::of(ctx.hub.cfg());
    ctx.hub
        .db()
        .write_async(move |tx| {
            let st = store(tx, lim, &board, &text, &actor, expected.as_deref())?;
            // Counts only: the scene itself stays in its table.
            ledger::append(
                tx,
                EventInput::new(
                    "agent.graph.canvas_write",
                    json!({
                        "board_id": board,
                        "size_bytes": text.len(),
                        "node_count": parsed["node_count"],
                        "edge_count": parsed["edge_count"],
                        "created": st.created,
                        "kept_revision": st.kept_revision,
                    }),
                )
                .by(actor.clone()),
            )?;
            Ok(json!({
                "board_id": board,
                "saved": true,
                "created": st.created,
                "updated_by": actor,
                "updated_at": st.updated_at,
                "size_bytes": text.len(),
                "kept_revision": st.kept_revision,
            }))
        })
        .await
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryArgs {
    /// Board id (default `default`).
    pub board_id: Option<String>,
    /// One revision to return with its scene. Omit to list the board's
    /// revisions, newest first, without scenes.
    pub revision: Option<i64>,
}

async fn graph_canvas_history(ctx: ToolCtx, a: HistoryArgs) -> UaResult<Value> {
    let board = board_id(a.board_id.as_deref())?;
    let keep = ctx.hub.cfg().graph_canvas_history_max;
    let keep_bytes = ctx.hub.cfg().graph_canvas_history_max_bytes;
    ctx.hub
        .db()
        .read_async(move |c| {
            if let Some(rev) = a.revision {
                let row: Option<(String, String, String, String, String)> = c
                    .query_row(
                        "SELECT scene_json, updated_by, updated_at, replaced_at, replaced_by \
                         FROM graph_canvas_revisions WHERE board_id = ?1 AND revision = ?2",
                        params![board, rev],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                    )
                    .optional()?;
                let Some((raw, by, at, replaced_at, replaced_by)) = row else {
                    return Err(UaError::not_found(format!("board {board:?} has no revision {rev}")));
                };
                let (scene, corrupt) = stored_scene(&raw);
                let parsed = if corrupt { parse(&json!({}))? } else { parse(&scene)? };
                return Ok(json!({
                    "board_id": board,
                    "revision": rev,
                    "updated_by": by,
                    "updated_at": at,
                    "replaced_at": replaced_at,
                    "replaced_by": replaced_by,
                    "size_bytes": raw.len(),
                    "corrupt": corrupt,
                    "parsed": parsed,
                    "scene": scene,
                }));
            }
            let current: Option<String> = c
                .query_row("SELECT updated_at FROM graph_canvas_scenes WHERE board_id = ?1", [&board], |r| {
                    r.get(0)
                })
                .optional()?;
            let mut stmt = c.prepare(
                "SELECT revision, updated_by, updated_at, replaced_at, replaced_by, length(scene_json) \
                 FROM graph_canvas_revisions WHERE board_id = ?1 ORDER BY revision DESC",
            )?;
            let revisions = stmt
                .query_map([&board], |r| {
                    Ok(json!({
                        "revision": r.get::<_, i64>(0)?,
                        "updated_by": r.get::<_, String>(1)?,
                        "updated_at": r.get::<_, String>(2)?,
                        "replaced_at": r.get::<_, String>(3)?,
                        "replaced_by": r.get::<_, String>(4)?,
                        "size_bytes": r.get::<_, i64>(5)?,
                    }))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(json!({
                "board_id": board,
                "exists": current.is_some(),
                "updated_at": current,
                "history_max": keep,
                "history_max_bytes": keep_bytes,
                "revisions": revisions,
            }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RestoreArgs {
    /// Board id (default `default`).
    pub board_id: Option<String>,
    /// The revision to write back (from `graph_canvas_history`).
    pub revision: i64,
    /// The `updated_at` you read; the restore is refused if the board
    /// changed since. Omit to restore unconditionally.
    pub expected_updated_at: Option<String>,
}

async fn graph_canvas_restore(ctx: ToolCtx, a: RestoreArgs) -> UaResult<Value> {
    let actor = writer(&ctx, None, "restoring a canvas")?;
    let board = board_id(a.board_id.as_deref())?;
    let expected = a.expected_updated_at.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let lim = Limits::of(ctx.hub.cfg());
    let rev = a.revision;
    ctx.hub
        .db()
        .write_async(move |tx| {
            let raw: Option<String> = tx
                .query_row(
                    "SELECT scene_json FROM graph_canvas_revisions WHERE board_id = ?1 AND revision = ?2",
                    params![board, rev],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(raw) = raw else {
                return Err(UaError::not_found(format!("board {board:?} has no revision {rev}")));
            };
            let (scene, corrupt) = stored_scene(&raw);
            if corrupt {
                return Err(UaError::invalid(format!(
                    "revision {rev} of board {board:?} is not a valid scene"
                )));
            }
            let (parsed, text) = checked_scene(&scene)?;
            let st = store(tx, lim, &board, &text, &actor, expected.as_deref())?;
            ledger::append(
                tx,
                EventInput::new(
                    "agent.graph.canvas_restore",
                    json!({
                        "board_id": board,
                        "revision": rev,
                        "size_bytes": text.len(),
                        "node_count": parsed["node_count"],
                        "edge_count": parsed["edge_count"],
                        "created": st.created,
                        "kept_revision": st.kept_revision,
                    }),
                )
                .by(actor.clone()),
            )?;
            Ok(json!({
                "board_id": board,
                "restored": true,
                "restored_revision": rev,
                "updated_by": actor,
                "updated_at": st.updated_at,
                "size_bytes": text.len(),
                "kept_revision": st.kept_revision,
            }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "graph_canvas_read",
            "Read a planning canvas board (an Excalidraw scene) and parse its labeled shapes into task \
             suggestions and its bound arrows into dependency suggestions (to depends on from). Suggestions \
             only: nothing is created. Returns {board_id, exists, updated_by, updated_at, scene, parsed: \
             {node_count, edge_count, unparsed_count, task_suggestions, dependency_suggestions}, corrupt}. A \
             stored scene that is not a JSON object reads as corrupt: true with scene null.",
            graph_canvas_read,
        )
        .read_only()
        .family("graph"),
    );
    r.add(
        tool(
            "graph_canvas_write",
            "Store an Excalidraw scene for a planning canvas board, attributed to the verified caller (at most \
             1000 elements, 2 MB). Pass expected_updated_at from your read to refuse a write over someone \
             else's change (stale_canvas). Creating a new board past graph_canvas_max_boards_per_agent or \
             graph_canvas_max_boards is refused (canvas_limit); updating a board is not capped. The replaced \
             scene is kept as a revision (graph_canvas_history). Writing does not act on the sketch. Returns \
             {board_id, saved, created, updated_by, updated_at, size_bytes, kept_revision}.",
            graph_canvas_write,
        )
        .family("graph"),
    );
    r.add(
        tool(
            "graph_canvas_history",
            "List a planning canvas board's earlier scenes, newest first, without their bodies: {board_id, \
             exists, updated_at, history_max, revisions: [{revision, updated_by, updated_at, replaced_at, \
             replaced_by, size_bytes}]}. With revision, return that one scene and its parse: {board_id, \
             revision, updated_by, updated_at, replaced_at, replaced_by, size_bytes, corrupt, parsed, scene}. \
             Every overwrite keeps the scene it replaced; the newest graph_canvas_history_max per board are kept.",
            graph_canvas_history,
        )
        .read_only()
        .family("graph"),
    );
    r.add(
        tool(
            "graph_canvas_restore",
            "Write an earlier revision of a planning canvas board back as a new write, attributed to the \
             verified caller and ledgered. The scene it replaces is kept as a revision too, so a restore can \
             itself be undone. Pass expected_updated_at from your read to refuse a restore over someone \
             else's change (stale_canvas). Returns {board_id, restored, restored_revision, updated_by, \
             updated_at, size_bytes, kept_revision}.",
            graph_canvas_restore,
        )
        .family("graph"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_become_suggestions_and_strays_are_counted() {
        let scene = json!({ "elements": [
            { "id": "a", "type": "rectangle" },
            { "id": "ta", "type": "text", "text": "Write the spec\nwith details", "containerId": "a" },
            { "id": "b", "type": "ellipse", "label": "Build it" },
            { "id": "c", "type": "diamond" },
            { "id": "t", "type": "text", "text": "Sprint 42" },
            { "id": "e1", "type": "arrow", "startBinding": { "elementId": "a" }, "endBinding": { "elementId": "b" } },
            { "id": "e2", "type": "arrow", "startBinding": { "elementId": "a" } },
            { "id": "e3", "type": "line", "startBinding": { "elementId": "a" }, "endBinding": { "elementId": "a" } },
        ]});
        let p = parse(&scene).unwrap();
        assert_eq!(p["node_count"], 3);
        assert_eq!(p["edge_count"], 3);
        assert_eq!(p["task_suggestions"][0]["title"], "Write the spec");
        assert_eq!(p["task_suggestions"].as_array().unwrap().len(), 2);
        assert_eq!(
            p["dependency_suggestions"],
            json!([{ "from_id": "a", "from_title": "Write the spec", "to_id": "b", "to_title": "Build it" }])
        );
        // c (no label), standalone text, e2 (unbound), e3 (self loop).
        assert_eq!(p["unparsed_count"], 4);
    }

    #[test]
    fn board_ids_are_bounded() {
        assert_eq!(board_id(Some(" Sprint-42 ")).unwrap(), "sprint-42");
        assert_eq!(board_id(None).unwrap(), "default");
        assert!(board_id(Some("-x")).is_err());
        assert!(board_id(Some(&"a".repeat(65))).is_err());
        assert!(board_id(Some("a/b")).is_err());
    }
}
