//! The planning canvas: an Excalidraw scene per board, and a deterministic
//! parse of its labeled shapes and arrows into task and dependency
//! suggestions.
//!
//! Tools: `graph_canvas_read` (the scene plus its parse) and
//! `graph_canvas_write` (store a scene, attributed to the verified caller).
//!
//! Nothing here creates a task, a dependency or a delegation. The parse is a
//! proposal for a human; acting on it goes through the ordinary task and
//! approval tools. A write may name the `expected_updated_at` it read, so two
//! editors cannot silently overwrite each other.

use std::collections::HashMap;

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use super::agents::verified;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "graph_canvas.v1",
    sql: "
CREATE TABLE IF NOT EXISTS graph_canvas_scenes (
    board_id TEXT PRIMARY KEY,
    scene_json TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
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
/// so nothing silently disappears.
pub fn parse(scene: &Value) -> UaResult<Value> {
    let els = elements(scene);
    if els.len() > SCENE_MAX_ELEMENTS {
        return Err(UaError::invalid(format!(
            "scene exceeds {SCENE_MAX_ELEMENTS} elements; split the board"
        )));
    }
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
                    "scene": {}, "parsed": parse(&json!({}))?,
                }),
                Some((scene, by, at)) => {
                    let scene: Value = serde_json::from_str(&scene).unwrap_or_else(|_| json!({}));
                    json!({
                        "board_id": board, "exists": true, "updated_by": by, "updated_at": at,
                        "parsed": parse(&scene)?, "scene": scene,
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

async fn graph_canvas_write(ctx: ToolCtx, a: WriteArgs) -> UaResult<Value> {
    let Some(actor) = verified(&ctx.caller).map(str::to_string) else {
        return Err(UaError::denied(
            "identity_required",
            "writing a canvas requires an authenticated identity",
        ));
    };
    if let Some(agent) = a.agent.as_deref().map(str::trim).filter(|s| !s.is_empty())
        && agent != actor
    {
        return Err(UaError::denied("identity_mismatch", "agent must match the authenticated caller"));
    }
    let board = board_id(a.board_id.as_deref())?;
    if !a.scene.is_object() {
        return Err(UaError::invalid("scene must be a JSON object (Excalidraw scene export)"));
    }
    match a.scene.get("elements") {
        None | Some(Value::Array(_)) => {}
        Some(_) => return Err(UaError::invalid("scene.elements must be an array of Excalidraw elements")),
    }
    let parsed = parse(&a.scene)?;
    let text = serde_json::to_string(&a.scene)?;
    if text.len() > SCENE_MAX_BYTES {
        return Err(UaError::invalid(format!(
            "scene too large: {} bytes (limit {SCENE_MAX_BYTES})",
            text.len()
        )));
    }
    let expected = a.expected_updated_at.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    ctx.hub
        .db()
        .write_async(move |tx| {
            let current: Option<String> = tx
                .query_row("SELECT updated_at FROM graph_canvas_scenes WHERE board_id = ?1", [&board], |r| r.get(0))
                .optional()?;
            if let Some(e) = &expected
                && current.as_deref() != Some(e.as_str())
            {
                return Err(UaError::conflict_code(
                    "stale_canvas",
                    format!(
                        "board {board:?} changed since {e} (now {}); read it again and merge",
                        current.as_deref().unwrap_or("absent")
                    ),
                ));
            }
            // Strictly increasing per board, so the precondition is exact.
            let mut now = ua_core::time::now();
            if current.as_deref().is_some_and(|c| c >= now.as_str()) {
                now = ua_core::time::format_ts(
                    current.as_deref().and_then(ua_core::time::parse_ts).unwrap_or_else(jiff::Timestamp::now)
                        + jiff::SignedDuration::from_secs(1),
                );
            }
            tx.execute(
                "INSERT INTO graph_canvas_scenes (board_id, scene_json, updated_by, updated_at) VALUES (?1, ?2, ?3, ?4) \
                 ON CONFLICT(board_id) DO UPDATE SET scene_json = excluded.scene_json, \
                 updated_by = excluded.updated_by, updated_at = excluded.updated_at",
                params![board, text, actor, now],
            )?;
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
                        "created": current.is_none(),
                    }),
                )
                .by(actor.clone()),
            )?;
            Ok(json!({
                "board_id": board,
                "saved": true,
                "updated_by": actor,
                "updated_at": now,
                "size_bytes": text.len(),
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
             {node_count, edge_count, unparsed_count, task_suggestions, dependency_suggestions}}.",
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
             else's change (stale_canvas). Writing does not act on the sketch. Returns {board_id, saved, \
             updated_by, updated_at, size_bytes}.",
            graph_canvas_write,
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
