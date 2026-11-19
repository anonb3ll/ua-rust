//! `format_render`: chat formatting with a plain-text fallback.
//!
//! Every renderer returns `{markdown, text}`; the text form stands on its own
//! for transports that strip markup.

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use ua_core::{UaError, UaResult};

use crate::registry::{Registry, ToolCtx, tool};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenderArgs {
    /// `table`, `section`, `code` or `chips`.
    pub kind: String,
    /// Renderer arguments. table: {columns: [str], rows: [[...]]}; section:
    /// {summary, body}; code: {content, filename?}; chips: {mapping: {k: v}}.
    pub payload: Map<String, Value>,
}

fn cell(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn width(s: &str) -> usize {
    s.chars().count()
}

fn pad(s: &str, w: usize) -> String {
    let mut out = s.to_string();
    out.extend(std::iter::repeat_n(' ', w.saturating_sub(width(s))));
    out
}

pub fn format_table(columns: &[Value], rows: &[Value]) -> UaResult<Value> {
    if columns.is_empty() {
        return Err(UaError::invalid("format_table needs at least one column"));
    }
    let n = columns.len();
    let cols: Vec<String> = columns.iter().map(cell).collect();
    let norm: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            let mut cells: Vec<String> = match r {
                Value::Array(a) => a.iter().take(n).map(cell).collect(),
                other => vec![cell(other)],
            };
            cells.resize(n, String::new());
            cells
        })
        .collect();

    let mut md = vec![
        format!("| {} |", cols.iter().map(|c| c.replace('|', "\\|")).collect::<Vec<_>>().join(" | ")),
        format!("| {} |", vec!["---"; n].join(" | ")),
    ];
    for cells in &norm {
        md.push(format!(
            "| {} |",
            cells.iter().map(|c| c.replace('|', "\\|").replace('\n', " ")).collect::<Vec<_>>().join(" | ")
        ));
    }

    let mut widths: Vec<usize> = cols.iter().map(|c| width(c)).collect();
    for cells in &norm {
        for (i, c) in cells.iter().enumerate() {
            widths[i] = widths[i].max(width(&c.replace('\n', " ")));
        }
    }
    let mut txt = vec![
        cols.iter()
            .enumerate()
            .map(|(i, c)| pad(c, widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string(),
        widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("  "),
    ];
    for cells in &norm {
        txt.push(
            cells
                .iter()
                .enumerate()
                .map(|(i, c)| pad(&c.replace('\n', " "), widths[i]))
                .collect::<Vec<_>>()
                .join("  ")
                .trim_end()
                .to_string(),
        );
    }
    Ok(json!({ "markdown": md.join("\n"), "text": txt.join("\n") }))
}

pub fn format_section(summary: &str, body: &str) -> UaResult<Value> {
    if summary.trim().is_empty() {
        return Err(UaError::invalid("format_section needs a non-empty summary"));
    }
    Ok(json!({
        "markdown": format!("<details>\n<summary>{summary}</summary>\n\n{body}\n</details>"),
        "text": format!("{summary}\n{}\n{body}", "-".repeat(width(summary))),
    }))
}

pub fn format_code(content: &str, filename: Option<&str>) -> Value {
    let header = filename.map(|f| format!("`{f}`\n")).unwrap_or_default();
    let lang = filename
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, ext)| match ext {
            "py" => "python",
            "js" => "javascript",
            "ts" => "typescript",
            "sh" => "bash",
            "json" => "json",
            "md" => "markdown",
            "yaml" | "yml" => "yaml",
            _ => "",
        })
        .unwrap_or("");
    json!({
        "markdown": format!("{header}```{lang}\n{content}\n```"),
        "text": format!("{}{content}", filename.map(|f| format!("{f}:\n")).unwrap_or_default()),
    })
}

pub fn format_chips(mapping: &Map<String, Value>) -> UaResult<Value> {
    if mapping.is_empty() {
        return Err(UaError::invalid("format_chips needs at least one key/value pair"));
    }
    let md = mapping.iter().map(|(k, v)| format!("`{k}: {}`", cell(v))).collect::<Vec<_>>().join(" ");
    let text = mapping.iter().map(|(k, v)| format!("{k}={}", cell(v))).collect::<Vec<_>>().join(" · ");
    Ok(json!({ "markdown": md, "text": text }))
}

pub fn format_render(kind: &str, payload: &Map<String, Value>) -> UaResult<Value> {
    let missing =
        |key: &str| UaError::invalid(format!("payload for kind={kind:?} is missing required key '{key}'"));
    let wrong = |key: &str, ty: &str| UaError::invalid(format!("payload key '{key}' must be {ty}"));
    let string = |key: &str| -> UaResult<String> {
        match payload.get(key) {
            None => Err(missing(key)),
            Some(Value::String(s)) => Ok(s.clone()),
            Some(_) => Err(wrong(key, "a string")),
        }
    };
    let opt_string = |key: &str| -> UaResult<Option<String>> {
        match payload.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(wrong(key, "a string")),
        }
    };
    match kind {
        "table" => {
            let columns = payload.get("columns").ok_or_else(|| missing("columns"))?;
            let columns = columns.as_array().ok_or_else(|| wrong("columns", "a list"))?;
            let rows = match payload.get("rows") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(r)) => r.clone(),
                Some(_) => return Err(wrong("rows", "a list of lists")),
            };
            format_table(columns, &rows)
        }
        "section" => format_section(&string("summary")?, &opt_string("body")?.unwrap_or_default()),
        "code" => Ok(format_code(&string("content")?, opt_string("filename")?.as_deref())),
        "chips" => {
            let mapping = payload.get("mapping").ok_or_else(|| missing("mapping"))?;
            format_chips(mapping.as_object().ok_or_else(|| wrong("mapping", "an object"))?)
        }
        other => {
            Err(UaError::invalid(format!("kind must be one of table|section|code|chips, got {other:?}")))
        }
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "format_render",
            "Render chat output with a plain-text fallback. kind: table {columns, rows} | section \
             {summary, body} | code {content, filename?} | chips {mapping}. Returns {markdown, text}; \
             the text form is self-contained for transports that strip markup.",
            |_ctx: ToolCtx, a: RenderArgs| async move { format_render(&a.kind, &a.payload) },
        )
        .family("code")
        .read_only(),
    );
}
