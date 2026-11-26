//! Workspace source-scan guard for C2 slice 1 (`docs/graph.md`):
//!
//! Enforces that every mutable-field update to `graph_nodes`, `graph_edges`, or
//! `graph_org_counts` goes strictly through the domain-only primitives
//! (`ua_graph::graph_node_update`, `ua_graph::graph_edge_update_weight`,
//! `ua_graph::retract_edge`):
//!
//! 1. **Domain-update call allowlist:** `graph_node_update` and
//!    `graph_edge_update_weight` are `pub` for C2 domain consumers, so every
//!    non-test reference outside `crates/ua-graph/src/{write,lib}.rs` must live
//!    in [`DOMAIN_UPDATE_CALL_ALLOWLIST`]. The allowlist is empty today; each
//!    C2 consumer adds its owning file in its own PR. Generic graph tools
//!    (`crates/ua-tools/src/families/graph_store.rs`) and `crates/ua-server/`
//!    must **never** appear on it.
//! 2. **Low-level `GraphRepo` guard:** No non-test code outside
//!    `crates/ua-graph/src/write.rs` and `crates/ua-store/src/graph.rs` may
//!    call `update_node_mutable` or `update_edge_weight` directly.
//! 3. **SQL mutation guard:** Scans every non-test Rust source file for SQL
//!    mutations against `graph_nodes`, `graph_edges`, and `graph_org_counts`:
//!    - `UPDATE [OR <conflict>] [<schema>.]<table>`
//!    - `INSERT OR REPLACE INTO [<schema>.]<table>`
//!    - `REPLACE INTO [<schema>.]<table>`
//!    - `INSERT [OR <conflict>] INTO [<schema>.]<table> ... ON CONFLICT ... DO UPDATE`
//!
//!    Handles unquoted, single-quoted, double-quoted, backtick-quoted, and
//!    bracket-quoted identifiers (including Rust-escaped `\"` / `\'`), any
//!    `<schema>.` prefix, and Rust string line continuations. Allowed ONLY at
//!    exact sanctioned sites:
//!    - `crates/ua-store/src/graph.rs`: 1 `UPDATE graph_nodes`
//!      (`update_node_mutable`) and 2 `UPDATE graph_edges` (`close_edge` +
//!      `update_edge_weight`).
//!    - `crates/ua-graph/src/schema.rs`: 3 `INSERT INTO graph_org_counts ...
//!      ON CONFLICT ... DO UPDATE` (`graph.v2.counters` backfill + two
//!      `AFTER INSERT` triggers).
//! 4. **Dynamic table-slot (`format!`) guard and static-scan limit:**
//!    In crates that access the graph tables (`ua-graph`, `ua-tools`,
//!    `ua-server`, `ua-memory`, `ua-deliverables`), refuses `format!` literals
//!    that place a `{...}` format slot in the table position of `UPDATE`,
//!    `INSERT OR REPLACE INTO`, or `REPLACE INTO`.
//!    **Static-scan limit:** a static text scanner cannot catch arbitrarily
//!    obfuscated runtime SQL builders (for example string concatenation via
//!    `String::push_str` or indirect table-name variables outside `format!`).
//!    SQLite immutability triggers (`graph_nodes_identity_immutable`,
//!    `graph_edges_provenance_immutable`, `graph_nodes_no_delete`,
//!    `graph_edges_no_delete`, `graph_org_counts_no_delete`) enforce identity,
//!    provenance, and non-deletion invariants at the database layer regardless,
//!    while code review covers non-literal SQL construction.

#[path = "../../ua-core/tests/support/mod.rs"]
mod support;

const GUARDED_TABLES: &[&str] = &["graph_nodes", "graph_edges", "graph_org_counts"];

/// Non-test workspace source files (suffixes, forward-slash normalized)
/// permitted to reference `graph_node_update` or `graph_edge_update_weight`
/// outside their definition (`crates/ua-graph/src/write.rs`) and re-export
/// (`crates/ua-graph/src/lib.rs`).
///
/// Empty in C2 slice 1: each C2 domain consumer adds its owning file in its
/// own PR. Generic graph tools (`crates/ua-tools/src/families/graph_store.rs`)
/// and `crates/ua-server/` must NEVER be added here.
const DOMAIN_UPDATE_CALL_ALLOWLIST: &[&str] = &[];

/// Non-test workspace source files (suffixes, forward-slash normalized)
/// permitted to reference `MigrationGraph` outside its definition
/// (`crates/ua-store/src/graph.rs`). `MigrationGraph::record_event` returns
/// `Ok(None)` so schema migrations and bulk importers do not write to the
/// hash-chained ledger; runtime handlers and `ua-server` must NEVER be added
/// here.
const MIGRATION_GRAPH_ALLOWLIST: &[&str] = &["crates/ua-tools/src/families/tasks/graph.rs"];

/// Crates where dynamic `format!` table-slot DML (`UPDATE {}`, `REPLACE INTO {}`,
/// `INSERT OR REPLACE INTO {}`) is forbidden.
const DYNAMIC_SQL_GUARDED_CRATES: &[&str] = &[
    "crates/ua-graph/",
    "crates/ua-tools/",
    "crates/ua-server/",
    "crates/ua-memory/",
    "crates/ua-deliverables/",
];

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn skip_space(b: &[u8], mut i: usize) -> usize {
    loop {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        // SQL line comment `-- ...\n`
        if b.get(i) == Some(&b'-') && b.get(i + 1) == Some(&b'-') {
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // SQL block comment `/* ... */`
        if b.get(i) == Some(&b'/') && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
            continue;
        }
        break;
    }
    i
}

/// Match ASCII keyword `kw` case-insensitively as a whole word at `i`.
fn keyword_ci(b: &[u8], i: usize, kw: &str) -> Option<usize> {
    let end = i + kw.len();
    let slice = b.get(i..end)?;
    if slice.eq_ignore_ascii_case(kw.as_bytes()) && b.get(end).is_none_or(|c| !is_ident_byte(*c)) {
        Some(end)
    } else {
        None
    }
}

/// Unescape the interior of a standard Rust `"..."` string literal so SQL
/// scanning sees the exact string passed to SQLite (`\"` -> `"`, `\'` -> `'`,
/// `\n` / `\r` / `\t`, `\\`, and `\<newline><ws>` line continuations).
fn unescape_rust_string(raw: &str) -> String {
    let b = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            match b[i + 1] {
                b'"' => {
                    out.push('"');
                    i += 2;
                }
                b'\'' => {
                    out.push('\'');
                    i += 2;
                }
                b'\\' => {
                    out.push('\\');
                    i += 2;
                }
                b'n' => {
                    out.push('\n');
                    i += 2;
                }
                b'r' => {
                    out.push('\r');
                    i += 2;
                }
                b't' => {
                    out.push('\t');
                    i += 2;
                }
                b'\n' | b'\r' => {
                    i += 2;
                    while i < b.len() && b[i].is_ascii_whitespace() {
                        i += 1;
                    }
                }
                _ => {
                    out.push('\\');
                    i += 1;
                }
            }
        } else {
            let ch = raw[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

#[derive(Debug)]
struct RustStringLit {
    /// Byte offset in the original source where this string literal starts.
    src_offset: usize,
    /// Decoded string content (what Rust passes at runtime).
    text: String,
}

/// Parse one Rust string literal (normal `"..."` or raw `r#*"..."#*`, with
/// optional `b`/`c` prefix) starting at `i`. Returns `(lit, next_idx)`.
fn parse_rust_string_at(src: &str, i: usize) -> Option<(RustStringLit, usize)> {
    let b = src.as_bytes();
    let mut k = i;
    if matches!(b.get(k), Some(b'b' | b'c'))
        && (k == 0 || !is_ident_byte(b[k - 1]))
        && matches!(b.get(k + 1), Some(b'"' | b'r'))
    {
        k += 1;
    }
    if b.get(k) == Some(&b'r')
        && (k == i || b[i] == b'b' || b[i] == b'c')
        && (i == 0 || !is_ident_byte(b[i - 1]))
    {
        let hashes = b[k + 1..].iter().take_while(|c| **c == b'#').count();
        if b.get(k + 1 + hashes) == Some(&b'"') {
            let close = format!("\"{}", "#".repeat(hashes));
            let content_start = k + 2 + hashes;
            let content_end = src[content_start..].find(&close).map_or(b.len(), |n| content_start + n);
            let next = (content_end + close.len()).min(b.len());
            return Some((
                RustStringLit {
                    src_offset: content_start,
                    text: src[content_start..content_end].to_string(),
                },
                next,
            ));
        }
    }
    if b.get(k) == Some(&b'"') {
        let content_start = k + 1;
        let mut j = content_start;
        while j < b.len() && b[j] != b'"' {
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        let content_end = j.min(b.len());
        let next = (j + 1).min(b.len());
        return Some((
            RustStringLit {
                src_offset: content_start,
                text: unescape_rust_string(&src[content_start..content_end]),
            },
            next,
        ));
    }
    None
}

/// Extract every Rust string literal from `src`, skipping comments and char
/// literals, and joining string-literal arguments inside `concat!(...)`.
fn extract_rust_string_literals(src: &str) -> Vec<RustStringLit> {
    let b = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                i = src[i..].find('\n').map_or(b.len(), |n| i + n + 1);
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                i = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
            }
            // Skip char literals (`'x'`, `'"'`, `'\''`) so `'"'` does not open a string.
            b'\'' => {
                let end = if b.get(i + 1) == Some(&b'\\') {
                    src.get(i + 3..).and_then(|r| r.find('\'')).map(|n| i + 3 + n)
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else {
                    src[i + 1..].chars().next().and_then(|c| {
                        let after = i + 1 + c.len_utf8();
                        (b.get(after) == Some(&b'\'')).then_some(after)
                    })
                };
                i = end.map_or(i + 1, |e| e + 1);
            }
            // Join `concat!("...", "...")` literal pieces into one SQL string.
            b'c' if (i == 0 || !is_ident_byte(b[i - 1])) && src[i..].starts_with("concat!") => {
                let mut k = i + "concat!".len();
                while k < b.len() && b[k].is_ascii_whitespace() {
                    k += 1;
                }
                if matches!(b.get(k), Some(b'(' | b'[' | b'{')) {
                    let close_delim = match b[k] {
                        b'(' => b')',
                        b'[' => b']',
                        _ => b'}',
                    };
                    k += 1;
                    let mut combined = String::new();
                    let mut first_offset = None;
                    let mut valid = true;
                    while k < b.len() {
                        while k < b.len() && (b[k].is_ascii_whitespace() || b[k] == b',') {
                            k += 1;
                        }
                        if b.get(k) == Some(&close_delim) {
                            k += 1;
                            break;
                        }
                        if b.get(k) == Some(&b'/') && b.get(k + 1) == Some(&b'/') {
                            k = src[k..].find('\n').map_or(b.len(), |n| k + n + 1);
                            continue;
                        }
                        if let Some((lit, next)) = parse_rust_string_at(src, k) {
                            if first_offset.is_none() {
                                first_offset = Some(lit.src_offset);
                            }
                            combined.push_str(&lit.text);
                            k = next;
                        } else {
                            valid = false;
                            break;
                        }
                    }
                    if valid && let Some(src_offset) = first_offset {
                        out.push(RustStringLit { src_offset, text: combined });
                        i = k;
                        continue;
                    }
                }
                i += 1;
            }
            _ => {
                if let Some((lit, next)) = parse_rust_string_at(src, i) {
                    out.push(lit);
                    i = next;
                } else {
                    i += 1;
                }
            }
        }
    }
    out
}

/// Read one SQLite identifier at `i` in decoded SQL text, supporting unquoted
/// (`t`), single-quoted (`'t'`), double-quoted (`"t"`), backtick-quoted
/// (`` `t` ``), and bracket-quoted (`[t]`) spellings.
fn read_sql_ident(text: &str, i: usize) -> Option<(String, usize)> {
    let b = text.as_bytes();
    let i = skip_space(b, i);
    let first = *b.get(i)?;

    let (quote_end, start) = if matches!(first, b'"' | b'\'' | b'`') {
        (first, i + 1)
    } else if first == b'[' {
        (b']', i + 1)
    } else {
        let n = b[i..].iter().take_while(|c| is_ident_byte(**c)).count();
        if n == 0 {
            return None;
        }
        return Some((text[i..i + n].to_string(), i + n));
    };

    let mut j = start;
    while j < b.len() {
        if b[j] == quote_end {
            // Skip doubled quote escape inside SQL (e.g. "" or '').
            if b.get(j + 1) == Some(&quote_end) && quote_end != b']' {
                j += 2;
                continue;
            }
            return Some((text[start..j].to_string(), j + 1));
        }
        if b[j] == b'\n' || b[j] == b';' {
            return None;
        }
        j += 1;
    }
    None
}

/// Parse `[<schema>.]<table>` at `i`, returning `(lowercased_table, next_idx)`.
fn parse_sql_table_name(text: &str, i: usize) -> Option<(String, usize)> {
    let b = text.as_bytes();
    let (first, after_first) = read_sql_ident(text, i)?;
    let j = skip_space(b, after_first);
    if b.get(j) == Some(&b'.') {
        let (table, after_table) = read_sql_ident(text, j + 1)?;
        Some((table.to_ascii_lowercase(), after_table))
    } else {
        Some((first.to_ascii_lowercase(), after_first))
    }
}

/// Whether decoded SQL text starting at `i` is a `format!` table-name slot
/// (`{...}`), optionally prefixed by quotes or a `<schema>.` qualifier.
fn has_dynamic_table_slot(text: &str, i: usize) -> bool {
    let b = text.as_bytes();
    let mut j = skip_space(b, i);
    // Optional schema prefix like `main.{}` or `"main".{}`.
    if let Some((_, after_first)) = read_sql_ident(text, j) {
        let dot = skip_space(b, after_first);
        if b.get(dot) == Some(&b'.') {
            j = skip_space(b, dot + 1);
        }
    }
    // Skip opening SQL quotes (`"`, `'`, `` ` ``, `[`).
    while j < b.len() && matches!(b[j], b'"' | b'\'' | b'`' | b'[') {
        j += 1;
    }
    if b.get(j) != Some(&b'{') {
        return false;
    }
    // Escaped literal `{{` is not a format slot.
    if b.get(j + 1) == Some(&b'{') {
        return false;
    }
    // Ensure a closing `}` exists before newline or `;`.
    for &ch in &b[j + 1..] {
        if ch == b'}' {
            return true;
        }
        if ch == b'\n' || ch == b';' {
            return false;
        }
    }
    false
}

/// True if the remainder of the SQL statement starting at `from` (inside a
/// single decoded string literal) contains an `ON CONFLICT ... DO UPDATE`
/// clause before the next unquoted `;`.
fn stmt_has_on_conflict_do_update(text: &str, from: usize) -> bool {
    let b = text.as_bytes();
    let mut i = from;
    let mut saw_on_conflict = false;
    while i < b.len() {
        // Skip SQL single-quoted string literals so `';'` inside a value does not end the statement.
        if b[i] == b'\'' {
            i += 1;
            while i < b.len() {
                if b[i] == b'\'' {
                    if b.get(i + 1) == Some(&b'\'') {
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b[i] == b';' {
            break;
        }
        if i == 0 || !is_ident_byte(b[i - 1]) {
            if let Some(after_on) = keyword_ci(b, i, "ON") {
                let k = skip_space(b, after_on);
                if keyword_ci(b, k, "CONFLICT").is_some() {
                    saw_on_conflict = true;
                }
            } else if saw_on_conflict && let Some(after_do) = keyword_ci(b, i, "DO") {
                let k = skip_space(b, after_do);
                if keyword_ci(b, k, "UPDATE").is_some() {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SqlMutationKind {
    Update,
    InsertOrReplace,
    ReplaceInto,
    OnConflictDoUpdate,
}

impl SqlMutationKind {
    fn as_str(&self) -> &'static str {
        match self {
            SqlMutationKind::Update => "UPDATE",
            SqlMutationKind::InsertOrReplace => "INSERT OR REPLACE",
            SqlMutationKind::ReplaceInto => "REPLACE INTO",
            SqlMutationKind::OnConflictDoUpdate => "ON CONFLICT ... DO UPDATE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlMutation {
    line: usize,
    table: String,
    kind: SqlMutationKind,
}

/// Find every SQL mutation (`UPDATE`, `INSERT OR REPLACE`, `REPLACE INTO`,
/// `INSERT ... ON CONFLICT ... DO UPDATE`) targeting `graph_nodes`,
/// `graph_edges`, or `graph_org_counts` across all Rust string literals in `src`.
fn graph_sql_mutations(src: &str) -> Vec<SqlMutation> {
    let mut out = Vec::new();
    for lit in extract_rust_string_literals(src) {
        let text = lit.text.as_str();
        let b = text.as_bytes();
        let base_line = support::line_of(src, lit.src_offset);
        let line_at = |at: usize| base_line + text[..at].bytes().filter(|&c| c == b'\n').count();
        for start in 0..b.len() {
            if start > 0 && is_ident_byte(b[start - 1]) {
                continue;
            }
            // 1. `UPDATE [OR <conflict>] [<schema>.]<table>`
            if let Some(after_update) = keyword_ci(b, start, "UPDATE") {
                let before = text[..start].trim_end();
                let prev_word =
                    before.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next().unwrap_or("");
                // Skip SQLite trigger headers (`BEFORE/AFTER/OF UPDATE`) and `DO UPDATE`
                // (which is caught at its enclosing `INSERT INTO <table>`).
                if prev_word.eq_ignore_ascii_case("BEFORE")
                    || prev_word.eq_ignore_ascii_case("AFTER")
                    || prev_word.eq_ignore_ascii_case("OF")
                    || prev_word.eq_ignore_ascii_case("DO")
                {
                    continue;
                }
                let mut i = skip_space(b, after_update);
                if let Some(after_or) = keyword_ci(b, i, "OR") {
                    let k = skip_space(b, after_or);
                    let w = b[k..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
                    i = skip_space(b, k + w);
                }
                if let Some((table, _)) = parse_sql_table_name(text, i)
                    && GUARDED_TABLES.contains(&table.as_str())
                {
                    out.push(SqlMutation { line: line_at(start), table, kind: SqlMutationKind::Update });
                }
                continue;
            }

            // 2. `INSERT [OR <conflict>] INTO [<schema>.]<table> ...`
            if let Some(after_insert) = keyword_ci(b, start, "INSERT") {
                let mut i = skip_space(b, after_insert);
                let mut is_or_replace = false;
                if let Some(after_or) = keyword_ci(b, i, "OR") {
                    let k = skip_space(b, after_or);
                    if let Some(after_rep) = keyword_ci(b, k, "REPLACE") {
                        is_or_replace = true;
                        i = skip_space(b, after_rep);
                    } else {
                        let w = b[k..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
                        i = skip_space(b, k + w);
                    }
                }
                let Some(after_into) = keyword_ci(b, i, "INTO") else {
                    continue;
                };
                let Some((table, after_table)) = parse_sql_table_name(text, after_into) else {
                    continue;
                };
                if !GUARDED_TABLES.contains(&table.as_str()) {
                    continue;
                }
                if is_or_replace {
                    out.push(SqlMutation {
                        line: line_at(start),
                        table,
                        kind: SqlMutationKind::InsertOrReplace,
                    });
                } else if stmt_has_on_conflict_do_update(text, after_table) {
                    out.push(SqlMutation {
                        line: line_at(start),
                        table,
                        kind: SqlMutationKind::OnConflictDoUpdate,
                    });
                }
                continue;
            }

            // 3. Standalone `REPLACE INTO [<schema>.]<table>`
            if let Some(after_replace) = keyword_ci(b, start, "REPLACE") {
                let before = text[..start].trim_end();
                let prev_word =
                    before.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next().unwrap_or("");
                if prev_word.eq_ignore_ascii_case("OR") {
                    continue;
                }
                let i = skip_space(b, after_replace);
                let Some(after_into) = keyword_ci(b, i, "INTO") else {
                    continue;
                };
                if let Some((table, _)) = parse_sql_table_name(text, after_into)
                    && GUARDED_TABLES.contains(&table.as_str())
                {
                    out.push(SqlMutation { line: line_at(start), table, kind: SqlMutationKind::ReplaceInto });
                }
            }
        }
    }
    out
}

/// Find `format!` literals whose SQL places a dynamic `{...}` slot directly in
/// the table position of `UPDATE`, `INSERT OR REPLACE INTO`, `REPLACE INTO`,
/// or `INSERT ... INTO {...} ... ON CONFLICT ... DO UPDATE`. Returns 1-based line numbers.
fn dynamic_table_slot_dml(src: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    for lit in extract_rust_string_literals(src) {
        let text = lit.text.as_str();
        let b = text.as_bytes();
        let base_line = support::line_of(src, lit.src_offset);
        let line_at = |at: usize| base_line + text[..at].bytes().filter(|&c| c == b'\n').count();
        for start in 0..b.len() {
            if start > 0 && is_ident_byte(b[start - 1]) {
                continue;
            }
            if let Some(after_update) = keyword_ci(b, start, "UPDATE") {
                let before = text[..start].trim_end();
                let prev_word =
                    before.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next().unwrap_or("");
                if prev_word.eq_ignore_ascii_case("BEFORE")
                    || prev_word.eq_ignore_ascii_case("AFTER")
                    || prev_word.eq_ignore_ascii_case("OF")
                    || prev_word.eq_ignore_ascii_case("DO")
                {
                    continue;
                }
                let mut i = skip_space(b, after_update);
                if let Some(after_or) = keyword_ci(b, i, "OR") {
                    let k = skip_space(b, after_or);
                    let w = b[k..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
                    i = skip_space(b, k + w);
                }
                if has_dynamic_table_slot(text, i) {
                    hits.push(line_at(start));
                }
                continue;
            }
            if let Some(after_insert) = keyword_ci(b, start, "INSERT") {
                let mut i = skip_space(b, after_insert);
                let mut is_or_replace = false;
                if let Some(after_or) = keyword_ci(b, i, "OR") {
                    let k = skip_space(b, after_or);
                    if let Some(after_rep) = keyword_ci(b, k, "REPLACE") {
                        is_or_replace = true;
                        i = skip_space(b, after_rep);
                    } else {
                        let w = b[k..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
                        i = skip_space(b, k + w);
                    }
                }
                if let Some(after_into) = keyword_ci(b, i, "INTO")
                    && has_dynamic_table_slot(text, after_into)
                    && (is_or_replace || stmt_has_on_conflict_do_update(text, after_into))
                {
                    hits.push(line_at(start));
                }
                continue;
            }
            if let Some(after_replace) = keyword_ci(b, start, "REPLACE") {
                let before = text[..start].trim_end();
                let prev_word =
                    before.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next().unwrap_or("");
                if prev_word.eq_ignore_ascii_case("OR") {
                    continue;
                }
                let i = skip_space(b, after_replace);
                if let Some(after_into) = keyword_ci(b, i, "INTO")
                    && has_dynamic_table_slot(text, after_into)
                {
                    hits.push(line_at(start));
                }
            }
        }
    }
    hits
}

/// Find whole-identifier references to `ident` in masked Rust source.
fn find_ident_refs<'a>(masked: &'a str, ident: &'a str) -> impl Iterator<Item = usize> + 'a {
    support::find_all(masked, ident)
        .filter(move |&at| masked.as_bytes().get(at + ident.len()).is_none_or(|c| !is_ident_byte(*c)))
}

fn direct_low_level_update_calls(path: &str, masked_non_test: &str) -> Vec<String> {
    if path.ends_with("crates/ua-graph/src/write.rs") || path.ends_with("crates/ua-store/src/graph.rs") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for ident in ["update_node_mutable", "update_edge_weight"] {
        for at in find_ident_refs(masked_non_test, ident) {
            let line = support::line_of(masked_non_test, at);
            findings.push(format!(
                "{path}:{line}: direct reference to low-level GraphRepo::{ident}; \
                 use ua_graph::graph_node_update / ua_graph::graph_edge_update_weight"
            ));
        }
    }
    findings
}

fn domain_update_call_violations(path: &str, masked_non_test: &str, allowlist: &[&str]) -> Vec<String> {
    if path.ends_with("crates/ua-graph/src/write.rs") || path.ends_with("crates/ua-graph/src/lib.rs") {
        return Vec::new();
    }
    if allowlist.iter().any(|allowed| path.ends_with(allowed)) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for ident in ["graph_node_update", "graph_edge_update_weight"] {
        for at in find_ident_refs(masked_non_test, ident) {
            let line = support::line_of(masked_non_test, at);
            findings.push(format!(
                "{path}:{line}: unauthorized reference to domain-only `{ident}`; \
                 only allowlisted domain consumers (never generic graph tools or ua-server) may call it"
            ));
        }
    }
    findings
}

fn migration_graph_call_violations(path: &str, masked_non_test: &str, allowlist: &[&str]) -> Vec<String> {
    if path.ends_with("crates/ua-store/src/graph.rs") || allowlist.iter().any(|a| path.ends_with(a)) {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for at in find_ident_refs(masked_non_test, "MigrationGraph") {
        let line = support::line_of(masked_non_test, at);
        findings.push(format!(
            "{path}:{line}: unauthorized reference to `MigrationGraph` (which skips ledger writes); \
             only allowlisted migration/import modules may construct it"
        ));
    }
    findings
}

#[test]
fn graph_table_updates_only_exist_in_sanctioned_primitives() {
    // Structural invariant on the allowlists themselves: generic graph tools and
    // ua-server must never be allowlisted to call domain-only node/edge updates
    // or ledger-skipping MigrationGraph writes.
    for entry in DOMAIN_UPDATE_CALL_ALLOWLIST {
        assert!(
            !entry.contains("families/graph_store.rs") && !entry.contains("crates/ua-server/"),
            "forbidden path in DOMAIN_UPDATE_CALL_ALLOWLIST: {entry}"
        );
    }
    for entry in MIGRATION_GRAPH_ALLOWLIST {
        assert!(
            !entry.contains("families/graph_store.rs") && !entry.contains("crates/ua-server/"),
            "forbidden path in MIGRATION_GRAPH_ALLOWLIST: {entry}"
        );
    }

    let files = support::sources();
    assert!(files.len() > 100, "found only {} workspace source files", files.len());

    let mut violations = Vec::new();
    let mut store_node_updates = 0usize;
    let mut store_edge_updates = 0usize;
    let mut schema_counter_upserts = 0usize;

    for (path, src) in &files {
        let path_str = path.display().to_string().replace('\\', "/");
        let raw_non_test = support::without_tests_raw(src);
        for m in graph_sql_mutations(&raw_non_test) {
            if path_str.ends_with("crates/ua-store/src/graph.rs") && m.kind == SqlMutationKind::Update {
                match m.table.as_str() {
                    "graph_nodes" => {
                        store_node_updates += 1;
                        continue;
                    }
                    "graph_edges" => {
                        store_edge_updates += 1;
                        continue;
                    }
                    _ => {}
                }
            }
            if path_str.ends_with("crates/ua-graph/src/schema.rs")
                && m.table == "graph_org_counts"
                && m.kind == SqlMutationKind::OnConflictDoUpdate
            {
                schema_counter_upserts += 1;
                continue;
            }
            violations.push(format!(
                "{path_str}:{}: unauthorized SQL `{}` on `{}`; mutable graph updates must go \
                 through ua_graph::graph_node_update / ua_graph::graph_edge_update_weight / ua_graph::retract_edge",
                m.line,
                m.kind.as_str(),
                m.table
            ));
        }

        if DYNAMIC_SQL_GUARDED_CRATES.iter().any(|c| path_str.contains(c)) {
            for line in dynamic_table_slot_dml(&raw_non_test) {
                violations.push(format!(
                    "{path_str}:{line}: dynamic table-slot UPDATE/REPLACE/UPSERT in format string is forbidden \
                     in crates touching graph tables"
                ));
            }
        }

        let masked_non_test = support::without_tests(src);
        violations.extend(direct_low_level_update_calls(&path_str, &masked_non_test));
        violations.extend(domain_update_call_violations(
            &path_str,
            &masked_non_test,
            DOMAIN_UPDATE_CALL_ALLOWLIST,
        ));
        violations.extend(migration_graph_call_violations(
            &path_str,
            &masked_non_test,
            MIGRATION_GRAPH_ALLOWLIST,
        ));
    }

    assert!(violations.is_empty(), "graph update guard violations:\n{}", violations.join("\n"));
    assert_eq!(
        store_node_updates, 1,
        "expected exactly 1 UPDATE graph_nodes in crates/ua-store/src/graph.rs (update_node_mutable), found {store_node_updates}"
    );
    assert_eq!(
        store_edge_updates, 2,
        "expected exactly 2 UPDATE graph_edges in crates/ua-store/src/graph.rs (close_edge + update_edge_weight), found {store_edge_updates}"
    );
    assert_eq!(
        schema_counter_upserts, 3,
        "expected exactly 3 graph_org_counts ON CONFLICT DO UPDATE in crates/ua-graph/src/schema.rs, found {schema_counter_upserts}"
    );
}

#[test]
fn update_guard_catches_all_sql_variants_dynamic_slots_and_call_allowlist_bypasses() {
    let bad_sql: &[(&str, &str, SqlMutationKind)] = &[
        // Plain and lowercase UPDATE
        (
            r#"let q = "UPDATE graph_nodes SET visibility = 'org' WHERE id = ?1";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        (
            r#"let q = "update graph_edges set weight = 2.0 where id = ?1";"#,
            "graph_edges",
            SqlMutationKind::Update,
        ),
        (
            r#"let q = "UPDATE graph_org_counts SET node_count = 0";"#,
            "graph_org_counts",
            SqlMutationKind::Update,
        ),
        // Single, double, backtick, bracket, and Rust-escaped quoting
        (r#"let q = "UPDATE 'graph_nodes' SET visibility = 'org'";"#, "graph_nodes", SqlMutationKind::Update),
        (r#"let q = "UPDATE `graph_edges` SET weight = 9.0";"#, "graph_edges", SqlMutationKind::Update),
        (
            r#"let q = "UPDATE [graph_org_counts] SET edge_count = 0";"#,
            "graph_org_counts",
            SqlMutationKind::Update,
        ),
        (
            r#"let q = "UPDATE \"graph_nodes\" SET display_label = 'x'";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        // Any schema prefix (unquoted, single-quoted, double-quoted, backtick-quoted)
        (r#"let q = "UPDATE main.graph_edges SET weight = 1.0";"#, "graph_edges", SqlMutationKind::Update),
        (
            r#"let q = "UPDATE \"main\".\"graph_nodes\" SET visibility = 'org'";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        (
            r#"let q = "UPDATE 'temp'.'graph_nodes' SET visibility = 'org'";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        (
            r#"let q = "UPDATE `attached`.`graph_org_counts` SET node_count = 0";"#,
            "graph_org_counts",
            SqlMutationKind::Update,
        ),
        // UPDATE OR <conflict> and multiline Rust string continuation
        (
            r#"let q = "UPDATE OR IGNORE graph_nodes SET meta_json = '{}'";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        ("let q = \"UPDATE \\\n    graph_edges SET weight = 3.0\";", "graph_edges", SqlMutationKind::Update),
        // INSERT OR REPLACE / REPLACE INTO
        (
            r#"let q = "INSERT OR REPLACE INTO graph_nodes (id, org_id) VALUES (?1, ?2)";"#,
            "graph_nodes",
            SqlMutationKind::InsertOrReplace,
        ),
        (
            r#"let q = "INSERT OR REPLACE INTO 'main'.'graph_edges' (id) VALUES (?1)";"#,
            "graph_edges",
            SqlMutationKind::InsertOrReplace,
        ),
        (
            r#"let q = "REPLACE INTO `graph_org_counts` (org_id, node_count, edge_count) VALUES ('default', 0, 0)";"#,
            "graph_org_counts",
            SqlMutationKind::ReplaceInto,
        ),
        // ON CONFLICT ... DO UPDATE (upsert), including raw strings with quoted columns
        (
            r#"let q = "INSERT INTO graph_nodes (id, org_id) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET visibility = 'org'";"#,
            "graph_nodes",
            SqlMutationKind::OnConflictDoUpdate,
        ),
        (
            r#"let q = "INSERT INTO \"main\".\"graph_edges\" (id) VALUES (?1) ON CONFLICT DO UPDATE SET weight = 9.0";"#,
            "graph_edges",
            SqlMutationKind::OnConflictDoUpdate,
        ),
        (
            r##"let q = r#"INSERT INTO "graph_nodes" ("node_id") VALUES (?1) ON CONFLICT("node_id") DO UPDATE SET display_label = ?2"#;"##,
            "graph_nodes",
            SqlMutationKind::OnConflictDoUpdate,
        ),
        // SQL comments, `\n` escapes, `concat!`, and preceding char literal `'"'`
        (
            r#"let q = "UPDATE /* sneak */ \"graph_nodes\" SET visibility = 'org'";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        (
            r#"let q = "UPDATE -- sneak\n graph_edges SET weight = 9.0";"#,
            "graph_edges",
            SqlMutationKind::Update,
        ),
        (r#"let q = "UPDATE\ngraph_nodes SET visibility = 'org'";"#, "graph_nodes", SqlMutationKind::Update),
        (
            r#"let q = concat!("UPDATE ", "graph_nodes", " SET visibility = 'org'");"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
        (
            r#"let c = '"'; let q = "UPDATE graph_nodes SET visibility = 'org'";"#,
            "graph_nodes",
            SqlMutationKind::Update,
        ),
    ];
    for (sample, exp_table, exp_kind) in bad_sql {
        let found = graph_sql_mutations(sample);
        assert_eq!(found.len(), 1, "expected 1 finding for {sample:?}, got {found:?}");
        assert_eq!(found[0].table, *exp_table, "{sample:?}");
        assert_eq!(found[0].kind, *exp_kind, "{sample:?}");
    }

    let ok_samples = [
        // Plain INSERT without OR REPLACE or ON CONFLICT DO UPDATE is not an update.
        r#"let q = "INSERT INTO graph_nodes (id, org_id) VALUES (?1, ?2)";"#,
        r#"let q = "INSERT INTO graph_nodes (id, org_id) VALUES (?1, ?2) ON CONFLICT DO NOTHING";"#,
        // Separate string literals do not bleed `ON CONFLICT DO UPDATE` from a later query.
        r#"let a = "INSERT INTO graph_nodes (id) VALUES (?1)"; let b = "INSERT INTO tasks (id) VALUES (?1) ON CONFLICT DO UPDATE SET x = 1";"#,
        // Trigger headers are DDL, not DML UPDATEs.
        r#"const SQL: &str = "CREATE TRIGGER t BEFORE UPDATE ON graph_nodes BEGIN SELECT 1; END";"#,
        r#"const SQL: &str = "CREATE TRIGGER t AFTER UPDATE OF weight ON graph_edges BEGIN SELECT 1; END";"#,
        // Comments mentioning UPDATE/REPLACE are ignored.
        "// Never run UPDATE graph_nodes or REPLACE INTO graph_edges directly.",
        "/* INSERT OR REPLACE INTO graph_org_counts */",
        // Unrelated table names are ignored.
        r#"let q = "UPDATE graph_canvas_scenes SET title = 'x'";"#,
        r#"let q = "UPDATE graph_nodes_shadow SET x = 1";"#,
    ];
    for sample in ok_samples {
        let found = graph_sql_mutations(sample);
        assert!(found.is_empty(), "false positive on {sample:?}: {found:?}");
    }

    // Dynamic `format!` table-slot DML detection.
    for dyn_bad in [
        r#"let q = format!("UPDATE {} SET visibility = 'org'", "graph_nodes");"#,
        r#"let q = format!("UPDATE {table} SET weight = 2.0");"#,
        r#"let q = format!("UPDATE \"{table}\" SET weight = 2.0");"#,
        r#"let q = format!("UPDATE main.{} SET weight = 2.0", t);"#,
        r#"let q = format!("INSERT OR REPLACE INTO {} (id) VALUES (?1)", t);"#,
        r#"let q = format!("REPLACE INTO {t} (id) VALUES (?1)");"#,
        r#"let q = format!("INSERT INTO {} (id) VALUES (?1) ON CONFLICT(id) DO UPDATE SET visibility = 'org'", t);"#,
    ] {
        assert_eq!(
            dynamic_table_slot_dml(dyn_bad).len(),
            1,
            "expected dynamic table-slot DML hit for {dyn_bad:?}"
        );
    }
    // Literal table name with dynamic column slot is NOT a dynamic table slot.
    let static_table_dyn_col = r#"let q = format!("UPDATE tasks SET {col} = ?1 WHERE id = ?2");"#;
    assert!(dynamic_table_slot_dml(static_table_dyn_col).is_empty());

    // `#[cfg(test)]` blocks are excluded from workspace scans.
    let in_test = r#"
        #[cfg(test)]
        mod tests {
            fn f() {
                let _ = "UPDATE 'graph_nodes' SET visibility = 'private'";
            }
        }
    "#;
    let stripped_test = support::without_tests_raw(in_test);
    assert!(graph_sql_mutations(&stripped_test).is_empty());

    // Direct calls (or imports/aliases) to low-level GraphRepo update methods are caught.
    let bad_low_level = r#"
        fn sneak(tx: &mut WriteTx) {
            let _ = tx.update_node_mutable("default", "n1", &patch);
            let _ = tx.update_edge_weight("default", "e1", 2.0);
        }
    "#;
    let masked_low = support::without_tests(bad_low_level);
    assert_eq!(
        direct_low_level_update_calls("crates/ua-tools/src/families/graph_store.rs", &masked_low).len(),
        2
    );
    assert!(direct_low_level_update_calls("crates/ua-graph/src/write.rs", &masked_low).is_empty());

    // Domain-update call allowlist catches both direct calls and renamed `use` aliases.
    let bad_domain_calls = r#"
        use ua_graph::graph_node_update as stealth;
        fn sneak(tx: &mut WriteTx) {
            let _ = ua_graph::graph_node_update(tx, req);
            let _ = ua_graph::graph_edge_update_weight(tx, wreq);
        }
    "#;
    let masked_dom = support::without_tests(bad_domain_calls);
    assert_eq!(
        domain_update_call_violations(
            "crates/ua-tools/src/families/graph_store.rs",
            &masked_dom,
            DOMAIN_UPDATE_CALL_ALLOWLIST,
        )
        .len(),
        3
    );
    assert_eq!(
        domain_update_call_violations(
            "crates/ua-server/src/http.rs",
            &masked_dom,
            DOMAIN_UPDATE_CALL_ALLOWLIST,
        )
        .len(),
        3
    );
    // An explicitly allowlisted domain file is permitted.
    assert!(
        domain_update_call_violations(
            "crates/ua-tools/src/families/memory/mod.rs",
            &masked_dom,
            &["crates/ua-tools/src/families/memory/mod.rs"],
        )
        .is_empty()
    );
    assert!(
        domain_update_call_violations(
            "crates/ua-graph/src/write.rs",
            &masked_dom,
            DOMAIN_UPDATE_CALL_ALLOWLIST,
        )
        .is_empty()
    );

    // MigrationGraph allowlist catches unauthorized usage and permits allowlisted modules.
    let bad_mig_use = r#"
        use ua_store::graph::MigrationGraph;
        fn bypass(conn: &Connection) {
            let _repo = MigrationGraph::new(conn);
        }
    "#;
    let masked_mig = support::without_tests(bad_mig_use);
    assert_eq!(
        migration_graph_call_violations(
            "crates/ua-tools/src/families/graph_store.rs",
            &masked_mig,
            MIGRATION_GRAPH_ALLOWLIST,
        )
        .len(),
        2
    );
    assert!(
        migration_graph_call_violations(
            "crates/ua-tools/src/families/tasks/graph.rs",
            &masked_mig,
            MIGRATION_GRAPH_ALLOWLIST,
        )
        .is_empty()
    );
}
