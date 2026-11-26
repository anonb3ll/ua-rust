//! Workspace source-scan guard for C2 slice 1 (`docs/graph.md`):
//!
//! 1. Every DML `UPDATE graph_nodes` or `UPDATE graph_edges` in non-test code
//!    across the entire workspace must live exclusively inside
//!    `crates/ua-store/src/graph.rs` (exact sanctioned count: 1 node update in
//!    `update_node_mutable`, 2 edge updates in `close_edge` and
//!    `update_edge_weight`).
//! 2. No non-test code outside `crates/ua-graph/src/write.rs` and
//!    `crates/ua-store/src/graph.rs` may call `.update_node_mutable(` or
//!    `.update_edge_weight(` directly; every mutable-field change must go
//!    through `ua_graph::graph_node_update` / `ua_graph::graph_edge_update_weight`
//!    so the same-transaction ledger event and redaction rules always run.

#[path = "../../ua-core/tests/support/mod.rs"]
mod support;

const GUARDED_TABLES: &[&str] = &["graph_nodes", "graph_edges"];

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

fn skip_space(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'\\') {
        i += 1;
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

/// Blank Rust line comments (`// ...`) and block comments (`/* ... */`) while
/// preserving string literals (so SQL inside string literals stays intact and
/// line offsets remain exact).
fn strip_comments_keep_strings(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
                blank(&mut out, i, end);
                i = end;
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && (i == 0 || !is_ident_byte(b[i - 1])) =>
            {
                let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
                if b.get(i + 1 + hashes) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let start = i + 2 + hashes;
                let end = src[start..].find(&close).map_or(b.len(), |n| start + n + close.len());
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                i = (j + 1).min(b.len());
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).expect("comment stripping preserves UTF-8 boundaries")
}

/// Every DML `UPDATE [OR <conflict>] [<schema>.]<table>` statement targeting
/// `graph_nodes` or `graph_edges` found in `text`, returning `(offset, table)`.
///
/// Trigger headers (`BEFORE UPDATE ON ...`, `AFTER UPDATE OF ... ON ...`,
/// `INSTEAD OF UPDATE ON ...`) are excluded.
fn graph_updates(text: &str) -> Vec<(usize, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    for start in 0..b.len() {
        if start > 0 && is_ident_byte(b[start - 1]) {
            continue;
        }
        let Some(after_update) = keyword_ci(b, start, "UPDATE") else {
            continue;
        };
        // Skip SQLite trigger headers (`BEFORE UPDATE`, `AFTER UPDATE`, `OF UPDATE`).
        let before = text[..start].trim_end_matches(|c: char| c.is_whitespace() || c == '\\');
        let prev_word =
            before.rsplit(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).next().unwrap_or("");
        if prev_word.eq_ignore_ascii_case("BEFORE")
            || prev_word.eq_ignore_ascii_case("AFTER")
            || prev_word.eq_ignore_ascii_case("OF")
        {
            continue;
        }
        let mut i = skip_space(b, after_update);
        if let Some(after_or) = keyword_ci(b, i, "OR") {
            let k = skip_space(b, after_or);
            let w = b[k..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
            i = skip_space(b, k + w);
        }
        // Optional quoting (`"t"`, `\"t\"`, `` `t` ``, `[t]`) and `main.` schema prefix.
        while i < b.len() && matches!(b[i], b'"' | b'\\' | b'`' | b'[') {
            i += 1;
        }
        if let Some(after_main) = keyword_ci(b, i, "main").filter(|e| b.get(*e) == Some(&b'.')) {
            i = after_main + 1;
        }
        let n = b[i..].iter().take_while(|c| is_ident_byte(**c)).count();
        if n == 0 {
            continue;
        }
        let table = text[i..i + n].to_ascii_lowercase();
        if GUARDED_TABLES.contains(&table.as_str()) {
            out.push((start, table));
        }
    }
    out
}

fn direct_low_level_update_calls(path: &str, masked_non_test: &str) -> Vec<String> {
    if path.ends_with("crates/ua-graph/src/write.rs") || path.ends_with("crates/ua-store/src/graph.rs") {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for needle in ["update_node_mutable(", "update_edge_weight("] {
        for at in support::find_all(masked_non_test, needle) {
            let line = support::line_of(masked_non_test, at);
            findings.push(format!(
                "{path}:{line}: direct call to low-level GraphRepo::{needle}..); \
                 use ua_graph::graph_node_update / ua_graph::graph_edge_update_weight"
            ));
        }
    }
    findings
}

#[test]
fn graph_table_updates_only_exist_in_sanctioned_primitives() {
    let files = support::sources();
    assert!(files.len() > 100, "found only {} workspace source files", files.len());

    let mut violations = Vec::new();
    let mut store_node_updates = 0usize;
    let mut store_edge_updates = 0usize;

    for (path, src) in &files {
        let path_str = path.display().to_string().replace('\\', "/");
        let raw_non_test = strip_comments_keep_strings(&support::without_tests_raw(src));
        for (at, table) in graph_updates(&raw_non_test) {
            let line = support::line_of(&raw_non_test, at);
            if path_str.ends_with("crates/ua-store/src/graph.rs") {
                match table.as_str() {
                    "graph_nodes" => store_node_updates += 1,
                    "graph_edges" => store_edge_updates += 1,
                    _ => {}
                }
            } else {
                violations.push(format!(
                    "{path_str}:{line}: unauthorized `UPDATE {table}`; mutable graph updates must go \
                     through ua_graph::graph_node_update / ua_graph::graph_edge_update_weight / ua_graph::retract_edge"
                ));
            }
        }

        let masked_non_test = support::without_tests(src);
        violations.extend(direct_low_level_update_calls(&path_str, &masked_non_test));
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
}

#[test]
fn update_guard_catches_unauthorized_sql_and_direct_repo_calls() {
    let bad_sql = [
        r#"let q = "UPDATE graph_nodes SET visibility = 'org' WHERE id = ?1";"#,
        r#"let q = "update graph_edges set weight = 2.0 where id = ?1";"#,
        r#"let q = "UPDATE OR IGNORE graph_nodes SET meta_json = '{}'";"#,
        r#"let q = "UPDATE main.graph_edges SET weight = 1.0";"#,
        r#"let q = "UPDATE \"graph_nodes\" SET display_label = 'x'";"#,
        "let q = \"UPDATE \\\n    graph_edges SET weight = 3.0\";",
    ];
    for sample in bad_sql {
        let stripped = strip_comments_keep_strings(sample);
        let found = graph_updates(&stripped);
        assert_eq!(found.len(), 1, "expected guard to catch {sample:?}, got {found:?}");
    }

    let ok_samples = [
        // Trigger headers are DDL, not DML UPDATEs.
        r#"const SQL: &str = "CREATE TRIGGER t BEFORE UPDATE ON graph_nodes BEGIN SELECT 1; END";"#,
        r#"const SQL: &str = "CREATE TRIGGER t AFTER UPDATE OF weight ON graph_edges BEGIN SELECT 1; END";"#,
        // Comments mentioning UPDATE are ignored.
        "// Never run UPDATE graph_nodes directly here.",
        "/* UPDATE graph_edges SET weight = 1.0 */",
        // Unrelated table names are ignored.
        r#"let q = "UPDATE graph_canvas_scenes SET title = 'x'";"#,
        r#"let q = "UPDATE graph_nodes_shadow SET x = 1";"#,
    ];
    for sample in ok_samples {
        let stripped = strip_comments_keep_strings(sample);
        let found = graph_updates(&stripped);
        assert!(found.is_empty(), "false positive on {sample:?}: {found:?}");
    }

    // `#[cfg(test)]` blocks are excluded from workspace scans.
    let in_test = r#"
        #[cfg(test)]
        mod tests {
            fn f() {
                let _ = "UPDATE graph_nodes SET visibility = 'private'";
            }
        }
    "#;
    let stripped_test = strip_comments_keep_strings(&support::without_tests_raw(in_test));
    assert!(graph_updates(&stripped_test).is_empty());

    // Direct calls to low-level GraphRepo update methods outside ua-graph/src/write.rs are caught.
    let bad_call = r#"
        fn sneak(tx: &mut WriteTx) {
            let _ = tx.update_node_mutable("default", "n1", &patch);
            let _ = tx.update_edge_weight("default", "e1", 2.0);
        }
    "#;
    let masked = support::without_tests(bad_call);
    let call_hits = direct_low_level_update_calls("crates/ua-tools/src/families/tasks/mod.rs", &masked);
    assert_eq!(call_hits.len(), 2, "{call_hits:?}");
    assert!(direct_low_level_update_calls("crates/ua-graph/src/write.rs", &masked).is_empty());
}
