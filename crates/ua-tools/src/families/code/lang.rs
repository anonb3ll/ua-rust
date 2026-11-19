//! Symbol extraction with tree-sitter.
//!
//! The grammars (Rust, Python, JavaScript/JSX, TypeScript/TSX, Go) are
//! compiled into the binary from their crates; nothing is downloaded at run
//! time. Extraction looks at declarations at file level, inside classes,
//! traits, impls, interfaces, namespaces and modules; it does not descend into
//! function bodies.

use std::path::Path;

use serde::Serialize;
use tree_sitter::{Language, Node, Parser};

/// Languages with a grammar compiled in.
pub const SUPPORTED_LANGUAGES: &[&str] = &["go", "javascript", "python", "rust", "tsx", "typescript"];

/// Deepest nesting of containers followed (modules in modules, classes in namespaces).
const MAX_DEPTH: usize = 32;
const MAX_SIGNATURE_CHARS: usize = 300;
const MAX_DOC_CHARS: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Go,
}

impl Lang {
    pub fn from_path(p: &Path) -> Option<Lang> {
        let ext = p.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "rs" => Lang::Rust,
            "py" | "pyi" => Lang::Python,
            "js" | "jsx" | "mjs" | "cjs" => Lang::JavaScript,
            "ts" | "mts" | "cts" => Lang::TypeScript,
            "tsx" => Lang::Tsx,
            "go" => Lang::Go,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Lang::Rust => "rust",
            Lang::Python => "python",
            Lang::JavaScript => "javascript",
            Lang::TypeScript => "typescript",
            Lang::Tsx => "tsx",
            Lang::Go => "go",
        }
    }

    fn grammar(self) -> Language {
        match self {
            Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
            Lang::Python => tree_sitter_python::LANGUAGE.into(),
            Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Lang::Go => tree_sitter_go::LANGUAGE.into(),
        }
    }
}

/// The keyword a function is written with, for repository maps.
pub fn function_keyword(language: &str) -> &'static str {
    match language {
        "rust" => "fn",
        "python" => "def",
        "go" => "func",
        _ => "function",
    }
}

/// One declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Symbol {
    pub name: String,
    /// `class`, `function` or `method`, as in the original hub.
    #[serde(rename = "type")]
    pub sym_type: &'static str,
    /// Language-level kind: class, struct, enum, union, trait, interface,
    /// type, function, method or macro.
    pub kind: &'static str,
    pub parent: Option<String>,
    pub signature: String,
    /// First line of the doc comment or docstring.
    pub docstring: String,
    /// 1-based.
    pub line_no: usize,
}

/// Why a file produced no symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseFailure {
    GrammarUnavailable,
    ParseFailed,
}

impl ParseFailure {
    pub fn code(self) -> &'static str {
        match self {
            ParseFailure::GrammarUnavailable => "grammar_unavailable",
            ParseFailure::ParseFailed => "parse_failed",
        }
    }
}

/// Parse `src` and list its declarations in source order.
pub fn parse_symbols(lang: Lang, src: &str) -> Result<Vec<Symbol>, ParseFailure> {
    let mut parser = Parser::new();
    parser.set_language(&lang.grammar()).map_err(|_| ParseFailure::GrammarUnavailable)?;
    let tree = parser.parse(src, None).ok_or(ParseFailure::ParseFailed)?;
    let mut ex = Extractor { src: src.as_bytes(), lang, out: Vec::new() };
    ex.walk_container(tree.root_node(), None, 0);
    ex.out.sort_by_key(|s| s.line_no);
    Ok(ex.out)
}

struct Extractor<'a> {
    src: &'a [u8],
    lang: Lang,
    out: Vec<Symbol>,
}

fn collapse(s: &str, cap: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > cap { one.chars().take(cap).collect::<String>() + "…" } else { one }
}

impl<'a> Extractor<'a> {
    fn text(&self, n: Node) -> &'a str {
        n.utf8_text(self.src).unwrap_or("")
    }

    fn field_text(&self, n: Node, field: &str) -> Option<String> {
        n.child_by_field_name(field).map(|c| self.text(c).to_string()).filter(|s| !s.is_empty())
    }

    fn push(&mut self, n: Node, name: String, kind: &'static str, parent: Option<&str>, signature: String) {
        let sym_type = match kind {
            "function" | "macro" => {
                if parent.is_some() {
                    "method"
                } else {
                    "function"
                }
            }
            "method" => "method",
            _ => "class",
        };
        let kind = if kind == "function" && parent.is_some() { "method" } else { kind };
        self.out.push(Symbol {
            name,
            sym_type,
            kind,
            parent: parent.map(str::to_string),
            signature,
            docstring: self.docstring(n),
            line_no: n.start_position().row + 1,
        });
    }

    /// Parameters plus return type, whitespace collapsed.
    fn signature(&self, n: Node) -> String {
        let params = n.child_by_field_name("parameters").map(|p| self.text(p)).unwrap_or("");
        let ret = match self.lang {
            Lang::Rust | Lang::Python => {
                n.child_by_field_name("return_type").map(|r| format!(" -> {}", self.text(r)))
            }
            Lang::Go => n.child_by_field_name("result").map(|r| format!(" {}", self.text(r))),
            _ => n.child_by_field_name("return_type").map(|r| self.text(r).to_string()),
        };
        collapse(&format!("{params}{}", ret.unwrap_or_default()), MAX_SIGNATURE_CHARS)
    }

    fn docstring(&self, n: Node) -> String {
        let raw = match self.lang {
            Lang::Python => self.python_docstring(n),
            _ => self.leading_comment(n),
        };
        raw.map(|d| collapse(&d, MAX_DOC_CHARS)).unwrap_or_default()
    }

    /// The first statement of a Python body when it is a string.
    fn python_docstring(&self, n: Node) -> Option<String> {
        let body = n.child_by_field_name("body")?;
        let first = body.named_child(0)?;
        if first.kind() != "expression_statement" {
            return None;
        }
        let s = first.named_child(0)?;
        if s.kind() != "string" {
            return None;
        }
        let t = self.text(s);
        let t = t.trim_start_matches(|c: char| c.is_ascii_alphabetic());
        let t = t.trim_matches(|c| c == '"' || c == '\'');
        t.lines().map(str::trim).find(|l| !l.is_empty()).map(str::to_string)
    }

    /// The doc comment directly above `n` (skipping attributes and decorators).
    fn leading_comment(&self, n: Node) -> Option<String> {
        let mut anchor = n;
        // In JS/TS an exported declaration's comment sits above the export.
        if let Some(p) = n.parent()
            && p.kind() == "export_statement"
        {
            anchor = p;
        }
        let mut lines: Vec<String> = Vec::new();
        let mut cur = anchor.prev_sibling();
        let mut expected_row = anchor.start_position().row;
        while let Some(c) = cur {
            let kind = c.kind();
            if kind == "attribute_item" || kind == "decorator" {
                expected_row = c.start_position().row;
                cur = c.prev_sibling();
                continue;
            }
            if !kind.contains("comment") {
                break;
            }
            let text = self.text(c);
            // Node text may include a trailing newline; count only real lines.
            let end_row = c.start_position().row + text.trim_end().lines().count().saturating_sub(1);
            if end_row + 1 < expected_row {
                break;
            }
            let doc = match self.lang {
                Lang::Rust => text.starts_with("///") || text.starts_with("/**"),
                Lang::Go => text.starts_with("//") || text.starts_with("/*"),
                _ => text.starts_with("/**") || text.starts_with("//"),
            };
            if !doc {
                break;
            }
            lines.insert(0, text.to_string());
            expected_row = c.start_position().row;
            cur = c.prev_sibling();
        }
        let joined = lines.join("\n");
        joined
            .lines()
            .map(|l| {
                l.trim()
                    .trim_start_matches("/**")
                    .trim_start_matches("/*")
                    .trim_end_matches("*/")
                    .trim_start_matches('/')
                    .trim_start_matches('!')
                    .trim_start_matches('*')
                    .trim()
            })
            .find(|l| !l.is_empty())
            .map(str::to_string)
    }

    fn walk_container(&mut self, n: Node, parent: Option<&str>, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let mut cursor = n.walk();
        let children: Vec<Node> = n.named_children(&mut cursor).collect();
        for c in children {
            match self.lang {
                Lang::Python => self.python(c, parent, depth),
                Lang::Rust => self.rust(c, parent, depth),
                Lang::Go => self.go(c),
                Lang::JavaScript | Lang::TypeScript | Lang::Tsx => self.js(c, parent, depth),
            }
        }
    }

    fn python(&mut self, n: Node, parent: Option<&str>, depth: usize) {
        match n.kind() {
            "decorated_definition" => {
                if let Some(def) = n.child_by_field_name("definition") {
                    self.python(def, parent, depth);
                }
            }
            "class_definition" => {
                let Some(name) = self.field_text(n, "name") else { return };
                self.push(n, name.clone(), "class", parent, String::new());
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk_container(body, Some(&name), depth + 1);
                }
            }
            "function_definition" => {
                let Some(name) = self.field_text(n, "name") else { return };
                let sig = self.signature(n);
                self.push(n, name, "function", parent, sig);
            }
            _ => {}
        }
    }

    fn rust(&mut self, n: Node, parent: Option<&str>, depth: usize) {
        let named = |kind: &'static str, me: &mut Self| {
            if let Some(name) = me.field_text(n, "name") {
                me.push(n, name, kind, parent, String::new());
            }
        };
        match n.kind() {
            "function_item" | "function_signature_item" => {
                let Some(name) = self.field_text(n, "name") else { return };
                let sig = self.signature(n);
                self.push(n, name, "function", parent, sig);
            }
            "macro_definition" => {
                if let Some(name) = self.field_text(n, "name") {
                    self.push(n, name, "macro", parent, String::new());
                }
            }
            "struct_item" => named("struct", self),
            "enum_item" => named("enum", self),
            "union_item" => named("union", self),
            "type_item" => named("type", self),
            "trait_item" => {
                let Some(name) = self.field_text(n, "name") else { return };
                self.push(n, name.clone(), "trait", parent, String::new());
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk_container(body, Some(&name), depth + 1);
                }
            }
            "impl_item" => {
                let ty = self.field_text(n, "type").unwrap_or_default();
                let ty = ty.split('<').next().unwrap_or("").trim().to_string();
                if let Some(body) = n.child_by_field_name("body") {
                    let p = (!ty.is_empty()).then_some(ty);
                    self.walk_container(body, p.as_deref(), depth + 1);
                }
            }
            "mod_item" => {
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk_container(body, None, depth + 1);
                }
            }
            _ => {}
        }
    }

    fn go(&mut self, n: Node) {
        match n.kind() {
            "function_declaration" => {
                let Some(name) = self.field_text(n, "name") else { return };
                let sig = self.signature(n);
                self.push(n, name, "function", None, sig);
            }
            "method_declaration" => {
                let Some(name) = self.field_text(n, "name") else { return };
                let recv = n.child_by_field_name("receiver").map(|r| self.receiver_type(r));
                let sig = self.signature(n);
                let recv = recv.flatten();
                self.push(n, name, "function", Some(recv.as_deref().unwrap_or("?")), sig);
            }
            "type_declaration" => {
                let mut cursor = n.walk();
                let specs: Vec<Node> = n.named_children(&mut cursor).collect();
                for spec in specs {
                    if !matches!(spec.kind(), "type_spec" | "type_alias") {
                        continue;
                    }
                    let Some(name) = self.field_text(spec, "name") else { continue };
                    let kind = match spec.child_by_field_name("type").map(|t| t.kind()) {
                        Some("struct_type") => "struct",
                        Some("interface_type") => "interface",
                        _ => "type",
                    };
                    // The comment sits above the `type` keyword, not the spec.
                    let mut sym_node = spec;
                    if n.named_child_count() == 1 {
                        sym_node = n;
                    }
                    self.push(sym_node, name, kind, None, String::new());
                }
            }
            _ => {}
        }
    }

    /// The type name in a Go method receiver, without `*` or type parameters.
    fn receiver_type(&self, recv: Node) -> Option<String> {
        let text = self.text(recv);
        let inner = text.trim().trim_start_matches('(').trim_end_matches(')');
        let ty = inner.split_whitespace().last()?;
        let ty = ty.trim_start_matches('*');
        Some(ty.split('[').next().unwrap_or(ty).to_string())
    }

    fn js(&mut self, n: Node, parent: Option<&str>, depth: usize) {
        match n.kind() {
            "export_statement" => {
                if let Some(decl) = n.child_by_field_name("declaration") {
                    self.js(decl, parent, depth);
                }
            }
            "class_declaration" | "abstract_class_declaration" | "class" => {
                let Some(name) = self.field_text(n, "name") else { return };
                self.push(n, name.clone(), "class", parent, String::new());
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk_container(body, Some(&name), depth + 1);
                }
            }
            "interface_declaration" => {
                let Some(name) = self.field_text(n, "name") else { return };
                self.push(n, name.clone(), "interface", parent, String::new());
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk_container(body, Some(&name), depth + 1);
                }
            }
            "type_alias_declaration" => {
                if let Some(name) = self.field_text(n, "name") {
                    self.push(n, name, "type", parent, String::new());
                }
            }
            "enum_declaration" => {
                if let Some(name) = self.field_text(n, "name") {
                    self.push(n, name, "enum", parent, String::new());
                }
            }
            "function_declaration" | "generator_function_declaration" | "function_signature" => {
                let Some(name) = self.field_text(n, "name") else { return };
                let sig = self.signature(n);
                self.push(n, name, "function", parent, sig);
            }
            "method_definition" | "method_signature" | "abstract_method_signature" => {
                let Some(name) = self.field_text(n, "name") else { return };
                let sig = self.signature(n);
                self.push(n, name, "method", parent, sig);
            }
            "lexical_declaration" | "variable_declaration" => {
                let mut cursor = n.walk();
                let decls: Vec<Node> = n.named_children(&mut cursor).collect();
                for d in decls {
                    if d.kind() != "variable_declarator" {
                        continue;
                    }
                    let Some(value) = d.child_by_field_name("value") else { continue };
                    if !matches!(value.kind(), "arrow_function" | "function_expression" | "function") {
                        continue;
                    }
                    let Some(id) = d.child_by_field_name("name").filter(|i| i.kind() == "identifier") else {
                        continue;
                    };
                    let name = self.text(id).to_string();
                    let mut sig = self.signature(value);
                    if sig.is_empty() {
                        // `x => x`: a single bare parameter.
                        sig = value
                            .child_by_field_name("parameter")
                            .map(|p| format!("({})", self.text(p)))
                            .unwrap_or_default();
                    }
                    // Document comments sit above the declaration statement.
                    self.push(n, name, "function", parent, sig);
                }
            }
            "internal_module" | "module" => {
                if let Some(body) = n.child_by_field_name("body") {
                    self.walk_container(body, parent, depth + 1);
                }
            }
            "expression_statement" => {
                // `namespace X {}` parses as an expression statement in TS.
                if let Some(inner) = n.named_child(0)
                    && inner.kind() == "internal_module"
                {
                    self.js(inner, parent, depth);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_symbols() {
        let src = "/// A point.\n#[derive(Debug)]\npub struct Point { x: i32 }\n\nimpl Point {\n    /// Make one.\n    pub fn new(x: i32) -> Self { Point { x } }\n}\n\nfn helper() {}\n";
        let s = parse_symbols(Lang::Rust, src).unwrap();
        let names: Vec<_> = s.iter().map(|s| (s.name.as_str(), s.sym_type, s.parent.as_deref())).collect();
        assert_eq!(
            names,
            [("Point", "class", None), ("new", "method", Some("Point")), ("helper", "function", None)]
        );
        assert_eq!(s[0].docstring, "A point.");
        assert_eq!(s[1].docstring, "Make one.");
        assert_eq!(s[1].signature, "(x: i32) -> Self");
    }
}
