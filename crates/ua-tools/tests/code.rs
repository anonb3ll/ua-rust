//! Code family: symbol indexing on fixture sources, repository maps, images,
//! formatting, dev-server detection and docsets, through the registry.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const RUST_SRC: &str = r#"//! Crate docs.

/// A friendly greeter.
#[derive(Debug, Clone)]
pub struct Greeter {
    name: String,
}

/// Ways to say hello.
pub enum Mood { Happy, Grumpy }

pub trait Speak {
    /// Say something.
    fn speak(&self) -> String;
}

impl Greeter {
    /// Build a greeter.
    pub fn new(name: &str) -> Self {
        Greeter { name: name.to_string() }
    }

    pub fn greet(&self, other: &str) -> String {
        format!("hello {other}")
    }
}

/// Top-level helper that returns a Greeter.
pub fn make_greeter() -> Greeter {
    fn inner_not_indexed() {}
    Greeter::new("x")
}

mod nested {
    pub fn deep_function() {}
}
"#;

const PY_SRC: &str = r#""""Module docstring."""
import functools


class Inventory:
    """Track items in stock.

    More detail here.
    """

    def __init__(self, items, *, strict=False):
        self.items = items

    @functools.cache
    def count(self, name: str) -> int:
        """Count one item."""
        return 0


def load_inventory(path, **kwargs):
    '''Load from disk.'''
    def nested():
        pass
    return Inventory([])
"#;

const TS_SRC: &str = r#"/** Shapes we can draw. */
export interface Shape {
  area(): number;
}

export type Point = { x: number; y: number };

/** A circle. */
export class Circle implements Shape {
  constructor(private r: number) {}
  /** Area of the circle. */
  area(): number {
    return Math.PI * this.r * this.r;
  }
}

export function makeCircle(r: number): Circle {
  return new Circle(r);
}

export const double = (n: number): number => n * 2;

enum Color { Red, Green }
"#;

const JS_SRC: &str = r#"// helpers
function plain(a, b) { return a + b; }

const arrow = (x) => x + 1;

class Widget {
  render() { return "<div/>"; }
}

module.exports = { plain, arrow, Widget };
"#;

const GO_SRC: &str = r#"package main

// Server holds state.
type Server struct {
	port int
}

// Handler serves requests.
type Handler interface {
	Serve() error
}

// Start runs the server.
func (s *Server) Start(addr string) error {
	return nil
}

// main is the entry point.
func main() {
}
"#;

const PNG_3X5: &[u8] = &[
    0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n', 0, 0, 0, 13, b'I', b'H', b'D', b'R', 0, 0, 0, 3, 0, 0, 0, 5,
    8, 6, 0, 0, 0,
];

struct Env {
    _home: tempfile::TempDir,
    _ws: tempfile::TempDir,
    _docs: tempfile::TempDir,
    ws: PathBuf,
    docs: PathBuf,
    hub: Hub,
    reg: Registry,
}

fn write(root: &Path, rel: &str, content: impl AsRef<[u8]>) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn setup_with(tweak: impl FnOnce(&mut Config, &Path)) -> Env {
    let home = tempfile::tempdir().unwrap();
    let ws_dir = tempfile::tempdir().unwrap();
    let docs_dir = tempfile::tempdir().unwrap();
    let ws = ws_dir.path().canonicalize().unwrap();
    let docs = docs_dir.path().canonicalize().unwrap();
    write(&ws, "src/lib.rs", RUST_SRC);
    write(&ws, "app/inventory.py", PY_SRC);
    write(&ws, "web/shapes.ts", TS_SRC);
    write(&ws, "web/widget.js", JS_SRC);
    write(&ws, "cmd/main.go", GO_SRC);
    write(&ws, "node_modules/dep/index.js", "function vendored() {}");
    write(&ws, "target/debug/build.rs", "fn generated() {}");
    write(&ws, "README.md", "# readme");
    let mut cfg = Config::for_home(home.path());
    cfg.workspace = Some(ws.clone());
    cfg.human_identities = vec!["operator".into()];
    tweak(&mut cfg, &docs);
    let hub = Hub::in_memory(cfg).unwrap();
    Env { _home: home, _ws: ws_dir, _docs: docs_dir, ws, docs, hub, reg: builtin_registry() }
}

fn setup() -> Env {
    setup_with(|_, _| {})
}

fn agent(label: &str, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind: ActorKind::Agent,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

impl Env {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, &agent("builder-1", Profile::Developer), tool, args).await
    }

    async fn ok(&self, tool: &str, args: Value) -> Value {
        self.call(tool, args.clone()).await.unwrap_or_else(|e| panic!("{tool} {args}: {e}"))
    }

    async fn symbols(&self, file: &str) -> Vec<Value> {
        self.ok("fs_list_symbols", json!({ "file_path": file })).await["symbols"].as_array().unwrap().clone()
    }
}

fn find<'a>(syms: &'a [Value], name: &str) -> &'a Value {
    syms.iter().find(|s| s["name"] == name).unwrap_or_else(|| panic!("no symbol {name} in {syms:?}"))
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::Denied { reason_code, .. } => reason_code.clone(),
        other => other.code().to_string(),
    }
}

#[tokio::test]
async fn indexes_fixture_sources() {
    let env = setup();
    let out = env.ok("fs_index_symbols", json!({})).await;
    assert_eq!(out["files_indexed"], 5, "{out}");
    assert_eq!(out["degraded"], false);
    for lang in ["rust", "python", "typescript", "javascript", "go"] {
        assert_eq!(out["languages"][lang], 1, "{lang}: {out}");
    }
    let total = out["symbols_indexed"].as_u64().unwrap();
    let parts = ["classes", "functions", "methods"].iter().map(|k| out[k].as_u64().unwrap()).sum::<u64>();
    assert_eq!(total, parts);

    // Rust: structs, enums, traits, impl methods with their parent, doc comments past attributes.
    let rs = env.symbols("src/lib.rs").await;
    let greeter = find(&rs, "Greeter");
    assert_eq!(greeter["type"], "class");
    assert_eq!(greeter["kind"], "struct");
    assert_eq!(greeter["docstring"], "A friendly greeter.");
    assert_eq!(greeter["line_no"], 5);
    assert_eq!(find(&rs, "Mood")["kind"], "enum");
    assert_eq!(find(&rs, "Speak")["kind"], "trait");
    let speak = find(&rs, "speak");
    assert_eq!((speak["type"].as_str(), speak["parent"].as_str()), (Some("method"), Some("Speak")));
    let new = find(&rs, "new");
    assert_eq!(new["parent"], "Greeter");
    assert_eq!(new["signature"], "(name: &str) -> Self");
    assert_eq!(new["docstring"], "Build a greeter.");
    assert_eq!(find(&rs, "make_greeter")["type"], "function");
    assert_eq!(find(&rs, "deep_function")["type"], "function");
    assert!(rs.iter().all(|s| s["name"] != "inner_not_indexed"), "function bodies are not indexed");

    // Python: class docstring first line, decorated methods, nested defs skipped.
    let py = env.symbols("app/inventory.py").await;
    let inv = find(&py, "Inventory");
    assert_eq!(inv["docstring"], "Track items in stock.");
    let count = find(&py, "count");
    assert_eq!((count["type"].as_str(), count["parent"].as_str()), (Some("method"), Some("Inventory")));
    assert_eq!(count["docstring"], "Count one item.");
    assert_eq!(count["signature"], "(self, name: str) -> int");
    assert_eq!(find(&py, "load_inventory")["docstring"], "Load from disk.");
    assert!(py.iter().all(|s| s["name"] != "nested"));

    // TypeScript: interfaces, aliases, classes, exported functions, arrow functions, enums.
    let ts = env.symbols("web/shapes.ts").await;
    assert_eq!(find(&ts, "Shape")["kind"], "interface");
    assert_eq!(find(&ts, "Shape")["docstring"], "Shapes we can draw.");
    assert_eq!(find(&ts, "Point")["kind"], "type");
    assert_eq!(find(&ts, "Circle")["docstring"], "A circle.");
    let area: Vec<&Value> = ts.iter().filter(|s| s["name"] == "area").collect();
    assert!(area.iter().any(|s| s["parent"] == "Circle" && s["docstring"] == "Area of the circle."));
    assert_eq!(find(&ts, "makeCircle")["signature"], "(r: number): Circle");
    assert_eq!(find(&ts, "double")["type"], "function");
    assert_eq!(find(&ts, "Color")["kind"], "enum");

    let js = env.symbols("web/widget.js").await;
    assert_eq!(find(&js, "plain")["signature"], "(a, b)");
    assert_eq!(find(&js, "arrow")["type"], "function");
    assert_eq!(find(&js, "render")["parent"], "Widget");

    // Go: struct and interface types, receiver methods.
    let go = env.symbols("cmd/main.go").await;
    assert_eq!(find(&go, "Server")["kind"], "struct");
    assert_eq!(find(&go, "Server")["docstring"], "Server holds state.");
    assert_eq!(find(&go, "Handler")["kind"], "interface");
    let start = find(&go, "Start");
    assert_eq!((start["type"].as_str(), start["parent"].as_str()), (Some("method"), Some("Server")));
    assert_eq!(start["signature"], "(addr string) error");
    assert_eq!(find(&go, "main")["docstring"], "main is the entry point.");

    // Dependency and build trees were skipped.
    let vendored = env.ok("fs_search_symbols", json!({ "query": "vendored" })).await;
    assert_eq!(vendored["results"].as_array().unwrap().len(), 0);
    let generated = env.ok("fs_search_symbols", json!({ "query": "generated" })).await;
    assert_eq!(generated["results"].as_array().unwrap().len(), 0);

    // The index build is on the ledger.
    let human = Caller { kind: ActorKind::Human, ..agent("operator", Profile::Operator) };
    let events = env
        .reg
        .call(&env.hub, &human, "event_log_query", json!({ "channels": ["agent.code.indexed"] }))
        .await
        .unwrap();
    assert_eq!(events["count"], 1);
    assert_eq!(events["events"][0]["payload"]["files_indexed"], 5);
}

#[tokio::test]
async fn search_list_and_reindex() {
    let env = setup();
    env.ok("fs_index_symbols", json!({ "path": "." })).await;

    let res = env.ok("fs_search_symbols", json!({ "query": "greet" })).await;
    let names: Vec<&str> = res["results"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names[0], "greet", "exact match first: {names:?}");
    assert!(names.contains(&"Greeter") && names.contains(&"make_greeter"));
    assert_eq!(res["results"][0]["file_path"], "src/lib.rs");
    assert!(res.get("note").is_none());

    let sem = env.ok("fs_search_symbols", json!({ "query": "Circle", "semantic": true })).await;
    assert_eq!(sem["semantic"], false);
    assert!(sem["note"].as_str().unwrap().contains("lexical"));
    assert_eq!(sem["results"][0]["name"], "Circle");

    // LIKE wildcards in the query are literal.
    let none = env.ok("fs_search_symbols", json!({ "query": "%" })).await;
    assert_eq!(none["results"].as_array().unwrap().len(), 0);

    // An unindexed file is parsed on the fly.
    write(&env.ws, "extra/late.py", "def arrived_late():\n    pass\n");
    let late = env.ok("fs_list_symbols", json!({ "file_path": "extra/late.py" })).await;
    assert_eq!(late["source"], "parse");
    assert_eq!(late["symbols"][0]["name"], "arrived_late");
    let md = env.ok("fs_list_symbols", json!({ "file_path": "README.md" })).await;
    assert!(md["note"].as_str().unwrap().contains("no grammar"));

    // Re-indexing a subdirectory replaces only that subtree.
    write(&env.ws, "app/inventory.py", "def replaced():\n    pass\n");
    let sub = env.ok("fs_index_symbols", json!({ "path": "app" })).await;
    assert_eq!(sub["files_indexed"], 1);
    assert_eq!(sub["path"], "app");
    let py = env.symbols("app/inventory.py").await;
    assert_eq!(py.len(), 1);
    assert_eq!(py[0]["name"], "replaced");
    assert!(!env.symbols("src/lib.rs").await.is_empty(), "other files keep their symbols");

    // Paths stay inside the workspace.
    let err = env.call("fs_index_symbols", json!({ "path": "../" })).await.unwrap_err();
    assert_eq!(reason(&err), "outside_sandbox");
    let err = env.call("fs_list_symbols", json!({ "file_path": "node_modules/dep/index.js" })).await.unwrap_err();
    assert_eq!(reason(&err), "dependency_dir");
    let err = env.call("fs_index_symbols", json!({ "path": "nope" })).await.unwrap_err();
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn repo_map_ranks_and_budgets() {
    let env = setup();
    // No index yet: the map builds one.
    let map = env.ok("fs_repo_map", json!({})).await;
    let text = map["repo_map"].as_str().unwrap();
    assert!(text.starts_with("# Codebase Map: ."), "{text}");
    for f in ["src/lib.rs", "app/inventory.py", "web/shapes.ts", "cmd/main.go"] {
        assert!(text.contains(&format!("## `{f}`")), "{f} missing:\n{text}");
    }
    assert!(text.contains("`struct Greeter`"), "{text}");
    assert!(text.contains("`fn new(name: &str) -> Self`"), "{text}");
    assert!(text.contains("`def load_inventory(path, **kwargs)`"), "{text}");
    assert!(text.contains("`func Server.Start(addr string) error`") || text.contains("`func Start(addr string) error`"), "{text}");

    let sub = env.ok("fs_repo_map", json!({ "path": "web" })).await;
    let sub_text = sub["repo_map"].as_str().unwrap();
    assert!(sub_text.contains("web/shapes.ts") && !sub_text.contains("src/lib.rs"), "{sub_text}");

    let small = env.ok("fs_repo_map", json!({ "token_budget": 40 })).await;
    let small_text = small["repo_map"].as_str().unwrap();
    assert!(small_text.contains("[truncated to fit token budget]"), "{small_text}");
    assert!(small_text.len() < text.len());

    let empty = env.ok("fs_repo_map", json!({ "path": "README.md" })).await;
    assert!(empty["repo_map"].as_str().unwrap().contains("No indexed symbols"));
}

#[tokio::test]
async fn reads_images() {
    let env = setup();
    write(&env.ws, "img/dot.png", PNG_3X5);
    let img = env.ok("read_image", json!({ "path": "img/dot.png" })).await;
    assert_eq!(img["mime"], "image/png");
    assert_eq!((img["width"].as_u64(), img["height"].as_u64()), (Some(3), Some(5)));
    assert_eq!(img["bytes"], PNG_3X5.len());
    assert_eq!(img["description"], format!("PNG image, 3x5, {} B", PNG_3X5.len()));

    let err = env.call("read_image", json!({ "path": "README.md" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    let err = env.call("read_image", json!({ "path": "/etc/hostname" })).await.unwrap_err();
    assert_eq!(reason(&err), "outside_sandbox");
    let err = env.call("read_image", json!({ "path": "img/none.png" })).await.unwrap_err();
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn renders_formats() {
    let env = setup();
    let t = env
        .ok("format_render", json!({ "kind": "table", "payload": { "columns": ["id", "name"], "rows": [[1, "a|b"], [22]] } }))
        .await;
    assert_eq!(t["markdown"], "| id | name |\n| --- | --- |\n| 1 | a\\|b |\n| 22 |  |");
    assert_eq!(t["text"], "id  name\n--  ----\n1   a|b\n22");

    let s = env.ok("format_render", json!({ "kind": "section", "payload": { "summary": "Logs", "body": "x" } })).await;
    assert_eq!(s["markdown"], "<details>\n<summary>Logs</summary>\n\nx\n</details>");
    assert_eq!(s["text"], "Logs\n----\nx");

    let c = env.ok("format_render", json!({ "kind": "code", "payload": { "content": "print(1)", "filename": "a.py" } })).await;
    assert_eq!(c["markdown"], "`a.py`\n```python\nprint(1)\n```");
    assert_eq!(c["text"], "a.py:\nprint(1)");

    let ch = env.ok("format_render", json!({ "kind": "chips", "payload": { "mapping": { "ci": "green", "n": 3 } } })).await;
    assert_eq!(ch["markdown"], "`ci: green` `n: 3`");
    assert_eq!(ch["text"], "ci=green · n=3");

    let err = env.call("format_render", json!({ "kind": "section", "payload": {} })).await.unwrap_err();
    assert!(err.to_string().contains("summary"));
    let err = env.call("format_render", json!({ "kind": "graph", "payload": {} })).await.unwrap_err();
    assert!(err.to_string().contains("table|section|code|chips"));
}

#[tokio::test]
async fn detects_dev_servers() {
    let env = setup();
    let p = env.ws.join("proj");
    write(&p, "package.json", r#"{"name": "site", "scripts": {"dev": "vite --port 5173", "build": "vite build", "lint": "eslint ."}}"#);
    write(&p, "pnpm-lock.yaml", "");
    write(
        &p,
        "pyproject.toml",
        "[project]\nname = \"svc\"\n[project.scripts]\nsvc-server = \"svc.server:main\"\nsvc-cli = \"svc.cli:main\"\n",
    );
    write(&p, "src/svc/server.py", "import os, uvicorn\nport = int(os.getenv('SVC_PORT', '8765'))\nuvicorn.run(app)\n");
    write(&p, "src/svc/cli.py", "def main():\n    print('hi')\n");
    write(&p, "Cargo.toml", "[package]\nname = \"api\"\n\n[dependencies]\naxum = \"0.8\"\n");
    write(&p, "src/main.rs", "async fn main() { let l = bind(\"0.0.0.0:8080\").await; }\n");
    write(&p, "docker-compose.yml", "services:\n  db:\n    image: postgres\n    ports:\n      - \"5433:5432\"\n  worker:\n    image: busybox\n");
    write(&p, "Procfile", "web: gunicorn app:app\n# comment\nworker: python worker.py\n");

    let out = env.ok("detect_dev_servers", json!({ "path": "proj" })).await;
    let cfgs = out["configurations"].as_array().unwrap();
    let by_name = |n: &str| cfgs.iter().find(|c| c["name"] == n).unwrap_or_else(|| panic!("{n} missing: {out}"));

    let dev = by_name("site (dev)");
    assert_eq!(dev["runtimeExecutable"], "pnpm");
    assert_eq!(dev["runtimeArgs"], json!(["run", "dev"]));
    assert_eq!(dev["port"], 5173);
    assert!(cfgs.iter().all(|c| c["name"] != "site (lint)" && c["name"] != "site (build)"));

    let py = by_name("svc-server");
    assert_eq!(py["runtimeExecutable"], "uv");
    assert_eq!(py["port"], 8765);
    assert!(cfgs.iter().all(|c| c["name"] != "svc-cli"), "CLI entry points are not servers");

    let rs = by_name("api");
    assert_eq!(rs["runtimeExecutable"], "cargo");
    assert_eq!(rs["runtimeArgs"], json!(["run"]));
    assert_eq!(rs["port"], 8080);

    assert_eq!(by_name("db")["port"], 5433);
    assert_eq!(by_name("worker")["port"], Value::Null);
    assert!(by_name("worker")["note"].is_string());
    assert_eq!(by_name("web")["runtimeExecutable"], "gunicorn");
    assert_eq!(by_name("web")["source"], "Procfile");
    assert!(cfgs.iter().all(|c| c.get("conflict").is_some()));
    assert!(out["warnings"].as_array().unwrap().is_empty(), "{out}");

    write(&p, "package.json", "{ not json");
    let out = env.ok("detect_dev_servers", json!({ "path": "proj" })).await;
    assert!(out["warnings"][0].as_str().unwrap().contains("package.json"));

    let err = env.call("detect_dev_servers", json!({ "path": "../" })).await.unwrap_err();
    assert_eq!(reason(&err), "outside_sandbox");
    let err = env.call("detect_dev_servers", json!({ "path": "README.md" })).await.unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

fn make_docset(dir: &Path) {
    let ds = dir.join("Rusty.docset");
    write(
        &ds,
        "Contents/Info.plist",
        "<plist><dict><key>CFBundleIdentifier</key><string>rusty</string>\
         <key>CFBundleName</key><string>Rusty Docs</string>\
         <key>DocSetPlatformFamily</key><string>rust</string></dict></plist>",
    );
    write(
        &ds,
        "Contents/Resources/Documents/std/vec.html",
        "<html><body><h1>Vec</h1><p>A contiguous growable array type, written as Vec&lt;T&gt;.</p></body></html>",
    );
    let db = rusqlite::Connection::open(ds.join("Contents/Resources/docSet.dsidx")).unwrap();
    db.execute_batch(
        "CREATE TABLE searchIndex(id INTEGER PRIMARY KEY, name TEXT, type TEXT, path TEXT);
         INSERT INTO searchIndex(name, type, path) VALUES
           ('Vec', 'Struct', 'std/vec.html#main'),
           ('VecDeque', 'Struct', 'std/vecdeque.html'),
           ('into_vec', 'Method', 'std/slice.html'),
           ('HashMap', 'Struct', 'std/hashmap.html');",
    )
    .unwrap();
}

#[tokio::test]
async fn dash_needs_configuration() {
    let env = setup();
    for (tool, args) in [
        ("dash_list", json!({})),
        ("dash_search", json!({ "query": "Vec" })),
        ("dash_view", json!({ "docset_id": "rusty", "path": "x.html" })),
    ] {
        let err = env.call(tool, args).await.unwrap_err();
        assert_eq!(reason(&err), "not_configured", "{tool}");
    }
}

#[tokio::test]
async fn dash_searches_and_views_docsets() {
    let env = setup_with(|cfg, docs| {
        make_docset(docs);
        cfg.dash_docsets = vec![docs.to_path_buf()];
    });
    let list = env.ok("dash_list", json!({})).await;
    assert_eq!(list["docsets"][0]["id"], "rusty");
    assert_eq!(list["docsets"][0]["name"], "Rusty Docs");
    assert_eq!(list["docsets"][0]["platform"], "rust");

    let res = env.ok("dash_search", json!({ "query": "vec" })).await;
    let names: Vec<&str> = res["results"].as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Vec", "VecDeque", "into_vec"]);
    let err = env.call("dash_search", json!({ "query": "vec", "docset": "python" })).await.unwrap_err();
    assert_eq!(err.code(), "not_found");

    let page = env.ok("dash_view", json!({ "docset_id": "Rusty Docs", "path": "std/vec.html#main" })).await;
    assert!(page["content"].as_str().unwrap().contains("contiguous growable array"), "{page}");
    assert_eq!(page["truncated"], false);

    let err = env.call("dash_view", json!({ "docset_id": "rusty", "path": "../../Info.plist" })).await.unwrap_err();
    assert_eq!(reason(&err), "outside_docset");
    let err = env.call("dash_view", json!({ "docset_id": "rusty", "path": "std/none.html" })).await.unwrap_err();
    assert_eq!(err.code(), "not_found");
    assert!(env.docs.join("Rusty.docset").is_dir());
}
