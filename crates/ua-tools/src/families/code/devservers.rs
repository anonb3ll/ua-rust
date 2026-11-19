//! `detect_dev_servers`: a read-only scan for launchable development servers.
//!
//! Looks only at the given directory's own manifests: `package.json`,
//! `pyproject.toml`, `Cargo.toml`, docker-compose files and `Procfile`. It
//! starts nothing and writes nothing.

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::{guard_secret_filename, resolve_for_read};
use ua_core::{UaError, UaResult};

use crate::families::workspace::{Sandbox, sandbox};
use crate::registry::{Registry, ToolCtx, blocking, tool};

const MANIFEST_MAX_BYTES: u64 = 200_000;
const NODE_DEV_SCRIPT_NAMES: &[&str] = &["dev", "start", "serve", "develop"];
const NODE_DEV_SCRIPT_TOKENS: &[&str] = &["dev", "serve", "watch"];
const NODE_LOCKFILES: &[(&str, &str)] =
    &[("yarn.lock", "yarn"), ("pnpm-lock.yaml", "pnpm"), ("bun.lockb", "bun"), ("package-lock.json", "npm")];
const COMPOSE_NAMES: &[&str] = &["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"];
/// Crates whose presence marks a Rust binary as a server.
const RUST_SERVER_CRATES: &[&str] =
    &["axum", "actix-web", "rocket", "warp", "hyper", "poem", "tide", "salvo", "tower-http", "rmcp"];

static PORT_FLAG: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?:--port|-p)[\s=](\d{2,5})\b").ok());
static PORT_ENV: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(r"\bPORT\s*=\s*(\d{2,5})\b").ok());
static PORT_GETENV: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"getenv\(\s*["']\w*PORT\w*["']\s*,\s*["']?(\d{2,5})"#).ok());
static SERVER_CALL: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"(?:uvicorn\.run\(|app\.run\(|mcp\.run\(|\.listen\(|HTTPServer\(|\bserve_forever\b|\brunserver\b)",
    )
    .ok()
});
/// A literal socket address such as "127.0.0.1:3000" or "0.0.0.0:8080".
static RUST_BIND: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#""(?:[\w.\-]+|\[[0-9a-fA-F:]+\]):(\d{2,5})""#).ok());

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DetectArgs {
    /// Project directory: relative to the workspace root, or absolute inside a read root (default ".").
    #[serde(default = "dot")]
    pub path: String,
}

fn dot() -> String {
    ".".into()
}

fn read_text(p: &Path) -> Option<String> {
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > MANIFEST_MAX_BYTES || guard_secret_filename(p).is_err() {
        return None;
    }
    std::fs::read(p).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn port_in(re: &Option<Regex>, text: &str) -> Option<u16> {
    re.as_ref()?.captures(text).and_then(|c| c.get(1)).and_then(|m| m.as_str().parse().ok())
}

fn config(
    name: String,
    exe: &str,
    args: Vec<String>,
    port: Option<u16>,
    source: &str,
    note: Option<&str>,
) -> Value {
    json!({
        "name": name,
        "runtimeExecutable": exe,
        "runtimeArgs": args,
        "port": port,
        "source": source,
        "note": if port.is_some() { Value::Null } else { json!(note) },
    })
}

fn detect_node(root: &Path, out: &mut Vec<Value>, warnings: &mut Vec<String>) {
    let Some(text) = read_text(&root.join("package.json")) else { return };
    let pkg: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            warnings.push("package.json is not valid JSON; skipped".into());
            return;
        }
    };
    let manager =
        NODE_LOCKFILES.iter().find(|(f, _)| root.join(f).is_file()).map(|(_, m)| *m).unwrap_or("npm");
    let pkg_name =
        pkg.get("name").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| {
            root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
        });
    let Some(scripts) = pkg.get("scripts").and_then(Value::as_object) else { return };
    for (name, cmd) in scripts {
        let Some(cmd) = cmd.as_str() else { continue };
        if !NODE_DEV_SCRIPT_NAMES.contains(&name.as_str())
            && !NODE_DEV_SCRIPT_TOKENS.iter().any(|t| cmd.contains(t))
        {
            continue;
        }
        let port = port_in(&PORT_FLAG, cmd).or_else(|| port_in(&PORT_ENV, cmd));
        let mut args: Vec<String> = if manager == "yarn" { vec![] } else { vec!["run".into()] };
        args.push(name.clone());
        out.push(config(
            format!("{pkg_name} ({name})"),
            manager,
            args,
            port,
            "package.json",
            Some("no explicit port in the script; check the framework's default"),
        ));
    }
}

/// `pkg.module:function` → the module file under a src/ layout or the root.
fn entry_module(root: &Path, target: &str) -> Option<std::path::PathBuf> {
    let module = target.split(':').next()?.trim();
    if module.is_empty() || module.contains("..") || module.contains('/') {
        return None;
    }
    let rel: std::path::PathBuf = module.split('.').collect();
    for base in [root.join("src"), root.to_path_buf()] {
        let file = base.join(&rel).with_extension("py");
        if file.is_file() {
            return Some(file);
        }
        let init = base.join(&rel).join("__init__.py");
        if init.is_file() {
            return Some(init);
        }
    }
    None
}

fn detect_python(root: &Path, out: &mut Vec<Value>, warnings: &mut Vec<String>) {
    let Some(text) = read_text(&root.join("pyproject.toml")) else { return };
    let doc: toml::Value = match text.parse() {
        Ok(v) => v,
        Err(_) => {
            warnings.push("pyproject.toml failed to parse; skipped".into());
            return;
        }
    };
    let Some(scripts) = doc.get("project").and_then(|p| p.get("scripts")).and_then(|s| s.as_table()) else {
        return;
    };
    for (name, target) in scripts {
        let Some(target) = target.as_str() else { continue };
        let Some(file) = entry_module(root, target) else { continue };
        let Some(src) = read_text(&file) else { continue };
        if !SERVER_CALL.as_ref().is_some_and(|r| r.is_match(&src)) {
            continue; // a CLI, not a server
        }
        let port = port_in(&PORT_GETENV, &src).or_else(|| port_in(&PORT_ENV, &src));
        let source = file.strip_prefix(root).unwrap_or(&file).to_string_lossy().into_owned();
        out.push(config(
            name.clone(),
            "uv",
            vec!["run".into(), name.clone()],
            port,
            &source,
            Some("server entry point found but no default port in source; set env vars or pass args"),
        ));
    }
}

fn detect_rust(root: &Path, out: &mut Vec<Value>, warnings: &mut Vec<String>) {
    let Some(text) = read_text(&root.join("Cargo.toml")) else { return };
    let doc: toml::Value = match text.parse() {
        Ok(v) => v,
        Err(_) => {
            warnings.push("Cargo.toml failed to parse; skipped".into());
            return;
        }
    };
    let Some(package) = doc.get("package") else { return }; // a virtual workspace manifest
    let deps = doc.get("dependencies").and_then(|d| d.as_table());
    let server_dep = deps.is_some_and(|d| RUST_SERVER_CRATES.iter().any(|c| d.contains_key(*c)));
    if !server_dep {
        return;
    }
    let pkg_name = package.get("name").and_then(|n| n.as_str()).unwrap_or("app").to_string();
    let mut bins: Vec<(String, std::path::PathBuf)> = doc
        .get("bin")
        .and_then(|b| b.as_array())
        .map(|bins| {
            bins.iter()
                .filter_map(|b| {
                    let name = b.get("name")?.as_str()?.to_string();
                    let path = b
                        .get("path")
                        .and_then(|p| p.as_str())
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| Path::new("src/bin").join(format!("{name}.rs")));
                    Some((name, path))
                })
                .collect()
        })
        .unwrap_or_default();
    if bins.is_empty() && root.join("src/main.rs").is_file() {
        bins.push((pkg_name.clone(), "src/main.rs".into()));
    }
    let single = bins.len() == 1;
    for (name, path) in bins {
        if path.is_absolute() || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            continue;
        }
        let src = read_text(&root.join(&path)).unwrap_or_default();
        let port = port_in(&RUST_BIND, &src).or_else(|| port_in(&PORT_ENV, &src));
        let mut args = vec!["run".to_string()];
        if !single {
            args.extend(["--bin".to_string(), name.clone()]);
        }
        out.push(config(
            name,
            "cargo",
            args,
            port,
            &path.to_string_lossy(),
            Some("server crate found but no literal listen address in the binary's main file"),
        ));
    }
}

fn compose_port(v: &Value) -> Option<u16> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        Value::String(s) => {
            // "8080:80", "127.0.0.1:8080:80", "8080:80/tcp"
            let parts: Vec<&str> = s.split('/').next().unwrap_or("").split(':').collect();
            let host = match parts.len() {
                2 => parts[0],
                3 => parts[1],
                _ => return None,
            };
            host.split('-').next().and_then(|p| p.parse().ok())
        }
        Value::Object(m) => m.get("published").and_then(|p| match p {
            Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }),
        _ => None,
    }
}

fn detect_compose(root: &Path, out: &mut Vec<Value>, warnings: &mut Vec<String>) {
    let Some(name) = COMPOSE_NAMES.iter().find(|n| root.join(n).is_file()) else { return };
    let Some(text) = read_text(&root.join(name)) else { return };
    let doc: Value = match serde_saphyr::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            warnings.push(format!("{name} failed to parse as YAML; skipped"));
            return;
        }
    };
    let Some(services) = doc.get("services").and_then(Value::as_object) else { return };
    for (svc, def) in services {
        if !def.is_object() {
            continue;
        }
        let port = def.get("ports").and_then(Value::as_array).and_then(|ps| ps.iter().find_map(compose_port));
        out.push(config(
            svc.clone(),
            "docker",
            vec!["compose".into(), "up".into(), svc.clone()],
            port,
            name,
            Some("no host port published for this service"),
        ));
    }
}

fn detect_procfile(root: &Path, out: &mut Vec<Value>) {
    let Some(text) = read_text(&root.join("Procfile")) else { return };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, cmd)) = line.split_once(':') else { continue };
        let mut parts = cmd.split_whitespace().map(str::to_string);
        let Some(exe) = parts.next() else { continue };
        let mut c = config(
            name.trim().to_string(),
            &exe,
            parts.collect(),
            None,
            "Procfile",
            Some(
                "Procfile processes typically read $PORT at runtime; set it explicitly if starting standalone",
            ),
        );
        c["runtimeExecutable"] = json!(exe);
        out.push(c);
    }
}

/// Ports in TCP LISTEN state, from /proc (Linux only; empty elsewhere).
fn listening_ports() -> HashSet<u16> {
    let mut ports = HashSet::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(f) else { continue };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[3] != "0A" {
                continue;
            }
            if let Some(hex) = fields[1].rsplit(':').next()
                && let Ok(p) = u16::from_str_radix(hex, 16)
            {
                ports.insert(p);
            }
        }
    }
    ports
}

/// Scan `root` (an existing directory). Exposed for tests.
pub fn scan_dir(root: &Path) -> (Vec<Value>, Vec<String>) {
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    detect_node(root, &mut out, &mut warnings);
    detect_python(root, &mut out, &mut warnings);
    detect_rust(root, &mut out, &mut warnings);
    detect_compose(root, &mut out, &mut warnings);
    detect_procfile(root, &mut out);
    (out, warnings)
}

fn detect(sb: &Sandbox, path: &str) -> UaResult<Value> {
    let root = resolve_for_read(path, &sb.root, &sb.read_roots)?;
    if !root.is_dir() {
        return Err(UaError::invalid(format!("path {path:?} is not a directory")));
    }
    let (mut configs, warnings) = scan_dir(&root);
    let listening = listening_ports();
    for c in &mut configs {
        let conflict = c["port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| listening.contains(p))
            .map(|p| format!("port {p} is already listening on this machine"));
        c["conflict"] = json!(conflict);
    }
    Ok(json!({ "root": root.to_string_lossy(), "configurations": configs, "warnings": warnings }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "detect_dev_servers",
            "Read-only scan of one project directory's package.json, pyproject.toml, Cargo.toml, \
             docker-compose and Procfile for launchable dev servers; proposes .claude/launch.json \
             entries. Ports are set only from explicit evidence; a port already listening here is \
             flagged in conflict (Linux only). Returns {root, configurations: [{name, \
             runtimeExecutable, runtimeArgs, port, source, note, conflict}], warnings}.",
            |ctx: ToolCtx, a: DetectArgs| async move {
                let sb = sandbox(&ctx)?;
                blocking(move || detect(&sb, &a.path)).await
            },
        )
        .family("code")
        .read_only(),
    );
}
