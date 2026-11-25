//! The governed-registry rule, enforced: every organization operation an agent
//! or a person makes runs through `Registry::call`, so the only workspace
//! crate that may depend on `ua-org`'s registry is `ua-tools`, which registers
//! the organization tools. An adapter that called `ua_org` directly would
//! bypass those checks. Reach the registry through the `org_*` tools instead.
//!
//! `ua-memory` is the one other dependent, and only for `ua_org::authz` (the
//! authority check on a note write). The test allows that crate by name and
//! then asserts every `ua_org::` path in its source is `ua_org::authz`, so a
//! registry call from memory fails here rather than slipping through as a
//! dependency that looks like the authz one.

use std::process::Command;

use serde_json::Value;

#[test]
fn only_ua_tools_depends_on_ua_org() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--manifest-path", manifest])
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr));
    let meta: Value = serde_json::from_slice(&out.stdout).expect("cargo metadata JSON");

    let packages = meta["packages"].as_array().expect("packages");
    assert!(packages.iter().any(|p| p["name"] == "ua-org"), "ua-org is not a workspace member");
    let mut dependents: Vec<String> = packages
        .iter()
        .filter(|p| {
            p["dependencies"].as_array().is_some_and(|deps| deps.iter().any(|d| d["name"] == "ua-org"))
        })
        .map(|p| p["name"].as_str().unwrap_or_default().to_string())
        .collect();
    dependents.sort();
    assert_eq!(
        dependents,
        ["ua-memory", "ua-tools"],
        "only ua-tools may depend on ua-org's registry, and ua-memory only for ua_org::authz. Every \
         organization operation must run through the governed registry; call the org_* tools instead of ua_org"
    );

    // ua-memory is allowed the dependency for authz only. Every `ua_org::` path
    // in its source must be `ua_org::authz`; a registry call would fail here.
    let memory_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ua-memory/src");
    let mut offenders: Vec<String> = Vec::new();
    for entry in walk(&memory_src) {
        let text = std::fs::read_to_string(&entry).expect("read ua-memory source");
        for (n, line) in text.lines().enumerate() {
            let mut rest = line;
            while let Some(i) = rest.find("ua_org::") {
                let tail = &rest[i + "ua_org::".len()..];
                if !tail.starts_with("authz") {
                    offenders.push(format!("{}:{}: {}", entry.display(), n + 1, line.trim()));
                }
                rest = &tail[tail.len()..];
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "ua-memory may reach ua-org only through ua_org::authz; registry calls belong in ua-tools:\n{}",
        offenders.join("\n")
    );
}

/// Every `.rs` file under `dir`, depth first.
fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}
