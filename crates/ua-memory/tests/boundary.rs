//! The governed-registry rule, enforced: every memory operation an agent or a
//! person makes runs through `Registry::call` (profile, policy file, approval
//! gate, ledger), so the only workspace crate that may depend on `ua-memory`
//! is `ua-tools`, which registers the memory tools. An adapter (`ua-server`,
//! `ua-cli`) or any other crate that called `ua_memory` directly would bypass
//! those checks. Reach memory through the `memory_*` tools instead.

use std::process::Command;

use serde_json::Value;

#[test]
fn only_ua_tools_depends_on_ua_memory() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--manifest-path", manifest])
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr));
    let meta: Value = serde_json::from_slice(&out.stdout).expect("cargo metadata JSON");

    let packages = meta["packages"].as_array().expect("packages");
    assert!(packages.iter().any(|p| p["name"] == "ua-memory"), "ua-memory is not a workspace member");
    // Every dependency kind counts (normal, dev, build): a dev-dependency is
    // still a direct call path that skips the registry.
    let mut dependents: Vec<String> = packages
        .iter()
        .filter(|p| {
            p["dependencies"].as_array().is_some_and(|deps| deps.iter().any(|d| d["name"] == "ua-memory"))
        })
        .map(|p| p["name"].as_str().unwrap_or_default().to_string())
        .collect();
    dependents.sort();
    assert_eq!(
        dependents,
        ["ua-tools"],
        "only ua-tools may depend on ua-memory. Every memory operation must run through the governed \
         registry (Registry::call: profile, policy, approval gate, ledger); call the memory_* tools \
         instead of ua_memory (CONTRIBUTING.md, Layout)"
    );
}
