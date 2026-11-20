//! The governed-registry rule, enforced: every organization operation an agent
//! or a person makes runs through `Registry::call`, so the only workspace
//! crate that may depend on `ua-org` is `ua-tools`, which registers the
//! organization tools. An adapter that called `ua_org` directly would bypass
//! those checks. Reach the registry through the `org_*` tools instead.

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
        ["ua-tools"],
        "only ua-tools may depend on ua-org. Every organization operation must run through the governed \
         registry; call the org_* tools instead of ua_org"
    );
}
