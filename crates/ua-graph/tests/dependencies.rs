//! Dependency direction and the governed-registry rule: `ua-graph` sits above
//! `ua-core` and `ua-store` and depends on no other workspace crate, so the
//! order core -> store -> organization -> families -> server/CLI stays one-way.
//! Only `ua-tools` depends on it: it registers the governed graph tools and
//! runs `ua-org::authz` checks before calling into `ua-graph`.

use std::process::Command;

use serde_json::Value;

fn metadata() -> Value {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let manifest = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml");
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--no-deps", "--manifest-path", manifest])
        .output()
        .expect("run cargo metadata");
    assert!(out.status.success(), "cargo metadata failed: {}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).expect("cargo metadata JSON")
}

#[test]
fn ua_graph_depends_only_on_core_and_store_and_only_ua_tools_depends_on_it() {
    let meta = metadata();
    let packages = meta["packages"].as_array().expect("packages");
    let members: Vec<&str> = packages.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(members.contains(&"ua-graph"), "ua-graph is not a workspace member");

    let deps_of = |name: &str| -> Vec<String> {
        let p = packages.iter().find(|p| p["name"] == name).expect("package");
        p["dependencies"]
            .as_array()
            .map(|d| d.iter().filter_map(|d| d["name"].as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };

    let mut ours: Vec<String> =
        deps_of("ua-graph").into_iter().filter(|d| members.contains(&d.as_str())).collect();
    ours.sort();
    ours.dedup();
    assert_eq!(
        ours,
        ["ua-core", "ua-store"],
        "ua-graph may depend on ua-core, ua-store and third-party crates only"
    );

    let mut dependents: Vec<&str> =
        members.iter().copied().filter(|m| deps_of(m).iter().any(|d| d == "ua-graph")).collect();
    dependents.sort();
    assert_eq!(
        dependents,
        ["ua-tools"],
        "only ua-tools may depend on ua-graph: call the graph_* tools through the registry instead"
    );
}
