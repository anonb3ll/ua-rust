//! Dependency direction: `ua-ingress` sits just above `ua-core` and
//! `ua-store`. It depends on no other workspace crate, and only `ua-tools`
//! and `ua-server` depend on it, so the order core → store → organization →
//! families → server/CLI stays one-way.

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
fn ua_ingress_depends_only_on_core_and_store_and_only_families_and_server_depend_on_it() {
    let meta = metadata();
    let packages = meta["packages"].as_array().expect("packages");
    let members: Vec<&str> = packages.iter().filter_map(|p| p["name"].as_str()).collect();
    assert!(members.contains(&"ua-ingress"), "ua-ingress is not a workspace member");
    let deps_of = |name: &str| -> Vec<String> {
        let p = packages.iter().find(|p| p["name"] == name).expect("package");
        p["dependencies"]
            .as_array()
            .map(|d| d.iter().filter_map(|d| d["name"].as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };

    let mut ours: Vec<String> =
        deps_of("ua-ingress").into_iter().filter(|d| members.contains(&d.as_str())).collect();
    ours.sort();
    ours.dedup();
    assert_eq!(
        ours,
        ["ua-core", "ua-store"],
        "ua-ingress may depend on ua-core, ua-store and third-party crates only"
    );

    let mut dependents: Vec<&str> =
        members.iter().copied().filter(|m| deps_of(m).iter().any(|d| d == "ua-ingress")).collect();
    dependents.sort();
    for d in &dependents {
        assert!(
            ["ua-server", "ua-tools"].contains(d),
            "{d} depends on ua-ingress; only ua-tools and ua-server may (docs/ingress.md)"
        );
    }
}
