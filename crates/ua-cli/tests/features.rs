//! A `ua` built without an optional feature says so instead of failing
//! obscurely.

use std::process::Command;

/// `ua mcp` is always a subcommand. Without the mcp-server feature it
/// refuses with a message naming the feature, not clap's "unrecognized
/// subcommand".
#[cfg(not(feature = "mcp-server"))]
#[test]
fn ua_mcp_without_the_mcp_server_feature_names_it() {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_ua"))
        .arg("mcp")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", home.path())
        .env("UA_HOME", home.path())
        .env("NO_COLOR", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{stderr}");
    assert!(stderr.contains("built without the mcp-server feature"), "{stderr}");
    assert!(!stderr.contains("unrecognized subcommand"), "{stderr}");
}

/// The help lists `mcp` in every build.
#[test]
fn help_lists_the_mcp_subcommand() {
    let out = Command::new(env!("CARGO_BIN_EXE_ua")).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{help}");
    assert!(help.lines().any(|l| l.trim_start().starts_with("mcp ")), "{help}");
}

/// `ua --version` names the optional features this build has and lacks.
#[test]
fn version_lists_the_compiled_features() {
    let out = Command::new(env!("CARGO_BIN_EXE_ua")).arg("--version").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}");
    let (on, off) = text.split_once("; without: ").unwrap_or_else(|| panic!("{text}"));
    for (feature, enabled) in [
        ("code-intel", cfg!(feature = "code-intel")),
        ("readability", cfg!(feature = "readability")),
        ("mcp-gateway", cfg!(feature = "mcp-gateway")),
        ("mcp-server", cfg!(feature = "mcp-server")),
        ("embeddings", cfg!(feature = "embeddings")),
    ] {
        assert_eq!(on.contains(feature), enabled, "{feature}: {text}");
        assert_eq!(off.contains(feature), !enabled, "{feature}: {text}");
    }
}
