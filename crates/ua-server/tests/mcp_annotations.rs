//! The MCP surface claims (capability_catalog's `tool_annotations`) that
//! every tool carries readOnlyHint and destructiveHint. Hold it to that.

use ua_server::mcp::to_mcp_tool;

#[test]
fn every_builtin_tool_carries_read_only_and_destructive_hints() {
    let reg = ua_tools::builtin_registry();
    let mut n = 0;
    for def in reg.all() {
        let tool = to_mcp_tool(def);
        let ann = tool.annotations.as_ref().unwrap_or_else(|| panic!("{} has no annotations", def.name));
        assert_eq!(ann.read_only_hint, Some(def.read_only), "{}: readOnlyHint", def.name);
        assert_eq!(ann.destructive_hint, Some(def.always_gated), "{}: destructiveHint", def.name);
        assert!(!(def.read_only && def.always_gated), "{} is both read-only and destructive", def.name);
        n += 1;
    }
    assert!(n > 100, "only {n} tools registered");
}
