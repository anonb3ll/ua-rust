"""Regenerate the harness config golden fixtures from the Python hub's renderer.

Python nodes compare each rendered harness surface by SHA-256, so the Rust
renderer must produce byte-identical output for the same bundle. This script
renders a fixed set of representative bundles with the Python hub's own
``harness_config`` module and writes one JSON file per case to
``crates/ua-tools/tests/fixtures/harness_config/``. The Rust test
``crates/ua-tools/tests/harness_config.rs`` normalizes the same raw payloads,
renders them and asserts byte equality with these files.

Regenerate (from the repository root), with the Python hub's virtualenv and
source tree:

    <python-hub>/.venv/bin/python -I scripts/harness_config_fixtures.py \
        --python-src <python-hub>/src

Every case is generic content only: no names, hosts or paths of a real
deployment.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "crates/ua-tools/tests/fixtures/harness_config"

CASES: dict[str, dict] = {
    # No rules, skills or servers: every default surface renders its
    # placeholder (the codex surface ends without a newline).
    "defaults": {"version": "1.0.0"},
    # Every default surface with its own rules, skills and OAuth servers.
    "full": {
        "version": "2024.06.01-rc.1",
        "rules": {
            "claude": "# Project rules\n\nRun the tests before you push.\n",
            "agents": "Shared agent rules without a trailing newline",
            "cursor": "cursor rules\n\n\n",
            "codex": "codex rules\nsecond line\n\n",
        },
        "skills": [
            {
                "name": "review-diff",
                "description": 'Review a diff. Use when asked to "check" a change.',
                "body": "---\nname: review-diff\n---\n\nRead the diff first.\n",
            },
            {"name": "write-tests", "description": "  Write tests first.  ", "content": "Body via content"},
            {"name": "no-body"},
        ],
        "mcp_servers": [
            {"name": "docs", "url": "https://mcp.example.com/docs", "auth": "OAuth"},
            {"name": "search", "serverUrl": "https://search.example.com/mcp", "transport": "sse"},
            {"name": "local", "server_url": "http://127.0.0.1:8765/mcp", "auth": "none", "transport": "  "},
        ],
    },
    # Fallbacks: agents takes claude's rules, codex and opencode take agents'.
    "fallbacks": {
        "version": "fallback-1",
        "rules": {"Claude ": "claude only\n", "opencode": ""},
        "skills": [{"name": "one", "description": "", "body": ""}],
    },
    "agents_fallback_to_codex": {
        "version": "v3",
        "rules": {"agents": "agents text\n", "codex": "", "claude": ""},
    },
    # Escaping: JSON with ensure_ascii, quotes and control characters, TOML
    # descriptions with quotes, non-ASCII text in every surface.
    "escaping": {
        "version": "esc_1",
        "rules": {
            "claude": "caf\u00e9 \u2014 \u65e5\u672c \U0001f680 tab\there\r\nback\\slash \"q\"\n",
            "agents": "\x00\x01\x08\x0c\x1f\x7f\u0080\u2028end",
            "opencode": "rules with \u00fc and \U0001f600",
        },
        "skills": [
            {
                "name": "quote-skill",
                "description": 'He said "hi" and \\"escaped\\" \u00e9',
                "body": "line1\nline2\t\"q\" \\ \u00e9 \U0001f680\x7f\n",
            }
        ],
        "mcp_servers": [
            {"name": "z-last", "url": "https://z.example.com/mcp"},
            {"name": "a-first", "url": "https://a.example.com/mcp?x=\"1\"", "auth": "oauth2"},
        ],
    },
    # Declared surfaces: custom paths and kinds, a rules-kind surface named
    # for a harness, a generic JSON surface, duplicate server names.
    "custom_surfaces": {
        "version": "custom.2",
        "rules": {"notes": "custom notes\n", "zed": "zed rules", "agents": "agents\n"},
        "skills": [{"name": "s1", "description": "first", "body": "b1"}],
        "mcp_servers": [
            {"name": "dup", "url": "https://one.example.com/mcp"},
            {"name": "dup", "url": "https://two.example.com/mcp", "transport": "http"},
        ],
        "surfaces": {
            "Notes": {"path": "docs/NOTES.md", "kind": "rules"},
            "codex": {"path": "codex/rules.md", "kind": "rules"},
            "zed": {"path": "zed/settings.json", "kind": "mcp"},
            "plain": {"path": ".plain", "kind": "skills"},
            "empty-rules": {"path": "EMPTY.md"},
            "claude": {"path": "nested/dir/CLAUDE.md", "kind": "mcp"},
        },
    },
    # Codex with servers but no skills and no rules, and an empty surfaces
    # object (which falls back to the defaults).
    "codex_servers_only": {
        "version": "9",
        "mcp_servers": [{"name": "only", "url": "https://only.example.com/mcp", "auth_type": "NONE"}],
        "surfaces": {},
    },
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--python-src", required=True, help="the Python hub's src directory")
    args = parser.parse_args()
    sys.path.insert(0, str(Path(args.python_src).expanduser().resolve()))
    from unified_agent import harness_config as hc

    OUT.mkdir(parents=True, exist_ok=True)
    for name, raw in CASES.items():
        bundle = hc.normalize_bundle(raw)
        rendered = hc.render_all(bundle)
        fixture = {
            "case": name,
            "raw": raw,
            "bundle": bundle,
            # What the Python hub stores in harness_config_bundles.bundle_json.
            "bundle_json": json.dumps(bundle, sort_keys=True, separators=(",", ":")),
            "rendered": {
                surface: {
                    "path": info["path"],
                    "kind": info["kind"],
                    "hash": info["hash"],
                    "content": info["content"],
                    "diff_from_empty": hc.make_diff(info["path"], None, info["content"]),
                }
                for surface, info in rendered.items()
            },
        }
        path = OUT / f"{name}.json"
        path.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="ascii")
        print(f"wrote {path.relative_to(OUT.parent.parent.parent.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
