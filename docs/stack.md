# Technology stack

This page records which libraries ua-rust uses and why. Each pick was checked on
2026-11-19 against crates.io, GitHub and the upstream docs (sources at the end).
Re-check a row before relying on it after a few months. The Decisions table
lists only crates that the workspace `Cargo.toml` files declare; libraries that
were considered and are not used are under [Planned or not adopted](#planned-or-not-adopted).

## Decisions

| Area | Pick | Runner-up | Why |
|---|---|---|---|
| Async runtime | tokio 1.54 | — | The default; axum and rmcp both build on it. |
| HTTP framework | axum 0.8 + tower-http 0.7 (`trace`); tower 0.5 in tests | actix-web 4.20 | rmcp's Streamable HTTP service is a Tower service and mounts with `nest_service("/mcp", …)`. The single call wrapper (auth → profile → policy → approval → ledger) is one in-process dispatcher, `Registry::call`, that every adapter goes through. |
| MCP | rmcp 3.11 (official SDK); its client features power `mcp_gateway` | rust-mcp-sdk 2.0 | Implements spec revision 2026-07-28 (stateless, no `initialize`), with a legacy session mode for 2025-11-25 clients. We implement `list_tools`/`call_tool` by hand so the tool list is filtered per profile. rmcp has no OAuth authorization server. The server side is behind the `mcp-server` cargo feature (ua-server, ua-cli) and the client side behind `mcp-gateway` (ua-tools); both are on by default. |
| SQLite | rusqlite 0.43 (bundled SQLite 3.54, FTS5 on) | sqlx 0.9 | Full control over WAL, `BEGIN IMMEDIATE`, custom functions and virtual tables. One writer connection plus a pool of four readers, lent through an RAII guard; when all are busy a read opens a short-lived extra reader (up to four) and then waits, never taking the writer. Blocking work runs on `spawn_blocking`. `ua serve` runs `PRAGMA wal_checkpoint(TRUNCATE)` on shutdown. |
| Migrations | Named schema parts (own code, about 50 lines) | rusqlite_migration 2.7 | Each feature module contributes idempotent parts recorded by name and checksum, so modules add tables without coordinating version numbers. |
| Full-text search | SQLite FTS5 | tantivy 0.27 | Same transaction as the row write; no second index to keep in sync. |
| Vector search | Vectors stored as BLOBs, brute-force cosine behind a `VectorIndex` trait in `ua-memory` | sqlite-vec 0.1.9 (not used) | sqlite-vec has had no release since 2026-05 and has open bugs; a brute-force scan is fast enough at 10⁵ notes and carries no dependency risk. |
| Embeddings | fastembed 7.7 (`BAAI/bge-small-en-v1.5`), behind the `embeddings` cargo feature of `ua-memory` (`ua-tools/embeddings` forwards to it) | model2vec-rs 0.4 | Same model catalog as the Python fastembed, so vectors stay comparable. Off by default to keep the build small; lexical search works without it. |
| Ledger hashing | sha2 0.11 | aws-lc-rs 1.19 | Pure Rust. Each event row stores the hash of its predecessor. |
| Constant-time compare | subtle 2.6 | — | Token checks. |
| Secrets at rest | aes-gcm 0.10 (AES-256-GCM) + hmac 0.13 (RustCrypto) | chacha20poly1305 0.10 | Both were already in the tree (cookie, webauthn-rs), so managed secrets add no new crate. aes-gcm 0.10 is the audited RustCrypto line (NCC Group, 2020); the 0.11 line in the tree is newer and less deployed. |
| OAuth 2.1 server | Hand-written on axum (PKCE S256, client ID metadata documents, dynamic registration, RFC 8414 and RFC 9728 metadata, RFC 8707 resource indicators, refresh rotation, revocation) | oauth-as 1.1 | No mature crate exists; we own the code and its conformance tests. |
| Passkeys | webauthn-rs 0.6 | — | Relying-party library. |
| Cookies | axum-extra `PrivateCookieJar` + a session table | tower-sessions 0.15 | Fewer moving parts. |
| Tool schemas | schemars 1.2 (`deny_unknown_fields`) | — | Every tool argument struct rejects unknown fields, as in the original. |
| SSE | axum `response::sse` | — | Built in. |
| HTML templates | askama 0.16 (+ askama_web) | minijinja 3.1 | Compile-time checked templates. |
| Interactivity | htmx 2.0.11 + htmx-ext-sse 2.2, vendored | Datastar 1.0 | No Node toolchain. htmx 4 is released but is not `latest` until 2027. |
| Static assets | memory-serve 2.4 | rust-embed 8.14 | Embedded, compressed at build time, ETags. |
| CLI | clap 4.6 (derive) | bpaf | Standard. |
| Config | figment 0.10 (defaults → TOML → `UA_*` env) | confique 0.4 | Layered with source-aware errors. |
| Secrets in memory | secrecy 0.10 | — | Redacted `Debug`, zeroized on drop. |
| `.env` | dotenvy 0.15 | — | Local development only. |
| Logging | tracing + tracing-subscriber | — | Plain-text output. There is no JSON layer and no OpenTelemetry export. |
| Git | The `git` CLI, run through the workspace command runner | gix 0.90, git2 0.21 | gix cannot yet remove worktrees or run merges. |
| HTTP client | reqwest 0.13 (rustls) | ureq 3 | rustls is now the default backend. |
| Content extraction | dom_smoothie 0.19 + htmd 0.6 | trafilatura 0.6 | Readability-style main content, then Markdown. dom_smoothie is behind the `readability` cargo feature (on by default); without it the whole page is converted and results say `extraction: "full-page"`. |
| Code intelligence | tree-sitter 0.27 + the Rust, Python, JavaScript, TypeScript and Go grammar crates | tree-sitter-language-pack, ast-grep-language | Five grammars, one crate each. Behind the `code-intel` cargo feature (on by default); without it the four symbol tools are not registered. |
| Markdown / vault | comrak 1.0 (wikilinks, front matter) | pulldown-cmark 0.13 | Mutable AST for note rewrites. |
| YAML | serde-saphyr 2.2 | yaml_serde 0.10 | serde_yaml is deprecated; serde_yml is unsound. |
| Durable workflows | Hand-written state machine with SQLite checkpoints | graph-flow, apalis | No mature LangGraph equivalent. |
| Process execution | `tokio::process`, argv allowlist, timeout, output cap | process-wrap 10 | No shell, kill the whole process group on timeout. |
| Sandboxing | Path resolvers in `ua-core` confine file and command tools to a workspace root | landlock 0.4, nono | No kernel sandbox is used. |
| Cron | croner 4.0 | cron 0.17 | |
| GitHub, Slack, Zulip | Own REST client on reqwest for GitHub and Zulip; own Slack code (signature check, parser, Socket Mode on tokio-tungstenite) | octocrab 0.54, slack-morphism 2.34 | The GitHub client is bound to configured repositories. No Slack SDK: the hub needs only request signing, `apps.connections.open` and the Socket Mode envelope protocol. Zulip has no maintained crate. |
| IDs | ulid 3 and uuid 1.29 (v4) | — | ULIDs are time-ordered; the code generates only v4 UUIDs, though the `v7` feature is enabled. Existing integer task ids stay integers. |
| Time | jiff 1.0 (`ua-tools` also uses chrono 0.4 for cron) | time 0.3 | |
| Tests and CI | cargo-nextest, Swatinem/rust-cache | cargo-audit | `cargo fmt`, `clippy` and `nextest` run in CI, with and without default features, plus a macOS dispatch job. |

## Planned or not adopted

These were in an earlier version of this page. None is a dependency of any
workspace crate today. Treat each as a candidate, not a decision.

| Area | Candidate | Note |
|---|---|---|
| Storage backends | Repository traits over SQLite | The tool families call `rusqlite` directly. There are no repository traits, so a second backend would need that layer first. |
| Ledger signing | ed25519-dalek (`verify_strict`) | Signed producer events. |
| Timestamp anchors | sigstore-tsa (RFC 3161) | Optional anchor backend. |
| JWT | jsonwebtoken | Bearer tokens are opaque and stored hashed; add it only where a spec needs one. |
| Password hashing | argon2 | For human-chosen secrets, if passwords are ever added. Sign-in uses passkeys and links. |
| Tool argument validation | jsonschema | Arguments are typed structs that reject unknown fields. |
| TUI | ratatui + crossterm | No terminal UI exists. |
| CLI completions | clap_complete | |
| Telemetry | OpenTelemetry export behind an `otel` feature | |
| File watching | notify + notify-debouncer-full | |
| LLM providers | An `LlmProvider` trait over genai | |
| Git reads | gix | Reads and writes both use the `git` CLI. |
| Sandboxing | landlock (Linux) | |
| Provider clients | octocrab, slack-morphism | |
| Release | dist | |

## Cargo features

The heavy optional dependencies sit behind cargo features, so a smaller build
can leave them out. Each feature is declared in `ua-tools` (or `ua-server`)
and forwarded with the same name by `ua-server`, `ua-import` and `ua-cli`.
`system_doctor` (`build.features`, the `build_features` row) and
`capability_catalog` (`build_features`, `compiled_out_tools`) report what a
build has.

| Feature | Default | Pulls in | Enables | Without it |
|---|---|---|---|---|
| `code-intel` | on | tree-sitter and five grammars | `fs_index_symbols`, `fs_list_symbols`, `fs_search_symbols`, `fs_repo_map` | Those four tools are not registered. |
| `readability` | on | dom_smoothie | The article pass in `web_fetch` and `dash_view` | The whole page is converted; results carry `extraction: "full-page"`. |
| `mcp-gateway` | on | rmcp (client) | `mcp_gateway`, the downstream MCP client | No `mcp_gateway`; `mcp_server_register` refuses, and the `mcp_server_*` descriptions and results say no gateway is compiled in. |
| `mcp-server` | on | rmcp (server) | The `/mcp` route, `ua mcp`, the `/mcp` OAuth protected resource | `ua serve` warns at startup and serves the JSON API and UI only; OAuth issues hub-wide tokens; `ua mcp` exits with an error naming the feature. |
| `slack-socket` | on | tokio-tungstenite 0.28 (WebSocket protocol only, no TLS feature; TLS is tokio-rustls with the rustls/ring stack and platform verifier reqwest already uses, so no second TLS implementation) | Slack Socket Mode in `ua serve` (an outbound WebSocket; no public URL) | `slack_socket_mode = true` is reported as not compiled in (startup log, `system_doctor`); the signed HTTP routes still work. |
| `embeddings` | off | fastembed | Semantic memory search (see the Embeddings row) | Memory search is lexical (FTS5). |

## Protocol notes

MCP revision 2026-07-28 removed sessions, `initialize`, `resources/subscribe` and
server-initiated `elicitation/create`. Consequences for ua-rust:

- Profiles are bound to the authenticated identity plus a client-chosen session key,
  not to an `Mcp-Session-Id`.
- Approval-gated calls return a durable approval handle immediately. The client
  re-polls or retries with the approval; nothing waits on a held-open stream.
- Older clients keep working through rmcp's legacy session mode.

## Sources

- https://modelcontextprotocol.io/specification/2026-07-28/changelog
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- https://github.com/modelcontextprotocol/rust-sdk
- https://github.com/tokio-rs/axum
- https://github.com/rusqlite/rusqlite
- https://github.com/transact-rs/sqlx
- https://github.com/asg017/sqlite-vec
- https://github.com/tursodatabase/turso
- https://github.com/Anush008/fastembed-rs
- https://github.com/MinishLab/model2vec-rs
- https://docs.rs/crate/oauth-as/latest
- https://github.com/kanidm/webauthn-rs
- https://blog.guillaume-gomez.fr/articles/2025-03-19+Askama+and+Rinja+merge
- https://htmx.org/ and https://www.infoq.com/news/2026/09/htmx-4-released/
- https://github.com/tweedegolf/memory-serve
- https://github.com/SergioBenitez/Figment
- https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md
- https://github.com/kivikakk/comrak
- crates.io API (`https://crates.io/api/v1/crates/<name>`) for every crate above
