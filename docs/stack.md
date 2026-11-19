# Technology stack

This page records which libraries ua-rust uses and why. Each pick was checked on
2026-11-19 against crates.io, GitHub and the upstream docs (sources at the end).
Re-check a row before relying on it after a few months.

## Decisions

| Area | Pick | Runner-up | Why |
|---|---|---|---|
| Async runtime | tokio 1.54 | — | The default; axum and rmcp both build on it. |
| HTTP framework | axum 0.8 + tower 0.5 + tower-http 0.7 | actix-web 4.20 | rmcp's Streamable HTTP service is a Tower service and mounts with `nest_service("/mcp", …)`. The single call wrapper (auth → profile → policy → approval → ledger) is written as Tower layers plus one in-process dispatcher. |
| MCP | rmcp 3.11 (official SDK) | rust-mcp-sdk 2.0 | Implements spec revision 2026-07-28 (stateless, no `initialize`), with a legacy session mode for 2025-11-25 clients. We implement `list_tools`/`call_tool` by hand so the tool list is filtered per profile. rmcp has no OAuth authorization server. |
| SQLite | rusqlite 0.43 (bundled SQLite 3.54, FTS5 on) | sqlx 0.9 | Full control over WAL, `BEGIN IMMEDIATE`, custom functions and virtual tables. One writer connection plus a read pool; blocking work runs on `spawn_blocking`. Storage sits behind repository traits so a Postgres backend can be added later. |
| Migrations | Named schema parts (own code, about 50 lines) | rusqlite_migration 2.7 | Each feature module contributes idempotent parts recorded by name and checksum, so modules add tables without coordinating version numbers. |
| Full-text search | SQLite FTS5 | tantivy 0.27 | Same transaction as the row write; no second index to keep in sync. |
| Vector search | Vectors stored as BLOBs, brute-force cosine behind a `VectorIndex` trait | sqlite-vec 0.1.9 (optional) | sqlite-vec has had no release since 2026-05 and has open bugs; a brute-force scan is fast enough at 10⁵ notes and carries no dependency risk. |
| Embeddings | fastembed 7.7 (`BAAI/bge-small-en-v1.5`), behind the `embeddings` cargo feature | model2vec-rs 0.4 | Same model catalog as the Python fastembed, so vectors stay comparable. Off by default to keep the build small; lexical search works without it. |
| Ledger hashing | sha2 0.11 | aws-lc-rs 1.19 | Pure Rust. |
| Ledger signing | ed25519-dalek 3.0 (`verify_strict`) | — | Signed producer events. |
| Timestamp anchors | sigstore-tsa 0.16 (RFC 3161) | x509-tsp + cms (RCs) | Optional anchor backend. |
| Constant-time compare | subtle 2.6 | — | Token checks. |
| OAuth 2.1 server | Hand-written on axum (PKCE S256, client ID metadata documents, dynamic registration, RFC 8414 and RFC 9728 metadata, RFC 8707 resource indicators, refresh rotation, revocation) | oauth-as 1.1 | No mature crate exists; we own the code and its conformance tests. |
| JWT | jsonwebtoken 12 | jwt-simple 0.15 | Bearer tokens are opaque and stored hashed; JWT only where a spec needs it. |
| Password hashing | argon2 0.6 | — | Human-chosen secrets only. High-entropy tokens use SHA-256. |
| Passkeys | webauthn-rs 0.6 | — | Relying-party library. |
| Cookies | axum-extra `PrivateCookieJar` + a session table | tower-sessions 0.15 | Fewer moving parts. |
| Tool schemas | schemars 1.2 (`deny_unknown_fields`) + jsonschema 0.61 | — | Every tool argument struct rejects unknown fields, as in the original. |
| SSE | axum `response::sse` | — | Built in. |
| HTML templates | askama 0.16 (+ askama_web) | minijinja 3.1 | Compile-time checked templates. |
| Interactivity | htmx 2.0.11 + htmx-ext-sse 2.2, vendored | Datastar 1.0 | No Node toolchain. htmx 4 is released but is not `latest` until 2027. |
| Static assets | memory-serve 2.4 | rust-embed 8.14 | Embedded, compressed at build time, ETags. |
| CLI | clap 4.6 (derive) + clap_complete | bpaf | Standard. |
| TUI | ratatui 0.30 + crossterm | — | The only serious option. |
| Config | figment 0.10 (defaults → TOML → `UA_*` env) | confique 0.4 | Layered with source-aware errors. |
| Secrets in memory | secrecy 0.10 | — | Redacted `Debug`, zeroized on drop. |
| `.env` | dotenvy 0.15 | — | Local development only. |
| Logging | tracing + tracing-subscriber | — | OpenTelemetry export behind the `otel` feature (OTel traces are still Beta in Rust). |
| Git | `git` CLI via `tokio::process` for writes; gix 0.90 for reads | git2 0.21 | gix cannot yet remove worktrees or run merges. |
| HTTP client | reqwest 0.13 (rustls) | ureq 3 | rustls is now the default backend. |
| Content extraction | dom_smoothie 0.19 + htmd 0.6 | trafilatura 0.6 | Readability-style main content, then Markdown. |
| Code intelligence | tree-sitter 0.27 + tree-sitter-language-pack | ast-grep-language | Same grammar pack as the original. |
| Markdown / vault | comrak 1.0 (wikilinks, front matter) | pulldown-cmark 0.13 | Mutable AST for note rewrites. |
| YAML | serde-saphyr 2.2 | yaml_serde 0.10 | serde_yaml is deprecated; serde_yml is unsound. |
| File watching | notify 8 + notify-debouncer-full | — | Standard. |
| LLM providers | Our own `LlmProvider` trait; genai 0.7 underneath | rig 0.46 | No official Rust SDK from the major providers; keep the dependency swappable. |
| Durable workflows | Hand-written state machine with SQLite checkpoints | graph-flow, apalis | No mature LangGraph equivalent. |
| Process execution | `tokio::process` + process-wrap 10, argv allowlist, timeout, output cap | — | No shell, kill the whole process group on timeout. |
| Sandboxing | landlock 0.4 (Linux) | nono (macOS) | Defense in depth beside the path resolvers. |
| Cron | croner 4.0 | cron 0.17 | |
| GitHub / Slack | octocrab 0.54 / slack-morphism 2.34 | reqwest | Zulip has no maintained crate; plain reqwest. |
| IDs | uuid 1.29 (v7) | ulid 3 | Time-ordered; maps to Postgres `uuid`. Existing integer task ids stay integers. |
| Time | jiff 1.0 | time 0.3 | |
| Tests and CI | cargo-nextest, insta, cargo-deny, Swatinem/rust-cache | cargo-audit | |
| Release | dist 0.34 | cargo-zigbuild | Per-target archives and installers. |

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
- https://github.com/dalek-cryptography/curve25519-dalek
- https://docs.rs/crate/oauth-as/latest
- https://github.com/kanidm/webauthn-rs
- https://github.com/Stranger6667/jsonschema
- https://github.com/Keats/jsonwebtoken
- https://blog.guillaume-gomez.fr/articles/2025-03-19+Askama+and+Rinja+merge
- https://htmx.org/ and https://www.infoq.com/news/2026/09/htmx-4-released/
- https://github.com/tweedegolf/memory-serve
- https://github.com/SergioBenitez/Figment
- https://github.com/open-telemetry/opentelemetry-rust
- https://raw.githubusercontent.com/GitoxideLabs/gitoxide/main/crate-status.md
- https://github.com/seanmonstar/reqwest/blob/master/CHANGELOG.md
- https://github.com/xberg-io/tree-sitter-language-pack
- https://github.com/kivikakk/comrak
- https://github.com/jeremychone/rust-genai
- https://github.com/axodotdev/cargo-dist
- crates.io API (`https://crates.io/api/v1/crates/<name>`) for every crate above
