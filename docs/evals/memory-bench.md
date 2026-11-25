# Memory retrieval bench

Baseline for the current `memory_search` path. The fixture corpus is the CI
gate (`crates/ua-memory/bench/floor.json`). LongMemEval-S is a recorded run,
not a CI gate. Ranking is unchanged.

`ua memory bench` is the command in the design. It is not wired in this
change: `crates/ua-cli` belongs to another lane. Until that lands, run the
`memory-bench` binary in `ua-memory`.

## Fixture corpus

Checked in at `crates/ua-memory/bench/corpus.json`. Nine queries, lexical
retrieval (`retrieval.mode` = `lexical_fallback`; the `embeddings` feature is
off). Each query runs on a fresh copy of the corpus database. `recall@5` is 1
only when every `must` note is in the top 5 and no `must_not` note is.
`mrr` is the reciprocal rank of the first `must` note inside the top 10.

| Class | n | recall@5 | MRR |
|---|---:|---:|---:|
| exact-term | 2 | 1.0000 | 1.0000 |
| paraphrase | 2 | 0.5000 | 0.5000 |
| temporal | 2 | 1.0000 | 1.0000 |
| contradiction | 2 | 1.0000 | 1.0000 |
| long-document | 1 | 1.0000 | 1.0000 |
| overall | 9 | 0.8889 | 0.8889 |

Stale share (top-5 hits that a query lists as `must_not`) is 0.

The paraphrase class is the gap this floor records. Porter stemming matches
`running` to `runs` (`para-stem`). `sedan` does not match a note that only says
`automobile` (`para-gap`), so that query scores 0. The long-document query
finds a token past the first 512 tokens because FTS indexes the whole note.

```sh
cargo run -p ua-memory --bin memory-bench
```

The binary prints this table on stderr and a JSON report on stdout. It exits
non-zero when a class is below `bench/floor.json`.
`crates/ua-memory/tests/bench.rs` runs the fixture twice and requires the same
report.

## LongMemEval-S

Not measured in this environment. The pinned file is the same one the
predecessor scored:

| Field | Value |
|---|---|
| Dataset | `xiaowu0162/longmemeval-cleaned` |
| Revision | `98d7416c24c778c2fee6e6f3006e7a073259d48f` |
| File | `longmemeval_s_cleaned.json` |
| sha256 | `d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442` |

`cargo run -p ua-memory --bin memory-bench -- --longmemeval` downloads that file on demand into
`~/.cache/ua-longmemeval/98d7416c/` (or `UA_LONGMEMEVAL_CACHE`), checks the
hash, and refuses a mismatch. `--data PATH` uses a local copy and still checks
the hash. The file is not committed.

The harness follows the predecessor's session protocol: one note per haystack
session, title `Conversation on <date>`, body `Conversation date: <date>` then
`role: text` turns, `valid_from` set to the session date (UTC), tag
`project:longmemeval-eval`, no session id in the note text. It searches with
`memory_search` at limit 10. Abstention questions (ids ending `_abs`) are
excluded. Headline metrics are strict recall@5 (every evidence session in the
top 5) and MRR@10. It also records temporal-reasoning strict recall@5 when
`as_of` is the question date, the share of knowledge-update top-5 hits that
are not evidence and predate the newest evidence session, and p95 search
latency excluding ingest.

This run could not download the file. Egress allows a fixed host list, and
`huggingface.co` is not on it: `curl` connected and the TLS handshake was
reset (`curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL`). The LongMemEval
git repository does not contain this cleaned file.

```sh
mkdir -p ~/.cache/ua-longmemeval/98d7416c
curl -fsSL -o ~/.cache/ua-longmemeval/98d7416c/longmemeval_s_cleaned.json \
  https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/98d7416c24c778c2fee6e6f3006e7a073259d48f/longmemeval_s_cleaned.json
cargo run -p ua-memory --bin memory-bench -- --longmemeval
```

A default build scores the lexical path (no embedding model). `--limit N`
scores the first N answerable questions in file order and is not the baseline.
