# Memory retrieval bench

Baseline for the current `memory_search` path. The fixture corpus is the CI
gate (`crates/ua-memory/bench/floor.json`). LongMemEval-S is a recorded run,
not a CI gate. Ranking is unchanged.

`ua memory bench` is the command in the design. It is not wired in this
change: `crates/ua-cli` belongs to another lane. Until that lands, run the
`memory-bench` binary in `ua-memory`.

## Fixture corpus

Checked in at `crates/ua-memory/bench/corpus.json`. Ten queries, lexical
retrieval (`retrieval.mode` = `lexical_fallback`; the `embeddings` feature is
off). Each query runs on a fresh copy of the corpus database.

A query lists three kinds of notes:

- `must`: every one must be in the top 5.
- `must_not`: none may be in the top 5.
- `outranked`: notes that share the query's terms and are retrieved, but must
  rank below every `must` note.

`recall@5` is 1 only when all three hold. `mrr` is the reciprocal rank of the
first `must` note inside the top 10.

| Class | n | recall@5 | MRR |
|---|---:|---:|---:|
| exact-term | 2 | 1.0000 | 1.0000 |
| paraphrase | 2 | 0.5000 | 0.5000 |
| temporal | 3 | 0.6667 | 0.6667 |
| contradiction | 2 | 1.0000 | 1.0000 |
| long-document | 1 | 1.0000 | 1.0000 |
| overall | 10 | 0.8000 | 0.8000 |

`floor.json` records `n` for each class as well as the floor. A class whose
query count differs from its recorded `n` fails the floor, so deleting a
failing query cannot quietly raise a class mean.

### Hard negatives

Every negative shares terms with its query, so lexical search could return it
(`fixture_negatives_share_their_query_terms` checks this). Each one tests a
specific mechanism:

| Query | Negative | Kept out by |
|---|---|---|
| `exact-token` (`quartz-falcon-17`) | `exact-noise`: `quartz-falcon-71`, `falcon quartz 17` | phrase match: the words are there, not in that order |
| `exact-title` (`signing key`) | `exact-near` (outranked): both words in the body | the title column weight; its title sorts first, so a score tie would fail |
| `para-stem` (`running archives`) | `para-stem-near` (outranked): `archive` only | AND matches rank above the OR fallback |
| `temporal-early`, `temporal-late` | the other version of the badge note | `as_of` and supersession |
| `contra-supersede` | `contra-old`, superseded | the superseded filter |
| `long-tail` (`violet-orchid-88`) | `long-noise`: `violet`, `orchid` and `88` apart | phrase match |

An `outranked` note must also be retrieved. If a ranking change stops
returning one, the negative no longer tests anything, and the floor check
fails with a reason naming the note.

### Paraphrase

`para-stem` is stem-only: neither query word appears verbatim in the note.
Porter stemming matches `running` to `runs` and `archives` to `archive`, and
the search uses AND, so both stems must match. (The earlier query, `running
nightly`, also passed without stemming, through the OR fallback on
`nightly`.) `sedan` does not match a note that only says `automobile`
(`para-gap`), so that query scores 0. That gap is recorded in the floor.

### Temporal: valid time versus write time

`as_of` keeps a note only when `valid_from <= as_of < valid_to` and
`created_at <= as_of` (`note.rs`). `created_at` is the write time. The
harness saves every note on the bench clock, then moves `created_at` back to
`valid_from` (`backdate_created`), so the temporal queries see notes recorded
when they became valid. That is why `temporal-early` and `temporal-late`
pass.

A note recorded late, saved today with a past `valid_from`, stays invisible to
any `as_of` between the two. `temporal-recorded` records this gap: its note is
valid from 2024-03-01, its `recorded_at` is 2026-02-15, and the query asks as
of 2024-06-01. It scores 0, so the temporal floor is 0.6667. If `as_of`
learns to answer from valid time, this query passes, and the floor is raised
in that commit. The LongMemEval harness backdates the same way, so its
`as_of` number measures the same thing.

### Long documents

The long-document query finds a token past the first 512 tokens because FTS
indexes the whole note.

### Stale share

`stale_share` is the design's metric (`docs/memory.md`, target under 2%): the
share of top-5 hits that are superseded by a note already valid at the query
instant (`as_of`, else the bench clock). It is 0 (0/12). `must_not_share` (top-5
hits a query lists as `must_not`) is also 0.

### Isolation

The corpus has no scope or leak case and the bench has no hard-fail leak gate.
That is intended: isolation lands with step 3 of `docs/memory.md` (scoped
recall), as a differential test that runs each query with and without hidden
notes and requires identical visible output. recall@k cannot see those side
channels.

### Determinism

- The clock is fixed. Search reads `Config.clock` for the recency leg, the
  prior's age discount and expiry, and save stamps `created_at` and
  `updated_at` from it. The bench sets it to `BENCH_NOW`
  (`2026-03-01T00:00:00+00:00`) and prints it as `clock` in the report. A
  hub always uses the wall clock.
- Search breaks score ties on title, then insertion order (the `memory`
  rowid), not the random note id. The lexical leg's `LIMIT` also breaks bm25
  ties on insertion order. `crates/ua-memory/tests/order.rs` checks both that tied notes
  come back in save order and that a fixture with no ties keeps the order and
  scores recorded before this change.
- `crates/ua-memory/tests/bench.rs` runs the fixture twice and requires
  byte-identical JSON.

```sh
cargo run -p ua-memory --bin memory-bench
```

The binary prints this table on stderr and a JSON report on stdout. It exits
non-zero when a class is below `bench/floor.json`.

## LongMemEval-S

The pinned file is the same one the predecessor scored:

| Field | Value |
|---|---|
| Dataset | `xiaowu0162/longmemeval-cleaned` |
| Revision | `98d7416c24c778c2fee6e6f3006e7a073259d48f` |
| File | `longmemeval_s_cleaned.json` |
| sha256 | `d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442` |

`cargo run -p ua-memory --bin memory-bench -- --longmemeval` reads
`~/.cache/ua-longmemeval/98d7416c/` (or `UA_LONGMEMEVAL_CACHE`). If the file
is missing there, it downloads it with `curl`, checks the hash, and refuses a
mismatch. `--data PATH` uses a local copy and still checks the hash. The file
is not committed. This is the only network access in the bench, and no test
takes it.

The harness follows the predecessor's session protocol: one note per haystack
session, title `Conversation on <date>`, body `Conversation date: <date>` then
`role: text` turns, `valid_from` set to the session date (UTC), tag
`project:longmemeval-eval`, no session id in the note text. It searches with
`memory_search` at limit 10. Abstention questions (ids ending `_abs`) are
excluded. Headline metrics are strict recall@5 (every evidence session in the
top 5) and MRR@10. It also records:

- `as_of_accuracy`: temporal-reasoning strict recall@5 when `as_of` is the
  question date.
- `older_non_evidence_share`: the share of knowledge-update top-5 hits that
  are not evidence and predate the newest evidence session. This was called
  `stale_share` before. It is not the design's stale share and cannot be
  compared with the 2% target: LongMemEval has no supersession links, and in a
  50-session haystack most of these hits are unrelated filler.
- p95 search latency, excluding ingest.

Sessions with the same timestamp get the same title and tie on score. They
now rank in haystack order, so `ranked_sessions` is the same on every run. The
run uses the bench clock. Every session predates it by more than 19.5 months,
where the age discount is clamped, as it was under the wall clock.

Each question runs in its own scratch subdirectory, and the directory
(database, `-wal` and `-shm`) is removed when the question finishes. A full
run no longer accumulates about 2 GB in `TMPDIR`. The scratch root is named by
pid, a per-process counter and the start time, so concurrent runs do not share
it.

`--limit N` scores the first N answerable questions in file order. `--ids
FILE` scores exactly the listed question ids (one per line or
comma-separated, `#` comments allowed), in file order. To reproduce the
predecessor's 120-question sample, write the ids its `stratified_sample` picks
(20 per type, `random.Random(2145)`) to a file and pass it with `--ids`. The
report's `dataset.selection` says which selection ran.

```sh
mkdir -p ~/.cache/ua-longmemeval/98d7416c
curl -fsSL -o ~/.cache/ua-longmemeval/98d7416c/longmemeval_s_cleaned.json \
  https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/98d7416c24c778c2fee6e6f3006e7a073259d48f/longmemeval_s_cleaned.json
cargo run --release -p ua-memory --bin memory-bench -- --longmemeval --out lme-full.json
```

A default build scores the lexical path (no embedding model).

### Recorded run

The only full run so far was measured at `1d9a30f`, before this harness
change. It was lexical only, all 470 answerable questions: strict recall@5
0.8489 (399/470), MRR@10 0.8389, `as_of` accuracy 0.48, search p95 18 ms. The
same numbers are in `docs/memory.md`; the per-type table is in the PR #53
review. The report JSON from that run is not in the repository. It has not
been re-run on this change. The tie-break did not move any score in that run
(the five reordered pairs stayed on the same side of rank 5 and of the first
evidence session). The fixed clock can move a session across a whole-day
recency boundary, so a re-run may differ slightly.
