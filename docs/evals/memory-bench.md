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

Every negative shares terms with its query
(`fixture_negatives_share_their_query_terms` checks this). Each one tests a
specific mechanism. There are two kinds:

- **Phrase guards** (`exact-noise`, `long-noise`). A single-token query is
  matched as one phrase with no OR fallback, so these notes are never returned
  while phrase matching holds. Each one contains every word of its query
  (`phrase_negatives_hold_every_query_word`), so a word-bag match returns it
  and fails the class. With the AND query split into words, exact-term fell to
  0.5 and long-document to 0.
- **Reachable negatives** (`exact-near`, `para-stem-near`, the temporal and
  superseded versions). Lexical search retrieves them, or would without the
  filter that the row names.

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
  prior's age discount and expiry. Save, delete and restore stamp
  `created_at`, `updated_at` and the captured version's `recorded_at` from
  it. The `memory_versions_capture` trigger writes SQLite's wall clock, and
  its SQL is locked in a merged schema part, so the write path restamps the
  new version in the same transaction. `tests/clock.rs` pins save, delete,
  restore, feedback, version history and both maintenance reports to fixed
  clocks. The bench sets it to `BENCH_NOW`
  (`2026-03-01T00:00:00+00:00`) and prints it as `clock` in the report. A
  hub always uses the wall clock.
- Search breaks score ties on title, then insertion order (the `memory`
  rowid), not the random note id. The lexical leg's `LIMIT` and the semantic
  leg's top-50 cut also break ties on insertion order.
  `crates/ua-memory/tests/order.rs` checks that tied notes come back in save
  order (lexically, and semantically with a constant test embedder), and that
  a fixture with no ties keeps the order and scores recorded before this
  change, on a fixed clock.
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

#### Historical lexical baseline (`1d9a30f`)

The initial full run was measured at `1d9a30f`, before the #2798 harness
changes. It was lexical only, all 470 answerable questions: strict recall@5
0.8489 (399/470), MRR@10 0.8389, `as_of` accuracy 0.48, search p95 18 ms. The
same numbers are in `docs/memory.md`; the per-type table is in the PR #53
review. The report JSON from that run is not in the repository.

#### Slice 2 measurement (`c6725b04`, `--features embeddings`, `BAAI/bge-small-en-v1.5`)

Measured at `c6725b04` (after PR #155 chunked embeddings, PR #156 deterministic
bench / injected `Config.clock`, and PR #157 local ONNX embedder and
`ua memory models fetch`). Ranking weights, thresholds and `RRF_K` are
**unchanged**.

**Headline findings:**

1. **Hybrid mode regresses the fixture corpus from `0.8000` to `0.6000`
   recall@5 (`0.8000` to `0.7500` MRR), failing `bench/floor.json` on
   `exact-term` (`1.0000` -> `0.0000`, `must_not_share` `0.0769`).** Both
   single-vector and chunked hybrid modes score identically on the fixture, and
   the fixture's `long-document` class stays `1.0000` in all three modes via
   FTS5.
2. **On LongMemEval-S (120-question stratified sample, 20 per type, seed 2145),
   hybrid embeddings lift strict recall@5 from `0.8833` to `0.9000` and MRR@10
   from `0.8302` to `0.8890` (single-vector) / `0.9111` (chunked), while search
   p95 latency was `16.7 ms` (lexical, single-process) vs `57.5 ms`
   (single-vector) and `87.8 ms` (chunked) — both hybrid runs mostly under
   2-shard contention (`91/120` questions; the `29` resumed questions ran
   uncontended; see note below).** At `n = 120`, one question is
   `≈ 0.83` percentage points (`0.0083`), so the overall strict recall@5 delta
   (`0.8833` -> `0.9000`) is `+2` net questions (`+3` wins / `-1` loss; within
   each 20-question class, one question is `5.0` percentage points).
3. **On LongMemEval-S, chunking on top of single-vector hybrid moves strict
   recall@5 by `0` (`0.9000` -> `0.9000`, `0` wins / `0` losses across all 6
   LongMemEval types), adds `+0.0221` MRR@10 (`0.8890` -> `0.9111`, within
   sample noise at `n = 120`), and increases p95 search latency (`57.5 ms` ->
   `87.8 ms`, both hybrid runs mostly under 2-shard contention; see note
   below).**
4. **`as_of` accuracy is flat at `0.5000` (`10/20`) across all three modes**
   (lexical, hybrid single-vector, and hybrid chunked).

##### Model and dataset pins

| Artifact | Pin |
|---|---|
| Codebase | `c6725b04` (`main` after #155, #156, #157) |
| Embedder | `local:BAAI/bge-small-en-v1.5@ea104dacec62c0de699686887e3f920caeb4f3e3` (`ua memory models fetch`) |
| Dataset | `xiaowu0162/longmemeval-cleaned` @ `98d7416c24c778c2fee6e6f3006e7a073259d48f` (`longmemeval_s_cleaned.json`) |
| Dataset sha256 | `d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442` |
| Stratified sample | `crates/ua-memory/bench/longmemeval-strat120-seed2145.txt` (120 questions: 20 per type, `random.Random(2145)`) |
| Bench clock | `2026-03-01T00:00:00+00:00` |

"Before" is reported both as **lexical-only** (default build without `--embed`)
and as **hybrid single-vector** (`--embed --no-chunks`, pre-#155 semantics:
single truncated vector per note, `memory_chunks` dropped before search) so the
effect of embeddings is separated from the effect of chunking.

##### Fixture corpus: lexical vs hybrid single-vector vs hybrid chunked

| Class | n | Lexical R@5 / MRR | Hybrid single-vector R@5 / MRR | Hybrid chunked R@5 / MRR | Floor R@5 / MRR |
|---|---:|---:|---:|---:|---:|
| exact-term | 2 | 1.0000 / 1.0000 | **0.0000 / 0.7500** (FAIL) | **0.0000 / 0.7500** (FAIL) | 1.0000 / 1.0000 |
| paraphrase | 2 | 0.5000 / 0.5000 | 0.5000 / 0.5000 | 0.5000 / 0.5000 | 0.5000 / 0.5000 |
| temporal | 3 | 0.6667 / 0.6667 | 0.6667 / 0.6667 | 0.6667 / 0.6667 | 0.6667 / 0.6667 |
| contradiction | 2 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| long-document | 1 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| **overall** | **10** | **0.8000 / 0.8000** | **0.6000 / 0.7500** | **0.6000 / 0.7500** | — |
| `stale_share` | — | 0.0000 (0/12) | 0.0000 (0/13) | 0.0000 (0/13) | — |
| `must_not_share` | — | 0.0000 | 0.0769 (1/13) | 0.0769 (1/13) | — |

Exact `BAAI/bge-small-en-v1.5` cosine diagnostics on the fixture corpus explain
every regression and non-movement:

- **`exact-token` (`quartz-falcon-17`, recall@5 `1.0 -> 0.0`):** `exact-noise`
  (`"Token quartz-falcon-71 was retired; falcon quartz 17 is the rota slot."`)
  scores cosine **`0.7910`**, exceeding `exact-key` (`0.7432`) and clearing
  `SEMANTIC_MIN_SIMILARITY = 0.65`. The semantic leg injects `exact-noise` at
  rank 2 despite FTS5 phrase matching rejecting it (`must_not` hit).
- **`exact-title` (`signing key`, recall@5 `1.0 -> 0.0`, MRR `1.0 -> 0.5`):**
  `exact-near` (`"Checklist for release"`) scores cosine **`0.7952`** vs
  `exact-key` (`"Harbor signing key"`) at `0.7330`. Under equal
  `LEG_WEIGHTS = [("lexical", 1.0), ("semantic", 1.0), ("recency", 0.2)]`,
  `exact-key` (lexical #1, semantic #2) and `exact-near` (lexical #2, semantic
  #1) produce an exact RRF tie, which `search.rs` breaks alphabetically by
  title (`"Checklist for release"` < `"Harbor signing key"`), inverting them.
- **`para-gap` (`sedan` -> `automobile`, recall@5 `0.0 -> 0.0`):** `para-auto`
  ranks #1 semantically at **`0.5965`** (well ahead of runner-up `exact-noise`
  at `0.5239`), but `0.5965 < 0.65`, so `SEMANTIC_MIN_SIMILARITY` drops it and
  the query still returns `[]`. (`para-stem`, `running archives`, also sits at
  `0.5746 < 0.65` and passes only via Porter stemming in FTS5.)
- **`long-tail` (`violet-orchid-88`, recall@5 `1.0 -> 1.0`):** chunking lifts
  `long-note`'s cosine from **`0.4828`** (single vector, truncated before the
  tail) to **`0.6469`** (tail chunk), overtaking `long-noise` (`0.5954`) by
  `+0.0515`, yet still misses `SEMANTIC_MIN_SIMILARITY = 0.65` by `0.0031`.
  Both single-vector and chunked runs pass `long-tail` solely via FTS5.
- **`temporal-recorded` (`locker code`, recall@5 `0.0 -> 0.0`):** the valid
  time vs write time gap is unchanged (`created_at > as_of`), while the
  semantic leg also admits `temporal-old` (`badge code`, cosine `0.6539 >= 0.65`)
  as a false positive where lexical returned `[]`.

##### LongMemEval-S: full 470 lexical baseline (`c6725b04`)

Re-run at `c6725b04` (deterministic bench clock and tie-break):

| Type | n | Lexical R@5 | Hits | MRR@10 |
|---|---:|---:|---:|---:|
| overall | 470 | 0.8511 | 400 | 0.8462 |
| single-session-user | 64 | 1.0000 | 64 | 0.8018 |
| single-session-assistant | 56 | 1.0000 | 56 | 0.7574 |
| single-session-preference | 30 | 0.9000 | 27 | 0.6209 |
| multi-session | 121 | 0.7025 | 85 | 0.8722 |
| knowledge-update | 72 | 0.9722 | 70 | 0.9306 |
| temporal-reasoning | 127 | 0.7717 | 98 | 0.8883 |

`as_of` accuracy: `0.4803` (`n=127`). `older_non_evidence_share`: `0.3861`
(`139/360`). Search p95: `16.4 ms`.

##### LongMemEval-S: 120-question stratified sample (`20/type`, seed `2145`)

In this 120-question sample, 5,464 of 5,766 haystack sessions (`94.8%`) exceed
the 2,048-char chunking threshold (median session length 10,468 chars; ~76,575
total vectors across 120 questions). Full 470-question hybrid chunked ingest
(~299k vectors) was impractical on a 4-core CPU box, so all three modes were
scored on the exact committed 120-question stratified sample
(`crates/ua-memory/bench/longmemeval-strat120-seed2145.txt`, matching the
predecessor's 20/type `random.Random(2145)` protocol).

| Class / Metric | n | Lexical R@5 / MRR@10 | Hybrid single-vector R@5 / MRR@10 | Hybrid chunked R@5 / MRR@10 | Delta (Lex -> Chunked) | Delta (Single -> Chunked) |
|---|---:|---:|---:|---:|---:|---:|
| **overall** | 120 | 0.8833 (106) / 0.8302 | 0.9000 (108) / 0.8890 | 0.9000 (108) / 0.9111 | +0.0167 (+2) / +0.0809 | +0.0000 (0) / +0.0221 |
| single-session-user | 20 | 1.0000 (20) / 0.8458 | 1.0000 (20) / 0.8542 | 1.0000 (20) / 0.8792 | +0.0000 / +0.0334 | +0.0000 / +0.0250 |
| single-session-assistant | 20 | 1.0000 (20) / 0.7500 | 1.0000 (20) / 1.0000 | 1.0000 (20) / 0.9750 | +0.0000 / +0.2250 | +0.0000 / -0.0250 |
| single-session-preference | 20 | 0.8500 (17) / 0.5855 | 0.8500 (17) / 0.6296 | 0.8500 (17) / 0.6955 | +0.0000 / +0.1100 | +0.0000 / +0.0659 |
| **multi-session** | 20 | **0.7500 (15) / 0.9250** | **0.8000 (16) / 0.9750** | **0.8000 (16) / 1.0000** | **+0.0500 (+1) / +0.0750** | **+0.0000 (0) / +0.0250** |
| knowledge-update | 20 | 0.9500 (19) / 0.9750 | 0.9500 (19) / 0.9500 | 0.9500 (19) / 1.0000 | +0.0000 / +0.0250 | +0.0000 / +0.0500 |
| temporal-reasoning | 20 | 0.7500 (15) / 0.9000 | 0.8000 (16) / 0.9250 | 0.8000 (16) / 0.9167 | +0.0500 (+1) / +0.0167 | +0.0000 (0) / -0.0083 |
| `as_of` accuracy | 20 | 0.5000 (10/20) | 0.5000 (10/20) | 0.5000 (10/20) | +0.0000 | +0.0000 |
| `older_non_evidence_share` | 100 | 0.3800 (38/100) | 0.3800 (38/100) | 0.3800 (38/100) | +0.0000 | +0.0000 |
| search latency p95* | 120 | 16.7 ms | 57.5 ms | 87.8 ms | +71.1 ms* | +30.3 ms* |

*\*Latency qualification:* the hybrid p95 figures above were collected with a
temporary dual-scoring measurement build scoring chunked, then dropping
`memory_chunks` and scoring single-vector on the same embedded database:
mostly under 2-shard contention on a 4-core CPU (`91/120` questions), with the
remaining `29` questions resumed uncontended after a host reboot (where
chunked p95 was `100.9 ms` and single-vector p95 was `57.9 ms`), whereas
lexical (`16.7 ms`) ran alone in a single process. Because most hybrid
questions ran under 2-shard CPU contention on a non-committed dual-scoring
build, those p95 values are not directly comparable to an uncontended
single-process run. The committed `memory-bench` binary runs one mode per
invocation and reports `p95` only.

##### Diagnosis

1. **Chunking did not materially move strict recall@5 on LongMemEval-S or the
   fixture `long-document` class.** All four recall@5 flips from lexical to
   hybrid (`+c4a1ceb8` multi-session, `+eac54adc` temporal-reasoning,
   `+06f04340` single-session-preference, `-195a1a1b`
   single-session-preference; net `+2`) occurred identically in single-vector
   hybrid and chunked hybrid (`0` net recall@5 change from adding chunks).
2. **Most of the MRR@10 gain came from embeddings rather than chunking:**
   hybrid single-vector accounted for `+0.0588` of the `+0.0809` total MRR@10
   gain over lexical (`0.8302` -> `0.8890`). Adding chunks shifted overall
   MRR@10 by `+0.0221` (`0.8890` -> `0.9111`), which is within sample noise at
   `n = 120` and moved classes in both directions: up on
   `single-session-preference` (`+0.0659`), `knowledge-update` (`+0.0500`),
   `single-session-user` (`+0.0250`), and `multi-session` (`+0.0250`), but
   down on `single-session-assistant` (`1.0000` -> `0.9750`) and
   `temporal-reasoning` (`0.9250` -> `0.9167`).
3. **Why remaining LongMemEval-S misses survive chunking:** 9 of the 12
   remaining misses (4 `multi-session`, 4 `temporal-reasoning`, 1
   `knowledge-update`) already achieve `recall_frac@5` between `0.50` and
   `0.80` (7 of those 9 already place an evidence session at rank 1). They miss
   strict `recall@5` because one of 2–5 scattered evidence sessions sits in
   ranks 6–10 — not because the entire note tail was truncated. The other 3
   misses are `single-session-preference` paraphrases (`195a1a1b` dropped from
   rank 5 to rank 6 under hybrid; `d6233ab6` at rank 7; `75832dbd` unretrieved).
4. **Why `as_of` stayed flat (`0.5000`):** `as_of` filters eligibility before
   ranking; changing embeddings or chunking cannot recover notes excluded by
   the `created_at <= as_of` filter or temporal reasoning over multi-session
   dates.
5. **Why `long-tail` and `para-gap` did not gain semantic hits:** the hard
   `SEMANTIC_MIN_SIMILARITY = 0.65` floor drops genuine rank-1 semantic hits
   just below `0.65` (`long-tail` tail chunk `0.6469`, `para-gap` `0.5965`).
6. **Latency overhead:** hybrid search adds query embedding + vector-scan time
   (`16.7 ms` lexical single-process vs `57.5 ms` single-vector and `87.8 ms`
   chunked, both hybrid runs mostly under 2-shard contention with `29/120`
   resumed uncontended; note `BruteForceIndex::nearest` also recomputes
   `text_sha` per scanned note). On ingest, batching a full
   >2,048-char note (512 tokens) together with its ~800-char chunks (~170
   tokens) pads all chunks to 512 tokens inside ONNX; a separate unmerged trial
   change that split the full-note call from the chunk batch (not included in
   this PR) cut 2-question pilot ingest wall time ~1.6x with identical
   rankings.

##### Candidate tuning levers (options only — no ranking changes in this PR)

Ranking weights, thresholds and `RRF_K` are intentionally untouched here so
tuning is a separate decision. The measurements above point to four concrete
options (none measured or recommended here):

| Option | Mechanism | Evidence from this run | Trade-off / risk |
|---|---|---|---|
| **A. Asymmetric `LEG_WEIGHTS` or lexical tie-break** | Give `lexical` slightly higher weight than `semantic` (currently `1.0` / `1.0`), or break exact RRF ties on lexical rank before alphabetical title. | Would address `exact-title` (`signing key`), where `exact-key` (`lex #1, sem #2`) tied `exact-near` (`lex #2, sem #1`) and lost purely on `"Checklist..." < "Harbor..."`. | Needs re-check on LongMemEval-S MRR@10 to confirm paraphrase wins are kept. |
| **B. Lexical exact/phrase guard for token queries** | For single-token / hyphenated identifier queries where FTS5 phrase matching finds exact hits, attenuate or gate semantic-only candidates. | Would address `exact-token` (`quartz-falcon-17`), where `exact-noise` (`quartz-falcon-71`, cosine `0.7910`) bypassed FTS5 phrase matching via the semantic leg. | Must avoid suppressing legitimate single-word paraphrases (`sedan` -> `automobile`), where FTS5 has zero hits. |
| **C. Recalibrate `SEMANTIC_MIN_SIMILARITY` or query-relative gating** | Lower the fixed `0.65` floor (e.g. `0.55–0.60`) or combine a lower floor with a margin/top-k cap when lexical hits are absent. | `para-gap` (`0.5965` vs `0.5239` runner-up) and `long-tail` tail chunk (`0.6469` vs `0.5954` `long-noise`) both rank #1 semantically yet are dropped by `0.65`. | Lowering `0.65` alone admits more `exact-noise` / `temporal-old` false positives unless paired with A/B. |
| **D. BGE query instruction prefix** | Prepend BGE's asymmetric query prefix (`"Represent this sentence for searching relevant passages: "`) for `BAAI/bge-*` queries in `search.rs`. | `BAAI/bge-small-en-v1.5` was trained asymmetrically with a query prefix; raw-query cosines compressed `para-gap` (`0.5965`) and `long-tail` (`0.6469`) under `0.65`. | Model-family-specific; requires re-measuring cosine separation across both fixture and LongMemEval-S before changing floors. |

##### Slice 2b: exact guard and lexical tie-break (`b9eaa29`, `--features embeddings`)

The decision on 2026-11-28 was tuning first, levers **B then A**, measured on
both corpora. This section records the fixture half; the LongMemEval-S
120-question stratified set (`longmemeval-strat120-seed2145.txt`, the same set
the table above measures) follows once it completes. The 470-question set is
not used here: on this 4-core desktop a hybrid pass costs roughly three minutes
per question, so a full 470 run would take about 22 hours and the 120-question
set already carries the comparison baselines.

**Changes.** In `crates/ua-memory/src/search.rs`:

- **B — exact guard.** For a one-token query whose FTS5 phrase match finds the
  token, candidates the lexical leg did not return are dropped. A single-token
  query is an exact lookup; a semantic near neighbour that shares the term but
  not the phrase must not displace the exact note. Queries with no lexical
  match keep the semantic leg as their only source, so paraphrase recall is
  unaffected. The retrieval block reports `exact_guard`.
- **A — lexical tie-break.** On an exact fused-score tie, order by lexical leg
  rank before the note title. `exact-title` (`signing key`) had tied
  `exact-key` (lex #1, sem #2) with `exact-near` (lex #2, sem #1) and lost to
  the alphabetical sort.

**Fixture result** (release build, `--features embeddings`, pinned
`BAAI/bge-small-en-v1.5`):

| Class | n | Lexical R@5 / MRR | Hybrid before R@5 / MRR | Hybrid after R@5 / MRR | Floor R@5 / MRR |
|---|---:|---:|---:|---:|---:|
| exact-term | 2 | 1.0000 / 1.0000 | 0.0000 / 0.7500 (FAIL) | **1.0000 / 1.0000** | 1.0000 / 1.0000 |
| paraphrase | 2 | 0.5000 / 0.5000 | 0.5000 / 0.5000 | 0.5000 / 0.5000 | 0.5000 / 0.5000 |
| temporal | 3 | 0.6667 / 0.6667 | 0.6667 / 0.6667 | 0.6667 / 0.6667 | 0.6667 / 0.6667 |
| contradiction | 2 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| long-document | 1 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 | 1.0000 / 1.0000 |
| **overall** | **10** | **0.8000 / 0.8000** | **0.6000 / 0.7500** | **0.8000 / 0.8000** | — |
| `stale_share` | — | 0.0000 (0/12) | 0.0000 (0/13) | 0.0000 (0/13) | — |
| `must_not_share` | — | 0.0000 | 0.0769 (1/13) | **0.0000** | — |

Hybrid now matches lexical on every class and clears the floor in both modes.
The regression test in `crates/ua-memory/tests/order.rs`
(`exact_guard_drops_semantic_only_neighbours_for_a_single_token`) pins the
guard's behaviour without needing the ONNX model, so the embeddings CI job
covers it.

**Risk stated.** The guard drops semantic-only candidates only when the query
is one token and FTS5 found the token. A single-word paraphrase whose token
does not occur in the target note still falls through to the semantic leg; the
LongMemEval-S 120-question hybrid run checks that the guard does not cost
paraphrase recall at scale.

##### Reproducing the `--features embeddings` run

`--embed` is opt-in and off by default so `cargo test -p ua-memory` and CI
stay lexical and never depend on local model files. When `--embed` is set,
`Config.home` points at `--models-home` (defaulting to `$UA_HOME` or
`~/.ua-rust`) for read-only model lookup (`local_embedder` never downloads or
writes there), while all benchmark SQLite databases remain isolated in the
temporary scratch directory. Each `--embed` report records
`retrieval.embed` (`model`, `revision`, `identity`, `no_chunks`,
`chunks_scored`) and fails fast if any query falls back from `hybrid`.

```sh
# 1. Fetch and verify the pinned local model into $UA_HOME/models (~/.ua-rust/models)
cargo run -p ua-cli -- memory models fetch
cargo run -p ua-cli -- memory models status --verify

# 2. Build memory-bench with local ONNX embeddings enabled
cargo build --release --features embeddings -p ua-memory --bin memory-bench

# 3. Fixture corpus (lexical, hybrid single-vector ablation, hybrid chunked)
./target/release/memory-bench --out fixture-lexical.json
./target/release/memory-bench --embed --no-chunks --out fixture-hybrid-single.json
./target/release/memory-bench --embed --out fixture-hybrid-chunked.json

# 4. LongMemEval-S 120-question stratified sample (seed 2145)
./target/release/memory-bench --longmemeval \
  --ids crates/ua-memory/bench/longmemeval-strat120-seed2145.txt \
  --out lme-strat120-lexical.json
./target/release/memory-bench --longmemeval --embed --no-chunks \
  --ids crates/ua-memory/bench/longmemeval-strat120-seed2145.txt \
  --out lme-strat120-hybrid-single.json
./target/release/memory-bench --longmemeval --embed \
  --ids crates/ua-memory/bench/longmemeval-strat120-seed2145.txt \
  --out lme-strat120-hybrid-chunked.json
```
