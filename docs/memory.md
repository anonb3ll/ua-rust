# Memory subsystem

Status: **design, not implemented.** This document designs the pieces the
memory family does not yet have. It is not a plan to rebuild what exists. It
depends on the organization model (`docs/organization.md`) for `org_id`,
teams and budgets.

The memory family is moving out of `ua-tools` into its own crate,
`crates/ua-memory`. File paths below name the module (`rank.rs`, `embed.rs`)
and hold in either location.

## Correction to the brief

An earlier task description claimed temporal validity, salience and hybrid
retrieval were missing. Verified against `e56fce8` and again at `28fdf58`, they
are present and implemented. This document is written against the code, not
that description.

## What already exists

The ranking layer is further along than the file names suggest. Do not rebuild
it.

| Capability | Where | State |
|---|---|---|
| Hybrid retrieval, reciprocal-rank fusion over lexical + semantic + recency legs | `rank.rs` (`RRF_K = 60`, `LEG_WEIGHTS`), `search.rs` (`competition_ranks`) | Present |
| BM25 with per-field weights (title 3.0, content 1.0, tags 2.0) | `rank.rs::BM25_WEIGHTS` | Present |
| Semantic leg with staleness detection (`content_sha` per vector) | `embed.rs`, `memory_embeddings` | Present, **off by default** (below) |
| Temporal validity and supersession | `memory.valid_from`, `valid_to`, `superseded_by` | Present |
| Salience, recency decay, reinforcement, voting | `salience`, `access_count`, `recalled_count`, `upvoted_count`, `RECENCY_HALF_LIFE_DAYS=15`, `DECAY_MONTHS=6`, `W_SALIENCE/W_FEEDBACK/W_VOTE` | Present |
| Contradiction attenuation and open-link surfacing | `contradicts`, `CONTRADICTION_BETA`, `MAX_COUNTED_CONTRADICTIONS`, `note.rs` | Present |
| Versioning, 50 versions per note, trigger-captured | `memory_versions` | Present |
| Maintenance pass: pruning candidates, staleness, low confidence | `maintenance.rs` (report-only) | Present |
| Shared eligibility filter (deletion, supersession, `as_of`, tags, host, expiry) | `note.rs::Filter` | Present |

Three things the first draft did not record:

- **Vector recall is effectively off.** `embed.rs::embedder_for` returns a
  `NoopEmbedder` unless the crate is built with the `embeddings` cargo feature,
  and that feature is off by default (`ua-tools/Cargo.toml`). A default build
  is lexical-only.
- **Long notes lose their tail.** One vector per note means text past the
  model's window (512 tokens for the default `BAAI/bge-small-en-v1.5`) is
  never embedded. The Python hub solved this with overlapping chunks
  (`memory_chunks.py`); `ua-rust` has no equivalent.
- **The predecessor had a graph leg.** The Python hub persists
  `memory_entities` and `memory_links` and fuses a one-hop graph leg
  (`memory_graph.py`). `ua-rust` exports those tables in the migration
  manifest (`export.rs::GRAPH_TABLES`) but does not create or rank them.

A note on the honest ceiling: this ranker is competitive. The claim that the
result is "as good as or better than a leading memory system" is currently
**unfalsifiable**, because nothing measures retrieval quality — see
[Evidence](#1-evidence).

## The gaps, in build order

### 1. Evidence

There is no recall-quality evaluation, so the product claim cannot be tested.
Unit tests prove that the code does what it says; they do not prove that the
retrieval is good. This lands first and gates everything after it.

Design:

- A checked-in fixture corpus (`ua-memory/bench/`): notes, labelled queries,
  and for each query the notes that must appear and those that must not.
- Query classes: exact-term, paraphrase, temporal (`as_of`), contradiction,
  long-document (an answer past the first 512 tokens), multi-hop graph,
  consolidation, and cross-tenant isolation.
- `recall@k` and mean reciprocal rank per class, from `ua memory bench` and
  from a CI test.
- **A floor, not a target.** `bench/floor.json` records the floor per class. A
  change that drops a class below its floor fails CI. Raising the floor is an
  explicit commit. Isolation is not a floor: any leaked note fails outright.
- **Deterministic in CI.** The paraphrase class depends on the embedding model,
  so the corpus ships with **checked-in vectors** produced by a pinned model
  and revision, recorded in `bench/model.json`. CI ranks against those vectors
  and needs no model download. A separate, non-gating job re-embeds with the
  live model and reports drift. The clock is injected, so recency is stable.
- Every later section adds its cases to the corpus in the same change, so each
  is measured from the day it lands.

### 2. Chunked embeddings and a default embedder

**Chunks.** Port `memory_chunks.py` exactly, so imported hubs behave the same:

| Constant | Value |
|---|---|
| Chunk | 400 tokens ≈ 1,600 characters (4 characters per token) |
| Overlap | 80 tokens ≈ 320 characters |
| Single-vector threshold | 512 tokens ≈ 2,048 characters; shorter notes keep one vector |
| Boundary snap | up to 80 characters, to whitespace |
| Maximum chunks per note | 16 |
| Backfill batch | 8 notes |

```sql
CREATE TABLE IF NOT EXISTS memory_chunks (
    note_id     TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    model       TEXT NOT NULL,
    dim         INTEGER NOT NULL,
    embedding   BLOB NOT NULL,
    content_sha TEXT NOT NULL,
    PRIMARY KEY (note_id, idx)
);
```

A note's semantic score is the maximum cosine over its chunks. The semantic leg
stays one leg; chunking changes what it scores, not how fusion works. Chunk
rows go stale by `content_sha` and `model` exactly as single vectors do, and the
maintenance pass backfills them.

**A default embedder that works with no setup.** Vector recall must not depend
on a compile flag the operator never sees.

```toml
[memory]
embedder = "auto"        # auto | local | ollama | openai_compat | off
# the model stays the existing top-level `embed_model` key
# ollama_url = "http://127.0.0.1:11434"
# openai_compat_url = "https://..."; key from UA_EMBED_API_KEY only
```

- `local`: the ONNX model through `fastembed`, loaded on first use into
  `~/.ua/models`. The `embeddings` feature becomes **default-on** for release
  builds; a `--no-default-features` build stays available for minimal
  environments.
- `ollama`: a local Ollama server's embedding endpoint.
- `openai_compat`: any OpenAI-compatible `/v1/embeddings` endpoint. The key
  comes only from the environment, never the config file.
- `auto` picks `local` when it is compiled in, else a loopback Ollama that
  answers with the configured model, else lexical-only. **`auto` never selects
  a remote endpoint**, because that sends note text off the machine; that
  takes an explicit `openai_compat`.
- When the result is lexical-only, `system_doctor` reports the memory row
  `DEGRADED` with the reason, rather than failing silently.
- Vectors record their model. Changing model marks every vector stale and the
  backfill re-embeds; mixed-model scoring never happens.

### 3. Scoped recall

There is no visibility on memory, so recall cannot be constrained by tenant or
team. This depends on the organization spine and is not faked before it lands.

```sql
ALTER TABLE memory ADD COLUMN org_id     TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory ADD COLUMN visibility TEXT NOT NULL DEFAULT 'org'
    CHECK (visibility IN ('private','team','org'));
ALTER TABLE memory ADD COLUMN team_id    TEXT;   -- required when visibility = 'team'
```

- `private` is visible to its author; `team` to the human and agent members of
  `team_id` (through `team_members`); `org` to every member of the
  organization.
- **Enforcement is in the SQL.** The visibility predicate is part of the shared
  eligibility filter (`note.rs::Filter`), in the same `WHERE` as the FTS match,
  the vector candidate set, the chunk scan, the recency leg and every graph hop.
  It is never a post-filter: a post-filter leaks through ranking side channels,
  because if the count and order change, an unauthorized caller learns that a
  note exists. A test asserts that each leg's query is built through the
  filter.
- Counts, totals and per-leg explanations are computed after eligibility, so
  they describe only visible notes.

**Default visibility is a per-organization setting**, `memory_default_visibility`
on `orgs`:

| Organization | Default for a note saved without `visibility` |
|---|---|
| Created for several people (`ua init` multi-user templates, `org_create`) | `private` |
| A solo template (`solo-builder`) | `org`, so one builder's agents share context |
| The `'default'` organization of an upgraded hub | `org` (parity, below) |

**Backfill.** Every existing note becomes `visibility = 'org'` in `'default'`.
That keeps today's behaviour, where every agent on the hub can recall every
note, so the existing suite passes untouched. Moving an upgraded hub to
`private` is an explicit admin setting change, recorded on the ledger, never a
side effect of the migration.

**Session grants.** A narrowed session credential (an ACP or node session bound
to one task) currently reaches `memory_*` with no narrowing. Under scoped
recall it reads only notes visible to its owner **and** linked to its task (by
evidence ref or entity); its writes are stamped with the credential id as well
as the owner label; and `overwrite` and `supersedes` are refused. A test fails
when a tool on the session allowlist has no explicit narrowing rule.

### 4. Consolidation and the contradiction workbench

Nothing turns episodes into durable notes. The store grows monotonically, each
new note dilutes the index, and recall quality falls as volume rises even
though every individual note is fine. (The Python `consolidate.py` only
proposed supersession of near-duplicates; it did not write summaries.)

It comes after scoped recall, so that a summary can never merge notes from
different scopes.

**Who writes summaries.** The hub calls no model. The scheduled pass is
deterministic: it groups unconsolidated notes and creates **consolidation
jobs**. A configured agent seat (`memory.consolidator`, an ordinary agent
identity in the organization, with a team-spec budget) claims a job, writes the
summary, and commits it with `memory_consolidate_commit`. Cost and rate are
therefore the seat's budget plus a per-pass job cap (`memory.consolidation_max_jobs`),
and both are visible on the ledger.

**Grouping never crosses scope.** A group is formed only from notes with the
same `org_id`, `visibility` and `team_id`, and for `private` the same author.
The summary takes exactly that scope. So a summary is never visible to anyone
who could not see every one of its sources.

**State is recorded, so the pass is idempotent.**

```sql
CREATE TABLE IF NOT EXISTS memory_consolidations (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    scope_key        TEXT NOT NULL,      -- visibility, team_id, author for private
    source_set_sha   TEXT NOT NULL,      -- hash of sorted (note_id, revision)
    status           TEXT NOT NULL CHECK (status IN ('pending','written','invalidated')),
    summary_note_id  TEXT REFERENCES memory(id),
    claimed_by       TEXT,
    created_at       TEXT NOT NULL,
    resolved_at      TEXT,
    UNIQUE (org_id, source_set_sha)
);
CREATE TABLE IF NOT EXISTS memory_consolidation_sources (
    consolidation_id TEXT NOT NULL REFERENCES memory_consolidations(id),
    note_id          TEXT NOT NULL,
    revision         TEXT NOT NULL,
    PRIMARY KEY (consolidation_id, note_id)
);
```

A source set already consolidated is skipped; a re-run after a failure finds the
`pending` row and produces no duplicate summary. A commit is refused if any
source revision changed since the job was cut.

**Summaries are lower-trust than their sources.**

- `epistemic = 'inferred'`, `evidence` lists every source id, and each source
  gains a `derives` link to the summary (provenance both ways).
- Sources are handed to the consolidator marked untrusted, like any recalled
  note, because a note can carry instructions meant to steer the summary.
- The summary's ranking prior is capped at the lowest prior among its sources,
  it cannot carry `broadcast` or a salience above its sources', and for a query
  that matches a source specifically, the summary does not outrank it.

**Supersession invalidates.** When a source is superseded, gets a `valid_to`, or
is deleted, its consolidation becomes `invalidated`: the summary gets
`valid_to = now` (it leaves default search, stays readable), the summary's
asserted graph edges are retired, and the remaining sources become eligible for
a new group. A summary never keeps a corrected fact alive.

**Contradiction workbench.** Open `contradicts` links already lower a note's
confidence. They become reviewable: `memory_conflicts` lists open pairs (scoped
like recall), and `memory_conflict_resolve` records one of: supersede A,
supersede B, both valid over different `valid_from`/`valid_to` ranges, or
dismiss. Resolving needs a human, or the author of both notes. The review inbox
renders each pair side by side. The consolidator may *propose* `contradicts`
links in a commit; they are links, never deletions.

### 5. Entity and wikilink graph leg

`ua-tools/src/families/graph.rs` is the planning canvas — an Excalidraw scene
store — not an edge store. The entity graph lives with memory, and the canvas
can render from it; there is still one set of edges.

Port the Python hub's tables, so imported graphs keep working, and add
attribution:

```sql
CREATE TABLE IF NOT EXISTS memory_entities (
    org_id  TEXT NOT NULL,
    note_id TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,   -- task, branch, repo, service, agent, wikilink
    value   TEXT NOT NULL,
    PRIMARY KEY (note_id, kind, value)
);
CREATE TABLE IF NOT EXISTS memory_links (
    org_id      TEXT NOT NULL,
    src_id      TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    dst_id      TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    rel         TEXT NOT NULL,   -- supersedes, contradicts, evidence, extends, derives
    asserted_by TEXT NOT NULL,   -- the note that asserted the edge
    actor       TEXT,
    created_at  TEXT NOT NULL,
    retired_at  TEXT,
    PRIMARY KEY (src_id, dst_id, rel)
);
```

- Entities are extracted deterministically at save: task ids, branches, repos,
  services, agent labels, and `[[wikilinks]]` in the content, so a note that
  names a vault page joins the same graph as the vault.
- Every edge names the note that asserted it. When that note is superseded or
  invalidated, its edges get `retired_at` and stop being walked.
- Triggers refuse an entity or link whose `org_id` differs from its notes'.
- The leg seeds from the best lexical and semantic hits and walks one hop:
  live links in either direction, and notes sharing an entity. An entity on
  more than a document-frequency cap of notes is a hub and is not walked; fanout
  per seed and the leg's total are capped.
- **Every hop target passes the same eligibility SQL**, visibility included, so
  traversal cannot reveal that a hidden note exists. The isolation class in the
  corpus covers the graph leg explicitly.
- The leg joins fusion as one more `LEG_WEIGHTS` entry at a lower weight than
  the content legs, and only adds notes: a note a content leg already matched
  gets no graph rank.

### 6. Context pack and post-run distillation

Agents across harnesses start cold. Memory should arrive without each one
remembering to search.

**`context_pack`** — a tool and an MCP resource. Input: the caller (from the
credential), optional `task_id`, optional query, and a token budget. Output, in
order until the budget is spent:

1. notes linked to the task (entity match on the task id, branch, repo);
2. the organization's and team's high-salience decisions;
3. the caller's own recent episodes;
4. open contradictions touching anything already included.

Every item goes through the same eligibility filter as search, carries its id,
why it was included, and the untrusted marker. The token estimate uses the
chunker's 4 characters per token. The same state and `as_of` produce the same
pack.

Delivery is per harness through harness-config bundles: a session-start hook
where the harness has one (Claude Code, Codex, Cursor, Pi, OpenCode, Hermes,
Gemini), otherwise a rules line telling the agent to call `context_pack` first.

**Distillation.** At session end, the bundle's stop hook asks the agent to call
`memory_distill` with structured fields — outcome, decisions, learnings, open
questions — for its session or run. The hub validates size and fields and
writes one episode note: `evidence` names the session or run, visibility is the
organization's default, and a repeat call for the same session updates the same
note rather than adding one. Episodes are what consolidation later groups.

## Where the code lives

- `crates/ua-memory`: everything in this document. `ua-tools` keeps only the
  registration.
- `ua-store` gains a `MemoryRepo` trait next to `OrgRepo`; `ua-memory` reaches
  the database only through it, and the trait exposes no `rusqlite` types. The
  bundled SQLite store stays the default; the trait is where another backend
  would plug in.

## Non-goals

- **Not a rewrite of the ranker.** Reciprocal-rank fusion, decay and salience
  priors stay as they are. New capability arrives as additional legs and passes.
- **Not a vector-database migration.** SQLite plus the embedding and chunk
  tables is adequate at the scale this hub runs. Revisit only with measurements.
- **Not cross-organization memory sharing.** Memory is tenant-scoped. A shared
  knowledge base is a separate design.
- **No model calls from the hub.** Summaries and episodes are written by agent
  seats, under their budgets, and validated by the hub.

## Acceptance

1. **The eval gate runs first** — `ua memory bench` and the CI test report
   `recall@k` and MRR per class from checked-in vectors, fail below the
   recorded floor, and fail on any isolation leak.
2. **Existing behaviour is unchanged** — the current memory test suite passes
   untouched after the backfill.
3. **Long documents** — a fact only in the last third of a 6,000-character note
   is recalled through its chunks; a note above 16 chunks embeds its first 16.
4. **Embedder default** — a default release build has vector recall with no
   configuration; with no embedder available, `system_doctor` reports
   `DEGRADED`; `auto` never selects a non-loopback endpoint.
5. **Scoping holds on every leg** — a caller in organization B, or outside a
   `team` note's team, or not the author of a `private` note, receives none of
   them from the lexical, semantic, chunk, recency or graph legs, and the result
   count and explanations do not reveal that they exist.
6. **Defaults** — a note saved without `visibility` takes the organization's
   default; a new multi-user organization defaults to `private`.
7. **Session grants** — a task-bound session reads only its task's notes, cannot
   overwrite or supersede, and its writes carry the credential id.
8. **Consolidation is idempotent and scoped** — running the pass twice produces
   no duplicate summary and no orphaned edges; a summary of private notes is
   visible to no one who could not see every source; a commit after a source
   changed is refused.
9. **Provenance is complete** — every summary names its sources and every source
   has a `derives` link to it.
10. **Supersession invalidates** — superseding a source invalidates its summary
    and retires the summary's edges.
11. **Graph attribution** — superseding an asserting note retires its edges; a
    retired edge is never walked.
12. **Context pack** — respects the token budget, includes only eligible notes,
    and is identical for the same state and `as_of`.
13. **Distillation** — two calls for one session leave one episode note.
