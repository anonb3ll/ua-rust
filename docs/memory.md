# Memory subsystem

Status: **design, not implemented.** This document designs the pieces the
memory family does not yet have. It is not a plan to rebuild what exists. It
depends on the organization model (`docs/organization.md`, PR #39) for
`org_id`, users, teams, roles and budgets.

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
| Hybrid retrieval: reciprocal-rank fusion over lexical and semantic legs, with recency as a third rank over their candidates | `rank.rs` (`RRF_K = 60`, `LEG_WEIGHTS`, `competition_ranks`), `search.rs` | Present |
| BM25 with per-field weights (title 3.0, content 1.0, tags 2.0) | `rank.rs::BM25_WEIGHTS` | Present |
| Semantic leg: one vector per note, scanned by `BruteForceIndex` | `embed.rs`, `memory_embeddings` | Present, **off by default** (below) |
| Temporal validity and supersession | `memory.valid_from`, `valid_to`, `superseded_by` | Present |
| Salience prior, recency decay, feedback and votes | `salience`, `upvoted_count`, `RECENCY_HALF_LIFE_DAYS=15`, `DECAY_MONTHS=6`, `W_SALIENCE/W_FEEDBACK/W_VOTE` | Present |
| Access and recall counters | `access_count`, `recalled_count` | Present, **reported, never ranked** |
| Contradiction attenuation and open-link surfacing | `contradicts`, `CONTRADICTION_BETA`, `MAX_COUNTED_CONTRADICTIONS`, `note.rs` | Present |
| Versioning, 50 versions per note, trigger-captured | `memory_versions` | Present |
| Maintenance pass: pruning candidates, low confidence | `maintenance.rs` (report-only) | Present |
| Shared eligibility filter (deletion, supersession, `as_of`, tags, host, expiry) | `note.rs::Filter` | Present, used by search only |

Facts the first draft did not record:

- **Vector recall is effectively off.** `embed.rs::embedder_for` returns a
  `NoopEmbedder` unless the crate is built with the `embeddings` cargo feature.
  That feature is off by default (`ua-tools/Cargo.toml`), `ua-cli` does not pass
  it through, and no CI job builds it, so the `fastembed` module has never been
  compiled in CI. A default build is lexical-only.
- **Vector staleness is not checked.** `store_vector` writes a `content_sha`,
  but nothing reads it: `BruteForceIndex::nearest` filters on `model` and `dim`
  only. If a re-embed after an edit fails, the old vector keeps scoring. There
  is no embedding backfill either; `maintenance.rs` only reports. Both are new
  work below.
- **Recency ranks only what the content legs found.** `search.rs` drops any
  note that neither the lexical nor the semantic leg hit before fusion. A
  graph-only hit would be dropped there today; §5 changes that line.
- **Long notes lose their tail.** One vector per note means text past the
  model's window (512 tokens for the default `BAAI/bge-small-en-v1.5`) is
  never embedded. The Python hub solved this with overlapping chunks
  (`memory_chunks.py`); `ua-rust` has no equivalent.
- **The predecessor had a graph leg.** The Python hub persists
  `memory_entities` and `memory_links` and fuses a one-hop graph leg
  (`memory_graph.py`). `ua-rust` exports those tables in the migration
  manifest (`export.rs::GRAPH_TABLES`) but does not create, import or rank
  them.
- **The predecessor's consolidation called a model from the hub.**
  `consolidate.py` clustered near-duplicates by cosine, then adjudicated pairs
  through `llm_client` (duplicate / contradiction / unrelated) and could
  auto-apply supersession above a 0.98 threshold without review
  (`UA_CONSOLIDATE_AUTO_APPLY`); `sleep_pass.py` classified nightly. It also
  taught one lesson this design keeps: untrusted note titles rendered into a
  parseable proposal file became `apply` commands (task #2012).
- **Memory scope is not one code path.** About a dozen tools read the `memory`
  table directly, not through `Filter`. See the inventory in §3.

A note on the honest ceiling: this ranker is competitive. The claim that the
result is "as good as or better than a leading memory system" is currently
**unfalsifiable**, because nothing measures retrieval quality — see
[Evidence](#1-evidence).

## The gaps, in build order

### 1. Evidence

There is no recall-quality evaluation, so the product claim cannot be tested.
Unit tests prove that the code does what it says; they do not prove that the
retrieval is good. This lands first and gates everything after it.

**Corpus.** A checked-in fixture corpus (`ua-memory/bench/`): notes, labelled
queries, and for each query the notes that must appear and those that must
not. Query classes: exact-term, paraphrase, temporal (`as_of`), contradiction,
long-document (an answer past the first 512 tokens), multi-hop graph,
consolidation, and isolation (cross-organization, and within one organization
across `private` and `team` notes).

**Metrics.** `recall@k` and mean reciprocal rank per class, from
`ua memory bench` and from a CI test. `bench/floor.json` records the floor per
class; a change that drops a class below its floor fails CI, and raising the
floor is an explicit commit.

**Isolation is not a floor, and presence is not enough.** recall@k cannot see
the side channels this design rules out (counts, order, explanations,
contradiction counts, graph document frequency). So isolation is a
**differential test**: each query runs once on the corpus and once with hidden
notes inserted (another organization's, another author's `private`, another
team's `team`), and the visible output — ids, order, counts, explanations,
confidence fields — must be identical. Access counters are excluded. Any
difference fails outright.

**Determinism.** The gate must not drift or pass by accident:

- Vectors are checked in for every corpus note, every chunk and every query,
  keyed by the SHA-256 of the exact embedded text, together with the pinned
  model id and revision (`bench/model.json`). A missing vector is a hard
  failure that prints the regeneration command (`ua memory bench --regen`);
  any change to the chunker or the embedded-text format therefore fails until
  vectors are regenerated in the same commit.
- The bench registers a lookup embedder with `register_embedder`, so CI needs
  no model and no network. It asserts the search ran in hybrid mode for the
  paraphrase class, so a lexical-only run cannot pass it silently.
- The clock is injected. Today `ua_core::time::now()` is called directly in
  `search.rs`, `Filter`, `open_contradictions` and `similar_notes`; threading
  a clock through those is named work in this step, not an assumption.
- Search writes access counters as a side effect, so each query runs against a
  fresh copy of the fixture database.
- The consolidation class uses checked-in summaries, since model-written ones
  are not deterministic.
- A separate, non-gating job re-embeds with the live model and reports drift.

Every later section adds its cases to the corpus in the same change, so each is
measured from the day it lands.

### 2. Chunked embeddings and a default embedder

**Chunks.** Port the constants of `memory_chunks.py` so imported hubs embed the
same text:

| Constant | Value |
|---|---|
| Chunk | 400 tokens ≈ 1,600 characters (4 characters per token) |
| Overlap | 80 tokens ≈ 320 characters |
| Single-vector threshold | 512 tokens ≈ 2,048 characters |
| Boundary snap | up to 80 characters, to whitespace |
| Maximum chunks per note | 16 |
| Backfill batch | 8 notes |

"Characters" are Unicode code points, as Python's `len` counts them, never
bytes.

Scoring follows Python too: **every note keeps its single vector**, a note
longer than the threshold also gets chunk vectors, and its semantic score is
the maximum of the single-vector cosine and the best chunk cosine. The semantic
leg stays one leg.

```sql
CREATE TABLE IF NOT EXISTS memory_chunks (
    org_id      TEXT NOT NULL,
    note_id     TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    idx         INTEGER NOT NULL,
    model       TEXT NOT NULL,   -- vector identity, below
    dim         INTEGER NOT NULL,
    embedding   BLOB NOT NULL,
    content_sha TEXT NOT NULL,
    PRIMARY KEY (note_id, idx)
);
CREATE TRIGGER IF NOT EXISTS memory_chunks_org_fence
BEFORE INSERT ON memory_chunks
WHEN NEW.org_id IS NOT (SELECT org_id FROM memory WHERE id = NEW.note_id)
BEGIN SELECT RAISE(ABORT, 'memory_chunks org_id differs from its note'); END;
```

**Staleness and backfill (new work).** The vector index scores a single vector
or chunk only when its `content_sha` equals the hash of the note's current
embedded text and its `model` equals the active vector identity. The
maintenance pass backfills missing or stale vectors and chunks in batches of
8. Neither exists today.

**Vector identity.** `model` stores `backend:model@revision`, for example
`local:BAAI/bge-small-en-v1.5@<revision>` or `ollama:nomic-embed-text@<digest>`.
Two backends with the same model name therefore never compare as equal.
Changing identity marks every vector stale and the backfill re-embeds;
mixed-identity scoring never happens.

**A default embedder.**

```toml
[memory]
embedder = "auto"        # auto | local | ollama | openai_compat | off
# the local model stays the existing top-level `embed_model` key
# ollama_model = "nomic-embed-text"
# ollama_url = "http://127.0.0.1:11434"
# openai_compat_url = "https://..."; key from UA_EMBED_API_KEY only
# allow_remote_embedder = false
```

- `local`: the ONNX model through `fastembed`, from `~/.ua-rust/models`
  (`cfg.home.join("models")`). The revision is pinned.
- `ollama`: an Ollama server's embedding endpoint, with its own
  `ollama_model` key, since Ollama names do not match Hugging Face ids.
- `openai_compat`: any OpenAI-compatible `/v1/embeddings` endpoint. The key
  comes only from the environment, never the config file.
- `auto` picks `local` when it is compiled in and its model is present, else a
  loopback Ollama that serves `ollama_model`, else lexical-only.

**Note text stays on the machine unless the operator says otherwise.** For any
backend, the endpoint's **resolved** addresses are checked; if any is not
loopback, the embedder refuses unless `allow_remote_embedder = true`. This
covers an explicit `ollama` with a remote URL as well as `openai_compat`, and a
hostname such as `localhost` that resolves elsewhere.

**No downloads inside a call.** Save, search and `system_doctor` never fetch a
model. `ua memory models fetch` downloads and verifies the pinned model (also
run by `ua init`), so an air-gapped host can be prepared offline. Until a model
is present, the embedder reports unavailable, search is lexical-only, and
`system_doctor` reports the memory row `DEGRADED` with the reason.

**Build.** The `embeddings` feature stays **off** in the Cargo default, so dev,
test and CI builds stay hermetic: `fastembed` is configured with
`ort-download-binaries-rustls-tls`, which downloads a prebuilt ONNX Runtime at
build time, fails on targets with no prebuilt runtime (musl, some aarch64), and
pulls a pre-release `ort`. Instead:

- `ua-cli` gains an `embeddings` feature that passes through to `ua-memory`;
- release artifacts are built with it, preferring `ort`'s `load-dynamic`
  linking where the platform allows, so the runtime is a verified file beside
  the binary rather than a build-time download;
- a CI job builds and tests the feature, so the module stops being uncompiled;
- the release enforces a binary-size budget, measured before it is set;
- `THIRD_PARTY_NOTICES.md` gains ONNX Runtime and the model's licence.

This is a real tension with "works with no setup": a source build is still
lexical-only until built with the feature, and a release build still needs
`ua memory models fetch` (or `ua init`) once. The promise holds for the
packaged install path, not for `cargo build`.

### 3. Scoped recall

There is no visibility on memory, so recall cannot be constrained by tenant or
team. This depends on the organization spine and is not faked before it lands.

**Columns.** `organization.v1` adds `org_id` to `memory`, `memory_versions` and
`memory_embeddings`; this part does not. It adds:

```sql
ALTER TABLE memory ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'
    CHECK (visibility IN ('private','team','org'));
ALTER TABLE memory ADD COLUMN team_id TEXT;
ALTER TABLE memory ADD COLUMN owner_type TEXT;   -- 'human' | 'agent'
ALTER TABLE memory ADD COLUMN owner TEXT;        -- users.id or agent label
ALTER TABLE memory ADD COLUMN credential_id TEXT; -- set for session-grant writes

-- parity backfill, in the same migration
UPDATE memory SET visibility = 'org';
UPDATE memory SET owner_type = 'agent', owner = author WHERE author IS NOT NULL;

CREATE TRIGGER IF NOT EXISTS memory_team_scope_insert
BEFORE INSERT ON memory
WHEN (NEW.visibility = 'team') != (NEW.team_id IS NOT NULL)
  OR (NEW.team_id IS NOT NULL AND NEW.org_id IS NOT
      (SELECT org_id FROM teams WHERE id = NEW.team_id))
BEGIN SELECT RAISE(ABORT, 'team_id must be set exactly for team visibility, in the same org'); END;
CREATE TRIGGER IF NOT EXISTS memory_team_scope_update
BEFORE UPDATE OF visibility, team_id, org_id ON memory
WHEN (NEW.visibility = 'team') != (NEW.team_id IS NOT NULL)
  OR (NEW.team_id IS NOT NULL AND NEW.org_id IS NOT
      (SELECT org_id FROM teams WHERE id = NEW.team_id))
BEGIN SELECT RAISE(ABORT, 'team_id must be set exactly for team visibility, in the same org'); END;
```

The column default is the **narrowest** tier, so an insert that forgets
`visibility` fails closed. The writer always binds `visibility` explicitly from
the organization's setting; the organization doc's insert-walking test is
extended so an `INSERT INTO memory` that omits `visibility` or `org_id` fails.

`owner` is who the note belongs to; `author` stays the writer stamped by
`write_author`. They differ for consolidation summaries and session-grant
writes. Backfilled human-authored notes are re-owned to their `users` row when
the organization migration creates it.

**Who sees what.** Comparisons are on `(principal_type, principal)`, with humans
keyed by `users.id`:

- `private`: the owner only;
- `team`: the human and agent members of `team_id` (`team_members`);
- `org`: every member of the organization.

`private` and `team` need a verified identity to read or write. An anonymous
caller, whose `author` is only claimed, sees and writes `org` notes only.

**Default visibility** is `orgs.memory_default_visibility` (defined by the
organization doc, column default `'private'`):

| Organization | Default for a note saved without `visibility` |
|---|---|
| `'default'` on an upgraded or fresh hub | `org`, set by the migration, so existing behaviour holds |
| Any organization created afterwards | `private` |
| Solo templates (Phase 5 `ua init`, later) | may set `org`, so one builder's agents share context |

Moving `'default'` to `private` is an explicit admin setting change, recorded on
the ledger, never a side effect.

**Changing a note's visibility.** The owner or an `org_admin` may widen or
narrow it. Narrowing invalidates every consolidation the note is a source of
(§4) and retires the topical graph edges it asserted (§5), so its content does
not survive in a wider summary or a traversal. Widening into `team` requires the
owner to be a member of that team.

**Enforcement is in the SQL, on every path.** `Filter` gains a mandatory scope
argument `(org_id, principal_type, principal, team_ids)`, and every read of
memory goes through `MemoryRepo` with it. A test walks the SQL statement strings
of the workspace and fails on any `FROM memory`, `JOIN memory` or
`FROM memory_*` outside `ua-memory`. Inventory of the paths that read the table
today, and the rule for each:

| Path | Today | Rule |
|---|---|---|
| `memory_search` | `Filter` | Scope in the same `WHERE` as the FTS match, the vector candidate set, the chunk scan and every graph hop |
| `memory_get`, `note_links`, versions | by id, unscoped | Scoped; linked ids, `supersedes` and `contradicts` lists show only visible notes |
| `memory_save` update / append / overwrite, `linked_note` for `supersedes`/`contradicts` | by id | Scoped; a hidden target is `not_found` |
| `memory_save` `similar_notes` / `check_only` | unscoped similarity | Only visible notes are compared or returned |
| `memory_delete`, `memory_restore`, `memory_feedback` | by id | Scoped |
| `memory_prune_candidates`, `recall_maintenance` (`live_notes`) | unfiltered | Scoped to the caller |
| `memory_promote` | copies any note to the shared vault | Only `org`-visible notes; `private` and `team` are refused |
| `session_packet` related memory | unscoped FTS | Replaced by `context_pack` (§6) |
| `propose_session_learnings` dedupe | unscoped existence check | Scoped |
| `platform_object_get` (`memory_note`) | by id | Scoped |
| vault ingest memory lookups | unscoped | Scoped to the ingesting caller |
| export manifest | every note | Operator-only, and records the scope columns |
| observability and evidence counts | global counts | Scoped counts, or hub-operator only |

**One not_found.** An invisible note and a missing note produce the same error,
code and message, so an id is no oracle.

**Counts and confidence are scoped.** Totals and per-leg explanations are
computed after eligibility. `note::open_contradictions` counts only disputing
notes the caller can see, inside the scoped query, so a hidden contradiction
neither changes a visible note's effective confidence, prior or rank nor
appears in `confidence_posterior`.

**Session grants.** A narrowed session credential (an ACP or node session bound
to one task) currently reaches `memory_*` with no narrowing. Under scoped
recall it reads only notes visible to its owner **and** tied to its task by an
evidence ref (`task:<id>`) — not by entity match, since entities are written by
any note author. Its writes are stamped with `credential_id`, and `overwrite`
and `supersedes` are refused. A test fails when a tool on the session allowlist
has no explicit narrowing rule.

### 4. Consolidation and the contradiction workbench

Nothing turns episodes into durable notes. The store grows monotonically, each
new note dilutes the index, and recall quality falls as volume rises even
though every individual note is fine.

It comes after scoped recall, so that a summary can never merge notes from
different scopes.

**Who writes summaries.** The hub calls no model. The scheduled pass is
deterministic: it groups unconsolidated notes and creates **consolidation
jobs**. An agent seat claims a job, writes the summary, and commits it with
`memory_consolidate_commit`. Cost and rate are that seat's team-spec budget plus
a per-pass job cap (`memory.consolidation_max_jobs`), both visible on the
ledger. Which seat may take a job depends on scope, so no seat sees a note it
could not already read:

| Group scope | Eligible consolidator |
|---|---|
| `org` | the organization's configured `memory.consolidator` seat |
| `team` | a seat that is a member of that team |
| `private` | only a seat acting for the owner (the owner's own agent, or the owning human's designated agent); never a shared seat |

A summary's `owner` is the sources' owner (for `org` and `team` groups, the
organization or team scope, with the consolidator as `author`), so a private
summary stays visible to exactly the owner.

**Grouping never crosses scope and stays small.** A group has one `org_id`,
`visibility`, `team_id` and, for `private`, one owner, and at most 20 sources —
the existing `MAX_EVIDENCE_REFS`, so the summary's evidence can name every
source. A note is a source of at most one live consolidation.

**State is recorded, so the pass is idempotent.**

```sql
CREATE TABLE IF NOT EXISTS memory_consolidations (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    scope_key       TEXT NOT NULL,      -- visibility, team_id, owner for private
    source_set_sha  TEXT NOT NULL,      -- hash of sorted (note_id, revision)
    status          TEXT NOT NULL CHECK (status IN ('pending','written','invalidated')),
    summary_note_id TEXT REFERENCES memory(id),
    claimed_by      TEXT,
    claimed_until   TEXT,               -- lease; an expired claim can be retaken
    created_at      TEXT NOT NULL,
    resolved_at     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS memory_consolidations_live_set
    ON memory_consolidations (org_id, source_set_sha)
    WHERE status != 'invalidated';
CREATE TABLE IF NOT EXISTS memory_consolidation_sources (
    org_id           TEXT NOT NULL,
    consolidation_id TEXT NOT NULL REFERENCES memory_consolidations(id),
    note_id          TEXT NOT NULL,
    revision         TEXT NOT NULL,
    PRIMARY KEY (consolidation_id, note_id)
);
```

- A source set already consolidated is skipped; a re-run after a failure finds
  the `pending` row. An invalidated row does not block the same set later.
- A claim takes a lease (`claimed_until`); an abandoned job becomes claimable
  again when it expires.
- **Commit is one compare-and-set**, in one write transaction: the job is
  `pending` and claimed by the caller with a live lease, every source's current
  revision equals the recorded one, then the summary, its links and
  `status = 'written'` are written together. Anything else is refused.
- A retried commit of a job already `written` by the same caller returns the
  same summary id.
- `Note::revision` gains `org_id`, `visibility`, `team_id` and `owner`, so a
  scope change between cut and commit is a revision change.

**Summaries are lower-trust than their sources.**

- `epistemic = 'inferred'`, `evidence` names every source, and each source gains
  a `derives` link to the summary (provenance both ways).
- Sources are handed to the consolidator as untrusted data, like any recalled
  note, because a note can carry instructions meant to steer the summary. The
  summary's trust marker lists the **source owners**, not only the
  consolidator.
- The summary's prior is capped at the lowest prior among its sources, and its
  salience at the lowest source salience; it cannot carry `broadcast`.
- **Ranking rule:** when any of a summary's sources is in a result set, the
  summary is placed directly below the best-ranked of those sources. The
  source set is read from `memory_consolidation_sources` in the same scoped
  query.

**Any change invalidates.** When any source's revision changes — an edit, a
scope change, supersession, `valid_to`, deletion — its consolidation becomes
`invalidated`: the summary gets `expires_at = now`, which the default filter
already honours (it ignores `valid_to` without `as_of`, and changing that would
change existing behaviour), so the summary leaves default search and listing but
stays readable by id; its topical edges are retired; the remaining sources
become eligible for a new group. A summary never keeps a corrected or narrowed
fact alive.

**Contradiction workbench.** Open `contradicts` links already lower a note's
confidence. They become reviewable:

- `memory_conflicts` lists only pairs where the caller can see **both** notes.
- `memory_conflict_resolve` records one of: supersede A, supersede B, both
  valid over different ranges, or dismiss. "Both valid" sets `valid_to` on the
  earlier note and `valid_from` on the later one through the same call; that
  call is the only API that sets `valid_to` on an unsuperseded note. Every
  resolution closes the link.
- The resolver is the owner of both notes, or a human who can see both and
  holds `team_lead` or above in the organization (organization doc roles).
- `contradicts` links **proposed** by a consolidator are stored as proposals
  and do not attenuate confidence until a resolver accepts them.
- The review inbox renders both notes as escaped text; titles and content never
  become markup, commands or parseable fields.

### 5. Entity and wikilink graph leg

`ua-tools/src/families/graph.rs` is the planning canvas — an Excalidraw scene
store — not an edge store. The entity graph lives with memory, and the canvas
can render from it.

Port the Python tables so imported graphs keep working, with attribution and
the Python checks:

```sql
CREATE TABLE IF NOT EXISTS memory_entities (
    org_id  TEXT NOT NULL,
    note_id TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,   -- task, branch, project, service, agent, wikilink
    value   TEXT NOT NULL,
    PRIMARY KEY (note_id, kind, value)
);
CREATE TABLE IF NOT EXISTS memory_links (
    org_id      TEXT NOT NULL,
    src_id      TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    dst_id      TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    rel         TEXT NOT NULL
                CHECK (rel IN ('supersedes','contradicts','evidence','extends','derives')),
    asserted_by TEXT NOT NULL,   -- the note that asserted the edge
    proposed    INTEGER NOT NULL DEFAULT 0,  -- 1: proposed contradiction, not yet accepted
    actor       TEXT,
    created_at  TEXT NOT NULL,
    retired_at  TEXT,
    CHECK (src_id != dst_id),
    PRIMARY KEY (src_id, dst_id, rel, asserted_by)
);
CREATE TRIGGER IF NOT EXISTS memory_links_org_fence
BEFORE INSERT ON memory_links
WHEN NEW.org_id IS NOT (SELECT org_id FROM memory WHERE id = NEW.src_id)
  OR NEW.org_id IS NOT (SELECT org_id FROM memory WHERE id = NEW.dst_id)
BEGIN SELECT RAISE(ABORT, 'memory_links org_id differs from its notes'); END;
CREATE TRIGGER IF NOT EXISTS memory_entities_org_fence
BEFORE INSERT ON memory_entities
WHEN NEW.org_id IS NOT (SELECT org_id FROM memory WHERE id = NEW.note_id)
BEGIN SELECT RAISE(ABORT, 'memory_entities org_id differs from its note'); END;
```

Entity kinds keep Python's `project` (not `repo`), so imported entities match.

**One authority per relation.** `memory.superseded_by` and `memory.contradicts`
stay authoritative for `supersedes` and `contradicts`, and triggers mirror them
into `memory_links`; `evidence` mirrors `memory:<id>` evidence refs; `extends`
and `derives` live only in `memory_links`. No relation is written in two places
by application code.

**Retirement is topical only.** When an asserting note is superseded,
invalidated or narrowed, its `extends` and `contradicts` edges and its entity
rows are retired. Lineage edges — `supersedes`, `derives`, `evidence` — are never
retired, so history and provenance stay walkable. Because `asserted_by` is in
the key, two notes asserting the same edge keep it alive until both retire.

**Extraction.** Entities are extracted deterministically at save: task ids,
branches, projects, services, agent labels, and `[[wikilinks]]` in the content,
at most 64 per note (`MAX_NOTE_ENTITIES`), so a note that names a vault page
joins the same graph as the vault.

**The leg**, with Python's caps: up to 5 seed notes from the content legs, at
most 16 entities per seed (`MAX_SEED_ENTITIES`), fanout 10 per seed, at most 20
notes from the leg, and an entity on more than 25 notes is a hub and is not
walked.

**Eligibility comes before every limit.** Unlike the Python leg — which applied
its scan `LIMIT` and computed document frequency over every note in the
organization before eligibility — the scoped eligibility predicate sits inside
the innermost subquery, document frequency is counted over **eligible** notes
only, and only then are caps applied. Hidden notes therefore cannot push an
entity over the cap, change a neighbour's score or use up the scan budget.

The leg joins fusion as one more `LEG_WEIGHTS` entry at a lower weight than the
content legs. `search.rs` stops dropping notes that only the graph leg found;
a note a content leg already matched gets no graph rank.

### 6. Context pack and post-run distillation

Agents across harnesses start cold. Memory should arrive without each one
remembering to search.

**`context_pack`** — a tool and an MCP resource. It **replaces** the unscoped
related-memory section of `session_packet`, which then calls it. Input: the
caller (from the credential), optional `task_id`, optional query, a token
budget, and optional `as_of`. Output, in order until the budget is spent:

1. notes tied to the task by an evidence ref, then by entity match on the task
   id, branch or project;
2. **decisions**: notes tagged `decision` with salience ≥ 0.7 at `org` or
   `team` visibility, limited to notes written by a human or confirmed by one
   (`memory_feedback` from a verified human), so an agent cannot plant text
   into every pack;
3. the caller's own episodes from the last 14 days;
4. open, accepted contradictions touching anything already included.

"Team" means the task's owning team when a task is given, else every team the
caller belongs to. Every item goes through the scoped filter, carries its id,
why it was included, its owners and the untrusted marker. The token estimate
uses the chunker's 4 characters per token. Ties break by note id, so the same
state and `as_of` produce the same pack. **Pack reads do not count as recalls**
and do not touch access counters, so `recall_maintenance`'s "never recalled"
signal stays meaningful.

Delivery is per harness through harness-config bundles: a session-start hook
where the harness has one, otherwise a rules line telling the agent to call
`context_pack` first. Hook-injected text is fenced in a labelled block that
states it is recalled data, not instructions.

**Distillation.** `memory_distill` is the structured successor of
`propose_session_learnings`. At session end, the bundle's stop hook asks the
agent to call it with outcome, decisions, learnings and open questions for its
session or run. The caller must own that session or run. The hub validates size
and fields and writes one episode note with `evidence` naming the session or
run and the organization's default visibility. A unique key on
`(org_id, session_or_run)` makes concurrent first calls produce one note; a
repeat call updates it. Episodes are what consolidation later groups.

## Import and export

- `ua-import` maps `memory_embeddings`, `memory_chunks` (`chunk_index` → `idx`,
  `content_sha` recomputed), `memory_entities` and `memory_links`, which today
  are unmapped. A NULL source `org_id` becomes `'default'`; imported links get
  `asserted_by = src_id`; entity kind `project` is kept. Imported notes take
  `visibility = 'org'` in their organization, matching the parity backfill.
- `export.rs::GRAPH_TABLES` and the memory manifest columns gain `org_id`,
  `visibility`, `team_id`, `owner`, `asserted_by`, `proposed` and `retired_at`,
  and the manifest fingerprint is versioned, so a retired edge never compares
  equal to a live one.

## Where the code lives

- `crates/ua-memory`: everything in this document. `ua-tools` keeps only the
  registration.
- `ua-store` gains a `MemoryRepo` trait next to `OrgRepo`; `ua-memory` reaches
  the database only through it. Today `Filter` binds `rusqlite` `SqlValue`s and
  `VectorIndex` takes a `&Connection`, and both are re-exported; the move
  redesigns them so the public surface carries a scope and plain values, and
  `rusqlite` stays inside the SQLite implementation. The bundled SQLite store
  stays the default; the trait is where another backend would plug in.

## Non-goals

- **Not a rewrite of the ranker.** Reciprocal-rank fusion, decay and salience
  priors stay as they are. New capability arrives as additional legs and passes.
- **Not a vector-database migration.** SQLite plus the embedding and chunk
  tables is adequate at the scale this hub runs. Revisit only with measurements.
- **Not cross-organization memory sharing.** Memory is tenant-scoped. A shared
  knowledge base is a separate design.
- **No model calls from the hub.** Summaries and episodes are written by agent
  seats, under their budgets, and validated by the hub. This deliberately drops
  the predecessor's hub-side adjudication and unreviewed auto-apply.

## Acceptance

1. **The eval gate runs first.** `ua memory bench` and the CI test report
   `recall@k` and MRR per class from checked-in vectors through a registered
   embedder, fail below the recorded floor, fail on a missing vector with the
   regeneration command, and fail if the paraphrase class ran lexical-only.
2. **Existing behaviour is unchanged.** The current memory test suite passes
   untouched after the migration and backfill.
3. **Differential isolation.** Inserting another organization's notes, another
   owner's `private` notes and another team's `team` notes leaves every
   corpus query's ids, order, counts, explanations and confidence fields
   identical, on every leg including chunks and graph.
4. **Long documents.** A fact only in the last third of a 6,000-character note
   is recalled through its chunks; a note above 16 chunks embeds its first 16;
   a non-ASCII note chunks at code-point boundaries identical to the Python
   chunker; a long note's score is the maximum of its single and chunk scores.
5. **Staleness and backfill.** After an edit whose re-embed fails, the old
   vector is not scored; the maintenance pass backfills it.
6. **Vector identity.** Vectors from two backends with the same model name are
   never compared; changing identity re-embeds.
7. **Embedder default and privacy.** A release build with a fetched model has
   vector recall with no configuration; with no model, `system_doctor` reports
   `DEGRADED` and triggers no download; save and search never download; any
   endpoint resolving to a non-loopback address is refused without
   `allow_remote_embedder`.
8. **Build.** CI builds and tests the `embeddings` feature; the release binary
   stays within the recorded size budget; the notices list ONNX Runtime.
9. **Every path is scoped.** The statement-walking test fails on a memory read
   outside `ua-memory`; each tool in the inventory returns nothing invisible,
   and an invisible id produces the same `not_found` as a missing one.
10. **Scoped confidence.** A hidden contradicting note changes neither a visible
    note's rank nor its `confidence_posterior`, and its id appears in no link
    list.
11. **Defaults fail closed.** An `INSERT INTO memory` omitting `visibility` is
    caught by the insert-walking test; a saved note takes its organization's
    default; a new organization defaults to `private`; `'default'` is `org`
    after migration; `team` without `team_id`, or with another organization's
    team, is refused.
12. **Visibility changes.** Only the owner or an `org_admin` changes
    visibility; narrowing invalidates the note's consolidations and retires its
    topical edges; an anonymous caller cannot read or write `private` or
    `team` notes.
13. **Session grants.** A task-bound session reads only notes with that task's
    evidence ref, cannot overwrite or supersede, and its writes carry
    `credential_id`.
14. **Promotion.** `memory_promote` refuses `private` and `team` notes.
15. **Consolidator eligibility.** A shared seat is never handed a `private`
    group or a `team` group of a team it is not in; a private summary is
    visible to exactly its owner.
16. **Consolidation is idempotent.** Running the pass twice produces no
    duplicate summary and no orphaned edges; an expired lease is retaken; a
    retried commit returns the same summary; a commit after any source revision
    or scope change is refused; a restored identical source set can be
    consolidated again.
17. **Provenance.** Every summary's evidence names its sources (at most 20) and
    every source has a `derives` link to it.
18. **Summary trust.** A summary's prior and salience never exceed its
    sources' minimum; when a source is in the results, the summary ranks
    directly below the best one; its trust marker lists the source owners.
19. **Invalidation.** Editing, narrowing or superseding a source expires its
    summary from default search and retires the summary's topical edges, while
    `derives` and `supersedes` edges remain.
20. **Workbench.** A pair with one hidden side is not listed; a `member` cannot
    resolve; "both valid" sets the two ranges and closes the link; a proposed
    contradiction does not attenuate before acceptance; rendered note text is
    escaped.
21. **Graph.** Superseding an asserting note retires its topical edges but not
    lineage; an edge asserted by two notes survives one retirement; an entity
    hub cap counts eligible notes only; a note found only by the graph leg is
    returned; a note's entities stop at 64.
22. **Context pack.** Respects the token budget, includes only eligible notes,
    takes decisions only from human-written or human-confirmed notes, does not
    change access or recall counters, and is identical for the same state and
    `as_of`.
23. **Distillation.** Two concurrent first calls for one session leave one
    episode note; a caller that does not own the session is refused.
24. **Import and export.** A Python hub's embeddings, chunks, entities and links
    import with `asserted_by = src_id` and NULL org mapped to `'default'`; a
    manifest compare distinguishes a retired edge from a live one.
