# Memory subsystem

Status: **design, with step 1 landed.** The ranking, save, lifecycle and
scoped-tenant pieces already exist; this document designs the pieces the
memory family does not yet have. It is not a plan to rebuild what exists. It
depends on the organization model (`docs/organization.md`, PR #39) for
`org_id`, users, teams, roles, organization settings and agent owners.

Step 1 (evidence) landed as the `ua memory bench` harness in PR #53 (merged
`e84f4b03`), but **it does not gate merges yet**: the fix round in task #2798
must land first. Everything from step 2 on is design.

The memory domain now lives in its own crate, `crates/ua-memory` (PR #49,
merged as `fdb4bad`); `ua-tools/src/families/memory` keeps only the tool
registration. File paths below name modules of `crates/ua-memory/src`
(`rank.rs`, `embed.rs`, `search.rs`, `note.rs`, `save.rs`, `lifecycle.rs`,
`schema.rs`, `bench.rs`).

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
| BM25 with per-field weights (title 3.0, content 1.0, tags 2.0), computed by FTS5 `bm25()` | `rank.rs::BM25_WEIGHTS`, `search.rs` | Present — but see the side channel in §3 |
| Semantic leg: one vector per note, scanned by `BruteForceIndex` | `embed.rs`, `memory_embeddings` | Present, **off by default** (below) |
| Temporal validity and supersession | `memory.valid_from`, `valid_to`, `superseded_by` | Present; the default filter checks `superseded_by` and expiry, and `valid_to` only under `as_of` |
| Salience prior, recency decay, feedback and votes | `salience`, `upvoted_count`, `RECENCY_HALF_LIFE_DAYS=15`, `DECAY_MONTHS=6`, `W_SALIENCE/W_FEEDBACK/W_VOTE` | Present |
| Access and recall counters | `access_count`, `recalled_count` | Present, **reported, never ranked** |
| Contradiction attenuation and open-link surfacing | `contradicts`, `CONTRADICTION_BETA`, `MAX_COUNTED_CONTRADICTIONS`, `note.rs` | Present |
| Versioning, 50 versions per note, trigger-captured | `memory_versions` | Present |
| Maintenance pass: pruning candidates, low confidence | `maintenance.rs` (report-only) | Present |
| Shared eligibility filter (deletion, supersession, `as_of`, tags, host, expiry) | `note.rs::Filter`, given `now` by `Eligibility` | Present; used by `memory_search`, `memory_list`, `open_contradictions`, `similar_notes` and `BruteForceIndex` |

Facts the first draft did not record:

- **Vector recall is effectively off.** `embed.rs::embedder_for` returns a
  `NoopEmbedder` unless the crate is built with the `embeddings` cargo feature.
  That feature is off by default (`ua-memory/Cargo.toml`, reached through
  `ua-tools/embeddings`), `ua-cli` does not pass
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
  parseable proposal file became `apply` commands.
- **Memory scope is not one code path.** About a dozen tools read the `memory`
  table directly, not through `Filter`. See the inventory in §3.
- **The clock is injected.** Every memory operation reads `Config.clock`
  (`ua_core::time::Clock`): search, list and get, `similar_notes`,
  `maintenance.rs` (`days_ago`), `save.rs` and `lifecycle.rs`. A hub uses the
  wall clock; tests and the retrieval bench fix it. Ledger event timestamps
  still come from `ua-store`.

A note on the honest ceiling: this ranker is competitive. The claim that the
result is "as good as or better than a leading memory system" is currently
**unfalsifiable**, because nothing measures retrieval quality — see
[Evidence](#1-evidence).

## The gaps, in build order

| Step | Lands after | Schema part |
|---|---|---|
| 1. Evidence | — | none |
| 2. Chunks and embedder | `organization.v1` (the chunk fence reads `memory.org_id`) | `memory.chunks.v1` |
| 3. Scoped recall | `organization.v3` (team visibility needs `teams`; owner backfill needs `users` from `organization.v2`) | `memory.scope.v1` |
| 4. Link store, consolidation, workbench | step 3 | `memory.links.v1`, `memory.consolidation.v1` |
| 5. Graph leg | step 4 | none |
| 6. Context pack, distillation | step 3 | `memory.episodes.v1` |

### 1. Evidence

**Landed and gating.** `crates/ua-memory/src/bench.rs`, the fixture corpus
and `floor.json` are in PR #53 (merged `e84f4b03`), and
`docs/evals/memory-bench.md` records the runs. Task #2798 made the harness fit
to gate merges: search breaks score ties on insertion order, the clock is
injected and fixed in the bench, each LongMemEval question's scratch files are
removed when it finishes, and every fixture negative shares its query's terms.

Measured on that head, lexical-only, release build, all 470 answerable
LongMemEval questions: strict recall@5 0.8489 (399/470), MRR@10 0.8389, `as_of`
accuracy 0.48, search p95 18 ms. The fixture floor is overall recall@5 0.8000,
with two recorded gaps: the paraphrase class at 0.5 (`sedan` and
`automobile`) and the temporal class at 0.6667 (a note recorded after its
`valid_from` is invisible to an `as_of` between the two). Multi-session
(0.686) and `as_of` (0.48) are the weak classes; the chunked-embedding step
targets the first.

Unit tests prove that the code does what it says, not that retrieval is good.
This step gates everything after it.

**Corpus.** A checked-in fixture corpus (`ua-memory/bench/`): notes, labelled
queries, and for each query the notes that must appear and those that must
not. Query classes: exact-term, paraphrase, temporal (`as_of`), contradiction,
long-document (an answer past the first 512 tokens), multi-hop graph and
consolidation. The isolation cases land with step 3, which creates the scope
they test.

**Metrics.** `recall@k` and mean reciprocal rank per class, from
`ua memory bench` and from a CI test. `bench/floor.json` records the floor per
class; a change that drops a class below its floor fails CI, and raising the
floor is an explicit commit.

**Isolation is not a floor, and presence is not enough.** recall@k cannot see
the side channels this design rules out (counts, order, scores, explanations,
contradiction counts, graph document frequency). So isolation is a
**differential test**: each query runs once on the corpus and once with hidden
notes inserted (another organization's, another owner's `private`, another
team's `team`, and hidden notes that share the query's terms and entities),
and the visible output — ids, order, raw leg scores, counts, explanations,
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
- The clock is injected: one clock (`Config.clock`) is threaded through the
  `now()` callers listed above, and the bench fixes it.
- Search writes access counters as a side effect, so each query runs against a
  fresh copy of the fixture database.
- The consolidation class uses checked-in summaries, since model-written ones
  are not deterministic.
- A separate, non-gating job re-embeds with the live model and reports drift.

Every later section adds its cases to the corpus in the same change, so each is
measured from the day it lands.

**External benchmark.** The fixture corpus measures what a multi-agent,
multi-organization store needs (supersession, `as_of`, scope) and that no public
benchmark expresses. Retrieval quality on long conversational history is
measured against LongMemEval-S, reusing the predecessor's method and the same
dataset file (pinned by SHA-256 `d6f21ea9d60a0d56f34a05b609c79c88a451d2ae03597821ea3d5a9678c3a442`),
so the numbers are comparable. It needs a download and a model, so it is a
recorded run (`ua memory bench --longmemeval`, results committed under
`docs/evals/`), not a CI gate. The predecessor's scorecard (2026-10-19) is the
baseline to beat:

| Configuration | Strict recall@5 |
|---|---|
| The predecessor hub, hybrid, 120-question stratified sample | 0.883 (106/120); about 0.846 reweighted to all 470 |
| The predecessor hub, lexical legs only, all 470 | 0.826 (388/470) |
| `ua-rust`, lexical only, all 470 (2026-11-20, `1d9a30f`) | 0.8489 (399/470); MRR@10 0.8389 |
| A leading standalone memory system, same file | 0.955 |

The scorecard also names the cause of most of the gap: notes average about
10,000 characters, the encoder reads only the first 512 tokens, and the
evidence is rarely in the opening, so the semantic leg added two questions out
of 120. That is why chunked embeddings (step 2) come straight after this step.
Besides recall@5, record MRR@10, `as_of` accuracy, the share of stale results
returned (target under 2%) and p95 search latency (target under 100 ms).

**One layer at a time.** Each later step records its numbers before the next
starts. If chunking does not move the long-document class and the LongMemEval
score materially, the diagnosis was wrong, and the next step waits rather than
stacking on top of it.

### 2. Chunked embeddings and a default embedder

**Chunks.** Port `memory_chunks.py` so imported hubs embed the same text:

| Constant or rule | Value |
|---|---|
| Chunk | 400 tokens ≈ 1,600 characters (4 characters per token) |
| Overlap | 80 tokens ≈ 320 characters |
| Single-vector threshold | 512 tokens ≈ 2,048 characters |
| Boundary snap | within the last 80 characters of a window, prefer a newline, else a space; snap only if the window keeps at least 800 characters |
| Piece trimming | each piece is stripped of leading and trailing whitespace by **Python's** definition (`str.isspace`, which includes `\x1c`–`\x1f`), not Rust's `char::is_whitespace` |
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
    content_sha TEXT NOT NULL,   -- '' marks an imported, unverifiable vector
    PRIMARY KEY (note_id, idx)
);
CREATE TRIGGER IF NOT EXISTS memory_chunks_org_fence
BEFORE INSERT ON memory_chunks
WHEN NEW.org_id IS NOT (SELECT org_id FROM memory WHERE id = NEW.note_id)
BEGIN SELECT RAISE(ABORT, 'memory_chunks org_id differs from its note'); END;
CREATE TRIGGER IF NOT EXISTS memory_embeddings_org_fence
BEFORE INSERT ON memory_embeddings
WHEN NEW.org_id IS NOT (SELECT org_id FROM memory WHERE id = NEW.note_id)
BEGIN SELECT RAISE(ABORT, 'memory_embeddings org_id differs from its note'); END;
```

`store_vector` binds `org_id` explicitly, as the organization doc's
insert-walking test requires. The fences guard against bugs: every write path
resolves its note through a scoped lookup first, so a fence never fires on a
legitimate call and its message is no oracle.

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
```

- `local`: the ONNX model through `fastembed`, from `~/.ua-rust/models`
  (`cfg.home.join("models")`). The revision is pinned.
- `ollama`: an Ollama server's embedding endpoint, with its own
  `ollama_model` key, since Ollama names do not match Hugging Face ids.
- `openai_compat`: any OpenAI-compatible `/v1/embeddings` endpoint. The key
  comes only from the environment, never the config file.
- `auto` picks `local` when it is compiled in and its model is present, else a
  loopback Ollama that serves `ollama_model`, else lexical-only.

**Note text stays on the machine unless the organization says otherwise.** For
any backend, the endpoint's host is resolved once; if any resolved address is
not loopback, the endpoint is **remote**. The HTTP client is then pinned to the
addresses it checked (`ClientBuilder::resolve`), follows no redirects
(`redirect::Policy::none()`) and uses no proxy (`no_proxy()`), so DNS
rebinding, a redirect or an `HTTP(S)_PROXY` cannot move the request elsewhere.
A remote endpoint is used only for the notes and queries of organizations whose
`allow_remote_embedder` setting is on (an `org_owner` decision, see the
organization doc); every other organization gets `local` or lexical-only, and
their vectors carry a different identity. An explicit `ollama` with a remote
URL is remote like any other.

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
`memory_embeddings`, with the generated existence and immutability triggers;
this part does not touch `org_id`. It adds:

```sql
ALTER TABLE memory ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'
    CHECK (visibility IN ('private','team','org'));
ALTER TABLE memory ADD COLUMN team_id TEXT;
ALTER TABLE memory ADD COLUMN owner_type TEXT
    CHECK (owner_type IS NULL OR owner_type IN ('human','agent','org','team'));
ALTER TABLE memory ADD COLUMN owner TEXT;          -- users.id, agent label, org id or team id
ALTER TABLE memory ADD COLUMN owner_verified INTEGER NOT NULL DEFAULT 0
    CHECK (owner_verified IN (0,1));               -- proof, not inference: see below
ALTER TABLE memory ADD COLUMN credential_id TEXT;  -- set for session-grant writes

-- parity backfill, in the same migration. owner_verified stays 0 for every row:
-- no historical write carries proof of who made it.
UPDATE memory SET visibility = 'org';
UPDATE memory SET owner_type = 'human',
                  owner = (SELECT u.id FROM users u WHERE u.label = memory.author COLLATE NOCASE)
 WHERE EXISTS (SELECT 1 FROM users u WHERE u.label = memory.author COLLATE NOCASE);
UPDATE memory SET owner_type = 'agent', owner = author
 WHERE owner_type IS NULL AND author IS NOT NULL;
UPDATE memory SET owner_type = 'org', owner = org_id
 WHERE owner_type IS NULL;

CREATE TRIGGER IF NOT EXISTS memory_team_scope_insert
BEFORE INSERT ON memory
WHEN (NEW.visibility = 'team') != (NEW.team_id IS NOT NULL)
  OR (NEW.team_id IS NOT NULL AND NEW.org_id IS NOT
      (SELECT org_id FROM teams WHERE id = NEW.team_id))
BEGIN SELECT RAISE(ABORT, 'team_id must be set exactly for team visibility, in the same org'); END;
CREATE TRIGGER IF NOT EXISTS memory_team_scope_update
BEFORE UPDATE OF visibility, team_id ON memory
WHEN (NEW.visibility = 'team') != (NEW.team_id IS NOT NULL)
  OR (NEW.team_id IS NOT NULL AND NEW.org_id IS NOT
      (SELECT org_id FROM teams WHERE id = NEW.team_id))
BEGIN SELECT RAISE(ABORT, 'team_id must be set exactly for team visibility, in the same org'); END;
```

**Ownership is not verification.** `owner` says who a note belongs to;
`owner_verified` says the hub can prove it. Only the write path sets it, from
the caller's identity kind: a verified human caller (`ActorKind::Human`)
writing a note it owns gets `1`; an agent, a system caller and an anonymous
caller all get `0`, because an anonymous caller supplies its own `author` text
and the hub never checked it. A session-grant write is verified only when the
grant's principal is verified, and it also carries `credential_id`. The value
is derived, never accepted from a client field.

The backfill sets `0` for every existing note, deliberately. There is no
historical proof to derive it from: the ledger records the originator label
but not whether that write was authenticated, and the predecessor's `author`
was free text. Failing closed costs convenience, not safety: on an upgraded
hub, `context_pack` injects nothing until an operator attests.
`ua memory attest-owners --author <label>` is that path — operator-only, one
`memory.owner_verified` ledger event per note (ids only, never title or
content), idempotent, and refused for a label that is not a `users` row.
Nothing else promotes a note to verified.

The column default is the **narrowest** tier, so an insert that forgets
`visibility` fails closed. The writer always binds `visibility` explicitly from
the organization's setting; the organization doc's insert-walking test is
extended so an `INSERT INTO memory` that omits `visibility`, `owner`,
`owner_verified` or `org_id` fails.

**Owners.** `owner` is who the note belongs to; `author` stays the writer
stamped by `write_author`. They differ for consolidation summaries and
session-grant writes. The owner backfill above maps a note to a human when its
author is a `users` label, else to its agent, else to the organization. A
`users` row can also appear after this part has applied (bootstrap of a newly
listed hub owner, an import). So **this** PR also owns the human re-own step
(`owner_type = 'human', owner = users.id` where `owner_type = 'agent'` and
`owner` equals that user's label, case-insensitively): it is a `MemoryRepo`
method, `reown_for_user`, which the organization doc's bootstrap and the
importer call through a hook `ua-memory` registers. Before `memory.scope.v1`
exists there is no hook and nothing to re-own; the step is idempotent, and it
runs through `MemoryRepo`, so the authorizer admits it. A consolidation summary of an `org` or
`team` group is owned by that organization or team (`owner_type = 'org'` or
`'team'`).

`reown_for_user` moves the owner id and never the proof: a note that was not
`owner_verified` stays `0` after re-owning, so an anonymous note whose `author`
happens to name a human does not become injectable later. The importer writes
`owner_verified = 0` for every note it creates, because a predecessor row
carries no proof of who wrote it; only `attest-owners` can change that.

**Who sees what.** Comparisons are on `(principal_type, principal)`, with humans
keyed by `users.id`:

- `private`: the owner only — for an agent owner, that agent; for a human
  owner, that human;
- `team`: the human and agent members of `team_id` (`team_members`);
- `org`: every member of the organization.

`private` and `team` need a verified identity to read or write. An anonymous
caller, whose `author` is only claimed, sees and writes `org` notes only.
An `org_admin` has **no** read access to `private` notes; admin authority over
notes is limited to the notes the admin can already see.

**Default visibility** is the organization's `memory_default_visibility`
setting (organization doc, column default `'private'`):

| Organization | Default for a note saved without `visibility` |
|---|---|
| `'default'` on an upgraded or fresh hub | `org`, set by the migration, so existing behaviour holds |
| Any organization created afterwards | `private` |
| Solo templates (Phase 5 `ua init`, later) | may set `org`, so one builder's agents share context |

When the default is `team`, the note goes to the caller's team if the caller is
a member of exactly one team in the organization; otherwise it falls back to
`private`. Changing the setting is `org_settings_update`, recorded on the
ledger, never a side effect.

**Changing a note's visibility.** Only the owner **widens** a note; widening
into `team` requires the owner to be a member of that team. The owner or an
`org_admin` who can see the note may **narrow** it or delete it. Narrowing
invalidates every consolidation the note is a source of (§4) and retires the
topical graph edges it asserted (§5). A note that supersedes another cannot be
narrowed below the note it supersedes (see Supersession).

**Supersession never crosses scope.** A supersede — through `supersedes` on
create or `overwrite` on update — is refused unless the replacement is at least
as visible as the target (`org` ≥ `team` ≥ `private`) and, for `team`, in the
same team. So a member cannot hide an `org` note from everyone by superseding it
with a `private` note. When reading, a `superseded_by` that points at a note the
caller cannot see is treated as `NULL`, both in the eligibility filter and in
the note's output, so neither the hiding nor the hidden id leaks.

**Enforcement is in the SQL, on every path.** `Filter` gains a mandatory scope
argument `(org_id, principal_type, principal, team_ids)`, and every read of
memory goes through `MemoryRepo` with it. A test cannot see dynamically built
SQL, so the guard is a **rusqlite authorizer hook**: every connection the hub
opens installs an authorizer that denies reads of `memory`, `memory_*` tables
and `memory_fts` unless the statement comes from `MemoryRepo`, or from an
explicit allowlist — schema migration, `ua-import`, and the operator-only
migration manifest. A test opens a connection outside that list and asserts the
denial.

Inventory of the paths that read the table today, and the rule for each:

| Path | Today | Rule |
|---|---|---|
| `memory_search` | `Filter` | Scope in the same `WHERE` as the FTS match, the vector candidate set, the chunk scan and every graph hop; BM25 from scoped statistics (below) |
| `memory_list` | `Filter` | Scoped |
| `memory_get`, `note_links`, versions | by id, unscoped | Scoped; linked ids, `supersedes`, `superseded_by` and `contradicts` show only visible notes |
| `memory_save` update / append / overwrite, `linked_note` for `supersedes`/`contradicts` | by id | Scoped; a hidden target is `not_found` |
| `memory_save` `similar_notes` / `check_only` | unscoped similarity | Only visible notes are compared or returned |
| `memory_save` idempotency replay | key stored as `memory_save/<caller>/<key>` and read only from `memory_save` rows (a pre-upgrade raw `memory_save` key still replays, but only for the caller that wrote or last updated the note it names; for anyone else it is a fresh key) | The table is keyed `(org_id, key)` (`idempotency.v2.tenant_keys`, organization doc) and a receipt is read only in the caller's organization, and the principal is the `<caller>` part of the key text, so it is scoped by organization **and** principal; a replay by another principal is a fresh call, and the "already used" and "is deleted" errors appear only to the key's own principal |
| `memory_delete`, `memory_restore`, `memory_feedback` | by id | Scoped |
| `memory_prune_candidates`, `recall_maintenance` (`live_notes`) | unfiltered | Scoped to the caller |
| `memory_promote` | copies any note to the shared vault | Only in `'default'` (the vault is hub-scoped) and only `org`-visible notes |
| `export_memory` / `export_data` | every note, written to the vault by default | Only the caller's visible notes; a vault write only in `'default'` |
| `session_packet` related memory | unscoped FTS | Replaced by `context_pack` (§6) |
| `propose_session_learnings` dedupe | unscoped existence check | Scoped |
| `platform_object_get` (`memory_note`) | by id | Scoped |
| vault ingest memory lookups | unscoped | Scoped to the ingesting caller |
| `agent.memory.saved` and other memory ledger events | carry `title` and `tags` | Only for `org` notes; for `private` and `team` notes, ids only — no title, tags or content hash, since a plain hash lets an auditor confirm guessed content |
| export manifest | every note | Operator-only, on the authorizer allowlist, and records the scope columns |
| observability and evidence counts | global counts | Scoped counts, or hub-operator only |

**One not_found.** An invisible note and a missing note produce the same error,
code and message, so an id is no oracle.

**Lexical scoring from scoped statistics.** FTS5's `bm25()` computes the
document count, each term's document frequency and the average field length
over the **whole** `memory_fts` table; a `WHERE` clause does not change them.
Hidden notes would therefore shift visible notes' lexical scores and order,
revealing whether a term occurs in notes the caller cannot see. So FTS5 is used
only as a **match index** — which eligible notes contain the terms — and BM25
is computed in Rust from scoped statistics. Every statistic comes from FTS5's
own tables, so nothing re-implements the `porter unicode61 remove_diacritics 2`
tokenizer and nothing can drift from the index:

- **Query terms** are tokenized by FTS5 itself: the query text is written to a
  temporary in-memory `fts5` table declared with the identical `tokenize`
  option and read back through `fts5vocab`, giving exactly the indexed term
  forms.
- **Term frequencies** per note and field come from an `fts5vocab` **instance**
  table over `memory_fts` (`term`, `doc`, `col`, `offset`), joined to `memory`
  on `seq` inside the scoped `WHERE`.
- **Document frequency** per term and field is the count of distinct eligible
  `doc`s in that table.
- **Field lengths** come from `memory_fts_docsize` (per-row column sizes, read
  and decoded in the SQLite implementation of `MemoryRepo`); `N` and the
  average field lengths are aggregated over eligible notes only.
- **The cap moves after scoring.** Today the lexical leg runs
  `ORDER BY bm25(...) LIMIT FTS_LIMIT` (200) in SQL (`search.rs`), so global
  statistics would still decide which visible notes reach the candidate set.
  The leg now fetches every eligible match (up to `MAX_LEXICAL_MATCHES`, below),
  scores it in Rust, and only then keeps the top `FTS_LIMIT`.

**The scan is bounded.** Two constants keep a scoped query's cost independent
of corpus size; neither is a setting:

- `MAX_QUERY_TERMS = 32` distinct indexed terms per query. Terms past the cap
  are dropped in the order FTS5 returns them, so the same query always scores
  the same terms.
- `MAX_LEXICAL_MATCHES = 10_000` eligible matches scored per query. Matches are
  read in FTS5 match order, then `memory.seq`, so which matches are scored is
  deterministic and never depends on notes the caller cannot see.

When either cap is hit, the search explanation carries
`lexical_truncated: true` beside the existing per-leg breakdown, so a caller
can tell a bounded result from an exhaustive one. A truncated leg is still a
valid leg: fusion and ranking are unchanged. The cost is a scan of at most
10,000 eligible matches per query; the bench records p95 latency on a
100,000-note corpus with a stopword-heavy query against the 100 ms target, so a
regression is visible. No columns are added for this. The per-field weights and
`RRF_K` are unchanged.

**Counts and confidence are scoped.** Totals and per-leg explanations are
computed after eligibility. `note::open_contradictions` counts only disputing
notes the caller can see, inside the scoped query, so a hidden contradiction
neither changes a visible note's effective confidence, prior or rank nor
appears in `confidence_posterior`.

**Session grants.** A narrowed session credential (an ACP or node session bound
to one task) currently reaches `memory_*` with no narrowing. Under scoped
recall it reads only notes visible to its owner **and** tied to its task by a
`task:<id>` evidence ref — not by entity match, since entities are written by
any note author. `task:` evidence refs may be added only by the note's owner
(other evidence kinds keep today's rule); if an existing test asserts that a
non-owner may add a `task:` ref, it changes in this step and the PR names it.
Session-grant writes are stamped with `credential_id`, and `overwrite` and
`supersedes` are refused. Every tool reached under a grant applies this rule,
including `context_pack` through `session_packet`. A test fails when a tool on
the session allowlist has no explicit narrowing rule.

**Revisions change once.** `Note::revision` gains `org_id`, `visibility`,
`team_id`, `owner_type` and `owner`. Every note's revision therefore changes at
deploy, and a client holding an old revision gets one `expected_revision`
conflict, after which it re-reads. This is stated in the release notes.

### 4. Links, consolidation and the contradiction workbench

Nothing turns episodes into durable notes. The store grows monotonically, each
new note dilutes the index, and recall quality falls as volume rises even
though every individual note is fine. This step comes after scoped recall, so
that a summary can never merge notes from different scopes, and it creates the
link store that consolidation writes to and §5 ranks over.

#### The link and entity store

Port the Python tables so imported graphs keep working, with attribution and
the Python checks:

```sql
CREATE TABLE IF NOT EXISTS memory_entities (
    org_id  TEXT NOT NULL,
    note_id TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    kind    TEXT NOT NULL,   -- task, branch, project, service, agent, wikilink
    value   TEXT NOT NULL,
    retired_at TEXT,
    PRIMARY KEY (note_id, kind, value)
);
CREATE TABLE IF NOT EXISTS memory_links (
    org_id      TEXT NOT NULL,
    src_id      TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    dst_id      TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    rel         TEXT NOT NULL
                CHECK (rel IN ('supersedes','contradicts','evidence','extends','derives')),
    asserted_by TEXT NOT NULL,   -- the note that asserted the edge
    proposed    INTEGER NOT NULL DEFAULT 0 CHECK (proposed IN (0,1)),
    actor       TEXT,
    created_at  TEXT NOT NULL,
    retired_at  TEXT,
    CHECK (src_id != dst_id),
    CHECK (proposed = 0 OR rel = 'contradicts'),
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

-- mirror of the authoritative superseded_by column; never raises
CREATE TRIGGER IF NOT EXISTS memory_links_mirror_supersedes
AFTER UPDATE OF superseded_by ON memory
BEGIN
    DELETE FROM memory_links
     WHERE rel = 'supersedes' AND dst_id = NEW.id AND asserted_by = OLD.superseded_by
       AND OLD.superseded_by IS NOT NEW.superseded_by;
    INSERT OR IGNORE INTO memory_links (org_id, src_id, dst_id, rel, asserted_by, actor, created_at)
    SELECT m.org_id, m.id, NEW.id, 'supersedes', m.id, NEW.updated_by, NEW.updated_at
      FROM memory m
     WHERE m.id = NEW.superseded_by AND m.org_id = NEW.org_id AND m.id != NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS memory_links_mirror_supersedes_insert
AFTER INSERT ON memory
WHEN NEW.superseded_by IS NOT NULL
BEGIN
    INSERT OR IGNORE INTO memory_links (org_id, src_id, dst_id, rel, asserted_by, actor, created_at)
    SELECT m.org_id, m.id, NEW.id, 'supersedes', m.id, NEW.updated_by, NEW.updated_at
      FROM memory m
     WHERE m.id = NEW.superseded_by AND m.org_id = NEW.org_id AND m.id != NEW.id;
END;

-- backfill in memory.links.v1, and the same statement as the importer's
-- post-import mirror pass: idempotent, never raises
INSERT OR IGNORE INTO memory_links (org_id, src_id, dst_id, rel, asserted_by, actor, created_at)
SELECT s.org_id, s.id, t.id, 'supersedes', s.id, t.updated_by, t.updated_at
  FROM memory t JOIN memory s ON s.id = t.superseded_by AND s.org_id = t.org_id
 WHERE s.id != t.id;
```

The `contradicts` and `evidence` mirrors have the same three shapes —
`AFTER INSERT`, `AFTER UPDATE OF contradicts` / `OF evidence`, and a backfill —
reading the JSON arrays with `json_each` (`memory:<id>` refs only, for
evidence) and joining the named note in the same organization. Mirrors fire on
insert as well as update, so a note written with `superseded_by`, `contradicts`
or evidence already set gets its edges. The backfill gives notes that predate
`memory.links.v1` their edges. The importer inserts rows in source order, so a
mirror can miss a target imported later in the same run; it therefore runs the
three backfill statements once after every import run.

Every new memory table in this document (`memory_chunks`, `memory_entities`,
`memory_links`, `memory_consolidations`, `memory_consolidation_sources`,
`memory_invalidations`, `memory_feedback_events`) is a tenant table: it carries
`org_id NOT NULL` and gets the generated `<table>_org_exists` and
`<table>_org_immutable` triggers from the organization doc's `ua-store` helper,
in addition to the fences shown here.

Entity kinds keep Python's `project` (not `repo`), so imported entities match.

**One authority per relation.** `memory.superseded_by` and `memory.contradicts`
are authoritative for accepted `supersedes` and `contradicts`; `memory:<id>`
evidence refs are authoritative for `evidence`; triggers mirror each into
`memory_links`. `extends`, `derives` and proposed contradictions live only in
`memory_links`. No relation is written in two places by application code.

**Mirroring never fails a save.** Each mirror is an `INSERT OR IGNORE …
SELECT` joined to `memory` in the same organization: a dangling ref, or one that
names another organization's note, simply produces no row. The mirror never
raises, so saves that succeed today keep succeeding and the fence's message is
never reached through a mirror. When the authoritative value changes — for
example `memory_restore` clearing `superseded_by` — the mirror deletes the old
row and inserts the new one, so un-superseding removes the edge.

**Retirement is topical only.** When an asserting note is superseded,
invalidated or narrowed, the `extends` and accepted `contradicts` edges it
asserted, and its entity rows, get `retired_at`. Lineage edges — `supersedes`,
`derives`, `evidence` — are never retired by that, so history and provenance
stay walkable; they change only when their authoritative source changes, as
above. Because `asserted_by` is in the key, two notes asserting the same edge
keep it alive until both retire.

**Extraction.** Entities are extracted deterministically at save: task ids,
branches, projects, services, agent labels, and `[[wikilinks]]` in the content,
at most 64 per note (`MAX_NOTE_ENTITIES`), so a note that names a vault page
joins the same graph as the vault.

#### Consolidation

**Who writes summaries.** The hub calls no model. The scheduled pass is
deterministic: it groups unconsolidated notes and creates **consolidation
jobs**. An agent claims a job, writes the summary, and commits it with
`memory_consolidate_commit`. Cost and rate are that agent's team-spec budget
plus a per-pass job cap (`memory.consolidation_max_jobs`), both visible on the
ledger. Which agent may take a job depends on scope, so no agent ever sees a
note it could not already read:

| Group scope | Eligible consolidator |
|---|---|
| `org` | the organization's `memory_consolidator_label` agent |
| `team` | an agent that is a member of that team |
| `private`, agent owner | only that agent |
| `private`, human owner | only an agent whose `agents.owner_user_id` is that user, and only while that user's `org_memberships.consolidate_private` is on |

A human's private notes are never consolidated by default. Both conditions
need the user's own act: `agents.owner_user_id` is set only with the named
user's act together with a different `org_admin`'s (request and approval, or
offer and acceptance), and `consolidate_private` is changed only by that member
(organization doc). An `org_admin` who holds an
agent's tokens therefore cannot point it at someone's private notes. Nor can
the admin take over an agent the user pointed: claiming an agent revokes the
credentials others issued for it, and while it has an owner a new root
credential for it is issued by the owner or approved by the owner (organization
doc, writer rules; per-dispatch node session credentials are minted by the
agent's own node). A claim itself needs both the user and an `org_admin`, so no
one can take over another's agent by claiming it.

**Grouping.** The scheduled pass runs as `system_for(org)` with a **grouping
scope**: it reads note ids, scope columns, tags and entity rows — never titles
or content — so it can form groups across scopes without reading them. A group
is:

- notes of one `org_id`, `visibility`, `team_id` and, for `private`, one owner;
- not summaries themselves, not superseded, not expired, and not already a live
  source;
- updated within the last 14 days;
- connected by sharing at least one non-hub entity (one carried by at most 25
  eligible notes in that scope) **and** at least one tag;
- at most 20 sources (oldest first) — the existing `MAX_EVIDENCE_REFS`, so the
  summary's evidence can name every source.

Cosine similarity, when vectors exist, may order sources inside a group but is
not part of grouping or of the idempotency key, so the pass behaves the same
with embeddings off.

**State is recorded, so the pass is idempotent.**

```sql
CREATE TABLE IF NOT EXISTS memory_consolidations (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    scope_key       TEXT NOT NULL,      -- visibility, team_id, owner for private
    source_set_sha  TEXT NOT NULL,      -- hash of sorted (note_id, revision)
    status          TEXT NOT NULL CHECK (status IN ('pending','written','invalidated','expired')),
    summary_note_id TEXT REFERENCES memory(id),
    claimed_by      TEXT,
    claimed_until   TEXT,               -- lease; an expired claim can be retaken
    created_at      TEXT NOT NULL,
    resolved_at     TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS memory_consolidations_live_set
    ON memory_consolidations (org_id, source_set_sha)
    WHERE status IN ('pending','written');
CREATE TABLE IF NOT EXISTS memory_consolidation_sources (
    org_id           TEXT NOT NULL,
    consolidation_id TEXT NOT NULL REFERENCES memory_consolidations(id),
    note_id          TEXT NOT NULL,
    revision         TEXT NOT NULL,
    live             INTEGER NOT NULL DEFAULT 1 CHECK (live IN (0,1)),
    PRIMARY KEY (consolidation_id, note_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS memory_consolidation_sources_one_live
    ON memory_consolidation_sources (note_id) WHERE live = 1;
CREATE TABLE IF NOT EXISTS memory_invalidations (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id           TEXT NOT NULL,
    consolidation_id TEXT NOT NULL,
    summary_note_id  TEXT,
    at               TEXT NOT NULL
);
```

- A source set already consolidated is skipped; a re-run after a failure finds
  the `pending` row. An invalidated row does not block the same set later.
- **No job without a consolidator.** The grouping pass resolves each group's
  eligible consolidator (the table above) *before* it inserts a row. A scope
  with none — a human's `private` notes with no owner agent, a team with no
  member agent — produces no job, so its sources are never pinned by work
  nobody can claim.
- **Unclaimed jobs expire.** A `pending` row older than
  `memory.consolidation_job_ttl_hours` (default 48) is set to `expired` by the
  maintenance pass, with `resolved_at` stamped and its sources `live = 0`, so
  they can be grouped again. The live unique index covers `pending` and
  `written` only, so an expired row never blocks a fresh job for the same set.
  A claimed job is governed by its lease, not by this TTL.
- A note is a live source of at most one consolidation, enforced by the partial
  unique index.
- A claim takes a lease (`claimed_until`); an abandoned job becomes claimable
  again when it expires.
- **Commit is one compare-and-set**, in one write transaction: the job is
  `pending` and claimed by the caller with a live lease, every source's current
  `Note::revision` equals the recorded one, then the summary, its links and
  `status = 'written'` are written together. Anything else is refused.
- A retried commit of a job already `written` by the same caller returns the
  same summary id.

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
- `contradicts` links a consolidator proposes are stored as `proposed = 1` rows
  and do not attenuate confidence until accepted (below).

**Any change invalidates, and invalidation purges.** A trigger on `memory`
catches every write path, so no tool can forget the hook:

```sql
CREATE TRIGGER IF NOT EXISTS memory_consolidation_invalidate
AFTER UPDATE OF title, content, tags, visibility, team_id, owner_type, owner,
                superseded_by, valid_from, valid_to, expires_at ON memory
WHEN (OLD.title IS NOT NEW.title OR OLD.content IS NOT NEW.content
      OR OLD.tags IS NOT NEW.tags OR OLD.visibility IS NOT NEW.visibility
      OR OLD.team_id IS NOT NEW.team_id OR OLD.owner_type IS NOT NEW.owner_type
      OR OLD.owner IS NOT NEW.owner OR OLD.superseded_by IS NOT NEW.superseded_by
      OR OLD.valid_from IS NOT NEW.valid_from OR OLD.valid_to IS NOT NEW.valid_to
      OR OLD.expires_at IS NOT NEW.expires_at)
 AND EXISTS (SELECT 1 FROM memory_consolidation_sources
              WHERE note_id = NEW.id AND live = 1)
BEGIN
    INSERT INTO memory_invalidations (org_id, consolidation_id, summary_note_id, at)
    SELECT c.org_id, c.id, c.summary_note_id, strftime('%Y-%m-%dT%H:%M:%S+00:00','now')
      FROM memory_consolidations c
     WHERE c.status != 'invalidated'
       AND c.id IN (SELECT consolidation_id FROM memory_consolidation_sources
                     WHERE note_id = NEW.id AND live = 1);
    UPDATE memory
       SET title = '[withdrawn]',
           content = '[withdrawn: a source of this summary changed]',
           tags = '[]',
           expires_at = strftime('%Y-%m-%dT%H:%M:%S+00:00','now')
     WHERE id IN (SELECT c.summary_note_id FROM memory_consolidations c
                   WHERE c.status = 'written'
                     AND c.id IN (SELECT consolidation_id FROM memory_consolidation_sources
                                   WHERE note_id = NEW.id AND live = 1));
    DELETE FROM memory_versions
     WHERE note_id IN (SELECT c.summary_note_id FROM memory_consolidations c
                        WHERE c.status = 'written'
                          AND c.id IN (SELECT consolidation_id FROM memory_consolidation_sources
                                        WHERE note_id = NEW.id AND live = 1));
    UPDATE memory_consolidations
       SET status = 'invalidated', resolved_at = strftime('%Y-%m-%dT%H:%M:%S+00:00','now')
     WHERE status != 'invalidated'
       AND id IN (SELECT consolidation_id FROM memory_consolidation_sources
                   WHERE note_id = NEW.id AND live = 1);
    UPDATE memory_consolidation_sources SET live = 0
     WHERE consolidation_id IN (SELECT consolidation_id FROM memory_consolidation_sources
                                 WHERE note_id = NEW.id AND live = 1);
END;
```

An `AFTER DELETE` twin does the same for `OLD.id`. `UPDATE OF` fires whenever
a column is in the `SET` list, and `save.rs` always sets `title`, `content`,
`tags`, `expires_at` and `valid_from`, so the `WHEN` clause compares each
listed column's old and new value: a save that changes only salience, evidence,
`contradicts` or counters does not invalidate. The columns listed are the
content, scope and validity columns; feedback counters and link columns
(`contradicts`, `evidence`) are not, so accepting a contradiction does not
invalidate the summary that proposed it. The trigger:

- **purges** the summary in place — title and content replaced by a tombstone,
  tags cleared, every stored version deleted (the version-capture trigger saves
  the old text, and the same body deletes it), its vectors and chunks deleted by
  the maintenance pass — so a narrowed, deleted or corrected source never
  survives in a wider summary, whether read by id or with `include_expired`;
- marks the consolidation `invalidated` and its sources not live, so the
  remaining sources can be grouped again;
- queues an `memory_invalidations` row, which the maintenance pass turns into
  an `agent.memory.consolidation_invalidated` ledger event carrying ids only,
  never content (a trigger cannot append to the hash-chained ledger).

The summary's topical edges are retired by the same maintenance pass.
`derives` edges to it remain, recording that it existed.

#### The contradiction workbench

Open, accepted `contradicts` links already lower a note's confidence. They
become reviewable:

- `memory_conflicts` lists only pairs where the caller can see **both** notes,
  including proposed ones, marked as such.
- `memory_conflict_resolve` records one of: accept a proposal, supersede A,
  supersede B, both valid over different ranges, or dismiss.
  - **Accept** writes the contradiction into `memory.contradicts` of the
    asserted source note and deletes the `proposed = 1` row; the mirror then
    creates the accepted edge.
  - **Both valid** sets `valid_to` on the earlier note and `valid_from` on the
    later one; this call is the only API that sets `valid_to` on an unsuperseded
    note. The default filter ignores `valid_to` without `as_of`, so both notes
    stay current in default search — intended: each is true for its range, and
    an `as_of` query tells them apart.
  - Every resolution closes the link.
- The resolver is the owner of both notes, or a human who can see both and
  holds `team_lead` or above in the organization. Writing `contradicts` or
  validity on a note the resolver does not own is the one stated exemption from
  the `not_owner` guard (`save.rs`); it is recorded with the resolver as actor.
- The review inbox renders both notes as escaped text; titles and content never
  become markup, commands or parseable fields.

### 5. Entity and wikilink graph leg

`ua-tools/src/families/graph.rs` is the planning canvas — an Excalidraw scene
store — not an edge store. The entity graph is the link and entity store from
§4, and the canvas can render from it.

**The leg**, with Python's caps: up to 5 seed notes from the content legs, at
most 16 entities per seed (`MAX_SEED_ENTITIES`), fanout 10 per seed, a scan
budget of fanout × 10, at most 20 notes from the leg, and an entity on more
than 25 notes is a hub and is not walked. Like Python, the leg walks both live,
accepted, unretired `memory_links` in either direction and notes sharing a
live entity.

**Eligibility comes before every limit.** Unlike the Python leg — which applied
its scan `LIMIT` and computed document frequency over every note in the
organization before eligibility — the scoped eligibility predicate sits inside
the innermost subquery, document frequency is counted over **eligible** notes
only, and only then are the scan budget and caps applied. Hidden notes
therefore cannot push an entity over the cap, change a neighbour's score or use
up the scan budget.

The leg joins fusion as one more `LEG_WEIGHTS` entry at a lower weight than the
content legs. `search.rs` stops dropping notes that only the graph leg found;
a note a content leg already matched gets no graph rank.

### 6. Context pack and post-run distillation

Agents across harnesses start cold. Memory should arrive without each one
remembering to search.

**`context_pack`** — a tool and an MCP resource. It **replaces** the unscoped
related-memory section of `session_packet`, which then calls it with the
caller's own credential, so a session grant's rule applies. Input: the caller,
optional `task_id`, optional query, a token budget, and optional `as_of`.
Output, in order until the budget is spent:

1. notes tied to the task by a `task:<id>` evidence ref (owner-only, §3), then
   by entity match on the task id, branch or project;
2. **decisions**: notes tagged `decision` with salience ≥ 0.7 at `org` or
   `team` visibility, limited to notes written by a verified human or confirmed
   by one;
3. the caller's own episodes from the last 14 days;
4. open, accepted contradictions touching anything already included.

**What may be injected.** Anything delivered by a hook into a session is
limited to notes **owned by a verified human** (`owner_type = 'human'` and
`owner_verified = 1`), or owned by an agent that is a seat of the caller's team
(the task's team when a task is given). Other matching notes are listed by id
and title only, as escaped text, for the agent to fetch deliberately. So an
arbitrary author cannot plant text into another team's session start by naming
its task or branch, and an anonymous note cannot borrow a human's name to get
in.

**Confirmation is recorded.** `memory_feedback` today only increments counters,
so "confirmed by a human" could not be evaluated. It now also writes a row:

```sql
CREATE TABLE IF NOT EXISTS memory_feedback_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id     TEXT NOT NULL,
    note_id    TEXT NOT NULL REFERENCES memory(id) ON DELETE CASCADE,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('human','agent')),
    actor      TEXT NOT NULL,
    kind       TEXT NOT NULL,
    at         TEXT NOT NULL
);
```

A note is human-confirmed when it has a `helpful` or upvote event from a
verified human.

**Determinism.** "Team" means the task's owning team when a task is given, else
every team the caller belongs to. Every item goes through the scoped filter,
carries its id, why it was included, its owners and the untrusted marker. The
token estimate uses the chunker's 4 characters per token. Ties break by note
id, so the same state and `as_of` produce the same pack. **Pack reads do not
count as recalls** and do not touch access counters, so `recall_maintenance`'s
"never recalled" signal stays meaningful.

**Delivery and fencing.** Delivery is per harness through harness-config
bundles: a session-start hook where the harness has one, otherwise a rules line
telling the agent to call `context_pack` first. Hook-injected text sits inside
a block delimited by a **random marker generated per pack** (128 bits), stating
that the block is recalled data, not instructions; any occurrence of the marker
in note text is removed before rendering, so a note cannot close the block
early.

**Distillation.** `memory_distill` is the structured successor of
`propose_session_learnings`. At session end, the bundle's stop hook asks the
agent to call it with outcome, decisions, learnings and open questions for its
session or run. The caller must own that session or run. The hub validates size
(each field and the total are capped) and writes one episode note with
`evidence` naming the session or run and the organization's default visibility
(with the same `team` fallback as above).

```sql
ALTER TABLE memory ADD COLUMN episode_key TEXT;   -- 'session:<id>' or 'run:<id>'
CREATE UNIQUE INDEX IF NOT EXISTS memory_episode_key
    ON memory (org_id, episode_key) WHERE episode_key IS NOT NULL;
```

Two concurrent first calls therefore produce one note; a repeat call updates
it. Episodes are what consolidation later groups.

## Privileged fields

`broadcast` tags and salience above 0.8 need a verified human with `org_admin`
or above in the note's organization — the same rule as the organization doc's
authority table. Today the check is "a verified human"; in `'default'` every
configured human is an `org_owner` after bootstrap, so existing behaviour
holds.

## Import and export

- `ua-import` maps `memory_embeddings`, `memory_chunks` (`chunk_index` → `idx`)
  and `memory_entities`, which today are unmapped. Imported vectors and chunks
  are **stale by construction**: their `model` becomes `import:<python model or
  unknown>`, which never equals an active identity, `content_sha` is empty and
  `dim` is computed from the blob, so the backfill re-embeds them rather than
  trusting freshness nobody can verify.
- From Python's `memory_links`, only `extends` and `derives` rows are imported
  (`asserted_by = src_id`); `supersedes`, `contradicts` and `evidence` are
  re-created by the mirrors from the imported columns, so each relation keeps
  one authority. Because rows arrive in source order, the importer runs the
  three mirror backfill statements (§4) after every run. Entity kind `project`
  is kept.
- The importer calls the `reown_for_user` hook (§3) for every `users` row it
  creates.
- A NULL source `org_id` becomes `'default'` (per the organization doc's
  mapping). Imported notes are written with `visibility = 'org'` and an
  explicit owner by the same rule as the backfill (human by `users` label, else
  agent, else organization), never left to the column default.
- `export.rs::GRAPH_TABLES` and the memory manifest columns gain `org_id`,
  `visibility`, `team_id`, `owner_type`, `owner`, `asserted_by`, `proposed` and
  `retired_at`, and the manifest fingerprint is versioned, so a retired edge
  never compares equal to a live one.

## Where the code lives

- `crates/ua-memory` (extracted in #49): everything in this document.
  `ua-tools` keeps only the registration. The organization doc's authority
  guard covers this crate too: today `note.rs` defines its own `is_human` and
  `lifecycle.rs` uses it for delete, restore and the privileged-field checks;
  those move to `ua-org::authz`.
- `ua-store` gains a `MemoryRepo` trait next to `OrgRepo`; `ua-memory` reaches
  the database only through it, and the authorizer hook enforces that. Today
  `Filter` binds `rusqlite` `SqlValue`s and `VectorIndex` takes a
  `&Connection`, and both are re-exported; the move redesigns them so the public
  surface carries a scope and plain values, and `rusqlite` stays inside the
  SQLite implementation. The bundled SQLite store stays the default; the trait
  is where another backend would plug in.

## Non-goals

- **Not a rewrite of the ranker.** Reciprocal-rank fusion, decay and salience
  priors stay as they are; BM25's formula and weights are unchanged, only the
  statistics it reads are scoped. New capability arrives as additional legs and
  passes.
- **Not a vector-database migration.** SQLite plus the embedding and chunk
  tables is adequate at the scale this hub runs. Revisit only with measurements.
- **Not cross-organization memory sharing.** Memory is tenant-scoped. A shared
  knowledge base is a separate design.
- **No model calls from the hub.** Summaries and episodes are written by agents,
  under their budgets, and validated by the hub. This deliberately drops the
  predecessor's hub-side adjudication and unreviewed auto-apply.
- **No cross-encoder reranking or model query rewriting** in this design.
  Each costs latency and a model dependency, and neither addresses the measured
  truncation gap.

## Considered for later

- **A second time axis.** `valid_from`/`valid_to` say when a fact was true, not
  when the hub learned it, so "as of X" today silently means "as known now".
  Adding `recorded_from`/`recorded_to` would make it bi-temporal, used to
  rerank rather than filter, so history is kept. It is deferred until the
  temporal class shows the gap.
- **Model-based entity extraction.** Entities here are deterministic
  identifiers and human-written `[[wikilinks]]`, so an edge is never a guess.
  Model-extracted entities are considered only if the graph leg leaves a
  measured relational gap, because a wrong edge silently degrades every
  traversal through it.

## Acceptance

Evidence and embeddings

1. **The eval gate runs first.** `ua memory bench` and the CI test report
   `recall@k` and MRR per class from checked-in vectors through a registered
   embedder, fail below the recorded floor, fail on a missing vector with the
   regeneration command, and fail if the paraphrase class ran lexical-only.
2. **Existing behaviour is unchanged.** The current memory test suite passes
   after the migration and backfill, apart from any test named in the PR under
   the `task:` evidence-ref rule (§3).
3. **Long documents.** A fact only in the last third of a 6,000-character note
   is recalled through its chunks; a note above 16 chunks embeds its first 16;
   chunk boundaries match the Python chunker on a non-ASCII note, on a note
   whose snap point is a newline, on one where snapping would leave under 800
   characters, and on one with `\x1c` padding; a long note's score is the
   maximum of its single and chunk scores.
4. **Staleness and backfill.** After an edit whose re-embed fails, the old
   vector is not scored; the maintenance pass backfills it; imported vectors are
   re-embedded, never scored as-is.
5. **Vector identity.** Vectors from two backends with the same model name are
   never compared; changing identity re-embeds.
6. **Embedder default and privacy.** A release build with a fetched model has
   vector recall with no configuration; with no model, `system_doctor` reports
   `DEGRADED` and triggers no download; save and search never download; an
   endpoint resolving to a non-loopback address is not used for an
   organization without `allow_remote_embedder`; a hostname that re-resolves
   to another address after the check, a redirect, and an `HTTP_PROXY` setting
   each fail to move a request off the checked address.
7. **Build.** CI builds and tests the `embeddings` feature; the release binary
   stays within the recorded size budget; the notices list ONNX Runtime.

Scope

8. **Differential isolation.** Inserting another organization's notes, another
   owner's `private` notes and another team's `team` notes — including ones
   sharing the query's terms and entities — leaves every corpus query's ids,
   order, raw lexical and semantic scores, counts, explanations and confidence
   fields identical, on every leg including chunks and graph — including when
   more than `FTS_LIMIT` hidden notes match the query (the cap applies after
   scoped scoring) — and the lexical leg's term forms equal FTS5's own
   tokenization for a query with stemming and diacritics.
9. **Every path is scoped.** A connection outside `MemoryRepo` and the
   allowlist is denied a memory read by the authorizer; each tool in the
   inventory returns nothing invisible; an invisible id produces the same
   `not_found` as a missing one.
10. **Idempotency and ledger.** Another principal reusing a `memory_save`
    idempotency key gets a fresh call and no hint of the first; ledger events
    for `private` and `team` notes carry ids only — no title, tags or content
    hash; `export_memory`
    exports only visible notes and writes to the vault only in `'default'`.
11. **Scoped confidence.** A hidden contradicting note changes neither a visible
    note's rank nor its `confidence_posterior`, and its id appears in no link
    list.
12. **Defaults fail closed.** An `INSERT INTO memory` omitting `visibility`,
    `owner` or `owner_verified` is caught by the insert-walking test; a saved
    note takes its organization's default; a new organization defaults to
    `private`; `'default'` is `org` after migration; with a `team` default, a
    caller in two teams saves `private`; `team` without `team_id`, or with
    another organization's team, is refused.
13. **Owners.** After migration and bootstrap, a note written by a configured
    human is owned by that `users` row; a hub owner bootstrapped after
    `memory.scope.v1` gets their notes re-owned through `reown_for_user`, and so
    does a user the importer creates; re-running bootstrap or import changes
    nothing further; the re-own runs through `MemoryRepo` and is not denied by
    the authorizer; a summary of an `org` group is owned by the organization.
    **Ownership proof:** every note the migration and the importer write has
    `owner_verified = 0`; a verified human's write has `1`, and an agent's,
    system caller's or anonymous caller's write has `0` even when it supplies a
    human `author`; `reown_for_user` never raises the flag; `attest-owners` is
    operator-only, refuses a label that is not a `users` row, writes ids only to
    the ledger, and is idempotent; no tool argument sets the column.
14. **Visibility changes.** Only the owner widens, and widening into a team
    needs membership; an `org_admin` cannot read, narrow or delete a `private`
    note they cannot see, and can narrow an `org` note; narrowing invalidates
    the note's consolidations and retires its topical edges; an anonymous
    caller cannot read or write `private` or `team` notes.
15. **Supersession.** Superseding an `org` note with a `private` or `team` one
    is refused; a note superseded by one the caller cannot see stays visible to
    that caller with `superseded_by` empty.
16. **Session grants.** A task-bound session reads only notes with that task's
    evidence ref, through every allowlisted tool including `session_packet`;
    a non-owner cannot add a `task:` ref; the session cannot overwrite or
    supersede; its writes carry `credential_id`.
17. **Promotion and privilege.** `memory_promote` refuses `private` and `team`
    notes and any call outside `'default'`; `broadcast` and salience above 0.8
    are refused to an agent and to a human below `org_admin`.

Links and consolidation

18. **Mirrors.** A save with a dangling or cross-organization `memory:` evidence
    ref succeeds and creates no edge; un-superseding a note removes its mirrored
    `supersedes` edge; accepting a proposed contradiction writes
    `memory.contradicts` and leaves no `proposed` row; a note inserted with
    `superseded_by`, `contradicts` or a `memory:` ref already set gets its edges
    on insert; notes that predate `memory.links.v1` get theirs from the
    backfill; running the backfill twice adds nothing.
19. **Consolidator eligibility.** No agent is handed a `private` group unless it
    is the owner, or its `owner_user_id` is the owning human **and** that human
    has `consolidate_private` on; an `org_admin` cannot set `owner_user_id` to
    another user or turn on someone else's `consolidate_private`, nor mint a
    credential for an owned agent without the owner's approval; a credential
    minted for an agent before its owner claimed it no longer works after the
    claim; no agent is handed a `team` group of a team it is not in; the
    grouping pass reads no title or content.
20. **Grouping.** With embeddings off, the same notes produce the same groups;
    a group never exceeds 20 sources or mixes scopes; a note is never a live
    source of two consolidations; the pass creates at most
    `consolidation_max_jobs` jobs.
21. **Idempotency.** Running the pass twice produces no duplicate summary and
    no orphaned edges; an expired lease is retaken; a retried commit returns the
    same summary; a commit after any source revision or scope change is
    refused; a restored identical source set can be consolidated again; a group
    whose scope has no eligible consolidator creates no job; an unclaimed
    `pending` row past `consolidation_job_ttl_hours` becomes `expired`, its
    sources return to groupable, and a fresh job for the same set is created;
    a claimed job is not expired by the TTL.
22. **Provenance and trust.** Every summary's evidence names its sources and
    every source has a `derives` link to it; a summary's prior and salience
    never exceed its sources' minimum and it cannot carry `broadcast`; when a
    source is in the results, the summary ranks directly below the best one;
    its trust marker lists the source owners; a proposed contradiction does not
    attenuate before acceptance.
23. **Invalidation purges.** Editing, narrowing, superseding or deleting a
    source leaves the summary's title and content as the tombstone through
    `memory_get` and `include_expired`, with no stored versions; the remaining
    sources are groupable again; an invalidation event with ids only reaches
    the ledger; `derives` edges remain. A save that rewrites a source with the
    same title, content, tags, scope and validity — changing only salience, an
    evidence ref, `contradicts` or counters — does not invalidate.
24. **Workbench.** A pair with one hidden side is not listed; a `member` who
    does not own both notes cannot resolve; "both valid" sets the two ranges,
    closes the link and leaves both notes in default search; rendered note text
    is escaped.

Graph, pack, distillation, import

25. **Graph.** Superseding an asserting note retires its topical edges and
    entities but not lineage; an edge asserted by two notes survives one
    retirement; the hub cap, fanout and scan budget count eligible notes only;
    a note found only by the graph leg is returned; a note's entities stop at
    64.
26. **Context pack.** Respects the token budget, includes only eligible notes,
    takes decisions only from verified-human-written or human-confirmed notes
    (by a `memory_feedback_events` row), injects only verified-human-owned or
    own-team notes — an anonymous note with a human `author` is listed by id and
    title only — does not change access or recall counters, survives a note
    containing the pack's marker without the block closing early, and is
    identical for the same state and `as_of`.
27. **Distillation.** Two concurrent first calls for one session leave one
    episode note; a repeat call updates it; an oversized field is refused; a
    caller that does not own the session is refused.
28. **Import and export.** A Python hub's embeddings, chunks, entities and
    `extends`/`derives` links import with `asserted_by = src_id`, NULL org
    mapped to `'default'`, explicit visibility and owners, and stale vectors;
    imported `supersedes`, `contradicts` and `evidence` edges come only from the
    mirrors and are all present after the run even when the superseding note
    was imported after the note it supersedes; a manifest compare distinguishes
    a retired edge from a live one.
29. **Bounded lexical leg.** A query with more than `MAX_QUERY_TERMS` distinct
    terms scores the first 32 in FTS5 order, identically on repeat; a query
    matching more than `MAX_LEXICAL_MATCHES` eligible notes scores a
    deterministic 10,000 and reports `lexical_truncated: true`; hidden notes
    never change which visible matches are scored; p95 stays under 100 ms on the
    100,000-note stopword-heavy bench case.
