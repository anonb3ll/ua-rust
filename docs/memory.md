# Memory subsystem

Status: **design, not implemented.** This document designs the pieces the
memory family does not yet have. It is not a plan to rebuild what exists.

## Correction to the brief

An earlier task description claimed temporal validity, salience and hybrid
retrieval were missing. Verified against `e56fce8`, they are present and
implemented. This document is written against the code, not that description.

## What already exists

The ranking layer is further along than the file names suggest. Do not rebuild
it.

| Capability | Where | State |
|---|---|---|
| Hybrid retrieval, reciprocal-rank fusion over lexical + semantic + recency legs | `memory/rank.rs` (`RRF_K`, `LEG_WEIGHTS`), `memory/search.rs` (`competition_ranks`) | Present |
| BM25 with per-field weights (title 3.0, content 1.0, tags 2.0) | `rank.rs::BM25_WEIGHTS` | Present |
| Semantic leg with staleness detection (`content_sha` per vector) | `memory/embed.rs`, `memory_embeddings.v1` | Present |
| Temporal validity and supersession | `memory.valid_from`, `valid_to`, `superseded_by` | Present |
| Salience, recency decay, reinforcement, voting | `salience`, `access_count`, `recalled_count`, `upvoted_count`, `RECENCY_HALF_LIFE_DAYS=15`, `DECAY_MONTHS=6`, `W_SALIENCE/W_FEEDBACK/W_VOTE` | Present |
| Contradiction attenuation and open-link surfacing | `contradicts`, `CONTRADICTION_BETA`, `MAX_COUNTED_CONTRADICTIONS`, `note.rs` | Present |
| Versioning, 50 versions per note, trigger-captured | `memory_versions.v1` | Present |
| Maintenance pass: pruning candidates, staleness, low confidence | `memory/maintenance.rs` (report-only) | Present |

A note on the honest ceiling: this ranker is competitive. The claim that the
result is "as good as or better than a leading memory system" is currently
**unfalsifiable**, because nothing measures retrieval quality — see
[Evidence](#4-evidence).

## The four gaps

### 1. Consolidation (reflection)

Nothing turns episodes into durable notes. A search of the memory family for
`consolidat` or `summariz` returns zero hits. The consequence is structural: the
store grows monotonically, each new note dilutes the index, and recall quality
falls as volume rises even though every individual note is fine.

Design:

- A scheduled pass, run by the hub rather than by a caller, groups recent
  unconsolidated notes by shared tags and entity overlap.
- For each group above a size threshold it writes one summary note, with
  `epistemic = 'inferred'` and `evidence` naming the source note ids.
- Provenance is recorded both ways: the summary lists its sources, and each
  source gains an edge to the summary. A summary is not allowed to outrank its
  own sources for a query that matches a source specifically — the ranker
  already gives recency and salience weight, so this needs a check rather than a
  new mechanism.
- The pass is **idempotent**: a group already consolidated is skipped, and a
  re-run after a failure produces no duplicate summary. Consolidation state must
  be recorded, not inferred from timestamps.

This is the headline piece of work.

### 2. Scoped recall

There is no visibility tier on memory, so recall cannot be constrained by
tenant or team. This depends on the organization spine (the `org_id` partition
key), and should not be faked before it lands.

Design:

- `memory` gains `org_id` (from the spine) and `visibility`
  (`private` / `team` / `org`), default `private` — the safe default, because a
  note that is accidentally public is worse than one that is accidentally
  private.
- Enforcement happens **in the search SQL**, in the same `WHERE` as the FTS
  match, never as a post-filter over results. A post-filter leaks through
  ranking side channels: if the count and order change, an unauthorized caller
  learns that a note exists.
- `private` is visible to its author; `team` to members of the author's team
  through `team_members`; `org` to every member of the organization.

### 3. Entity graph linkage

`crates/ua-tools/src/families/graph.rs` is an unconnected canvas: it has no
edges to memory notes, so retrieval can only match text and vectors, never
traverse from a note to the things it mentions.

Design:

- Extend the existing graph rather than introducing a second store, so there is
  one graph and one set of edges.
- An edge between a note and an entity carries a relation label and the note
  that asserted it, so the edge is attributable and can be retired when its
  asserting note is superseded.
- Retrieval gains an optional third leg: notes one edge away from a matched
  entity, at lower weight than a direct match. This slots into the existing
  fusion as one more leg with its own `LEG_WEIGHTS` entry rather than a
  parallel scorer.

### 4. Evidence

There is no recall-quality evaluation, so the product claim cannot be tested.
Unit tests prove that the code does what it says; they do not prove that the
retrieval is good.

Design:

- A checked-in fixture corpus with labelled queries: for each query, a small set
  of notes that must appear and a set that must not.
- Report `recall@k` and mean reciprocal rank per query class — exact-term,
  paraphrase, temporal ("as of date X"), and contradiction.
- Run it in CI as a **regression gate with a floor**, not a pass/fail on a
  moving target: a change that drops recall below the recorded floor fails.
- The corpus must include at least one case for each of the four gaps above, so
  consolidation and scoping are measured once they land.

Without this, every later change to the ranker is a guess.

## Suggested order

1. **Evidence first.** Build the fixture corpus and the harness before touching
   ranking or adding consolidation. It is the only way to tell whether the next
   two steps help.
2. **Consolidation**, measured against the corpus.
3. **Scoped recall**, after the organization spine lands.
4. **Entity graph linkage**, which depends on 2 and 3 being stable.

Putting evidence first is deliberate. Every other item here changes retrieval
behaviour, and without a measurement a change that looks better in one query is
indistinguishable from one that quietly broke ten others.

## Non-goals

- **Not a rewrite of the ranker.** Reciprocal-rank fusion, decay and salience
  priors stay as they are. New capability arrives as additional legs and passes.
- **Not a vector-database migration.** SQLite plus the existing embedding table
  is adequate at the scale this hub runs. Revisit only with measurements.
- **Not cross-organization memory sharing.** Memory is tenant-scoped. A shared
  knowledge base is a separate design.

## Acceptance

1. **Consolidation is idempotent** — running the pass twice produces no
   duplicate summary and no orphaned edges.
2. **Provenance is complete** — every summary note names its sources and every
   source has an edge to its summary.
3. **Scoping holds** — with the organization spine, a caller in organization B
   receives zero notes from A, and the result count does not reveal that A has
   matches.
4. **Visibility defaults closed** — a note created without an explicit
   visibility is `private`, and a test asserts it.
5. **The eval gate runs** — the fixture corpus reports `recall@k` and MRR in CI
   and fails below the recorded floor.
6. **Existing behaviour is unchanged** — the current memory test suite passes
   untouched.
