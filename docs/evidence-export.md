# Evidence export and the independent verifier

Status: design, not implemented. Scope: track G2 (#2716). The export replaces
the `501` answers at `/api/evidence/*` and ships with a verifier so the format
is testable by someone who does not trust the hub.

## What this decides

An organization must be able to hand an outside party a file that proves:

1. **Who approved what** — a named, verified human approved this exact action,
   under this policy revision, at this point in the ledger.
2. **What an agent did** — the run, the attempt, the tool calls and the artifact
   revisions it produced or read.
3. **That the record is intact and was not edited afterwards** — verified
   offline, on a machine that has never talked to the hub.

This document fixes the bundle format, what is hashed, what a receipt binds, and
what `ua evidence verify` checks. It does not cover the provenance graph, SIEM
streaming, or retention; those are G3.

## Trust model

The verifier trusts exactly three things, and none of them is the hub:

| Trusted input | Why it is trusted | Where it comes from |
| --- | --- | --- |
| One or more Ed25519 public keys, by key id | The operator delivered them out of band | A file the verifier is given, never the bundle |
| A checkpoint the verifier already holds, or genesis | It was pinned when the export was first accepted | Operator or a prior verification |
| Its own recomputation | It is the verifier | The bundle plus the rules below |

Three claims are separate, and the output must keep them separate:

- **Integrity** — the bytes are what they were. Proven by recomputing each row's
  hash and, depending on the class, the ledger chain or the organization's
  running hash.
- **Authorship** — the holder of key `K` attested this checkpoint. Proven by the
  signature. The key is operator-held (`## Keys`), so this is not a claim that
  the hub process signed anything.
- **Completeness** — nothing was withheld from the stated range. Proven only
  *relative to a pinned checkpoint*, and the basis depends on the bundle class
  (next section): for a `hub` bundle, every global `seq` in the window appears
  exactly once and the chain from the end back to the pinned point is
  continuous; for an `org` bundle, that organization's rows occupy an absolute
  `org_seq` range `[pinned_count + 1 .. pinned_count + N]` whose running hash,
  cumulative count and the global window's bounding hashes are signed in the
  checkpoint — complete *relative to the hub's signed statement of the window*,
  not proof that the hub omitted nothing (see Bundle classes).
  Neither class can prove the hub did not end the range early; a verifier given
  a later pinned checkpoint can detect a shortened range, one that was not,
  cannot. The output says which case it is in.

This is the point of signing checkpoints rather than only hashing rows: anyone
with write access to the database can rewrite a row and recompute every
subsequent hash. A signature over a checkpoint is the only thing they cannot
recompute without the key. A bundle without a trusted signature proves
integrity, not authorship, and must say so.

## Bundle classes and what each can prove

`event_log` is one global chain and is never forked (`docs/organization.md`,
The ledger). An organization's export cannot carry the global `seq` of its
rows — the gaps would reveal hub-wide volume — and its rows are linked through
other organizations' rows, so it is not chain-continuous on its own. One
completeness rule therefore cannot serve both readers. A bundle declares its
class in `manifest.json`:

| Class | Rows | Sequence basis | Chain claim |
| --- | --- | --- | --- |
| `hub` | every row in the window | global `seq` | full: continuity back to the pinned checkpoint or genesis, no gaps, no duplicates |
| `org` | one organization's rows | `org_seq`, absolute from genesis in global `seq` order | each row's own hash, plus a per-organization running hash signed in the checkpoint; cross-organization linkage is reported as *not provable from this bundle* |

For an `org` bundle the checkpoint signs `{class: "org", org_id, window,
global_from_hash, global_head_hash, org_row_count, org_chain_hash, key_id,
signed_at}`:

- `org_seq` is **absolute** — the organization's cumulative row index from
  genesis — so a bundle covers `[pinned_count + 1, pinned_count + N]` and
  continuity across successive bundles is checkable against the pinned
  checkpoint's count instead of restarting at 1 in every file.
- `org_chain_hash` is the fold `H(prev_org_chain_hash || entry_hash)` over that
  organization's rows from genesis, seeded from the pinned checkpoint's value
  (empty at genesis). `org_row_count` is the cumulative count at the window's
  closing row, not the number of rows in this bundle.
- `global_from_hash` is the `entry_hash` of the global row the window starts
  after, and `global_head_hash` the `entry_hash` of its closing row. They pin
  where the window sits on the global chain by hash alone: the checkpoint
  carries **no global sequence number**, because two endpoints would be
  subtracted to recover the hub-wide row count for the window — the volume
  `docs/organization.md` keeps out of an organization's export. A holder of a
  hub checkpoint locates both hashes in the global chain itself.
- `window` is the export window's time bounds, not a sequence range.

The verifier recomputes each row's `entry_hash` under its `hash_v`, checks
`org_seq` runs from `pinned_count + 1` to `pinned_count + N` with no gap or
duplicate, refolds the running hash, and compares both against the signed
values. When a later hub checkpoint or a `hub` bundle is available it also
resolves `global_from_hash` and `global_head_hash` in the global chain and
confirms the window sits where the hub places it.

That proves the organization's own rows were neither edited, reordered nor
dropped *relative to the hub's signed statement of the window*. It cannot, by
itself, prove the hub included every row it held: `org_seq`, the fold, the
count and the window hashes are all produced by the same hub at export time, so
a row omitted mid-window yields a bundle that is internally consistent.
Detecting that omission needs the global chain — a `hub` bundle, or a verifier
that can resolve the signed hashes against a later hub checkpoint.
The verdict prints the class and this limitation, so a reader cannot mistake
the narrower claim for the wider one.

## Bundle layout

```text
bundle/
  manifest.json            # class, format version, window, counts, every hashed file with sha256
  manifest.sig             # Ed25519 signature over manifest.json's digest
  producer.json            # export time, host, tool version — reported, never hashed
  ledger/events.jsonl      # canonical JSON, one event per line, ascending seq (hub) or org_seq (org)
  ledger/checkpoint.json   # {class, seq|global_from_hash,global_head_hash,org_row_count,org_chain_hash, key_id, signed_at, signature}
  approvals/<id>.json      # one receipt per approval in range
  evidence/rows.jsonl      # evidence records and their labels
  policy/revisions.json    # the policy revisions the receipts cite
  artifacts/index.json     # artifact id, revision, sha256, size, media type
  withheld.json            # classes deliberately left out, with counts
```

Rules that make the bundle verifiable:

- **Canonical JSON for bundle files** (sorted keys, integers only, RFC 3339 UTC,
  no floating point, no `null` vs absent ambiguity). This is the bundle encoder,
  defined here; it is **not** the ledger's row-hash encoder. Ledger rows are
  re-hashed with the encoder their `hash_v` names, because imported Python rows
  were hashed over a form that accepts floats and must keep verifying.
- **One ordering**: events by `seq` (class `hub`) or `org_seq` (class `org`),
  receipts by approval id, artifacts by id. No maps keyed by something the
  writer chooses.
- **Export metadata is outside the hashed set.** Export time, host and tool
  version live in `producer.json`, a separate file that is not listed in the
  manifest and not covered by the bundle digest. The verifier reports it and
  never treats it as evidence.
- **No content by default.** Artifacts are referenced by hash and size.
  Including bytes is opt-in per export and changes the bundle class.

## What is hashed, and under which version

The ledger already versions its hash form (`docs/organization.md`, The ledger):

- `hash_v = 1` covers nine fields and is what imported and pre-tenancy rows use.
- `hash_v = 2` covers the same nine plus `org_id`.
- The verifier selects the form per row from `hash_v`, refuses any other value,
  and refuses a `hash_v = 1` row whose `seq` is after the first `hash_v = 2` row.

On top of that:

- `manifest.json` carries a `sha256` per hashed file. The bundle digest is the
  hash of the manifest with the `digest` field removed; `producer.json` is not
  in the manifest and therefore not covered.
- A receipt's digest is the hash of its canonical body. Receipts carry no
  signature of their own: their digests travel in the manifest, and the
  manifest is what the checkpoint signature covers. Authorship of a receipt is
  therefore "the holder of key `K` attested this checkpoint and the manifest it
  signs", not a per-receipt signature.
- A checkpoint's signature covers `{class, format, org_id, seq, hash, key_id,
  signed_at}` for class `hub` and `{class, format, org_id, window,
  global_from_hash, global_head_hash, org_row_count, org_chain_hash, key_id,
  signed_at}` for class `org`. `format` is the domain tag
  `ua.evidence.checkpoint.v1`, so a signature over a checkpoint cannot be
  replayed as a signature over a different object type.

## The approval receipt

One receipt per approval. The receipt is what makes an approval auditable
without replaying the whole hub.

| Field | Meaning |
| --- | --- |
| `receipt_id` | Deterministic: hash of the fields below |
| `approval_id`, `org_id` | The row this receipt is about |
| `tool`, `action_digest` | The governed action and the hash of its canonical payload |
| `request_digest` | Hash of the request as the requester submitted it |
| `policy_revision`, `policy_digest` | The policy in force when it was decided |
| `requester` | Identity label, kind (`human`/`agent`/`service`) |
| `resolver` | Identity label, kind, and transport (`ui`, `http`, `mcp`, `cli`, `slack`) |
| `decision`, `reason` | `approved` or `denied`, with the recorded reason |
| `decided_at`, `expires_at` | Decision time and any one-time window |
| `ledger` | `{seq, hash}` (class `hub`) or `{org_seq, hash}` (class `org`) of the event that recorded the decision |
| `run_id`, `attempt` | The execution the approval authorizes, if any |
| `covers` | Artifact revisions (`id`, `sha256`) the approval is bound to |

A receipt carries no signature of its own. Its digest is listed in the manifest,
which the operator's checkpoint signature covers, so a receipt's authorship is
the signer's attestation of the bundle, not a separate per-receipt key.

Binding rules the verifier enforces:

- The `action_digest` must match the payload in the event. A changed payload
  needs a new approval; a receipt for a different payload is a refusal, not a
  warning.
- A one-time approval names the revisions it covers. A release at a different
  revision is refused even if the approval is still live.
- `resolver` must be a verified human and must differ from `requester` where
  separation of duties applies. A receipt that cannot show this fails.

## What `ua evidence verify` checks

Exit codes: `0` verified, `1` refused (with a machine-readable reason and the
offending sequence or field), `2` cannot verify (missing input, unknown key,
unsupported version). A refusal is never downgraded to a warning.

1. **Format.** Version known; every file in the manifest present; no extra files
   counted as evidence.
2. **Manifest digest and per-file digests.**
3. **Checkpoint signature** against the pinned anchor. An unknown key id is `2`,
   never a pass; a key read from the same database is reported as
   `valid_in_store_only` and is not authorship.
4. **Row hashes and chain continuity.** Every row's `entry_hash` is recomputed
   under its `hash_v`. For class `hub`, continuity is checked from the
   checkpoint back to the pinned point or genesis. For class `org`, continuity
   is the signed running hash (check 5).
5. **Sequence basis.** Class `hub`: every global `seq` in the window appears
   once, in order, with no gap or duplicate. Class `org`: `org_seq` runs from
   `pinned_count + 1` to `pinned_count + N` with no gap or duplicate, the
   refolded `org_chain_hash` and the cumulative `org_row_count` equal the signed
   values, and — when a later hub checkpoint is available — the signed
   `global_from_hash` and `global_head_hash` resolve in the global chain with
   the bundle's rows between them. A mismatch is a refusal; an `org` bundle
   with no pinned checkpoint or hub cross-check reports completeness as
   `unverified`, never as a pass.
6. **Downgrade refusal** — a `hash_v = 1` row after the first `hash_v = 2` row.
7. **Receipts** — digest matches the manifest, `action_digest` matches the event
   payload, resolver is a verified human, separation of duties holds, `covers`
   matches the artifact index. Separation of duties is taken from the action's
   approval rule as captured in `policy/revisions.json` (today that is
   `config_revision_manage`'s "a human other than the requester",
   `docs/policy.md` → Config revisions). Where the rule has no such clause the
   claim is reported as `not-applicable`, never as a pass.
8. **Cross-links** — every approval event has a receipt and every receipt has an
   event; `ledger.seq`/`ledger.org_seq` and `ledger.hash` in the receipt resolve.
9. **Trace** — for each artifact: artifact → task → run/attempt → policy
   revision → approval. A missing link is a refusal, not a blank field.
10. **Private content** — a bundle containing a record marked private, a secret
    value, or a message body marked private is refused.
11. **Unhashed or legacy rows** — reported explicitly with their count and
    sequence range; never silently accepted as verified.
12. **Withheld classes** — `withheld.json` is reported as part of the verdict, so
    a reader knows what the bundle deliberately does not contain.

The verifier also prints the three claims separately (`integrity`, `authorship`,
`completeness`) with the basis for each, so a reader cannot mistake "hashes
match" for "the hub is honest".

## Keys

- Ed25519. The key id travels in the checkpoint; the public key never travels in
  the bundle.
- Rotation: old public keys stay in the verifier's trust file so old bundles
  still verify; a bundle signed by a key the verifier does not have is `2`.
- Revocation: a retired key stays in the store so older bundles verify, but a
  revoked key is refused outright and every checkpoint naming it no longer
  verifies. Revocation is authoritative at the trust anchor, not in the
  database: the verifier stops pinning the key, passes `--revoked-key-id`
  (repeatable), or lists the key id in `--trust-file` (`revoked_key_ids`), and
  a checkpoint or bundle signed by a key on that list exits `2` even if the
  database's `revoked_at` column was cleared. The store's `revoked_at` is
  advisory — it is a convenience for the hub's own CLI, and anyone who can
  write the database can clear it.
- Trust anchor: the key row sits in the same database as the checkpoint, so a
  verifier that trusts it is trusting the database it protects. `ua evidence
  verify` therefore takes `--anchor-key` and `--anchor-key-id` (or
  `--trust-file`, which holds rotated `keys` and `revoked_key_ids`) obtained
  out of band. Without a pinned anchor or trust file the verdict is
  `valid_in_store_only`, which is not authorship and exits `2`.
- Custody is operator-held (decided 2026-11-22): the hub never holds the signing
  key. It writes the checkpoint row and its JSON file (`checkpoint --out`), and
  the operator signs that checkpoint file offline with `sign --checkpoint-file`,
  which recomputes the digest locally and displays every field before signing,
  so the operator never signs an opaque digest handed over by a compromised hub.
  A hub-owned key would protect only against database editors, which the hash
  chain already covers.
- The offline commands (`key-generate`, `sign`) do not open or create a hub
  database. They read and write key and checkpoint files only, and zeroize seed
  buffers in memory on drop.

## What must never be in a bundle

Managed secret values, provider credentials, tokens, passkeys, session
credentials, and message bodies marked private. Export refuses to write them;
the verifier refuses to accept a bundle that contains a record marked private.
`withheld.json` names the classes and counts, so absence is visible rather than
silent.

## Testability

The format is testable without a hub:

- Fixtures in the repository: one good bundle of each class, one with a flipped
  byte, one with a dropped event, one with a reordered pair, one `org`-class
  bundle missing a row inside its own range, one signed by an unknown key, one
  with a receipt bound to a different payload, one containing a private record.
- Property tests: for any valid bundle, flipping one byte anywhere in a hashed
  file refuses; dropping or duplicating a sequence (global or `org_seq`)
  refuses; re-signing the checkpoint with a different key refuses.
- The producer's own `verify.json` is never trusted; the verifier recomputes.

## Slices and gates

| Slice | Content | Gate |
| --- | --- | --- |
| S1 | This document | Normal review |
| S2 | Checkpoint signing and the key store | Red tier — ledger semantics |
| S3 | `ua evidence export` and the bundle writer | Red tier — data egress |
| S4 | `ua evidence verify` CLI and fixtures | Ships with S3 |
| S5 | A receipt for every approval, resolved at decision time | Red tier — approval semantics |
| S6 | Anchor: the signed commit is recorded in the manifest and its signature verified | Red tier |

S3 without S2 is not shippable: an unsigned bundle proves integrity only, and
shipping it would invite the wrong reading.

## Decisions (recorded 2026-11-22)

1. **Anchor: a signed git commit in a repository the organization controls.** No
   timestamp authority is added. The bundle records the anchor commit and the ref
   it sits on; the verifier checks that commit's signature against a pinned key
   and reads the time from the commit. The manifest's `anchor` object keeps a
   class field so an RFC 3161 token can be added later without a format change;
   an anchor class the verifier does not know is `2` (cannot verify), never a pass.
2. **Artifact content: hash-only by default.** Content inclusion is opt-in per
   export and recorded in the manifest class.
3. **Key custody: operator-held.** The signing key is held offline by the owner
   and never by the hub process. The hub assembles the bundle and writes the
   checkpoint digest; signing is a separate operator step over that digest. A
   hub-held key would only protect against database editors, which the hash chain
   already covers, and it would let a compromised hub forge an export.
4. **Two bundle classes, because tenancy and chain continuity conflict.** The
   ledger stays one global chain, but an organization's export carries no global
   `seq` and is not chain-continuous (`docs/organization.md`, The ledger). An
   `org` bundle therefore proves integrity, authorship and completeness over
   that organization's own `org_seq` range against a signed running hash and
   count; cross-organization linkage is reported as not provable from the
   bundle. A whole-hub `hub` bundle keeps global-`seq` chain continuity and is
   operator-only. Receipts carry no signature of their own — the manifest
   carries their digests and the checkpoint signature covers it. This replaces
   the earlier single whole-hub assumption (review, 2026-11-22).


## S2: the key store and checkpoint signing

Implemented in `crates/ua-store/src/evidence.rs` and the `ua evidence` CLI.
The hub never holds a private key: it writes a checkpoint row and its digest,
and the operator signs that digest offline.

- **Key store.** `evidence_key` holds public keys only — `key_id`, the
  algorithm (`ed25519`), the 32-byte public key as hex, when it was added, and
  optional retirement and revocation times. A retired key still verifies old
  bundles; it only stops new checkpoints naming it. A revoked key is refused
  outright and every checkpoint naming it stops verifying. There is no
  private-key column and no path that would add one.
- **Checkpoint rows.** `evidence_checkpoint` holds one row per checkpoint:
  its class, the class's signed fields, the digest, the key id, and the
  operator's signature once attached. `evidence_key_store.v2.checkpoint_checks`
  enforces per-class column invariants (`hub` rows carry `seq`/`hash` and
  `org_id IS NULL`; `org` rows carry the window/chain fields and a non-null
  `org_id` that exists in `orgs`) via `BEFORE INSERT` triggers alongside
  Rust-side validation in `checkpoint_write`. `checkpoint_write` also checks a
  `hub` checkpoint's `(seq, hash)` against `event_log` before inserting, so a
  wrong row cannot be stored permanently. A row is signed once; `attach`
  verifies the signature against the stored public key and recomputed digest
  before storing it so a typo or wrong key does not lock the row, and a second
  signature is refused so the row cannot hide which key attested it.
- **The digest.** The signed value is the raw 32-byte SHA-256 of one canonical
  JSON object holding exactly the class's fields with sorted keys and explicit
  `null`s, plus the domain tag `format: "ua.evidence.checkpoint.v1"` so a
  signature cannot be replayed over a different object type. The canonical
  encoding is the ledger's: `,`/`:` separators and non-ASCII escaped as
  `\uXXXX`. The signature is Ed25519 over the raw digest bytes, not over the
  hex text. A row whose stored fields no longer hash to the stored digest is
  reported as a digest mismatch, never as a pass.
- **The ledger anchor.** A `hub` checkpoint is checked against `event_log`:
  its `seq` must exist, its `hash` must equal that row's `entry_hash`, and the
  chain must verify through that `seq`. A made-up sequence or hash is refused at
  write time (`checkpoint_write`) and reported as a ledger mismatch on
  `verify`, never as a pass.
  - *DB-side consistency check:* `verify` also re-checks every earlier signed
    `hub` checkpoint (`seq <= checkpoint.seq`) still present in
    `evidence_checkpoint` — **always** recomputing its digest and comparing
    `event_log[prev_seq].entry_hash` (`ledger_mismatch`, exit `1`, on any
    mismatch), even when the signer is revoked. **Database state alone never
    relaxes a check:** only the verifier's own revocation list
    (`--revoked-key-id` or `--trust-file`'s `revoked_key_ids`) may skip an
    earlier checkpoint's *signature* check while keeping exit `0` (recording a
    `warnings` entry on `valid`). Pass `--revoked-key-id` only when you
    independently know that key was compromised, because anyone with database
    write access can set `evidence_key.revoked_at`. Because its signature check
    is skipped once revoked in the verifier's trust, a revoked key's
    checkpoints in `evidence_checkpoint` detect only a careless ledger rewrite
    (where `event_log` and the checkpoint row disagree); out-of-band pinning
    (`--prev-checkpoint` or `signed_checkpoints` in `--trust-file`) is the only
    protection for those `seq`s. When the verifier supplied
    a pinned key for `prev.key_id`, `verify` always checks the store key row
    and Ed25519 signature (`ledger_mismatch`, exit `1`, if the key row is
    missing/altered or the signature fails); if digest, `entry_hash`, and
    signature all verify against the supplied key, the witness is accepted
    despite `evidence_key.revoked_at` (with a `warnings` note, exit `0`). When
    no pinned key was supplied for `prev.key_id` and it is marked revoked in
    `evidence_key.revoked_at` (without verifier revocation) or missing from
    `evidence_key`, `verify` returns `witness_skipped` (exit `2`) after
    checking `entry_hash`. An earlier checkpoint signed by a non-revoked
    rotated-out key not present in the verifier's trust material still has its
    digest and `entry_hash` checked and adds a benign `warnings` entry on
    `valid` (exit `0`). Because an attacker with SQLite write access could drop
    triggers to delete an earlier row or clear its `signature`, the DB-side
    check alone is a consistency check rather than full tamper-evidence.
  - *Out-of-band tamper-evidence:* `verify` accepts records held outside the
    hub database via repeatable `--prev-checkpoint <file>` flags (pointing at
    local copies of previously signed checkpoint files) and/or a
    `signed_checkpoints` list of `{"checkpoint_id", "seq", "hash", "digest"}`
    entries in `--trust-file`. Every supplied record must match `event_log`,
    exist as a signed `hub` row in `evidence_checkpoint` with matching
    `(seq, hash, digest)`, and pass signature verification against the pinned
    key — pinned records always fail hard on any mismatch, including a revoked
    signer. Supplying out-of-band records closes history rewrites combined with
    checkpoint deletion or cleared signatures.
- **The trust anchor and revocation.** The key row is in the same database as
  the checkpoint, so a verifier that trusts it is trusting the database it
  protects. `verify` takes either a pinned key (`--anchor-key` and
  `--anchor-key-id`, both required together) or a local JSON `--trust-file`
  (`{"keys": [{"key_id": ..., "public_key": ...}], "revoked_key_ids": [...],
  "signed_checkpoints": [{"checkpoint_id": ..., "seq": ..., "hash": ...,
  "digest": ...}]}`; unknown fields on the file, any key entry, or any pinned
  checkpoint entry are refused),
  plus optional repeatable `--revoked-key-id` and `--prev-checkpoint` flags.
  Without a pinned key or trust file the verdict is `valid_in_store_only`,
  which is not authorship. Verifier-side revocations (`--revoked-key-id` and
  `revoked_key_ids`) are authoritative and return `key_revoked` (exit `2`) even
  if `revoked_at` in the database is cleared.
- **Confirming continuity before signing.** `ua evidence checkpoint --out
  <file>` writes the checkpoint's fields along with the hub's most recent
  previously signed checkpoint head (`previous_signed`). When signing offline,
  `ua evidence sign --key-file <key> --checkpoint-file <file>` recomputes the
  digest locally from the checkpoint fields (refusing if an embedded `digest`
  disagrees) and prints every field, the recomputed digest, and the previous
  signed checkpoint head to stderr before signing. Operators should keep a
  local copy of each checkpoint file they sign and pass
  `--prev-checkpoint <prev-file>` when signing the next one: `sign` checks
  offline progression against the local previous head (strictly higher `seq`
  for `hub`; matching `global_head_hash` → `global_from_hash` and
  non-decreasing `org_row_count` for `org`) and refuses if the hub's reported
  `previous_signed` disagrees with the operator's local copy. Because `sign`
  runs offline without the ledger, `--prev-checkpoint` on `sign` checks `seq`
  monotonicity and hub-reported `previous_signed` equality only — it does not
  by itself prove the hub did not rewrite `event_log` prior to the earlier
  `seq`. To get tamper-evident continuity across checkpoints on `verify`, pass
  your local copies with `--prev-checkpoint <file>` (repeatable) or record them
  under `signed_checkpoints` in `--trust-file`.
- **The commands and exit codes.** `ua evidence key-generate` writes a 0600
  seed file on the operator's machine and prints the public key; `key-add`,
  `key-retire` and `key-revoke` maintain the store; `checkpoint` writes a row
  and prints/writes its checkpoint JSON and digest (`--org` is refused on
  `hub`); `sign --checkpoint-file` recomputes the digest, displays the fields
  and previous head, and signs offline with the seed file; `attach` verifies
  and stores the signature; `verify` recomputes the digest, checks the ledger
  anchor (including the DB-side consistency check over earlier signed `hub`
  checkpoints and any out-of-band `--prev-checkpoint` / `signed_checkpoints`
  records) and verifies signatures against the pinned key or trust file.
  `verify` exit codes:

  | Exit code | Meaning | States / conditions |
  |---|---|---|
  | `0` | Verified | `valid` — including when `warnings` notes a non-revoked rotated-out earlier key not supplied in the verifier's trust (`signature not verified: no pinned key supplied`), a witness whose signature check was skipped by the verifier's own `--revoked-key-id` / `revoked_key_ids` (digest and `entry_hash` still checked), or a witness that verified against a verifier-supplied key despite DB `revoked_at` |
  | `1` | Refused | `digest_mismatch`, `ledger_mismatch` (including an earlier witness missing from `evidence_key` when the verifier supplied a pinned key for it), `invalid_signature`, `key_mismatch` |
  | `2` | Cannot verify | `unsigned`, `unknown_key`, `key_revoked`, `valid_in_store_only`, `witness_skipped` (an earlier witness with no supplied key whose signer is DB-revoked without verifier revocation or missing from `evidence_key`), `org_class_not_verifiable`, or any missing/invalid input, config, open/schema-fence, or database error |

  `key-generate` and `sign` are offline: they do not open or create a hub
  database. Key and checkpoint changes are appended to `event_log`
  (`evidence.key.added`, `evidence.key.retired`, `evidence.key.revoked`,
  `evidence.checkpoint.written`, `evidence.checkpoint.signed`).
