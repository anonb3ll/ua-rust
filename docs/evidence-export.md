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

- **Integrity** — the bytes are what they were. Proven by recomputing hashes and
  the ledger chain.
- **Authorship** — the hub holding key `K` produced this checkpoint. Proven by
  the signature.
- **Completeness** — nothing was withheld from the stated range. Proven only
  *relative to a pinned checkpoint*: a bundle shows every sequence number in
  `[from, to]` exactly once and that the chain from `to` back to the pinned
  point is continuous. It cannot prove the hub did not decide to end the range
  early. A verifier that was given a pinned checkpoint from a later time can
  detect a shortened range; one that was not, cannot. The output says which case
  it is in.

This is the point of signing checkpoints rather than only hashing rows: anyone
with write access to the database can rewrite a row and recompute every
subsequent hash. A signature over a checkpoint is the only thing they cannot
recompute without the key. A bundle without a trusted signature proves
integrity, not authorship, and must say so.

## Bundle layout

```text
bundle/
  manifest.json            # format version, range, counts, every file with sha256
  manifest.sig             # Ed25519 signature over manifest.json's digest
  ledger/events.jsonl      # canonical JSON, one event per line, ascending seq
  ledger/checkpoint.json   # {seq, hash, key_id, signed_at, signature}
  approvals/<id>.json      # one receipt per approval in range
  evidence/rows.jsonl      # evidence records and their labels
  policy/revisions.json    # the policy revisions the receipts cite
  artifacts/index.json     # artifact id, revision, sha256, size, media type
  withheld.json            # classes deliberately left out, with counts
```

Rules that make the bundle verifiable:

- **Canonical JSON everywhere** (sorted keys, integers only, RFC 3339 UTC, no
  floating point, no `null` vs absent ambiguity). The same encoder the ledger
  uses for hashing.
- **One ordering**: events by `seq`, receipts by approval id, artifacts by id.
  No maps keyed by something the writer chooses.
- **Export metadata is outside the hashed set.** Export time, host and tool
  version live in `manifest.json` under `producer`, which the verifier reports
  but never treats as evidence.
- **No content by default.** Artifacts are referenced by hash and size.
  Including bytes is opt-in per export and changes the bundle class.

## What is hashed, and under which version

The ledger already versions its hash form (`docs/organization.md`, The ledger):

- `hash_v = 1` covers nine fields and is what imported and pre-tenancy rows use.
- `hash_v = 2` covers the same nine plus `org_id`.
- The verifier selects the form per row from `hash_v`, refuses any other value,
  and refuses a `hash_v = 1` row whose `seq` is after the first `hash_v = 2` row.

On top of that:

- `manifest.json` carries a `sha256` per file. The bundle digest is the hash of
  the manifest with the `digest` field removed.
- A receipt's digest is the hash of its canonical body with `signature` removed.
- A checkpoint's signature covers `{org_id, seq, hash, key_id, signed_at}` in
  canonical form.

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
| `ledger` | `{seq, hash}` of the event that recorded the decision |
| `run_id`, `attempt` | The execution the approval authorizes, if any |
| `covers` | Artifact revisions (`id`, `sha256`) the approval is bound to |
| `signature`, `key_id` | Hub signature over the receipt body |

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
3. **Checkpoint signature** against a trusted key id. An unknown key id is `2`,
   never a pass.
4. **Chain continuity** from the checkpoint back to the pinned point or genesis,
   recomputing each row's hash under its `hash_v`.
5. **No gaps, no duplicates, no reordering** across `[from, to]`.
6. **Downgrade refusal** — a `hash_v = 1` row after the first `hash_v = 2` row.
7. **Receipts** — signature, `action_digest` matches the event payload, resolver
   is a verified human, separation of duties holds, `covers` matches the
   artifact index.
8. **Cross-links** — every approval event has a receipt and every receipt has an
   event; `ledger.seq`/`hash` in the receipt resolve.
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
- Custody is a decision, not a default (see open questions). The hub holding the
  key protects against database editors, not against the hub's operator.

## What must never be in a bundle

Managed secret values, provider credentials, tokens, passkeys, session
credentials, and message bodies marked private. Export refuses to write them;
the verifier refuses to accept a bundle that contains a record marked private.
`withheld.json` names the classes and counts, so absence is visible rather than
silent.

## Testability

The format is testable without a hub:

- Fixtures in the repository: one good bundle, one with a flipped byte, one with
  a dropped event, one with a reordered pair, one signed by an unknown key, one
  with a receipt bound to a different payload, one containing a private record.
- Property tests: for any valid bundle, flipping one byte anywhere in a hashed
  file refuses; dropping or duplicating a sequence refuses; re-signing the
  checkpoint with a different key refuses.
- The producer's own `verify.json` is never trusted; the verifier recomputes.

## Slices and gates

| Slice | Content | Gate |
| --- | --- | --- |
| S1 | This document | Normal review |
| S2 | Checkpoint signing and the key store | Red tier — ledger semantics |
| S3 | `ua evidence export` and the bundle writer | Red tier — data egress |
| S4 | `ua evidence verify` CLI and fixtures | Ships with S3 |
| S5 | A receipt for every approval, resolved at decision time | Red tier — approval semantics |
| S6 | External anchor (timestamp authority or signed commit) | Red tier |

S3 without S2 is not shippable: an unsigned bundle proves integrity only, and
shipping it would invite the wrong reading.

## Open decisions

1. **Anchor.** RFC 3161 timestamp authority, or a signed git commit in a
   repository the organization already controls? The commit is cheaper and
   already understood; a TSA is independent of our infrastructure.
2. **Artifact content.** Hash-only by default is recommended. Content inclusion
   is opt-in per export and recorded in the manifest class.
3. **Key custody.** Hub-held key (protects against database edits) or
   operator-held key (also protects against a compromised hub)? The second is
   stronger and needs a signing step the operator can perform offline.
