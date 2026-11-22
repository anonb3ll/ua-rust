# Software factory scenario status

The [first end-to-end acceptance scenario](software-factory.md#first-end-to-end-acceptance-scenario)
runs as one test, `crates/ua-server/tests/factory_scenario.rs`. It drives the
five steps against a disposable in-process hub and a disposable git
repository and scores each step, so anyone can see at a given commit which
parts of the scenario work.

## What the test does

Every tool call goes in-process through the governed `Registry::call`, as
the HTTP and MCP adapters do. The callers are:

- two verified agents for the two harnesses: `builder-1` (transport label
  MCP) and `builder-2` (transport label HTTP; its calls are in-process like
  everyone's);
- a lead, `lead-1`, that delegates and also runs the merge (there is no
  separate release agent);
- a dispatched worker;
- a verified human approver, `operator`, built from its bearer token by the
  hub's own identity check (`resolve_bearer_blocking` and `caller_for`);
- an unverified caller naming the human;
- a same-organization agent with no access to the hidden records,
  `builder-3`, whose stream request goes over the server's router with a
  bearer token;
- an auditor, `auditor-1` (a coordinator-profile agent, since the manifest
  tools need that profile).

A scripted CI verifier stands in for the forge, behind the hub's own
verifier interface (`Hub::with_ci_verifier`), as the continuity tests do.
A second, empty hub is used only to run `compare_migration_manifests` on
the exported bundle. The trace checks in step 5 are lookups the test makes
in the exported JSON, not a product verifier.

Each sentence of the scenario becomes one or more named checks. Every check
ends in exactly one status:

| Status | Meaning |
| --- | --- |
| `pass` | The test exercised the behaviour through an entry point and verified the effect in the hub's own records (ledger events, rows, responses) or in the disposable repository. |
| `fail` | The product has the capability and gets it wrong. The reason starts with `scored:` and names the capability being scored. |
| `not-built` | The capability does not exist yet. The reason names what is missing. |

A check the test cannot exercise is `not-built`, never skipped. A few checks
are scored from what the test observes: when the product's verifier accepts
a tampered bundle, the check is `not-built` because no single-bundle
verifier exists, not `pass`.

"Visible in the audit record" means a row on the hash-chained ledger
(`event_log`), appended by the refused call, that names the approval or
authorization and gives a reason. A `tool_calls` row alone does not count:
it names no approval or reason and is not hash-chained.

The isolation checks in step 4 follow the document's rule: they capture
what `builder-3` sees through each surface before the hidden records exist
and again after (a private message and a typed handoff to `builder-2`,
`builder-2`'s sealed handoff note, and a conversation handoff). A check
passes only when the two views are identical, apart from fields that move
with the clock or with `builder-3`'s own records. `isolation.same-org-own-inbox`
is a control check, not a sentence of the document.

The preamble asks to record the hub revision, harness versions, fixture
inputs and enabled features. The test prints them; the hub keeps no record
of harness versions, so nothing about them is scored.

## How to run it

```sh
cargo test -p ua-server --test factory_scenario -- --nocapture
```

The test needs `git` on `PATH`. It takes one to two seconds. With
`--nocapture` it prints the header and the scorecard: each check grouped by
step, its status, and one line on how it was verified or why it failed or
is missing. An event stream that stops before the caller's own sentinel row
arrives is a setup failure (the test panics), never a scored outcome.

## The ratchet

The expected scorecard is `crates/ua-server/tests/fixtures/factory_scenario.txt`,
one line per check: `<step> <check-id> <status>`. The test fails when the
actual scorecard differs from it in any line, and names the line:

- a check that regresses (`pass` to anything else) fails the test as a
  regression; fix the product;
- a check that improves (`not-built` or `fail` to `pass`) also fails the test
  until the change that made it pass updates its line;
- a new check, or a fixture line the test no longer records, fails the test
  until the fixture matches.

So the fixture is always the truth about what works at that commit, and it
only moves forward. One exception: a line may move away from `pass` to
correct an overstated check, in a change whose message says it corrects the
scorecard. It never moves to accommodate a product regression.

The fixture is the source of truth; the table below was written by hand
from it and may lag behind it.

## Current scorecard

62 checks: 31 pass, 11 fail, 20 not-built.

### 1. Plan and delegate

| Check | Status | Reason |
| --- | --- | --- |
| `delegate.task-delegated-to-first-harness` | pass | |
| `delegate.team-accepts-task` | not-built | Teams do not exist: a task is delegated to and claimed by one agent. |
| `delegate.task-claimed-with-review-requirement` | pass | Recorded, not enforced: the implementer records the expected review; nothing gates on it (see `release.requires-review-at-head`). |
| `delegate.handoff-tied-to-revision` | pass | |
| `delegate.session-handoff-sealed` | pass | |
| `delegate.deliverable-revision-object` | not-built | No deliverable record: the revision is a commit SHA repeated on the workflow record, the checks and the handoff. |

### 2. Resume and review

| Check | Status | Reason |
| --- | --- | --- |
| `review.second-harness-opens-same-task` | pass | |
| `review.packet-carries-handoff-at-revision` | pass | |
| `review.packet-cites-decisions-and-constraints` | pass | An unrelated note is left out. |
| `review.packet-excludes-superseded-decision` | pass | |
| `review.packet-marks-superseded-decision` | not-built | The session packet drops a superseded decision silently; no context pack cites it as superseded. |
| `review.superseded-decision-identifiable` | pass | |
| `review.checks-bound-to-exact-revision` | pass | Bound to the head, self-reported (attested, not verified). |
| `review.checks-verified-against-ci` | pass | Graded `verified` after the hub asked the CI verifier (scripted here) about the run at the head. |
| `review.resumed-attempt-keeps-task-link` | pass | |
| `review.interrupted-attempt-fenced` | pass | |
| `review.at-most-one-external-effect` | not-built | External effects are not recorded against the run attempt that made them. |
| `review.uncertain-outcome-visible` | pass | |

### 3. Approve and release

| Check | Status | Reason |
| --- | --- | --- |
| `release.expired-approval-refused` | pass | Refused as expired. |
| `release.expired-refusal-audited` | fail | Scored: an audited refusal. The refused merge appends no ledger row naming the authorization and a reason; only a `tool_calls` row with outcome `denied` remains. |
| `release.changed-revision-refused` | pass | Refused, naming the authorized head and the new one. |
| `release.changed-revision-refusal-audited` | fail | As above. |
| `release.changed-target-refused` | pass | Refused as another repository. |
| `release.changed-target-refusal-audited` | fail | As above. |
| `release.verified-human-approves-exact-action` | pass | Through the policy authorization path; the one-time approval path is scored separately below. |
| `release.approved-attempt-produces-artifact` | pass | |
| `release.one-time-approval-binds-revision` | fail | Scored: an approval bound to the revision. A one-time approval of `git_merge_task` records the task, not the head, so the merge it allows is not bound to the revision shown at approval. |
| `release.requires-review-at-head` | not-built | Nothing gates a merge on the recorded review: with the expected review unknown at the head, a merge under a valid authorization for that head runs. |

The passing approval path is the policy authorization
(`policy_authorization_record` and `git_merge_task(policy_authorization_id)`),
which binds the task, the bound repository and the exact head.

### 4. Check isolation

| Check | Status | Reason |
| --- | --- | --- |
| `isolation.other-org-direct-reads` | not-built | Only the default organization can exist. |
| `isolation.other-org-retrieval-and-explanations` | not-built | As above. |
| `isolation.other-org-handoffs` | not-built | As above. |
| `isolation.other-org-streams` | not-built | As above. |
| `isolation.other-org-exports` | not-built | As above. |
| `isolation.same-org-restricted-memory` | not-built | Memory notes carry no access restriction. |
| `isolation.same-org-hidden-task` | not-built | Tasks carry no access restriction. |
| `isolation.same-org-mailbox-direct-read` | pass | |
| `isolation.same-org-handoff-note` | pass | |
| `isolation.same-org-conversation-handoffs` | pass | |
| `isolation.same-org-own-inbox` | pass | Control check. |
| `isolation.same-org-ledger-read` | fail | Scored: the mailbox and handoff restriction applied to ledger reads. Ledger reads (`event_log_query`) are not scoped per caller: message and handoff events are returned to every caller whose profile allows ledger reads. |
| `isolation.same-org-stream` | fail | Scored: the same restriction applied to the event stream. The event stream uses the same unscoped rule as ledger reads. |
| `isolation.same-org-handoffs-in-retrieval` | fail | Scored: the same restriction applied to resume packets. `session_packet` for a task includes the latest typed handoff on it, and the task's recent events, whoever they are addressed to. |
| `isolation.same-org-evidence` | fail | Scored: the same restriction applied to evidence reports. `evidence_report` on a task lists the ledger events of messages and handoffs on it, with sender and time, to callers who cannot read them. |
| `isolation.same-org-exports` | fail | Scored: the same restriction applied to exports. The manifest export is refused by the developer profile, so it is out of reach rather than shown clean; the tasks export changes because `conversation_handoff` writes a line naming the conversation into the task's notes. |
| `isolation.same-org-retrieval-and-explanations` | fail | Scored: the same restriction applied to retrieval and its explanations. Memory search is unchanged; ranked task search returns the task with the line `conversation_handoff` writes into its notes. |

### 5. Verify independently

| Check | Status | Reason |
| --- | --- | --- |
| `verify.trace-artifact-to-task` | pass | |
| `verify.trace-artifact-to-handoff` | fail | The release handoff is addressed to the reviewer. The auditor receives its ID and stored hash. Tracing the handoff to the reviewed revision requires authorized access. |
| `verify.trace-artifact-to-approval` | pass | |
| `verify.trace-artifact-to-policy` | not-built | The approval carries a caller-supplied policy reference (free text); no policy record exists to resolve it against. |
| `verify.policy-reference-recorded` | pass | A label, not a resolvable policy. |
| `verify.trace-artifact-to-run-attempt` | not-built | A merge is not recorded against a run attempt. |
| `verify.trace-artifact-to-checks-at-revision` | pass | |
| `verify.record-fingerprint-recomputed-offline` | pass | Detects only a record edited without updating the stated fingerprint. |
| `verify.integrity-an-editor-cannot-recompute` | not-built | The fingerprint is an unkeyed SHA-256 inside the bundle; the listed ledger rows are outside it, and the chain flag is the exporter's own claim. |
| `verify.rejects-tampered-ledger-row` | not-built | No single-bundle verifier: `compare_migration_manifests` trusts the exporter's `chain_ok` and leaves listed ledger rows outside the fingerprint. |
| `verify.rejects-incomplete-bundle` | not-built | No bundle declares a scope and interval it is complete for, and nothing checks listed rows against the declared count and rolling hash. |
| `verify.authenticity-against-trusted-key` | not-built | Exports carry no signature or signed checkpoint. |
| `verify.asserted-evidence-labelled` | pass | |
| `verify.unavailable-and-unhashed-evidence-reported` | not-built | No bundle verifier reports unavailable evidence or unhashed legacy rows. |
| `verify.private-content-kept-out` | pass | The migration manifest gives the auditor IDs and stored hashes for message rows outside its mailbox. |
| `verify.unauthorized-caller-refused-export` | pass | Refused by the developer profile; the gate is the coordinator profile, not an auditor grant. |
| `verify.auditor-authorization` | not-built | No auditor role or grant exists: any coordinator-profile agent may export the whole hub. |

The bundle in step 5 is the migration manifest with its ledger rows listed
(`export_migration_manifest(events_since_ulid=...)`), carried as bytes to the
second hub and compared there.

## What the scenario does not cover yet

- Harness versions are printed, not scored (see above).
- The `/ui/activity/stream` view uses the same scope as the API stream and is
  not driven separately.
- The agents' `Caller` values are built directly; only the human and the
  outsider's stream request pass through the hub's bearer-token identity
  check.
