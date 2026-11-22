# Software factory scenario status

The [first end-to-end acceptance scenario](software-factory.md#first-end-to-end-acceptance-scenario)
runs as one test, `crates/ua-server/tests/factory_scenario.rs`. It drives the
five steps against a disposable in-process hub and a disposable git
repository and scores each step, so anyone can see at a given commit which
parts of the scenario work.

## What the test does

The test uses the entry points agents and operators use: registered tools
through the governed `Registry::call`, with verified agents for the two
harnesses (`builder-1` over MCP, `builder-2` over HTTP), a lead and a
release agent, a verified human approver (`operator`), an unverified caller
naming the human, a same-organization agent with no access (`builder-3`) and
an auditor. The stream check opens `GET /api/events/stream` over the
server's router with a bearer token. A second, empty hub stands in for the
auditor's machine.

Each sentence of the scenario becomes one or more named checks. Every check
ends in exactly one status:

| Status | Meaning |
| --- | --- |
| `pass` | The test exercised the behaviour through an entry point and verified the effect in the hub's own records (ledger events, rows, responses) or in the disposable repository. |
| `fail` | The product has the capability and gets it wrong. The reason says how. |
| `not-built` | The capability does not exist yet. The reason names what is missing. |

A check the test cannot exercise is `not-built`, never skipped. A few checks
are scored from what the test observes: when the product's verifier accepts
a tampered bundle, the check is `not-built` because no single-bundle
verifier exists, not `pass`.

"Visible in the audit record" means a row in the hash-chained ledger
(`event_log`), the record an export carries and a reviewer can check. A
`tool_calls` row alone does not count: it names no approval or reason and is
not hash-chained.

## How to run it

```sh
cargo test -p ua-server --test factory_scenario -- --nocapture
```

The test needs `git` on `PATH`. It takes about a second. With
`--nocapture` it prints the hub version and revision, the harness labels,
the build features and the scorecard: each check grouped by step, its
status, and one line on how it was verified or why it failed or is missing.

## The ratchet

The expected scorecard is `crates/ua-server/tests/fixtures/factory_scenario.txt`,
one line per check: `<step> <check-id> <status>`. The test fails when the
actual scorecard differs from it in any line, and names the line:

- a check that regresses (`pass` to anything else) fails the test as a
  regression; fix the product, never move a line away from `pass`;
- a check that improves (`not-built` or `fail` to `pass`) also fails the test
  until the change that made it pass updates its line;
- a new check, or a fixture line the test no longer records, fails the test
  until the fixture matches.

So the fixture is always the truth about what works at that commit, and it
only moves forward. The fixture is the source of truth; the table below was
written by hand from it once and may lag behind it.

## Current scorecard

55 checks: 32 pass, 8 fail, 15 not-built.

### 1. Plan and delegate

| Check | Status | Reason |
| --- | --- | --- |
| `delegate.task-delegated-to-first-harness` | pass | |
| `delegate.team-accepts-task` | not-built | Teams do not exist: a task is delegated to and claimed by one agent. |
| `delegate.task-claimed-with-review-requirement` | pass | |
| `delegate.handoff-tied-to-revision` | pass | |
| `delegate.session-handoff-sealed` | pass | |
| `delegate.deliverable-revision-object` | pass | |

The first harness records its change as revision 1 of the task's commit
deliverable (`deliverable_create`, `deliverable_revise`, see
[deliverables](deliverables.md)); the check reads the revision row, its
`agent.deliverable.revised` ledger event and the task's workflow head. The
handoff and the checks still name the commit itself, not the revision.

### 2. Resume and review

| Check | Status | Reason |
| --- | --- | --- |
| `review.second-harness-opens-same-task` | pass | |
| `review.packet-carries-handoff-at-revision` | pass | |
| `review.packet-cites-decisions-and-constraints` | pass | |
| `review.packet-excludes-superseded-decision` | pass | |
| `review.packet-marks-superseded-decision` | not-built | The session packet drops a superseded decision silently; no context pack cites it as superseded. |
| `review.superseded-decision-identifiable` | pass | |
| `review.checks-verified-at-exact-revision` | pass | |
| `review.resumed-attempt-keeps-task-link` | pass | |
| `review.interrupted-attempt-fenced` | pass | |
| `review.at-most-one-external-effect` | not-built | External effects are not recorded against the run attempt that made them. |
| `review.uncertain-outcome-visible` | pass | |

### 3. Approve and release

| Check | Status | Reason |
| --- | --- | --- |
| `release.expired-approval-refused` | pass | |
| `release.expired-refusal-audited` | fail | The refused merge leaves no ledger event, only a `tool_calls` row with outcome `denied`. |
| `release.changed-revision-refused` | pass | |
| `release.changed-revision-refusal-audited` | fail | As above. |
| `release.changed-target-refused` | pass | |
| `release.changed-target-refusal-audited` | fail | As above. |
| `release.verified-human-approves-exact-action` | pass | |
| `release.approved-attempt-produces-artifact` | pass | |
| `release.one-time-approval-binds-revision` | fail | A one-time approval of `git_merge_task` binds only `{task_id}`; a commit added to the branch after the approval is merged under it. |

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
| `isolation.same-org-own-inbox` | pass | |
| `isolation.same-org-ledger-read` | fail | `event_log_query` returns another agent's message bodies and typed handoffs, which `message_list` refuses. |
| `isolation.same-org-stream` | fail | `/api/events/stream` applies the same unscoped rule and streams them too. |
| `isolation.same-org-handoffs-in-retrieval` | fail | `session_packet(task_id)` gives any caller the latest typed handoff on the task, addressed to someone else. |
| `isolation.same-org-evidence` | pass | |
| `isolation.same-org-exports` | pass | |

The same-organization checks compare what `builder-3` sees through each
surface before and after the hidden records (a private message, a typed
handoff and a sealed handoff note addressed to `builder-2`, and a
conversation handoff) are added.

### 5. Verify independently

| Check | Status | Reason |
| --- | --- | --- |
| `verify.trace-artifact-to-task` | pass | |
| `verify.trace-artifact-to-handoff` | pass | |
| `verify.trace-artifact-to-approval` | pass | |
| `verify.trace-artifact-to-policy` | pass | |
| `verify.trace-artifact-to-run-attempt` | not-built | A merge is not recorded against a run attempt. |
| `verify.trace-artifact-to-checks-at-revision` | pass | |
| `verify.integrity-checked-offline` | pass | |
| `verify.rejects-tampered-ledger-row` | not-built | No single-bundle verifier: `compare_migration_manifests` trusts the exporter's `chain_ok` and leaves listed ledger rows outside the fingerprint. |
| `verify.rejects-incomplete-bundle` | not-built | No bundle declares a scope and interval it is complete for, and nothing checks listed rows against the declared count and rolling hash. |
| `verify.authenticity-against-trusted-key` | not-built | Exports carry no signature or signed checkpoint. |
| `verify.asserted-evidence-labelled` | pass | |
| `verify.unavailable-and-unhashed-evidence-reported` | not-built | No bundle verifier reports unavailable evidence or unhashed legacy rows. |
| `verify.private-content-kept-out` | fail | The migration manifest export carries private message and handoff content the exporting auditor may not read. |

The bundle in step 5 is the migration manifest with its ledger rows listed
(`export_migration_manifest(events_since_ulid=...)`), carried as bytes to a
second hub and checked there with `compare_migration_manifests`.

## What the scenario does not cover yet

- The scenario's preamble asks to record the hub revision, harness versions,
  fixture inputs and enabled features. The test prints them; the hub has no
  record of harness versions to check.
- CI verification of a check against a forge needs a forge. The checks in
  step 2 are attested at the exact head, not verified against CI.
- The `/ui/activity/stream` view uses the same scope as the API stream and is
  not driven separately.
