# Software factory direction

ua-rust evolves unified-agent from shared context and memory for coding
agents into a meta-harness for software delivery. An organization should be
able to assemble a team of people and agents, carry work and context across
harnesses, and independently verify how a change reached release.

Compatibility with the Python hub gives existing clients and data a path
forward. Preserve the contracts they rely on, test the workflows they use,
and document intentional changes. Judge new work by what an organization can
do, recover, or verify with it.

## Product priorities

| Area | What the product should let people do |
| --- | --- |
| [Organizations and teams](organization.md) | Define who owns work, who can review or approve it, and who can inspect the result. Enforce those boundaries across tools, interfaces, and exports. |
| [Harness execution](dispatch.md) and [handoffs](continuity.md) | Route work to a compatible harness or node. Resume with the same task, deliverable, and applicable permissions after interruption. Make failures, retries, and uncertain external outcomes visible. |
| [Shared memory](memory.md) | Give the next agent relevant decisions, constraints, and evidence within its access and context budget. Show the source and validity of recalled facts and carry corrections forward. |
| [Approvals](policy.md) and [evidence](sdk.md#evidence) | Tie consequential actions to the verified actor, governing policy, exact approval, execution attempt, and artifact revision. Let a reviewer verify that history independently. |

The repository already has governed tool calls, dispatch and continuity
records, memory retrieval, and a hash-chained ledger. The scenario below is
an acceptance target for the combined product. Organization-wide isolation,
scoped context packs, and independently verifiable evidence exports are
parts of that target.

## First end-to-end acceptance scenario

Use a disposable hub and repository with two organizations, two different
harnesses, and a human authorized to approve a restricted action. Record the
hub revision, harness versions, fixture inputs, and enabled features. Use
the same entry points that operators and agents use.

1. **Plan and delegate.** A team accepts a task with a review requirement.
   The first harness implements a small change and records a handoff tied to
   the deliverable revision.
2. **Resume and review.** The second harness opens the same task and receives
   a context pack citing the applicable decisions and constraints. It can
   identify a superseded decision and verify checks against the exact revision
   it reviews. Interrupt a worker after a durable claim and verify that a
   resumed attempt keeps its link to the task and produces at most one external
   effect. An uncertain outcome is visible for reconciliation.
3. **Approve and release.** A verified human approves the exact restricted
   action for the reviewed revision. An expired approval and an action with a
   changed revision or target are refused and visible in the audit record.
   The approved attempt produces a release or equivalent artifact in the
   disposable repository.
4. **Check isolation.** Callers in another organization and callers without
   access in the same organization cannot discover restricted memory, work, or
   evidence through direct reads, retrieval results and explanations, handoffs,
   streams, or exports. Compare what they see before and after adding the
   hidden records.
5. **Verify independently.** An authorized auditor on another machine can
   trace the artifact to the task, handoff, approval, applicable policy, run
   attempt, and checks at the reviewed revision. The verifier checks integrity,
   authenticity against a separately trusted signing key or checkpoint, and
   completeness within the declared scope and interval. It rejects tampered
   or incomplete bundles and reports asserted, unavailable, and unhashed
   legacy evidence explicitly. Keep private content out of the export unless
   the auditor is authorized to see it.

## Measure improvement

Pin the memory corpus, expected answers and sources, retrieval mode, and
reproducible run configuration. Compare against the Python hub on the same
fixture. Report matched retrieval modes and the configurations users run,
along with recall by query class, source accuracy, stale or inaccessible
context exposure, and p95 latency. Include cross-session recall,
time-sensitive facts, conflicting decisions, and access revocation. Use the
[memory evaluation design](memory.md#1-evidence) for the retrieval benchmark
and the scenario above to verify whether a second harness can use the result
to continue the work.

Use runnable evidence from the scenario to track progress. Each milestone
should make a step work through its normal entry point or close a measured
gap in quality, isolation, recovery, or auditability.
