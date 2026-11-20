# Continuity

Work outlives the session that started it. An agent's context is compacted,
a task changes hands, a conversation turns into a job, an epic goes quiet for
a month. These tools keep what matters in hub state instead of in an agent's
head. All of them are `coordination_manage` actions (module docs:
`crates/ua-tools/src/families/continuity/`), and every write appends a ledger
event in the same transaction.

| Action | Who | What |
|---|---|---|
| `task_workflow_get` | Anyone (the research profile too) | A task's stage, resume capsule and graded checks |
| `task_workflow_set` | Claimant, next owner, lifecycle operator, human | Set the stage and capsule |
| `task_check_record` | Claimant, next owner, lifecycle operator, human | Record one check result at one head |
| `task_check_verify` | Anyone | Look a stored check's CI run up again |
| `session_handoff_propose` | The session's owner | Write a draft handoff note |
| `session_handoff_update` | The note's author | Edit the draft |
| `session_handoff_seal` | The note's author | Commit the note |
| `session_handoff_discard` | The note's author | Drop the draft |
| `session_handoff_recover` | The session's owner, the note's receiver, lifecycle operator, human | The session's latest sealed note |
| `session_handoff_ack` | The agent the note was handed to | Acknowledge it |
| `conversation_handoff` | A participant (or a human) | Link or create a task that points at a conversation |
| `conversation_handoffs` | A verified participant (or a human) | Where a conversation was handed off |
| `queue_health` | Anyone (the research profile too) | Open, parked, stale and milestone counts |
| `queue_stale` | Anyone | Stale tasks, oldest first |
| `queue_sweep` | Anyone | Proposed parks and folds; writes nothing |
| `queue_park` | Holder, lifecycle operator, human (see below) | Park a task and fold its open descendants |
| `queue_fold` | Holder, lifecycle operator, human (see below) | Fold a later child into its parked root |
| `queue_unpark` | Holder, lifecycle operator, human (see below) | Restore a parked root and its folded children |
| `queue_close_merged` | Anyone (dry run); a lifecycle operator or a human to close | Close tasks whose linked pull request merged |

Delegation stats are a read on `observability_manage` (see below).

## Task workflow

One record per task:

- `stage`: `plan`, `implement`, `verify`, `review`, `merge`, `deploy`,
  `prove` or `done`.
- The resume capsule: `goal`, `done` (up to 20 short items) and `focus`.
- `head_sha`: the commit the capsule describes. Checks are graded at this
  head unless `task_workflow_get` names another.
- `expected_checks`: check names that should exist before the task is done.
  A missing one reads `unknown`. An entry may be `{name, job}` to bind the
  check to one CI job (returned as `expected_jobs`).

Every write bumps `revision`. Pass `expected_revision` to refuse a write over
a revision you did not read. `session_packet` carries the record as
`workflow` (stage, capsule, head, and each check's grade).

### Checks and grades

A check is one named result (`tests`, `lint`, `ci`, ...) at one head, `pass`
or `fail`. Its grade:

| Grade | Meaning |
|---|---|
| `attested` | An agent said so. Every recorded check starts here; recording the same check at the same head again resets it here. |
| `verified` | The hub looked the check's CI run up itself, and it agrees: same head, finished, the stated outcome. |
| `unknown` | Nothing is recorded at the head being judged. `stale_head` shows where the check was last seen. |

A check may carry `ref: {kind: "ci_run", ref, repo, job}`. With `job`, the
grade is that job's: missing or skipped contradicts the claim. Without it a
verified grade covers the run as a whole only (`verified_scope: "run"`,
listed in `summary.verified_run_only`), since a green run can contain a
skipped job.

A lookup that contradicts the claim leaves the grade `attested` and lists the
check in `summary.contradicted`. Nothing here gates a claim or a merge.

The caller does not choose what the hub looks up:

- **Repository.** The reference's repository is the task's project's bound
  repository (`project_repo_bind`). A `ref.repo` naming another is refused
  (`repo_mismatch`); an omitted one is filled in from the binding. With no
  binding the reference is kept, but the check stays `attested` and its
  verification says the project has no bound repository. A binding changed
  after recording is checked again at verify time.
- **Head.** A check with a reference needs the full 40-character
  `head_sha`; an abbreviated SHA is ambiguous and is never graded
  `verified`.
- **Job.** When `expected_checks` binds a check to a job, a reference naming
  another job is refused (`job_mismatch`), and one naming no job is graded
  on the bound job. So a run-scope `tests` can never be verified by some
  other job. A binding added after the check was recorded applies when it is
  verified.

### CI verification

The hub resolves CI references through the `CiVerifier` trait
(`crates/ua-tools/src/ci.rs`), held by the hub and replaceable with
`Hub::with_ci_verifier`. It never shells out to a forge CLI. The built-in
`GitHubCiVerifier` looks the run up through the native GitHub client in the
bound repository: an Actions workflow run, else a check run, by id. It is
`verified` only when the run (or the named job, in every attempt) completed
at exactly the claimed head with the claimed conclusion; another head or
conclusion, or a missing or skipped job, is `mismatch`; a run still going,
not found or rate limited is `insufficient`. The run must also be the one
the check stands for: a check run only from an app in `github_ci_apps`, and
a run whose name is the check's name, its bound job, or the workflow
`github_check_workflows` maps it to; otherwise `insufficient`. Without a
token (`github_token_env`) no request is made and the verdict is
`unverifiable`. See [github](github.md#ci-verification).

A completed `check_run`, `check_suite` or `workflow_run` webhook (or a new
PR head seen by the poller) re-verifies every check recorded at that head,
so a check recorded while CI was still running becomes `verified` without
another call.

### Review queue and `review_ready`

`task_list(stage="review")` lists unfinished tasks at stage `review` (any
stage works; pass `status` to narrow). When a task is at stage `review`,
expects at least one check and every expected check is `verified` at the
capsule's head, the hub sends one `review_ready` notification through the
notify webhook: a fixed template (task id, head, check names, never the
title), at most once per task and head and once per task per 10 minutes.
See [github](github.md#the-review-queue-and-review_ready).

## Session handoff notes

A note is what an agent knew at the end of its context: `done` and
`next_steps` (at least one item each), and `open_questions`. Items are
redacted for credential shapes and bounded to 20 items of 500 characters.

```
draft --seal--> sealed --> assigned --> delivered
  |               |            \__________^
  +--discard--> discarded
                  +--(a newer note seals)--> superseded
```

- Only the session's owner proposes, edits, seals or discards.
- `seal` is the commit point. A sealed note is immutable; SQLite triggers
  enforce the forward-only states as well.
- `session_handoff_recover` and the packet's `handoff_note` return the latest
  sealed, assigned or delivered note, never a draft. Notes are marked
  untrusted: they are context, not instructions.
- `session_handoff_recover` answers a verified caller that owns the session
  (or wrote the note), the agent the note was assigned or delivered to, a
  lifecycle operator or a human. Anyone else, unverified callers included,
  reads `not_found`, the same as for a missing session.
- Per session: one pending note (a draft, or a sealed note not yet
  delivered; a new note while a sealed one is pending needs
  `supersede: true`, and its seal supersedes the old one), a 5-minute
  cooldown between proposals (`handoff_cooldown`) and at most 5 proposals in
  any hour (`handoff_rate_limited`). Edits to a draft are not proposals.
- `session_handoff_ack` is the receiver of an `assigned` note saying it has
  it; the note becomes `delivered`.

## Conversation handoff

`conversation_handoff` (`conversation_id`, then `task_id` to link or `title`,
`project`, `priority` to create) ties a mailbox conversation to a task. The
task gets one notes line, `[conversation: <id>] handed off from the agent
conversation`; no message is copied. The caller must have sent or received a
message in the conversation (a human, or the coordinator profile, sees every
conversation). The task write goes through the registry as `task_add` or
`task_update`, so the caller's profile, the policy file and the approval gate
apply as they do to a direct call. Creating is idempotent per conversation,
title, project and priority.

`conversation_handoffs` has the same caller rule (a verified caller that can
see the conversation; anyone else reads `not_found`). The handoff ledger
event is the audited record: `handoffs` lists the tasks an
`agent.conversation.handoff` event links, with who handed off, when, and
`note_reference` (whether the notes line is still there). A task whose
notes carry the line with no event behind it (anyone who can write notes can
type one) is listed apart, under `unaudited`.

## Queue closure

The rules:

1. A task untouched for `stale_days` (default 30) may be parked, with a
   stated reason. Parked is not closed: the task keeps its status.
2. Parking a task folds its open descendants into it, so no open child sits
   under a parked root.
3. Nothing closes on a date. `queue_sweep` only proposes.

Parking has its own columns on `tasks`: `parked_at`, `parked_by`,
`parked_reason`, and `folded_into` (the parked root a folded task went with).
Archiving (`archived_at`, `task_update(archived=...)`) is separate: it files
work away.

- `task_list` leaves parked tasks out; `task_list(parked=true)` is the parked
  view.
- The claim gate refuses a parked or folded task with `task_parked`
  (`task_claim`, `task_update` into `doing`, dispatch and node work).
- Closing a parked task (`done` or `cancelled`) ends its park.
- `queue_unpark` on the root restores the root and every task folded into it.
  A folded task is restored only through its root.
- `queue_fold` folds a child that appeared after the park into the parked
  root above it.

**Staleness** is the latest of `updated_at`, `claimed_at` and the comment
thread, else `created_at`. Live work is never stale and is never parked or
folded (`task_live`): a live claim, an open or live dispatch run, a pending
or in-flight delegation, queued or claimed node work.

**Who may park.** Park, fold and unpark need a verified caller. A task
someone holds (a non-empty `claimed_by` or `next_owner`) is parked, folded or
unparked only by that holder, a lifecycle operator or a human
(`not_task_owner`), the same rule as the workflow record. A task nobody holds
is open to any verified caller on the coordinator, lead or developer
profile. Parking folds every open descendant, so a descendant held by
someone else needs an operator as well. Unpark is judged on the root alone.

**Protected rows** are never proposed for parking: the `operator-only` and
`interactive-only` lanes, `waiting_review`, a `[waiting-for: ...]` marker, a
red-tier row, and the `tracking` lane. `queue_park` parks a gated row (all
but the `tracking` lane) only for a verified human or lifecycle operator
(`protected_task` otherwise); the recorded approval is that caller's
identity. `approved_by` is never authority: only such a caller may pass it
(`operator_required` otherwise), and it is recorded as a note on the
approval.

`queue_health` returns `open`, `active`, `by_status`, `parked`,
`parked_folded`, `stale`, `stale_actionable`, review-ready milestones (an
open task marked `[milestone-review]` whose `Gate:` tasks and prerequisites
are all done, judged once its notes carry a `VERDICT:` line) and
`ready_unowned` (tasks whose prerequisites are all closed and that have no
next owner, claimant or agent lane).

**Close-on-merge.** A task whose `evidence_ref` names a pull request
(`https://<host>/<owner>/<name>/pull/<n>` on the configured GitHub host, or
`<owner>/<name>#<n>`), or whose notes carry a `closes: <owner>/<name>#<n>`
marker, in its project's bound repository closes when that PR merges into
the project's merge branch (the repository's default branch unless
`github_merge_branches` names another): `task_update` to `done` with the
merge commit as `evidence_ref` and a `[github: closed-on-merge ...]` notes
line, fenced on the task's `updated_at`. Other mentions in notes never
match. Not when it links two PRs in that repository (`ambiguous`), the PR
merged into another branch such as a stacked parent (`merged_to_non_default`),
the PR merged before the task was created, or the task is live, protected
(the park rules above), has open descendants, or names another branch than
the PR's head (`blocked`). Merges arrive by webhook or poll, or on demand:
`queue_close_merged` (params `dry_run`, default true, and `repo`) looks every
linked PR up on GitHub; a real run is for a lifecycle operator or a human.
Each close appends `agent.github.closed_on_merge`.
Details in [github](github.md#close-on-merge).

## Delegation stats

`observability_manage(action="delegation_stats")` (alias
`delegation_ledger`), params `agent`, `window_days` (default 30) or `since`:
per agent, delegations sent and received, received by state, open count,
completion rate, and latencies in seconds (`completion`: creation to a
terminal state; `first_claim`: creation to the claim, for delegations
claimed once), plus state counts per sender and receiver pair. Read only; no
vault page is written.

## Import

`ua import python-hub` copies `task_workflow`, `task_checks` and
`session_handoff_notes` by column name. A Python task parked the old way
(archived, with a `[parked @ ...]` or `[folded-into: #N @ ...]` notes line)
moves to the parking columns and is un-archived; its notes are kept.

## Differences from the Python hub

- Parking uses its own columns instead of `archived_at` plus notes markers.
- `queue_fold` folds only into a parked root, never into a folded task, so
  unparking the root always restores the whole fold.
- `queue_close_merged` matches a task's `evidence_ref` and `closes:` markers rather than
  the PR-watch cursor, and runs from the webhook and poller as well as on
  demand. The sweep does not propose closes.
- Session-handoff failover and context epochs are not ported (failover had
  no tool surface in the Python hub); an imported `assigned` note can still
  be acknowledged.
- Each handoff-note state change (drafted, edited, sealed, superseded,
  discarded, acknowledged) appends an `agent.lifecycle.handoff` event.
- A conversation handoff records no completion-return origin: posting a
  status back into the conversation is not ported.
- `conversation_handoffs` returns `{conversation_id, handoffs, unaudited}`
  rather than a bare list, and counts only ledger-recorded handoffs.
- Delegation stats replace the Python ledger's review-outcome parsing and
  monthly vault page with state counts and latencies.
- The stale threshold is the `stale_days` argument (default 30); there is no
  environment override.
