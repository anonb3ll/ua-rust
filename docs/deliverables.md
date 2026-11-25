# Deliverables

A deliverable is what a task produces. A revision is one version of it.
Before deliverables existed, the "revision" a reviewer looked at was only a
commit SHA that an agent wrote on the task's workflow record, on its checks
and in a handoff message, with nothing tying them together. A deliverable
gives that work an id, and each version of it a number, a producer and a
place in order that never changes.

The domain is the `ua-deliverables` crate (schema, validation, reads and
writes). Its tools are registered in `ua-tools`
(`crates/ua-tools/src/families/deliverables.rs`) and run through the
governed registry like every other tool.

## The object

- A **deliverable** is a typed attachment to a task. A `commit` deliverable names a commit in the repository the task's project
  is bound to (`project_repo_bind`). A task has at most one commit deliverable.
  A `file` deliverable uses a title within the task and a SHA-256 revision.
  Its task, kind and repository are immutable.
- A **revision** is one version of a deliverable. For a commit deliverable
  its identity is the full 40-character hex commit SHA (lowercased). An
  abbreviated SHA is ambiguous and refused. Revisions are numbered from 1 in
  the order they are recorded, and a revision is never edited or removed: a
  new version of the work is a new commit and a new revision.
- **The repository** is the task's project's bound repository, resolved the
  same way task checks resolve it. The caller never names it. The
  deliverable keeps the repository it was created in, and a revision
  recorded after the project was rebound to another repository is refused.
- **The current head.** Recording a revision sets `head_sha` on the task's
  workflow record (the resume capsule, [continuity](continuity.md#task-workflow))
  through the same write as `task_workflow_set`, in the same transaction.
  That record is the one place that says which commit the task is at, so the
  task's checks are graded at the recorded revision. A deliverable stores no
  head of its own; `deliverable_get` reads the workflow head and says
  whether it is the latest revision (`latest_is_workflow_head`).

Neither table has a foreign key to `tasks`. A revision is immutable, so a
deleted task must not cascade into it (the rule sealed handoff notes
follow). The task id stays as the record of what the deliverable was for;
no new revision can be recorded once the task is gone.

## Tools

| Tool | Who | What |
|---|---|---|
| `deliverable_create` | The task's claimant, its next owner, a lifecycle operator or a human | Attach a deliverable to a task (`task_id`, `title`, `kind`, default `commit`). The same title again returns the existing deliverable (`created: false`). |
| `deliverable_revise` | As above | Record a revision (`deliverable_id`, `commit`, optional `summary`) and set the task's workflow head to it. The latest commit with the same summary again returns that revision (`recorded: false`). |
| `deliverable_get` | Any caller of the task's organization | A deliverable, its revisions (newest first, at most 100), the revision count and the workflow head |
| `deliverable_list` | Any caller of the task's organization | A task's deliverables, each with its revision count and latest revision |

The writers are the task workflow record's writers, checked by the same
rule. The `reviewer` profile does not see the two write tools. Tasks carry
no read restriction inside an organization yet, so neither do their
deliverables; a row of another organization answers `not_found`.

Refusals, each with a reason code:

| Reason | When |
|---|---|
| `invalid_argument` | Not a full 40-hex commit SHA; an empty or over-long title or summary; kind `file` passed to `deliverable_create` (use `deliverable_submit`) or any unknown kind |
| `not_found` | An unknown task or deliverable, or a deliverable whose task was deleted (for a new revision) |
| `not_task_owner` | The caller may not write the task's workflow record |
| `repo_unbound` | The task's project has no bound repository |
| `repo_mismatch` | The project is bound to another repository than the deliverable's |
| `deliverable_exists` | The task already has a commit deliverable under another title |
| `revision_conflict` | The latest revision's commit again, with another summary |
| `revision_not_latest` | An earlier revision's commit again: revisions only move forward |
| `unknown_organization` | The caller's organization does not exist |
| `org_mismatch` | The caller is in another organization than the task |

## File releases

On a Unix hub, a verified default-organization task writer submits a relative
worktree path with `deliverable_submit(task_id, title, path, summary?)`. The
hub reads a regular file up to 1 MiB and records the path, size, SHA-256
and producer. The path must stay in the caller's workspace. Symbolic links,
multiply linked files, dependency or hook paths, and credential-looking
paths are refused. Reusing a title records a new revision when the bytes
change. Repeating the latest submission with identical metadata returns the
existing revision. File revisions leave the commit workflow head untouched.

Set `deliverable_release_root` to an existing absolute directory owned by the
hub user with mode `0700`, separate from workspaces and the vault. Releases
are disabled when it is unset. The directory and its ancestors are
operator-managed.

1. Move the workflow to `review` and call
   `deliverable_release(revision_id, destination)` with the latest file
   revision and a new basename in the configured directory.
2. A verified human other than the requester and producer approves. The
   approval binds the task, file revision, SHA-256, workflow revision,
   ownership generation, destination name and directory identity.
3. Repeat the exact call. It rereads the source and refuses changed bytes
   before consuming approval. Once consumed, the exact approved bytes and
   release intent are recorded together. The hub publishes the staged file
   with exclusive creation, then commits the release receipt and both the
   task status and workflow stage `done`.

For an interrupted release, retry the same call as the original requester.
A saved intent allows the hub to resume from the approved bytes even if the
source later changes. The staged inode identifies a publication whose
completion transaction did not commit. An unrelated existing destination
is refused, even when its bytes have the same hash. The approval is consumed
once, the release is ledgered once, and retries of a completed release verify
the published bytes before returning its receipt.

`deliverable_verify(revision_id)` compares the stored identity with the
current source or with the published file after release. It returns the
comparison and does not return file contents. Pending release intents hold
up to 1 MiB of approved file bytes in SQLite until completion. Database
backups made during a pending release can therefore contain those bytes.

## What is recorded

The `deliverables` and `deliverable_revisions` tables carry an organization
key from their first schema part. The additive file schema introduces
`deliverable_files` and `deliverable_releases` with the same tenant fences.
Triggers keep revisions immutable, numbered in order, and scoped to their
deliverable's organization.

Every state change appends one ledger event in the same write transaction,
in the row's organization. Payloads carry ids, the kind, the repository and
the revision identity; never the title or the summary.

| Channel | Payload |
|---|---|
| `agent.deliverable.created` | `org_id`, `deliverable_id`, `task_id`, `kind`, `repo` |
| `agent.deliverable.revised` | `org_id`, `deliverable_id`, `task_id`, `revision_id`, `rev_no`, `kind`, `identity`, `repo` |

A revision that moves the workflow head also appends the workflow record's
own `agent.task.workflow` event (`kind: "capsule"`, `fields: ["head_sha"]`).

## Not built yet

Later slices add:

- **Handoff binding.** A sealed handoff note names the revision it hands
  over (by default the latest), and the session packet shows it, flagged
  when a newer revision exists.
- **Release through approval.** `git_merge_task` now enforces the
  review-at-head gate when `"review"` is in the task's `expected_checks`: it
  requires a passing, uncontradicted `review` check at the exact commit being
  merged (`review_required`) and refuses a self-review when a commit
  deliverable revision for that commit names the reviewer as its `producer`
  (`self_review_refused`), without consuming the policy authorization. Later
  slices will require every expected check to be verified at that revision
  and add a release tag effect in the hub's own repository.
- **Isolation and read surfaces.** A platform object kind and an evidence
  report section for deliverables, checked across organizations.

The older hub's work-product routes (`/api/work-products*`) still answer
501. The compatibility routes and SDK migration are a later slice.
