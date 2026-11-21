# GitHub connector

The hub talks to GitHub itself, through a native REST client, for four
things: grading task checks against real CI runs, closing tasks whose pull
request merged, polling when GitHub cannot reach the hub, and policy
authorizations that stand in for a one-time merge approval. It never shells
out to a forge CLI. Module docs: `crates/ua-tools/src/families/github/`.

| Piece | Where | What |
|---|---|---|
| REST client | `github/client.rs` | Pinned to one API host, bound repositories only, no redirects, bounded, rate-limit aware |
| CI verifier | `ci.rs` (`GitHubCiVerifier`) | `task_check_record` / `task_check_verify` grade a check `verified` when the run proves it |
| Webhook | `POST /api/github/webhook` | Signed deliveries: re-verify checks, close tasks on merge |
| Poller | `ua serve`, `github_poll_interval_s` | The same effects from the open-PR list, with ETags |
| Close-on-merge | `coordination_manage(action="queue_close_merged")` | On demand, dry run by default |
| Policy authorizations | `policy_authorization_record`, `policy_authorization_list`, `policy_authorization_revoke` | A human's standing-policy authorization for one exact head |
| Review queue | `task_list(stage="review")`, the `review_ready` notification | What was `scan_for_reviewable_tasks` |

## Configuration

```toml
# github_api_url = "https://api.github.com"     # or a GHES root: https://ghe.example.com/api/v3
github_token_env = "HUB_GITHUB_TOKEN"           # the NAME of a variable holding the token
github_webhook_secret_env = "HUB_GITHUB_WEBHOOK_SECRET"
github_poll_interval_s = 0                      # 0 = off

# Which runs may verify which check (see "CI verification").
github_ci_apps = ["github-actions"]             # check-run apps that count as CI: slug or numeric app id
github_require_default_branch_workflow = false  # require the workflow file to match the default branch
github_ci_latest_attempt_only = false           # judge a job on its latest attempt only
# check name -> workflow name, or a workflow file path that pins the run to that file
# github_check_workflows = { tests = ".github/workflows/ci.yml", lint = "Lint" }

# Webhooks and close-on-merge.
github_webhook_max_age_hours = 24               # refuse payloads whose own timestamp is older; 0 = off
# github_web_host = "github.com"                # host PR links must name (default: from github_api_url)
# project -> branch a merged PR must target; unlisted: the repository's default branch
# github_merge_branches = { default = "main" }
```

The HTTP client for `github_api_url` is built once and shared by every
request (one connection pool), not rebuilt per call.

- **Token.** `github_token_env` names an environment variable; the hub reads
  the token from it when it needs it. Pick a name outside `UA_*` (those are
  read as configuration). The token is never written to the
  database or the config file, never returned by a tool and never logged
  (it is held as a secret and sent as a sensitive header). A fine-grained
  token with read access to Actions, Checks, Pull requests and Metadata of
  the bound repositories is enough; nothing here writes to GitHub (the relay
  posts comments with its own token, see [relay.md](relay.md)). Without a
  token there are no GitHub requests at all: checks stay `attested` with
  verdict `unverifiable`, the poller skips, and `queue_close_merged` refuses.
- **Later sources.** A GitHub App installation token can replace the
  personal token behind the same client. Once the managed-secret store
  (slice 4) is merged, it becomes the token's and webhook secret's source;
  `github_token_env` stays as the fallback.
- **Webhook secret.** `github_webhook_secret_env` names the variable holding
  the secret set on the GitHub webhook. Without it the endpoint answers 503
  to everything.

## Security model

**Repository scoping.** The client takes only a `BoundRepo`, which exists
only for a repository some project is bound to (`project_repo_bind`).
Request paths are built from that normalized `owner/name` and numeric ids,
never from caller text. A CI reference is looked up in the task project's
bound repository (see [continuity](continuity.md#checks-and-grades)); a
webhook for a repository no project is bound to is acknowledged, ledgered
and has no effect.

**One host, no redirects.** Every request goes to `github_api_url`, which
must be `https` without credentials, query or fragment (plain `http` only to
loopback under the test hook). A 3xx other than 304 is an error and is never
followed, so the token cannot be forwarded anywhere. For the public API the
connection goes through the same guarded resolver as `web_fetch`, so a DNS
answer pointing at a private address is refused; a GHES host is the
operator's choice and may be private.

**Bounded.** 20 seconds per request, 8 MiB per response, JSON only. When
GitHub says the rate limit is spent (`x-ratelimit-remaining: 0`, or a
403/429 with `retry-after`) the client stops calling that host until the
reset (at most an hour) and answers `rate limited` without a request; a CI
lookup then reads `insufficient` and can be verified again later.

**Webhook authentication.** `/api/github/webhook` takes no bearer token
(GitHub cannot send one). Before anything is parsed or stored:

1. `X-Hub-Signature-256` must be `sha256=` + the HMAC-SHA256 of the raw body
   under the webhook secret, compared in constant time. Otherwise 401
   `bad_signature`.
2. When the payload carries its own timestamp (`pull_request.merged_at`,
   `updated_at` or `closed_at`; `check_run.completed_at`;
   `check_suite.updated_at`; `workflow_run.updated_at`;
   `repository.pushed_at` for a push), the newest of them must be within
   `github_webhook_max_age_hours` (default 24; 0 turns it off). Otherwise
   409 `stale`. A signed body captured long ago is not accepted again; a
   manual redelivery from GitHub's UI older than the window is refused too.
3. Neither `X-GitHub-Delivery` (a well-formed id) nor the SHA-256 of the raw
   body may have been processed before. Either repeat is 409 `replayed`. The
   delivery and event headers are outside the signature, so a signed body
   re-sent under a fresh delivery id is still a replay. Ids and body hashes
   are recorded in `inbound_deliveries` ([ingress.md](ingress.md#inbound-deliveries)),
   kept 30 days, at most 20 000 of each.
4. The body must be `application/json` (the API guard refuses a form body
   with 415) and at most 5 MiB.

The delivery id, the body hash (both `accepted` by this process) and an
`agent.github.webhook.received` event are written in one transaction before
any effect. After the effects both records are marked `finished`, and a later
copy is a replay. If an effect fails with an internal error, the id and hash
are released instead, so GitHub's redelivery is processed again. If the hub
stops between recording a delivery and finishing it, or the delivery has been
in flight for 15 minutes, a redelivery is processed again rather than
refused, and its ledger event says `"redelivered": true`. Every effect is
idempotent. Rows the old `github_deliveries` and `github_delivery_bodies`
tables held when the hub was upgraded are copied in as `finished`; the two
tables stay in the schema, unread and unwritten, until a later release drops
them. The payload is trusted only after the signature check:
it carries the merge commit and head, so these effects need no API call.

**Effects are governed calls under a narrow grant.** Closing a task is a
registry `task_update` and re-verifying a check is
`coordination_manage(task_check_verify)`, both made as the hub identity
`hub-github`, so the policy and ledger rules apply as to any caller. The
route is public (authenticated only by the HMAC), so that identity holds a
grant the registry enforces first, before profiles and whatever its
`enforce_profile` says: `task_update` with only `id`, `status="done"`,
`evidence_ref` (a 40-hex merge commit), `append_note` and
`expected_updated_at`, and `coordination_manage` with action
`task_check_verify`. Any other call made as `hub-github` is refused
`grant_denied` and ledgered as an `agent.gateway.decision`. Effects are
ledgered on `agent.github.*`:

| Channel | When |
|---|---|
| `agent.github.webhook.received` | A signed, new delivery |
| `agent.github.checks_reverified` | Checks at a head were looked up again (webhook or poll) |
| `agent.github.closed_on_merge` | A task closed because its PR merged |
| `agent.github.merged_to_non_default` | A linked PR merged into a branch other than the project's merge branch; the task stayed open |
| `agent.github.polled` | A poll changed something (a merge or a new head) |
| `agent.github.policy_authorization.recorded` / `.consumed` / `.restored` / `.revoked` | A policy authorization was recorded, reserved by a merge, put back after a failed merge, or revoked |

## CI verification

A check recorded with `ref: {kind: "ci_run", ref: <id>, job?}` is looked up
in the bound repository. The id is tried as an Actions workflow run
(`/actions/runs/{id}`), then as a check run (`/check-runs/{id}`).

| Verdict | When |
|---|---|
| `verified` | Completed, at exactly the claimed 40-hex head, concluded as claimed (`success` for pass, `failure` for fail), and the run the check stands for (below) |
| `mismatch` | Another head, another conclusion; for a job: missing, skipped, or one attempt that disagrees |
| `insufficient` | Not finished yet, not found (or not visible to the token), rate limited, a network or server error; a check run from an unlisted app; a run that is not the check's workflow; a changed workflow file when that is required |
| `unverifiable` | No token, the repository is not bound, the token is refused (401/403) |

**Which run may verify which check.** A green run proves only what it ran:

- **Apps.** A check run counts only when the GitHub App that created it is
  in `github_ci_apps`, matched on `app.slug` or the numeric `app.id`
  (default `["github-actions"]`). Any app with checks write access can post
  a green check run with any name, so an unlisted app's run is
  `insufficient`. Workflow runs are Actions runs and always count.
- **The check's workflow.** `github_check_workflows` maps a check name to a
  workflow name (`"CI"`, ASCII case-blind) or to a workflow file path
  (`".github/workflows/ci.yml"`), which pins the run to that file (a check
  run cannot show its file, so a path-mapped check needs a workflow run).
  Unmapped, a check bound to a job (`expected_checks` `{name, job}` or
  `ref.job`) is pinned by the job's name; a check with no job is verified
  only by a run whose name is the check's name. So one green `CI` run no
  longer verifies `ci`, `lint` and `tests` at once. The way a run matched is
  `observed.matched_by` (`run_name`, `workflow_name`, `workflow_path`, `job`).
- **The workflow file.** For a workflow run the hub compares the workflow
  file's blob SHA at the run's head with the one on the repository's default
  branch (`GET /repos/{repo}` and the contents API) and records
  `observed.workflow_unchanged` (`true`, `false`, or `null` when it cannot
  tell). With `github_require_default_branch_workflow = true` anything but
  `true` is `insufficient`, so an agent cannot rewrite the workflow on its
  own branch to grade its own check. It is off by default because a branch
  that legitimately changes its CI would then never verify until merged; the
  comparison is recorded either way. Turn it on where agents push to the
  repository the hub verifies against.

**Jobs and attempts.** With a job name the grade is that job's
(`/actions/runs/{id}/jobs?filter=all`); a check run stands for exactly one
job, its own name. By default every attempt must agree: a job that failed
and was re-run to green is a `mismatch`. That is the safe default (a flaky
or wrong result cannot be retried away unnoticed) but it makes
rerun-to-green permanent. `github_ci_latest_attempt_only = true` judges the
latest attempt only (`observed.judged`), keeping every attempt, failures
included, in `observed.attempts`. Only `verified` changes the grade; the
rest leave it `attested` with the reason in `verification`.

## Close-on-merge

A task is matched to a merged pull request only by an explicit link:

- its `evidence_ref` names the PR (`https://<host>/<owner>/<name>/pull/<n>`
  or `<owner>/<name>#<n>`), or
- its notes carry a `closes: <owner>/<name>#<n>` marker (or `closes:`
  followed by the PR URL).

Free text in notes ("blocked by owner/repo#3", "see owner/repo#4") is never
a match. A URL must name the configured web host (`github_web_host`; by
default `github.com` for the public API, else the GHES host of
`github_api_url`). Only links into the task project's bound repository
count, and the project must be bound to the PR's repository. It closes only
when:

- it links exactly one PR in that repository (more is `ambiguous`; a link
  into another repository does not count),
- the PR merged into the project's merge branch: `github_merge_branches`
  for the project, else the repository's default branch
  (`repository.default_branch` in the webhook, `base.repo.default_branch`
  from the API). A PR merged anywhere else, such as a stacked PR merged
  into its parent's feature branch, has a merge commit that is not on that
  branch: it is reported under `merged_to_non_default`, ledgered as
  `agent.github.merged_to_non_default`, and the task stays open until a PR
  lands on the merge branch. A payload without `base.ref` cannot show this
  and is treated the same way,
- the PR did not merge before the task was created,
- it is unfinished and nobody is working it (no live claim, open or live
  dispatch run, pending delegation or node work),
- it is not human-gated (`operator-only`/`interactive-only` lane,
  `waiting_review`, a `[waiting-for: ...]` marker, red tier) and not in the
  `tracking` lane,
- it has no open descendants,
- the PR's head branch is the task's recorded `branch`, when both are known.

Anything else is reported under `ambiguous`, `blocked` or
`merged_to_non_default`, never closed. A
close is `task_update(status="done", evidence_ref=<merge commit>,
append_note="[github: closed-on-merge @ ...] PR ... merge_sha=...")`, fenced
on the task's `updated_at` as matched (a task edited meanwhile is
`skipped`).

`queue_close_merged` (params `dry_run`, default true, and `repo`) looks up
on GitHub every PR an unfinished task in a bound project links (at most 50
per run) and applies the same rules. A dry run is open to anyone who can
call the action; a real run (`dry_run=false`) needs a lifecycle operator or
a human (`operator_required` otherwise), and each close is a `task_update`
as that caller. It is
also how a task blocked at merge time (a claim still live) closes later.

## Polling

With `github_poll_interval_s > 0`, `ua serve` lists each bound repository's
open pull requests every interval with the previous ETag; an unchanged list
is a 304 that costs no rate limit. On a change, a PR that left the list is
looked up and, if merged, runs close-on-merge; a PR with a new head has the
checks recorded at that head re-verified. Only the first page (the 100
newest open PRs) is compared. State is in `github_poll_state`.

## Policy authorizations

An approval is a human deciding one call. A policy authorization is a human
recording that a standing policy covers merging one exact head:

- `policy_authorization_record` (params `repo`, `pr`, `head_sha`, `task_id`,
  `policy_ref`, `expires_in_hours`, `allow_in_flight`): verified humans only
  (`not_human`).
  The repository must be bound and be the task's project's binding
  (`repo_mismatch`), the task unfinished, the head the full 40-hex SHA, and
  the human not the task's claimant or next owner (`self_authorization`).
  `policy_ref` is a short reference (`release-policy-2026-11`,
  `decision:42`), never conversation text. Expires after 24 hours by
  default, at most 720.
- `policy_authorization_list` (params `repo`, `pr`, `task_id`, `head_sha`,
  `include_inactive`, `limit`): each row with `state` (`active`, `expired`,
  `consumed`, `revoked`) and `valid`.
- `policy_authorization_revoke` (params `id`, `reason`): verified humans
  only. Withdraws an active authorization; a spent or revoked one is a
  `conflict`.
- `git_merge_task(task_id, policy_authorization_id)` accepts a valid one in
  place of the one-time approval: it must be for that task, the task
  project's bound repository and exactly the head being merged, and the
  caller must not be the authorizer (`policy_authorization_mismatch`
  otherwise). The authorizer must still be a configured human identity when
  it is spent (`authorizer_not_human`). On this path `force=true` is refused
  (`policy_authorization_force`), and `allow_in_flight=true` is accepted only
  when the authorization was recorded with `allow_in_flight=true`. The merge
  reserves the authorization (marks it consumed, fenced on the exact head)
  right before `git merge`, so two merges cannot spend it twice; if the
  checkout or merge fails it is put back to active
  (`agent.github.policy_authorization.restored`), so a failed merge does not
  burn it. A dry run reports `policy_authorization_id` and spends nothing. Without the argument the
  approval gate applies as before. The revoked-agent, scope and anonymous
  checks for prod actions run either way.

## The review queue and `review_ready`

`scan_for_reviewable_tasks` is not a tool here: `task_list(stage="review")`
lists unfinished tasks whose workflow record is at stage `review` (any
other `stage` works the same way; pass `status` to narrow it).

When a task is at stage `review`, expects at least one check, and every
expected check is `verified` at the capsule's head, the hub sends one
`review_ready` notification through the notify webhook (`notify_outbox`,
category `review_ready`; without `notify_webhook_url` it stays in the outbox
as `not_configured`). It fires from `task_workflow_set` and from a check
verification, and is ledgered as `agent.task.workflow` kind `review_ready`.

The message is a fixed template: `Task #<id> is ready for review (head
<12 hex>; verified checks: <names>)`. Nothing an agent wrote (title, notes,
check detail) reaches the channel, so an agent whose profile denies
`notify` cannot use a check to push its own text. Each head is announced at
most once per task, even if the task returns to it (`review_ready_notices`),
and a task gets at most one notice per 10 minutes; a head that becomes ready
inside that gap is ledgered as `review_ready_suppressed` and not sent. A
failure to notify never fails the write.

## Differences from the Python hub

- One REST client with a bound-repository type replaces the GitHub App
  worker, fast path and `gh` lookups. Nothing here writes to GitHub
  (comments, labels, merges); only reads. The one GitHub write in the hub is
  the relay's approval-gated comment on a repository listed in
  `relay_github_repos`, made with a separate managed secret
  ([relay.md](relay.md)).
- Webhook replay protection is by delivery id and body hash in the
  database, plus a payload-timestamp window; the Python hub relied on
  GitHub's signature alone.
- Close-on-merge matches the task's `evidence_ref` and `closes:` markers
  (and checks the base branch, and the recorded branch when both are known)
  instead of the PR-watch cursor and the branch-name convention; webhook,
  poll and on-demand runs share it.
- A policy authorization is recorded by a verified human, not by an agent in
  `UA_POLICY_AUTHORIZERS`, and is a database row with an expiry and a
  consumed state instead of an HMAC-signed ledger row. There is no red-tier
  file check at merge time; `git_merge_task` is the only consumer.
- `scan_for_reviewable_tasks` is `task_list(stage="review")`, judged on the
  workflow record rather than `[waiting-for: review]` notes markers, and the
  review notification goes through the notify webhook (no iMessage).
- No `pr_watch` held-PR handling and no GitHub App installation flow yet.
