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
| Policy authorizations | `policy_authorization_record`, `policy_authorization_list` | A human's standing-policy authorization for one exact head |
| Review queue | `task_list(stage="review")`, the `review_ready` notification | What was `scan_for_reviewable_tasks` |

## Configuration

```toml
# github_api_url = "https://api.github.com"     # or a GHES root: https://ghe.example.com/api/v3
github_token_env = "HUB_GITHUB_TOKEN"           # the NAME of a variable holding the token
github_webhook_secret_env = "HUB_GITHUB_WEBHOOK_SECRET"
github_poll_interval_s = 0                      # 0 = off
```

- **Token.** `github_token_env` names an environment variable; the hub reads
  the token from it when it needs it. Pick a name outside `UA_*` (those are
  read as configuration). The token is never written to the
  database or the config file, never returned by a tool and never logged
  (it is held as a secret and sent as a sensitive header). A fine-grained
  token with read access to Actions, Checks, Pull requests and Metadata of
  the bound repositories is enough; nothing here writes to GitHub. Without a
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
2. `X-GitHub-Delivery` must be a well-formed id the hub has not processed.
   A repeat is 409 `replayed`. Ids are kept 30 days, at most 20 000.
3. The body must be `application/json` (the API guard refuses a form body
   with 415) and at most 5 MiB.

The delivery id and an `agent.github.webhook.received` event are written in
one transaction before any effect. If an effect fails with an internal
error, the id is forgotten so GitHub's redelivery is processed again; every
effect is idempotent. The payload is trusted only after the signature check:
it carries the merge commit and head, so these effects need no API call.

**Effects are governed calls.** Closing a task is a registry `task_update`
and re-verifying a check is `coordination_manage(task_check_verify)`, both
made as the hub identity `hub-github`, so the profile, policy and ledger
rules apply as to any caller. Effects are ledgered on `agent.github.*`:

| Channel | When |
|---|---|
| `agent.github.webhook.received` | A signed, new delivery |
| `agent.github.checks_reverified` | Checks at a head were looked up again (webhook or poll) |
| `agent.github.closed_on_merge` | A task closed because its PR merged |
| `agent.github.polled` | A poll changed something (a merge or a new head) |
| `agent.github.policy_authorization.recorded` / `.consumed` | A policy authorization was recorded or spent |

## CI verification

A check recorded with `ref: {kind: "ci_run", ref: <id>, job?}` is looked up
in the bound repository. The id is tried as an Actions workflow run
(`/actions/runs/{id}`), then as a check run (`/check-runs/{id}`).

| Verdict | When |
|---|---|
| `verified` | Completed, at exactly the claimed 40-hex head, concluded as claimed (`success` for pass, `failure` for fail) |
| `mismatch` | Another head, another conclusion; for a job: missing, skipped, or one attempt that disagrees |
| `insufficient` | Not finished yet, not found (or not visible to the token), rate limited, a network or server error |
| `unverifiable` | No token, the repository is not bound, the token is refused (401/403) |

With a job name the grade is that job's, across every attempt
(`/actions/runs/{id}/jobs?filter=all`); a check run stands for exactly one
job, its own name. Only `verified` changes the grade; the rest leave it
`attested` with the reason in `verification`.

## Close-on-merge

A task is matched to a merged pull request when its `evidence_ref` or notes
link it (`https://<host>/<owner>/<name>/pull/<n>` or `<owner>/<name>#<n>`)
and its project is bound to the PR's repository. It closes only when:

- it links exactly one PR (more is `ambiguous`),
- it is unfinished and nobody is working it (no live claim, open or live
  dispatch run, pending delegation or node work),
- it is not human-gated (`operator-only`/`interactive-only` lane,
  `waiting_review`, a `[waiting-for: ...]` marker, red tier) and not in the
  `tracking` lane,
- it has no open descendants,
- the PR's head branch is the task's recorded `branch`, when both are known.

Anything else is reported under `ambiguous` or `blocked`, never closed. A
close is `task_update(status="done", evidence_ref=<merge commit>,
append_note="[github: closed-on-merge @ ...] PR ... merge_sha=...")`, fenced
on the task's `updated_at` as matched (a task edited meanwhile is
`skipped`).

`queue_close_merged` (params `dry_run`, default true, and `repo`) looks up
on GitHub every PR an unfinished task in a bound project links (at most 50
per run) and applies the same rules. A real run needs a verified
coordinator, lead or developer, a lifecycle operator or a human (the
`queue_park` rule), and each close is a `task_update` as that caller. It is
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
  `policy_ref`, `expires_in_hours`): verified humans only (`not_human`).
  The repository must be bound and be the task's project's binding
  (`repo_mismatch`), the task unfinished, the head the full 40-hex SHA, and
  the human not the task's claimant or next owner (`self_authorization`).
  `policy_ref` is a short reference (`release-policy-2026-11`,
  `decision:42`), never conversation text. Expires after 24 hours by
  default, at most 720.
- `policy_authorization_list` (params `repo`, `pr`, `task_id`, `head_sha`,
  `include_inactive`, `limit`): each row with `state` (`active`, `expired`,
  `consumed`, `revoked`) and `valid`.
- `git_merge_task(task_id, policy_authorization_id)` accepts a valid one in
  place of the one-time approval: it must be for that task, the task
  project's bound repository and exactly the head being merged, and the
  caller must not be the authorizer (`policy_authorization_mismatch`
  otherwise). The real merge spends it; a dry run reports
  `policy_authorization_id` and spends nothing. Without the argument the
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
verification, once per head (`task_workflow.review_notified_head`), and is
ledgered as `agent.task.workflow` kind `review_ready`. A failure to notify
never fails the write.

## Differences from the Python hub

- One REST client with a bound-repository type replaces the GitHub App
  worker, fast path and `gh` lookups. Nothing here writes to GitHub
  (comments, labels, merges); only reads.
- Webhook replay protection is by delivery id in the database; the Python
  hub relied on GitHub's signature alone.
- Close-on-merge matches the task's `evidence_ref` and notes (and checks the
  recorded branch when both are known) instead of the PR-watch cursor and
  the branch-name convention; webhook, poll and on-demand runs share it.
- A policy authorization is recorded by a verified human, not by an agent in
  `UA_POLICY_AUTHORIZERS`, and is a database row with an expiry and a
  consumed state instead of an HMAC-signed ledger row. There is no red-tier
  file check at merge time; `git_merge_task` is the only consumer.
- `scan_for_reviewable_tasks` is `task_list(stage="review")`, judged on the
  workflow record rather than `[waiting-for: review]` notes markers, and the
  review notification goes through the notify webhook (no iMessage).
- No `pr_watch` held-PR handling and no GitHub App installation flow yet.
