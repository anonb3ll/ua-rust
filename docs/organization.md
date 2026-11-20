# Organization model

Status: **design, not implemented.** This document is the review gate for the
`organization.v1` schema part and the `ua-org` crate. Nothing here is in the
tree yet.

## Decision

The organization is the structural partition key, and it exists from the first
release: `org_id` is `NOT NULL` on every tenant-scoped table, with one seeded
default organization, so a single-organization hub behaves exactly as it does
today and a second organization needs no migration.

The alternative — ship single-tenant and add tenancy when a second tenant
appears — was considered and rejected. A partition key added after the tables
exist is a retrofit across every query path, every approval binding and every
audit read. That retrofit is the reason the predecessor implementation filed
organization-as-partition-key and never finished it.

An organization holds **people and agents together**. A hub that serves a
company has to know which humans belong to which team, because approvals,
reviews and escalation belong to a team's lead, not to one global operator
list. People are first-class rows, not configuration.

## What exists today

Three things are easy to confuse. Only the first two exist.

| Concept | Where | What it actually is |
|---|---|---|
| Profiles | `ua-core/src/profiles.rs`, `profiles.json` | A **capability overlay**. Decides which tools a session can see. Neutral tiers: `developer`, `lead`, `coordinator`, `reviewer`, `operator`, `public`, `research`. |
| Agents | `agents` table | A **flat roster** of identity labels. No owner, no reporting line, no grouping. |
| Organization | — | **Does not exist.** Verified at `28fdf58`: no `org_id` on any table and no org concept in `Caller`. |

Humans exist only as configuration. `human_identities` in `ua-core/src/config.rs`
is a flat list of labels; `Config::is_human` checks membership, the HTTP adapter
sets `ActorKind::Human` from it (`ua-server/src/auth.rs`), and passkeys and UI
sessions carry a bare `label`. Any human on that list can approve any gated
action on the hub: `approvals.rs::resolve` checks only `caller.is_human()` and
that the approver is not the requester.

`Caller` (`ua-core/src/identity.rs`) carries `label`, `kind`, `profile`,
`enforce_profile`, `session_key` and `transport`. It does not carry an
organization or a user, so no query path can scope by one today.

One deliberate exception already exists in the opposite direction: `ua-import`
**refuses** to import source rows that carry an `org_id` unless
`--drop-org-scope` is passed, and then records that tenant boundaries were
dropped. That is correct while the hub has no tenant scope. It becomes a
migration question the moment the spine lands — see [The importer](#the-importer).

## The model

All of it is data rather than configuration, because the product promise is
that an operator can define their own organization at runtime and have that
definition audited.

```
users (global identity) ──┐
                          │ org_memberships (role)
orgs ─────────────────────┼── offices          (named capability scopes inside an org)
                          ├── teams            (groupings of people and agents)
                          │     ├── team_members  (principal_type human | agent, lead | member)
                          │     └── team_specs    (versioned, executable: seats, edges, budgets)
                          ├── reporting        (supervisor edges, temporal, human | agent | office)
                          ├── org_proposals    (self-organization, human-gated)
                          └── agents, tasks, memory, approvals, ...   (the tenant-scoped set)
```

- **user** — a human identity. Global, like a passkey: one person can belong to
  several organizations. The user's `label` is the same label passkeys, UI
  sessions and bearer tokens already carry.
- **org membership** — a user's role in one organization (see [People](#people)).
- **org** — the tenant boundary. Everything else hangs off it.
- **office** — a named role scope within an org, carrying a tier and a
  reference to the capability profile it implies. It is *not* an HR job title.
  Offices are runtime data, never a fixed enum.
- **team** — a many-to-many grouping of people and agents, used for approval
  routing, memory visibility and task ownership.
- **team spec** — the executable definition of how a team's agent seats start,
  who they may delegate to, and what they may spend (see [Team specs](#team-specs)).
- **reporting** — a temporal edge from a subordinate to a supervisor, with
  `effective_from` / `effective_to`, so "who reported to whom in March" is
  answerable rather than overwritten.

## People

```sql
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL UNIQUE,   -- the identity label credentials carry
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active','suspended')),
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_memberships (
    org_id   TEXT NOT NULL REFERENCES orgs(id),
    user_id  TEXT NOT NULL REFERENCES users(id),
    role     TEXT NOT NULL
             CHECK (role IN ('org_owner','org_admin','team_lead','member','auditor')),
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
```

`users` is global, like `passkeys`; `org_memberships` is the tenant-scoped
grant. A user's role decides **which rows and which approvals** they have
authority over. It never decides which tools a session can see — that stays
with profiles and the policy file.

| Role | Authority inside the organization |
|---|---|
| `org_owner` | Everything `org_admin` can do, plus granting and removing `org_owner`. The last owner cannot be removed or demoted. |
| `org_admin` | Manage memberships (below owner), teams, offices, team specs and budgets. Approve any gated action in the organization. |
| `team_lead` | Approve gated actions owned by a team where they are a `lead` member; approve that team's self-organization proposals that do not widen authority. |
| `member` | Belong to teams and request approvals. No approval authority. |
| `auditor` | Read the organization's ledger, approvals and audit exports. Cannot approve, deny, write, or resolve anything. |

### Bootstrap and single-operator parity

`human_identities` stays the bootstrap source. On every start the hub syncs it,
idempotently, into the default organization: each listed label gets a `users`
row and an `org_owner` membership in `'default'` if it has none. A label later
removed from the config keeps its rows (removal is an explicit membership
change, recorded on the ledger), so an edited config file cannot silently
strip an owner. A hub with one configured human therefore behaves exactly as
today: that human owns the default organization and can approve everything.

`Config::is_human` remains the test for `ActorKind::Human`. What changes is the
approval check, which moves from "is a human" to "is a human with authority
over this approval" (below).

## Schema

Released schema parts are immutable; `ua-store/src/schema.rs` refuses to apply a
changed part and requires a new one. So this is a **new part**, `organization.v1`,
not an edit to the existing parts.

### New tables

```sql
CREATE TABLE IF NOT EXISTS orgs (
    id           TEXT PRIMARY KEY,
    slug         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active','suspended')),
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS offices (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    tier       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS teams (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    office_id  TEXT REFERENCES offices(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS team_members (
    org_id         TEXT NOT NULL,
    team_id        TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('human','agent')),
    principal      TEXT NOT NULL,   -- users.id for 'human', agent label for 'agent'
    member_role    TEXT NOT NULL DEFAULT 'member'
                   CHECK (member_role IN ('lead','member')),
    added_at       TEXT NOT NULL,
    PRIMARY KEY (team_id, principal_type, principal)
);

CREATE TABLE IF NOT EXISTS reporting (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id           TEXT NOT NULL REFERENCES orgs(id),
    subordinate_type TEXT NOT NULL CHECK (subordinate_type IN ('human','agent','office')),
    subordinate      TEXT NOT NULL,
    supervisor_type  TEXT NOT NULL CHECK (supervisor_type IN ('human','agent','office')),
    supervisor       TEXT NOT NULL,
    effective_from   TEXT NOT NULL,
    effective_to     TEXT
);
```

A `lead` row requires `principal_type = 'human'` and an org role of
`team_lead`, `org_admin` or `org_owner`; the writer refuses anything else, so a
demoted user stops leading without a second bookkeeping step (eligibility is
checked at approval time, below). An agent may be a team member, never a lead.

`users` and `org_memberships` are in [People](#people); `team_specs` and
`org_proposals` are in [Team specs](#team-specs) and
[Self-organization](#self-organization).

### Adding the column

SQLite permits `ADD COLUMN ... NOT NULL` only when a constant default is
supplied, which is exactly the behaviour wanted here: every existing row is
backfilled atomically with the default organization.

```sql
INSERT OR IGNORE INTO orgs (id, slug, display_name, status, created_at)
    VALUES ('default', 'default', 'Default organization', 'active', strftime('%Y-%m-%dT%H:%M:%fZ','now'));

ALTER TABLE tasks ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE tasks ADD COLUMN team_id TEXT;            -- owning team, nullable
ALTER TABLE approvals ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE approvals ADD COLUMN team_id TEXT;        -- routing team, nullable
-- ... one org_id statement per tenant-scoped table
```

**The default is a migration convenience, not a safety net.** A tool path that
forgets `org_id` will silently write into the default organization instead of
failing. Two guards:

1. The resolver always binds `org_id` explicitly; it is never omitted.
2. A unit test walks the statement strings in the tenant-scoped families and
   fails for an `INSERT INTO <tenant table>` that does not name `org_id`.

That test is the real invariant. The column default exists only so the
migration is a single transaction.

## Resolution

`Caller` gains `org_id: String` and `user_id: Option<String>`. Both are set by
the adapter from the verified credential and from nothing else:

| Transport | Source of the organization | Source of the user |
|---|---|---|
| Bearer token / OAuth | the token row's `org_id` | the `users` row for the token's label, when it is a human |
| Passkey / UI session | the selected membership (one membership: that one; several: the session's chosen organization, validated against `org_memberships`) | the passkey's label |
| CLI and stdio, local | the default organization | the `users` row for the label, when it is a human |
| `Caller::system()` | `'default'` — see [Decisions](#decisions) | none |

**Never from tool arguments.** `goal_manage` already accepts a `params.org_id`;
that stays a *filter within the caller's organization* and must never widen
scope. A test asserts that passing a different `org_id` returns zero rows
rather than that organization's rows.

## Approvals routed by team

Today any configured human can approve anything. In an organization with
several teams that is wrong in both directions: Team A's lead should not need
the hub owner for routine approvals, and should not be able to approve Team B's
deploys.

**Routing team.** When an approval is requested, the gate records
`approvals.team_id`, in this order:

1. the owning team of the task the gated call names (`tasks.team_id`);
2. otherwise the requester's team, when the requesting agent is a seat on
   exactly one team in the organization;
3. otherwise `NULL` — organization-level, approvable by admins only.

The routing team is recorded once, at request time, and is part of the row the
approver sees. It is not part of the bound payload, so routing never changes
what is being approved.

**Eligibility.** `resolve` with `approve` succeeds only when every check holds,
evaluated at resolution time against current rows:

1. `caller.is_human()` and `caller.org_id == approvals.org_id` (an approval in
   A never satisfies, and is never visible to, a caller in B);
2. the caller is not the requester (unchanged);
3. the caller's membership role is `org_owner` or `org_admin`, **or** the
   approval has a `team_id` and the caller is a `lead` member of that team with
   role `team_lead` or above;
4. `auditor` and `member` never approve.

`deny` follows the same eligibility, plus the requester (unchanged). `revoke`
is unchanged. Membership is evaluated at resolution, not at request, so a lead
removed while an approval is pending can no longer approve it.

**Escalation.** If a team has no eligible lead, or a pending approval exceeds
the team spec's `approval_timeout`, the approval is offered to the targets of
the team's `escalates_to` edge and to the organization's admins. Escalation
widens who may approve; it never narrows it, and it is recorded on the ledger.

Nothing about which tools are gated changes. `require_approval`, profile
filters and `lifecycle_operators` keep their current meaning.

## Team specs

A team spec is the executable definition of a team: which agent seats exist,
how each one starts, how seats may interact, and what they may spend. It is
what lets one human approval bring up a working multi-harness team.

Specs are tenant data, not hub configuration, so they live in their own
append-only table rather than in `config_revisions` (which versions the
hub-wide policy file and whose `kind` set is fixed by its schema part).

```sql
CREATE TABLE IF NOT EXISTS team_specs (
    org_id       TEXT NOT NULL REFERENCES orgs(id),
    team_id      TEXT NOT NULL REFERENCES teams(id),
    version      INTEGER NOT NULL,
    spec         TEXT NOT NULL,      -- canonical JSON
    spec_sha256  TEXT NOT NULL,
    committed_by TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    PRIMARY KEY (team_id, version)
);
-- triggers refuse UPDATE and DELETE; the live spec is the highest version
```

Committing a spec needs an approval from an eligible approver for that team
(an `org_admin`, or the team's lead for changes that do not widen authority —
see [Self-organization](#self-organization) for "widen"). Every commit appends
an `agent.team.spec` ledger event with the hash.

### Spec shape

```json
{
  "team": "platform",
  "office": "engineering",
  "approval_timeout": "4h",
  "budget": {"tokens_per_day": 4000000, "cost_usd_per_month": 900},
  "seats": [
    {
      "label": "builder-1",
      "harness": "claude",
      "model": "<model id>",
      "fallback": [{"harness": "codex", "model": "<model id>"}],
      "node": "desk-01",
      "workspace": {"repo": "org/service", "worktree": "per_task", "trust_root": "/srv/work"},
      "profile": "developer",
      "skill_pack": "<published harness_config bundle id>",
      "budget": {"tokens_per_day": 1500000, "cost_usd_per_day": 40},
      "guidance": "short startup guidance"
    }
  ],
  "edges": [
    {"from": "builder-1", "to": "reviewer-1", "type": "reviews"},
    {"from": "planner-1", "to": "builder-1", "type": "delegates_to"},
    {"from": "builder-1", "to": "user:<id>", "type": "escalates_to"},
    {"from": "reviewer-1", "to": "builder-1", "type": "can_observe"}
  ]
}
```

Only one seat is shown; `reviewer-1` and `planner-1` are seats of the same
shape.

Validation at commit:

- Every seat `label` is an agent `team_members` row of this team, in this
  organization. A spec never creates an identity.
- `harness` is one the harness-config surface supports; `fallback` entries are
  tried in order when the primary is unavailable or out of budget.
- `profile` may not exceed the tier of the team's office.
- `workspace.trust_root` must be a root the named node itself reported. A spec
  can narrow trust, never grant it; workspaces are never auto-trusted.
- `skill_pack` must name a published harness-config bundle; the spec does not
  write harness config itself.
- Seat budgets may not sum above the team budget.
- `delegates_to` and `escalates_to` must be acyclic. Edge endpoints are seats
  of this team, or `user:<id>` / `team:<slug>` for `escalates_to`.
- Size is capped; unknown keys are refused.

### Edges are enforced, not decorative

When a team has a committed spec, its seats are governed by its edges. Seats
outside any spec are unaffected, so this is opt-in per team.

| Edge | Enforced at | Rule |
|---|---|---|
| `delegates_to` | delegation and dispatch | A seat may delegate only to seats it has a `delegates_to` edge to. |
| `reviews` | task stage review | A review counts toward a task's review stage only from a seat with a `reviews` edge to the author. |
| `escalates_to` | approvals and blocked tasks | Target of approval escalation and of a seat's blocked-task escalation. |
| `can_observe` | session, run and flight-recorder reads | A seat may read another seat's sessions and runs only with a `can_observe` edge to it. |

All four checks live in one function in `ua-org`, called by the tool wrapper's
policy layer, so the rule is in one place and is tested once per edge type.
A refusal names the missing edge.

### Budgets

Usage arrives from run reports (tokens and cost per run) and is recorded on the
ledger, so budgets are sums over the ledger for the seat, the team and the
window. A seat at its cap is refused new dispatch; the dispatcher then tries the
seat's `fallback` entries that still have headroom, and only then refuses with
`budget_exhausted` and escalates. Enforcement granularity is one run: a run in
flight finishes, which is stated rather than hidden.

### `ua team plan` and `ua team up`

`ua team plan <team>` (tool `team_plan`) is read-only. Per seat it reports the
node, harness, model, workspace, skill pack, budget headroom and every readiness
check (identity in this organization, node live and reporting the trust root,
harness installed on the node, skill pack published, profile within the office
tier, edges valid), with each refusal and its reason. The plan contains no
timestamps and is canonical JSON, so two plans of the same spec against the same
hub state are **byte-identical** and diffable; its `plan_sha256` is returned.

`ua team up <team>` (tool `team_up`) boots a **committed** spec only. It
recomputes the plan, refuses if any seat is refused, then requests one approval
bound to `(org_id, team_id, spec_sha256, plan_sha256)`. After approval it
launches seats in `delegates_to` order through the node work queue, one run
record per seat linked by a `team_run_id` on `agent.team.run`. If the hub state
changed between approval and launch so that the plan hash differs, the pass does
not match and a new approval is requested.

## Self-organization

Agents can see where their own team's structure is wrong — a missing reviewer, a
routing rule that bounces work, a routine nobody runs. They may **propose**
changes; they may never **apply** them.

```sql
CREATE TABLE IF NOT EXISTS org_proposals (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    team_id     TEXT REFERENCES teams(id),
    office_id   TEXT REFERENCES offices(id),
    proposer    TEXT NOT NULL,
    kind        TEXT NOT NULL
                CHECK (kind IN ('role','team','routing','skill','routine','edge','budget','other')),
    diff        TEXT NOT NULL,   -- structured patch against the live spec or org rows
    base_sha256 TEXT NOT NULL,   -- hash of the state the diff applies to
    rationale   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'proposed'
                CHECK (status IN ('proposed','applied','rejected','stale','withdrawn')),
    created_at  TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT
);
```

Rules:

1. **Proposing is on by default** and can be switched off per organization.
2. **Scope is membership.** A proposer may target only teams and offices it is
   a member of. A proposal outside that scope is refused, not queued.
3. **Applying is never automatic.** Apply needs an approval bound to the
   proposal id, the diff hash and `base_sha256`. If the live state no longer
   hashes to `base_sha256`, the proposal becomes `stale` and is not applied.
4. **Widening needs an admin.** A proposal that widens any seat's authority —
   a higher profile, a larger budget, a new `delegates_to` or `can_observe`
   edge, a broader trust root — needs an `org_admin` or `org_owner`. A team
   lead may approve the rest for their own team.
5. Applying a spec change commits a new `team_specs` version through the same
   path as a human commit, so history has one shape.

The diff is structured so the review inbox can render it side by side.

## Scoping per subsystem

| Subsystem | Tables | Rule |
|---|---|---|
| Tasks | `tasks`, `task_dependencies`, `task_fts` | `org_id` (and optional `team_id`) on `tasks`; the FTS read joins through it |
| Agents | `agents`, `agent_sessions`, `agent_tokens`, `session_profiles` | An agent label belongs to exactly one organization |
| People | `org_memberships` | Per organization; `users` is global |
| Teams | `teams`, `team_members`, `team_specs`, `reporting`, `org_proposals` | Per organization |
| Memory | `memory`, `memory_versions`, `memory_embeddings`, `memory_fts` | `org_id` plus a visibility tier, enforced in the search SQL — see `docs/memory.md` |
| Approvals | `approvals` | `org_id` and routing `team_id`; an approval from A never satisfies the same payload in B |
| Messages | `message_index`, `message_reads`, `notify_outbox`, `pending_notifications` | `org_id` on the message tables |
| Skills | `skill_versions`, `skill_assignments`, `skill_publish_staging` | Catalog is per organization |
| Secrets | `managed_secrets` | Per organization |
| Planning | `plans`, `plan_steps`, `plan_checkpoints`, `routines`, `routine_runs` | Per organization |
| Delegation / cycles | `delegations`, `autonomous_cycles*` | Per organization |
| Nodes | `nodes`, node work queue | A node serves one organization |
| **Global** | `users`, `oauth_clients`, `oauth_*`, `passkeys`, `webauthn_states`, `login_links`, `ui_sessions`, `ui_keys` | Identity is global; the **grant** carries the organization |

## The ledger

`event_log` is a single global hash chain. The organization must not fork it,
or every existing chain verification breaks and cross-organization tamper
evidence disappears.

So `org_id` is an ordinary column on `event_log`, included in the hashed row
content, and `verify()` continues to walk one chain. Audit reads filter by
`org_id`; integrity checks stay global.

Today `ledger::compute_entry_hash` hashes nine fields (`causal_parent_id`,
`channel`, `created_at`, `dedupe_key`, `episode_id`, `originator`, `payload`,
`prev_hash`, `ulid`) in the byte form the Python hub produced, which is what
lets imported chains verify. Adding a field changes that form, so the hash is
versioned:

```sql
ALTER TABLE event_log ADD COLUMN org_id  TEXT NOT NULL DEFAULT 'default';
ALTER TABLE event_log ADD COLUMN hash_v  INTEGER NOT NULL DEFAULT 1;
```

- `hash_v = 1`: the existing nine-field form. Every row written before the
  migration, and every imported row, keeps it. Their `org_id` is not covered by
  their hash, which is honest: those rows predate tenancy.
- `hash_v = 2`: the nine fields plus `org_id`, in sorted key position. Every
  row appended after the migration uses it.
- `verify()` chooses the form per row by `hash_v`, and refuses a `hash_v = 1`
  row whose `seq` is after the first `hash_v = 2` row, so a downgrade cannot be
  slipped into the chain.

The Python verifier cannot check `hash_v = 2` rows. That is acceptable because
the Python hub is frozen and never reads a `ua-rust` ledger.

## Where the code lives

- **`ua-org`**, a new workspace crate: users, memberships, offices, teams,
  members, reporting, specs, proposals, the edge check and the approval
  eligibility check. Its tools register through `ua-tools`, which stays a thin
  registry and envelope; no organization logic is added to `ua-tools` beyond
  the call into `ua-org` from the approval gate and policy layer.
- **`ua-store`** gains a `repo` module with an `OrgRepo` trait and its SQLite
  implementation. `ua-org` reaches the database only through that trait, and
  the trait exposes no `rusqlite` types. Methods are synchronous and run inside
  the hub's existing write transaction, because each write must commit
  atomically with its ledger append. A PostgreSQL backend is a later decision;
  this trait is where it would plug in, and the bundled SQLite WAL store stays
  the zero-configuration default.

## The importer

Once the spine exists, `ua-import` has two honest options:

- **A.** `--drop-org-scope`: source organizations all map to the default
  organization and the import report says so. Kept as an explicit flag for
  importing a single-organization hub.
- **B (the cutover path).** Map each source `org_id` to an organization of the
  same slug, creating it if missing, and preserve boundaries row by row. The
  source's single organization maps to `'default'`. This is what the hub
  cutover uses, checked by the migration manifest compare.

Do not silently accept and drop. Until B lands, the current refusal stays the
default.

## What this is not

- **Not a tool-permission matrix.** Capability stays with profiles and the
  policy file. Membership roles decide which rows a person administers and
  which approvals they may resolve, not which tools a session sees.
- **Not hard isolation.** Organizations share one hub and one database. Hard
  data-plane separation per organization was considered and not chosen.
- **Not a job-title system.** Offices carry a tier and a name. No HR semantics,
  no hierarchy beyond the reporting edges.
- **Not an external directory.** Users are created by admins or synced from
  `human_identities`. An external identity provider (OIDC, SAML, SCIM) is a
  later layer that verifies the person and their membership; this model stays
  the authority on what they may do.

## Decisions

The three questions left open in the first draft are settled:

1. **`Caller::system()` belongs to `'default'`.** Hub maintenance runs as the
   default organization. A job that touches another organization must name its
   target `org_id` explicitly; there is no organization-free caller, so no code
   path can read across tenants by accident.
2. **Offices are runtime data**, not a fixed enum, since the product promise is
   that an operator defines their own.
3. **Tasks are organization-local in v1.** Task identity does not move between
   organizations; a cross-organization handoff is a copy plus a reference.

## Acceptance

1. **Single-organization parity.** The existing suite passes unchanged, the
   seeded default organization is invisible to callers, and a hub with
   `human_identities = ["operator"]` lets that human approve exactly what they
   can approve today.
2. **Isolation.** Seed a second organization; every read tool called as B
   returns zero rows from A across tasks, memory, approvals, messages, secrets,
   skills, teams and proposals.
3. **Approval binding.** An approval created in A does not satisfy, and is not
   resolvable from, the identical payload in B.
4. **Team routing.** Team A's lead approves Team A's approval; is refused on
   Team B's and on an organization-level one; an `auditor` and a `member` are
   refused; an `org_admin` approves all three; a lead removed while an approval
   is pending is refused.
5. **Bootstrap.** Removing a label from `human_identities` does not remove its
   membership; adding one creates an `org_owner` membership once.
6. **Ledger integrity.** `verify()` reports a valid chain across `hash_v` 1 and
   2 rows; a forged `hash_v = 1` row after the switch fails; an
   organization-filtered audit returns only that organization's events.
7. **Resolver guard.** The statement-walking test fails if a tenant-scoped
   insert omits `org_id`.
8. **Team plan determinism.** Two `team_plan` calls on the same spec and state
   are byte-identical; changing one seat's node changes `plan_sha256`.
9. **Team up binding.** `team_up` refuses an uncommitted spec and a plan with a
   refused seat; an approval for one plan hash does not launch a changed plan.
10. **Edges.** For each of the four edge types, the action is allowed with the
    edge and refused without it, naming the missing edge.
11. **Budgets.** A seat at its cap falls back to a fallback with headroom, and
    is refused with `budget_exhausted` when none has any.
12. **Self-organization.** A proposal outside the proposer's teams is refused;
    a stale base is not applied; a widening proposal approved by a team lead is
    refused; apply writes a new spec version.
13. **Importer.** A single-organization source hub imports into `'default'`
    with no silent boundary loss; a two-organization source keeps both.
