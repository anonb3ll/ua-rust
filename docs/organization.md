# Organization model

Status: **design, not implemented.** This document is the review gate for the
`organization.v1` schema parts and the `ua-org` crate. Nothing here is in the
tree yet. Its companion is `docs/memory.md` (PR #40), which relies on the
decisions recorded here for memory columns and defaults.

## Decision

The organization is the structural partition key, and it exists from the first
release: `org_id` is `NOT NULL` on every tenant-scoped table, with one seeded
default organization, so a single-organization hub behaves exactly as it does
today and a second organization needs no further migration.

The alternative — ship single-tenant and add tenancy when a second tenant
appears — was considered and rejected. A partition key added after the tables
exist is a retrofit across every query path, every approval binding and every
audit read. That retrofit is the reason the predecessor implementation filed
organization-as-partition-key and never finished it.

An organization holds **people and agents together**. A hub that serves a
company has to know which humans belong to which team, because approvals,
reviews and escalation belong to a team's lead, not to one global operator
list. People are first-class rows, not configuration.

There are three levels of authority, and every rule below names one:

| Level | Who | Examples |
|---|---|---|
| **Hub** | Hub owners: the labels in `human_identities` | Create and suspend organizations, hub-wide policy, MCP servers, provider accounts, the vault, ledger verification |
| **Organization** | Members by role (`org_owner` … `auditor`) | Memberships, teams, specs, secrets, tokens, the organization's approvals |
| **Team** | A team's human leads | The team's own routed approvals and narrowing changes |

## What exists today

| Concept | Where | What it actually is |
|---|---|---|
| Profiles | `ua-core/src/profiles.rs`, `profiles.json` | A **capability overlay**. Decides which tools a session can see. Tiers: `public`, `remote-assistant`, `remote-vault-curator`, `research`, `acp-session`, `operator`, `reviewer`, `developer`, `lead`, `coordinator`, ordered by `Profile::rank`. |
| Agents | `agents` table | A **flat roster** of identity labels (`label` is the primary key). No owner, no reporting line, no grouping. |
| Organization | — | **Does not exist as a concept.** Verified at `28fdf58`: `Caller` has no organization, and no tool scopes by one. Two tables already carry a nullable, unused `org_id`: `harness_config_bundles` and `harness_config_proposals` (`harness_config/mod.rs`). |

Humans exist only as configuration. `human_identities` in `ua-core/src/config.rs`
is a flat list of labels; `Config::is_human` checks membership. Every path to
`ActorKind::Human` is gated on that list: bearer tokens (`ua-server/src/auth.rs`),
and login links, passkey start, registration and session lookup
(`ua-server/src/login.rs`). OAuth grants never act as a human. Any listed human
can approve any gated action: `approvals.rs::resolve` checks only
`caller.is_human()` and that the approver is not the requester. Beyond
approvals, `is_human()` / `cfg.is_human()` is the authority test at about fifty
call sites in twenty-six `ua-tools` modules — token minting, secret
administration, governance, node operations, MCP servers, GitHub authorization
and more.

`Caller` (`ua-core/src/identity.rs`) carries `label`, `kind`, `profile`,
`enforce_profile`, `session_key` and `transport`.

`goal_manage` **refuses** a `params.org_id` today (`invalid_argument`, asserted
in `ua-tools/tests/tasks.rs`), because its parameter structs deny unknown
fields. That stays: the organization never comes from tool arguments.

`ua-import` refuses source rows that carry an `org_id` only when `org_id` is an
**unmapped** column (`ua-import/src/lib.rs`); `--drop-org-scope` overrides and
records that boundaries were dropped. Where a target table already has an
`org_id` column (today `harness_config_bundles`), the source value is copied
silently. See [The importer](#the-importer) for why that must change in the
same change that adds the columns.

## The model

All of it is data rather than configuration, because the product promise is
that an operator can define their own organization at runtime and have that
definition audited.

```
users (global identity) ──┐
                          │ org_memberships (role)
orgs ─────────────────────┼── offices          (named capability scopes inside an org)
                          ├── teams            (groupings of people and agents; archived, never deleted)
                          │     ├── team_members  (principal_type human | agent, lead | member)
                          │     └── team_specs    (versioned, executable: seats, edges, budgets)
                          ├── reporting        (supervisor edges, temporal, informational)
                          ├── org_proposals    (self-organization, human-gated)
                          └── agents, tasks, memory, approvals, ...   (the tenant-scoped set)
```

- **user** — a human identity. Global, like a passkey: one person can belong to
  several organizations.
- **org membership** — a user's role in one organization (see [People](#people)).
- **org** — the tenant boundary. Created and suspended only by hub owners;
  never deleted.
- **office** — a named role scope within an org, carrying the capability
  profile it implies. Offices are runtime data, never a fixed enum. It is not
  an HR job title.
- **team** — a many-to-many grouping of people and agents, used for approval
  routing, memory visibility and task ownership.
- **team spec** — the executable definition of how a team's agent seats start,
  who they may interact with, and what they may spend.
- **reporting** — a temporal supervisor edge. Informational in v1: it answers
  "who reported to whom in March" and draws the org chart; no authority is
  derived from it.

**One label namespace.** Agent labels and user labels share one hub-wide
namespace: the writers for `agents` and `users` each refuse a label the other
table holds. Labels are identifiers, not secrets; creating either is
admin-gated, so the existence of a label is not treated as confidential.

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

CREATE TABLE IF NOT EXISTS org_bootstrap (
    label      TEXT PRIMARY KEY,   -- a human_identities label already synced once
    synced_at  TEXT NOT NULL
);
```

`users` is global, like `passkeys`; `org_memberships` is the tenant-scoped
grant. A role decides **which rows and which approvals** a person has authority
over. It never decides which tools a session can see — that stays with
profiles and the policy file.

| Role | Authority inside the organization |
|---|---|
| `org_owner` | Everything `org_admin` can do, plus granting and removing `org_owner`. The last owner cannot be removed or demoted. |
| `org_admin` | Manage memberships below owner, teams, offices, team specs, budgets, the organization's secrets, tokens and nodes. Approve any tenant-scoped gated action in the organization. |
| `team_lead` | Approve approvals routed to a team they lead, and narrowing changes to that team ([Self-organization](#self-organization)). |
| `member` | Belong to teams and request approvals. No approval authority. |
| `auditor` | Read the organization's ledger, approvals and audit exports. Cannot approve, deny, revoke, write or resolve anything. |

**Who is a human.** A verified credential whose label is either a hub owner
(`human_identities`) or an `active` user with at least one membership in an
`active` organization. This replaces the config-only test everywhere it gates
`ActorKind::Human`: `auth.rs` and every `login.rs` path. OAuth grants remain
never-human.

**User status.** Only hub owners suspend or reactivate a `users` row, because
the row is global. An organization's admins remove that person's membership
instead; that affects their organization only.

**Two-person rule.** Approver-is-not-requester compares labels, so one admin
must not be able to mint a second approver. Each of these needs an approval
from a different human holding `org_admin` or `org_owner` in that organization
— or, when no such human exists, a hub owner:

- granting `team_lead`, `org_admin` or `org_owner`;
- issuing a user's first credential (login link, passkey registration or
  token).

### Bootstrap and single-operator parity

`human_identities` is the hub-owner list and the bootstrap source. On start,
each listed label that has no `org_bootstrap` row gets a `users` row (if
missing), an `org_owner` membership in `'default'`, and an `org_bootstrap` row
— **once**. A later explicit removal of that membership is respected: the
bootstrap row is the tombstone, so a restart does not re-promote. Removing a
label from the config removes hub-owner authority but not its membership,
which is changed explicitly and recorded on the ledger. The bootstrap is
exempt from the two-person rule.

A hub with one configured human therefore behaves exactly as today: that human
is a hub owner and owns the default organization.

## Authority checks

Raw `is_human()` checks are replaced by one module, `ua-org::authz`, used by
every tool:

```rust
enum Authority<'a> {
    HubOwner,
    OrgRole { min: Role },                    // in the caller's organization
    TeamLead { team_id: &'a str },            // a human lead of that team
    Requester { approval_id: i64 },
}
fn require(caller: &Caller, need: &[Authority], target_org: &str) -> UaResult<()>;
```

Every check names the organization of the **target row**, and fails when it
differs from the caller's (hub owners acting on hub-scoped tools excepted). A
test fails if `is_human(` appears in `ua-tools` or `ua-server` outside
`authz`, so a new call site cannot skip the mapping.

Each registered tool declares `scope: Hub | Tenant`. A hub-scoped tool is
callable only by callers in `'default'`, and its approvals are resolvable only
by hub owners.

Initial mapping of today's call sites (the implementation PR classifies every
site; this table is the rule it follows):

| Module | Scope | Required authority |
|---|---|---|
| `approvals.rs` | Tenant | [Approvals routed by team](#approvals-routed-by-team) |
| `families/tokens.rs` | Tenant | `org_admin`; the target agent must be in the caller's organization; a user's first credential follows the two-person rule |
| `families/managed_secrets.rs` | Tenant | `org_admin` |
| `families/governance/*` (claim release, proposals, operator actions) | Tenant | `org_admin`, or the routed team's lead where the action is routed |
| `families/node_queue/*`, `families/dispatch` | Tenant | `org_admin` of the node's organization; node retire/unretire also by hub owners and `lifecycle_operators` |
| `families/tasks/write.rs` | Tenant | `member`; setting `tasks.team_id` needs `org_admin` or that team's lead |
| `families/messaging.rs`, `families/continuity/*` | Tenant | `member` |
| `families/memory/*` | Tenant | `member`; `broadcast` and salience above 0.8 need `org_admin` |
| `families/routines.rs`, `families/wake.rs` | Tenant | the owner, or `org_admin` |
| `families/capability.rs` | Tenant | any role, for its own organization |
| `families/mcp/*`, `families/github/authz.rs`, `families/vault/*`, `families/zulip.rs`, `families/relay/*` | Hub | hub owner |
| `config_revisions.rs`, `families/harness_config` publish of hub-wide surfaces | Hub | hub owner |

**`lifecycle_operators`** stays hub configuration. Its members are, by
definition, hub-level operators who may act across organizations; the list is
edited only by whoever controls the hub's config file. An organization's own
`org_admin` gets lifecycle authority over that organization's agents and nodes
only.

**Profile ceiling.** Each organization has a `max_profile`, set only by hub
owners. Every profile assignment in that organization — session profiles,
office profiles, spec seats — must have `Profile::rank` at or below it. The
migration sets `'default'` to `coordinator` (parity); new organizations
default to `lead`, so a tenant admin cannot hand out hub-level config
authority.

**Organizations.** `org_create` and `org_suspend` / `org_reactivate` are
hub-scoped and need a hub owner. A suspended organization's callers are refused
every tool with `org_suspended`, except reads by its `org_owner` and `auditor`
members; scheduled jobs skip it and its nodes take no work.

## Schema

Released schema parts are immutable; `ua-store/src/schema.rs` refuses to apply a
changed part and requires a new one. So this is **two new parts**:
`organization.v1` (new tables and added columns, one transaction) and
`organization.v1-rebuild` (tables whose keys must change, see
[Global keys](#global-keys-and-table-rebuilds)).

### New tables

```sql
CREATE TABLE IF NOT EXISTS orgs (
    id                        TEXT PRIMARY KEY,
    slug                      TEXT NOT NULL UNIQUE,
    display_name              TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active','suspended')),
    max_profile               TEXT NOT NULL DEFAULT 'lead',
    memory_default_visibility TEXT NOT NULL DEFAULT 'private'
                              CHECK (memory_default_visibility IN ('private','team','org')),
    self_organization         INTEGER NOT NULL DEFAULT 1 CHECK (self_organization IN (0,1)),
    created_at                TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS orgs_no_delete BEFORE DELETE ON orgs
BEGIN SELECT RAISE(ABORT, 'organizations are suspended, never deleted'); END;

CREATE TABLE IF NOT EXISTS offices (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    profile    TEXT NOT NULL,   -- a Profile name, validated by the writer
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug),
    UNIQUE (org_id, id)
);

CREATE TABLE IF NOT EXISTS teams (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    office_id  TEXT,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug),
    UNIQUE (org_id, id),
    FOREIGN KEY (org_id, office_id) REFERENCES offices(org_id, id)
);
CREATE TRIGGER IF NOT EXISTS teams_no_delete BEFORE DELETE ON teams
BEGIN SELECT RAISE(ABORT, 'teams are archived, never deleted'); END;

CREATE TABLE IF NOT EXISTS team_members (
    org_id         TEXT NOT NULL,
    team_id        TEXT NOT NULL,
    principal_type TEXT NOT NULL CHECK (principal_type IN ('human','agent')),
    principal      TEXT NOT NULL,   -- users.id for 'human', agent label for 'agent'
    member_role    TEXT NOT NULL DEFAULT 'member'
                   CHECK (member_role IN ('lead','member')),
    added_at       TEXT NOT NULL,
    PRIMARY KEY (team_id, principal_type, principal),
    CHECK (member_role = 'member' OR principal_type = 'human'),
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id)
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

Writer rules the schema cannot express, each with an acceptance test:

- A `lead` member must hold `team_lead`, `org_admin` or `org_owner` in the
  team's organization; eligibility is re-checked at approval time, so a demoted
  user stops leading without a second step.
- A human `principal` must have a membership in the team's organization; an
  agent `principal` must be an agent of that organization.
- `offices.profile` must be a `Profile` name with rank at or below the
  organization's `max_profile`.
- `reporting` endpoints must belong to the same organization; only
  `org_admin` and above write it.
- An archived team takes no new members, specs or `team_up`; its rows stay for
  history.

`team_specs` and `org_proposals` are in [Team specs](#team-specs) and
[Self-organization](#self-organization).

### Adding the column

SQLite permits `ADD COLUMN ... NOT NULL` only when a constant default is
supplied, which is exactly the behaviour wanted here: every existing row is
backfilled atomically with the default organization. (`ADD COLUMN` cannot also
carry `REFERENCES` with a non-NULL default while foreign keys are on, so
organization existence for added columns is guarded by triggers instead.)

```sql
INSERT OR IGNORE INTO orgs (id, slug, display_name, status, max_profile,
                            memory_default_visibility, created_at)
    VALUES ('default', 'default', 'Default organization', 'active', 'coordinator',
            'org', strftime('%Y-%m-%dT%H:%M:%S+00:00','now'));

ALTER TABLE tasks ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE tasks ADD COLUMN team_id TEXT;            -- owning team, nullable
ALTER TABLE approvals ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE approvals ADD COLUMN team_id TEXT;        -- routing team, nullable
ALTER TABLE approvals ADD COLUMN routing_basis TEXT NOT NULL DEFAULT 'org';
ALTER TABLE approvals ADD COLUMN escalated_at TEXT;
ALTER TABLE approvals ADD COLUMN escalation_targets TEXT;   -- JSON, set at escalation
ALTER TABLE memory ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory_versions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory_embeddings ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE ui_sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
UPDATE harness_config_bundles SET org_id = 'default' WHERE org_id IS NULL;
-- ... one ADD COLUMN org_id per remaining tenant table (see Scoping per subsystem)

CREATE TRIGGER IF NOT EXISTS tasks_team_same_org
BEFORE UPDATE OF team_id ON tasks
WHEN NEW.team_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM teams WHERE id = NEW.team_id AND org_id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'tasks.team_id must be a team of the task''s organization'); END;

CREATE TRIGGER IF NOT EXISTS approvals_team_same_org
BEFORE INSERT ON approvals
WHEN NEW.team_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM teams WHERE id = NEW.team_id AND org_id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'approvals.team_id must be a team of the approval''s organization'); END;
```

The same pair of triggers (insert and update) is generated for `tasks.team_id`
and `approvals.team_id`, and an insert trigger refusing an unknown `org_id` is
generated for every table that gains the column. Because organizations are
never deleted, insert-time existence is sufficient.

The memory part (`docs/memory.md`) adds only `visibility`, `team_id` and owner
columns to `memory`; `org_id` on `memory`, `memory_versions` and
`memory_embeddings` belongs to this part, so the two parts never add the same
column. `memory_default_visibility` is `'org'` for `'default'` (parity: every
agent on an upgraded hub recalls every note today) and `'private'` for every
new organization. Starter templates (a later `ua init`) may choose otherwise
when they create an organization; they are not defined here.

**The default is a migration convenience, not a safety net.** A tool path that
forgets `org_id` will silently write into the default organization instead of
failing. Three guards:

1. The resolver always binds `org_id` explicitly; it is never omitted.
2. A unit test walks the statement strings in the tenant-scoped families and
   fails for an `INSERT INTO <tenant table>` that does not name `org_id`.
3. Every lookup by id takes the caller's organization (`WHERE id = ? AND
   org_id = ?`) and returns the same `not_found` for another organization's row
   as for a missing one. This includes `approvals::get` in `resolve`.

### Global keys and table rebuilds

`ALTER TABLE` cannot change a primary key or a `UNIQUE` constraint. Every
existing global key is classified:

| Table and key | Class | Reason / action |
|---|---|---|
| `agents.label`, `users.label` | Hub namespace | One label namespace, shared by agents and users (above). Agents gain `org_id`; an agent belongs to one organization. |
| `nodes.node` | Hub namespace | Node names are registered hub-wide; `nodes` gains `org_id`, and a node serves one organization. |
| `provider_accounts.label`, `mcp_servers.name` | Hub table | Hub-scoped configuration, managed by hub owners. No tenant conflict. |
| `managed_secrets.name` | **Rebuild** | Key becomes `(org_id, name)`. |
| `skill_versions UNIQUE(name, version)` | **Rebuild** | Becomes `UNIQUE(org_id, name, version)`. |
| `skill_assignments UNIQUE(skill_name, target_type, target)` | **Rebuild** | Becomes `UNIQUE(org_id, skill_name, target_type, target)`. |
| `harness_config_bundles.version UNIQUE`, nullable `org_id` | **Rebuild** | `org_id NOT NULL`, `UNIQUE(org_id, version)`. |
| `harness_config_proposals` nullable `org_id` | **Rebuild** | `org_id NOT NULL`. |

Without the rebuilds, organization B could not create a secret or skill whose
name A uses, and the conflict error would tell B that A has it.

`organization.v1-rebuild` is a schema part flagged `rebuild`. `schema::apply`
runs a flagged part **outside** its usual `BEGIN IMMEDIATE` transaction, at
start-up before the hub serves, using SQLite's documented table-rebuild
procedure:

1. `PRAGMA foreign_keys = OFF` (it has no effect inside a transaction, which is
   why the part runs outside the normal one);
2. `BEGIN IMMEDIATE`; for each table: create `<table>_new` with the new keys,
   `INSERT INTO <table>_new SELECT …`, drop the old table, rename, recreate its
   indexes and triggers;
3. `PRAGMA foreign_key_check` — any row aborts with `ROLLBACK`;
4. record the part, `COMMIT`, `PRAGMA foreign_keys = ON`.

A failed rebuild leaves the database exactly as before and the hub refuses to
start, naming the part.

## Resolution

`Caller` gains `org_id: String` and `user_id: Option<String>`. Both are set by
the adapter from the verified credential and from nothing else:

| Credential | Organization | User |
|---|---|---|
| Static config token (`UA_AGENT_TOKENS`) | `'default'` (hub configuration issues it) | the users row, when the label is human |
| Agent token row (`agent_tokens`) | the agent's `agents.org_id` | none (agents are not users) |
| Node session credential (`uas_…`) | `session_credentials.org_id`, the organization of the work item it was minted for | none |
| OAuth grant | the grant's `org_id` | none — OAuth never acts as a human |
| Passkey / UI session | `ui_sessions.org_id`: chosen at login among the user's memberships, **re-validated against `org_memberships` on every request**; switching organization issues a new session id and CSRF token | the passkey's label |
| CLI and stdio, local | `'default'`, or `--org <slug>`, refused unless the label has a membership there | the users row, when the label is human |
| Anonymous HTTP (`enforce_auth` off) | `'default'` | none; never human |
| `Caller::system()` | `'default'` | none |
| `Caller::system_for(org_id)` | the named organization | none |

Background jobs (escalation timers, dispatch, wake, routines, consolidation)
iterate the active organizations and act through `system_for(org_id)`, so each
action is attributed to the organization it touches. There is no
organization-free caller.

**Never from tool arguments.** `goal_manage` keeps refusing `params.org_id`.

## Approvals routed by team

Today any configured human can approve anything. In an organization with
several teams that is wrong in both directions: Team A's lead should not need
the hub owner for routine approvals, and must not be able to approve Team B's
deploys.

**Routing team.** When an approval is requested, the gate determines a target
team `T` from the call itself and records `team_id` and `routing_basis`:

| Basis | When | `team_id` |
|---|---|---|
| `hub` | the tool is hub-scoped | `NULL`; resolvable only by hub owners |
| `task_team` | the call names a task whose `team_id` is set, **and** the requester is a member of that team | the task's team |
| `named_team` | the call is a team operation (`team_up`, spec commit, proposal apply) **and** the requester is a member of that team | the named team |
| `org` | anything else, including a requester naming another team's task | `NULL`; admins only |

So the requester cannot steer an approval to a lax team: naming a foreign
team's task routes to the organization level. `tasks.team_id` can be set only
by `org_admin` and above or by a lead of the team in question; agents cannot
set it. The routing team is part of the row the approver sees, not of the
bound payload, so routing never changes what is being approved.

**Eligibility.** `resolve` with `approve` succeeds only when every check holds,
evaluated at resolution time against current rows:

1. the caller is human and `caller.org_id == approvals.org_id`, or the basis is
   `hub` and the caller is a hub owner (an approval in A is invisible to, and
   never satisfiable from, B);
2. the caller is not the requester;
3. one of:
   - a. the caller's role is `org_owner` or `org_admin` (not for basis `hub`);
   - b. `team_id` is set and the caller is a `lead` member of that team with
     role `team_lead` or above;
   - c. the approval is escalated (`escalated_at` set), the caller is in
     `escalation_targets`, and still holds `team_lead` or above in the same
     organization;
4. `auditor` and `member` never approve.

`deny` follows the same eligibility, plus the requester. `revoke` requires the
same organization and either approve eligibility or being the requester.
Membership is evaluated at resolution, so a lead removed while an approval is
pending can no longer approve it.

**Escalation.** A team spec may set `approval_escalation: {after, to}`.
`after` has a floor of 15 minutes. Each target is `user:<id>` — a user with
`team_lead` or above in the same organization — or `team:<slug>` — a team of
the same organization, meaning its current leads. Targets are validated when the
spec is committed. A `system_for(org)` job marks a pending approval older than
`after` by setting `escalated_at` and `escalation_targets` (resolved user ids),
records an `agent.approval.escalated` event, and leaves `status` unchanged
(its `CHECK` is not altered). Escalation adds eligible approvers under rule 3c;
it never removes any. Organization admins are always eligible under 3a.

The seat-level `escalates_to` edge is separate: it routes a seat's blocked-task
notifications and confers no approval authority.

## Team specs

A team spec is the executable definition of a team: which agent seats exist,
how each one starts, how seats may interact, and what they may spend. It is
what lets one human approval bring up a working multi-harness team.

Specs are tenant data, not hub configuration, so they live in their own
append-only table rather than in `config_revisions` (which versions the
hub-wide policy file and whose `kind` set is fixed by its schema part).

```sql
CREATE TABLE IF NOT EXISTS team_specs (
    org_id         TEXT NOT NULL,
    team_id        TEXT NOT NULL,
    version        INTEGER NOT NULL,
    parent_version INTEGER NOT NULL,   -- 0 for the first commit
    spec           TEXT NOT NULL,      -- canonical JSON
    spec_sha256    TEXT NOT NULL,
    committed_by   TEXT NOT NULL,
    committed_at   TEXT NOT NULL,
    PRIMARY KEY (team_id, version),
    CHECK (parent_version = version - 1),
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id)
);
CREATE TRIGGER IF NOT EXISTS team_specs_no_update BEFORE UPDATE ON team_specs
BEGIN SELECT RAISE(ABORT, 'team specs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS team_specs_no_delete BEFORE DELETE ON team_specs
BEGIN SELECT RAISE(ABORT, 'team specs are append-only'); END;
```

A commit needs an approval bound to `(org_id, team_id, parent_version,
spec_sha256)` and is refused if the live version is no longer
`parent_version`, so two approved commits cannot silently overwrite each other.
Which approver it needs follows [Self-organization](#self-organization): a team
lead may approve a commit whose diff from the parent is narrowing only; anything
else, **including the first commit**, needs `org_admin`. Every commit appends an
`agent.team.spec` ledger event with the hash.

### Spec shape

```json
{
  "team": "platform",
  "office": "engineering",
  "budget": {"tokens_per_day": 4000000, "cost_usd_per_month": 900},
  "approval_escalation": {"after": "4h", "to": ["team:platform-leads"]},
  "seats": [
    {
      "label": "builder-1",
      "harness": "claude",
      "model": "<model id>",
      "fallback": [{"harness": "codex", "model": "<model id>"}],
      "node": "desk-01",
      "workspace": {"repo": "org/service", "worktree": "per_task", "trust_root": "/srv/work"},
      "profile": "developer",
      "skill_pack": "<published harness_config bundle version>",
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

Validation at commit (each refusal names the field):

- Every seat `label` is an agent member of this team, in this organization. A
  spec never creates an identity.
- `node` is a node of this organization; `skill_pack` is a published bundle of
  this organization; escalation targets are in this organization with an
  approving role.
- `harness` is one the harness-config surface supports; `fallback` entries are
  tried in order when the primary harness or its provider is unavailable or
  rate-limited.
- `profile` has rank at or below both the office's profile and the
  organization's `max_profile`.
- `workspace.trust_root` must be a root the named node itself reported. A spec
  can narrow trust, never grant it; workspaces are never auto-trusted.
- Seat budgets may not sum above the team budget.
- `delegates_to` and `escalates_to` are acyclic; edge endpoints are seats of
  this team, or `user:<id>` for `escalates_to`.
- `approval_escalation.after` is at least 15 minutes.
- Size is capped; unknown keys are refused.

### Edges are enforced, not decorative

When a team has a committed spec, its seats are governed by its edges — as
actors **and** as targets. Agents that are not seats of any spec are
unaffected as actors, but they cannot reach into a governed seat.

| Edge | Enforced at | As actor | As target |
|---|---|---|---|
| `delegates_to` | delegation and dispatch | A seat may delegate only along its edges. | A seat accepts delegation only from a seat with an edge to it, or from a human `org_admin` or lead of its team. |
| `reviews` | task stage review | A seat's review counts only for authors it has the edge to. | — |
| `escalates_to` | blocked-task notification | Where a seat's blocked tasks are announced. | — |
| `can_observe` | session, run and flight-recorder reads | A seat may read another seat's sessions and runs only along its edges. | A seat's sessions and runs are readable only by seats with an edge to it, and by humans of its organization with `org_admin`, `auditor` or lead of its team. |

All checks live in one function in `ua-org`, called by the tool wrapper's
policy layer. A refusal names the missing edge.

### Budgets

A seat has one budget pool, shared by its primary and its fallbacks; fallback
exists for availability, not to escape a cap. Usage is recorded per run on the
ledger with `usage_source`:

- `node` — reported by the node that ran the harness, from the harness's own
  usage output. Preferred.
- `agent` — reported by the agent. Accepted only where the node cannot report;
  admins see the split.

Budgets are sums over the ledger for the seat, the team and the window. A seat
at its cap is refused new dispatch with `budget_exhausted`, and its
`escalates_to` targets are notified. Enforcement granularity is one run: a run
in flight finishes.

### `ua team plan` and `ua team up`

`ua team plan <team>` (tool `team_plan`) is read-only. It reports two parts:

- `static`: what the spec and slow-moving rows determine — per seat the
  identity, node, harness, model, workspace, trust-root registration, skill
  pack hash, profile, budget limits, and edge validity, each with a refusal and
  its reason. This part is canonical JSON with no timestamps, so two plans of
  the same spec against the same rows are **byte-identical**; `plan_sha256` is
  its hash.
- `volatile`: node liveness, harness presence on the node, and budget headroom.
  Reported, never hashed.

`ua team up <team>` (tool `team_up`) boots a **committed** spec only. It
recomputes the plan and refuses if any `static` check fails, then requests one
approval bound to `(org_id, team_id, spec_sha256, plan_sha256)`, routed to the
named team (`named_team` basis). After approval it re-checks the `volatile`
part; if any seat fails, nothing launches, the refusals are returned, and the
pass stays unconsumed until it expires so a retry reuses it. Otherwise seats
launch in `delegates_to` order through the node work queue, one run record per
seat linked by a `team_run_id` on `agent.team.run`, and the pass is consumed.
A change to `static` facts changes `plan_sha256` and needs a new approval.

## Self-organization

Agents can see where their own team's structure is wrong — a missing reviewer, a
routing rule that bounces work, a routine nobody runs. They may **propose**
changes; they may never **apply** them.

```sql
CREATE TABLE IF NOT EXISTS org_proposals (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id),
    team_id     TEXT,
    proposer    TEXT NOT NULL,
    kind        TEXT NOT NULL
                CHECK (kind IN ('role','team','routing','skill','routine','edge','budget','other')),
    diff        TEXT NOT NULL,   -- structured patch against the live spec or rows
    base_sha256 TEXT NOT NULL,   -- hash of the state the diff applies to
    rationale   TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'proposed'
                CHECK (status IN ('proposed','applied','rejected','stale','withdrawn')),
    created_at  TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT,
    FOREIGN KEY (org_id, team_id) REFERENCES teams(org_id, id)
);
```

Rules:

1. **Proposing is on by default** and switched off per organization by
   `orgs.self_organization = 0`.
2. **Scope is membership.** A proposer may target only teams it is a
   `team_members` row of; its office scope is the offices of those teams. A
   proposal outside that scope is refused, not queued.
3. **Rate limited.** At most `org_proposal_daily_limit` proposals per proposer
   per day (default 10).
4. **Applying is never automatic.** Apply needs an approval bound to the
   proposal id, the diff hash and `base_sha256`. `base_sha256` is the live
   spec's `spec_sha256` for spec changes, and otherwise the SHA-256 of the
   canonical JSON of the targeted rows ordered by primary key. If the live
   state no longer hashes to it, the proposal becomes `stale` and is not
   applied.
5. **Team leads approve narrowing only.** A change is narrowing only if every
   part of it is on this list:
   - lowering a seat or team budget;
   - lowering a seat's profile;
   - removing a `delegates_to` or `can_observe` edge;
   - narrowing a `trust_root` to a subdirectory of itself;
   - removing a seat or an agent member.

   Everything else needs `org_admin` or `org_owner`. That includes adding
   members, any `reviews` change, `approval_escalation` and `escalates_to`
   changes, `skill_pack` (harness config, so code on a node), `node`,
   `workspace.repo`, `harness`, `fallback`, `model`, `guidance`, and every
   proposal of kind `skill` or `routine`.
6. Applying a spec change commits a new `team_specs` version through the same
   path as a human commit, so history has one shape.

The diff is structured so the review inbox can render it side by side.

## Scoping per subsystem

Every table is classified, and a test over `sqlite_master` fails on any table
missing from `ua-org`'s classification list. For every **tenant** table it also
checks, through `PRAGMA table_info`, that `org_id` exists and is `NOT NULL`.

| Class | Tables | Rule |
|---|---|---|
| Tenant: tasks and planning | `tasks`, `task_dependencies`, `task_fts` (joins through `tasks`), `task_comments`, `task_comment_threads`, `task_checks`, `task_holds`, `task_hold_members`, `task_workflow`, `task_goal_links`, `goals`, `work_proposals`, `work_proposal_items`, `review_ready_notices`, `project_repo_bindings`, `plans`, `plan_steps`, `plan_checkpoints`, `routines`, `routine_runs`, `workflow_runs`, `workflow_checkpoints`, `delegations`, `autonomous_cycles`, `autonomous_cycle_transitions`, `autonomous_cycle_usage` | `org_id`; `tasks` also has optional `team_id` |
| Tenant: agents and sessions | `agents`, `agent_sessions`, `agent_tokens`, `agent_lifecycle`, `session_profiles`, `session_credentials`, `session_handoff_notes`, `session_wake`, `session_wake_offers`, `dispatch_meta`, `dispatch_receipts`, `dispatch_runs` | An agent belongs to exactly one organization |
| Tenant: nodes | `nodes`, `node_acceptance`, `node_claim_ops`, `node_command`, `node_command_notice`, `node_dispatch`, `node_followups` | A node serves one organization |
| Tenant: people and teams | `org_memberships`, `offices`, `teams`, `team_members`, `team_specs`, `reporting`, `org_proposals` | Per organization |
| Tenant: memory | `memory`, `memory_versions`, `memory_embeddings`, `memory_fts` (joins through `memory`), and from `docs/memory.md`: `memory_chunks`, `memory_entities`, `memory_links`, `memory_consolidations`, `memory_consolidation_sources` | `org_id` plus a visibility tier, enforced in the search SQL — see `docs/memory.md` |
| Tenant: approvals and policy | `approvals`, `policy_authorizations` | `org_id` and routing `team_id` |
| Tenant: messages | `message_index`, `message_reads`, `notify_outbox`, `pending_notifications`, `relay_messages`, `zulip_sends` | `org_id` |
| Tenant: skills and config | `skill_versions`, `skill_assignments`, `skill_publish_staging`, `harness_config_bundles`, `harness_config_proposals`, `harness_config_drift`, `harness_config_report_window` | Catalog is per organization (keys rebuilt) |
| Tenant: other | `managed_secrets`, `graph_canvas_scenes`, `graph_canvas_revisions`, `idempotency_keys`, `tool_calls`, `web_search_cache`, `code_symbols` | `org_id`; the search cache is keyed by organization so one tenant's queries never answer another's |
| Tenant column on a global table | `event_log` | One chain, `org_id` per row — see [The ledger](#the-ledger) |
| Global identity | `users`, `passkeys`, `webauthn_states`, `login_links`, `oauth_clients`, `oauth_codes`, `oauth_grants`, `oauth_requests`, `oauth_tokens`, `ui_keys`, `ui_sessions`, `org_bootstrap` | Identity is global; the **grant** carries the organization (`oauth_grants.org_id`, `ui_sessions.org_id`) |
| Hub | `orgs`, `config_revisions`, `mcp_servers`, `provider_accounts`, `github_deliveries`, `github_delivery_bodies`, `github_poll_state`, `slack_seen_signatures`, `zulip_fetch_cursors`, `vault_ingest_ledger`, `import_runs`, `schema_parts`, `ledger_meta` | Hub-scoped tools only; hub owners |

## The ledger

`event_log` is a single global hash chain. The organization must not fork it,
or every existing chain verification breaks and cross-organization tamper
evidence disappears.

**Whose event.** An event's `org_id` is the organization of the **affected
row**, not of the caller. `ledger::EventInput` gains a required `org_id` field
with no default, so every call site must supply one and the compiler finds them
all. A system job acting for organization B writes B's `org_id`, so B's
auditors see it.

**Hash versioning.** Today `ledger::compute_entry_hash` hashes nine fields
(`causal_parent_id`, `channel`, `created_at`, `dedupe_key`, `episode_id`,
`originator`, `payload`, `prev_hash`, `ulid`) in the byte form the Python hub
produced, which is what lets imported chains verify. Adding a field changes that
form, so the hash is versioned:

```sql
ALTER TABLE event_log ADD COLUMN org_id  TEXT NOT NULL DEFAULT 'default';
ALTER TABLE event_log ADD COLUMN hash_v  INTEGER NOT NULL DEFAULT 1;
```

- `hash_v = 1`: the existing nine-field form. Every row written before the
  migration, and every imported row, keeps it. Their `org_id` is not covered by
  their hash, which is honest: those rows predate tenancy.
- `hash_v = 2`: the nine fields plus `org_id`, in sorted key position. Every
  row appended after the migration uses it.
- `verify()` chooses the form per row by `hash_v`, **refuses any other value**,
  and refuses a `hash_v = 1` row whose `seq` is after the first `hash_v = 2`
  row, so a downgrade cannot be slipped into the chain.

**Who verifies.** `verify()` walks every organization's rows and its counts
reveal each tenant's event volume, so it is hub-scoped: hub owners only. An
organization's audit export carries each of its rows with `prev_hash` and
`entry_hash`, so every row's own hash is checkable, but the export is not
chain-continuous on its own, because the chain links through other
organizations' rows. A hub owner's `verify()` attests the whole chain.

The Python verifier cannot check `hash_v = 2` rows. That is acceptable because
the Python hub is frozen and never reads a `ua-rust` ledger.

## Where the code lives

- **`ua-org`**, a new workspace crate: users, memberships, offices, teams,
  members, reporting, specs, proposals, the `authz` module, the edge check and
  approval eligibility. Its tools register through `ua-tools`, which stays a
  thin registry and envelope; no organization logic is added to `ua-tools`
  beyond the calls into `ua-org`.
- **`ua-store`** gains a `repo` module with an `OrgRepo` trait and its SQLite
  implementation. `ua-org` reaches the database only through that trait, and
  the trait exposes no `rusqlite` types. Methods are synchronous and run inside
  the hub's existing write transaction, because each write must commit
  atomically with its ledger append. A PostgreSQL backend is a later decision;
  this trait is where it would plug in, and the bundled SQLite WAL store stays
  the zero-configuration default.

## The importer

`organization.v1` adds `org_id` to the target tables, which would turn today's
refusal into a silent copy: once the column is mapped, source values are copied
verbatim, a source `NULL` fails `NOT NULL` (an explicit `NULL` bypasses the
default), and a non-null value points at an organization that does not exist.
So **the same change** makes the importer exclude `org_id` from column mapping
explicitly for every table, and keep refusing rows that carry one, until an
explicit mapping is given:

- **A.** `--drop-org-scope`: every source row goes to `'default'`, and the
  report says so.
- **B.** `--org-map <source_org_id>=<target_org_id>`, repeated. Every distinct
  non-NULL source `org_id` must be mapped, or the import refuses and lists the
  unmapped ones. Source rows with `NULL` go to `'default'`. A target
  organization must already exist (a hub owner creates it first), so the
  importer never invents one. This is the cutover path, checked by the
  migration manifest compare, which records the mapping in its fingerprint.

Imported ledger rows keep `hash_v = 1`, so the `org_id` the mapping assigns to
them is **not** covered by their hash. Imported boundaries are as trustworthy as
the import run that set them, which is recorded on `import_runs`.

## What this is not

- **Not a tool-permission matrix.** Capability stays with profiles and the
  policy file, bounded by each organization's `max_profile`. Roles decide which
  rows a person administers and which approvals they may resolve.
- **Not hard isolation.** Organizations share one hub and one database. Hard
  data-plane separation per organization was considered and not chosen.
- **Not a job-title system.** Offices carry a profile and a name. No HR
  semantics; reporting edges are informational.
- **Not an external directory.** Users are created by admins or bootstrapped
  from `human_identities`. An external identity provider (OIDC, SAML, SCIM) is a
  later layer that verifies the person and their membership; this model stays
  the authority on what they may do.

## Decisions

The three questions left open in the first draft are settled:

1. **`Caller::system()` belongs to `'default'`.** Hub maintenance runs as the
   default organization. A job that acts for another organization uses
   `Caller::system_for(org_id)`; there is no organization-free caller, so no
   code path can read across tenants by accident. The one sanctioned global
   read is `verify()`, hub owners only.
2. **Offices are runtime data**, not a fixed enum, since the product promise is
   that an operator defines their own.
3. **Tasks are organization-local in v1.** Task identity does not move between
   organizations; a cross-organization handoff is a copy plus a reference.

## Acceptance

Parity and isolation

1. **Single-organization parity.** The existing suite passes unchanged (including
   `goal_manage` refusing `params.org_id`), the default organization is invisible
   to callers, and a hub with `human_identities = ["operator"]` lets that human do
   exactly what they can do today.
2. **Read isolation, registry-driven.** Seed organization A through the write
   tools of every family, then call every `read_only` tool as a caller in B
   (with A's ids where a tool takes one), plus the SSE event stream, the compat
   API and exports: zero A rows, and A's ids return the same `not_found` as a
   missing id.
3. **Classification.** The `sqlite_master` test fails on an unclassified table
   and on a tenant table whose `org_id` is missing or nullable.
4. **Resolver guard.** The statement-walking test fails if a tenant-scoped
   insert omits `org_id`.
5. **Cross-org references.** Inserting a team member, team office, spec, task
   `team_id` or approval `team_id` that points at another organization fails.
6. **Global keys.** After the rebuild, A and B can each create a secret, a skill
   version, a skill assignment and a harness bundle with the same name, and
   neither error reveals the other; a rebuild that fails `foreign_key_check`
   leaves the database unchanged and the hub refuses to start.

People and authority

7. **Human derivation.** An admin-created active user with a membership logs in
   as a human; a suspended user, or one with no active membership, does not; an
   OAuth grant never does.
8. **Authz guard.** The test fails on `is_human(` outside `authz`; for each row
   of the authority table, a `member` and an `auditor` are refused, and a caller
   in B is refused on A's target (for example minting a token for A's agent).
9. **Hub scope.** A hub-scoped tool is refused to a caller outside `'default'`;
   its approval is refused to an `org_admin` and accepted from a hub owner;
   `org_create` and `org_suspend` are hub-owner only.
10. **Profile ceiling.** Assigning a profile above `max_profile` to a session,
    office or seat is refused.
11. **Suspension.** A suspended organization's callers get `org_suspended` except
    owner and auditor reads; its nodes receive no work. Only a hub owner can
    suspend a user.
12. **Bootstrap.** A label in `human_identities` gets one `org_owner` membership
    once; removing that membership explicitly survives a restart; removing the
    label from the config removes hub-owner authority but not the membership.
13. **Two-person rule.** Granting `team_lead` or above, and issuing a user's
    first credential, are refused without an approval from a different eligible
    human; the last owner cannot be removed or demoted.
14. **Label namespace.** Creating a user with an agent's label, or the reverse,
    is refused.
15. **Resolution.** For each credential row of the resolution table, the caller
    gets the stated organization; a UI session whose membership is removed is
    refused on its next request; switching organization rotates the session id
    and CSRF token; `--org` without a membership is refused.

Approvals

16. **Routing.** `task_team` when the requester is a member of the task's team;
    `org` when the requester names another team's task or no task; `named_team`
    for `team_up`; `hub` for a hub-scoped tool. An agent cannot set
    `tasks.team_id`.
17. **Eligibility.** Team A's lead approves a `task_team` approval for A; is
    refused on B's, on an `org` one and on a `hub` one; `auditor` and `member`
    are refused; `org_admin` approves the first three; a lead removed while an
    approval is pending is refused; the requester is always refused.
18. **Cross-org approval.** An approval created in A cannot be seen, approved,
    denied or revoked from B, and does not satisfy the identical payload in B.
19. **Escalation.** After `after` elapses, a listed target with `team_lead` or
    above can approve; a target who lost the role cannot; `after` below 15
    minutes and a target outside the organization are refused at commit; status
    stays `pending` throughout.

Ledger

20. **Integrity.** `verify()` reports a valid chain across `hash_v` 1 and 2; an
    unknown `hash_v` fails; a `hash_v = 1` row after the switch fails; `verify()`
    is refused to anyone but a hub owner.
21. **Attribution.** An event written by a `system_for(B)` job about B's row
    carries B's `org_id` and appears in B's audit read, not A's.

Teams

22. **Spec commit.** A commit against a stale `parent_version` is refused; a
    first commit approved by a team lead is refused; a node, bundle or escalation
    target from another organization is refused.
23. **Plan determinism.** Two `team_plan` calls on the same spec and rows are
    byte-identical in `static`; a heartbeat or a new run changes only `volatile`;
    changing a seat's node changes `plan_sha256`.
24. **Team up.** An uncommitted spec, or a `static` refusal, is refused; a failed
    `volatile` check launches nothing and leaves the pass reusable; a changed
    `plan_sha256` needs a new approval.
25. **Edges.** For each edge type, the action is allowed with the edge and
    refused without it (naming the edge); a non-seat agent cannot delegate to or
    observe a governed seat; an `auditor` human can observe.
26. **Budgets.** A seat at its cap is refused with `budget_exhausted` regardless
    of fallbacks; a primary marked unavailable falls back within the same pool;
    usage records carry `usage_source`.
27. **Self-organization.** A proposal outside the proposer's teams is refused;
    the daily limit is enforced; the switch off suppresses proposing; a stale
    base is not applied; for each non-narrowing category, a team lead's approval
    is refused and an admin's is accepted; apply writes a new spec version.
28. **Teams and reporting.** Deleting a team fails and archiving blocks new
    members and `team_up`; a reporting query for a past date returns the
    supervisor in effect then.

Importer

29. **Exclusion.** Against an `organization.v1` target, a source row carrying
    `org_id` is refused without `--drop-org-scope` or `--org-map`, including for
    `harness_config_bundles`.
30. **Mapping.** `--drop-org-scope` imports everything into `'default'`; a
    two-organization source with both ids mapped keeps both; an unmapped source
    id or a missing target organization refuses the import.
