# Organization model

Status: **design, first infrastructure in the tree.** This document is the
review gate for the `organization.*` schema parts and the `ua-org` crate. Its
companion is `docs/memory.md` (PR #40), which relies on the decisions recorded
here for memory columns, owners and defaults.

`organization.v1` lands in several PRs rather than one. What is in the tree:

- The `Procedure` part kind with `version` refusal and the `standalone` flag
  ([Schema](#schema)). It departs from the wording below in one way:
  `SchemaPart` stays the static kind, unchanged, and both kinds convert into
  a `Part` that `schema::apply` takes, so existing static parts did not
  change. A procedure's generated SQL is stored in a `schema_procedures`
  table, created with the first procedure that runs, rather than in a column
  of `schema_parts`, so an older database and an older backup keep exactly
  the objects they had.
- `organization.v1.store`: `orgs` (created without `IF NOT EXISTS`, so a
  database holding another `orgs` table refuses the part), the seed, and
  `event_log.org_id` and `event_log.hash_v`. Every row is written with
  `hash_v = 1`, the nine-field form, which does **not** cover `org_id`: until
  rows are written with `hash_v = 2`, a row's `org_id` can be changed without
  `verify()` noticing. `verify()` refuses any `hash_v` other than 1.
- `ua_store::org::tenant_part`. It takes the full part name
  (`organization.v1.<crate>`) rather than the owner alone, so the part stays a
  constant. No table uses it yet.
- `ua_core::DEFAULT_ORG`.
- The importer exclusion: `org_id` is never mapped by column name.
- The classification test (`crates/ua-tools/tests/org_classification.rs`,
  until `ua-org` exists). It uses the classes in
  [Scoping per subsystem](#scoping-per-subsystem), plus `schema_procedures`
  as a hub table. **The test is the authority on classification**; the table
  in that section is a copy kept in step with it. Two temporary relaxations
  may only shrink: the tenant tables still missing `org_id` (all 68 today,
  frozen as a baseline that a new table cannot join), and the grant tables
  `oauth_grants` and `ui_sessions`, which must carry `org_id` and do not yet.
- The procedure checksum covers the part's name, `version` and arguments,
  so a table added to a released tenant part is refused, not skipped.
- A rollback fence: opening the store, and every append, refuses a ledger
  whose newest row has a `hash_v` above the build's.

- `Caller.org_id` (always `DEFAULT_ORG`; a serialized caller without it
  reads as the default) and `Caller::system_for(org_id)`, with
  `Caller::system()` in the default organization. A source test
  (`crates/ua-core/tests/org_guard.rs`, over every crate's non-test source)
  fails if a `Caller` literal, an `EventInput`, or an `.org_id =`
  assignment names any organization but `DEFAULT_ORG` (a caller's
  organization included), or if anything calls `system_for`, before
  memberships exist.
- `EventInput::new(org_id, …)` with `Default` removed, so every event names
  its organization; every site passes `ua_core::DEFAULT_ORG`, the
  organization of the affected row, never the caller's. `append` writes
  `org_id` and `hash_v` explicitly, and refuses an organization `orgs` does
  not hold. On a ledger from before
  `organization.v1.store` (an older backup just restored) it writes the old
  row shape, and refuses any organization other than the default rather than
  drop it. `org_id` is still not covered by the hash.

- The `ua-org` crate, holding only `authz` for now. Departure from the
  [Authority checks](#authority-checks) API: until users and memberships
  exist (`organization.v2`), authority comes from the hub configuration, so
  the checks run through an `Authz { cfg }` value with
  `require(caller, need, target_org)` and `holds(...)`. `target_org` must be
  `'default'` and the caller's organization; anything else is refused. The
  authorities are **transitional**: each reproduces one rule the tree used,
  and names the design authority that replaces it. Four of them use a
  profile as authority, which this design forbids; they are marked, and kept
  only to preserve behaviour. The operator, dispatch, hub-view and mailbox
  predicates delegate to `authz`, and ua-memory's human check goes through
  it. A guard test (`crates/ua-core/tests/authz_guard.rs`) holds per-crate
  counts of the remaining ad-hoc checks (`is_human` definitions and calls,
  `is_lifecycle_operator` calls, `fn is_operator…`, profile comparisons and
  matches, profile-as-authority uses, `ActorKind` comparisons and matches,
  and direct reads of `human_identities` / `lifecycle_operators`), which may
  only go down. It scans `ua-core` too, skipping only the files that define
  the primitives. One behaviour change:
  an unverified caller naming a configured human as its actor is no longer a
  workflow-record operator.

- Authority comes from identity, never from a profile (two owner
  decisions). `Operator` is a verified human; `LifecycleOperator` is a
  separate fleet-maintenance grant for agents in `lifecycle_operators`,
  never operator authority, named at each call site that admits it next to
  `Operator`. The coordinator and operator profiles grant nothing; the
  profile-as-authority count in the guard is 0. Unverified mailbox reads
  (auth enforcement off) are unchanged and under review
  (`LocalTrustReader`).

Not yet: the tenant parts, the label and launch-key indexes, the
`memory_versions_capture` trigger, `hash_v = 2`, and everything after
`organization.v1`.

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
| **Hub** | Hub owners (below) | Create and suspend organizations, hub-wide policy, MCP servers, provider accounts, the vault, credentials that cross organizations |
| **Organization** | Members by role (`org_owner` … `auditor`) | Memberships, teams, specs, secrets, tokens, settings, the organization's approvals |
| **Team** | A team's human leads | The team's own routed approvals and narrowing changes |

## What exists today

| Concept | Where | What it actually is |
|---|---|---|
| Profiles | `ua-core/src/profiles.rs`, `profiles.json` | A **capability overlay**. Decides which tools a session can see. Ten profiles: `public`, `remote-assistant`, `remote-vault-curator`, `research`, `acp-session`, `operator`, `reviewer`, `developer`, `lead`, `coordinator`. `Profile::rank` orders them for display only; it does **not** order capability (`operator`, rank 4, sees `approval_resolve`, which `lead`, rank 7, does not). |
| Agents | `agents` table | A **flat roster** of identity labels (`label` is the primary key). No owner, no reporting line, no grouping. |
| Organization | — | **Does not exist as a concept.** Verified at `28fdf58`: `Caller` has no organization, and no tool scopes by one. Two tables already carry a nullable, unused `org_id`: `harness_config_bundles` and `harness_config_proposals` (`harness_config/mod.rs`). |

Humans exist only as configuration. `human_identities` in `ua-core/src/config.rs`
is a flat list of labels; `Config::is_human` checks membership. The paths that
decide `ActorKind::Human` or refuse a human are:

- `ua-server/src/auth.rs` (bearer tokens; OAuth access tokens are refused for
  human subjects);
- `ua-server/src/login.rs` (login links, passkey start, registration, session
  lookup);
- `ua-server/src/oauth/authorize.rs` and `oauth/token.rs` (a human may not be
  an OAuth subject);
- `ua-server/src/compat_api.rs` (a local `fn is_human` over the identity);
- `ua-server/src/events.rs` (UI sessions on the event stream are human);
- `ua-cli/src/main.rs` (a local `--label` naming a human, after confirmation).

Any listed human can approve any gated action: `approvals.rs::resolve` checks
only `caller.is_human()` and that the approver is not the requester. Beyond
approvals, `is_human()` / `cfg.is_human()` is the authority test at 45 call
sites in 26 `ua-tools` files — token minting, secret administration,
governance, node operations, MCP servers, GitHub authorization and more —
and a few checks grant authority by profile or by `is_lifecycle_operator`
instead.

`Caller` (`ua-core/src/identity.rs`) carries `label`, `kind`, `profile`,
`enforce_profile`, `session_key` and `transport`.

`goal_manage` **refuses** a `params.org_id` today (`invalid_argument`, asserted
in `ua-tools/tests/tasks.rs`), because its parameter structs deny unknown
fields. That stays: the organization never comes from tool arguments.

`ua-import` never copies `org_id` as a column on any table (including
`harness_config_bundles`, `work_proposals`, `work_proposal_items`, `task_holds`,
and `project_repo_bindings`): any non-NULL `org_id` rows are reported in
`org_scoped_rows` and refused unless `--drop-org-scope` is passed (which drops
the tenant boundary and leaves target `org_id` NULL on tables that carry the
column). See [The importer](#the-importer) for the multi-tenant import design when org
columns are introduced.

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
- **org** — the tenant boundary, with its settings. Created and suspended only
  by hub owners; never deleted.
- **office** — a named role scope within an org, carrying the set of capability
  profiles its agents may hold. Offices are runtime data, never a fixed enum.
  It is not an HR job title.
- **team** — a many-to-many grouping of people and agents, used for approval
  routing, memory visibility and task ownership.
- **team spec** — the executable definition of how a team's agent seats start,
  who they may interact with, and what they may spend.
- **reporting** — a temporal supervisor edge. Informational in v1: it answers
  "who reported to whom in March" and draws the org chart; no authority is
  derived from it.
- **agent owner** — an agent may name the human it acts for
  (`agents.owner_user_id`). Memory uses it to decide which agent may summarize
  that human's private notes; nothing else derives authority from it.

**One label namespace.** Agent labels and user labels share one hub-wide
namespace, compared **case-insensitively** (as `agent_lifecycle.agent` already
is). Today `agents.label` is a case-sensitive primary key, so `Builder-1` in B
could coexist with `builder-1` in A and then overwrite A's NOCASE
`agent_lifecycle` row. `organization.v1` therefore adds a unique index on
`agents(label COLLATE NOCASE)`, after a pre-check that refuses to apply the
part and lists any existing case-collisions for the operator to resolve; the
writers for `agents` and `users` — including `touch_agent`'s auto-create on
first contact — each refuse a label the other table holds in any case. Labels
are identifiers, not secrets; creating either is admin-gated, so the existence
of a label is not treated as confidential.

**Reserved labels.** Every label named in hub configuration —
`human_identities`, `lifecycle_operators`, static `UA_AGENT_TOKENS` labels and
the `[profiles]` map — is **reserved**. A reserved label's row may be created
only in `'default'`, and only by a hub owner, by that label's own verified
credential resolving to `'default'`, or by a local stdio or CLI caller on the
hub host (which already carries hub-host trust, see Resolution). The check
keys on the transport (`Transport::Stdio` / CLI), never on
`ActorKind::Anonymous`, because anonymous HTTP with `enforce_auth` off has the
same actor kind and must stay refused. So a
static-token, `[profiles]` or local agent's first `session_start` or heartbeat
still creates its own row, exactly as today. Every other writer — a tenant
admin, an unverified remote caller, `touch_agent` acting for anyone else —
refuses it in any letter case. A tenant
admin therefore cannot pre-create a row for a label the hub's own config will
later trust, and the config's trust never lands in a tenant. Reservation is
checked at write time, so a label added to the config after an organization
other than `'default'` already holds it is reported `MISCONFIGURED` by
`system_doctor`, and the hub keeps starting but does not grant that label any
configured authority (static token, lifecycle operator, hub owner) until the
operator resolves it — the same treatment as Bootstrap's unadopted row. Rows in
`'default'` are not a conflict; that is where reserved labels belong.

## People

```sql
CREATE TABLE IF NOT EXISTS users (
    id           TEXT PRIMARY KEY,
    label        TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- the label credentials carry
    display_name TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active','suspended')),
    bootstrap    INTEGER NOT NULL DEFAULT 0 CHECK (bootstrap IN (0,1)),
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS org_memberships (
    org_id   TEXT NOT NULL REFERENCES orgs(id),
    user_id  TEXT NOT NULL REFERENCES users(id),
    role     TEXT NOT NULL
             CHECK (role IN ('org_owner','org_admin','team_lead','member','auditor')),
    profile  TEXT,                 -- session profile in this org; NULL = 'reviewer'
    consolidate_private INTEGER NOT NULL DEFAULT 0
             CHECK (consolidate_private IN (0,1)),  -- set only by the member themselves
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS org_bootstrap (
    label      TEXT PRIMARY KEY COLLATE NOCASE,  -- a human_identities label synced once
    synced_at  TEXT NOT NULL
);
```

`users` is global, like `passkeys`; `org_memberships` is the tenant-scoped
grant. A role decides **which rows and which approvals** a person has authority
over.

| Role | Authority inside the organization |
|---|---|
| `org_owner` | Everything `org_admin` can do, plus granting and removing `org_owner` and changing owner-only settings. The last owner cannot be removed or demoted. |
| `org_admin` | Manage memberships below owner, teams, offices, team specs, budgets, settings, the organization's secrets, agent tokens and nodes. Approve approvals whose required authority is `org_admin` or `team_lead`. |
| `team_lead` | Approve approvals whose required authority is `team_lead` and that are routed to a team they lead ([Approvals](#approvals-routed-by-team)). |
| `member` | Belong to teams and request approvals. No approval authority. |
| `auditor` | Read the organization's ledger, approvals and audit exports. Cannot approve, deny, revoke, write or resolve anything. |

### Hub owners

A **hub owner** is a label listed in `human_identities` **whose `users` row was
created by the bootstrap** (`users.bootstrap = 1`). Only the bootstrap sets that
flag. Binding hub authority to a bootstrap-created row, not to the label alone,
means a row a tenant admin created — and every credential issued for it — can
never become a hub owner by having its label added to the config later.

### Who is a human

A verified credential is human when its label is:

1. a hub owner; or
2. an `active` user with a membership in an `active` organization; or
3. an `active` user whose only memberships are `org_owner` or `auditor` in a
   **suspended** organization — signed in **read-only**, so owners and
   auditors can still inspect a suspended tenant.

This replaces the config-only test at every path listed above. OAuth grants
remain never-human. A local CLI or stdio caller with `--label` runs on the hub
host itself, so a human label there carries **hub-host trust**, equivalent to a
hub owner; this is stated, not hidden, and unchanged from today's confirmation
prompt.

**User status.** Only hub owners suspend or reactivate a `users` row, because
the row is global. An organization's admins remove that person's membership
instead; that affects their organization only.

### Credentials for people

- A credential for **another** human — a login link, a passkey-registration
  invite, or a token on a human label — always needs an approval from a
  different eligible human (two-person). The required authority is
  `org_admin` in the issuer's organization, and **`hub_owner`** when the target
  user holds any membership outside that organization or is a hub owner. So a
  tenant admin who adds someone else's user to their organization cannot then
  sign in as them.
- **Adding** an existing user who holds a membership in another organization,
  or who is a hub owner, is itself two-person with required authority
  **`hub_owner`**. This closes the reverse path: B's admins cannot create a
  user (perhaps under an expected label), give it credentials, and wait for A's
  admin to add "the same person" to A, because that addition needs a hub owner
  who sees the user's other memberships and credential issuers.
- `agent_token_issue` and the managed-token tools refuse any label that is a
  `users` label or listed in `human_identities`; agent tokens are for agents.
- Granting `team_lead`, `org_admin` or `org_owner` is also two-person, with
  required authority `org_admin` (`org_owner` for granting `org_owner`).
- Exemptions: the bootstrap, and grants or credentials **requested by a hub
  owner**, because a hub owner already controls the hub's configuration and a
  second approver adds nothing. Each is still recorded on the ledger.
- Every credential issued for a user records the issuer and the user id.

### Bootstrap and single-operator parity

`human_identities` is the hub-owner list and the bootstrap source. On start,
for each listed label with no `org_bootstrap` row:

- if no `users` row has that label (case-insensitive), create one with
  `bootstrap = 1`, an `org_owner` membership in `'default'`, and the
  `org_bootstrap` row — **once**;
- if a `users` row already exists that the bootstrap did not create, **do not
  adopt it**: that label is not a hub owner, and `system_doctor` reports the
  hub-owner row `MISCONFIGURED` naming the label. The operator resolves it on
  the hub host with `ua org adopt-owner <label>` (hub-host trust), which
  revokes every credential issued for that row, sets `bootstrap = 1` and
  records the adoption on the ledger.

In the same transaction the bootstrap calls the memory re-own hook for the new
user. The hook, and the `memory.owner_type` column it writes, belong to the
memory scope PR (`docs/memory.md`, `MemoryRepo::reown_for_user`); before that
part has applied no hook is registered and the call does nothing. The step is
idempotent.

A later explicit removal of the membership is respected: the `org_bootstrap`
row is the tombstone, so a restart does not re-promote. Removing a label from
the config removes hub-owner authority, not the membership.

A hub with one configured human therefore behaves exactly as today: that human
is a hub owner and owns the default organization.

## Organization settings

Settings are columns on `orgs`, changed only through `org_settings_update`,
which records an `agent.org.settings` ledger event with the old and new values:

| Setting | Default | Who changes it |
|---|---|---|
| `allowed_profiles` | `'default'`: all ten; new orgs: `public`, `remote-assistant`, `research`, `acp-session`, `reviewer`, `developer`, `lead` | hub owners only |
| `memory_default_visibility` | `'private'`; `'org'` for `'default'` | `org_admin` |
| `self_organization` | on | `org_admin` |
| `proposal_daily_limit` | 10 | `org_admin` |
| `memory_consolidator_label` | none | `org_admin`; must be an agent of the org |
| `allow_remote_embedder` | off | `org_owner` |

## Authority checks

Raw `is_human()` checks are replaced by one module, `ua-org::authz`, used by
every tool and every adapter:

```rust
enum Authority<'a> {
    HubOwner,
    LifecycleOperator,                        // hub configuration; crosses organizations
    OrgRole { min: Role },                    // in the target row's organization
    TeamLead { team_id: &'a str },            // a human lead of that team
    Requester { approval_id: i64 },
}
fn require(caller: &Caller, need: &[Authority], target_org: &str) -> UaResult<()>;
```

Every check names the organization of the **target row** and fails when it
differs from the caller's, except `HubOwner` on hub-scoped tools and
`LifecycleOperator`, which are hub authority by definition.
`LifecycleOperator` holds only when the caller's label is in
`lifecycle_operators` **and** is either an agent whose row is in `'default'` or
a hub-owner user — never a same-named row a tenant created (reserved labels make
that row impossible to create, and this check makes it useless if it existed).

**The guard test** scans **every workspace crate except `ua-org`** and fails on
any of these outside `authz`: a call to `is_human(` or `is_lifecycle_operator(`,
a definition of `fn is_human`, and a `match`/`matches!` on `caller.profile` used
as an authority decision. Known sites the implementation must move include
`compat_api.rs`'s local `is_human`, `capability.rs` (hub boundaries shown to
the `operator` profile), `dispatch/tools.rs`, `vault_move`, `messaging.rs`,
`config_revisions.rs`, `nodes.rs`, `node_queue/command.rs`,
`continuity/mod.rs`, and in `crates/ua-memory` (extracted by #49) the
`fn is_human` in `note.rs` and its uses in `lifecycle.rs` (delete, restore,
privileged fields). `ua-core` is the one other exemption: it defines the
primitives (`Caller::is_human` in `identity.rs`, `Config::is_human` and
`Config::is_lifecycle_operator` in `config.rs`) and tests them; the guard
allows those definitions and `ua-core`'s own unit tests, and nothing else.

**Tool scope.** Each registered tool declares `scope: Hub | Tenant`, an
approval authority class, and whether its approvals are `team_routable`. A
hub-scoped tool is callable only by callers in `'default'` — agents and humans
alike — and its approvals need a hub owner.

Initial mapping of today's call sites (the implementation PR classifies every
site; this table is the rule it follows):

| Module | Scope | Required authority | Team-routable |
|---|---|---|---|
| `approvals.rs` | Tenant | [Approvals routed by team](#approvals-routed-by-team) | — |
| `families/tokens.rs` | Tenant | `org_admin`; target agent in the caller's org; human credentials per [Credentials for people](#credentials-for-people) | no |
| `families/managed_secrets.rs` | Tenant | `org_admin` | no |
| `families/governance/*` (claim release, proposals, operator actions) | Tenant | `org_admin` | claim release only |
| `families/node_queue/*`, `families/dispatch` | Tenant | `org_admin` of the node's organization; retire/unretire also hub owners and `lifecycle_operators` | dispatch only |
| `families/tasks/write.rs` | Tenant | `member`; setting `tasks.team_id` per [Routing](#approvals-routed-by-team) | — |
| `families/messaging.rs`, `families/continuity/*` | Tenant | `member` | — |
| `families/memory/*` | Tenant | `member`; `broadcast` and salience above 0.8 need a verified human with `org_admin` or above | — |
| `families/routines.rs`, `families/wake.rs` | Tenant | the owner, or `org_admin` | — |
| `families/capability.rs` | Tenant | any role, for its own organization; hub boundaries only to hub owners | — |
| `families/mcp/*`, `families/github/authz.rs`, `families/vault/*`, `families/zulip.rs`, `families/relay/*` | Hub | hub owner | no |
| `config_revisions.rs`, `families/harness_config` publish of hub-wide surfaces | Hub | hub owner | no |
| team spec commit, `team_up`, proposal apply | Tenant | `team_lead` for narrowing changes and `team_up`, else `org_admin` | yes |

**`lifecycle_operators`** stays hub configuration. Its members are hub-level
operators who may act across organizations; `require()` admits them through
`Authority::LifecycleOperator` (bound to a `'default'` agent row or a hub-owner
user, above), and the list is edited only by whoever controls the hub's config
file. An organization's own `org_admin` has lifecycle
authority over that organization's agents and nodes only.

**Profiles.** A profile decides which tools a session sees; a role never does,
with one stated exception: `approval_pending` and `approval_resolve` are
visible to a verified human holding an approving role (`team_lead` or above)
whatever their profile, so a tenant's leads can act on their approvals.
Session profiles come from:

- `'default'`: the hub config's `[profiles]` by label, as today (parity);
- other organizations, agents: `agents.default_profile` (set by `org_admin`),
  else `developer`;
- other organizations, humans: `org_memberships.profile`, else `reviewer`.

Every profile assigned in an organization — session, office, seat, agent
default, membership — must be in its `allowed_profiles` set. A set, not a rank
ceiling, because rank does not order capability.

**Organizations.** `org_create` (which names the first `org_owner`, an existing
user) and `org_suspend` / `org_reactivate` are hub-scoped and need a hub owner.
A suspended organization's callers are refused every tool with
`org_suspended`, except read tools for its `org_owner` and `auditor` members;
scheduled jobs skip it and its nodes take no work.

## Schema

Released schema parts are immutable; `ua-store/src/schema.rs` refuses to apply a
changed part and requires a new one. The organization model lands as **several
steps**, one per implementation PR, in this order:

| Step | Contents |
|---|---|
| `organization.v1` | `orgs`, `org_id` columns with immutability and existence triggers, `hash_v`, the case-insensitive agent label index, the recreated `memory_versions_capture` trigger, the `node_dispatch` launch-key index, the classification test, the importer exclusion, `Caller.org_id` |
| `organization.v1-rebuild` | the tables whose keys must change ([Global keys](#global-keys-and-table-rebuilds)) |
| `organization.v2` | `users`, `org_memberships`, `org_bootstrap`, agent owner and profile columns, `authz` |
| `organization.v3` | `offices`, `teams`, `team_members`, `reporting`, `team_specs` |
| `organization.v4` | approval routing columns and their same-organization team triggers |
| `organization.v5` | `org_proposals` |

Teams come before approval routing because routing (`task_team`, rule 3b) and
its `tasks_team_same_org` / `approvals_team_same_org` triggers read `teams` and
`team_members`. The memory parts (`docs/memory.md`) follow `organization.v1`;
team visibility needs `organization.v3`.

**Parts per owning crate.** Tenant tables are created by several crates
(`ua-tools`, `ua-memory`, `ua-import`, …), and a crate's own test database
applies only that crate's parts, so one part that `ALTER`s every crate's tables
would fail there with "no such table". Each step is therefore a set of parts,
one per owner: `ua-store` owns `organization.v1.store` (`orgs`, the seed, the
`event_log` columns), and each crate that owns tenant tables declares
`organization.v1.<crate>` for its own tables. All of them are produced by one
helper, `ua_store::org::tenant_part(owner, tables)`, which emits the `ADD
COLUMN`, the generated `org_exists` / `org_immutable` triggers and the
backfills for exactly the listed tables, so the rules are written once.

**Two part kinds.** `SchemaPart` today is a static `name` and `sql`. It becomes:

| Kind | Body | Checksum covers |
|---|---|---|
| `Static` | a `&'static str` of SQL | that SQL, as today |
| `Procedure` | a named Rust function and an explicit `version` number, run with a connection (and, if flagged `standalone`, outside the shared transaction) | the part name, the `version` and the procedure's static arguments (for a tenant part, its table list) |

An applied procedure is checked by name, `version` and arguments only, because the SQL it
generates may depend on the database it ran on; that generated SQL is stored
beside the checksum for audit and is never regenerated or compared on later
starts. A procedure that changes must bump its `version`, which makes it a new
part, so immutability holds for both kinds. The seed (whose timestamp is bound from
`ua_core::time::now()`), the helper-generated tenant parts and the rebuild are
procedures; the rebuild is the only `standalone` one.

`schema::apply` today runs every pending part in one `BEGIN IMMEDIATE`
transaction. It changes so that a `standalone` part runs **alone**: the pending
parts before it are committed first, the standalone part runs its own procedure
([below](#global-keys-and-table-rebuilds)), and the parts after it resume in a
new transaction.

### `organization.v1`

```sql
CREATE TABLE IF NOT EXISTS orgs (
    id                        TEXT PRIMARY KEY,
    slug                      TEXT NOT NULL UNIQUE,
    display_name              TEXT NOT NULL,
    status                    TEXT NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active','suspended')),
    allowed_profiles          TEXT NOT NULL
        DEFAULT '["public","remote-assistant","research","acp-session","reviewer","developer","lead"]'
        CHECK (json_valid(allowed_profiles) AND json_type(allowed_profiles) = 'array'),
    memory_default_visibility TEXT NOT NULL DEFAULT 'private'
                              CHECK (memory_default_visibility IN ('private','team','org')),
    self_organization         INTEGER NOT NULL DEFAULT 1 CHECK (self_organization IN (0,1)),
    proposal_daily_limit      INTEGER NOT NULL DEFAULT 10 CHECK (proposal_daily_limit > 0),
    memory_consolidator_label TEXT,
    allow_remote_embedder     INTEGER NOT NULL DEFAULT 0 CHECK (allow_remote_embedder IN (0,1)),
    created_at                TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS orgs_no_delete BEFORE DELETE ON orgs
BEGIN SELECT RAISE(ABORT, 'organizations are suspended, never deleted'); END;
```

SQLite permits `ADD COLUMN ... NOT NULL` only with a constant default, which is
exactly the behaviour wanted: every existing row is backfilled atomically with
the default organization. (`ADD COLUMN` cannot also carry `REFERENCES` with a
non-NULL default while foreign keys are on, so existence is guarded by
triggers.) The seed timestamp is bound by the migration code from
`ua_core::time::now()`, so it has the storage form; the literal below is only
for the SQL check.

```sql
INSERT OR IGNORE INTO orgs (id, slug, display_name, status, allowed_profiles,
                            memory_default_visibility, created_at)
    VALUES ('default', 'default', 'Default organization', 'active',
            '["public","remote-assistant","remote-vault-curator","research","acp-session","operator","reviewer","developer","lead","coordinator"]',
            'org', '2026-01-01T00:00:00+00:00');

ALTER TABLE tasks ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE tasks ADD COLUMN team_id TEXT;            -- owning team, nullable
ALTER TABLE approvals ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agents ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agent_tokens ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE oauth_grants ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE ui_sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory_versions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE memory_embeddings ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
UPDATE harness_config_bundles SET org_id = 'default' WHERE org_id IS NULL;
-- ... one ADD COLUMN org_id per remaining tenant table (see Scoping per subsystem)

-- generated for every tenant table:
CREATE TRIGGER IF NOT EXISTS tasks_org_exists
BEFORE INSERT ON tasks
WHEN NOT EXISTS (SELECT 1 FROM orgs WHERE id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'unknown organization'); END;

CREATE TRIGGER IF NOT EXISTS tasks_org_immutable
BEFORE UPDATE OF org_id ON tasks
WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id
BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;

-- one label namespace, case-insensitive (after the duplicate pre-check)
CREATE UNIQUE INDEX IF NOT EXISTS agents_label_nocase ON agents(label COLLATE NOCASE);

-- launch keys are client-chosen: scope them to the organization
DROP INDEX IF EXISTS idx_node_dispatch_launch_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_node_dispatch_launch_key
    ON node_dispatch(org_id, launch_key);

-- the existing version-capture trigger (part memory_versions.v1) inserts
-- without naming org_id, so every tenant's history would land in 'default'
DROP TRIGGER IF EXISTS memory_versions_capture;
CREATE TRIGGER memory_versions_capture
BEFORE UPDATE OF content, tags ON memory
FOR EACH ROW
WHEN (OLD.content IS NOT NEW.content OR OLD.tags IS NOT NEW.tags)
BEGIN
    INSERT INTO memory_versions (org_id, note_id, version, content, tags, updated_at, actor, recorded_at)
    VALUES (
        OLD.org_id,
        OLD.id,
        COALESCE((SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id), 0) + 1,
        OLD.content,
        OLD.tags,
        OLD.updated_at,
        COALESCE(OLD.updated_by, OLD.author),
        strftime('%Y-%m-%dT%H:%M:%S+00:00', 'now')
    );
    DELETE FROM memory_versions
    WHERE note_id = OLD.id
      AND version <= (SELECT MAX(version) FROM memory_versions WHERE note_id = OLD.id) - 50;
END;
```

The duplicate pre-check runs before the label index:
`SELECT lower(label) FROM agents GROUP BY lower(label) HAVING count(*) > 1`
(and the same across `agents` and `users` once `users` exists). Any row refuses
the part and names the labels.

An existence trigger (`<table>_org_exists`) and an immutability trigger
(`<table>_org_immutable`) are generated for every tenant table. A row never
moves between organizations; "moving" is a copy plus a reference. Because
organizations are never deleted, insert-time existence is sufficient. The
`OLD.org_id IS NOT NULL` clause lets the harness-config tables' legacy `NULL`
be filled once, before the rebuild makes the column `NOT NULL`.

`org_id` on `memory`, `memory_versions` and `memory_embeddings` belongs to this
part; the memory parts add only visibility, team, owner and credential columns,
so no two parts add the same column.

**The default is a migration convenience, not a safety net.** A tool path that
forgets `org_id` will silently write into the default organization instead of
failing. Three guards:

1. The resolver always binds `org_id` explicitly; it is never omitted.
2. A unit test walks the statement strings in the tenant-scoped families and
   fails for an `INSERT INTO <tenant table>` that does not name `org_id`. It
   also walks the SQL of **every trigger** in `sqlite_master` after all parts
   have applied, because trigger bodies insert too (the
   `memory_versions_capture` case above) and no Rust string shows them.
3. Every lookup by id takes the caller's organization (`WHERE id = ? AND
   org_id = ?`) and returns the same `not_found` for another organization's row
   as for a missing one. This includes `approvals::get` in `resolve`.

### Global keys and table rebuilds

`ALTER TABLE` cannot change a primary key or a `UNIQUE` constraint. Every
global key in the tree is classified:

| Table and key | Class | Reason / action |
|---|---|---|
| `agents.label`, `users.label` | Hub namespace | One case-insensitive label namespace (above). An agent belongs to one organization. |
| `nodes.node` | Hub namespace | Node names are registered hub-wide; a node serves one organization. |
| `provider_accounts.label`, `mcp_servers.name`, `dispatch_meta.key` | Hub table | Hub-scoped configuration and hub salts, managed by hub owners. |
| `managed_secrets.name` | **Rebuild** | Key becomes `(org_id, name)`. |
| `skill_versions UNIQUE(name, version)` | **Rebuild** | Becomes `UNIQUE(org_id, name, version)`. |
| `skill_assignments UNIQUE(skill_name, target_type, target)` | **Rebuild** | Becomes `UNIQUE(org_id, skill_name, target_type, target)`. |
| `harness_config_bundles.version UNIQUE`, nullable `org_id` | **Rebuild** | `org_id NOT NULL`, `UNIQUE(org_id, version)`. |
| `harness_config_proposals` nullable `org_id` | **Rebuild** | `org_id NOT NULL`. |
| `idempotency_keys.key` | **Rebuild** | Key becomes `(org_id, principal, key)` with a new `principal` column (the verified caller, `(principal_type, principal)` flattened); a replay never returns another organization's or another principal's stored result, and a second principal's first use is a fresh insert, not a collision. Existing rows have no recorded caller, so the rebuild sets their `principal` to the reserved value `legacy:` and their `org_id` to `'default'`; no live caller ever matches `legacy:`, so an old key is never replayed to anyone and simply ages out. |
| `node_dispatch` unique index on `launch_key` | **Re-index** | An index, not a table key: `organization.v1` drops it and creates a unique index on `(org_id, launch_key)`. No rebuild. |
| `event_log.dedupe_key UNIQUE` | Global, safe | Every producer builds it from hub-global identifiers (ULIDs, approval, run and delivery ids), never from client-chosen text alone, so two organizations cannot collide on it. A test asserts each producer's key format; a future producer that takes client text must prefix `org_id`. |
| `web_search_cache (provider, query, max_results)` | **Rebuild** | Key becomes `(org_id, provider, query, max_results)`. |
| `project_repo_bindings.project` | **Rebuild** | Key becomes `(org_id, project)`. |
| `graph_canvas_scenes.board_id`, `graph_canvas_revisions (board_id, revision)` | **Rebuild** | Keys become `(org_id, board_id)` and `(org_id, board_id, revision)`, rebuilt together. |

Without the rebuilds, organization B could not create a secret, skill, binding
or board whose name A uses, the conflict error would tell B that A has it, and
an idempotency replay could return A's stored result to B.

`organization.v1-rebuild` runs alone, outside the usual transaction, at
start-up before the hub serves, using SQLite's documented table-rebuild
procedure:

1. `PRAGMA foreign_keys = OFF` (it has no effect inside a transaction, which is
   why the part runs alone);
2. `BEGIN IMMEDIATE`; for each table: record its dependent triggers, indexes
   and views from `sqlite_master`; create `<table>_new` with the new keys;
   `INSERT INTO <table>_new SELECT …, COALESCE(org_id, 'default') …`; drop the
   old table; rename; recreate the recorded indexes, triggers (including the
   generated `org_exists` and `org_immutable` triggers) and views;
3. `PRAGMA foreign_key_check(<table>)` for **each rebuilt table** — any row
   aborts with `ROLLBACK`. Not a whole-database check: legacy dangling
   references elsewhere (which `state_sync_verify` exists to report, and which
   imports can carry) must not stop the hub from starting. None of the rebuilt
   tables declares a foreign key or is referenced by one today, so the
   per-table check is what proves the rebuild itself is sound;
4. compare the set of trigger and view names against the recorded set — any
   difference aborts with `ROLLBACK`;
5. record the part, `COMMIT`, `PRAGMA foreign_keys = ON`.

A failed rebuild leaves the database exactly as before and the hub refuses to
start, naming the part.

## Resolution

`Caller` gains `org_id: String` and `user_id: Option<String>`. Both are set by
the adapter from the verified credential and from nothing else:

| Credential | Organization | User |
|---|---|---|
| Static config token (`UA_AGENT_TOKENS`) | always `'default'` — it is hub configuration and its label is reserved. If an organization other than `'default'` held the label before it was added to the config, the token is **refused** (it does not authenticate) until the operator resolves the `MISCONFIGURED` row | the users row, when the label is human |
| Agent token row (`agent_tokens`) | `agent_tokens.org_id`, set at issue to the agent's organization | none — refused for human labels |
| Node session credential (`uas_…`) | `session_credentials.org_id`, the organization of the work item it was minted for | none |
| OAuth grant | `oauth_grants.org_id`, which must equal the subject agent's organization — checked at grant creation and on every use | none — OAuth never acts as a human |
| Passkey / UI session | `ui_sessions.org_id`: chosen at login among the user's memberships, **re-validated against `org_memberships` on every request**; switching organization issues a new session id and CSRF token | the passkey's label |
| CLI and stdio, local | `'default'`, or `--org <slug>`, refused unless the label has a membership there | the users row, when the label is human (hub-host trust) |
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
deploys — or anything that needs an admin.

```sql
-- organization.v4
ALTER TABLE approvals ADD COLUMN team_id TEXT;
ALTER TABLE approvals ADD COLUMN routing_basis TEXT NOT NULL DEFAULT 'hub'
    CHECK (routing_basis IN ('hub','task_team','named_team','org'));
ALTER TABLE approvals ADD COLUMN required_authority TEXT NOT NULL DEFAULT 'hub_owner'
    CHECK (required_authority IN ('hub_owner','org_admin','team_lead','agent_owner'));
ALTER TABLE approvals ADD COLUMN two_person INTEGER NOT NULL DEFAULT 0
    CHECK (two_person IN (0,1));
ALTER TABLE approvals ADD COLUMN escalated_at TEXT;
ALTER TABLE approvals ADD COLUMN escalation_targets TEXT;   -- JSON user ids

CREATE TRIGGER IF NOT EXISTS approvals_team_same_org
BEFORE INSERT ON approvals
WHEN NEW.team_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM teams WHERE id = NEW.team_id AND org_id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'approvals.team_id must be a team of the approval''s organization'); END;

CREATE TRIGGER IF NOT EXISTS tasks_team_same_org
BEFORE UPDATE OF team_id ON tasks
WHEN NEW.team_id IS NOT NULL
 AND NOT EXISTS (SELECT 1 FROM teams WHERE id = NEW.team_id AND org_id = NEW.org_id)
BEGIN SELECT RAISE(ABORT, 'tasks.team_id must be a team of the task''s organization'); END;
```

The matching insert/update triggers are generated for both columns. The column
defaults are the **narrowest** values, so a pending approval from before the
migration fails closed: on first start after `organization.v4`, a one-time step
reclassifies each pending row from the tool registry (`routing_basis = 'org'`,
`required_authority = 'org_admin'` for tenant-scoped tools; hub-scoped rows
stay as they are).

**Binding.** The gate matches a pass on `(org_id, tool, payload,
requested_by)`. A pass parked in organization A never satisfies the identical
call in B, even for a human who belongs to both.

**Required authority.** Computed when the approval is parked, from the tool's
classification and the payload, and never lowered afterwards:

| Call | `required_authority` |
|---|---|
| A hub-scoped tool | `hub_owner` |
| A team-routable tool routed to a team (below) — and, for a spec commit or proposal apply, only when the change is narrowing | `team_lead` |
| A grant of an approving role, or a credential for another human | `org_admin` with `two_person = 1` (`hub_owner` when [Credentials for people](#credentials-for-people) says so) |
| A root credential for an agent with an `owner_user_id`, requested by anyone but that owner | `agent_owner` |
| Every other tenant-scoped gated call | `org_admin` |

**Routing team.** Only for team-routable tools; every other tool routes to
`org` (or `hub`):

| Basis | When | `team_id` |
|---|---|---|
| `hub` | the tool is hub-scoped | `NULL` |
| `task_team` | the call names a task whose `team_id` is set, **and** the requester is a member of that team | the task's team |
| `named_team` | a team operation (`team_up`, spec commit, proposal apply) **and** the requester is a member of that team | the named team |
| `org` | anything else, including a requester naming another team's task | `NULL` |

`tasks.team_id` can be set by `org_admin` and above. A team lead may set it
only on a task whose current team is `NULL` or one they lead, and only to a
team they lead — so moving a task between teams needs `org_admin` or a lead of
both. Agents cannot set it.

**Eligibility.** `resolve` with `approve` succeeds only when every check holds,
evaluated at resolution time against current rows:

1. **Organization.** The caller is human and `caller.org_id ==
   approvals.org_id` — or the caller is a hub owner and either
   `required_authority = 'hub_owner'` or this is a `two_person` approval in an
   organization with no other eligible human.
2. **Not the requester.** For `two_person` approvals, also not the subject of
   the grant or credential.
3. **Authority**, by `required_authority`:
   - `hub_owner`: the caller is a hub owner;
   - `org_admin`: the caller's role is `org_admin` or `org_owner` (`org_owner`
     when granting `org_owner`);
   - `team_lead`: one of
     - a. the caller's role is `org_admin` or `org_owner`;
     - b. the routing is re-checked — for `task_team`, the task's `team_id` is
       still the recorded team and the requester is still a member; for
       `named_team`, the requester is still a member — **and** the caller is a
       `lead` member of that team with role `team_lead` or above;
     - c. the approval is escalated, the caller is in `escalation_targets`, and
       still holds `team_lead` or above in the same organization.

     If the re-check in (b) fails, only (a) applies.
   - `agent_owner`: the caller is the user in the target agent's current
     `owner_user_id`, whatever their role. Nobody else qualifies, hub owners
     included; if the owner link is cleared while the approval is pending, the
     approval falls back to `org_admin`.
4. Apart from `agent_owner`, `auditor` and `member` never approve.

`deny` follows the same eligibility, plus the requester. `revoke` requires the
same organization and either approve eligibility or being the requester.
Membership is evaluated at resolution, so a lead removed while an approval is
pending can no longer approve it.

**Escalation.** A team spec may set `approval_escalation: {after, to}`.
`after` has a floor of 15 minutes. Each target is `user:<id>` — a user with
`team_lead` or above in the same organization — or `team:<slug>` — a team of
the same organization, meaning its current leads. Targets are validated when
the spec is committed. Escalation applies only to pending approvals whose
`team_id` is that spec's team and whose `required_authority` is `team_lead`; it
never changes `required_authority`. A `system_for(org)` job marks such an
approval older than `after` by setting `escalated_at` and `escalation_targets`
(resolved user ids), records an `agent.approval.escalated` event, and leaves
`status` unchanged (its `CHECK` is not altered). Escalation adds approvers
under rule 3c; it never removes any.

The seat-level `escalates_to` edge is separate: it routes a seat's blocked-task
notifications and confers no approval authority.

## Teams

```sql
-- organization.v3
CREATE TABLE IF NOT EXISTS offices (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    profiles   TEXT NOT NULL CHECK (json_valid(profiles) AND json_type(profiles) = 'array'),
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

`organization.v2` adds the agent columns:

```sql
ALTER TABLE agents ADD COLUMN owner_user_id TEXT;    -- the human this agent acts for
ALTER TABLE agents ADD COLUMN default_profile TEXT;  -- within allowed_profiles
```

Writer rules the schema cannot express, each with an acceptance test:

- A `lead` member must hold `team_lead`, `org_admin` or `org_owner` in the
  team's organization; eligibility is re-checked at approval time, so a demoted
  user stops leading without a second step.
- A human `principal` must have a membership in the team's organization; an
  agent `principal` must be an agent of that organization.
- `agents.owner_user_id` must be a member of the agent's organization, and is
  set only with **both** parties: the named user's own act **and** an
  `org_admin`'s. Either the user requests a claim and an `org_admin` approves
  it, or an `org_admin` offers the link and the user accepts. Neither can set
  it alone: the approving or offering admin must be a different person from
  the user being linked, so an admin linking an agent to themselves needs
  another admin. Only an agent with no current owner can be claimed. An
  `org_admin` may clear it (that narrows), never set it to someone else.
  Clearing the link immediately ends the agent's eligibility for that
  person's private notes, so an admin who clears it and then issues the agent
  a token, or whose pending `agent_owner` approval falls back to `org_admin`,
  gains nothing over those notes. Memory uses this link to decide
  which agent may summarize that person's private notes, so an admin who holds
  an agent's tokens must not be able to aim it at another person.
- **An owned agent's credentials belong to its owner.** Claiming an agent
  revokes every live credential for it that someone other than the claiming
  user issued (agent tokens, managed tokens, OAuth grants, node session
  credentials). While `owner_user_id` is set, a new **root** credential for
  that agent — `agent_token_issue`, `agent_token_rotate`, a managed token, an
  OAuth grant — is issued in one of two ways: the owner issues it themselves
  (the owner may issue and rotate credentials for their own agent whatever
  their role, with no second approval, since the owner is the person being
  protected), or anyone else requests it and it parks with
  `required_authority = 'agent_owner'`, which only that owner can approve. An
  `org_admin` cannot mint one alone. Node session credentials are not root
  credentials: the agent's own node mints them per dispatch from a credential
  the agent already holds, so they need no extra approval. Otherwise an admin
  could take over an agent its owner had enabled for private consolidation and
  read that person's private notes.
- `org_memberships.consolidate_private` is changed only by the member
  themselves (default off); see `docs/memory.md`.
- `offices.profiles` and `agents.default_profile` must be within the
  organization's `allowed_profiles`.
- `reporting` endpoints must belong to the same organization; only
  `org_admin` and above write it.
- An archived team takes no new members, spec commits or `team_up`; its rows
  stay for history.

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
Its `required_authority` is `team_lead` only when the diff from the parent is
narrowing ([Self-organization](#self-organization) rule 5); anything else,
**including the first commit**, is `org_admin`. Every commit appends an
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

- The team is `active`.
- Every seat `label` is an agent member of this team, in this organization. A
  spec never creates an identity.
- `node` is a node of this organization; `skill_pack` is a published bundle of
  this organization; escalation targets are in this organization with an
  approving role.
- `harness` is one the harness-config surface supports; `fallback` entries are
  tried in order when the primary harness or its provider is unavailable or
  rate-limited.
- `profile` is in both the office's `profiles` and the organization's
  `allowed_profiles`.
- `workspace.trust_root` must be a root the named node itself reported. A spec
  can narrow trust, never grant it; workspaces are never auto-trusted.
- Seat budgets may not sum above the team budget.
- `delegates_to` and `escalates_to` are acyclic; edge endpoints are seats of
  this team, or `user:<id>` for `escalates_to`.
- `approval_escalation.after` is at least 15 minutes.
- The canonical JSON is at most 64 KiB; unknown keys are refused.

### Edges are enforced, not decorative

When a team has a committed spec, its seats are governed by its edges — as
actors **and** as targets. Agents that are not seats of any spec are
unaffected as actors, but they cannot reach into a governed seat.

**Leaving a seat does not free an agent.** An agent removed from a spec's
seats but still a `team_members` row of that team stays **governed with no
edges**: it may not delegate, observe or count as a reviewer until an
`org_admin` removes it from the team. So a team lead's narrowing approval of a
seat removal cannot be used to lift that agent's edge restrictions.

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

`ua team up <team>` (tool `team_up`) boots a **committed** spec of an active
team only. It recomputes the plan and refuses if any `static` check fails, then
requests one approval bound to `(org_id, team_id, spec_sha256, plan_sha256)`,
routed to the named team (`named_team`, required authority `team_lead`). After
approval it re-checks the `volatile` part; if any seat fails, nothing
launches, the refusals are returned, and the pass stays unconsumed until it
expires so a retry reuses it. Otherwise seats launch in `delegates_to` order
through the node work queue, one run record per seat linked by a
`team_run_id` on `agent.team.run`, and the pass is consumed. A change to
`static` facts changes `plan_sha256` and needs a new approval.

## Self-organization

Agents can see where their own team's structure is wrong — a missing reviewer, a
routing rule that bounces work, a routine nobody runs. They may **propose**
changes; they may never **apply** them.

```sql
-- organization.v5
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

1. **Proposing is on by default** and switched off per organization by the
   `self_organization` setting.
2. **Scope is membership.** A proposer may target only teams it is a
   `team_members` row of; its office scope is the offices of those teams. A
   proposal outside that scope is refused, not queued.
3. **Rate limited.** At most `proposal_daily_limit` proposals per proposer per
   day.
4. **Applying is never automatic.** Apply needs an approval bound to the
   proposal id, the diff hash and `base_sha256`. `base_sha256` is the live
   spec's `spec_sha256` for spec changes, and otherwise the SHA-256 of the
   canonical JSON of the targeted rows ordered by primary key. If the live
   state no longer hashes to it, the proposal becomes `stale` and is not
   applied.
5. **Team leads approve narrowing only.** A change is narrowing only if every
   part of it is on this list:
   - lowering a seat or team budget;
   - moving a seat's profile to another profile already in the office's set
     that the organization classes as narrower (the office lists them in
     order);
   - removing a `delegates_to` or `can_observe` edge;
   - narrowing a `trust_root` to a subdirectory of itself;
   - removing a seat that is **not** an endpoint of a `reviews` edge and
     **not** an `escalates_to` or `approval_escalation` target — the agent
     stays a governed team member with no edges ([above](#edges-are-enforced-not-decorative));
     removing the agent from the team itself needs `org_admin`.

   Everything else needs `org_admin` or `org_owner`. That includes adding
   members, any `reviews` change, `approval_escalation` and `escalates_to`
   changes, `skill_pack` (harness config, so code on a node), `node`,
   `workspace.repo`, `harness`, `fallback`, `model`, `guidance`, and every
   proposal of kind `skill` or `routine`.
6. Applying a spec change commits a new `team_specs` version through the same
   path as a human commit, so history has one shape.

The diff is structured so the review inbox can render it side by side, as
escaped text.

## Scoping per subsystem

Every table is classified, and a test over `sqlite_master` fails on any table
missing from `ua-org`'s classification list. That list (today in
`crates/ua-tools/tests/org_classification.rs`) is the authority; the table
below is kept in step with it. For every **tenant** table it also
checks, through `PRAGMA table_info`, that `org_id` exists and is `NOT NULL`,
and that its `org_exists` and `org_immutable` triggers exist.

| Class | Tables | Rule |
|---|---|---|
| Tenant: tasks and planning | `tasks`, `task_dependencies`, `task_comments`, `task_comment_threads`, `task_checks`, `task_holds`, `task_hold_members`, `task_workflow`, `task_goal_links`, `goals`, `work_proposals`, `work_proposal_items`, `review_ready_notices`, `project_repo_bindings`, `plans`, `plan_steps`, `plan_checkpoints`, `routines`, `routine_runs`, `workflow_runs`, `workflow_checkpoints`, `delegations`, `autonomous_cycles`, `autonomous_cycle_transitions`, `autonomous_cycle_usage` | `org_id`; `tasks` also has optional `team_id` |
| Tenant: agents and sessions | `agents`, `agent_sessions`, `agent_tokens`, `agent_lifecycle`, `session_profiles`, `session_credentials`, `session_handoff_notes`, `session_wake`, `session_wake_offers`, `dispatch_receipts`, `dispatch_runs` | An agent belongs to exactly one organization |
| Tenant: nodes | `nodes`, `node_acceptance`, `node_claim_ops`, `node_command`, `node_command_notice`, `node_dispatch`, `node_followups` | A node serves one organization |
| Tenant: people and teams | `org_memberships`, `offices`, `teams`, `team_members`, `team_specs`, `reporting`, `org_proposals` | Per organization |
| Tenant: memory | `memory`, `memory_versions`, `memory_embeddings`, and from `docs/memory.md`: `memory_chunks`, `memory_entities`, `memory_links`, `memory_consolidations`, `memory_consolidation_sources`, `memory_invalidations`, `memory_feedback_events` | `org_id` plus a visibility tier, enforced in the search SQL — see `docs/memory.md`; each new table gets the generated `org_exists` / `org_immutable` triggers |
| Tenant: approvals and policy | `approvals`, `policy_authorizations` | `org_id`, routing `team_id`, required authority |
| Tenant: messages | `message_index`, `message_reads`, `notify_outbox`, `pending_notifications`, `relay_messages`, `zulip_sends` | `org_id` |
| Tenant: skills and config | `skill_versions`, `skill_assignments`, `skill_publish_staging`, `harness_config_bundles`, `harness_config_proposals`, `harness_config_drift`, `harness_config_report_window` | Catalog is per organization (keys rebuilt) |
| Tenant: other | `managed_secrets`, `graph_canvas_scenes`, `graph_canvas_revisions`, `idempotency_keys`, `tool_calls`, `web_search_cache`, `code_symbols` | `org_id`; keys rebuilt where listed above |
| Derived index | FTS5 virtual tables `task_fts` and `memory_fts`, and their shadow tables (`*_data`, `*_idx`, `*_content`, `*_docsize`, `*_config`) | No `org_id`; every read joins through the owner table (`tasks`, `memory`) and filters there |
| SQLite internal | `sqlite_sequence`, `sqlite_stat*` | Not application data |
| Tenant column on a global table | `event_log` | One chain, `org_id` per row — see [The ledger](#the-ledger) |
| Global identity | `users`, `passkeys`, `webauthn_states`, `login_links`, `oauth_clients`, `oauth_codes`, `oauth_grants`, `oauth_requests`, `oauth_tokens`, `ui_keys`, `ui_sessions`, `org_bootstrap` | Identity is global; the **grant** carries the organization (`oauth_grants.org_id`, `ui_sessions.org_id`, `agent_tokens.org_id`) |
| Hub | `orgs`, `config_revisions`, `mcp_servers`, `provider_accounts`, `dispatch_meta`, `github_deliveries`, `github_delivery_bodies`, `github_poll_state`, `slack_seen_signatures`, `slack_seen_deliveries`, `zulip_fetch_cursors`, `vault_ingest_ledger`, `import_runs`, `import_org_map`, `import_finalized`, `schema_parts`, `ledger_meta` | Hub-scoped tools only; hub owners |

The vault is hub-scoped, so anything that copies tenant data into it —
`memory_promote` above all — is allowed only in `'default'` (see
`docs/memory.md`).

## The ledger

`event_log` is a single global hash chain. The organization must not fork it,
or every existing chain verification breaks and cross-organization tamper
evidence disappears.

**Whose event.** An event's `org_id` is the organization of the **affected
row**, not of the caller. Events about global rows — users, passkeys, login
links, user suspension, bootstrap — go to `'default'`. Today `ledger::EventInput`
derives `Default` and `EventInput::new()` fills the rest with
`..Self::default()`, so a new field would compile silently; the change removes
`Default` and makes `new()` take `org_id`, so every call site must supply one.
A system job acting for organization B writes B's `org_id`, so B's auditors
see it.

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
reveal each tenant's event volume. It is available to callers in `'default'`
(the hub operator's own organization; this keeps today's behaviour, where any
agent may call `event_log_verify`) and to hub owners, and refused to callers in
any other organization. An organization's audit export carries each of its
rows with `prev_hash` and `entry_hash` but **without `seq`**, whose gaps would
reveal hub-wide volume; every row's own hash is checkable, but the export is not
chain-continuous on its own, because the chain links through other
organizations' rows.

The Python verifier cannot check `hash_v = 2` rows. That is acceptable because
the Python hub is frozen and never reads a `ua-rust` ledger.

## Where the code lives

- **`ua-org`**, a new workspace crate: users, memberships, settings, offices,
  teams, members, reporting, specs, proposals, the `authz` module, the edge
  check and approval eligibility. Its tools register through `ua-tools`, which
  stays a thin registry and envelope; no organization logic is added to
  `ua-tools` beyond the calls into `ua-org`.
- **`ua-store`** gains the `org::tenant_part` helper and the `Procedure` part
  kind ([Schema](#schema)), and a `repo` module with an `OrgRepo` trait and its
  SQLite implementation. `ua-org` reaches the database only through that trait, and
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
- **B.** `--org-map <source_org_id>=<target_slug>`, repeated. Every distinct
  non-NULL source `org_id` must be mapped, or the import refuses and lists the
  unmapped ones. Source rows with `NULL` go to `'default'`, and a mapping to
  `default` is allowed. This is the cutover path.

The importer still requires a target ledger holding no events it did not write
(today's rule), so it runs against a fresh store before the hub first serves.
For option B it **creates the mapped organizations itself**, as `orgs` rows
with no ledger events, then imports the source chain unchanged (`hash_v = 1`).

`ua-import` is resumable and supports catch-up runs (`import_runs.last_key`),
so the completion event cannot be written on every run: a catch-up after it
would append `hash_v = 1` rows after a `hash_v = 2` row, which `verify()`
refuses. So:

```sql
CREATE TABLE IF NOT EXISTS import_org_map (
    source_hash   TEXT NOT NULL,
    source_org_id TEXT NOT NULL,
    target_org_id TEXT NOT NULL REFERENCES orgs(id),
    PRIMARY KEY (source_hash, source_org_id)
);
CREATE TABLE IF NOT EXISTS import_finalized (
    source_hash  TEXT PRIMARY KEY,
    finalized_at TEXT NOT NULL,
    event_ulid   TEXT            -- NULL only for the legacy backfill marker
);
```

- Each run records its mapping in `import_org_map`; a later run with a
  different mapping for the same source is refused.
- Ordinary and catch-up runs write **no** `hash_v = 2` row. They are refused if
  the target holds any `hash_v = 2` row.
- `ua import python-hub --finalize` is the explicit last run: it imports any
  remaining rows, appends the completion event — which records the full mapping
  — as the first `hash_v = 2` row, and writes `import_finalized`.
- Finalization is **target-wide**: `--finalize` finalizes every source
  imported into that target at once, so a hub built from two sources imports
  both, then finalizes once. After finalization every further import into that
  target is refused.
- `ua serve` refuses to start on a store with an import recorded but not
  finalized, so the hub cannot append `hash_v = 2` rows ahead of a catch-up.
- **Stores imported before this design** already hold `import_runs` rows and
  hub-written events. `import_finalized` and `import_org_map` are created by a
  `ua-store` procedure part, `organization.v1.import-marker`, ordered after
  `organization.v1.store` (`import_org_map` references `orgs`), which both
  `ua serve` (`Hub::open`) and `ua import` apply, so the check `ua serve` makes
  never depends on a part only the importer applies. When `import_runs` exists,
  that part backfills a legacy marker (`event_ulid` NULL) for every
  `source_hash` already recorded, so those hubs keep starting and are treated
  as finalized; their chain is already `hash_v = 1` throughout and verifies as
  today. On a store never imported, `import_runs` does not exist and nothing is
  checked.

`verify()` therefore always sees the order it requires. The migration manifest
compare records the mapping in its fingerprint.

Imported ledger rows keep `hash_v = 1`, so the `org_id` the mapping assigns to
them is **not** covered by their hash. Imported boundaries are as trustworthy as
the import run that set them, which is recorded on `import_runs` and in the
completion event.

## What this is not

- **Not a tool-permission matrix.** Capability stays with profiles and the
  policy file, bounded by each organization's `allowed_profiles`. Roles decide
  which rows a person administers and which approvals they may resolve; the one
  exception is that approvers see the approval tools.
- **Not hard isolation.** Organizations share one hub and one database. Hard
  data-plane separation per organization was considered and not chosen.
- **Not a job-title system.** Offices carry profiles and a name. No HR
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
   read is `verify()`, for `'default'` and hub owners.
2. **Offices are runtime data**, not a fixed enum, since the product promise is
   that an operator defines their own.
3. **Tasks are organization-local in v1.** Task identity does not move between
   organizations; a cross-organization handoff is a copy plus a reference.

## Acceptance

Parity and isolation

1. **Single-organization parity.** The existing suite passes unchanged —
   including `goal_manage` refusing `params.org_id` and an agent in `'default'`
   calling `event_log_verify` — the default organization is invisible to
   callers, and a hub with `human_identities = ["operator"]` lets that human do
   exactly what they can do today.
2. **Read isolation, registry-driven.** Seed organization A through the write
   tools of every family, then call every `read_only` tool as a caller in B
   (with A's ids where a tool takes one), plus the SSE event stream, the compat
   API and exports: zero A rows, and A's ids return the same `not_found` as a
   missing id.
3. **Classification.** The `sqlite_master` test fails on an unclassified table,
   on a tenant table whose `org_id` is missing or nullable, and on a tenant
   table missing either generated trigger; FTS virtual and shadow tables and
   SQLite internals pass as classified.
4. **Resolver guard.** The statement-walking test fails if a tenant-scoped
   insert omits `org_id`, in Rust statement strings **or** in any trigger body
   in `sqlite_master`; after `organization.v1`, editing a note in B writes its
   `memory_versions` row with B's `org_id`.
5. **Cross-org references.** Inserting a team member, team office, spec, task
   `team_id` or approval `team_id` that points at another organization fails.
6. **`org_id` is immutable.** An `UPDATE` changing `org_id` on any tenant table
   fails.
7. **Global keys.** After the rebuild, A and B can each create a secret, a skill
   version, a skill assignment, a harness bundle, a project binding and a canvas
   board with the same name, and neither error reveals the other; the same
   idempotency key used in A and B, or by two principals in one organization,
   returns each its own result and the second first-use is a fresh call, not a
   collision; the same node launch key used in A and B succeeds in both; the
   same web search in A and B is cached separately; a rebuild whose rebuilt
   tables fail `foreign_key_check` or that loses a trigger leaves the database
   unchanged and the hub refuses to start, while an unrelated dangling
   reference elsewhere does not stop it; the parts before a standalone part are
   committed and the parts after it apply.
7a. **Schema parts.** Each crate's test database applies its own
   `organization.v1.<crate>` part without the other crates' tables; a
   procedure part whose `version` changes is refused as a changed part, while
   one that generated different SQL on a different database is not; a crate
   whose parts read organization tables (e.g. `memory.scope.v1` reads `users`)
   applies the organization parts in its test database first; the `agents` label index part refuses to apply while two
   agent labels differ only in case, and names them.

People and authority

8. **Human derivation.** An admin-created active user with a membership logs in
   as a human; a suspended user, or one with no active membership, does not; an
   owner or auditor of a suspended organization logs in read-only; an OAuth
   grant never does.
9. **Hub-owner binding.** A label added to `human_identities` whose `users` row
   a tenant admin created is not a hub owner, and `system_doctor` reports it;
   `ua org adopt-owner` revokes that row's credentials before adopting it.
10. **Authz guard.** The test fails on `is_human(`, `is_lifecycle_operator(`, a
    `fn is_human` or a profile match used as authority outside `authz`, in any
    workspace crate other than `ua-org` (including `ua-memory`), except the
    `ua-core` primitive definitions and `ua-core`'s own unit tests; for each row
    of the authority table, a `member` and an `auditor` are refused, and a
    caller in B is refused on A's target (for example minting a token for A's
    agent); a lifecycle operator whose label is a `'default'` agent or a hub
    owner may retire a node in any organization, and a same-named label
    resolving to anything else may not.
11. **Hub scope.** A hub-scoped tool is refused to an agent and to a human
    outside `'default'`; its approval is refused to an `org_admin` and accepted
    from a hub owner; `org_create` (with its first owner) and `org_suspend` are
    hub-owner only.
12. **Profiles.** Assigning a profile outside `allowed_profiles` to a session,
    office, seat, agent default or membership is refused; a tenant `team_lead`
    with the `reviewer` profile sees `approval_resolve`; a tenant agent with no
    default gets `developer`.
13. **Suspension.** A suspended organization's callers get `org_suspended`
    except owner and auditor reads; its nodes receive no work. Only a hub owner
    can suspend a user.
14. **Bootstrap.** A label in `human_identities` gets one `org_owner`
    membership once; removing that membership explicitly survives a restart;
    removing the label from the config removes hub-owner authority but not the
    membership; once `memory.scope.v1` has applied, the person's agent-owned
    memory notes are re-owned to the user once through the memory hook, and
    before it the bootstrap succeeds without touching memory.
15. **Two-person rule.** Granting `team_lead` or above, and issuing a credential
    for another human, are refused without an approval from a different
    eligible human who is not the subject; a hub owner's own request proceeds
    and is recorded; the last owner cannot be removed or demoted.
16. **Cross-org people.** An `org_admin` of B cannot add a user who belongs to
    A, or a hub owner, without a hub owner's approval; issuing such a user a
    credential also needs a hub owner; a user B created and credentialed, once
    added to A with that approval, is not reachable by B's credentials in A
    without A's own membership; `agent_token_issue` refuses a human label.
17. **Label namespace.** Creating a user with an agent's label, or the reverse,
    in any letter case, is refused; creating agent `Builder-1` in B while
    `builder-1` exists in A is refused, including through `touch_agent`'s
    auto-create, so B cannot overwrite A's `agent_lifecycle` row.
17a. **Reserved labels.** A tenant admin, an unverified named caller, and
    `touch_agent` acting for another label cannot create an agent or user whose
    label is in `human_identities`, `lifecycle_operators`, a static token or
    the `[profiles]` map, in any case; a hub owner can, only in `'default'`; a
    static-token agent's own first `session_start` creates its row in
    `'default'` as today, and so do a local stdio caller's and a local CLI
    caller's, while an anonymous HTTP caller (`enforce_auth` off) with the same
    label is refused; a label added to the config while a non-default
    organization holds it makes `system_doctor` report `MISCONFIGURED`, the hub
    still starts, the label gets none of its configured authority, and a static
    token for it does not authenticate, until resolved; a reserved label already
    in `'default'` raises nothing.
17b. **Agent owners.** An `org_admin` cannot set `agents.owner_user_id` alone
    and can clear it; a `member` cannot claim an agent alone; a claim needs the
    user's request plus an `org_admin`'s approval (or the reverse offer and
    acceptance), where the admin is not the user being linked; an agent that
    already has an owner cannot be claimed; only the
    member can turn
    `consolidate_private` on or off; claiming an agent revokes credentials for
    it that another person issued, including one minted before the claim; with
    an owner set, an `org_admin` cannot issue or rotate an agent token, or
    issue a managed token or OAuth grant for it, without the owner's approval;
    such a request parks as `agent_owner`, the owner (a plain `member`) can
    approve it, an `org_admin` and a hub owner cannot; the owner can issue and
    rotate their own agent's credentials directly; the agent's node still mints
    per-dispatch session credentials with no approval.
18. **Resolution.** For each credential row of the resolution table, the caller
    gets the stated organization — including a static token, which resolves to
    `'default'`, and is refused outright while its label is held by another
    organization (17a), and an
    `agent_tokens` row of B; an OAuth grant whose `org_id` differs from
    its subject agent's organization is refused at creation and on use; a UI
    session whose membership is removed is refused on its next request;
    switching organization rotates the session id and CSRF token; `--org`
    without a membership is refused.
19. **Settings.** Each setting changes only through `org_settings_update` by the
    role in the settings table, and records old and new values on the ledger.

Approvals

20. **Routing.** `task_team` when the requester is a member of the task's team
    and the tool is team-routable; `org` for a non-routable tool, when the
    requester names another team's task, or no task; `named_team` for `team_up`;
    `hub` for a hub-scoped tool. An agent cannot set `tasks.team_id`; a lead
    cannot move a task out of, or into, a team they do not lead.
21. **Required authority.** A secret or token action that names a team task is
    `org_admin` and refused to that team's lead; a non-narrowing spec commit
    under `named_team` is refused to the lead and to an escalation target;
    pending approvals from before the migration are reclassified and none ends
    up below its tool's authority.
22. **Eligibility.** Team A's lead approves a `team_lead` approval routed to A;
    is refused on B's, on an `org` one and on a `hub` one; is refused once the
    task moved to another team or the requester left the team; `auditor` and
    `member` are refused; `org_admin` approves `team_lead` and `org_admin`
    ones; a lead removed while an approval is pending is refused; the requester
    is always refused.
23. **Cross-org approval.** An approval created in A cannot be seen, approved,
    denied or revoked from B, and its pass does not satisfy the identical call
    in B for a human who belongs to both.
24. **Escalation.** After `after` elapses, a listed target with `team_lead` or
    above can approve a `team_lead` approval of that team, never an `org_admin`
    one; a target who lost the role cannot; `after` below 15 minutes and a
    target outside the organization are refused at commit; status stays
    `pending` throughout.

Ledger

25. **Integrity.** `verify()` reports a valid chain across `hash_v` 1 and 2; an
    unknown `hash_v` fails; a `hash_v = 1` row after the switch fails; a caller
    in a tenant organization is refused, a caller in `'default'` is not.
26. **Attribution.** An event written by a `system_for(B)` job about B's row
    carries B's `org_id` and appears in B's audit read, not A's; an event about
    a user row carries `'default'`; an organization's export contains no `seq`.

Teams

27. **Spec commit.** A commit against a stale `parent_version` is refused; a
    first commit approved by a team lead is refused; a node, bundle or
    escalation target from another organization is refused; a trust root the
    node did not report, seat budgets above the team budget, an unknown key,
    and a spec over 64 KiB are each refused; an archived team refuses a commit.
28. **Plan determinism.** Two `team_plan` calls on the same spec and rows are
    byte-identical in `static`; a heartbeat or a new run changes only
    `volatile`; changing a seat's node changes `plan_sha256`.
29. **Team up.** An uncommitted spec, an archived team, or a `static` refusal is
    refused; a failed `volatile` check launches nothing and leaves the pass
    reusable; a changed `plan_sha256` needs a new approval.
30. **Edges.** For each edge type, the action is allowed with the edge and
    refused without it (naming the edge); a non-seat agent cannot delegate to or
    observe a governed seat; an `auditor` human can observe; an agent removed
    from its seat but still on the team cannot delegate, observe or review
    until an `org_admin` removes it from the team.
31. **Budgets.** A seat at its cap is refused with `budget_exhausted` regardless
    of fallbacks; a primary marked unavailable falls back within the same pool;
    usage records carry `usage_source`.
32. **Self-organization.** A proposal outside the proposer's teams is refused;
    the daily limit is enforced; the setting off suppresses proposing; a stale
    base is not applied; for each non-narrowing category — including removing a
    `reviews` endpoint or an escalation target — a team lead's approval is
    refused and an admin's is accepted; a lead-approved seat removal leaves the
    agent governed with no edges; apply writes a new spec version.
33. **Teams and reporting.** Deleting a team fails and archiving blocks new
    members, commits and `team_up`; a reporting query for a past date returns
    the supervisor in effect then; only `org_admin` and above write
    `reporting`, and a cross-organization endpoint is refused.

Importer

34. **Exclusion.** Against an `organization.v1` target, a source row carrying
    `org_id` is refused without `--drop-org-scope` or `--org-map`, including for
    `harness_config_bundles`.
35. **Mapping and cutover.** `--drop-org-scope` imports everything into
    `'default'`; an unmapped source id refuses the import; a full two-organization
    cutover with both ids mapped creates both organizations, keeps both
    boundaries, and writes no `hash_v = 2` row; a catch-up run with the same
    mapping imports only new rows and a different mapping is refused;
    `--finalize` appends one completion event after the imported chain, after
    which `verify()` reports a valid chain and any further import is refused;
    `ua serve` refuses to start on an imported but unfinalized store; a store
    imported before this design starts after the upgrade (legacy marker) and
    still verifies; two sources imported into one target finalize together.
