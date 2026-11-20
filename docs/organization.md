# Organization model

Status: **design, not implemented.** This document is the review gate for the
`organization.v1` schema part. Nothing here is in the tree yet.

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

## What exists today

Three things are easy to confuse. Only the first two exist.

| Concept | Where | What it actually is |
|---|---|---|
| Profiles | `ua-core/src/profiles.rs`, `profiles.json` | A **capability overlay**. Decides which tools a session can see. Neutral tiers: `developer`, `lead`, `coordinator`, `reviewer`, `operator`, `public`, `research`. |
| Agents | `agents` table | A **flat roster** of identity labels. No owner, no reporting line, no grouping. |
| Organization | — | **Does not exist.** Verified at `e56fce8`: no `org_id` on any table and no org concept in `Caller`. |

`Caller` (`ua-core/src/identity.rs:35`) carries `label`, `kind`, `profile`,
`enforce_profile`, `session_key` and `transport`. It does not carry an
organization, so no query path can scope by one today.

One deliberate exception already exists in the opposite direction: `ua-import`
**refuses** to import source rows that carry an `org_id` unless
`--drop-org-scope` is passed, and then records that tenant boundaries were
dropped (`ua-import/src/lib.rs:81,143,223,420,568`). That is correct while the
hub has no tenant scope. It becomes a migration question the moment the spine
lands — see [The importer](#the-importer).

## The model

Four relations, all data rather than configuration, because the product promise
is that an operator can define their own organization at runtime and have that
definition audited.

```
orgs ──┬── offices        (named capability scopes inside an org)
       ├── teams          (groupings of agents)
       │     └── team_members
       ├── reporting      (supervisor edges, temporal)
       └── agents, tasks, memory, approvals, ...   (the tenant-scoped set)
```

- **org** — the tenant boundary. Everything else hangs off it.
- **office** — a named role scope within an org, carrying a tier and a
  reference to the capability profile it implies. It is *not* an HR job title.
- **team** — a many-to-many grouping of agents, used for memory visibility and
  task ownership.
- **reporting** — a temporal edge from a subordinate to a supervisor, with
  `effective_from` / `effective_to`, so "who reported to whom in March" is
  answerable rather than overwritten.

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
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (org_id, slug)
);

CREATE TABLE IF NOT EXISTS team_members (
    org_id      TEXT NOT NULL,
    team_id     TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    agent_label TEXT NOT NULL,
    added_at    TEXT NOT NULL,
    PRIMARY KEY (team_id, agent_label)
);

CREATE TABLE IF NOT EXISTS reporting (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id           TEXT NOT NULL REFERENCES orgs(id),
    subordinate_type TEXT NOT NULL CHECK (subordinate_type IN ('agent','office')),
    subordinate      TEXT NOT NULL,
    supervisor_type  TEXT NOT NULL CHECK (supervisor_type IN ('agent','office')),
    supervisor       TEXT NOT NULL,
    effective_from   TEXT NOT NULL,
    effective_to     TEXT
);
```

### Adding the column

SQLite permits `ADD COLUMN ... NOT NULL` only when a constant default is
supplied, which is exactly the behaviour wanted here: every existing row is
backfilled atomically with the default organization.

```sql
INSERT OR IGNORE INTO orgs (id, slug, display_name, status, created_at)
    VALUES ('default', 'default', 'Default organization', 'active', strftime('%Y-%m-%dT%H:%M:%fZ','now'));

ALTER TABLE tasks ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
-- ... one statement per tenant-scoped table
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

`Caller` gains `org_id: String`. It is set by the adapter from the verified
credential and from nothing else:

| Transport | Source of the organization |
|---|---|
| Bearer token / OAuth | the token row's `org_id` |
| Passkey / UI session | the user's membership row |
| CLI and stdio, local | the default organization |
| `Caller::system()` | the default organization; cross-organization maintenance must name its target explicitly |

**Never from tool arguments.** `goal_manage` already accepts a `params.org_id`
(`ua-tools/tests/tasks.rs:670`); that stays a *filter within the caller's
organization* and must never widen scope. A test asserts that passing a
different `org_id` returns zero rows rather than that organization's rows.

## Scoping per subsystem

| Subsystem | Tables | Rule |
|---|---|---|
| Tasks | `tasks`, `task_dependencies`, `task_fts` | `org_id` on `tasks`; the FTS read joins through it |
| Agents | `agents`, `agent_sessions`, `agent_tokens`, `session_profiles` | An agent label belongs to exactly one organization |
| Memory | `memory`, `memory_versions`, `memory_embeddings`, `memory_fts` | `org_id` plus a visibility tier (`private` / `team` / `org`), enforced at query time |
| Approvals | `approvals` | An approval from organization A never satisfies the same payload in B |
| Messages | `message_index`, `message_reads`, `notify_outbox`, `pending_notifications` | `org_id` on the message tables |
| Skills | `skill_versions`, `skill_assignments`, `skill_publish_staging` | Catalog is per organization |
| Secrets | `managed_secrets` | Per organization |
| Planning | `plans`, `plan_steps`, `plan_checkpoints`, `routines`, `routine_runs` | Per organization |
| Delegation / cycles | `delegations`, `autonomous_cycles*` | Per organization |
| Nodes | `nodes`, node work queue | A node serves one organization |
| **Global** | `oauth_clients`, `oauth_*`, `passkeys`, `webauthn_states`, `login_links`, `ui_sessions`, `ui_keys` | Identity is global; the **grant** carries the organization |

## The ledger

`event_log` is a single global hash chain. The organization must not fork it,
or every existing chain verification breaks and cross-organization tamper
evidence disappears.

So `org_id` is an ordinary column on `event_log`, included in the hashed row
content, and `verify()` continues to walk one chain. Audit reads filter by
`org_id`; integrity checks stay global. This is the only table where "add the
partition key" and "keep one chain" have to be designed together rather than
assumed.

## The importer

Once the spine exists, `ua-import` has two honest options:

- **A (recommended now).** Keep `--drop-org-scope` as the only path. Source
  organizations all map to the default organization and the import report says
  so. Correct for the common case of importing a single-organization hub.
- **B (when a real multi-organization import appears).** Map source `org_id`
  values to new organizations and preserve boundaries. This needs the source
  organization list, which the importer can already read.

Do not silently accept and drop. The current refusal is the right default and
should stay until B exists.

## What this is not

- **Not an RBAC matrix.** Capability stays with profiles and the policy file.
  The organization decides *which rows*, not *which tools*.
- **Not hard isolation.** Organizations share one hub and one database. Hard
  data-plane separation per organization was considered and not chosen.
- **Not a job-title system.** Offices carry a tier and a name. No HR semantics,
  no hierarchy beyond the reporting edges.

## Acceptance

1. **Single-organization parity.** The existing suite passes unchanged, and the
   seeded default organization is invisible to callers.
2. **Isolation.** Seed a second organization; every read tool called as B
   returns zero rows from A across tasks, memory, approvals, messages, secrets
   and skills.
3. **Approval binding.** An approval created in A does not satisfy the
   identical payload in B.
4. **Ledger integrity.** `verify()` still reports a valid chain; an
   organization-filtered audit returns only that organization's events.
5. **Resolver guard.** The statement-walking test fails if a tenant-scoped
   insert omits `org_id`.
6. **Importer.** A single-organization source hub still imports, and carries no
   silent boundary loss.

## Open questions

1. Does `Caller::system()` belong to the default organization, or is it
   organization-free? Proposal: default organization, with cross-organization
   maintenance naming its target.
2. Are offices defined as data, or a fixed enum? Proposal: data, since the
   product promise is that an operator defines their own.
3. May a task move between organizations? Proposal: no in v1 — task identity
   is organization-local, and a move is a copy plus a cross-reference.
