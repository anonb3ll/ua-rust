# Parity with the Python hub

> **Status: draft for the maintainer's review.** Nothing here is in force until
> it is approved. The dispositions in the tables below are proposals.

ua-rust is the next version of the Python unified-agent hub, not a copy of it.
This page says what "parity" means for that work, what is deliberately left
behind, and how each family of capabilities is checked before and after it is
brought over.

## What parity means

There are three things a port could preserve. They are treated differently.

| Level | What it is | Rule |
|---|---|---|
| Contract | Tool names, argument shapes, HTTP routes and event shapes that an existing client, the SDK or the importer depends on | Kept. A change is deliberate, tested, and written down under the family's "Differences from the Python hub" |
| Capability | What a person or an agent can get done: hand out work, hold it, approve it, recover a session, prove what happened | Reached or exceeded. This is the measure of parity |
| Implementation | How the Python hub does it: its modules, tables, config switches, helper paths and the order things happen to run in | Not preserved. It is evidence of what the capability is, nothing more |

A count of tool names that exist in one registry and not the other is a useful
inventory. It is not the goal. A family is at parity when its capability
statement holds here, the contract its clients use still answers, and the
differences are recorded.

## Principles

1. **One mechanism per concern.** When the Python hub grew two ways of doing
   one thing, ua-rust gets one. The second is merged, not ported. Examples
   already found in this repository:
   - *Who has authority.* "Is this a human" was defined four times and
     "is this an operator" was decided five different ways. They now go through
     one module (`ua-org`'s `authz`), and a test counts the remaining ad-hoc
     checks so the number can only go down.
   - *Inbound deliveries and outbound calls.* The GitHub, Slack, Zulip, relay,
     webhook and gateway paths carry six duplicate-delivery mechanisms, six
     HTTP clients and three private-address guards between them. The target is
     one inbound-delivery table and one guarded HTTP client in a crate of
     their own.
   - *Gates.* An action reached through a consolidated `*_manage` tool is held
     to the same profile, policy and approval rules as the standalone tool.
     There is one table that says which is which.
2. **Do not port accidental complexity.** A behaviour that exists because of
   how the Python code happened to be built is not a requirement. A switch
   that exists to work around another part of the Python hub is not ported
   with it. If the reason for a behaviour cannot be stated as something a user
   or an agent needs, it is left behind and listed as a difference.
3. **Security and evidence only get stronger.** A port may refuse something
   the Python hub allowed. It may not allow something the Python hub refused,
   and it may not record less. Authority comes from identity, never from a
   session profile; a profile is a set of permissions.
4. **Keep the contract honest.** A route or tool that is not built answers
   `501` and says so. Nothing is stubbed to look present.
5. **New families get their own crate.** `ua-tools` is not the place for a
   new family; storage goes through `ua-store`.
6. **Ratchets instead of rewrites.** Where the existing code falls short of a
   principle, a test records the current count and refuses an increase. The
   count comes down slice by slice.
7. **Stored data moves through the importer.** The storage schema is new. What
   an operator had in the Python hub arrives through `ua import python-hub`,
   which refuses rather than guesses, and a family is not done until its
   tables are mapped or explicitly excluded.

## Non-goals

These are decisions, not gaps. A proposal that needs one of them changed has to
say so and be approved as a change to this page.

- **Not bug-for-bug compatible.** Timing, error wording beyond the documented
  error codes, incidental ordering and undocumented side effects are not
  reproduced.
- **Not every tool.** A tool is not ported when another tool already does its
  job, when it served the Python codebase itself (its linter, its deployment
  and release scripts), or when its only callers were inside the Python hub.
- **No second path to the same effect.** Fast paths, fallbacks and legacy
  spellings that duplicate a main path are merged into it.
- **No authority from profiles.** The Python hub lets some profiles act as an
  operator or read everyone's mail. Here those rights come from who the caller
  is.
- **No model calls made by the hub.** Summaries, reviews and adjudication are
  written by agents under their own budgets and validated by the hub.
- **Not the Python schema, and not the Python configuration one for one.**
  Tables and config keys are designed for this codebase. The importer and the
  docs carry the mapping.
- **Not the Python user interface.** The control centre is server-rendered and
  new. It needs to let an operator do the same jobs, not look the same.
- **No second storage backend for now.** SQLite is the store. Repository
  traits come before any alternative.
- **Retired integrations stay retired.** Something the Python hub had already
  switched off by default is not revived by the port.
- **No unreviewed automatic changes.** Where the Python hub applied a change
  on its own (to memory, to configuration, to a queue), the port proposes and
  a person or a gated tool applies.

## How a family is reviewed

Every family goes through the same steps, and the result is written in that
family's page under "Differences from the Python hub".

**Before the port**

1. *Capability statement.* One paragraph: what a person or an agent can do
   with this family, written from the Python hub's behaviour, not its code.
2. *Contract inventory.* The tool names, arguments, routes and events a
   client can observe, and which of them the SDK, the conformance suite or the
   importer rely on.
3. *Overlap check.* For each part, does ua-rust already have the mechanism:
   identity and authority, approvals, policy, the ledger, inbound-delivery
   handling, outbound HTTP, secrets, scheduling, leases? If yes, the family
   uses it. If two candidates exist, they are merged first.
4. *Non-goal check.* Each item is read against the list above.
5. *Disposition.* Every item in the inventory gets one of:

   | Disposition | Meaning | Needs |
   |---|---|---|
   | Keep | Same contract, same behaviour | A conformance or contract test |
   | Merge | Served by an existing mechanism or tool | The mapping, and a test that the old spelling still answers if clients use it |
   | Redesign | Same capability, different shape | The reason, the new shape, and tests for the capability |
   | Drop | Not brought over | The non-goal or the reason, and what a user does instead |
   | Defer | Wanted, not now | What it waits for; the route or tool answers `501` |

**During review of the pull request**

6. The independent reviewer checks the disposition table against the
   non-goals as well as the code: was anything ported that a principle says to
   merge, and was anything dropped that removes a capability?
7. A Drop or a Redesign that changes what a person can do, and anything that
   touches authority, approvals or the ledger, is read by the maintainer
   before it lands.

**After the port**

8. The family's page has its "Differences from the Python hub" section, the
   README's lists are updated, the importer maps or excludes the family's
   tables, and no ratchet count went up.

## Families still to bring over (proposed dispositions)

Taken from the README's "Not yet ported" list. These are proposals for review.

| Family | Proposed | Note |
|---|---|---|
| Queue-health and node-session routes the SDK calls | Keep | Contract the SDK already depends on |
| Session-handoff failover | Keep | Completes a family that is otherwise in |
| Native-session resume and adopt | Redesign | On the node work queue and its fences, not a separate path |
| Discovered native sessions | Defer | Waits for the redesign above |
| GitHub writes (labels, held pull requests, the app installation flow) | Merge | Into the relay's approved-write path; one gate for every outbound write |
| Slack interactions, bot-token posting and live chat | Redesign | Outbound through the relay's gates; inbound through the one delivery table |
| Role workflows | Redesign | On organization roles once memberships exist, not on profiles |
| Provenance graph and evidence export | Redesign | Derived from the ledger, with the manifest's hash checks |
| Billing and usage ledgers | Redesign | Scoped by organization; waits for the organization keys |
| Tenancy | In progress | The organization foundation is in; tables gain `org_id` slice by slice |
| Cloud executors | Defer | Waits for the dispatch contract and budgets |
| Work products | Undecided | Needs a product decision before any disposition |

## Overlaps to merge inside ua-rust

The port itself has copied some duplication. These are tracked the same way.

| Overlap | State |
|---|---|
| Ad-hoc authority checks (human, operator, profile) | One module exists; a ratchet counts what is left |
| Six duplicate-delivery mechanisms, six HTTP clients, three address guards | Planned: one crate for inbound deliveries and guarded outbound calls |
| Raw SQL in tool families, no repository layer | Planned: repository traits in `ua-store`; a ratchet on raw SQL outside it |
| Most of the code living in `ua-tools` | New families go in their own crates; existing ones move out by family |
| Tables without an organization key | A frozen list that may only shrink |

## Open questions for the maintainer

1. Is "capability, not tool count" the right measure, and should the README's
   opening statement about keeping the Python tool contract be reworded to
   match the three levels above?
2. Are the proposed dispositions right, in particular merging GitHub writes
   into the relay and redesigning role workflows on organization roles?
3. Should a dropped tool keep answering with a clear refusal that names its
   replacement, for one release, or simply not exist?
4. Work products: port, redesign as generic deliverables, or drop?
