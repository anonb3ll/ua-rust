# Design principles

> **Status: draft for the maintainer's review.** Companion to
> [parity.md](parity.md), which covers what is brought over from the Python
> hub and what is not. This page is the shape every change builds toward.

A change that needs to break one of these says so in its pull request, and the
maintainer reads it.

## Principles

1. **One call path.** Every interface (MCP, HTTP, the web UI, the CLI, chat
   bridges) reaches a tool through the registry's call wrapper: authenticate,
   profile, policy, approval gate, tool, ledger. No handler is reached another
   way, so a rule is written once and holds everywhere.
2. **Authority comes from identity.** Who may act as an operator, approve, or
   administer is decided in one place (`ua-org`'s `authz`) from who the caller
   is. A session profile is a set of permissions: it can narrow what a session
   sees and calls, and it never grants authority.
3. **One mechanism per concern.** One approval gate, one authority module, one
   way to record an inbound delivery, one guarded client for outbound calls,
   one secrets store, one way to change the schema. A second way to do the
   same thing is merged, not added.
4. **What happened is provable.** Every write that matters appends a
   hash-chained ledger event that names its organization. Evidence and
   security properties only get stronger; a change may refuse more and record
   more, never less.
5. **Tenant-aware from the start.** Every table is classified. A tenant table
   carries its organization key, and an event carries the organization of the
   row it affects, not of the caller.
6. **Fail closed.** An unknown tool, action, argument or configuration key is
   refused. A route that is not built answers `501` and says so. Nothing is
   granted by a default.
7. **The schema only moves forward.** Storage is SQLite through `ua-store`. A
   released schema part is never edited; new behaviour is a new part. Tool
   families are moving off raw SQL onto a repository layer.
8. **Crates by family.** A new family is a new crate, not more code in
   `ua-tools`. Dependencies point one way: core, store, organization,
   families, then the server and the CLI.
9. **The hub governs; agents do the work.** The hub makes no model calls. It
   validates, gates and records what agents and people do under their own
   budgets.
10. **Writes to the outside world go through one gated path.** Anything posted
    to a third party passes the relay's content gates and a human approval
    bound to the exact text and target.
11. **Off by default.** Integrations, public endpoints and background
    schedules are off until an operator turns them on. Secrets come from the
    environment or the managed-secrets store, never from a configuration file
    or a log line.
12. **Ratchets instead of rewrites.** Where the code falls short of a
    principle, a test records the current count and refuses an increase. The
    count comes down one slice at a time.
13. **Small reviewed slices.** One slice per pull request: an independent
    review on the thread, a regression test for each finding, and green checks
    on the exact commit that lands. Changes to authority, approvals, the
    ledger, public endpoints or outbound writes are read by the maintainer.
14. **A public repository.** No private names, hosts, paths or internal
    vocabulary in code, tests, documents or commit messages; a check enforces
    it.

## Non-goals

The parity-specific non-goals are in [parity.md](parity.md#non-goals). These
apply to all work:

- **No authority from profiles**, and no second source of identity outside the
  organization model.
- **No second path to the same effect**: no fast path, fallback or legacy
  spelling that bypasses the call wrapper or duplicates a mechanism.
- **No model calls made by the hub.**
- **No unreviewed automatic changes** to memory, configuration or queues: the
  hub proposes; a person or a gated tool applies.
- **No silent compatibility.** A behaviour kept only because the Python hub
  had it is either a stated requirement or it is dropped and listed as a
  difference.
- **No second storage backend for now.**
- **Nothing on by default that talks to the outside or runs on a timer.**

## How this page is used

- A pull request that adds a family, a table, an outbound call or an authority
  check says which principle covers it.
- The independent reviewer checks the change against this page as well as the
  code.
- The ratchet tests are the enforced part: authority checks outside `authz`,
  tenant tables without an organization key, and (planned) client
  constructions and delivery tables outside the ingress crate, lines in
  `ua-tools`, and raw SQL outside the store.
