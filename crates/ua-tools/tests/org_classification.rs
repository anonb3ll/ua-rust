//! Every table in the schema is classified for organization scoping
//! (`docs/organization.md`, Scoping per subsystem).
//!
//! The test applies every schema part this build knows (required and
//! optional) and walks `sqlite_master`. It fails when:
//! - a table is in no class, or in two;
//! - a classified table does not exist (a stale entry);
//! - a tenant table lacks a `NOT NULL` `org_id` or either generated trigger
//!   (`<table>_org_exists`, `<table>_org_immutable`), unless it is listed in
//!   [`TENANT_MISSING_ORG_ID`];
//! - a table in [`TENANT_MISSING_ORG_ID`] is not a tenant table, or already
//!   has what the tenant check requires (remove it from the list);
//! - `event_log` (a global table with a tenant column) lacks a `NOT NULL`
//!   `org_id`;
//! - [`TENANT_MISSING_ORG_ID`] names a table outside its frozen baseline or
//!   grows past it;
//! - a grant table ([`GRANT_TENANT_COLUMN`]: `oauth_grants`, `ui_sessions`)
//!   lacks a `NOT NULL` `org_id`, unless it is in [`GRANT_MISSING_ORG_ID`],
//!   or is still listed there once it has one.
//!
//! This file, not the table in the design, is the authority on which class a
//! table is in; the design's table is kept in step with it.
//!
//! `TENANT_MISSING_ORG_ID` is a temporary relaxation of the design, which
//! requires the tenant check for every tenant table: most tenant tables do not
//! carry `org_id` yet. Each family's part (`organization.v1.<crate>.<family>`;
//! one per family, because a generated part's checksum covers its table list,
//! so a released part can never take another family's tables) removes its
//! tables from the list, and the list may only shrink. A new tenant table gets its
//! `org_id` and triggers in the part that creates it, and is never added here.
//!
//! The lists hold only tables that exist today. A table the design names but
//! no part creates yet (`users`, `teams`, ...) is added with its part.
//!
//! The same lists drive the insert guard at the end of this file
//! (`docs/organization.md`, `organization.v1`, guard 2): every `INSERT` into a
//! tenant table that already carries its organization key (a [`TENANT`]
//! table not in [`TENANT_MISSING_ORG_ID`]) must name `org_id`, in the
//! non-test source of every workspace crate and in every trigger body in
//! `sqlite_master`. The column's default is the default organization, so an
//! insert that leaves it out would write there silently.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};

// The source scanner shared with `ua-core`'s guard tests (`org_guard`,
// `authz_guard`): comment and string masking, `#[cfg(test)]` removal, and the
// workspace's non-test source files.
#[path = "../../ua-core/tests/support/mod.rs"]
mod support;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Tenant data: `org_id NOT NULL` plus both generated triggers.
    Tenant,
    /// FTS5 indexes. No `org_id`; every read joins through the owner table.
    DerivedIndex,
    /// One hash chain for the hub, with an `org_id` per row.
    TenantColumnOnGlobal,
    /// Identity is global; the grant carries the organization.
    GlobalIdentity,
    /// Hub-scoped configuration and bookkeeping.
    Hub,
}

const TENANT: &[&str] = &[
    // tasks and planning
    "tasks",
    "task_dependencies",
    "task_comments",
    "task_comment_threads",
    "task_checks",
    "task_holds",
    "task_hold_members",
    "task_workflow",
    "task_goal_links",
    "goals",
    "work_proposals",
    "work_proposal_items",
    "review_ready_notices",
    "project_repo_bindings",
    "plans",
    "plan_steps",
    "plan_checkpoints",
    "routines",
    "routine_runs",
    "workflow_runs",
    "workflow_checkpoints",
    "delegations",
    "autonomous_cycles",
    "autonomous_cycle_transitions",
    "autonomous_cycle_usage",
    // agents and sessions
    "agents",
    "agent_sessions",
    "agent_tokens",
    "agent_lifecycle",
    "session_profiles",
    "session_credentials",
    "session_handoff_notes",
    "session_wake",
    "session_wake_offers",
    "dispatch_receipts",
    "dispatch_runs",
    // nodes
    "nodes",
    "node_acceptance",
    "node_claim_ops",
    "node_command",
    "node_command_notice",
    "node_dispatch",
    "node_followups",
    // memory
    "memory",
    "memory_versions",
    "memory_embeddings",
    // approvals and policy
    "approvals",
    "policy_authorizations",
    // messages
    "message_index",
    "message_reads",
    "notify_outbox",
    "pending_notifications",
    "relay_messages",
    "zulip_sends",
    // skills and config
    "skill_versions",
    "skill_assignments",
    "skill_publish_staging",
    "harness_config_bundles",
    "harness_config_proposals",
    "harness_config_drift",
    "harness_config_report_window",
    // other
    "managed_secrets",
    "graph_canvas_scenes",
    "graph_canvas_revisions",
    "idempotency_keys",
    "tool_calls",
    "web_search_cache",
    "code_symbols",
    // the GitHub poller's per-organization state: org_id and the triggers from birth
    "github_poll_repos",
    // inbound deliveries (`ua-ingress`): org_id and the triggers from birth
    "inbound_deliveries",
    // deliverables (`ua-deliverables`): org_id and the triggers from birth
    "deliverables",
    "deliverable_revisions",
];

/// Tenant tables that do not yet pass the tenant check. May only shrink.
/// Today that is every tenant table except `inbound_deliveries` (born with
/// its `org_id`), `deliverables` and `deliverable_revisions` (born with their
/// `org_id`), `code_symbols`, the two graph canvas tables,
/// `web_search_cache` (`web.v2.tenant_keys`, `organization.v1.tools.web`),
/// the three skill registry tables (`skill_registry.v2.tenant_keys`,
/// `organization.v1.tools.skills`), `project_repo_bindings`
/// (`governance.v2.project_bindings_tenant_keys`,
/// `organization.v1.tools.project_bindings`), `notify_outbox` and
/// `pending_notifications` (`organization.v1.tools.notify`), `zulip_sends`
/// (`organization.v1.tools.zulip`), the four harness config tables
/// (`harness_config.v3.tenant_keys`, `organization.v1.tools.harness_config`),
/// `routines` and `routine_runs` (`organization.v1.tools.routines`),
/// `workflow_runs` and `workflow_checkpoints`
/// (`organization.v1.tools.workflows`), the three plans tables
/// (`organization.v1.tools.plans`), the three autonomous-cycle tables
/// (`organization.v1.tools.cycles`), `approvals`
/// (`organization.v1.tools.approvals`), `tasks`, `task_dependencies`,
/// `task_comments` and `task_comment_threads` (`organization.v1.tools.tasks`),
/// `managed_secrets` (`managed_secrets.v2.tenant_keys`,
/// `organization.v1.tools.managed_secrets`), `policy_authorizations`
/// (`organization.v1.tools.policy_authorizations`), `tool_calls`
/// (`organization.v1.tools.tool_calls`), `memory`, `memory_versions`
/// and `memory_embeddings` (`organization.v1.memory`, `memory.v2.org_scope`),
/// `message_index` and `message_reads` (`organization.v1.tools.messaging`),
/// `relay_messages` (`organization.v1.tools.relay`), the seven node tables
/// (`node_queue.v2.tenant_keys`, `organization.v1.tools.nodes`) and
/// `dispatch_runs` and `dispatch_receipts` (`organization.v1.tools.dispatch`).
const TENANT_MISSING_ORG_ID: &[&str] = &[
    "agent_lifecycle",
    "agent_sessions",
    "agent_tokens",
    "agents",
    "idempotency_keys",
    "session_credentials",
    "session_handoff_notes",
    "session_profiles",
    "session_wake",
    "session_wake_offers",
];

const DERIVED_INDEX: &[&str] = &["task_fts", "memory_fts"];

/// FTS5 shadow tables are `<index>_<suffix>`.
const FTS_SHADOW_SUFFIXES: &[&str] = &["data", "idx", "content", "docsize", "config"];

const TENANT_COLUMN_ON_GLOBAL: &[&str] = &["event_log"];

const GLOBAL_IDENTITY: &[&str] = &[
    "passkeys",
    "webauthn_states",
    "login_links",
    "oauth_clients",
    "oauth_codes",
    "oauth_grants",
    "oauth_requests",
    "oauth_tokens",
    "ui_keys",
    "ui_sessions",
];

const HUB: &[&str] = &[
    "orgs",
    "config_revisions",
    "mcp_servers",
    "provider_accounts",
    "dispatch_meta",
    "github_deliveries",
    "github_delivery_bodies",
    "github_poll_state",
    "slack_seen_signatures",
    "slack_seen_deliveries",
    "zulip_fetch_cursors",
    "vault_ingest_ledger",
    "import_runs",
    "schema_parts",
    // The audit record of applied procedure parts (not in the design's list,
    // which predates it).
    "schema_procedures",
    "ledger_meta",
];

/// The frozen baseline the missing list started from when the classification
/// test landed: every tenant table that existed then. Never add to it. The
/// missing list must stay a subset of it, so a tenant table created later
/// cannot be parked on the missing list; it gets `org_id` and the triggers in
/// the part that creates it.
const TENANT_MISSING_BASELINE: &[&str] = &[
    "agent_lifecycle",
    "agent_sessions",
    "agent_tokens",
    "agents",
    "approvals",
    "autonomous_cycle_transitions",
    "autonomous_cycle_usage",
    "autonomous_cycles",
    "code_symbols",
    "delegations",
    "dispatch_receipts",
    "dispatch_runs",
    "goals",
    "graph_canvas_revisions",
    "graph_canvas_scenes",
    "harness_config_bundles",
    "harness_config_drift",
    "harness_config_proposals",
    "harness_config_report_window",
    "idempotency_keys",
    "managed_secrets",
    "memory",
    "memory_embeddings",
    "memory_versions",
    "message_index",
    "message_reads",
    "node_acceptance",
    "node_claim_ops",
    "node_command",
    "node_command_notice",
    "node_dispatch",
    "node_followups",
    "nodes",
    "notify_outbox",
    "pending_notifications",
    "plan_checkpoints",
    "plan_steps",
    "plans",
    "policy_authorizations",
    "project_repo_bindings",
    "relay_messages",
    "review_ready_notices",
    "routine_runs",
    "routines",
    "session_credentials",
    "session_handoff_notes",
    "session_profiles",
    "session_wake",
    "session_wake_offers",
    "skill_assignments",
    "skill_publish_staging",
    "skill_versions",
    "task_checks",
    "task_comment_threads",
    "task_comments",
    "task_dependencies",
    "task_goal_links",
    "task_hold_members",
    "task_holds",
    "task_workflow",
    "tasks",
    "tool_calls",
    "web_search_cache",
    "work_proposal_items",
    "work_proposals",
    "workflow_checkpoints",
    "workflow_runs",
    "zulip_sends",
];
const TENANT_MISSING_BASELINE_LEN: usize = 68;

/// Global identity tables whose rows are grants and so carry the
/// organization (`docs/organization.md`, Scoping per subsystem: "the grant
/// carries the organization"). Each needs a `NOT NULL` `org_id`, unless it is
/// listed in [`GRANT_MISSING_ORG_ID`]. (`agent_tokens` is a tenant table.)
const GRANT_TENANT_COLUMN: &[&str] = &["oauth_grants", "ui_sessions"];

/// Grant tables that do not have their `org_id` yet: the same temporary
/// relaxation as [`TENANT_MISSING_ORG_ID`]. May only shrink.
const GRANT_MISSING_ORG_ID: &[&str] = &["oauth_grants", "ui_sessions"];

/// SQLite's own tables.
const SQLITE_INTERNAL: &[&str] = &["sqlite_sequence", "sqlite_stat1", "sqlite_stat4"];

struct Lists<'a> {
    classes: Vec<(Class, &'a [&'a str])>,
    missing: &'a [&'a str],
    grants_missing: &'a [&'a str],
}

fn lists() -> Lists<'static> {
    Lists {
        classes: vec![
            (Class::Tenant, TENANT),
            (Class::DerivedIndex, DERIVED_INDEX),
            (Class::TenantColumnOnGlobal, TENANT_COLUMN_ON_GLOBAL),
            (Class::GlobalIdentity, GLOBAL_IDENTITY),
            (Class::Hub, HUB),
        ],
        missing: TENANT_MISSING_ORG_ID,
        grants_missing: GRANT_MISSING_ORG_ID,
    }
}

fn schema() -> Connection {
    let mut parts = ua_tools::schema_parts();
    parts.extend(ua_tools::optional_schema_parts());
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    ua_store::schema::apply(&mut conn, &parts).unwrap();
    conn
}

fn tables(conn: &Connection) -> Vec<String> {
    conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// `Some(notnull)` when `table` has an `org_id` column.
fn org_id(conn: &Connection, table: &str) -> Option<bool> {
    conn.query_row("SELECT \"notnull\" FROM pragma_table_info(?1) WHERE name = 'org_id'", [table], |r| {
        r.get::<_, i64>(0).map(|n| n != 0)
    })
    .optional()
    .unwrap()
}

fn has_trigger(conn: &Connection, table: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1 AND tbl_name = ?2",
        [name, table],
        |_| Ok(()),
    )
    .optional()
    .unwrap()
    .is_some()
}

/// What the tenant check finds wrong with `table`; empty when it passes.
fn tenant_gaps(conn: &Connection, table: &str) -> Vec<String> {
    let mut gaps = Vec::new();
    match org_id(conn, table) {
        None => gaps.push("no org_id".to_string()),
        Some(false) => gaps.push("nullable org_id".to_string()),
        Some(true) => {}
    }
    for suffix in ["org_exists", "org_immutable"] {
        let name = format!("{table}_{suffix}");
        if !has_trigger(conn, table, &name) {
            gaps.push(format!("no {name} trigger"));
        }
    }
    gaps
}

/// Every classification problem in `conn`, one line each.
fn problems(conn: &Connection, l: &Lists<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut class_of: BTreeMap<&str, Class> = BTreeMap::new();
    for (class, names) in &l.classes {
        for name in names.iter() {
            if let Some(prev) = class_of.insert(*name, *class) {
                out.push(format!("{name}: classified twice ({prev:?} and {class:?})"));
            }
        }
    }
    for name in SQLITE_INTERNAL {
        if class_of.contains_key(name) {
            out.push(format!("{name}: SQLite's own table is classified"));
        }
    }

    let present = tables(conn);
    let present_set: BTreeSet<&str> = present.iter().map(String::as_str).collect();
    for name in &present {
        if SQLITE_INTERNAL.contains(&name.as_str()) || class_of.contains_key(name.as_str()) {
            continue;
        }
        let shadow = DERIVED_INDEX.iter().any(|ix| {
            name.strip_prefix(ix)
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(|suffix| FTS_SHADOW_SUFFIXES.contains(&suffix))
        });
        if !shadow {
            out.push(format!("{name}: unclassified table; add it to a class in tests/org_classification.rs"));
        }
    }
    for name in class_of.keys() {
        if !present_set.contains(name) {
            out.push(format!("{name}: classified but no schema part creates it"));
        }
    }

    let missing: BTreeSet<&str> = l.missing.iter().copied().collect();
    if l.missing.len() > TENANT_MISSING_BASELINE_LEN {
        out.push(format!(
            "TENANT_MISSING_ORG_ID has {} entries, more than its baseline of {TENANT_MISSING_BASELINE_LEN}; it may only shrink",
            l.missing.len()
        ));
    }
    for name in &missing {
        if class_of.get(name) != Some(&Class::Tenant) {
            out.push(format!("{name}: listed as missing org_id but is not a tenant table"));
        } else if !TENANT_MISSING_BASELINE.contains(name) {
            out.push(format!(
                "{name}: listed as missing org_id but not in the frozen baseline; a new tenant table gets \
                 org_id and its triggers in the part that creates it"
            ));
        } else if present_set.contains(name) && tenant_gaps(conn, name).is_empty() {
            out.push(format!("{name}: now passes the tenant check; remove it from TENANT_MISSING_ORG_ID"));
        }
    }
    for (name, class) in &class_of {
        if !present_set.contains(name) {
            continue;
        }
        match class {
            Class::Tenant if !missing.contains(name) => {
                for gap in tenant_gaps(conn, name) {
                    out.push(format!("{name}: tenant table with {gap}"));
                }
            }
            Class::TenantColumnOnGlobal if org_id(conn, name) != Some(true) => {
                out.push(format!("{name}: needs a NOT NULL org_id"));
            }
            _ => {}
        }
    }

    for name in l.grants_missing {
        if !GRANT_TENANT_COLUMN.contains(name) {
            out.push(format!("{name}: listed as a grant missing org_id but is not a grant table"));
        }
    }
    for name in GRANT_TENANT_COLUMN {
        if class_of.get(name) != Some(&Class::GlobalIdentity) {
            out.push(format!("{name}: a grant table must be classified as global identity"));
            continue;
        }
        if !present_set.contains(name) {
            continue;
        }
        let has = org_id(conn, name) == Some(true);
        match (l.grants_missing.contains(name), has) {
            (true, true) => {
                out.push(format!("{name}: now has a NOT NULL org_id; remove it from GRANT_MISSING_ORG_ID"))
            }
            (false, false) => out.push(format!(
                "{name}: a grant table needs a NOT NULL org_id (the grant carries the organization)"
            )),
            _ => {}
        }
    }
    out
}

#[test]
fn every_table_is_classified() {
    let conn = schema();
    let found = problems(&conn, &lists());
    assert!(found.is_empty(), "{}", found.join("\n"));
    // A visible count, so a change in the number of tables shows in review.
    eprintln!("{} tables in sqlite_master", tables(&conn).len());
}

#[test]
fn an_unclassified_table_fails() {
    let conn = schema();
    conn.execute_batch("CREATE TABLE rogue_things (id INTEGER PRIMARY KEY);").unwrap();
    let found = problems(&conn, &lists());
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("rogue_things: unclassified"), "{found:?}");
}

#[test]
fn a_table_resembling_an_fts_shadow_is_not_excused() {
    let conn = schema();
    conn.execute_batch("CREATE TABLE task_fts_extra (id INTEGER PRIMARY KEY);").unwrap();
    let found = problems(&conn, &lists());
    assert!(found.iter().any(|p| p.starts_with("task_fts_extra: unclassified")), "{found:?}");
}

#[test]
fn a_stale_entry_fails() {
    let conn = schema();
    let hub: Vec<&str> = HUB.iter().copied().chain(["retired_table"]).collect();
    let mut l: Lists<'_> = lists();
    l.classes.retain(|(c, _)| *c != Class::Hub);
    l.classes.push((Class::Hub, hub.as_slice()));
    let found = problems(&conn, &l);
    assert_eq!(found, ["retired_table: classified but no schema part creates it"]);
}

#[test]
fn a_tenant_table_must_leave_the_missing_list_once_it_passes_and_fail_otherwise() {
    let conn = schema();
    // Give `idempotency_keys` its tenant shape by hand, as its part will.
    conn.execute_batch(
        "ALTER TABLE idempotency_keys ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
         CREATE TRIGGER idempotency_keys_org_exists BEFORE INSERT ON idempotency_keys
         WHEN NOT EXISTS (SELECT 1 FROM orgs WHERE id = NEW.org_id)
         BEGIN SELECT RAISE(ABORT, 'unknown organization'); END;
         CREATE TRIGGER idempotency_keys_org_immutable BEFORE UPDATE OF org_id ON idempotency_keys
         WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id
         BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;",
    )
    .unwrap();
    let found = problems(&conn, &lists());
    assert_eq!(
        found,
        ["idempotency_keys: now passes the tenant check; remove it from TENANT_MISSING_ORG_ID"]
    );

    // Off the list, `idempotency_keys` passes, and `agents` (still without org_id) fails.
    let shrunk: Vec<&str> = TENANT_MISSING_ORG_ID
        .iter()
        .copied()
        .filter(|t| !["idempotency_keys", "agents"].contains(t))
        .collect();
    let l = Lists { missing: &shrunk, ..lists() };
    let found = problems(&conn, &l);
    assert_eq!(
        found,
        [
            "agents: tenant table with no org_id",
            "agents: tenant table with no agents_org_exists trigger",
            "agents: tenant table with no agents_org_immutable trigger",
        ]
    );
}

#[test]
fn only_tenant_tables_may_be_listed_as_missing() {
    let conn = schema();
    // Swap one entry for a hub table, so the list keeps its length.
    let missing: Vec<&str> =
        TENANT_MISSING_ORG_ID.iter().copied().filter(|t| *t != "idempotency_keys").chain(["orgs"]).collect();
    // Give `idempotency_keys` its tenant shape, so leaving the list is not itself a finding.
    conn.execute_batch(
        "ALTER TABLE idempotency_keys ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
         CREATE TRIGGER idempotency_keys_org_exists BEFORE INSERT ON idempotency_keys
         WHEN NOT EXISTS (SELECT 1 FROM orgs WHERE id = NEW.org_id)
         BEGIN SELECT RAISE(ABORT, 'unknown organization'); END;
         CREATE TRIGGER idempotency_keys_org_immutable BEFORE UPDATE OF org_id ON idempotency_keys
         WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id
         BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;",
    )
    .unwrap();
    let l = Lists { missing: &missing, ..lists() };
    let found = problems(&conn, &l);
    assert_eq!(found, ["orgs: listed as missing org_id but is not a tenant table"]);
}

#[test]
fn the_missing_baseline_is_frozen() {
    assert_eq!(TENANT_MISSING_BASELINE.len(), TENANT_MISSING_BASELINE_LEN, "the baseline never grows");
    assert!(TENANT_MISSING_ORG_ID.len() <= TENANT_MISSING_BASELINE_LEN);
    for name in TENANT_MISSING_ORG_ID {
        assert!(TENANT_MISSING_BASELINE.contains(name), "{name}");
    }
}

#[test]
fn a_new_tenant_table_cannot_be_parked_on_the_missing_list() {
    let conn = schema();
    conn.execute_batch("CREATE TABLE new_widgets (id INTEGER PRIMARY KEY);").unwrap();
    let tenant: Vec<&str> = TENANT.iter().copied().chain(["new_widgets"]).collect();
    let missing: Vec<&str> = TENANT_MISSING_ORG_ID.iter().copied().chain(["new_widgets"]).collect();
    let mut l: Lists<'_> = lists();
    l.classes.retain(|(c, _)| *c != Class::Tenant);
    l.classes.push((Class::Tenant, tenant.as_slice()));
    l.missing = &missing;
    let found = problems(&conn, &l);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].starts_with("new_widgets: listed as missing org_id but not in the frozen baseline"),
        "{found:?}"
    );

    // A list longer than the baseline fails on its length alone (the list has
    // shrunk below the baseline, so pad it with entries already on it).
    let padded: Vec<&str> =
        TENANT_MISSING_ORG_ID.iter().copied().cycle().take(TENANT_MISSING_BASELINE_LEN + 1).collect();
    let found = problems(&schema(), &Lists { missing: &padded, ..lists() });
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].starts_with("TENANT_MISSING_ORG_ID has 69 entries"), "{found:?}");
}

#[test]
fn grant_tables_are_tracked_until_they_carry_org_id() {
    let conn = schema();
    // With the relaxation removed, both grant tables fail.
    let l = Lists { grants_missing: &[], ..lists() };
    assert_eq!(
        problems(&conn, &l),
        [
            "oauth_grants: a grant table needs a NOT NULL org_id (the grant carries the organization)",
            "ui_sessions: a grant table needs a NOT NULL org_id (the grant carries the organization)",
        ]
    );
    // Once one has its column, it must leave the list.
    conn.execute_batch("ALTER TABLE ui_sessions ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';").unwrap();
    assert_eq!(
        problems(&conn, &lists()),
        ["ui_sessions: now has a NOT NULL org_id; remove it from GRANT_MISSING_ORG_ID"]
    );
}

// ---------------------------------------------------------------------------
// Insert guard
// ---------------------------------------------------------------------------

/// Tenant tables that carry their organization key: [`TENANT`] minus
/// [`TENANT_MISSING_ORG_ID`]. `every_table_is_classified` proves each of them
/// has a `NOT NULL` `org_id` and both triggers.
fn keyed_tenant_tables() -> BTreeSet<&'static str> {
    TENANT.iter().copied().filter(|t| !TENANT_MISSING_ORG_ID.contains(t)).collect()
}

/// One `INSERT` (any `OR <conflict>` form, upserts included) or `REPLACE`
/// statement found in text: its table and its column list, if it has one.
struct Insert {
    at: usize,
    table: String,
    columns: Option<String>,
}

fn is_ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Skip whitespace and the `\` of a Rust string's line continuation.
fn skip_space(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'\\') {
        i += 1;
    }
    i
}

/// The keyword `kw` (upper case, whole word) at `i`; the index after it.
fn keyword(b: &[u8], i: usize, kw: &str) -> Option<usize> {
    let end = i + kw.len();
    (b.get(i..end) == Some(kw.as_bytes()) && b.get(end).is_none_or(|c| !is_ident_byte(*c))).then_some(end)
}

/// Every insert statement in `text`. SQL in this tree is upper case; a table
/// name built at run time (`{table}`) is not a name and is skipped.
fn inserts(text: &str) -> Vec<Insert> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    for start in 0..b.len() {
        if start > 0 && is_ident_byte(b[start - 1]) {
            continue;
        }
        let mut i = if let Some(e) = keyword(b, start, "INSERT") {
            let j = skip_space(b, e);
            match keyword(b, j, "OR") {
                Some(e) => {
                    let k = skip_space(b, e);
                    let w = b[k..].iter().take_while(|c| c.is_ascii_alphabetic()).count();
                    k + w
                }
                None => j,
            }
        } else if let Some(e) = keyword(b, start, "REPLACE") {
            // `INSERT OR REPLACE` was taken at its `INSERT`.
            let before = text[..start].trim_end_matches(|c: char| c.is_whitespace() || c == '\\');
            if before.ends_with("OR") {
                continue;
            }
            e
        } else {
            continue;
        };
        i = skip_space(b, i);
        let Some(e) = keyword(b, i, "INTO") else { continue };
        i = skip_space(b, e);
        // An optional quote around the name (`"t"`, `\"t\"` in Rust source,
        // `` `t` ``, `[t]`) and an optional `main.` schema.
        while i < b.len() && matches!(b[i], b'"' | b'\\' | b'`' | b'[') {
            i += 1;
        }
        if let Some(e) = keyword(b, i, "main").filter(|e| b.get(*e) == Some(&b'.')) {
            i = e + 1;
        }
        let n = b[i..].iter().take_while(|c| is_ident_byte(**c)).count();
        if n == 0 {
            continue;
        }
        let table = text[i..i + n].to_string();
        i += n;
        while i < b.len() && matches!(b[i], b'"' | b'\\' | b'`' | b']') {
            i += 1;
        }
        i = skip_space(b, i);
        let columns = (b.get(i) == Some(&b'(')).then(|| {
            let mut depth = 0usize;
            let mut end = b.len();
            for (k, c) in b[i..].iter().enumerate() {
                match c {
                    b'(' => depth += 1,
                    b')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i + k;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            text[i + 1..end].to_string()
        });
        out.push(Insert { at: start, table, columns });
    }
    out
}

/// Whether a column list names `org_id` as a whole word.
fn names_org_id(columns: &str) -> bool {
    columns.match_indices("org_id").any(|(at, _)| {
        let b = columns.as_bytes();
        (at == 0 || !is_ident_byte(b[at - 1])) && b.get(at + 6).is_none_or(|c| !is_ident_byte(*c))
    })
}

/// Findings for the inserts in `text` (named `origin`) into `keyed` tables,
/// and how many such inserts there were.
fn insert_findings(origin: &str, text: &str, keyed: &BTreeSet<&str>) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut seen = 0;
    for ins in inserts(text) {
        if !keyed.contains(ins.table.as_str()) {
            continue;
        }
        seen += 1;
        let line = support::line_of(text, ins.at);
        match &ins.columns {
            None => out.push(format!(
                "{origin}:{line}: INSERT INTO {} has no column list; name org_id explicitly",
                ins.table
            )),
            Some(cols) if !names_org_id(cols) => out.push(format!(
                "{origin}:{line}: INSERT INTO {} does not name org_id (its default is the default organization)",
                ins.table
            )),
            Some(_) => {}
        }
    }
    (out, seen)
}

/// Released, checksum-locked parts whose SQL creates a trigger that inserts
/// into a tenant table without naming `org_id`, and that a later part drops
/// and recreates naming it. The released text cannot change (`ua-store`
/// refuses an edited part), so it is excused here by its exact text, in its
/// own file only; the trigger scan below still checks the live trigger, which
/// is the one that runs. Each entry must still be found, so none goes stale.
///
/// - `memory_versions.v1`'s `memory_versions_capture`, recreated by
///   `memory.v2.org_scope` with `OLD.org_id`.
fn released_superseded() -> [(&'static str, &'static str); 1] {
    [("crates/ua-memory/src/schema.rs", ua_memory::VERSIONS_SCHEMA.sql)]
}

/// `src` with each excused released text in it blanked (newlines kept, so
/// line numbers hold), and how many were blanked.
fn without_released_superseded(path: &str, src: &str) -> (String, usize) {
    let mut out = src.to_string();
    let mut hits = 0;
    for (file, sql) in released_superseded() {
        if path.ends_with(file)
            && let Some(at) = out.find(sql)
        {
            let blank: String = sql.chars().map(|c| if c == '\n' { c } else { ' ' }).collect();
            out.replace_range(at..at + sql.len(), &blank);
            hits += 1;
        }
    }
    (out, hits)
}

#[test]
fn every_insert_into_a_keyed_tenant_table_names_org_id() {
    let keyed = keyed_tenant_tables();
    assert!(keyed.contains("code_symbols") && keyed.contains("inbound_deliveries"), "{keyed:?}");
    let mut found = Vec::new();
    let mut seen = 0;
    let files = support::sources();
    assert!(files.len() > 100, "found only {} source files", files.len());
    let mut excused = 0;
    for (path, src) in &files {
        let path = path.display().to_string();
        let (text, hits) = without_released_superseded(&path, &support::without_tests_raw(src));
        excused += hits;
        let (f, n) = insert_findings(&path, &text, &keyed);
        found.extend(f);
        seen += n;
    }
    // Trigger bodies insert too, and no Rust string shows them.
    let conn = schema();
    let triggers: Vec<(String, String)> = conn
        .prepare("SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(!triggers.is_empty());
    for (name, sql) in &triggers {
        let (f, n) = insert_findings(&format!("trigger {name}"), sql, &keyed);
        found.extend(f);
        seen += n;
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
    assert_eq!(
        excused,
        released_superseded().len(),
        "an excused released part was not found; drop its entry"
    );
    // The scan sees the inserts it is meant to: the code family's, the
    // inbound table's and its two copies (GitHub, Slack).
    assert!(seen >= 5, "saw only {seen} inserts into keyed tenant tables");
}

#[test]
fn the_insert_guard_catches_a_missing_org_id_and_accepts_a_named_one() {
    let keyed: BTreeSet<&str> = ["code_symbols", "inbound_deliveries"].into();
    let bad = [
        "INSERT INTO code_symbols (workspace, file_path) VALUES (?1, ?2)",
        "INSERT OR REPLACE INTO code_symbols (workspace) VALUES (?1)",
        "INSERT OR IGNORE INTO code_symbols(workspace) VALUES (?1)",
        "REPLACE INTO code_symbols (workspace) VALUES (?1)",
        "INSERT INTO inbound_deliveries (source, kind) VALUES (?1, ?2) ON CONFLICT DO NOTHING",
        "INSERT INTO code_symbols VALUES (1, 'w')",
        "INSERT INTO \\\"code_symbols\\\" (workspace) VALUES (?1)",
        "INSERT INTO main.code_symbols (workspace) VALUES (?1)",
        "INSERT INTO code_symbols \\\n    (org_id_shadow, workspace) VALUES (?1, ?2)",
        "INSERT INTO code_symbols (workspace) SELECT workspace FROM other",
    ];
    for sql in bad {
        let (found, seen) = insert_findings("demo.rs", &format!("let q = \"{sql}\";"), &keyed);
        assert_eq!((found.len(), seen), (1, 1), "{sql}: {found:?}");
    }
    let good = [
        "INSERT INTO code_symbols (org_id, workspace) VALUES (?1, ?2)",
        "INSERT OR REPLACE INTO code_symbols \\\n    (workspace, org_id) VALUES (?1, ?2)",
        "INSERT INTO inbound_deliveries (org_id, source) SELECT 'default', source FROM old",
        // Not a keyed tenant table, a longer name, or a name built at run time.
        "INSERT INTO tasks (title) VALUES (?1)",
        "INSERT INTO code_symbols_extra (workspace) VALUES (?1)",
        "INSERT INTO {table} (workspace) VALUES (?1)",
        // Not a statement.
        "REINSERT INTO code_symbols (workspace)",
    ];
    for sql in good {
        let (found, _) = insert_findings("demo.rs", &format!("let q = \"{sql}\";"), &keyed);
        assert!(found.is_empty(), "{sql}: {found:?}");
    }
    // A trigger body is checked the same way.
    let body =
        "CREATE TRIGGER t AFTER UPDATE ON x BEGIN INSERT INTO code_symbols (workspace) VALUES (1); END";
    assert_eq!(insert_findings("trigger t", body, &keyed).0.len(), 1);
}
