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
//!   `org_id`.
//!
//! `TENANT_MISSING_ORG_ID` is a temporary relaxation of the design, which
//! requires the tenant check for every tenant table: no tenant table carries
//! `org_id` yet. Each `organization.v1.<crate>` part removes its tables from
//! the list, and the list may only shrink. A new tenant table gets its
//! `org_id` and triggers in the part that creates it, and is never added here.
//!
//! The lists hold only tables that exist today. A table the design names but
//! no part creates yet (`users`, `teams`, ...) is added with its part.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};

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
];

/// Tenant tables that do not yet pass the tenant check. May only shrink.
/// Today that is every tenant table: `harness_config_bundles` and
/// `harness_config_proposals` carry a nullable `org_id` and no triggers.
const TENANT_MISSING_ORG_ID: &[&str] = &[
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

/// SQLite's own tables.
const SQLITE_INTERNAL: &[&str] = &["sqlite_sequence", "sqlite_stat1", "sqlite_stat4"];

struct Lists<'a> {
    classes: Vec<(Class, &'a [&'a str])>,
    missing: &'a [&'a str],
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
    for name in &missing {
        if class_of.get(name) != Some(&Class::Tenant) {
            out.push(format!("{name}: listed as missing org_id but is not a tenant table"));
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
    // Give `goals` its tenant shape by hand, as its part will.
    conn.execute_batch(
        "ALTER TABLE goals ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default';
         CREATE TRIGGER goals_org_exists BEFORE INSERT ON goals
         WHEN NOT EXISTS (SELECT 1 FROM orgs WHERE id = NEW.org_id)
         BEGIN SELECT RAISE(ABORT, 'unknown organization'); END;
         CREATE TRIGGER goals_org_immutable BEFORE UPDATE OF org_id ON goals
         WHEN OLD.org_id IS NOT NULL AND NEW.org_id IS NOT OLD.org_id
         BEGIN SELECT RAISE(ABORT, 'org_id cannot change'); END;",
    )
    .unwrap();
    let found = problems(&conn, &lists());
    assert_eq!(found, ["goals: now passes the tenant check; remove it from TENANT_MISSING_ORG_ID"]);

    // Off the list, `goals` passes, and `tasks` (still without org_id) fails.
    let shrunk: Vec<&str> =
        TENANT_MISSING_ORG_ID.iter().copied().filter(|t| !["goals", "tasks"].contains(t)).collect();
    let l = Lists { missing: &shrunk, ..lists() };
    let found = problems(&conn, &l);
    assert_eq!(
        found,
        [
            "tasks: tenant table with no org_id",
            "tasks: tenant table with no tasks_org_exists trigger",
            "tasks: tenant table with no tasks_org_immutable trigger",
        ]
    );
}

#[test]
fn only_tenant_tables_may_be_listed_as_missing() {
    let conn = schema();
    let missing: Vec<&str> = TENANT_MISSING_ORG_ID.iter().copied().chain(["orgs"]).collect();
    let l = Lists { missing: &missing, ..lists() };
    let found = problems(&conn, &l);
    assert_eq!(found, ["orgs: listed as missing org_id but is not a tenant table"]);
}
