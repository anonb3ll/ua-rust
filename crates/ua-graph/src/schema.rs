//! Schema parts for the shared graph store (`docs/graph.md`, `graph.v1` and
//! `organization.v1.graph`).
//!
//! Both tables are born tenant-scoped (`org_id TEXT NOT NULL`), with composite
//! foreign keys and defense-in-depth cross-org endpoint triggers, provenance
//! immutability triggers, and `organization.v1.graph` organization existence
//! and immutability triggers.

use ua_store::{Part, Procedure, SchemaPart};

/// `graph.v1`: `graph_nodes`, `graph_edges`, indexes, endpoint fences, and
/// immutability triggers. Applied after `organization.v1.store`.
pub const SCHEMA: SchemaPart = SchemaPart {
    name: "graph.v1",
    sql: "
CREATE TABLE IF NOT EXISTS graph_nodes (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN (
                         'agent','person','skill','memory_note','memory_entity',
                         'task','goal','plan','run','deliverable','vault_note',
                         'approval','policy_revision'
                     )),
    external_id      TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 256),
    display_label    TEXT CHECK (display_label IS NULL OR length(display_label) <= 256),
    visibility       TEXT NOT NULL DEFAULT 'org'
                     CHECK (visibility IN ('private','team','org')),
    team_id          TEXT,
    owner_type       TEXT CHECK (owner_type IS NULL OR owner_type IN ('human','agent','org')),
    owner_id         TEXT,
    asserted_by      TEXT NOT NULL CHECK (length(asserted_by) BETWEEN 1 AND 128),
    asserted_by_kind TEXT NOT NULL CHECK (asserted_by_kind IN ('agent','person','node','system')),
    source_kind      TEXT NOT NULL CHECK (source_kind IN ('tool','event','mirror','import')),
    source_ref       TEXT NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
    meta_json        TEXT NOT NULL DEFAULT '{}'
                     CHECK (json_valid(meta_json) AND length(meta_json) <= 8192),
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    archived_at      TEXT,
    UNIQUE (org_id, kind, external_id),
    UNIQUE (org_id, id),
    CHECK (visibility != 'team' OR team_id IS NOT NULL),
    CHECK (visibility != 'private' OR (owner_type IS NOT NULL AND owner_id IS NOT NULL)),
    CHECK ((asserted_by = 'system') = (asserted_by_kind = 'system'))
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_org_kind_vis
    ON graph_nodes (org_id, kind, visibility, team_id, owner_id)
    WHERE archived_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_graph_nodes_source
    ON graph_nodes (org_id, source_kind, source_ref);

CREATE TRIGGER IF NOT EXISTS graph_nodes_identity_immutable
BEFORE UPDATE OF id, kind, external_id, asserted_by, asserted_by_kind,
                 source_kind, source_ref, created_at ON graph_nodes
BEGIN
    SELECT RAISE(ABORT, 'graph node identity and provenance are immutable');
END;

CREATE TRIGGER IF NOT EXISTS graph_nodes_no_delete
BEFORE DELETE ON graph_nodes
BEGIN
    SELECT RAISE(ABORT, 'graph nodes are archived, never deleted');
END;

CREATE TABLE IF NOT EXISTS graph_edges (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL,
    src_id           TEXT NOT NULL,
    dst_id           TEXT NOT NULL,
    kind             TEXT NOT NULL CHECK (kind IN (
                         'depends_on','subtask_of','serves_goal','goal_parent',
                         'plan_tracks','delegated_to','executes','executed_by',
                         'produces','uses_skill','reviewed_by','approved_by',
                         'governed_by','delegates_to','reviews','escalates_to',
                         'can_observe','mentions','links_to','promoted_from',
                         'supersedes','contradicts','evidence','extends','derives'
                     )),
    assertion_scope  TEXT NOT NULL DEFAULT '' CHECK (length(assertion_scope) <= 128),
    state            TEXT NOT NULL DEFAULT 'active'
                     CHECK (state IN ('active','proposed')),
    weight           REAL NOT NULL DEFAULT 1.0 CHECK (weight > 0.0 AND weight <= 1000.0),
    asserted_by      TEXT NOT NULL CHECK (length(asserted_by) BETWEEN 1 AND 128),
    asserted_by_kind TEXT NOT NULL CHECK (asserted_by_kind IN ('agent','person','node','system')),
    asserted_at      TEXT NOT NULL,
    source_kind      TEXT NOT NULL CHECK (source_kind IN ('tool','event','mirror','import')),
    source_ref       TEXT NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
    valid_from       TEXT NOT NULL,
    valid_to         TEXT,
    meta_json        TEXT NOT NULL DEFAULT '{}'
                     CHECK (json_valid(meta_json) AND length(meta_json) <= 4096),
    CHECK (src_id != dst_id),
    CHECK (state = 'active' OR kind = 'contradicts'),
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    CHECK ((asserted_by = 'system') = (asserted_by_kind = 'system')),
    FOREIGN KEY (org_id, src_id) REFERENCES graph_nodes(org_id, id),
    FOREIGN KEY (org_id, dst_id) REFERENCES graph_nodes(org_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_live_unique
    ON graph_edges (org_id, src_id, dst_id, kind, assertion_scope)
    WHERE valid_to IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_graph_edges_single_out_live
    ON graph_edges (org_id, src_id, kind)
    WHERE valid_to IS NULL
      AND kind IN ('serves_goal','subtask_of','goal_parent','executes','executed_by','governed_by');

CREATE INDEX IF NOT EXISTS idx_graph_edges_out
    ON graph_edges (org_id, src_id, kind, state, valid_to, valid_from, dst_id, weight);
CREATE INDEX IF NOT EXISTS idx_graph_edges_in
    ON graph_edges (org_id, dst_id, kind, state, valid_to, valid_from, src_id, weight);

CREATE INDEX IF NOT EXISTS idx_graph_edges_org_kind_live
    ON graph_edges (org_id, kind, state, valid_to, asserted_at);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source
    ON graph_edges (org_id, source_kind, source_ref);
CREATE INDEX IF NOT EXISTS idx_graph_edges_asserted_by
    ON graph_edges (org_id, asserted_by, asserted_at);

CREATE TRIGGER IF NOT EXISTS graph_edges_org_endpoints_insert
BEFORE INSERT ON graph_edges
WHEN NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.src_id AND org_id = NEW.org_id)
  OR NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.dst_id AND org_id = NEW.org_id)
BEGIN
    SELECT RAISE(ABORT, 'graph edge endpoints must exist in the edge organization');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_org_endpoints_update
BEFORE UPDATE ON graph_edges
WHEN NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.src_id AND org_id = NEW.org_id)
  OR NOT EXISTS (SELECT 1 FROM graph_nodes WHERE id = NEW.dst_id AND org_id = NEW.org_id)
BEGIN
    SELECT RAISE(ABORT, 'graph edge endpoints must exist in the edge organization');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_provenance_immutable
BEFORE UPDATE OF id, src_id, dst_id, kind, assertion_scope,
                 asserted_by, asserted_by_kind, asserted_at,
                 source_kind, source_ref, valid_from ON graph_edges
BEGIN
    SELECT RAISE(ABORT, 'graph edge endpoints and provenance are immutable');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_valid_to_once
BEFORE UPDATE OF valid_to ON graph_edges
WHEN OLD.valid_to IS NOT NULL AND NEW.valid_to IS NOT OLD.valid_to
BEGIN
    SELECT RAISE(ABORT, 'a closed graph edge cannot be reopened; assert a new edge');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_state_no_revert
BEFORE UPDATE OF state ON graph_edges
WHEN OLD.state = 'active' AND NEW.state != 'active'
BEGIN
    SELECT RAISE(ABORT, 'an active graph edge cannot revert to proposed');
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_no_delete
BEFORE DELETE ON graph_edges
BEGIN
    SELECT RAISE(ABORT, 'graph edges are closed with valid_to, never deleted');
END;
",
};

/// `organization.v1.graph`: generated `*_org_exists` and `*_org_immutable`
/// triggers for `graph_nodes` and `graph_edges`.
pub const TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.graph", &["graph_nodes", "graph_edges"]);

/// `graph.v2.counters`: trigger-maintained per-organization node and edge
/// counters (`graph_org_counts`) so quota checks run in O(1) inside the write
/// transaction without scanning `graph_nodes` / `graph_edges`.
pub const COUNTERS_SCHEMA: SchemaPart = SchemaPart {
    name: "graph.v2.counters",
    sql: "
CREATE TABLE IF NOT EXISTS graph_org_counts (
    org_id     TEXT PRIMARY KEY NOT NULL,
    node_count INTEGER NOT NULL DEFAULT 0 CHECK (node_count >= 0),
    edge_count INTEGER NOT NULL DEFAULT 0 CHECK (edge_count >= 0)
);

INSERT INTO graph_org_counts (org_id, node_count, edge_count)
SELECT o.org_id,
       COALESCE(n.cnt, 0),
       COALESCE(e.cnt, 0)
FROM (
    SELECT org_id FROM graph_nodes
    UNION
    SELECT org_id FROM graph_edges
) o
LEFT JOIN (SELECT org_id, COUNT(*) AS cnt FROM graph_nodes GROUP BY org_id) n ON n.org_id = o.org_id
LEFT JOIN (SELECT org_id, COUNT(*) AS cnt FROM graph_edges GROUP BY org_id) e ON e.org_id = o.org_id
ON CONFLICT(org_id) DO UPDATE SET
    node_count = excluded.node_count,
    edge_count = excluded.edge_count;

CREATE TRIGGER IF NOT EXISTS graph_nodes_count_ai
AFTER INSERT ON graph_nodes
BEGIN
    INSERT INTO graph_org_counts (org_id, node_count, edge_count)
    VALUES (NEW.org_id, 1, 0)
    ON CONFLICT(org_id) DO UPDATE SET node_count = node_count + 1;
END;

CREATE TRIGGER IF NOT EXISTS graph_edges_count_ai
AFTER INSERT ON graph_edges
BEGIN
    INSERT INTO graph_org_counts (org_id, node_count, edge_count)
    VALUES (NEW.org_id, 0, 1)
    ON CONFLICT(org_id) DO UPDATE SET edge_count = edge_count + 1;
END;
",
};

/// `organization.v1.graph_counters`: generated `*_org_exists` and
/// `*_org_immutable` triggers for `graph_org_counts`.
pub const COUNTERS_TENANT_PART: Procedure =
    ua_store::org::tenant_part("organization.v1.graph_counters", &["graph_org_counts"]);

/// `graph.v3.counters_no_delete`: additive immutability guard preventing
/// `DELETE` on `graph_org_counts` (nodes and edges are never deleted, so
/// deleting a counter row would reset quota accounting).
pub const COUNTERS_NO_DELETE_SCHEMA: SchemaPart = SchemaPart {
    name: "graph.v3.counters_no_delete",
    sql: "
CREATE TRIGGER IF NOT EXISTS graph_org_counts_no_delete
BEFORE DELETE ON graph_org_counts
BEGIN
    SELECT RAISE(ABORT, 'graph organization counters cannot be deleted');
END;
",
};

/// Schema parts for the shared graph store, in application order. Requires
/// `organization.v1.store` applied first.
pub fn schema_parts() -> Vec<Part> {
    vec![
        SCHEMA.into(),
        TENANT_PART.into(),
        COUNTERS_SCHEMA.into(),
        COUNTERS_TENANT_PART.into(),
        COUNTERS_NO_DELETE_SCHEMA.into(),
    ]
}
