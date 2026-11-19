//! Tables several families share. Each family adds its own tables in its own
//! module; only rows referenced across families live here.

use ua_store::SchemaPart;

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "core.v1",
    sql: "
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','doing','waiting_review','blocked','done','cancelled')),
    priority TEXT NOT NULL DEFAULT 'med' CHECK (priority IN ('high','med','low')),
    parent_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT,
    archived_at TEXT,
    source_host TEXT,
    claimed_by TEXT,
    claimed_at TEXT,
    lock_expires_at TEXT,
    untrusted INTEGER NOT NULL DEFAULT 0,
    worktree_path TEXT,
    branch TEXT,
    project TEXT NOT NULL DEFAULT 'default',
    domain TEXT NOT NULL DEFAULT 'general',
    due_at TEXT,
    evidence_ref TEXT,
    lane TEXT NOT NULL DEFAULT 'default' CHECK (length(lane) >= 1 AND length(lane) <= 64),
    current_run_id TEXT,
    current_run_agent TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    next_owner TEXT,
    waiting_on TEXT,
    terminal_predicate TEXT,
    ownership_generation INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, priority);
CREATE INDEX IF NOT EXISTS idx_tasks_parent ON tasks(parent_id);
CREATE INDEX IF NOT EXISTS idx_tasks_claimed ON tasks(claimed_by);
CREATE INDEX IF NOT EXISTS idx_tasks_project ON tasks(project, status);

CREATE TABLE IF NOT EXISTS task_dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (task_id, depends_on_task_id),
    CHECK (task_id != depends_on_task_id)
);

CREATE TABLE IF NOT EXISTS agents (
    label TEXT PRIMARY KEY,
    kind TEXT NOT NULL DEFAULT 'unknown',
    host TEXT,
    known INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    last_seen_via TEXT,
    pid INTEGER,
    version TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('starting','running','waiting','completed','failed','abandoned')),
    started_at TEXT NOT NULL,
    last_heartbeat_at TEXT NOT NULL,
    ended_at TEXT,
    task_id INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    delegation_id INTEGER,
    worktree_path TEXT,
    branch TEXT,
    external_session_id TEXT,
    transcript_path TEXT,
    host TEXT,
    pid INTEGER,
    episode_id TEXT,
    exit_status TEXT,
    summary TEXT,
    model TEXT,
    meta TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent ON agent_sessions(agent, status);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    tool TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
",
};

/// Per-call telemetry written by the registry wrapper.
pub const SCHEMA_V2: SchemaPart = SchemaPart {
    name: "core.v2",
    sql: "
CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    caller TEXT NOT NULL,
    profile TEXT NOT NULL,
    transport TEXT NOT NULL,
    started_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_calls_tool ON tool_calls(tool, started_at);
CREATE INDEX IF NOT EXISTS idx_tool_calls_caller ON tool_calls(caller, started_at);
",
};
