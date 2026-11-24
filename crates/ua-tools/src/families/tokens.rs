//! Credentials: managed agent tokens, OAuth grants and browser sessions.
//!
//! This family owns the tables behind every hub credential except the static
//! `agent_tokens` list in configuration:
//!
//! - `oauth.v1`: the OAuth 2.1 authorization server (clients, pending consent
//!   requests, authorization codes, access and refresh tokens, and one
//!   `oauth_grants` row per approved sign-in, called a session below).
//! - `ui_auth.v1`: Control Center browser sessions, one-time login links,
//!   passkeys and in-flight WebAuthn ceremonies.
//!
//! Every token, code, session id and link is stored as a SHA-256 hex digest;
//! raw values exist only in the response that hands them out.
//!
//! Tools:
//! - `agent_token_issue` / `agent_token_rotate`: human-only. The caller
//!   supplies the token value; the hub stores its digest and returns
//!   metadata, never the value. `ua token issue` is the one path that mints
//!   and prints a value.
//! - `agent_token_list`: metadata rows.
//! - `oauth_device_manage`: list OAuth sessions, or revoke one session or
//!   every session of an identity (revoke needs a one-time human approval).

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use crate::approvals::{self, GateOutcome};
use crate::families::managed_secrets::config_fingerprint;
use crate::families::plans::ledger_text;
use crate::registry::{Registry, ToolCtx, tool};

pub const OAUTH_SCHEMA: SchemaPart = SchemaPart {
    name: "oauth.v1",
    sql: "
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT,
    redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types TEXT NOT NULL DEFAULT '[\"authorization_code\",\"refresh_token\"]',
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none',
    secret_hash TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_requests (
    id_hash TEXT PRIMARY KEY,
    session_hash TEXT NOT NULL,
    client_id TEXT NOT NULL,
    params TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS oauth_grants (
    family_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    client_name TEXT,
    subject TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    grant_type TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_oauth_grants_subject ON oauth_grants(subject);
CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('access','refresh')),
    family_id TEXT NOT NULL REFERENCES oauth_grants(family_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','rotated','revoked')),
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_oauth_tokens_family ON oauth_tokens(family_id, kind, status);
",
};

pub const UI_AUTH_SCHEMA: SchemaPart = SchemaPart {
    name: "ui_auth.v1",
    sql: "
CREATE TABLE IF NOT EXISTS ui_sessions (
    id_hash TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    csrf TEXT NOT NULL,
    method TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT,
    user_agent TEXT,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_ui_sessions_label ON ui_sessions(label);
CREATE TABLE IF NOT EXISTS login_links (
    token_hash TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS passkeys (
    cred_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    name TEXT,
    passkey TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkeys_label ON passkeys(label);
CREATE TABLE IF NOT EXISTS webauthn_states (
    id_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('register','login')),
    label TEXT NOT NULL,
    session_hash TEXT,
    state TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ui_keys (
    name TEXT PRIMARY KEY,
    key_hex TEXT NOT NULL,
    created_at TEXT NOT NULL
);
",
};

pub fn schema_parts() -> Vec<SchemaPart> {
    vec![OAUTH_SCHEMA, UI_AUTH_SCHEMA]
}

/// SHA-256 hex digest: how every credential in this family is stored.
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// The identity a presented managed token resolves to: its agent label and
/// organization (`agent_tokens.org_id`), when the token is active and
/// unexpired. A token whose organization disagrees with its agent's
/// (`agents.org_id`) is refused (`None`): an agent belongs to exactly one
/// organization, and a token never authenticates it into another.
pub fn resolve_managed_token(
    c: &rusqlite::Connection,
    presented: &str,
) -> UaResult<Option<(String, String)>> {
    let row: Option<(String, String)> = c
        .query_row(
            "SELECT agent_label, org_id FROM agent_tokens WHERE token_hash = ?1 AND status = 'active' \
             AND (expires_at IS NULL OR expires_at > ?2)",
            params![digest(presented), ua_core::time::now()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((label, org)) = row else { return Ok(None) };
    if crate::families::agents::label_org(c, &label)?.is_some_and(|held| held != org) {
        tracing::warn!("a managed token's organization disagrees with its agent's; the token is refused");
        return Ok(None);
    }
    Ok(Some((label, org)))
}

/// Whether `label`, presented by a credential that always resolves to the
/// default organization (a static configuration token, an OAuth grant), is
/// held by another organization's agent: such a credential is refused, so
/// the hub's configuration never authenticates into another organization.
pub fn held_outside_default(c: &rusqlite::Connection, label: &str) -> UaResult<bool> {
    crate::families::agents::foreign_label(c, ua_core::DEFAULT_ORG, label)
}

/// Minimum length of a caller-supplied agent token.
const MIN_TOKEN_LEN: usize = 32;
const STATUSES: &[&str] = &["active", "rotated", "revoked", "expired"];

fn require_human(ctx: &ToolCtx, tool: &str) -> UaResult<()> {
    if ctx.caller.is_human() {
        Ok(())
    } else {
        Err(UaError::denied("human_only", format!("{tool} may only be called by a verified human")))
    }
}

fn check_value(value: &str) -> UaResult<()> {
    if value.len() < MIN_TOKEN_LEN {
        return Err(UaError::invalid(format!("token value must be at least {MIN_TOKEN_LEN} characters")));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(UaError::invalid("token value may not contain whitespace"));
    }
    // OAuth tokens and session credentials are recognized by prefix; a
    // managed token must not look like one.
    if value.starts_with("uao_") || value.starts_with("uar_") || value.starts_with("uas_") {
        return Err(UaError::invalid("token value may not start with an OAuth or session credential prefix"));
    }
    Ok(())
}

fn expires_at(ttl_days: Option<u32>) -> UaResult<Option<String>> {
    match ttl_days {
        None => Ok(None),
        Some(0) => Err(UaError::invalid("ttl_days must be positive")),
        Some(d) => {
            let ts = jiff::Timestamp::now()
                .checked_add(jiff::SignedDuration::from_hours(i64::from(d) * 24))
                .map_err(|e| UaError::invalid(e.to_string()))?;
            Ok(Some(ua_core::time::format_ts(ts)))
        }
    }
}

fn token_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "token_id": r.get::<_, i64>("id")?,
        "agent_label": r.get::<_, String>("agent_label")?,
        "token_hash": r.get::<_, String>("token_hash")?,
        "status": r.get::<_, String>("status")?,
        "issued_at": r.get::<_, String>("issued_at")?,
        "expires_at": r.get::<_, Option<String>>("expires_at")?,
        "rotated_from": r.get::<_, Option<i64>>("rotated_from")?,
        "rotated_at": r.get::<_, Option<String>>("rotated_at")?,
        "revoked_at": r.get::<_, Option<String>>("revoked_at")?,
        "issued_by": r.get::<_, Option<String>>("issued_by")?,
        "note": r.get::<_, Option<String>>("note")?,
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssueArgs {
    /// Identity the token authenticates as.
    pub agent_label: String,
    /// The token value (at least 32 characters). Only its SHA-256 digest is
    /// stored; it is never returned.
    pub value: String,
    /// Days until the token expires. Omit for no expiry.
    pub ttl_days: Option<u32>,
    /// Free-text note shown in listings.
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RotateArgs {
    /// Identity whose newest active token is replaced.
    pub agent_label: String,
    /// The new token value (at least 32 characters). Only its digest is stored.
    pub new_value: String,
    /// Days until the new token expires. Omit for no expiry.
    pub ttl_days: Option<u32>,
    /// Free-text note shown in listings.
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only tokens of this identity.
    pub agent_label: Option<String>,
    /// Only tokens with this status: active, rotated, revoked or expired.
    pub status: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceArgs {
    /// `list` (read-only) or `revoke` (needs a one-time human approval).
    #[serde(default = "default_action")]
    pub action: String,
    /// Revoke: the session id from `list`.
    pub session_id: Option<String>,
    /// Revoke: every live session of this identity.
    pub identity: Option<String>,
}

/// What an approval of `agent_token_issue` / `agent_token_rotate` binds:
/// every argument except the token value, which is replaced by a keyed
/// fingerprint (see [`config_fingerprint`]) and its length. The value itself
/// never reaches the approvals table.
fn token_gate_payload(value_field: &'static str) -> impl Fn(&ua_core::Config, &Value) -> Value {
    move |cfg, args| {
        let value = args.get(value_field).and_then(Value::as_str).unwrap_or("");
        let mut out = args.as_object().cloned().unwrap_or_default();
        out.remove(value_field);
        out.insert("value_fingerprint".into(), json!(config_fingerprint(cfg, value)));
        out.insert("value_bytes".into(), json!(value.len()));
        Value::Object(out)
    }
}

fn issue_gate_payload(cfg: &ua_core::Config, args: &Value) -> Value {
    token_gate_payload("value")(cfg, args)
}

fn rotate_gate_payload(cfg: &ua_core::Config, args: &Value) -> Value {
    token_gate_payload("new_value")(cfg, args)
}

fn default_action() -> String {
    "list".into()
}

/// Insert a managed token for `label`, an agent of organization `org`. A
/// label another organization's agent holds is refused (the token would
/// authenticate into the wrong organization), before anything is written.
#[allow(clippy::too_many_arguments)]
fn insert_token(
    tx: &rusqlite::Transaction<'_>,
    org: &str,
    label: &str,
    hash: &str,
    expires: Option<&str>,
    by: &str,
    note: Option<&str>,
    rotated_from: Option<i64>,
) -> UaResult<(i64, String)> {
    crate::families::agents::require_org(tx, org)?;
    crate::families::agents::require_label_free(tx, org, label)?;
    let now = ua_core::time::now();
    let dup: bool = tx
        .query_row("SELECT 1 FROM agent_tokens WHERE token_hash = ?1", [hash], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    if dup {
        return Err(UaError::conflict("that token value is already registered; choose a new one"));
    }
    tx.execute(
        "INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at, expires_at, rotated_from, \
         issued_by, note) VALUES (?8, ?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![label, hash, now, expires, rotated_from, by, note, org],
    )?;
    Ok((tx.last_insert_rowid(), now))
}

async fn issue(ctx: ToolCtx, a: IssueArgs) -> UaResult<Value> {
    require_human(&ctx, "agent_token_issue")?;
    let label = a.agent_label.trim().to_string();
    if label.is_empty() {
        return Err(UaError::invalid("agent_label must not be empty"));
    }
    check_value(&a.value)?;
    let hash = digest(&a.value);
    let expires = expires_at(a.ttl_days)?;
    let by = ctx.caller.label.clone();
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let (id, issued_at) =
                insert_token(tx, &org, &label, &hash, expires.as_deref(), &by, a.note.as_deref(), None)?;
            crate::families::agents::emit(
                tx,
                &org,
                "agent.token.issued",
                json!({ "agent": ledger_text(&org, &label), "token_id": id }),
                &by,
                None,
            )?;
            Ok(json!({
                "ok": true,
                "token_id": id,
                "agent_label": label,
                "token_hash": hash,
                "issued_at": issued_at,
                "expires_at": expires,
            }))
        })
        .await
}

async fn rotate(ctx: ToolCtx, a: RotateArgs) -> UaResult<Value> {
    require_human(&ctx, "agent_token_rotate")?;
    let label = a.agent_label.trim().to_string();
    if label.is_empty() {
        return Err(UaError::invalid("agent_label must not be empty"));
    }
    check_value(&a.new_value)?;
    let hash = digest(&a.new_value);
    let expires = expires_at(a.ttl_days)?;
    let by = ctx.caller.label.clone();
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            let previous: Option<i64> = tx
                .query_row(
                    "SELECT id FROM agent_tokens WHERE org_id = ?2 AND agent_label = ?1 AND status = 'active' \
                     ORDER BY issued_at DESC, id DESC LIMIT 1",
                    [&label, &org],
                    |r| r.get(0),
                )
                .optional()?;
            let (id, issued_at) =
                insert_token(tx, &org, &label, &hash, expires.as_deref(), &by, a.note.as_deref(), previous)?;
            if let Some(prev) = previous {
                tx.execute(
                    "UPDATE agent_tokens SET status = 'rotated', rotated_at = ?2 WHERE id = ?1 AND org_id = ?3",
                    params![prev, issued_at, org],
                )?;
            }
            crate::families::agents::emit(
                tx,
                &org,
                "agent.token.rotated",
                json!({ "agent": ledger_text(&org, &label), "previous_token_id": previous, "new_token_id": id }),
                &by,
                None,
            )?;
            Ok(json!({
                "ok": true,
                "agent_label": label,
                "previous_token_id": previous,
                "new_token_id": id,
                "new_token_hash": hash,
                "issued_at": issued_at,
                "expires_at": expires,
                "rotated_at": previous.map(|_| issued_at.clone()),
            }))
        })
        .await
}

async fn list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    if let Some(s) = &a.status
        && !STATUSES.contains(&s.as_str())
    {
        return Err(UaError::invalid(format!("status must be one of {}", STATUSES.join(", "))));
    }
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT * FROM agent_tokens WHERE org_id = ?3 AND (?1 IS NULL OR agent_label = ?1) \
                 AND (?2 IS NULL OR status = ?2) ORDER BY issued_at DESC, id DESC",
            )?;
            let rows: Vec<Value> = stmt
                .query_map(params![a.agent_label, a.status, org], token_row)?
                .collect::<Result<_, _>>()?;
            Ok(json!({ "count": rows.len(), "tokens": rows }))
        })
        .await
}

/// Live OAuth sessions (grants with an unexpired, unrevoked token).
pub fn list_oauth_sessions(c: &rusqlite::Connection) -> UaResult<Vec<Value>> {
    let now = ua_core::time::now();
    let mut stmt = c.prepare(
        "SELECT g.family_id, g.client_id, g.client_name, g.subject, g.approved_by, g.grant_type, g.scope, \
                g.resource, g.created_at, MAX(t.expires_at) AS live_until \
         FROM oauth_grants g JOIN oauth_tokens t ON t.family_id = g.family_id \
         WHERE g.revoked_at IS NULL AND t.status = 'active' AND t.expires_at > ?1 \
         GROUP BY g.family_id ORDER BY g.created_at DESC",
    )?;
    let rows = stmt
        .query_map([&now], |r| {
            Ok(json!({
                "session_id": r.get::<_, String>(0)?,
                "client_id": r.get::<_, String>(1)?,
                "client_name": r.get::<_, Option<String>>(2)?,
                "identity": r.get::<_, String>(3)?,
                "approved_by": r.get::<_, String>(4)?,
                "grant_type": r.get::<_, String>(5)?,
                "scope": r.get::<_, String>(6)?,
                "resource": r.get::<_, String>(7)?,
                "created_at": r.get::<_, String>(8)?,
                "live_until": r.get::<_, String>(9)?,
            }))
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Revoke one grant family: the grant row and every token in it.
/// Returns the number of tokens revoked.
pub fn revoke_family(tx: &rusqlite::Transaction<'_>, family_id: &str, reason: &str) -> UaResult<usize> {
    let now = ua_core::time::now();
    tx.execute(
        "UPDATE oauth_grants SET revoked_at = ?2, revoked_reason = ?3 WHERE family_id = ?1 AND revoked_at IS NULL",
        params![family_id, now, reason],
    )?;
    let n = tx.execute(
        "UPDATE oauth_tokens SET status = 'revoked', revoked_at = ?2 WHERE family_id = ?1 AND status != 'revoked'",
        params![family_id, now],
    )?;
    Ok(n)
}

async fn device_manage(ctx: ToolCtx, a: DeviceArgs) -> UaResult<Value> {
    match crate::routes::action_of("oauth_device_manage", Some(&a.action))? {
        "list" => {
            let sessions = ctx.hub.db().read_async(list_oauth_sessions).await?;
            Ok(json!({
                "oauth_enabled": ctx.hub.cfg().oauth_enabled,
                "session_count": sessions.len(),
                "sessions": sessions,
            }))
        }
        "revoke" => {
            let session_id = a.session_id.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            let identity = a.identity.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
            if session_id.is_some() == identity.is_some() {
                return Err(UaError::invalid("revoke needs exactly one of session_id or identity"));
            }
            let payload = json!({ "action": "revoke", "session_id": session_id, "identity": identity });
            let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
            let outcome = ctx
                .hub
                .db()
                .write_async(move |tx| {
                    approvals::gate(tx, hub.cfg(), &caller, "oauth_device_manage", &payload)
                })
                .await?;
            match outcome {
                GateOutcome::Pass { .. } => {}
                GateOutcome::Pending { approval_id } => {
                    return Err(UaError::ApprovalRequired {
                        tool: "oauth_device_manage".into(),
                        approval_id,
                    });
                }
                GateOutcome::Denied { approval_id, reason } => {
                    return Err(UaError::denied(
                        "approval_denied",
                        format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                    ));
                }
            }
            let actor = ctx.caller.label.clone();
            ctx.hub
                .db()
                .write_async(move |tx| {
                    let families: Vec<String> = {
                        let mut stmt = tx.prepare(
                            "SELECT family_id FROM oauth_grants WHERE revoked_at IS NULL \
                             AND ((?1 IS NOT NULL AND family_id = ?1) OR (?2 IS NOT NULL AND subject = ?2))",
                        )?;
                        stmt.query_map(params![session_id, identity], |r| r.get(0))?.collect::<Result<_, _>>()?
                    };
                    let mut tokens = 0;
                    for f in &families {
                        tokens += revoke_family(tx, f, "operator_revoke")?;
                    }
                    ledger::append(
                        tx,
                        EventInput::new(ua_core::DEFAULT_ORG,
                            "agent.oauth.sessions_revoked",
                            json!({ "session_id": session_id, "identity": identity, "sessions": families.len() }),
                        )
                        .by(actor.clone()),
                    )?;
                    Ok(json!({
                        "ok": true,
                        "revoked_sessions": families.len(),
                        "revoked_tokens": tokens,
                        "session_ids": families,
                    }))
                })
                .await
        }
        other => Err(crate::routes::unhandled("oauth_device_manage", other)),
    }
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "agent_token_issue",
            "Register a bearer token for an agent identity. Human only. The caller supplies the value; the hub \
             stores its SHA-256 digest and returns metadata, never the value. It authenticates from the next request.",
            |ctx: ToolCtx, a: IssueArgs| issue(ctx, a),
        )
        .gate_payload(issue_gate_payload)
        .secret_args()
        .family("tokens"),
    );
    r.add(
        tool(
            "agent_token_rotate",
            "Replace an identity's newest active token with a new value. Human only. The old token stops \
             authenticating at once; the new row links to it. Returns metadata, never the value.",
            |ctx: ToolCtx, a: RotateArgs| rotate(ctx, a),
        )
        .gate_payload(rotate_gate_payload)
        .secret_args()
        .family("tokens"),
    );
    r.add(
        tool(
            "agent_token_list",
            "List managed agent-token metadata (digests, status, dates). Never returns token values.",
            |ctx: ToolCtx, a: ListArgs| list(ctx, a),
        )
        .family("tokens")
        .read_only(),
    );
    r.add(
        tool(
            "oauth_device_manage",
            "List signed-in OAuth sessions (remote MCP clients), or revoke one session (`session_id`) or every \
             session of an identity. Revoke needs a one-time human approval: the first call returns an approval id.",
            |ctx: ToolCtx, a: DeviceArgs| device_manage(ctx, a),
        )
        .handler_may_gate(crate::HandlerGate::Actions(&["revoke"]))
        .family("tokens"),
    );
}
