//! Managed secrets: a write-only store for credentials the hub hands to a
//! consumer (today, a downstream MCP server) without any agent seeing them.
//!
//! Tools: `managed_secret_set` (a human or operator stores a value; replacing
//! an existing value needs a one-time human approval bound to the new
//! fingerprint), `managed_secret_list` (metadata only) and
//! `managed_secret_delete` (always needs a one-time human approval).
//!
//! Who is an admin is decided by identity, never by profile: a verified human,
//! or an authenticated agent listed in `human_identities` or
//! `lifecycle_operators`. Any agent can activate the `operator` profile (the
//! profile check is by rank only), so that profile grants nothing here.
//!
//! A secret for a downstream MCP server is bound to the server's name
//! (`mcp:<server>`). Revoking the server orphans it: every secret bound to
//! that consumer is deleted under the revocation's approval, which lists them.
//! A name registered again (possibly at another endpoint) never inherits a
//! credential confirmed for the old registration; the operator sets it again.
//!
//! What holds the boundary:
//!
//! * **No read path.** No tool returns a value. Only [`load_for_consumer`],
//!   called in-process by the consumer it is bound to, decrypts one.
//! * **Encrypted at rest.** AES-256-GCM with a random 96-bit nonce per write
//!   and the name and consumer as associated data, so a row copied under
//!   another name or consumer does not decrypt. The key comes from config
//!   (`managed_secret_key` / `UA_MANAGED_SECRET_KEY`), never the database.
//!   With no key, writes are refused; there is no plaintext mode.
//! * **Consumer scope.** Every secret names the one consumer that may load it
//!   (`mcp:<server>` for a downstream MCP server). There is no default.
//! * **Fingerprint, not digest.** Metadata carries an HMAC-SHA256 of the value
//!   under a key derived from the encryption key, so a reader of the metadata
//!   or the approval queue cannot confirm a guessed value offline.
//! * **Ledger names only.** Events carry the name and consumer, never the
//!   value or its fingerprint. `tool_calls` rows never hold arguments, and an
//!   approval for `managed_secret_set` (when an operator lists it in
//!   `approval_tools`) binds the fingerprint, not the value.
//!
//! Key rotation: list the new key first and the old one after it. Existing
//! rows keep decrypting; `managed_secret_list` shows `key_current: false` for
//! rows sealed with an older key, and setting the value again re-seals it.

use aes_gcm::aead::{Aead, KeyInit as AeadKeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use hmac::{Hmac, KeyInit as MacKeyInit, Mac};
use rand::TryRngCore;
use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::{ActorKind, Caller, Config, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use crate::approvals::{self, GateOutcome};
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "managed_secrets.v1",
    sql: "
CREATE TABLE IF NOT EXISTS managed_secrets (
    name TEXT PRIMARY KEY,
    consumer TEXT NOT NULL,
    key_id TEXT NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    fingerprint TEXT NOT NULL,
    value_bytes INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_managed_secrets_consumer ON managed_secrets(consumer);
",
};

/// Largest value accepted, in bytes.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
const NAME_MAX: usize = 128;
const AAD_PREFIX: &str = "ua-managed-secret/v1";

// --- names ------------------------------------------------------------------------

/// `[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}`.
pub fn check_name(name: &str) -> UaResult<()> {
    let mut chars = name.chars();
    let ok = name.len() <= NAME_MAX
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-'));
    if ok {
        Ok(())
    } else {
        Err(UaError::invalid("secret name must match [A-Za-z0-9][A-Za-z0-9:_.-]{0,127}"))
    }
}

/// A consumer is `kind` or `kind:target`: `kind` is `[a-z][a-z0-9_-]{0,31}`,
/// `target` is `[a-z0-9][a-z0-9_-]{0,63}`. An MCP server's is `mcp:<server>`.
pub fn check_consumer(consumer: &str) -> UaResult<()> {
    let part = |s: &str, max: usize, first_alpha: bool| {
        let mut chars = s.chars();
        s.len() <= max
            && chars.next().is_some_and(|c| c.is_ascii_lowercase() || (!first_alpha && c.is_ascii_digit()))
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
    };
    let ok = match consumer.split_once(':') {
        None => part(consumer, 32, true),
        Some((kind, target)) => part(kind, 32, true) && part(target, 64, false),
    };
    if ok {
        Ok(())
    } else {
        Err(UaError::invalid(
            "consumer must be `kind` or `kind:target` (lowercase), e.g. `mcp:docs` for MCP server docs",
        ))
    }
}

/// The consumer a downstream MCP server's secrets must be bound to.
pub fn mcp_consumer(server: &str) -> String {
    format!("mcp:{server}")
}

// --- keys -----------------------------------------------------------------------

struct Key {
    id: String,
    bytes: [u8; 32],
}

/// The configured keys, the write key first. `None` when no key is set.
fn keyring(cfg: &Config) -> UaResult<Option<Vec<Key>>> {
    let Some(raw) = cfg.managed_secret_key.as_ref() else { return Ok(None) };
    let mut keys = Vec::new();
    for item in raw.expose_secret().split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let bytes = decode_key(item).ok_or_else(|| {
            UaError::internal(
                "managed_secret_key must be 32 bytes as base64 or 64 hex characters (comma-separated to rotate)",
            )
        })?;
        let mut h = Sha256::new();
        h.update(b"ua-managed-secret-key-id:");
        h.update(bytes);
        keys.push(Key { id: hex::encode(h.finalize())[..16].to_string(), bytes });
    }
    Ok((!keys.is_empty()).then_some(keys))
}

fn decode_key(s: &str) -> Option<[u8; 32]> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let bytes = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(s).ok()?
    } else {
        [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD].iter().find_map(|e| e.decode(s).ok())?
    };
    bytes.try_into().ok()
}

fn write_key(cfg: &Config) -> UaResult<Key> {
    keyring(cfg)?.and_then(|mut k| (!k.is_empty()).then(|| k.swap_remove(0))).ok_or_else(|| {
        UaError::denied(
            "secret_key_unset",
            "managed_secret_key (UA_MANAGED_SECRET_KEY) is not set; the hub never stores a secret unencrypted",
        )
    })
}

/// HMAC-SHA256 of `value` under a key derived from `key`, first 128 bits as hex.
fn fingerprint(key: &Key, value: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"ua-managed-secret-fingerprint:");
    h.update(key.bytes);
    let fp_key = h.finalize();
    let mut mac = <Hmac<Sha256> as MacKeyInit>::new_from_slice(&fp_key).expect("HMAC takes any key length");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())[..32].to_string()
}

/// A keyed fingerprint of `value` under the configured `managed_secret_key`,
/// for an approval to bind a secret argument without storing it. `None`
/// when no key is configured: the approval then cannot tell two values
/// apart.
pub(crate) fn config_fingerprint(cfg: &Config, value: &str) -> Option<String> {
    write_key(cfg).ok().map(|k| fingerprint(&k, value))
}

fn aad(name: &str, consumer: &str) -> Vec<u8> {
    format!("{AAD_PREFIX}\0{name}\0{consumer}").into_bytes()
}

fn seal(key: &Key, name: &str, consumer: &str, value: &str) -> UaResult<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| UaError::internal("the operating system random source failed"))?;
    let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&key.bytes)
        .map_err(|_| UaError::internal("invalid secret key length"))?;
    let aad = aad(name, consumer);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: value.as_bytes(), aad: &aad })
        .map_err(|_| UaError::internal("managed secret encryption failed"))?;
    Ok((nonce.to_vec(), ct))
}

fn unseal(key: &Key, name: &str, consumer: &str, nonce: &[u8], ct: &[u8]) -> UaResult<SecretString> {
    if nonce.len() != 12 {
        return Err(UaError::internal(format!("managed secret {name:?} is corrupt")));
    }
    let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&key.bytes)
        .map_err(|_| UaError::internal("invalid secret key length"))?;
    let aad = aad(name, consumer);
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| UaError::internal(format!("managed secret {name:?} did not decrypt with its key")))?;
    let text = String::from_utf8(plain)
        .map_err(|_| UaError::internal(format!("managed secret {name:?} is corrupt")))?;
    Ok(SecretString::from(text))
}

// --- the consumer path -------------------------------------------------------------

/// Decrypt one secret for its bound consumer, with its stored keyed
/// fingerprint (what an approval binds). In-process only: no tool returns the
/// value. Refuses a secret bound to any other consumer.
pub(crate) fn load_for_consumer(
    conn: &Connection,
    cfg: &Config,
    name: &str,
    consumer: &str,
) -> UaResult<(SecretString, String)> {
    type Sealed = (String, String, Vec<u8>, Vec<u8>, String);
    let row: Option<Sealed> = conn
        .query_row(
            "SELECT consumer, key_id, nonce, ciphertext, fingerprint FROM managed_secrets WHERE name = ?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((bound, key_id, nonce, ct, fp)) = row else {
        return Err(UaError::not_found(format!("managed secret {name:?} is not set")));
    };
    if bound != consumer {
        return Err(UaError::denied(
            "secret_consumer_mismatch",
            format!("managed secret {name:?} is bound to another consumer, not {consumer:?}"),
        ));
    }
    let keys = keyring(cfg)?.ok_or_else(|| {
        UaError::denied(
            "secret_key_unset",
            "managed_secret_key is not set; stored secrets cannot be decrypted",
        )
    })?;
    let key = keys.iter().find(|k| k.id == key_id).ok_or_else(|| {
        UaError::denied(
            "secret_key_missing",
            format!("managed secret {name:?} was sealed with a key that is no longer configured"),
        )
    })?;
    Ok((unseal(key, name, consumer, &nonce, &ct)?, fp))
}

/// Whether `name` is stored and bound to `consumer` (no decryption).
pub(crate) fn bound_to(conn: &Connection, name: &str, consumer: &str) -> UaResult<bool> {
    let bound: Option<String> = conn
        .query_row("SELECT consumer FROM managed_secrets WHERE name = ?1", [name], |r| r.get(0))
        .optional()?;
    Ok(bound.as_deref() == Some(consumer))
}

/// Name and keyed fingerprint of every secret bound to `consumer`, by name.
pub(crate) fn bound_secrets(conn: &Connection, consumer: &str) -> UaResult<Vec<(String, String)>> {
    let mut stmt =
        conn.prepare("SELECT name, fingerprint FROM managed_secrets WHERE consumer = ?1 ORDER BY name")?;
    let rows = stmt.query_map([consumer], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Delete every secret bound to `consumer` (the caller holds the approval
/// that listed them), one `managed_secret.deleted` event each. Returns the names.
pub(crate) fn orphan_consumer(
    tx: &mut ua_store::WriteTx<'_>,
    consumer: &str,
    by: &str,
    approval_id: i64,
    why: &str,
) -> UaResult<Vec<String>> {
    let names: Vec<String> = bound_secrets(tx, consumer)?.into_iter().map(|(n, _)| n).collect();
    tx.execute("DELETE FROM managed_secrets WHERE consumer = ?1", [consumer])?;
    for name in &names {
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "managed_secret.deleted",
                json!({ "name": name, "consumer": consumer, "approval_id": approval_id, "reason": why }),
            )
            .by(by.to_string()),
        )?;
    }
    Ok(names)
}

// --- who may write ------------------------------------------------------------------

/// A verified human, or an authenticated agent whose identity is a configured
/// human or lifecycle operator. Keyed on identity, never on profile: an agent
/// can activate the `operator` profile itself, so the profile proves nothing.
pub(crate) fn is_secret_admin(cfg: &Config, caller: &Caller) -> bool {
    match caller.kind {
        ActorKind::Human => true,
        ActorKind::Agent => cfg.is_human(&caller.label) || cfg.is_lifecycle_operator(&caller.label),
        ActorKind::System | ActorKind::Anonymous => false,
    }
}

fn require_admin(cfg: &Config, caller: &Caller, doing: &str) -> UaResult<()> {
    if caller.kind == ActorKind::Anonymous {
        return Err(UaError::denied(
            "identity_required",
            format!("{doing} requires an authenticated identity"),
        ));
    }
    if !is_secret_admin(cfg, caller) {
        return Err(UaError::denied("operator_only", format!("{doing} is for a human or an operator")));
    }
    Ok(())
}

// --- tools ---------------------------------------------------------------------------

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetArgs {
    /// Secret name, `[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}`.
    pub name: String,
    /// The one consumer that may load it, e.g. `mcp:docs` for MCP server `docs`.
    pub consumer: String,
    /// The value, 1-65536 bytes. Never returned by any tool.
    pub value: String,
}

impl std::fmt::Debug for SetArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetArgs").field("name", &self.name).field("consumer", &self.consumer).finish()
    }
}

/// What an approval of `managed_secret_set` binds: never the value.
fn set_payload(name: &str, consumer: &str, fp: Option<&str>, value_bytes: usize) -> Value {
    json!({ "name": name, "consumer": consumer, "fingerprint": fp, "value_bytes": value_bytes })
}

fn set_gate_payload(cfg: &Config, args: &Value) -> Value {
    let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let value = s("value");
    let fp = write_key(cfg).ok().map(|k| fingerprint(&k, &value));
    set_payload(&s("name"), &s("consumer"), fp.as_deref(), value.len())
}

async fn managed_secret_set(ctx: ToolCtx, a: SetArgs) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    require_admin(&cfg, &ctx.caller, "managed_secret_set")?;
    check_name(&a.name)?;
    check_consumer(&a.consumer)?;
    if a.value.is_empty() || a.value.len() > MAX_VALUE_BYTES {
        return Err(UaError::invalid(format!("value must be 1-{MAX_VALUE_BYTES} bytes")));
    }
    let key = write_key(&cfg)?;
    let fp = fingerprint(&key, &a.value);
    let (nonce, ct) = seal(&key, &a.name, &a.consumer, &a.value)?;
    let (who, value_bytes) = (ctx.caller.label.clone(), a.value.len() as i64);
    let gate_payload = set_payload(&a.name, &a.consumer, Some(&fp), a.value.len());
    drop(a.value);
    let (name, consumer, key_id) = (a.name, a.consumer, key.id);
    // With managed_secret_set in approval_tools the registry has already
    // consumed a pass for this exact payload.
    let registry_gated = cfg.approval_tools.iter().any(|t| t == "managed_secret_set");
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let prior: Option<String> = tx
                .query_row("SELECT consumer FROM managed_secrets WHERE name = ?1", [&name], |r| r.get(0))
                .optional()?;
            if let Some(prior) = &prior
                && prior != &consumer
            {
                return Err(UaError::conflict_code(
                    "secret_consumer_change",
                    format!(
                        "managed secret {name:?} is bound to {prior:?}; delete it before binding the name to another consumer"
                    ),
                ));
            }
            // Replacing a credential is as consequential as deleting it: a
            // one-time human approval bound to the new value's fingerprint.
            let mut approval_id = None;
            if prior.is_some() && !registry_gated {
                match approvals::gate(tx, hub.cfg(), &caller, "managed_secret_set", &gate_payload)? {
                    GateOutcome::Pass { approval_id: id } => approval_id = Some(id),
                    GateOutcome::Pending { approval_id } => return Ok(Err(approval_id)),
                    GateOutcome::Denied { approval_id, reason } => {
                        return Err(UaError::denied(
                            "approval_denied",
                            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                        ));
                    }
                }
            }
            let now = ua_core::time::now();
            tx.execute(
                "INSERT INTO managed_secrets (name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
                 created_by, created_at, updated_by, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?8, ?9) \
                 ON CONFLICT(name) DO UPDATE SET key_id = ?3, nonce = ?4, ciphertext = ?5, fingerprint = ?6, \
                 value_bytes = ?7, updated_by = ?8, updated_at = ?9",
                params![name, consumer, key_id, nonce, ct, fp, value_bytes, who, now],
            )?;
            let replaced = prior.is_some();
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG,
                    "managed_secret.set",
                    json!({ "name": name, "consumer": consumer, "replaced": replaced, "approval_id": approval_id }),
                )
                .by(who.clone()),
            )?;
            Ok(Ok(json!({
                "name": name, "consumer": consumer, "fingerprint": fp, "key_id": key_id,
                "value_bytes": value_bytes, "replaced": replaced, "updated_at": now, "stored": true,
                "approval_id": approval_id,
            })))
        })
        .await?;
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: "managed_secret_set".into(), approval_id })
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only secrets bound to this consumer.
    pub consumer: Option<String>,
}

async fn managed_secret_list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let current: Vec<String> = keyring(ctx.hub.cfg())
        .ok()
        .flatten()
        .map(|k| k.into_iter().map(|k| k.id).collect())
        .unwrap_or_default();
    let write_id = current.first().cloned();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT name, consumer, key_id, fingerprint, value_bytes, created_by, created_at, updated_by, \
                 updated_at FROM managed_secrets WHERE (?1 IS NULL OR consumer = ?1) ORDER BY name",
            )?;
            let rows = stmt
                .query_map([a.consumer], |r| {
                    let key_id: String = r.get(2)?;
                    Ok(json!({
                        "name": r.get::<_, String>(0)?,
                        "consumer": r.get::<_, String>(1)?,
                        "key_id": key_id,
                        "key_current": write_id.as_deref() == Some(key_id.as_str()),
                        "decryptable": current.contains(&key_id),
                        "fingerprint": r.get::<_, String>(3)?,
                        "value_bytes": r.get::<_, i64>(4)?,
                        "created_by": r.get::<_, String>(5)?,
                        "created_at": r.get::<_, String>(6)?,
                        "updated_by": r.get::<_, String>(7)?,
                        "updated_at": r.get::<_, String>(8)?,
                    }))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(json!({ "secrets": rows, "count": rows.len(), "key_configured": write_id.is_some() }))
        })
        .await
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteArgs {
    /// Secret name.
    pub name: String,
}

async fn managed_secret_delete(ctx: ToolCtx, a: DeleteArgs) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    require_admin(&cfg, &ctx.caller, "managed_secret_delete")?;
    check_name(&a.name)?;
    let (hub, caller, name) = (ctx.hub.clone(), ctx.caller.clone(), a.name);
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT consumer, fingerprint FROM managed_secrets WHERE name = ?1",
                    [&name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((consumer, fp)) = row else {
                return Err(UaError::not_found(format!("managed secret {name:?} is not set")));
            };
            // Bound to the exact value: a rotation after the request needs a new approval.
            let payload = json!({ "name": name, "consumer": consumer, "fingerprint": fp });
            let approval_id =
                match approvals::gate(tx, hub.cfg(), &caller, "managed_secret_delete", &payload)? {
                    GateOutcome::Pass { approval_id } => approval_id,
                    GateOutcome::Pending { approval_id } => return Ok(Err(approval_id)),
                    GateOutcome::Denied { approval_id, reason } => {
                        return Err(UaError::denied(
                            "approval_denied",
                            format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                        ));
                    }
                };
            tx.execute("DELETE FROM managed_secrets WHERE name = ?1", [&name])?;
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "managed_secret.deleted",
                    json!({ "name": name, "consumer": consumer, "approval_id": approval_id }),
                )
                .by(caller.label.clone()),
            )?;
            Ok(Ok(json!({ "name": name, "consumer": consumer, "deleted": true, "approval_id": approval_id })))
        })
        .await?;
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: "managed_secret_delete".into(), approval_id })
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "managed_secret_set",
            "Store a credential for one consumer (e.g. `mcp:docs`, the MCP server docs), encrypted at rest. \
             For a human or a configured operator identity. The value is never returned by any tool; the \
             result and managed_secret_list show only metadata and a keyed fingerprint. Replacing an existing \
             value needs a one-time human approval bound to the new value's fingerprint (the identical retry \
             after approval stores it). Refused when the hub has no managed_secret_key. Rebinding a name to \
             another consumer needs a delete first.",
            managed_secret_set,
        )
        .gate_payload(set_gate_payload)
        .secret_args()
        .handler_may_gate(crate::HandlerGate::Always)
        .family("secrets"),
    );
    r.add(
        tool(
            "managed_secret_list",
            "List managed secrets: name, consumer, keyed fingerprint, size, key id and who set them. Never values.",
            managed_secret_list,
        )
        .read_only()
        .family("secrets"),
    );
    r.add(
        tool(
            "managed_secret_delete",
            "Delete one managed secret. For a human or a configured operator identity, and always needs a one-time human approval \
             bound to the name, consumer and current fingerprint; the identical retry after approval deletes it.",
            managed_secret_delete,
        )
        .always_gated()
        .gates_in_handler()
        .family("secrets"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(key: &str) -> Config {
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.managed_secret_key = Some(SecretString::from(key.to_string()));
        cfg
    }

    const K1: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    #[test]
    fn keys_decode_from_hex_and_base64_and_reject_other_lengths() {
        assert!(decode_key(K1).is_some());
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(decode_key(&b64), Some([7u8; 32]));
        assert_eq!(decode_key(b64.trim_end_matches('=')), Some([7u8; 32]));
        assert!(decode_key("short").is_none());
        assert!(decode_key(&base64::engine::general_purpose::STANDARD.encode([1u8; 16])).is_none());
        assert!(keyring(&cfg_with("nope")).is_err());
        assert!(keyring(&Config::for_home(std::env::temp_dir())).unwrap().is_none());
    }

    #[test]
    fn seal_round_trips_and_binds_name_and_consumer() {
        let key = write_key(&cfg_with(K1)).unwrap();
        let (nonce, ct) = seal(&key, "tok", "mcp:docs", "s3cret").unwrap();
        assert!(!ct.windows(6).any(|w| w == b"s3cret"), "ciphertext must not hold the plaintext");
        assert_eq!(unseal(&key, "tok", "mcp:docs", &nonce, &ct).unwrap().expose_secret(), "s3cret");
        assert!(unseal(&key, "other", "mcp:docs", &nonce, &ct).is_err(), "renamed rows do not decrypt");
        assert!(unseal(&key, "tok", "mcp:evil", &nonce, &ct).is_err(), "rebound rows do not decrypt");
        let (n2, _) = seal(&key, "tok", "mcp:docs", "s3cret").unwrap();
        assert_ne!(nonce, n2, "every write takes a fresh nonce");
    }

    #[test]
    fn fingerprints_are_keyed() {
        let a = write_key(&cfg_with(K1)).unwrap();
        let b = write_key(&cfg_with(&base64::engine::general_purpose::STANDARD.encode([9u8; 32]))).unwrap();
        assert_eq!(fingerprint(&a, "v"), fingerprint(&a, "v"));
        assert_ne!(fingerprint(&a, "v"), fingerprint(&b, "v"));
        assert_ne!(fingerprint(&a, "v"), hex::encode(Sha256::digest(b"v"))[..32]);
    }

    #[test]
    fn names_and_consumers() {
        assert!(check_name("docs-token").is_ok());
        assert!(check_name("agent-token:builder-1").is_ok());
        assert!(check_name("../x").is_err());
        assert!(check_name("").is_err());
        assert!(check_consumer("mcp:docs").is_ok());
        assert!(check_consumer("zulip").is_ok());
        assert!(check_consumer("").is_err());
        assert!(check_consumer("MCP:docs").is_err());
        assert!(check_consumer("mcp:").is_err());
        assert!(check_consumer("mcp:a:b").is_err());
    }
}
