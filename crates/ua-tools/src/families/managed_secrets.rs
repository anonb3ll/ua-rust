//! Managed secrets: a write-only store for credentials the hub hands to a
//! consumer (a downstream MCP server, the relay, an organization's GitHub
//! automation) without any agent seeing them.
//!
//! Tools: `managed_secret_set` (a human or operator stores a value; replacing
//! an existing value needs a one-time human approval bound to the new
//! fingerprint), `managed_secret_list` (metadata only) and
//! `managed_secret_delete` (always needs a one-time human approval).
//!
//! Who is an admin is decided by identity, never by profile: a verified human
//! of the secret's organization ([`Authority::Operator`] in the caller's
//! organization). Any agent can activate the `operator` profile (the profile
//! check is by rank only), so that profile grants nothing here.
//!
//! **Organizations.** A secret belongs to one organization: the table is
//! keyed by `(org_id, name)` (`managed_secrets.v2.tenant_keys`), every
//! statement filters `org_id`, and the tools act in the caller's
//! organization only. Another organization's secret of the same name answers
//! exactly as a missing one. The hub-scoped consumers (downstream MCP
//! servers, the relay) keep their secrets in the default organization, which
//! operates the hub. Until memberships exist only the default organization's
//! humans hold [`Authority::Operator`], so another organization's secrets
//! cannot be set or deleted by any caller (fail closed).
//!
//! **Reserved for GitHub.** The names `github:token` and
//! `github:webhook-secret` and consumers of kind `github` belong to the
//! per-organization GitHub credentials
//! ([`crate::families::github::credentials`]). `managed_secret_set` refuses
//! them (`reserved_secret`), and so does `managed_secret_delete` outside the
//! default organization, so those rows have one write path with its own
//! rules. The default organization's GitHub credential is the hub's
//! configuration, never such a row, so one found there (stored before this
//! rule) is inert and `managed_secret_delete` may remove it.
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
//!   and the organization, name and consumer as associated data (`aad_v`
//!   2), so a row copied under another organization, name or consumer does
//!   not decrypt. Rows sealed before organizations (`aad_v` 1: name and
//!   consumer only) decrypt only in the default organization. The key comes
//!   from config (`managed_secret_key` / `UA_MANAGED_SECRET_KEY`), never the
//!   database. With no key, writes are refused; there is no plaintext mode.
//! * **Consumer scope.** Every secret names the one consumer that may load it
//!   (`mcp:<server>` for a downstream MCP server). There is no default.
//! * **Fingerprint, not digest.** Metadata carries an HMAC-SHA256 of the value
//!   under a key derived from the encryption key, so a reader of the metadata
//!   or the approval queue cannot confirm a guessed value offline.
//!   `managed_secret_list` leaves it (and the size and key id) out for a
//!   reserved GitHub credential row.
//! * **Ledger names only.** Events carry the name and consumer, never the
//!   value or its fingerprint; for another organization's secret even the
//!   name and consumer are `null` and the originator is `system`
//!   (`ORG-EVENT-DEFAULT`). `tool_calls` rows never hold arguments, and an
//!   approval for `managed_secret_set` (when an operator lists it in
//!   `approval_tools`) binds the fingerprint, not the value.
//!
//! Key rotation: list the new key first and the old one after it. Existing
//! rows keep decrypting; `managed_secret_list` shows `key_current: false` for
//! rows sealed with an older key, and setting the value again re-seals it.

mod tenant_keys;

pub use tenant_keys::{TENANT_KEYS, TENANT_PART};

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
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::approvals::{self, GateOutcome};
use crate::families::github::credentials as gh_credentials;
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

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
const AAD_V1_PREFIX: &str = "ua-managed-secret/v1";
const AAD_V2_PREFIX: &str = "ua-managed-secret/v2";
/// The associated-data form every write uses: organization, name, consumer.
const AAD_V: i64 = 2;

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

/// Whether `name` or `consumer` belongs to the per-organization GitHub
/// credentials, which only their own tools write.
fn reserved(name: &str, consumer: &str) -> bool {
    gh_credentials::RESERVED_NAMES.iter().any(|r| r.eq_ignore_ascii_case(name))
        || consumer.split(':').next() == Some(gh_credentials::RESERVED_CONSUMER_KIND)
}

fn refuse_reserved(name: &str, consumer: &str, doing: &str) -> UaResult<()> {
    if reserved(name, consumer) {
        return Err(UaError::denied(
            "reserved_secret",
            format!(
                "{doing}: the names {:?} and consumers of kind {:?} are the organization's GitHub \
                 credentials; use github_credential_set or github_credential_clear",
                gh_credentials::RESERVED_NAMES,
                gh_credentials::RESERVED_CONSUMER_KIND
            ),
        ));
    }
    Ok(())
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

/// The ids of the configured keys, the write key first; empty when no key
/// is set or the setting does not parse.
pub(crate) fn key_ids(cfg: &Config) -> Vec<String> {
    keyring(cfg).ok().flatten().map(|k| k.into_iter().map(|k| k.id).collect()).unwrap_or_default()
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

/// The associated data for a row of organization `org` sealed under form
/// `aad_v`. Form 1 (before organizations) binds the name and consumer only
/// and is accepted for the default organization alone; form 2 binds the
/// organization too. Any other form is refused.
fn aad(aad_v: i64, org: &str, name: &str, consumer: &str) -> Option<Vec<u8>> {
    match aad_v {
        1 if org == DEFAULT_ORG => Some(format!("{AAD_V1_PREFIX}\0{name}\0{consumer}").into_bytes()),
        2 => Some(format!("{AAD_V2_PREFIX}\0{org}\0{name}\0{consumer}").into_bytes()),
        _ => None,
    }
}

/// Whether a row of organization `org` sealed under form `aad_v` can be
/// opened there at all (no decryption): form 2 anywhere, form 1 in the
/// default organization only.
pub(crate) fn form_accepted(aad_v: i64, org: &str) -> bool {
    aad(aad_v, org, "", "").is_some()
}

fn seal(key: &Key, org: &str, name: &str, consumer: &str, value: &str) -> UaResult<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| UaError::internal("the operating system random source failed"))?;
    let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&key.bytes)
        .map_err(|_| UaError::internal("invalid secret key length"))?;
    let aad = aad(AAD_V, org, name, consumer).expect("the write form is always accepted");
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: value.as_bytes(), aad: &aad })
        .map_err(|_| UaError::internal("managed secret encryption failed"))?;
    Ok((nonce.to_vec(), ct))
}

/// Where a sealed row lives and how it was sealed.
struct Bound<'a> {
    org: &'a str,
    name: &'a str,
    consumer: &'a str,
    aad_v: i64,
}

/// Test hook: the steps an unauthenticated webhook check takes (`read`,
/// `decrypt`, `mac`), on this thread, so a test can assert every refusal
/// takes the same ones. Nothing outside tests.
#[cfg(test)]
pub(crate) mod work_trace {
    use std::cell::RefCell;
    thread_local! {
        static STEPS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }
    pub(crate) fn record(step: &'static str) {
        STEPS.with(|s| s.borrow_mut().push(step));
    }
    /// The steps recorded since the last call.
    pub(crate) fn take() -> Vec<&'static str> {
        STEPS.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }
}

/// Record one step of a webhook check (tests only; nothing otherwise).
#[inline]
pub(crate) fn trace_step(_step: &'static str) {
    #[cfg(test)]
    work_trace::record(_step);
}

fn unseal(key: &Key, at: &Bound<'_>, nonce: &[u8], ct: &[u8]) -> UaResult<SecretString> {
    trace_step("decrypt");
    let name = at.name;
    if nonce.len() != 12 {
        return Err(UaError::internal(format!("managed secret {name:?} is corrupt")));
    }
    let aad = aad(at.aad_v, at.org, name, at.consumer).ok_or_else(|| {
        UaError::internal(format!("managed secret {name:?} was sealed in a form this organization refuses"))
    })?;
    let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&key.bytes)
        .map_err(|_| UaError::internal("invalid secret key length"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| UaError::internal(format!("managed secret {name:?} did not decrypt with its key")))?;
    let text = String::from_utf8(plain)
        .map_err(|_| UaError::internal(format!("managed secret {name:?} is corrupt")))?;
    Ok(SecretString::from(text))
}

// --- the consumer path -------------------------------------------------------------

/// Decrypt one secret of organization `org` for its bound consumer, with its
/// stored keyed fingerprint (what an approval binds). In-process only: no
/// tool returns the value. Refuses a secret bound to any other consumer;
/// another organization's secret of the same name is not found.
pub(crate) fn load_for_consumer(
    conn: &Connection,
    cfg: &Config,
    org: &str,
    name: &str,
    consumer: &str,
) -> UaResult<(SecretString, String)> {
    type Sealed = (String, String, Vec<u8>, Vec<u8>, String, i64);
    let row: Option<Sealed> = conn
        .query_row(
            "SELECT consumer, key_id, nonce, ciphertext, fingerprint, aad_v FROM managed_secrets \
             WHERE org_id = ?1 AND name = ?2",
            [org, name],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    let Some((bound, key_id, nonce, ct, fp, aad_v)) = row else {
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
    let at = Bound { org, name, consumer, aad_v };
    Ok((unseal(key, &at, &nonce, &ct)?, fp))
}

/// One stored row as read for a webhook route: how it was sealed and the
/// sealed bytes. Holds no plaintext.
pub(crate) struct SealedRow {
    pub(crate) consumer: String,
    pub(crate) key_id: String,
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) aad_v: i64,
}

/// Length of the dummy value [`open_once`] decrypts when there is nothing
/// real to decrypt: about a webhook secret's.
const DUMMY_VALUE_BYTES: usize = 40;

/// Decrypt a fixed dummy value under a fixed key: the same one AES-GCM
/// decryption a real row costs, with nothing usable at the end.
fn dummy_unseal() {
    /// The dummy key, nonce and ciphertext.
    type Dummy = (Key, Vec<u8>, Vec<u8>);
    static DUMMY: std::sync::OnceLock<Option<Dummy>> = std::sync::OnceLock::new();
    let dummy = DUMMY.get_or_init(|| {
        let key = Key { id: String::new(), bytes: [0x5a; 32] };
        let (nonce, ct) = seal(&key, "dummy", "dummy", "dummy", &"x".repeat(DUMMY_VALUE_BYTES)).ok()?;
        Some((key, nonce, ct))
    });
    if let Some((key, nonce, ct)) = dummy {
        let at = Bound { org: "dummy", name: "dummy", consumer: "dummy", aad_v: AAD_V };
        let _ = unseal(key, &at, nonce, ct);
    }
}

/// Open `row` as secret `name` of organization `org` for `consumer`, with
/// exactly one AES-GCM decryption whatever `row` is: the real one when the
/// row is bound to `consumer`, sealed with a configured key and in a form
/// `org` opens; otherwise a dummy one, so no row, a row for another
/// consumer, a missing key and a refused form cost what a real row costs.
/// `Ok(None)` when there is no row for `consumer`; `Err` when there is one
/// that cannot be used (no key, its key gone, a refused form, or it does
/// not decrypt).
pub(crate) fn open_once(
    cfg: &Config,
    org: &str,
    name: &str,
    consumer: &str,
    row: Option<&SealedRow>,
) -> UaResult<Option<SecretString>> {
    let keys = keyring(cfg);
    let usable = match row {
        None => Err(Ok(None)),
        Some(r) if r.consumer != consumer => Err(Ok(None)),
        Some(r) => match &keys {
            Ok(Some(keys)) => match keys.iter().find(|k| k.id == r.key_id) {
                Some(_) if !form_accepted(r.aad_v, org) => Err(Err(UaError::denied(
                    "secret_form_refused",
                    format!("managed secret {name:?} was sealed in a form this organization refuses"),
                ))),
                Some(key) => Ok((key, r)),
                None => Err(Err(UaError::denied(
                    "secret_key_missing",
                    format!("managed secret {name:?} was sealed with a key that is no longer configured"),
                ))),
            },
            Ok(None) => Err(Err(UaError::denied(
                "secret_key_unset",
                "managed_secret_key is not set; stored secrets cannot be decrypted",
            ))),
            // The setting does not parse: say so, not that it is unset.
            Err(_) => Err(Err(UaError::denied(
                "secret_key_invalid",
                "managed_secret_key does not parse (32 bytes as base64 or 64 hex characters, comma-separated \
                 to rotate); stored secrets cannot be decrypted",
            ))),
        },
    };
    match usable {
        Ok((key, r)) => {
            let at = Bound { org, name, consumer, aad_v: r.aad_v };
            unseal(key, &at, &r.nonce, &r.ciphertext).map(Some)
        }
        Err(outcome) => {
            dummy_unseal();
            outcome
        }
    }
}

/// `value`'s keyed fingerprint under the configured key `key_id`, or `None`
/// when that key is not configured. Compared, never shown.
pub(crate) fn fingerprint_under_key(cfg: &Config, key_id: &str, value: &str) -> Option<String> {
    keyring(cfg).ok().flatten()?.iter().find(|k| k.id == key_id).map(|k| fingerprint(k, value))
}

/// Whether `name` is stored in organization `org` and bound to `consumer`
/// (no decryption).
pub(crate) fn bound_to(conn: &Connection, org: &str, name: &str, consumer: &str) -> UaResult<bool> {
    let bound: Option<String> = conn
        .query_row("SELECT consumer FROM managed_secrets WHERE org_id = ?1 AND name = ?2", [org, name], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(bound.as_deref() == Some(consumer))
}

/// How a stored secret was sealed: its consumer, key id and associated-data
/// form. Holds no value and no fingerprint.
pub(crate) struct SealedWith {
    pub(crate) consumer: String,
    pub(crate) key_id: String,
    pub(crate) aad_v: i64,
}

/// How `name` in organization `org` was sealed (no decryption).
pub(crate) fn sealed_with(conn: &Connection, org: &str, name: &str) -> UaResult<Option<SealedWith>> {
    Ok(conn
        .query_row(
            "SELECT consumer, key_id, aad_v FROM managed_secrets WHERE org_id = ?1 AND name = ?2",
            [org, name],
            |r| Ok(SealedWith { consumer: r.get(0)?, key_id: r.get(1)?, aad_v: r.get(2)? }),
        )
        .optional()?)
}

/// Name and keyed fingerprint of every secret of organization `org` bound to
/// `consumer`, by name.
pub(crate) fn bound_secrets(conn: &Connection, org: &str, consumer: &str) -> UaResult<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT name, fingerprint FROM managed_secrets WHERE org_id = ?1 AND consumer = ?2 ORDER BY name",
    )?;
    let rows = stmt.query_map([org, consumer], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
    Ok(rows)
}

/// Delete every secret of organization `org` bound to `consumer` (the caller
/// holds the approval that listed them), one `managed_secret.deleted` event
/// each. Returns the names.
pub(crate) fn orphan_consumer(
    tx: &mut WriteTx<'_>,
    org: &str,
    consumer: &str,
    by: &str,
    approval_id: i64,
    why: &str,
) -> UaResult<Vec<String>> {
    let names: Vec<String> = bound_secrets(tx, org, consumer)?.into_iter().map(|(n, _)| n).collect();
    tx.execute("DELETE FROM managed_secrets WHERE org_id = ?1 AND consumer = ?2", [org, consumer])?;
    for name in &names {
        // ORG-EVENT-DEFAULT: another organization's names stay out of the
        // default organization's ledger.
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "managed_secret.deleted",
                json!({
                    "name": ledger_text(org, name), "consumer": ledger_text(org, consumer),
                    "approval_id": approval_id, "reason": why,
                }),
            )
            .by(approvals::ledger_originator(org, by)),
        )?;
    }
    Ok(names)
}

/// A caller-chosen name or label for an event: events stay in the default
/// organization's ledger (`ORG-EVENT-DEFAULT`), so another organization's
/// are `null` there.
fn ledger_text(org: &str, text: &str) -> Value {
    if org == DEFAULT_ORG { json!(text) } else { Value::Null }
}

// --- the shared write path -----------------------------------------------------------

/// A value sealed for one organization, name and consumer. Holds no
/// plaintext.
pub(crate) struct Sealed {
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    pub(crate) fingerprint: String,
    pub(crate) value_bytes: usize,
    /// The value's keyed fingerprint under every configured key, by key id
    /// (the write key's is `fingerprint`): what a stored row sealed under an
    /// older key is compared with. Never stored, never returned.
    fingerprints: Vec<(String, String)>,
}

impl Sealed {
    /// The value's keyed fingerprint under the key `key_id` names, when that
    /// key is configured.
    pub(crate) fn fingerprint_under(&self, key_id: &str) -> Option<&str> {
        self.fingerprints.iter().find(|(k, _)| k == key_id).map(|(_, fp)| fp.as_str())
    }
}

/// Check the size of `value`, then seal it for `org`, `name` and `consumer`
/// under the write key. Refused when no key is configured.
pub(crate) fn seal_value(
    cfg: &Config,
    org: &str,
    name: &str,
    consumer: &str,
    value: &str,
) -> UaResult<Sealed> {
    if value.is_empty() || value.len() > MAX_VALUE_BYTES {
        return Err(UaError::invalid(format!("value must be 1-{MAX_VALUE_BYTES} bytes")));
    }
    let key = write_key(cfg)?;
    let fingerprint = fingerprint(&key, value);
    let fingerprints = keyring(cfg)?
        .unwrap_or_default()
        .iter()
        .map(|k| (k.id.clone(), self::fingerprint(k, value)))
        .collect();
    let (nonce, ciphertext) = seal(&key, org, name, consumer, value)?;
    Ok(Sealed { key_id: key.id, nonce, ciphertext, fingerprint, value_bytes: value.len(), fingerprints })
}

/// What an approval of a secret write binds: never the value.
pub(crate) fn set_payload(name: &str, consumer: &str, fp: Option<&str>, value_bytes: usize) -> Value {
    json!({ "name": name, "consumer": consumer, "fingerprint": fp, "value_bytes": value_bytes })
}

/// What [`put`] did.
pub(crate) struct Stored {
    pub(crate) replaced: bool,
    pub(crate) approval_id: Option<i64>,
    pub(crate) updated_at: String,
}

/// Why [`put`] stored nothing, though its transaction may commit.
pub(crate) enum NotStored {
    /// A one-time human approval is pending, with this id.
    Pending(i64),
    /// Refused after the approval gate; the refusal is already in the
    /// ledger, so the caller commits its transaction and then returns this.
    Refused(UaError),
}

impl NotStored {
    /// The error `tool`'s caller sees.
    pub(crate) fn into_error(self, tool: &str) -> UaError {
        match self {
            NotStored::Pending(approval_id) => UaError::ApprovalRequired { tool: tool.into(), approval_id },
            NotStored::Refused(e) => e,
        }
    }
}

/// Store `sealed` as secret `name` of organization `org`, inside the
/// caller's write transaction. A name already bound to another consumer is
/// refused. Replacing a value is as consequential as deleting it: unless
/// the registry already consumed a pass for this call (`registry_gated`),
/// it needs a one-time human approval of `tool`, bound to the new value's
/// fingerprint (`Err(NotStored::Pending)`). Writes no event when it
/// stores: the tool records its own.
///
/// An organization's GitHub webhook secret must be its own: a value another
/// organization or the hub configuration already uses is refused
/// ([`gh_credentials::refuse_shared_webhook_secret`]). That check runs
/// after the approval gate, so a replacement answers nothing about the
/// value before a human approved it, and every such refusal is ledgered
/// (`github.credential.refused`, the attempted value's keyed fingerprint
/// only, never an organization it collides with) and returned as
/// `Err(NotStored::Refused)` for the caller to commit: repeated probing of
/// a first value, which no approval gates, leaves a trail.
#[allow(clippy::too_many_arguments)]
pub(crate) fn put(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    org: &str,
    tool: &str,
    name: &str,
    consumer: &str,
    sealed: &Sealed,
    registry_gated: bool,
) -> UaResult<Result<Stored, NotStored>> {
    let prior: Option<String> = tx
        .query_row("SELECT consumer FROM managed_secrets WHERE org_id = ?1 AND name = ?2", [org, name], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(prior) = &prior
        && prior != consumer
    {
        return Err(UaError::conflict_code(
            "secret_consumer_change",
            format!(
                "managed secret {name:?} is bound to {prior:?}; delete it before binding the name to another consumer"
            ),
        ));
    }
    let mut approval_id = None;
    if prior.is_some() && !registry_gated {
        let payload = set_payload(name, consumer, Some(&sealed.fingerprint), sealed.value_bytes);
        match approvals::gate(tx, cfg, caller, tool, &payload)? {
            GateOutcome::Pass { approval_id: id } => approval_id = Some(id),
            GateOutcome::Pending { approval_id } => return Ok(Err(NotStored::Pending(approval_id))),
            GateOutcome::Denied { approval_id, reason } => {
                return Err(UaError::denied(
                    "approval_denied",
                    format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
                ));
            }
        }
    }
    if name == gh_credentials::WEBHOOK_SECRET
        && consumer == gh_credentials::WEBHOOK_CONSUMER
        && let Err(refusal) = gh_credentials::refuse_shared_webhook_secret(tx, cfg, org, sealed)
    {
        if refusal.reason_code() != Some(gh_credentials::SECRET_IN_USE) {
            return Err(refusal);
        }
        // ORG-EVENT-DEFAULT: as the credential tools' own events. The
        // attempted value's keyed fingerprint only. The transaction commits,
        // so a pass the gate consumed stays consumed: each probe of a
        // replacement costs a fresh human approval.
        ledger::append(
            tx,
            EventInput::new(
                ua_core::DEFAULT_ORG,
                "github.credential.refused",
                json!({
                    "kind": "webhook_secret", "reason": gh_credentials::SECRET_IN_USE,
                    "fingerprint": sealed.fingerprint, "value_bytes": sealed.value_bytes,
                    "approval_id": approval_id,
                }),
            )
            .by(approvals::ledger_originator(org, &caller.label)),
        )?;
        return Ok(Err(NotStored::Refused(refusal)));
    }
    let now = ua_core::time::now();
    tx.execute(
        "INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
         created_by, created_at, updated_by, updated_at, aad_v) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?9, ?10, ?11) \
         ON CONFLICT(org_id, name) DO UPDATE SET key_id = ?4, nonce = ?5, ciphertext = ?6, fingerprint = ?7, \
         value_bytes = ?8, updated_by = ?9, updated_at = ?10, aad_v = ?11",
        params![
            org,
            name,
            consumer,
            sealed.key_id,
            sealed.nonce,
            sealed.ciphertext,
            sealed.fingerprint,
            sealed.value_bytes as i64,
            caller.label,
            now,
            AAD_V
        ],
    )?;
    Ok(Ok(Stored { replaced: prior.is_some(), approval_id, updated_at: now }))
}

/// Store `sealed` with none of [`put`]'s checks: a row as an older build,
/// or a direct database edit, could have left it. Tests only.
#[cfg(test)]
pub(crate) fn put_unchecked(
    tx: &mut WriteTx<'_>,
    org: &str,
    name: &str,
    consumer: &str,
    sealed: &Sealed,
) -> UaResult<()> {
    let now = ua_core::time::now();
    tx.execute(
        "INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
         created_by, created_at, updated_by, updated_at, aad_v) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'test', ?9, 'test', ?9, ?10)",
        params![
            org,
            name,
            consumer,
            sealed.key_id,
            sealed.nonce,
            sealed.ciphertext,
            sealed.fingerprint,
            sealed.value_bytes as i64,
            now,
            AAD_V
        ],
    )?;
    Ok(())
}

/// Delete secret `name` of organization `org`, inside the caller's write
/// transaction, under a one-time human approval of `tool` bound to the name,
/// consumer and current fingerprint (a rotation after the request needs a
/// new approval). Returns the consumer and approval id, or `Ok(Err(id))` for
/// a pending approval. Another organization's secret is not found. Writes
/// no event: the tool records its own.
pub(crate) fn remove(
    tx: &mut WriteTx<'_>,
    cfg: &Config,
    caller: &Caller,
    org: &str,
    tool: &str,
    name: &str,
) -> UaResult<Result<(String, i64), i64>> {
    let row: Option<(String, String)> = tx
        .query_row(
            "SELECT consumer, fingerprint FROM managed_secrets WHERE org_id = ?1 AND name = ?2",
            [org, name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((consumer, fp)) = row else {
        return Err(UaError::not_found(format!("managed secret {name:?} is not set")));
    };
    let payload = json!({ "name": name, "consumer": consumer, "fingerprint": fp });
    let approval_id = match approvals::gate(tx, cfg, caller, tool, &payload)? {
        GateOutcome::Pass { approval_id } => approval_id,
        GateOutcome::Pending { approval_id } => return Ok(Err(approval_id)),
        GateOutcome::Denied { approval_id, reason } => {
            return Err(UaError::denied(
                "approval_denied",
                format!("approval {approval_id} was denied: {}", reason.unwrap_or_default()),
            ));
        }
    };
    tx.execute("DELETE FROM managed_secrets WHERE org_id = ?1 AND name = ?2", [org, name])?;
    Ok(Ok((consumer, approval_id)))
}

// --- who may write ------------------------------------------------------------------

/// An operator of the hub: a verified human of the default organization
/// ([`Authority::Operator`]), for the hub-scoped consumers (downstream MCP
/// servers). Keyed on identity, never on profile; a profile grants no
/// authority.
pub(crate) fn is_secret_admin(cfg: &Config, caller: &Caller) -> bool {
    Authz::new(cfg).holds(caller, &[Authority::Operator], ua_core::DEFAULT_ORG)
}

/// Refuse an organization `orgs` does not hold. Runs before anything is
/// read, and again first in every write transaction: the `org_exists`
/// trigger only sees inserts, so a delete would otherwise pass.
pub(crate) fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let known = c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?.is_some();
    if !known {
        return Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {org:?}; no secret was changed"),
        ));
    }
    Ok(())
}

/// Refuse an anonymous caller: every secret or credential write needs an
/// authenticated identity before any authority is weighed.
pub(crate) fn require_identity(caller: &Caller, doing: &str) -> UaResult<()> {
    if caller.kind == ActorKind::Anonymous {
        return Err(UaError::denied(
            "identity_required",
            format!("{doing} requires an authenticated identity"),
        ));
    }
    Ok(())
}

/// A secret admin of organization `org`: an authenticated caller holding
/// [`Authority::Operator`] there. Until memberships exist that is a verified
/// human of the default organization only, so another organization's
/// secrets cannot be written by any caller.
pub(crate) fn require_admin(cfg: &Config, caller: &Caller, org: &str, doing: &str) -> UaResult<()> {
    require_identity(caller, doing)?;
    if !Authz::new(cfg).holds(caller, &[Authority::Operator], org) {
        return Err(UaError::denied(
            "operator_only",
            format!("{doing} is for a verified human of the secret's organization"),
        ));
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

fn set_gate_payload(cfg: &Config, args: &Value) -> Value {
    let s = |k: &str| args.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let value = s("value");
    let fp = write_key(cfg).ok().map(|k| fingerprint(&k, &value));
    set_payload(&s("name"), &s("consumer"), fp.as_deref(), value.len())
}

async fn managed_secret_set(ctx: ToolCtx, a: SetArgs) -> UaResult<Value> {
    let cfg = ctx.hub.cfg().clone();
    let org = ctx.caller.org_id.clone();
    let known = org.clone();
    ctx.hub.db().read_async(move |c| require_org(c, &known)).await?;
    require_admin(&cfg, &ctx.caller, &org, "managed_secret_set")?;
    check_name(&a.name)?;
    check_consumer(&a.consumer)?;
    refuse_reserved(&a.name, &a.consumer, "managed_secret_set")?;
    let sealed = seal_value(&cfg, &org, &a.name, &a.consumer, &a.value)?;
    drop(a.value);
    let (name, consumer) = (a.name, a.consumer);
    // With managed_secret_set in approval_tools the registry has already
    // consumed a pass for this exact payload.
    let registry_gated = cfg.approval_tools.iter().any(|t| t == "managed_secret_set");
    let (hub, caller) = (ctx.hub.clone(), ctx.caller.clone());
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let stored = match put(
                tx,
                hub.cfg(),
                &caller,
                &org,
                "managed_secret_set",
                &name,
                &consumer,
                &sealed,
                registry_gated,
            )? {
                Ok(s) => s,
                Err(not_stored) => return Ok(Err(not_stored)),
            };
            // ORG-EVENT-DEFAULT: use the secret's organization once callers
            // can resolve to other organizations and org_guard allows it.
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "managed_secret.set",
                    json!({
                        "name": ledger_text(&org, &name), "consumer": ledger_text(&org, &consumer),
                        "replaced": stored.replaced, "approval_id": stored.approval_id,
                    }),
                )
                .by(approvals::ledger_originator(&org, &caller.label)),
            )?;
            Ok(Ok(json!({
                "name": name, "consumer": consumer, "fingerprint": sealed.fingerprint, "key_id": sealed.key_id,
                "value_bytes": sealed.value_bytes, "replaced": stored.replaced, "updated_at": stored.updated_at,
                "stored": true, "approval_id": stored.approval_id,
            })))
        })
        .await?;
    out.map_err(|not_stored| not_stored.into_error("managed_secret_set"))
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only secrets bound to this consumer.
    pub consumer: Option<String>,
}

async fn managed_secret_list(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let current = key_ids(ctx.hub.cfg());
    let write_id = current.first().cloned();
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut stmt = c.prepare(
                "SELECT name, consumer, key_id, fingerprint, value_bytes, created_by, created_at, updated_by, \
                 updated_at FROM managed_secrets WHERE org_id = ?1 AND (?2 IS NULL OR consumer = ?2) ORDER BY name",
            )?;
            let rows = stmt
                .query_map(params![org, a.consumer], |r| {
                    let (name, consumer): (String, String) = (r.get(0)?, r.get(1)?);
                    let key_id: String = r.get(2)?;
                    // A GitHub credential row is its own tools' (and, in the
                    // default organization, inert): listed so it can be
                    // seen and removed, with no fingerprint, size or key.
                    if reserved(&name, &consumer) {
                        return Ok(json!({
                            "name": name, "consumer": consumer, "reserved": true,
                            "key_id": null, "key_current": null, "decryptable": null,
                            "fingerprint": null, "value_bytes": null,
                            "created_by": r.get::<_, String>(5)?,
                            "created_at": r.get::<_, String>(6)?,
                            "updated_by": r.get::<_, String>(7)?,
                            "updated_at": r.get::<_, String>(8)?,
                        }));
                    }
                    Ok(json!({
                        "name": name,
                        "consumer": consumer,
                        "reserved": false,
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
    let org = ctx.caller.org_id.clone();
    let known = org.clone();
    ctx.hub.db().read_async(move |c| require_org(c, &known)).await?;
    require_admin(&cfg, &ctx.caller, &org, "managed_secret_delete")?;
    check_name(&a.name)?;
    let (hub, caller, name) = (ctx.hub.clone(), ctx.caller.clone(), a.name);
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            // Another organization's GitHub credential is its tools' to
            // clear; in the default organization such a row is never read.
            if org != DEFAULT_ORG
                && let Some(found) = sealed_with(tx, &org, &name)?
            {
                refuse_reserved(&name, &found.consumer, "managed_secret_delete")?;
            }
            let (consumer, approval_id) =
                match remove(tx, hub.cfg(), &caller, &org, "managed_secret_delete", &name)? {
                    Ok(done) => done,
                    Err(pending) => return Ok(Err(pending)),
                };
            // ORG-EVENT-DEFAULT: use the secret's organization once callers
            // can resolve to other organizations and org_guard allows it.
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "managed_secret.deleted",
                    json!({
                        "name": ledger_text(&org, &name), "consumer": ledger_text(&org, &consumer),
                        "approval_id": approval_id,
                    }),
                )
                .by(approvals::ledger_originator(&org, &caller.label)),
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
            "Store a credential for one consumer (e.g. `mcp:docs`, the MCP server docs), encrypted at rest, in \
             the caller's organization. For a verified human of that organization. The value is never returned \
             by any tool; the result and managed_secret_list show only metadata and a keyed fingerprint. \
             Replacing an existing value needs a one-time human approval bound to the new value's fingerprint \
             (the identical retry after approval stores it). Refused when the hub has no managed_secret_key. \
             Rebinding a name to another consumer needs a delete first. The names `github:token` and \
             `github:webhook-secret` and consumers of kind `github` are refused: use github_credential_set.",
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
            "List the caller's organization's managed secrets: name, consumer, keyed fingerprint, size, key id \
             and who set them. Never values. A reserved GitHub credential row (`github:token`, \
             `github:webhook-secret`, consumer kind `github`) shows only its name, consumer and who set it; \
             github_credential_status reports those.",
            managed_secret_list,
        )
        .read_only()
        .family("secrets"),
    );
    r.add(
        tool(
            "managed_secret_delete",
            "Delete one managed secret of the caller's organization. For a verified human of that organization, \
             and always needs a one-time human approval bound to the name, consumer and current fingerprint; the \
             identical retry after approval deletes it. A GitHub credential is cleared with \
             github_credential_clear instead.",
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

    fn at<'a>(org: &'a str, name: &'a str, consumer: &'a str) -> Bound<'a> {
        Bound { org, name, consumer, aad_v: AAD_V }
    }

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

    /// A stored row under a key setting that does not parse is reported
    /// as that, not as an unset key; an unset key stays `secret_key_unset`.
    #[test]
    fn open_once_names_why_the_keyring_is_unusable() {
        let row = SealedRow {
            consumer: "mcp:docs".into(),
            key_id: "0000000000000000".into(),
            nonce: vec![0; 12],
            ciphertext: vec![0; 32],
            aad_v: AAD_V,
        };
        let code = |cfg: &Config| {
            let e = open_once(cfg, DEFAULT_ORG, "tok", "mcp:docs", Some(&row)).unwrap_err();
            e.reason_code().map(str::to_string)
        };
        assert_eq!(code(&cfg_with("not-a-key")).as_deref(), Some("secret_key_invalid"));
        assert_eq!(code(&Config::for_home(std::env::temp_dir())).as_deref(), Some("secret_key_unset"));
        assert_eq!(code(&cfg_with(K1)).as_deref(), Some("secret_key_missing"));
    }

    #[test]
    fn seal_round_trips_and_binds_organization_name_and_consumer() {
        let key = write_key(&cfg_with(K1)).unwrap();
        let (nonce, ct) = seal(&key, DEFAULT_ORG, "tok", "mcp:docs", "s3cret").unwrap();
        assert!(!ct.windows(6).any(|w| w == b"s3cret"), "ciphertext must not hold the plaintext");
        let open = |b: Bound<'_>| unseal(&key, &b, &nonce, &ct);
        assert_eq!(open(at(DEFAULT_ORG, "tok", "mcp:docs")).unwrap().expose_secret(), "s3cret");
        assert!(open(at(DEFAULT_ORG, "other", "mcp:docs")).is_err(), "renamed rows do not decrypt");
        assert!(open(at(DEFAULT_ORG, "tok", "mcp:evil")).is_err(), "rebound rows do not decrypt");
        assert!(
            open(at("org-b", "tok", "mcp:docs")).is_err(),
            "a row moved to another organization does not decrypt"
        );
        let (n2, _) = seal(&key, DEFAULT_ORG, "tok", "mcp:docs", "s3cret").unwrap();
        assert_ne!(nonce, n2, "every write takes a fresh nonce");
    }

    #[test]
    fn rows_sealed_before_organizations_decrypt_only_in_the_default_organization() {
        let key = write_key(&cfg_with(K1)).unwrap();
        // The managed_secrets.v1 form: name and consumer only.
        let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&key.bytes).unwrap();
        let nonce = [3u8; 12];
        let legacy_aad = format!("{AAD_V1_PREFIX}\0tok\0mcp:docs").into_bytes();
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: b"legacy-value-not-real", aad: &legacy_aad })
            .unwrap();
        let v1 = |org| Bound { org, name: "tok", consumer: "mcp:docs", aad_v: 1 };
        assert_eq!(
            unseal(&key, &v1(DEFAULT_ORG), &nonce, &ct).unwrap().expose_secret(),
            "legacy-value-not-real"
        );
        assert!(
            unseal(&key, &v1("org-b"), &nonce, &ct).is_err(),
            "form 1 is the default organization's only"
        );
        let bad = Bound { org: DEFAULT_ORG, name: "tok", consumer: "mcp:docs", aad_v: 3 };
        assert!(unseal(&key, &bad, &nonce, &ct).is_err(), "an unknown form is refused");
    }

    fn person(label: &str, org: &str) -> Caller {
        Caller {
            label: label.into(),
            kind: ActorKind::Human,
            profile: ua_core::Profile::Operator,
            enforce_profile: false,
            session_key: Some(format!("{label}-s")),
            transport: ua_core::identity::Transport::Mcp,
            org_id: org.into(),
        }
    }

    fn row_form(c: &Connection, org: &str, name: &str) -> i64 {
        c.query_row("SELECT aad_v FROM managed_secrets WHERE org_id = ?1 AND name = ?2", [org, name], |r| {
            r.get(0)
        })
        .unwrap()
    }

    /// End to end over the real store: a row sealed with the
    /// `managed_secrets.v1` associated data survives the upgrade, decrypts
    /// for its consumer in the default organization, and is re-sealed in
    /// form 2 when replaced under an approval. A form-2 row of another
    /// organization moved into the default organization and relabelled
    /// form 1 never decrypts.
    #[tokio::test]
    async fn a_pre_organization_row_upgrades_decrypts_and_reseals_and_a_downgrade_does_not_decrypt() {
        const V1: &str = "fake-legacy-docs-token-not-real";
        const V2: &str = "fake-rotated-docs-token-not-real";
        const B_VALUE: &str = "fake-org-b-docs-token-not-real";
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::for_home(dir.path());
        cfg.managed_secret_key = Some(SecretString::from(K1.to_string()));
        cfg.human_identities = vec!["operator".into(), "approver".into()];
        let key = write_key(&cfg).unwrap();

        // Before the upgrade: seal exactly as managed_secrets.v1 did.
        let pre: Vec<_> = crate::schema_parts()
            .into_iter()
            .filter(|p| p.name != TENANT_KEYS.name && p.name != TENANT_PART.name)
            .collect();
        {
            let db = ua_store::Db::open(&cfg.db_path(), &pre).unwrap();
            let nonce = [5u8; 12];
            let legacy_aad = format!("{AAD_V1_PREFIX}\0docs-token\0mcp:docs").into_bytes();
            let cipher = <Aes256Gcm as AeadKeyInit>::new_from_slice(&key.bytes).unwrap();
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), Payload { msg: V1.as_bytes(), aad: &legacy_aad })
                .unwrap();
            let (kid, fp) = (key.id.clone(), fingerprint(&key, V1));
            db.write(move |tx| {
                tx.execute(
                    "INSERT INTO managed_secrets (name, consumer, key_id, nonce, ciphertext, fingerprint, \
                     value_bytes, created_by, created_at, updated_by, updated_at) \
                     VALUES ('docs-token', 'mcp:docs', ?1, ?2, ?3, ?4, ?5, 'operator', 'then', 'operator', 'then')",
                    params![kid, nonce.to_vec(), ct, fp, V1.len() as i64],
                )?;
                Ok(())
            })
            .unwrap();
        }

        let hub = crate::Hub::open(cfg.clone()).unwrap();
        let load = |org: &'static str, name: &'static str| {
            let cfg = cfg.clone();
            hub.db().read(move |c| {
                load_for_consumer(c, &cfg, org, name, "mcp:docs")
                    .map(|(v, fp)| (v.expose_secret().to_string(), fp))
            })
        };
        assert_eq!(hub.db().read(|c| Ok(row_form(c, DEFAULT_ORG, "docs-token"))).unwrap(), 1);
        let (value, fp) = load(DEFAULT_ORG, "docs-token").unwrap();
        assert_eq!(value, V1);
        assert_eq!(fp, fingerprint(&key, V1));

        // Replacing it is gated; the approved retry re-seals it in form 2.
        let reg = crate::builtin_registry();
        let (op, approver) = (person("operator", DEFAULT_ORG), person("approver", DEFAULT_ORG));
        let args = json!({ "name": "docs-token", "consumer": "mcp:docs", "value": V2 });
        let e = reg.call(&hub, &op, "managed_secret_set", args.clone()).await.unwrap_err();
        let UaError::ApprovalRequired { approval_id, .. } = e else { panic!("{e:?}") };
        reg.call(&hub, &approver, "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
            .await
            .unwrap();
        let out = reg.call(&hub, &op, "managed_secret_set", args).await.unwrap();
        assert_eq!(out["replaced"], true);
        assert_eq!(hub.db().read(|c| Ok(row_form(c, DEFAULT_ORG, "docs-token"))).unwrap(), AAD_V);
        assert_eq!(load(DEFAULT_ORG, "docs-token").unwrap().0, V2);

        // Downgrade: org B's form-2 row copied into the default organization
        // and relabelled form 1 (or left form 2) does not decrypt there.
        let sealed = seal_value(&cfg, "org-b", "b-token", "mcp:docs", B_VALUE).unwrap();
        let (put_cfg, system) = (cfg.clone(), Caller::system_for("org-b"));
        hub.db()
            .write(move |tx| {
                tx.execute(
                    "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) \
                     VALUES ('org-b', 'org-b', 'org-b', '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                    [],
                )?;
                let out = put(
                    tx,
                    &put_cfg,
                    &system,
                    "org-b",
                    "managed_secret_set",
                    "b-token",
                    "mcp:docs",
                    &sealed,
                    true,
                )?;
                assert!(out.is_ok());
                Ok(())
            })
            .unwrap();
        assert_eq!(load("org-b", "b-token").unwrap().0, B_VALUE);
        for aad_v in [1, 2] {
            hub.db()
                .write(move |tx| {
                    let gone = "DELETE FROM managed_secrets WHERE org_id = 'default' AND name = 'b-token'";
                    tx.execute(gone, [])?;
                    tx.execute(
                        "INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, \
                         value_bytes, created_by, created_at, updated_by, updated_at, aad_v) \
                         SELECT 'default', name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, \
                         created_by, created_at, updated_by, updated_at, ?1 FROM managed_secrets \
                         WHERE org_id = 'org-b' AND name = 'b-token'",
                        [aad_v],
                    )?;
                    Ok(())
                })
                .unwrap();
            let e = load(DEFAULT_ORG, "b-token").unwrap_err();
            assert!(!format!("{e:?}").contains(B_VALUE), "{e:?}");
            assert!(format!("{e}").contains("did not decrypt"), "aad_v {aad_v}: {e}");
        }
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

    #[test]
    fn github_names_and_consumers_are_reserved() {
        assert!(reserved("github:token", "mcp:docs"));
        assert!(reserved("GitHub:Webhook-Secret", "mcp:docs"));
        assert!(reserved("docs-token", "github"));
        assert!(reserved("docs-token", "github:api"));
        assert!(!reserved("github:relay", "relay:github"), "the relay's name and consumer are its own");
        assert!(!reserved("githubish", "mcp:docs"));
        assert!(!reserved("gh", "mcp:github"));
    }
}
