//! The single egress filter for evidence bundles (`docs/evidence-export.md`).
//!
//! Every outgoing bundle record passes through [`EgressFilter`], and the
//! offline verifier runs the same [`find_forbidden_in_ledger_event`] and
//! [`find_forbidden_in_value`] checks over every parsed file in a bundle.
//!
//! The refusal floor covers:
//! - managed secret values and private keys (PEM blocks)
//! - provider credentials and API keys
//! - authentication tokens (agent tokens, OAuth tokens/codes/grants, UI
//!   sessions, GitHub/PAT/Slack/AWS/JWT tokens, `Bearer ` headers)
//! - passkeys
//! - session credentials (`session_credentials` rows and raw `uas_<16+>` values)
//! - private/restricted ledger channels (`agent.message.*`, `agent.mailbox.*`,
//!   `agent.lifecycle.handoff`, `agent.lifecycle.handoff_hook`,
//!   `agent.conversation.handoff`, `private.*`, `*.private.*`) and records
//!   marked private
//!
//! Restricted/private ledger channels are exported as hash-only chain-link
//! stubs (`redacted: true`) so real hubs can export verifiable bundles without
//! leaking private content; any unredacted private event or any secret/token
//! material causes export and verification to refuse outright.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ua_core::{UaError, UaResult};

use super::cmp_ts;

/// Summary of classes deliberately excluded from a bundle (`withheld.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithheldReport {
    pub classes: BTreeMap<String, u64>,
    pub total: u64,
}

impl WithheldReport {
    pub fn record(&mut self, class: &str, count: u64) {
        if count == 0 {
            return;
        }
        *self.classes.entry(class.to_string()).or_insert(0) += count;
        self.total += count;
    }
}

/// Withheld class names matching `docs/evidence-export.md` ("What must never
/// be in a bundle").
pub const CLASS_MANAGED_SECRETS: &str = "managed_secret_values";
pub const CLASS_PROVIDER_CREDENTIALS: &str = "provider_credentials";
pub const CLASS_AUTH_TOKENS: &str = "auth_tokens";
pub const CLASS_PASSKEYS: &str = "passkeys";
pub const CLASS_SESSION_CREDENTIALS: &str = "session_credentials";
pub const CLASS_PRIVATE_MESSAGES: &str = "private_message_bodies";
pub const CLASS_PRIVATE_RECORDS: &str = "private_records";
pub const CLASS_CROSS_ORG_EVENTS: &str = "cross_org_events";

const CREDENTIAL_PREFIX: &str = "uas_";
const CREDENTIAL_MIN_TAIL: usize = 16;

/// Maximum recursion depth when parsing JSON strings nested inside strings.
const MAX_NESTED_JSON_DEPTH: usize = 8;

/// Normalized (lowercase alphanumeric only, stripping `_`, `-`, `.`, spaces)
/// key substrings that denote secret/credential fields regardless of casing or
/// separator style (`accessToken`, `api-key`, `X-API-Key`, `Authorization`,
/// `private_key_pem`, `password`, etc.).
const SECRET_KEY_SUBSTRINGS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "authorization",
    "credential",
    "apikey",
    "privatekey",
    "signingseed",
];

/// Exact normalized key names that are known non-secret metadata fields emitted
/// by the hub (numeric counts or opaque non-secret IDs). Their *values* are
/// still scanned for secret value patterns and nested JSON.
const SAFE_METADATA_KEYS: &[&str] = &[
    "authorizationid",
    "policyauthorizationid",
    "credentialid",
    "inputtokens",
    "outputtokens",
    "totaltokens",
    "cachereadinputtokens",
    "cachecreationinputtokens",
    "reasoningtokens",
    "tokencount",
    "tokensused",
    "tokenendpointauthmethod",
    "tokenendpointauthmethodssupported",
];

/// Reason a record was refused by the egress filter or verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressViolation {
    pub class: &'static str,
    pub detail: String,
}

/// Action taken by [`EgressFilter::inspect_ledger_event`] on a ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerEgressAction {
    /// Safe to export in full.
    Allow,
    /// Private/restricted record: strip channel/payload/parties and emit a
    /// hash-only chain-link stub under the named withheld class.
    RedactToHashOnly(&'static str),
}

/// Whether `channel` is one of the hub's restricted/private channels
/// (`ua-tools/src/families/events.rs`) or an explicitly private channel.
pub fn is_restricted_channel(channel: &str) -> bool {
    restricted_channel_class(channel).is_some()
}

/// Classify a restricted/private channel into its withheld class, or `None` if
/// the channel is not inherently restricted.
pub fn restricted_channel_class(channel: &str) -> Option<&'static str> {
    let lower = channel.to_ascii_lowercase();
    if lower.starts_with("agent.message.") || lower.starts_with("agent.mailbox.") {
        return Some(CLASS_PRIVATE_MESSAGES);
    }
    if lower == "agent.lifecycle.handoff"
        || lower == "agent.lifecycle.handoff_hook"
        || lower == "agent.conversation.handoff"
        || lower.starts_with("private.")
        || lower.contains(".private.")
    {
        return Some(CLASS_PRIVATE_RECORDS);
    }
    None
}

/// Normalize a JSON object key by stripping separators (`_`, `-`, `.`, spaces)
/// and lowercasing ASCII characters.
fn normalize_key(k: &str) -> String {
    k.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
}

fn secret_key_class(norm_key: &str) -> Option<&'static str> {
    if SAFE_METADATA_KEYS.contains(&norm_key) {
        return None;
    }
    if !SECRET_KEY_SUBSTRINGS.iter().any(|sub| norm_key.contains(sub)) {
        return None;
    }
    if norm_key.contains("credential") {
        Some(CLASS_SESSION_CREDENTIALS)
    } else if norm_key.contains("token") || norm_key.contains("authorization") {
        Some(CLASS_AUTH_TOKENS)
    } else if norm_key.contains("apikey") || norm_key.contains("clientsecret") {
        Some(CLASS_PROVIDER_CREDENTIALS)
    } else {
        Some(CLASS_MANAGED_SECRETS)
    }
}

/// Whether a value under a secret-matching key is an explicit empty/redacted
/// placeholder (safe) vs real material (including non-empty objects, arrays,
/// numbers, booleans, or non-placeholder strings).
fn is_safe_redacted_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => {
            let t = s.trim();
            t.is_empty()
                || t.eq_ignore_ascii_case("[redacted]")
                || t.eq_ignore_ascii_case("[redacted-credential]")
        }
        Value::Array(arr) => arr.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

/// The one egress filter through which every exported bundle record flows.
#[derive(Debug, Default)]
pub struct EgressFilter {
    withheld: WithheldReport,
}

impl EgressFilter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_withheld(&mut self, class: &str, count: u64) {
        self.withheld.record(class, count);
    }

    /// Count rows in inherently withheld database tables strictly within the
    /// checkpoint's window `(start_excl_ts, cutoff_ts]` (and `(start_seq_excl,
    /// end_seq]` for `message_index`) without reading secret values.
    ///
    /// - When `org_id` is `Some(org)`, only tables carrying `org_id` are
    ///   counted, filtered to `org` (hub-global tables return 0).
    /// - `already_redacted_ulids` prevents double-counting `message_index` rows
    ///   whose corresponding `agent.message.*` ledger events were already
    ///   counted as redacted hash-only stubs in this bundle.
    pub fn count_withheld_tables(
        &mut self,
        conn: &Connection,
        org_id: Option<&str>,
        start_excl_ts: Option<&str>,
        cutoff_ts: &str,
        seq_bounds: Option<(i64, i64)>,
        already_redacted_ulids: &BTreeSet<String>,
    ) -> UaResult<()> {
        let specs: &[(&str, &str, &[&str])] = &[
            ("managed_secrets", CLASS_MANAGED_SECRETS, &["created_at"]),
            ("provider_accounts", CLASS_PROVIDER_CREDENTIALS, &["created_at"]),
            ("agent_tokens", CLASS_AUTH_TOKENS, &["issued_at", "created_at"]),
            ("oauth_tokens", CLASS_AUTH_TOKENS, &["issued_at", "created_at"]),
            ("oauth_codes", CLASS_AUTH_TOKENS, &["created_at"]),
            ("oauth_grants", CLASS_AUTH_TOKENS, &["created_at"]),
            ("ui_sessions", CLASS_AUTH_TOKENS, &["created_at"]),
            ("passkeys", CLASS_PASSKEYS, &["created_at"]),
            ("session_credentials", CLASS_SESSION_CREDENTIALS, &["issued_at", "created_at"]),
            ("session_handoff_notes", CLASS_PRIVATE_MESSAGES, &["created_at"]),
        ];
        for &(table, class, ts_cols) in specs {
            let n = count_table_rows_in_window(conn, table, org_id, ts_cols, start_excl_ts, cutoff_ts)?;
            self.withheld.record(class, n);
        }
        let msg_n = count_message_index_in_window(
            conn,
            org_id,
            start_excl_ts,
            cutoff_ts,
            seq_bounds,
            already_redacted_ulids,
        )?;
        self.withheld.record(CLASS_PRIVATE_MESSAGES, msg_n);
        Ok(())
    }

    /// Inspect a ledger event before writing it to `ledger/events.jsonl`.
    ///
    /// - Restricted/private channels (`agent.message.*`, `agent.mailbox.*`,
    ///   `agent.lifecycle.handoff`, `agent.lifecycle.handoff_hook`,
    ///   `agent.conversation.handoff`, `private.*`, `*.private.*`) and rows
    ///   explicitly marked private return `Ok(LedgerEgressAction::RedactToHashOnly(class))`
    ///   so export writes a hash-only chain-link stub and records the count in
    ///   `withheld.json`.
    /// - Any secret, token, credential, or PEM key on a non-private channel
    ///   refuses the export outright (`Err(egress_refused)`).
    pub fn inspect_ledger_event(&mut self, channel: &str, payload_str: &str) -> UaResult<LedgerEgressAction> {
        if let Some(class) = restricted_channel_class(channel) {
            self.withheld.record(class, 1);
            return Ok(LedgerEgressAction::RedactToHashOnly(class));
        }
        if let Some(v) = find_forbidden_in_ledger_event(channel, payload_str) {
            if v.class == CLASS_PRIVATE_RECORDS || v.class == CLASS_PRIVATE_MESSAGES {
                self.withheld.record(v.class, 1);
                return Ok(LedgerEgressAction::RedactToHashOnly(v.class));
            }
            self.withheld.record(v.class, 1);
            return Err(UaError::denied(
                "egress_refused",
                format!("refusing to export ledger event on {channel:?}: {} ({})", v.detail, v.class),
            ));
        }
        Ok(LedgerEgressAction::Allow)
    }

    /// Inspect an arbitrary structured bundle record (approval receipt,
    /// policy revision, artifact entry) before writing. Refuses on violation.
    pub fn check_structured_record(&mut self, context: &str, value: &Value) -> UaResult<()> {
        if let Some(v) = find_forbidden_in_value(value) {
            self.withheld.record(v.class, 1);
            return Err(UaError::denied(
                "egress_refused",
                format!("refusing to export {context}: {} ({})", v.detail, v.class),
            ));
        }
        Ok(())
    }

    /// Filter an optional evidence row: returns `Ok(false)` (withholding and
    /// counting it in `withheld.json`) if the row is marked private, or
    /// `Err(...)` if it leaks secret/credential material.
    pub fn allow_evidence_row(&mut self, value: &Value) -> UaResult<bool> {
        if let Some(v) = find_forbidden_in_value(value) {
            self.withheld.record(v.class, 1);
            if v.class == CLASS_PRIVATE_RECORDS || v.class == CLASS_PRIVATE_MESSAGES {
                return Ok(false);
            }
            return Err(UaError::denied(
                "egress_refused",
                format!("refusing to export evidence row: {} ({})", v.detail, v.class),
            ));
        }
        Ok(true)
    }

    pub fn into_report(self) -> WithheldReport {
        self.withheld
    }
}

/// Inspect an unredacted ledger event `(channel, payload_str)` for forbidden
/// private or secret content. Shared by both the exporter and the offline
/// verifier.
pub fn find_forbidden_in_ledger_event(channel: &str, payload_str: &str) -> Option<EgressViolation> {
    if let Some(class) = restricted_channel_class(channel) {
        return Some(EgressViolation { class, detail: format!("restricted/private channel {channel:?}") });
    }
    if let Some(v) = find_forbidden_in_text(payload_str) {
        return Some(v);
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(payload_str)
        && let Some(v) = find_forbidden_in_value(&parsed)
    {
        return Some(v);
    }
    None
}

/// Recursively inspect any JSON value for forbidden private markers, secret
/// keys (case- and separator-insensitive, string and non-string values),
/// secret value patterns, and JSON nested inside strings. Shared by exporter
/// and verifier.
pub fn find_forbidden_in_value(value: &Value) -> Option<EgressViolation> {
    find_forbidden_in_value_depth(value, 0)
}

fn find_forbidden_in_value_depth(value: &Value, depth: usize) -> Option<EgressViolation> {
    match value {
        Value::String(s) => {
            if let Some(v) = find_forbidden_in_text(s) {
                return Some(v);
            }
            if depth < MAX_NESTED_JSON_DEPTH {
                let trimmed = s.trim();
                if (trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"'))
                    && let Ok(nested) = serde_json::from_str::<Value>(trimmed)
                    && let Some(v) = find_forbidden_in_value_depth(&nested, depth + 1)
                {
                    return Some(v);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(|item| find_forbidden_in_value_depth(item, depth)),
        Value::Object(map) => {
            for (k, v) in map {
                let lk = k.to_ascii_lowercase();
                let norm = normalize_key(k);

                // Private markers (`private: true`, `visibility: "private"`, `sensitivity: "private"`, etc.).
                if lk == "private" && v.as_bool() == Some(true) {
                    return Some(EgressViolation {
                        class: CLASS_PRIVATE_RECORDS,
                        detail: "record has private=true".into(),
                    });
                }
                if matches!(lk.as_str(), "visibility" | "sensitivity" | "classification")
                    && v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("private"))
                {
                    return Some(EgressViolation {
                        class: CLASS_PRIVATE_RECORDS,
                        detail: format!("record has {k}=\"private\""),
                    });
                }
                if lk == "labels"
                    && let Some(arr) = v.as_array()
                    && arr.iter().any(|x| x.as_str().is_some_and(|s| s.eq_ignore_ascii_case("private")))
                {
                    return Some(EgressViolation {
                        class: CLASS_PRIVATE_RECORDS,
                        detail: "record carries \"private\" label".into(),
                    });
                }

                // Case- and separator-insensitive secret key matching across ALL
                // value types (strings, objects, arrays, numbers, booleans).
                if let Some(class) = secret_key_class(&norm)
                    && !is_safe_redacted_value(v)
                {
                    return Some(EgressViolation {
                        class,
                        detail: format!("non-redacted secret field {k:?}"),
                    });
                }

                if let Some(found) = find_forbidden_in_value_depth(v, depth) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn is_cred_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_boundary_before(text: &str, pos: usize) -> bool {
    text[..pos].chars().next_back().is_none_or(|c| !is_cred_char(c))
}

fn has_prefixed_token(text: &str, prefix: &str, min_tail: usize) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find(prefix) {
        let boundary = is_boundary_before(rest, pos);
        let tail_start = pos + prefix.len();
        let tail_len = rest[tail_start..].chars().take_while(|c| is_cred_char(*c)).count();
        if boundary && tail_len >= min_tail {
            return true;
        }
        rest = &rest[tail_start..];
    }
    false
}

/// Detect a hub session credential (`uas_<16+ token chars>`).
pub fn contains_session_credential(text: &str) -> bool {
    has_prefixed_token(text, CREDENTIAL_PREFIX, CREDENTIAL_MIN_TAIL)
}

fn contains_pem_private_key(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    let mut rest = upper.as_str();
    while let Some(pos) = rest.find("-----BEGIN ") {
        let after = &rest[pos + "-----BEGIN ".len()..];
        if let Some(end) = after.find("-----") {
            let label = &after[..end];
            if label.contains("PRIVATE KEY") {
                return true;
            }
            rest = &after[end + 5..];
        } else {
            break;
        }
    }
    false
}

fn contains_bearer_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(rel) = lower[offset..].find("bearer ") {
        let pos = offset + rel;
        let boundary = text[..pos].chars().next_back().is_none_or(|c| !c.is_ascii_alphanumeric());
        let after = text[pos + "bearer ".len()..].trim_start();
        let tok: String = after
            .chars()
            .take_while(|c| !c.is_whitespace() && !matches!(c, '"' | '\'' | ',' | ';' | ')' | '}' | ']'))
            .collect();
        if boundary
            && tok.len() >= 6
            && !tok.eq_ignore_ascii_case("[redacted]")
            && !tok.eq_ignore_ascii_case("[redacted-credential]")
            && !(tok.starts_with('<') && tok.ends_with('>'))
        {
            return true;
        }
        offset = pos + "bearer ".len();
    }
    false
}

fn contains_aws_access_key(text: &str) -> bool {
    for prefix in ["AKIA", "ASIA"] {
        let mut rest = text;
        while let Some(pos) = rest.find(prefix) {
            let before_ok = is_boundary_before(rest, pos);
            let tail = &rest[pos + 4..];
            let count = tail.chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit()).count();
            let after_ok = tail.chars().nth(count).is_none_or(|c| !is_cred_char(c));
            if before_ok && count == 16 && after_ok {
                return true;
            }
            rest = &rest[pos + 4..];
        }
    }
    false
}

fn contains_jwt(text: &str) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find("eyJ") {
        let before_ok = is_boundary_before(rest, pos);
        let cand: String = rest[pos..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
            .collect();
        let parts: Vec<&str> = cand.split('.').collect();
        if before_ok
            && parts.len() == 3
            && parts[0].len() >= 10
            && parts[1].starts_with("eyJ")
            && parts[1].len() >= 10
            && parts[2].len() >= 10
        {
            return true;
        }
        rest = &rest[pos + 3..];
    }
    false
}

/// Scan free text for raw secret/token value patterns: hub `uas_` credentials,
/// PEM private key blocks, `Bearer ` tokens, GitHub/PAT/Slack/AWS/Google/
/// Anthropic/OpenAI/Stripe/GitLab/npm/PyPI/HuggingFace tokens, and JWTs.
pub fn find_forbidden_in_text(text: &str) -> Option<EgressViolation> {
    if contains_session_credential(text) {
        return Some(EgressViolation {
            class: CLASS_SESSION_CREDENTIALS,
            detail: "contains hub session credential (uas_...)".into(),
        });
    }
    if contains_pem_private_key(text) {
        return Some(EgressViolation {
            class: CLASS_MANAGED_SECRETS,
            detail: "contains PEM private key block".into(),
        });
    }
    if contains_bearer_token(text) {
        return Some(EgressViolation {
            class: CLASS_AUTH_TOKENS,
            detail: "contains Bearer authorization token".into(),
        });
    }
    const AUTH_TOKEN_PREFIXES: &[(&str, usize)] = &[
        ("ghp_", 10),
        ("gho_", 10),
        ("ghu_", 10),
        ("ghs_", 10),
        ("ghr_", 10),
        ("github_pat_", 10),
        ("glpat-", 10),
        ("xoxb-", 10),
        ("xoxp-", 10),
        ("xoxa-", 10),
        ("xoxr-", 10),
        ("xoxs-", 10),
        ("xapp-", 10),
        ("npm_", 16),
        ("pypi-", 16),
        ("hf_", 16),
        ("pat_", 12),
    ];
    for &(prefix, min_tail) in AUTH_TOKEN_PREFIXES {
        if has_prefixed_token(text, prefix, min_tail) {
            return Some(EgressViolation {
                class: CLASS_AUTH_TOKENS,
                detail: format!("contains token matching prefix {prefix:?}"),
            });
        }
    }
    const PROVIDER_KEY_PREFIXES: &[(&str, usize)] = &[
        ("sk-ant-", 12),
        ("sk-proj-", 12),
        ("sk_live_", 10),
        ("sk_test_", 10),
        ("rk_live_", 10),
        ("rk_test_", 10),
        ("sk-", 16),
        ("AIza", 20),
    ];
    for &(prefix, min_tail) in PROVIDER_KEY_PREFIXES {
        if has_prefixed_token(text, prefix, min_tail) {
            return Some(EgressViolation {
                class: CLASS_PROVIDER_CREDENTIALS,
                detail: format!("contains credential matching prefix {prefix:?}"),
            });
        }
    }
    if contains_aws_access_key(text) {
        return Some(EgressViolation {
            class: CLASS_PROVIDER_CREDENTIALS,
            detail: "contains AWS access key".into(),
        });
    }
    if contains_jwt(text) {
        return Some(EgressViolation {
            class: CLASS_AUTH_TOKENS,
            detail: "contains JWT bearer token".into(),
        });
    }
    None
}

fn table_exists(conn: &Connection, table: &str) -> UaResult<bool> {
    Ok(conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()?
        .unwrap_or(false))
}

fn column_exists(conn: &Connection, table: &str, col: &str) -> UaResult<bool> {
    Ok(conn
        .query_row(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?1"), [col], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false))
}

fn in_time_window(ts: &str, start_excl_ts: Option<&str>, cutoff_ts: &str) -> bool {
    if cmp_ts(ts, cutoff_ts) == Ordering::Greater {
        return false;
    }
    if let Some(start) = start_excl_ts
        && cmp_ts(ts, start) != Ordering::Greater
    {
        return false;
    }
    true
}

fn count_table_rows_in_window(
    conn: &Connection,
    table: &str,
    org_id: Option<&str>,
    ts_cols: &[&str],
    start_excl_ts: Option<&str>,
    cutoff_ts: &str,
) -> UaResult<u64> {
    if !table_exists(conn, table)? {
        return Ok(0);
    }
    let has_org = column_exists(conn, table, "org_id")?;
    if org_id.is_some() && !has_org {
        // In org scope, hub-global tables without org_id are never counted to avoid
        // leaking hub-wide volume.
        return Ok(0);
    }
    let mut ts_col: Option<&str> = None;
    for &c in ts_cols {
        if column_exists(conn, table, c)? {
            ts_col = Some(c);
            break;
        }
    }
    let Some(ts_col) = ts_col else {
        // Without a timestamp column, a table cannot be deterministically scoped
        // to a historical checkpoint.
        return Ok(0);
    };

    let timestamps: Vec<String> = match org_id {
        Some(org) => {
            let mut stmt =
                conn.prepare(&format!("SELECT \"{ts_col}\" FROM \"{table}\" WHERE org_id = ?1"))?;
            stmt.query_map([org], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?
        }
        None => {
            let mut stmt = conn.prepare(&format!("SELECT \"{ts_col}\" FROM \"{table}\""))?;
            stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?
        }
    };
    let count = timestamps.iter().filter(|ts| in_time_window(ts, start_excl_ts, cutoff_ts)).count();
    Ok(count as u64)
}

fn count_message_index_in_window(
    conn: &Connection,
    org_id: Option<&str>,
    start_excl_ts: Option<&str>,
    cutoff_ts: &str,
    seq_bounds: Option<(i64, i64)>,
    already_redacted_ulids: &BTreeSet<String>,
) -> UaResult<u64> {
    if !table_exists(conn, "message_index")? {
        return Ok(0);
    }
    let has_org = column_exists(conn, "message_index", "org_id")?;
    if org_id.is_some() && !has_org {
        return Ok(0);
    }
    let has_ulid = column_exists(conn, "message_index", "event_ulid")?;
    let has_seq = column_exists(conn, "message_index", "event_seq")?;
    let has_created = column_exists(conn, "message_index", "created_at")?;
    if !has_seq && !has_created {
        return Ok(0);
    }

    let ulid_expr = if has_ulid { "event_ulid" } else { "NULL" };
    let seq_expr = if has_seq { "event_seq" } else { "NULL" };
    let ts_expr = if has_created { "created_at" } else { "NULL" };

    let rows: Vec<(Option<String>, Option<i64>, Option<String>)> = match org_id {
        Some(org) => {
            let mut stmt = conn.prepare(&format!(
                "SELECT {ulid_expr}, {seq_expr}, {ts_expr} FROM message_index WHERE org_id = ?1"
            ))?;
            stmt.query_map([org], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?
        }
        None => {
            let mut stmt =
                conn.prepare(&format!("SELECT {ulid_expr}, {seq_expr}, {ts_expr} FROM message_index"))?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?
        }
    };

    let mut count = 0u64;
    for (ulid, ev_seq, created_at) in rows {
        if let Some(u) = ulid.as_deref()
            && already_redacted_ulids.contains(u)
        {
            continue;
        }
        let in_window = if let (Some((min_excl, max_incl)), Some(s)) = (seq_bounds, ev_seq) {
            s > min_excl && s <= max_incl
        } else if let Some(ts) = created_at.as_deref() {
            in_time_window(ts, start_excl_ts, cutoff_ts)
        } else {
            false
        };
        if in_window {
            count += 1;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn egress_filter_catches_all_twelve_review_probes_and_forbidden_classes() {
        // 1. GitHub token in `token` key.
        assert!(
            find_forbidden_in_ledger_event(
                "agent.log",
                r#"{"token":"ghp_0123456789abcdef0123456789abcdef0123"}"#
            )
            .is_some()
        );
        // 2. GitHub PAT inside free-text notes.
        assert!(
            find_forbidden_in_ledger_event(
                "agent.log",
                r#"{"notes":"pushed using github_pat_11ABCDEF0123456789_xyz9876543210abcdef"}"#,
            )
            .is_some()
        );
        // 3. Bearer Authorization header nested inside `headers`.
        assert!(
            find_forbidden_in_ledger_event(
                "sdk.http",
                r#"{"headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"}}"#,
            )
            .is_some()
        );
        // 4. `password` holding a non-string JSON object.
        assert!(find_forbidden_in_ledger_event("sdk.auth", r#"{"password":{"value":"hunter2"}}"#).is_some());
        // 5. `api_key` holding a non-string JSON array.
        assert!(find_forbidden_in_ledger_event("sdk.auth", r#"{"api_key":["key-one","key-two"]}"#).is_some());
        // 6. camelCase `accessToken`.
        assert!(
            find_forbidden_in_ledger_event("sdk.auth", r#"{"accessToken":"opaque-tok-value"}"#).is_some()
        );
        // 7. Secret inside a JSON-encoded string.
        assert!(
            find_forbidden_in_ledger_event(
                "sdk.raw",
                r#"{"blob":"{\"clientSecret\":\"super-secret-value\"}"}"#,
            )
            .is_some()
        );
        // 8. PEM private key block.
        assert!(
            find_forbidden_in_ledger_event(
                "sdk.key",
                r#"{"note":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----"}"#,
            )
            .is_some()
        );
        // 9. agent.lifecycle.handoff_hook.
        assert_eq!(
            find_forbidden_in_ledger_event("agent.lifecycle.handoff_hook", r#"{"note":"hook"}"#)
                .unwrap()
                .class,
            CLASS_PRIVATE_RECORDS
        );
        // 10. agent.mailbox.read.
        assert_eq!(
            find_forbidden_in_ledger_event("agent.mailbox.read", r#"{"message_id":"m1"}"#).unwrap().class,
            CLASS_PRIVATE_MESSAGES
        );
        // 11. agent.message.inform with `text`.
        assert_eq!(
            find_forbidden_in_ledger_event("agent.message.inform", r#"{"text":"private update"}"#)
                .unwrap()
                .class,
            CLASS_PRIVATE_MESSAGES
        );
        // 12. agent.conversation.handoff.
        assert_eq!(
            find_forbidden_in_ledger_event("agent.conversation.handoff", r#"{"conversation_id":"c1"}"#)
                .unwrap()
                .class,
            CLASS_PRIVATE_RECORDS
        );

        // Additional value & marker checks.
        assert_eq!(
            find_forbidden_in_value(&json!({ "visibility": "private", "id": 1 })).unwrap().class,
            CLASS_PRIVATE_RECORDS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "private": true })).unwrap().class,
            CLASS_PRIVATE_RECORDS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "labels": ["audit", "private"] })).unwrap().class,
            CLASS_PRIVATE_RECORDS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "note": "leaked uas_0123456789abcdef0123" })).unwrap().class,
            CLASS_SESSION_CREDENTIALS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "x-api-key": "opaque" })).unwrap().class,
            CLASS_PROVIDER_CREDENTIALS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "msg": "Bearer secret123456" })).unwrap().class,
            CLASS_AUTH_TOKENS
        );

        // Clean hub metadata and redacted placeholders pass.
        assert!(find_forbidden_in_value(&json!({ "api_key": "[redacted]", "ok": true })).is_none());
        assert!(find_forbidden_in_value(&json!({ "authorization_id": 42, "input_tokens": 1200 })).is_none());
        assert!(find_forbidden_in_ledger_event("agent.task.created", r#"{"task_id":1}"#).is_none());
    }
}
