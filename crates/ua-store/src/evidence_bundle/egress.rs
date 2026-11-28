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
//!   sessions, cookies, GitHub/PAT/Slack/AWS/Google/JWT tokens, `Bearer` and
//!   `Basic` headers, URL userinfo, Slack webhooks)
//! - passkeys
//! - session credentials (`session_credentials` rows and raw `uas_<16+>` values)
//! - private/restricted ledger channels (`agent.message.*`, `agent.mailbox.*`,
//!   `agent.lifecycle.handoff`, `agent.lifecycle.handoff_hook`,
//!   `agent.conversation.handoff`, `private.*`, `*.private.*`) and records
//!   marked private
//!
//! Restricted/private ledger channels, records marked private, and payloads
//! that are not strict JSON (or that the scanner cannot walk completely) are
//! exported as hash-only chain-link stubs (`redacted: true`). Any secret or
//! token material on a non-private record refuses the export outright.
//!
//! The scanner fails closed: a payload with duplicate keys, `NaN`/`Infinity`,
//! trailing text or nesting past the JSON depth limit, or a single string
//! longer than [`MAX_SCANNED_STRING_BYTES`], is never reported as clean. Every
//! scan is linear in the input length.

use std::collections::BTreeMap;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use ua_core::{UaError, UaResult};
use unicode_normalization::UnicodeNormalization;

use super::export_schema::{envelope_is_typed, schema_stub_class};
use crate::evidence::CheckpointClass;

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
/// A ledger payload the scanner cannot walk completely (not strict JSON:
/// duplicate keys, `NaN`/`Infinity`, trailing text, nesting past the depth
/// limit, or a string past [`MAX_SCANNED_STRING_BYTES`]). Exported as a
/// hash-only stub; never exported in clear.
pub const CLASS_UNPARSEABLE_PAYLOAD: &str = "unparseable_payload";
/// Approvals of a non-default organization whose ledger events sit in the
/// default organization's ledger (`ORG-EVENT-DEFAULT`), so an `org` bundle for
/// that organization cannot carry their receipts.
pub const CLASS_APPROVALS_IN_DEFAULT_LEDGER: &str = "approvals_in_default_ledger";

/// A row the backstop pattern scanner flagged (a token, key or credential
/// pattern in a row the allow-list would otherwise export). Stubbed and
/// counted; never a refusal, so row contents cannot block an export.
pub const CLASS_SCANNER_WITHHELD: &str = "scanner_withheld";

/// Redacted stub classes the verifier accepts on a `redacted: true` row.
pub const STUB_CLASSES: &[&str] = &[
    CLASS_PRIVATE_MESSAGES,
    CLASS_PRIVATE_RECORDS,
    CLASS_CROSS_ORG_EVENTS,
    CLASS_UNPARSEABLE_PAYLOAD,
    super::export_schema::CLASS_UNLISTED_PAYLOAD,
    super::export_schema::CLASS_FREE_TEXT_PAYLOAD,
    CLASS_SCANNER_WITHHELD,
];

/// Longest single string the scanner inspects. A longer string fails closed
/// ([`CLASS_UNPARSEABLE_PAYLOAD`]).
pub const MAX_SCANNED_STRING_BYTES: usize = 1024 * 1024;

/// Maximum JSON container depth across a payload and every JSON document
/// nested inside its strings. Past it the scan fails closed.
const MAX_TOTAL_DEPTH: usize = 512;
/// Maximum levels of JSON nested inside JSON strings. Past it the scan fails
/// closed.
const MAX_STRING_NESTING: usize = 16;
/// Longest key the embedded-key scanner reads inside free text.
const MAX_EMBEDDED_KEY_LEN: usize = 128;

const CREDENTIAL_PREFIX: &str = "uas_";
const CREDENTIAL_MIN_TAIL: usize = 16;

/// Skeleton substrings that mark a key as secret wherever they occur
/// (`accessToken`, `x-api-key`, `Authorization`, `private_key_pem`,
/// `Set-Cookie`, `wallet_mnemonic`, ...).
const STRONG_KEY_SUBSTRINGS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "passkey",
    "authorization",
    "credential",
    "apikey",
    "privatekey",
    "signingseed",
    "cookie",
    "mnemonic",
    "sessionkey",
    "bearer",
];

/// Whole words that mark a key as secret when they end the key or are
/// followed by a word from [`SECRETISH_FOLLOWERS`] (`pwd`, `db_pass`, `auth`,
/// `basic_auth`, `auth_header`, `seed_phrase`). `auth_method` and
/// `tests_passed` stay ordinary keys.
const WEAK_KEY_WORDS: &[&str] = &["pwd", "pw", "pass", "auth", "seed", "session"];
/// Weak words that mark a key secret only with a follower from
/// [`SECRETISH_FOLLOWERS`] (`session_key`, `session_secret`), because the bare
/// word names an identifier on the hub (`owner_session`, `session_status`).
const WEAK_FOLLOWER_ONLY: &[&str] = &["session"];
const SECRETISH_FOLLOWERS: &[&str] =
    &["key", "value", "secret", "word", "phrase", "code", "header", "string", "data", "blob", "material"];

/// Last words that make a key id-shaped (`token_id`, `token_ids`,
/// `credential_id`, `session_id`).
const ID_WORDS: &[&str] = &["id", "ids", "uuid", "ulid", "seq", "idx", "index", "no", "number"];
/// Last words that make a key count-shaped (`revoked_tokens`, `input_tokens`,
/// `token_count`, `revoked_sessions`).
const COUNT_WORDS: &[&str] = &[
    "count",
    "counts",
    "total",
    "totals",
    "num",
    "used",
    "budget",
    "limit",
    "max",
    "min",
    "size",
    "len",
    "length",
    "tokens",
    "sessions",
    "credentials",
    "secrets",
    "passes",
    "cookies",
    "passkeys",
    "keys",
    "seeds",
];

/// Keys whose string value `"private"` marks a record private.
const PRIVACY_LEVEL_KEYS: &[&str] = &["visibility", "sensitivity", "classification", "privacy"];
/// Keys whose array values carry labels.
const LABEL_KEYS: &[&str] = &["labels", "tags"];

/// Reason a record was refused by the egress filter or verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressViolation {
    pub class: &'static str,
    pub detail: String,
}

impl EgressViolation {
    fn new(class: &'static str, detail: impl Into<String>) -> Self {
        Self { class, detail: detail.into() }
    }

    /// Whether this violation is withheld as a hash-only stub rather than
    /// refused (private records and payloads the scanner cannot walk).
    pub fn is_stubbable(&self) -> bool {
        matches!(self.class, CLASS_PRIVATE_RECORDS | CLASS_PRIVATE_MESSAGES | CLASS_UNPARSEABLE_PAYLOAD)
    }
}

/// Action taken by [`EgressFilter::inspect_ledger_event`] on a ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerEgressAction {
    /// Safe to export in full.
    Allow,
    /// Private/restricted or unwalkable record: strip channel/payload/parties
    /// and emit a hash-only chain-link stub under the named withheld class.
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
    let lower = channel.trim().to_ascii_lowercase();
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

    /// Decide how a ledger row leaves the hub: in clear, or as a hash-only
    /// stub under a counted withheld class. Never refuses: row contents can
    /// never block an export (see [`ledger_row_stub_class`]).
    pub fn inspect_ledger_event(
        &mut self,
        class: CheckpointClass,
        channel: &str,
        payload_str: &str,
        envelope: &[Option<&str>],
    ) -> LedgerEgressAction {
        match ledger_row_stub_class(class, channel, payload_str, envelope) {
            Some((stub_class, _)) => {
                self.withheld.record(stub_class, 1);
                LedgerEgressAction::RedactToHashOnly(stub_class)
            }
            None => LedgerEgressAction::Allow,
        }
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

// ---------------------------------------------------------------------------
// Strict JSON
// ---------------------------------------------------------------------------

/// Parse `text` as strict JSON: one value, no trailing text, no duplicate
/// object keys, no `NaN`/`Infinity`, nesting within `serde_json`'s 128-level
/// limit. Shared by exporter and verifier; anything it refuses is never
/// reported as clean.
pub fn parse_strict_json(text: &str) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_str(text);
    let v = StrictSeed.deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

/// Parse `bytes` as strict JSON (UTF-8 required).
pub fn parse_strict_json_bytes(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))?;
    parse_strict_json(text)
}

struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("strict JSON")
    }
    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        Number::from_f64(v).map(Value::Number).ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }
    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(StrictSeed)? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate key {k:?}")));
            }
            let v = map.next_value_seed(StrictSeed)?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}

// ---------------------------------------------------------------------------
// Key classification
// ---------------------------------------------------------------------------

/// ASCII look-alikes for common confusable letters (Cyrillic, Greek, Latin
/// extensions). Applied after NFKC, which already folds full-width and
/// mathematical forms.
fn confusable_ascii(c: char) -> Option<char> {
    Some(match c {
        'а' => 'a',
        'А' => 'A',
        'в' => 'b',
        'В' => 'B',
        'е' | 'ё' => 'e',
        'Е' | 'Ё' => 'E',
        'к' => 'k',
        'К' => 'K',
        'м' => 'm',
        'М' => 'M',
        'н' => 'h',
        'Н' => 'H',
        'о' => 'o',
        'О' => 'O',
        'р' => 'p',
        'Р' => 'P',
        'с' => 'c',
        'С' => 'C',
        'т' => 't',
        'Т' => 'T',
        'у' => 'y',
        'У' => 'Y',
        'х' => 'x',
        'Х' => 'X',
        'ѕ' => 's',
        'Ѕ' => 'S',
        'і' | 'ї' => 'i',
        'І' | 'Ї' => 'I',
        'ј' => 'j',
        'Ј' => 'J',
        'ԁ' => 'd',
        'ӏ' | 'Ӏ' => 'l',
        'ԛ' => 'q',
        'ԝ' => 'w',
        'һ' => 'h',
        'ɡ' => 'g',
        'α' => 'a',
        'Α' => 'A',
        'β' => 'b',
        'Β' => 'B',
        'ε' => 'e',
        'Ε' => 'E',
        'η' => 'n',
        'Η' => 'H',
        'ι' => 'i',
        'Ι' => 'I',
        'κ' => 'k',
        'Κ' => 'K',
        'μ' => 'u',
        'Μ' => 'M',
        'ν' => 'v',
        'Ν' => 'N',
        'ο' => 'o',
        'Ο' => 'O',
        'ρ' => 'p',
        'Ρ' => 'P',
        'τ' => 't',
        'Τ' => 'T',
        'υ' => 'u',
        'Υ' => 'Y',
        'χ' => 'x',
        'Χ' => 'X',
        'Ζ' => 'Z',
        'ω' => 'w',
        'ı' => 'i',
        'ȷ' => 'j',
        'ɑ' => 'a',
        'ɩ' | 'ɪ' => 'i',
        'ʀ' => 'r',
        'ѵ' => 'v',
        'ⅰ' => 'i',
        _ => return None,
    })
}

/// Characters dropped from a key before matching: zero-width and format
/// characters, combining marks and the soft hyphen.
fn is_ignorable_key_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206F}'
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}'
        | '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}'
        | '\u{E0000}'..='\u{E007F}')
}

/// A key's skeleton split into lowercase ASCII words: NFKC, ignorable
/// characters dropped, confusables folded to ASCII, then split on any other
/// character and on lower-to-upper camelCase boundaries.
fn key_words(key: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in key.nfkc() {
        if is_ignorable_key_char(c) {
            continue;
        }
        let mapped = if c.is_ascii_alphanumeric() { Some(c) } else { confusable_ascii(c) };
        match mapped {
            Some(m) => {
                if m.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                prev_lower = m.is_ascii_lowercase() || m.is_ascii_digit();
                cur.push(m.to_ascii_lowercase());
            }
            None => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
                prev_lower = false;
            }
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyStrength {
    /// A strong substring (`token`, `password`, ...): only integers or null
    /// under an id/count-shaped key are metadata.
    Strong,
    /// A weak word (`session`, `auth`, ...): an id-shaped key may also hold
    /// opaque identifier strings (`session_id`).
    Weak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SecretKey {
    class: &'static str,
    strength: KeyStrength,
    id_or_count: bool,
}

fn secret_class_for(norm: &str, weak_word: Option<&str>) -> &'static str {
    if norm.contains("credential") {
        CLASS_SESSION_CREDENTIALS
    } else if norm.contains("passkey") {
        CLASS_PASSKEYS
    } else if norm.contains("apikey") || norm.contains("clientsecret") {
        CLASS_PROVIDER_CREDENTIALS
    } else if norm.contains("token")
        || norm.contains("authorization")
        || norm.contains("cookie")
        || norm.contains("bearer")
        || norm.contains("sessionkey")
        || matches!(weak_word, Some("auth" | "session"))
    {
        CLASS_AUTH_TOKENS
    } else {
        CLASS_MANAGED_SECRETS
    }
}

fn classify_secret_key(key: &str) -> Option<SecretKey> {
    let words = key_words(key);
    if words.is_empty() {
        return None;
    }
    let norm: String = words.concat();
    let last = words.last().map(String::as_str).unwrap_or("");
    let id_or_count = ID_WORDS.contains(&last)
        || COUNT_WORDS.contains(&last)
        || (words.len() == 1 && ["id", "ids", "count", "total"].iter().any(|s| norm.ends_with(s)));
    if STRONG_KEY_SUBSTRINGS.iter().any(|s| norm.contains(s)) {
        return Some(SecretKey {
            class: secret_class_for(&norm, None),
            strength: KeyStrength::Strong,
            id_or_count,
        });
    }
    for (i, w) in words.iter().enumerate() {
        if !WEAK_KEY_WORDS.contains(&w.as_str()) {
            continue;
        }
        let next = words.get(i + 1).map(String::as_str);
        let matches = match next {
            None => !WEAK_FOLLOWER_ONLY.contains(&w.as_str()),
            Some(n) => SECRETISH_FOLLOWERS.contains(&n),
        };
        let id_suffix = matches!(next, Some(n) if ID_WORDS.contains(&n) || COUNT_WORDS.contains(&n))
            && i + 2 == words.len();
        if matches || id_suffix {
            return Some(SecretKey {
                class: secret_class_for(&norm, Some(w)),
                strength: KeyStrength::Weak,
                id_or_count: id_or_count || id_suffix,
            });
        }
    }
    None
}

/// Whether `key`'s skeleton names a private marker (`private`, `is_private`,
/// `privateFlag`; not `private_key`, which is a secret).
fn is_private_marker_key(key: &str) -> bool {
    let norm: String = key_words(key).concat();
    norm.contains("private") && !norm.contains("privatekey")
}

fn is_privacy_level_key(key: &str) -> bool {
    let norm: String = key_words(key).concat();
    PRIVACY_LEVEL_KEYS.contains(&norm.as_str())
}

fn is_label_key(key: &str) -> bool {
    let norm: String = key_words(key).concat();
    LABEL_KEYS.contains(&norm.as_str())
}

fn is_private_word(s: &str) -> bool {
    s.trim().eq_ignore_ascii_case("private")
}

fn is_truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_i64() == Some(1),
        Value::String(s) => {
            let t = s.trim().to_ascii_lowercase();
            matches!(t.as_str(), "true" | "yes" | "1" | "on" | "private")
        }
        _ => false,
    }
}

fn is_placeholder_str(s: &str) -> bool {
    let t = s.trim();
    t.is_empty()
        || t.eq_ignore_ascii_case("[redacted]")
        || t.eq_ignore_ascii_case("[redacted-credential]")
        || t.eq_ignore_ascii_case("[redacted-label]")
}

/// The shape of a value under a secret-matching key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueShape {
    /// `null`, a placeholder string, `[]` or `{}`.
    Empty,
    Bool,
    /// An integer, or a non-empty array of integers.
    Integers,
    /// A non-placeholder string, or an array of strings.
    Strings,
    /// Anything else (a float, an object, a mixed array).
    Other,
}

fn value_shape(v: &Value) -> ValueShape {
    match v {
        Value::Null => ValueShape::Empty,
        Value::Bool(_) => ValueShape::Bool,
        Value::Number(n) if n.is_i64() || n.is_u64() => ValueShape::Integers,
        Value::Number(_) => ValueShape::Other,
        Value::String(s) if is_placeholder_str(s) => ValueShape::Empty,
        Value::String(_) => ValueShape::Strings,
        Value::Array(a) if a.is_empty() => ValueShape::Empty,
        Value::Array(a) if a.iter().all(|x| x.as_i64().is_some() || x.as_u64().is_some()) => {
            ValueShape::Integers
        }
        Value::Array(a) if a.iter().all(Value::is_string) => ValueShape::Strings,
        Value::Array(_) => ValueShape::Other,
        Value::Object(m) if m.is_empty() => ValueShape::Empty,
        Value::Object(_) => ValueShape::Other,
    }
}

/// Whether a value of `shape` under secret key `k` is material (refused).
///
/// - `null`, placeholders, empty containers and booleans are never material.
/// - Integers (and integer arrays) are metadata only under an id- or
///   count-shaped key (`token_id: 7`, `revoked_tokens: 2`).
/// - Strings are metadata only under a weak, id-shaped key (`session_id`).
/// - Everything else is material.
fn is_material(k: SecretKey, shape: ValueShape) -> bool {
    match shape {
        ValueShape::Empty | ValueShape::Bool => false,
        ValueShape::Integers => !k.id_or_count,
        ValueShape::Strings => !(k.strength == KeyStrength::Weak && k.id_or_count),
        ValueShape::Other => true,
    }
}

// ---------------------------------------------------------------------------
// Value walk
// ---------------------------------------------------------------------------

/// Why a ledger row may not leave the hub in clear, as `(stub class, detail)`,
/// or `None` when it may. Shared by exporter (which stubs) and verifier
/// (which refuses a row in clear that this would stub). In order:
/// 1. restricted/private channels;
/// 2. payloads that are not strict JSON;
/// 3. the allow-list ([`super::export_schema`]): unlisted channels, unknown
///    keys, mistyped values, free text;
/// 4. envelope fields (originator, episode, causal parent, dedupe key) that
///    are not safe labels;
/// 5. the backstop pattern scanner (private markers stub as private records,
///    any secret pattern as [`CLASS_SCANNER_WITHHELD`]).
pub fn ledger_row_stub_class(
    class: CheckpointClass,
    channel: &str,
    payload_str: &str,
    envelope: &[Option<&str>],
) -> Option<(&'static str, String)> {
    if let Some(c) = restricted_channel_class(channel) {
        return Some((c, format!("restricted/private channel {channel:?}")));
    }
    let parsed = match parse_strict_json(payload_str) {
        Ok(v) => v,
        Err(e) => return Some((CLASS_UNPARSEABLE_PAYLOAD, format!("payload is not strict JSON ({e})"))),
    };
    if let Some(c) = schema_stub_class(channel, &parsed, class) {
        return Some((
            c,
            format!("channel {channel:?} row is not exported in clear by the egress allow-list"),
        ));
    }
    if !envelope_is_typed(envelope) {
        return Some((
            super::export_schema::CLASS_UNLISTED_PAYLOAD,
            "row envelope field is not a safe label".into(),
        ));
    }
    // The allow-list fixed every key and type, so the backstop scans values
    // only: every string the row would carry in clear, and its envelope.
    let mut strings = Vec::new();
    collect_strings(&parsed, &mut strings);
    let scanned =
        strings.into_iter().chain(envelope.iter().flatten().copied()).find_map(find_forbidden_in_text);
    if let Some(v) = scanned {
        return Some((CLASS_SCANNER_WITHHELD, v.detail));
    }
    None
}

fn collect_strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect_strings(x, out)),
        Value::Object(m) => m.iter().for_each(|(k, x)| {
            out.push(k);
            collect_strings(x, out);
        }),
        _ => {}
    }
}

/// Inspect an unredacted ledger event `(channel, payload_str)` for forbidden
/// private or secret content, or a payload the scanner cannot walk. Shared by
/// both the exporter and the offline verifier.
pub fn find_forbidden_in_ledger_event(channel: &str, payload_str: &str) -> Option<EgressViolation> {
    if let Some(class) = restricted_channel_class(channel) {
        return Some(EgressViolation::new(class, format!("restricted/private channel {channel:?}")));
    }
    let parsed = match parse_strict_json(payload_str) {
        Ok(v) => v,
        Err(e) => {
            return Some(EgressViolation::new(
                CLASS_UNPARSEABLE_PAYLOAD,
                format!("payload is not strict JSON ({e})"),
            ));
        }
    };
    if let Some(v) = find_forbidden_in_value(&parsed) {
        return Some(v);
    }
    find_forbidden_in_text(payload_str)
}

/// Recursively inspect any JSON value for forbidden private markers, secret
/// keys (skeleton- and word-matched, any value type), secret value patterns,
/// and JSON nested inside strings. Shared by exporter and verifier.
pub fn find_forbidden_in_value(value: &Value) -> Option<EgressViolation> {
    walk_value(value, 0, 0)
}

fn walk_value(value: &Value, depth: usize, nesting: usize) -> Option<EgressViolation> {
    if depth > MAX_TOTAL_DEPTH {
        return Some(EgressViolation::new(CLASS_UNPARSEABLE_PAYLOAD, "nesting exceeds the scan limit"));
    }
    match value {
        Value::String(s) => scan_string(s, depth, nesting),
        Value::Array(items) => items.iter().find_map(|item| walk_value(item, depth + 1, nesting)),
        Value::Object(map) => {
            for (k, v) in map {
                if let Some(found) = inspect_key(k, v) {
                    return Some(found);
                }
                if let Some(found) = scan_key_text(k) {
                    return Some(found);
                }
                if let Some(found) = walk_value(v, depth + 1, nesting) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

fn inspect_key(k: &str, v: &Value) -> Option<EgressViolation> {
    if is_private_marker_key(k) && is_truthy(v) {
        return Some(EgressViolation::new(CLASS_PRIVATE_RECORDS, format!("record has private marker {k:?}")));
    }
    if is_privacy_level_key(k) && v.as_str().is_some_and(is_private_word) {
        return Some(EgressViolation::new(CLASS_PRIVATE_RECORDS, format!("record has {k}=\"private\"")));
    }
    if is_label_key(k)
        && let Some(arr) = v.as_array()
        && arr.iter().any(|x| x.as_str().is_some_and(is_private_word))
    {
        return Some(EgressViolation::new(CLASS_PRIVATE_RECORDS, "record carries \"private\" label"));
    }
    if let Some(sk) = classify_secret_key(k)
        && is_material(sk, value_shape(v))
    {
        return Some(EgressViolation::new(sk.class, format!("non-redacted secret field {k:?}")));
    }
    None
}

fn scan_key_text(k: &str) -> Option<EgressViolation> {
    if k.len() > MAX_SCANNED_STRING_BYTES {
        return Some(EgressViolation::new(CLASS_UNPARSEABLE_PAYLOAD, "key exceeds the scan cap"));
    }
    find_forbidden_in_text(k)
}

fn scan_string(s: &str, depth: usize, nesting: usize) -> Option<EgressViolation> {
    if s.len() > MAX_SCANNED_STRING_BYTES {
        return Some(EgressViolation::new(
            CLASS_UNPARSEABLE_PAYLOAD,
            format!("string of {} bytes exceeds the {MAX_SCANNED_STRING_BYTES}-byte scan cap", s.len()),
        ));
    }
    if let Some(v) = find_forbidden_in_text(s) {
        return Some(v);
    }
    if let Some(v) = scan_embedded_keys(s) {
        return Some(v);
    }
    let trimmed = s.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('"') {
        match parse_strict_json(trimmed) {
            Ok(nested) => {
                if nesting + 1 > MAX_STRING_NESTING {
                    return Some(EgressViolation::new(
                        CLASS_UNPARSEABLE_PAYLOAD,
                        "JSON nested inside strings exceeds the scan limit",
                    ));
                }
                if let Some(v) = walk_value(&nested, depth + 1, nesting + 1) {
                    return Some(v);
                }
            }
            Err(_) => {
                // Valid JSON the strict parser refuses (duplicate keys, deep
                // nesting) is never treated as plain text.
                if serde_json::from_str::<de::IgnoredAny>(trimmed).is_ok() || looks_like_deep_json(trimmed) {
                    return Some(EgressViolation::new(
                        CLASS_UNPARSEABLE_PAYLOAD,
                        "string holds JSON that is not strict (duplicate keys or nesting past the limit)",
                    ));
                }
            }
        }
    }
    None
}

/// Whether text opens with more nested containers than the JSON depth limit
/// (so `serde_json` refuses it for depth, not syntax).
fn looks_like_deep_json(t: &str) -> bool {
    let mut depth = 0usize;
    for b in t.bytes().take(4096) {
        match b {
            b'[' | b'{' => {
                depth += 1;
                if depth > 127 {
                    return true;
                }
            }
            b' ' | b'\t' | b'\n' | b'\r' | b',' | b':' => {}
            b'"' => {
                // Keys and short strings inside the opening run.
                continue;
            }
            _ if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' => {}
            _ => return false,
        }
    }
    false
}

/// Scan free text for embedded `"key": value` pairs (JSON that starts
/// mid-string, escaped JSON, JSON past the parser's depth limit) and apply the
/// same key rules. Linear: every quote is tried once as a key opener and the
/// key search is bounded by [`MAX_EMBEDDED_KEY_LEN`].
fn scan_embedded_keys(s: &str) -> Option<EgressViolation> {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    while i < n {
        let Some(off) = b[i..].iter().position(|&c| c == b'"') else { break };
        let open = i + off;
        let key_start = open + 1;
        let limit = (key_start + MAX_EMBEDDED_KEY_LEN + 1).min(n);
        let Some(close_off) = b[key_start..limit].iter().position(|&c| c == b'"') else {
            i = open + 1;
            continue;
        };
        let close = key_start + close_off;
        let mut key_end = close;
        while key_end > key_start && b[key_end - 1] == b'\\' {
            key_end -= 1;
        }
        let mut j = close + 1;
        while j < n && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if j < n && b[j] == b':' && s.is_char_boundary(key_start) && s.is_char_boundary(key_end) {
            let key = &s[key_start..key_end];
            if let Some(v) = check_embedded_pair(key, s, j + 1) {
                return Some(v);
            }
        }
        i = close;
    }
    None
}

/// Classify the value following an embedded `key:` at byte `pos` of `s`.
fn check_embedded_pair(key: &str, s: &str, pos: usize) -> Option<EgressViolation> {
    let b = s.as_bytes();
    let n = b.len();
    let mut j = pos;
    while j < n && b[j].is_ascii_whitespace() {
        j += 1;
    }
    if j >= n {
        return None;
    }
    let marker = is_private_marker_key(key);
    let level = is_privacy_level_key(key);
    let secret = classify_secret_key(key);
    if !marker && !level && secret.is_none() {
        return None;
    }
    let shape = embedded_value_shape(s, j);
    if marker && matches!(shape.1.as_deref(), Some("true" | "yes" | "1" | "on" | "private")) {
        return Some(EgressViolation::new(CLASS_PRIVATE_RECORDS, format!("embedded private marker {key:?}")));
    }
    if level && shape.1.as_deref() == Some("private") {
        return Some(EgressViolation::new(CLASS_PRIVATE_RECORDS, format!("embedded {key}=\"private\"")));
    }
    let sk = secret?;
    if is_material(sk, shape.0) {
        return Some(EgressViolation::new(sk.class, format!("non-redacted embedded secret field {key:?}")));
    }
    None
}

/// The shape of an embedded JSON value starting at byte `j`, plus its
/// lowercase trimmed scalar text (bounded) for marker checks.
fn embedded_value_shape(s: &str, j: usize) -> (ValueShape, Option<String>) {
    let b = s.as_bytes();
    let n = b.len();
    let c = b[j];
    if c == b'"' || (c == b'\\' && j + 1 < n && b[j + 1] == b'"') {
        let start = if c == b'"' { j + 1 } else { j + 2 };
        let mut k = start;
        while k < n && b[k] != b'"' {
            k += 1;
        }
        let mut end = k;
        while end > start && b[end - 1] == b'\\' {
            end -= 1;
        }
        let text = if s.is_char_boundary(start) && s.is_char_boundary(end) { &s[start..end] } else { "" };
        let lower = text.trim().to_ascii_lowercase();
        let marker = (lower.len() <= 16).then(|| lower.clone());
        return (if is_placeholder_str(text) { ValueShape::Empty } else { ValueShape::Strings }, marker);
    }
    let rest = &s[j..];
    if rest.starts_with("null") {
        return (ValueShape::Empty, None);
    }
    if rest.starts_with("true") {
        return (ValueShape::Bool, Some("true".into()));
    }
    if rest.starts_with("false") {
        return (ValueShape::Bool, Some("false".into()));
    }
    if c == b'-' || c.is_ascii_digit() {
        let mut k = j + 1;
        while k < n && b[k].is_ascii_digit() {
            k += 1;
        }
        if k < n && matches!(b[k], b'.' | b'e' | b'E') {
            return (ValueShape::Other, None);
        }
        let text = &s[j..k];
        return (ValueShape::Integers, Some(text.to_string()));
    }
    if c == b'[' || c == b'{' {
        let close = if c == b'[' { b']' } else { b'}' };
        let mut k = j + 1;
        while k < n && b[k].is_ascii_whitespace() {
            k += 1;
        }
        if k < n && b[k] == close {
            return (ValueShape::Empty, None);
        }
        if c == b'[' {
            // An integer array stays metadata under id/count keys.
            let mut m = k;
            while m < n && (b[m].is_ascii_digit() || matches!(b[m], b',' | b' ' | b'-')) {
                m += 1;
            }
            if m < n && b[m] == b']' && m > k {
                return (ValueShape::Integers, None);
            }
        }
        return (ValueShape::Other, None);
    }
    (ValueShape::Other, None)
}

// ---------------------------------------------------------------------------
// Value patterns (all linear)
// ---------------------------------------------------------------------------

fn is_cred_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn is_boundary_before(text: &str, pos: usize) -> bool {
    text[..pos].chars().next_back().is_none_or(|c| !is_cred_char(c))
}

/// Whether `text` holds `prefix` followed by at least `min_tail` credential
/// characters, at a word boundary. One pass: after a miss the search resumes
/// past the whole credential run, so no character is walked twice.
fn has_prefixed_token(text: &str, prefix: &str, min_tail: usize) -> bool {
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find(prefix) {
        let pos = offset + rel;
        let tail_start = pos + prefix.len();
        let tail_len = text[tail_start..].bytes().take_while(|b| is_cred_char(*b as char)).count();
        if is_boundary_before(text, pos) && tail_len >= min_tail {
            return true;
        }
        offset = tail_start + tail_len;
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
            if after[..end].contains("PRIVATE KEY") {
                return true;
            }
            rest = &after[end + 5..];
        } else {
            break;
        }
    }
    false
}

fn is_auth_placeholder(tok: &str) -> bool {
    tok.eq_ignore_ascii_case("[redacted]")
        || tok.eq_ignore_ascii_case("[redacted-credential]")
        || (tok.starts_with('<') && tok.ends_with('>'))
        || tok.chars().all(|c| c == '*' || c == 'x' || c == 'X' || c == '.')
}

/// Skip a run of separators after an auth scheme word: any Unicode
/// whitespace, `+`, or percent-encoded whitespace (`%20`, `%09`, `%0A`,
/// `%0D`). Returns the byte offset after the run and whether any separator
/// was seen.
fn skip_auth_separators(text: &str, mut i: usize) -> (usize, bool) {
    let b = text.as_bytes();
    let start = i;
    loop {
        if i >= b.len() {
            break;
        }
        if b[i] == b'+' {
            i += 1;
            continue;
        }
        if b[i] == b'%' && i + 2 < b.len() {
            let code = [b[i + 1].to_ascii_lowercase(), b[i + 2].to_ascii_lowercase()];
            if matches!(&code, b"20" | b"09" | b"0a" | b"0d") {
                i += 3;
                continue;
            }
            break;
        }
        match text[i..].chars().next() {
            Some(c) if c.is_whitespace() || c == '\u{00A0}' => i += c.len_utf8(),
            _ => break,
        }
    }
    (i, i > start)
}

fn auth_token_at(text: &str, i: usize) -> (&str, usize) {
    let tail = &text[i..];
    let len = tail
        .char_indices()
        .find(|(_, c)| {
            c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | ')' | '}' | ']' | '\\' | '&')
        })
        .map_or(tail.len(), |(idx, _)| idx);
    (&tail[..len], i + len)
}

/// `Bearer <token>` with any whitespace, `+` or percent-encoded whitespace
/// between the scheme and the token.
fn contains_bearer_token(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(rel) = lower[offset..].find("bearer") {
        let pos = offset + rel;
        let after_word = pos + "bearer".len();
        let boundary = text[..pos].chars().next_back().is_none_or(|c| !c.is_ascii_alphanumeric());
        let (tok_start, sep) = skip_auth_separators(text, after_word);
        let (tok, tok_end) = auth_token_at(text, tok_start);
        if boundary && sep && tok.len() >= 6 && !is_auth_placeholder(tok) {
            return true;
        }
        offset = tok_end.max(after_word);
    }
    false
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let t = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in t.as_bytes() {
        acc = (acc << 6) | u32::from(val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `Basic <base64(user:password)>`.
fn contains_basic_auth(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let mut offset = 0usize;
    while let Some(rel) = lower[offset..].find("basic") {
        let pos = offset + rel;
        let after_word = pos + "basic".len();
        let boundary = text[..pos].chars().next_back().is_none_or(|c| !c.is_ascii_alphanumeric());
        let (tok_start, sep) = skip_auth_separators(text, after_word);
        let (tok, tok_end) = auth_token_at(text, tok_start);
        if boundary
            && sep
            && tok.len() >= 8
            && !is_auth_placeholder(tok)
            && base64_decode(tok).is_some_and(|d| d.contains(&b':'))
        {
            return true;
        }
        offset = tok_end.max(after_word);
    }
    false
}

/// `scheme://user:password@host` (or a long bare userinfo token).
fn contains_url_userinfo(text: &str) -> bool {
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find("://") {
        let auth_start = offset + rel + 3;
        let tail = &text[auth_start..];
        let auth_len = tail
            .char_indices()
            .find(|(_, c)| c.is_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | '\\'))
            .map_or(tail.len(), |(i, _)| i);
        let authority = &tail[..auth_len];
        if let Some(at) = authority.rfind('@') {
            let userinfo = &authority[..at];
            match userinfo.split_once(':') {
                Some((_, pw)) if !pw.is_empty() && !is_auth_placeholder(pw) => return true,
                None if userinfo.len() >= 20 => return true,
                _ => {}
            }
        }
        offset = auth_start + auth_len;
    }
    false
}

fn contains_slack_webhook(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let needle = "hooks.slack.com/services/";
    let mut offset = 0usize;
    while let Some(rel) = lower[offset..].find(needle) {
        let start = offset + rel + needle.len();
        let run = lower[start..]
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-'))
            .count();
        if run >= 8 {
            return true;
        }
        offset = start + run;
    }
    false
}

fn contains_aws_access_key(text: &str) -> bool {
    for prefix in ["AKIA", "ASIA"] {
        let mut offset = 0usize;
        while let Some(rel) = text[offset..].find(prefix) {
            let pos = offset + rel;
            let tail_start = pos + 4;
            let count = text[tail_start..]
                .bytes()
                .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                .count();
            let after_ok = text[tail_start + count..].chars().next().is_none_or(|c| !is_cred_char(c));
            if is_boundary_before(text, pos) && count == 16 && after_ok {
                return true;
            }
            offset = tail_start + count;
        }
    }
    false
}

/// A free-text AWS secret access key: a run of exactly 40 base64 characters
/// mixing upper case, lower case and digits (so lowercase hex digests never
/// match), with `aws` or `secret` in the 64 bytes before it (so ordinary
/// mixed-case paths do not match).
fn contains_aws_secret_key(text: &str) -> bool {
    let b = text.as_bytes();
    let context_ok = |start: usize| {
        let from = start.saturating_sub(64);
        let window = b[from..start].to_ascii_lowercase();
        window.windows(3).any(|w| w == b"aws") || window.windows(6).any(|w| w == b"secret")
    };
    let is_b64 = |c: u8| c.is_ascii_alphanumeric() || c == b'+' || c == b'/';
    let mut i = 0usize;
    while i < b.len() {
        if !is_b64(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_b64(b[i]) {
            i += 1;
        }
        let run = &b[start..i];
        let next_is_pad = i < b.len() && b[i] == b'=';
        if run.len() == 40
            && !next_is_pad
            && run.iter().any(u8::is_ascii_uppercase)
            && run.iter().any(u8::is_ascii_lowercase)
            && run.iter().any(u8::is_ascii_digit)
            && context_ok(start)
        {
            return true;
        }
    }
    false
}

fn contains_jwt(text: &str) -> bool {
    let mut offset = 0usize;
    while let Some(rel) = text[offset..].find("eyJ") {
        let pos = offset + rel;
        let cand_len = text[pos..]
            .bytes()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
            .count();
        let cand = &text[pos..pos + cand_len];
        let parts: Vec<&str> = cand.split('.').collect();
        if is_boundary_before(text, pos)
            && parts.len() == 3
            && parts[0].len() >= 10
            && parts[1].starts_with("eyJ")
            && parts[1].len() >= 10
            && parts[2].len() >= 10
        {
            return true;
        }
        offset = pos + cand_len.max(3);
    }
    false
}

/// Percent-decode `%XX` sequences in one pass (invalid sequences are kept).
fn percent_decode(text: &str) -> Option<String> {
    if !text.contains('%') {
        return None;
    }
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    let mut changed = false;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = ((b[i + 1] as char).to_digit(16), (b[i + 2] as char).to_digit(16))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            changed = true;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    changed.then(|| String::from_utf8_lossy(&out).into_owned())
}

/// Scan free text for raw secret/token value patterns: hub `uas_`
/// credentials, PEM private key blocks, `Bearer`/`Basic` credentials, URL
/// userinfo, Slack webhooks, GitHub/PAT/Slack/AWS/Google/Anthropic/OpenAI/
/// Stripe/GitLab/npm/PyPI/HuggingFace tokens, AWS secret keys and JWTs. The
/// percent-decoded form is scanned too.
pub fn find_forbidden_in_text(text: &str) -> Option<EgressViolation> {
    if let Some(v) = find_forbidden_in_text_once(text) {
        return Some(v);
    }
    if let Some(decoded) = percent_decode(text) {
        return find_forbidden_in_text_once(&decoded);
    }
    None
}

fn find_forbidden_in_text_once(text: &str) -> Option<EgressViolation> {
    if text.len() > MAX_SCANNED_STRING_BYTES * 64 {
        return Some(EgressViolation::new(CLASS_UNPARSEABLE_PAYLOAD, "text exceeds the scan cap"));
    }
    if contains_session_credential(text) {
        return Some(EgressViolation::new(
            CLASS_SESSION_CREDENTIALS,
            "contains hub session credential (uas_...)",
        ));
    }
    if contains_pem_private_key(text) {
        return Some(EgressViolation::new(CLASS_MANAGED_SECRETS, "contains PEM private key block"));
    }
    if contains_bearer_token(text) {
        return Some(EgressViolation::new(CLASS_AUTH_TOKENS, "contains Bearer authorization token"));
    }
    if contains_basic_auth(text) {
        return Some(EgressViolation::new(CLASS_AUTH_TOKENS, "contains Basic authorization credentials"));
    }
    if contains_url_userinfo(text) {
        return Some(EgressViolation::new(CLASS_AUTH_TOKENS, "contains credentials in URL userinfo"));
    }
    if contains_slack_webhook(text) {
        return Some(EgressViolation::new(CLASS_AUTH_TOKENS, "contains Slack webhook URL"));
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
        ("xoxe-", 10),
        ("xapp-", 10),
        ("ya29.", 20),
        ("npm_", 16),
        ("pypi-", 16),
        ("hf_", 16),
        ("pat_", 12),
    ];
    for &(prefix, min_tail) in AUTH_TOKEN_PREFIXES {
        if has_prefixed_token(text, prefix, min_tail) {
            return Some(EgressViolation::new(
                CLASS_AUTH_TOKENS,
                format!("contains token matching prefix {prefix:?}"),
            ));
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
            return Some(EgressViolation::new(
                CLASS_PROVIDER_CREDENTIALS,
                format!("contains credential matching prefix {prefix:?}"),
            ));
        }
    }
    if contains_aws_access_key(text) {
        return Some(EgressViolation::new(CLASS_PROVIDER_CREDENTIALS, "contains AWS access key"));
    }
    if contains_aws_secret_key(text) {
        return Some(EgressViolation::new(CLASS_PROVIDER_CREDENTIALS, "contains AWS secret access key"));
    }
    if contains_jwt(text) {
        return Some(EgressViolation::new(CLASS_AUTH_TOKENS, "contains JWT"));
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn refused(channel: &str, payload: &str) -> EgressViolation {
        find_forbidden_in_ledger_event(channel, payload)
            .unwrap_or_else(|| panic!("expected {payload} on {channel} to be refused"))
    }

    fn clean(channel: &str, payload: &str) {
        let v = find_forbidden_in_ledger_event(channel, payload);
        assert!(v.is_none(), "expected {payload} on {channel} to be clean, got {v:?}");
    }

    #[test]
    fn egress_filter_catches_all_twelve_review_probes_and_forbidden_classes() {
        refused("agent.log", r#"{"token":"ghp_0123456789abcdef0123456789abcdef0123"}"#);
        refused("agent.log", r#"{"notes":"pushed using github_pat_11ABCDEF0123456789_xyz9876543210abcdef"}"#);
        refused(
            "sdk.http",
            r#"{"headers":{"Authorization":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"}}"#,
        );
        refused("sdk.auth", r#"{"password":{"value":"hunter2"}}"#);
        refused("sdk.auth", r#"{"api_key":["key-one","key-two"]}"#);
        refused("sdk.auth", r#"{"accessToken":"opaque-tok-value"}"#);
        refused("sdk.raw", r#"{"blob":"{\"clientSecret\":\"super-secret-value\"}"}"#);
        refused(
            "sdk.key",
            r#"{"note":"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj\n-----END PRIVATE KEY-----"}"#,
        );
        assert_eq!(
            refused("agent.lifecycle.handoff_hook", r#"{"note":"hook"}"#).class,
            CLASS_PRIVATE_RECORDS
        );
        assert_eq!(refused("agent.mailbox.read", r#"{"message_id":"m1"}"#).class, CLASS_PRIVATE_MESSAGES);
        assert_eq!(
            refused("agent.message.inform", r#"{"text":"private update"}"#).class,
            CLASS_PRIVATE_MESSAGES
        );
        assert_eq!(
            refused("agent.conversation.handoff", r#"{"conversation_id":"c1"}"#).class,
            CLASS_PRIVATE_RECORDS
        );

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

        assert!(find_forbidden_in_value(&json!({ "api_key": "[redacted]", "ok": true })).is_none());
        assert!(find_forbidden_in_value(&json!({ "authorization_id": 42, "input_tokens": 1200 })).is_none());
        clean("agent.task.created", r#"{"task_id":1}"#);
    }

    /// The hub's own token, OAuth and session lifecycle payloads are metadata
    /// (blocker A-B1): integers, null and integer arrays under id- and
    /// count-shaped keys, and opaque ids under weak `session_*` keys.
    #[test]
    fn hub_lifecycle_payloads_are_metadata_not_material() {
        clean("agent.token.issued", r#"{"agent":"builder-1","token_id":7}"#);
        clean("agent.token.rotated", r#"{"agent":"builder-1","previous_token_id":7,"new_token_id":8}"#);
        clean("agent.token.rotated", r#"{"agent":"builder-1","previous_token_id":null,"new_token_id":8}"#);
        clean(
            "agent.token.revoked",
            r#"{"agent":"builder-1","token_ids":[7,8],"reason":"decommissioned","revoked_at":"2026-11-20T00:00:00Z"}"#,
        );
        clean(
            "agent.oauth.sessions_revoked",
            r#"{"identity":"operator","revoked_sessions":2,"revoked_tokens":4,"reason":"retired"}"#,
        );
        clean(
            "agent.oauth.sessions_revoked",
            r#"{"session_id":"fam-01","identity":"operator","sessions":1}"#,
        );
        clean(
            "agent.oauth.refresh_reuse",
            r#"{"client_id":"c1","identity":"operator","session_id":"fam-01","revoked_tokens":3}"#,
        );
        clean("agent.session.reaped", r#"{"session_ids":[3,4],"count":2}"#);
        clean(
            "agent.session.started",
            r#"{"session_id":"01HZX","session_status":"running","auth_method":"pkce","owner_session":"s-1"}"#,
        );
        clean(
            "sdk.usage",
            r#"{"input_tokens":1200,"output_tokens":30,"total_tokens":1230,"tests_passed":5}"#,
        );
        clean("agent.approval.resolved", r#"{"authorization_id":3,"credential_id":4,"pass_ttl_hours":2}"#);
        clean("agent.config", r#"{"token_configured":true,"credential_verified":false}"#);
    }

    /// Mutation N01: widening the metadata rule to any string under `*tokens`
    /// or `*_id` keys must be caught; strings under strong id/count keys are
    /// material.
    #[test]
    fn strings_under_strong_id_or_count_keys_are_material() {
        for payload in [
            r#"{"input_tokens":"OPAQUESECRETVALUE"}"#,
            r#"{"credential_id":"RAWCREDVALUE"}"#,
            r#"{"token_id":"abc-def"}"#,
            r#"{"api_tokens":"abc"}"#,
            r#"{"revoked_tokens":["t1"]}"#,
            r#"{"token":7}"#,
            r#"{"password":123456}"#,
            r#"{"secret":1.5}"#,
        ] {
            assert!(!refused("agent.log", payload).is_stubbable(), "{payload}");
        }
    }

    /// Mutation N07: a JWT is caught without any `Bearer` scheme.
    #[test]
    fn bare_jwt_without_bearer_is_refused() {
        let v = refused(
            "agent.log",
            r#"{"note":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3ZhbHVl"}"#,
        );
        assert_eq!(v.class, CLASS_AUTH_TOKENS);
        assert_eq!(v.detail, "contains JWT");
    }

    /// Review B-S4 coverage gaps.
    #[test]
    fn filter_coverage_gaps_are_closed() {
        for payload in [
            r#"{"headers":{"Cookie":"sid=abc123"}}"#,
            r#"{"headers":{"Set-Cookie":"sid=abc123; HttpOnly"}}"#,
            r#"{"dsn":"postgres://admin:PLANT03pw@db.example.com/app"}"#,
            r#"{"log":"Authorization: Basic YWRtaW46aHVudGVyMg=="}"#,
            r#"{"pwd":"hunter2"}"#,
            r#"{"db_pass":"hunter2"}"#,
            r#"{"auth":"hunter2"}"#,
            r#"{"sessionKey":"abc123"}"#,
            r#"{"session_secret":"abc123"}"#,
            r#"{"session_value":"abc123"}"#,
            r#"{"wallet_mnemonic":"word word word"}"#,
            r#"{"seed_phrase":"word word word"}"#,
            "{\"p\u{0430}ssword\":\"hunter2\"}",
            "{\"\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff4f}\u{ff52}\u{ff44}\":\"hunter2\"}",
            "{\"pass\u{200b}word\":\"hunter2\"}",
            r#"{"msg":"Bearer%20abcdef123456"}"#,
            "{\"msg\":\"Bearer\\tabcdef123456\"}",
            "{\"msg\":\"Bearer\u{00a0}abcdef123456\"}",
            r#"{"msg":"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}"#,
            r#"{"msg":"ya29.a0AfH6SMBx1234567890abcdefghij"}"#,
            r#"{"hook":"https://hooks.slack.com/services/T000/B000/XXXXXXXX"}"#,
            r#"{"msg":"ghp%5F0123456789abcdef0123456789abcdef0123"}"#,
            r#"{"d":"{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":{\"password\":\"x1\"}}}}}}}}}}"}"#,
            r#"{"resp":"resp body: {\"password\":\"hunter2\"}"}"#,
            r#"{"resp":"resp body: {\\\"password\\\":\\\"hunter2\\\"}"}"#,
        ] {
            let v = refused("agent.log", payload);
            assert!(!v.is_stubbable(), "{payload} must refuse, got {v:?}");
        }
        for payload in [
            r#"{"is_private":true}"#,
            r#"{"private":"true"}"#,
            r#"{"Private":" TRUE "}"#,
            r#"{"visibility":"private "}"#,
            r#"{"Visibility":" Private"}"#,
            r#"{"tags":["Private "]}"#,
            r#"{"note":"x {\"is_private\": true}"}"#,
        ] {
            assert_eq!(refused("agent.log", payload).class, CLASS_PRIVATE_RECORDS, "{payload}");
        }
        clean("agent.log", r#"{"dsn":"https://db.example.com/app","git":"ssh://git@github.com/o/r"}"#);
        clean(
            "agent.log",
            r#"{"note":"basic usage of the tool","sha":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}"#,
        );
        clean("agent.log", r#"{"private":false,"visibility":"public"}"#);
    }

    /// Review B-B2: non-strict JSON never passes as clean.
    #[test]
    fn non_strict_json_payloads_fail_closed() {
        let deep_open = "[".repeat(130);
        let deep_close = "]".repeat(130);
        for payload in [
            r#"{"password":"PLANT24","score":NaN}"#.to_string(),
            r#"{"password":"PLANT25"} trailing"#.to_string(),
            r#"{"password":"PLANT26","password":null}"#.to_string(),
            r#"{"a":Infinity}"#.to_string(),
            format!(r#"{{"d":{deep_open}{{"password":"PLANT14"}}{deep_close}}}"#),
            "not json".to_string(),
        ] {
            assert_eq!(refused("agent.log", &payload).class, CLASS_UNPARSEABLE_PAYLOAD, "{payload}");
        }
        // A duplicate key nested inside a string is never treated as text.
        let v = refused("agent.log", r#"{"blob":"{\"a\":1,\"a\":2}"}"#);
        assert_eq!(v.class, CLASS_UNPARSEABLE_PAYLOAD);
        // Oversized strings fail closed.
        let big = format!(r#"{{"note":"{}"}}"#, "a".repeat(MAX_SCANNED_STRING_BYTES + 1));
        assert_eq!(refused("agent.log", &big).class, CLASS_UNPARSEABLE_PAYLOAD);
        // Within limits stays clean.
        clean("agent.log", &format!(r#"{{"d":{}1{}}}"#, "[".repeat(100), "]".repeat(100)));
    }

    /// Review B-S5: the scanner is linear. Inputs that took tens of seconds at
    /// 80 KB before must finish quickly at 512 KB.
    #[test]
    fn scanner_is_linear_on_adversarial_inputs() {
        let n = 512 * 1024;
        let inputs = [
            "auas_".repeat(n / 5),
            "eyJ".repeat(n / 3),
            "AKIA".repeat(n / 4),
            "bearer".repeat(n / 6),
            "basic ".repeat(n / 6),
            "://".repeat(n / 3),
            "\"".repeat(n),
            "\"k\":".repeat(n / 4),
            "ghp_".repeat(n / 4),
            "a".repeat(n),
            "%2".repeat(n / 2),
        ];
        // Run on a worker with a deadline, so a quadratic regression (M24)
        // fails the test instead of hanging the suite.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            for s in &inputs {
                let _ = find_forbidden_in_value(&json!({ "note": s }));
            }
            let _ = tx.send(started.elapsed());
        });
        let elapsed = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the scanner did not finish 512 KB adversarial inputs within 20 s (quadratic?)");
        assert!(elapsed < std::time::Duration::from_secs(20), "scanner took {elapsed:?}");
    }

    #[test]
    fn key_words_fold_confusables_and_split_camel_case() {
        assert_eq!(key_words("accessToken"), vec!["access", "token"]);
        assert_eq!(key_words("X-API-Key"), vec!["x", "api", "key"]);
        assert_eq!(key_words("p\u{0430}ssword"), vec!["password"]);
        assert_eq!(key_words("\u{ff50}\u{ff41}\u{ff53}\u{ff53}"), vec!["pass"]);
        assert_eq!(key_words("pass\u{200b}word"), vec!["password"]);
        assert_eq!(key_words("session_id"), vec!["session", "id"]);
    }
}
