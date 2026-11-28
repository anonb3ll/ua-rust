//! The single egress filter for evidence bundles (`docs/evidence-export.md`).
//!
//! Every outgoing bundle record passes through [`EgressFilter`], and the
//! offline verifier runs the same [`find_forbidden_in_value`] check over every
//! parsed file in a bundle. The refusal floor covers:
//! - managed secret values
//! - provider credentials
//! - authentication tokens (agent tokens, OAuth tokens/codes/grants, UI sessions)
//! - passkeys
//! - session credentials (`session_credentials` rows and raw `uas_<16+>` values)
//! - private message bodies and records marked private

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ua_core::{UaError, UaResult};

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

const CREDENTIAL_PREFIX: &str = "uas_";
const CREDENTIAL_MIN_TAIL: usize = 16;

/// JSON field names whose non-null, non-empty string values indicate raw secret
/// or credential material that must never appear in an evidence bundle.
const FORBIDDEN_SECRET_KEYS: &[&str] = &[
    "secret_value",
    "secret_plaintext",
    "private_key",
    "private_key_pem",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session_token",
    "raw_token",
    "bearer_token",
    "password",
    "passphrase",
    "webhook_secret",
    "signing_seed",
];

/// Reason a record was refused by the egress filter or verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressViolation {
    pub class: &'static str,
    pub detail: String,
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

    /// Count all rows in inherently withheld database tables (secrets,
    /// provider credentials, tokens, passkeys, session credentials, private
    /// messages / handoff notes) without ever reading their secret values.
    ///
    /// When `org_id` is `Some(org)`, tables carrying `org_id` are counted only
    /// for that organization so an `org` bundle never leaks hub-wide counts.
    pub fn count_withheld_tables(&mut self, conn: &Connection, org_id: Option<&str>) -> UaResult<()> {
        let specs: &[(&str, &str)] = &[
            ("managed_secrets", CLASS_MANAGED_SECRETS),
            ("provider_accounts", CLASS_PROVIDER_CREDENTIALS),
            ("agent_tokens", CLASS_AUTH_TOKENS),
            ("oauth_tokens", CLASS_AUTH_TOKENS),
            ("oauth_codes", CLASS_AUTH_TOKENS),
            ("oauth_grants", CLASS_AUTH_TOKENS),
            ("ui_sessions", CLASS_AUTH_TOKENS),
            ("passkeys", CLASS_PASSKEYS),
            ("session_credentials", CLASS_SESSION_CREDENTIALS),
            ("message_index", CLASS_PRIVATE_MESSAGES),
            ("session_handoff_notes", CLASS_PRIVATE_MESSAGES),
        ];
        for &(table, class) in specs {
            let n = count_table_rows(conn, table, org_id)?;
            self.withheld.record(class, n);
        }
        Ok(())
    }

    /// Inspect a ledger event before writing it to `ledger/events.jsonl`.
    ///
    /// Refuses the export if the event carries raw secret material, a session
    /// credential, or a private body/marker — we never emit forbidden content
    /// and never silently drop a chained ledger row.
    pub fn check_ledger_event(&mut self, channel: &str, payload_str: &str) -> UaResult<()> {
        if let Some(v) = find_forbidden_in_ledger_event(channel, payload_str) {
            self.withheld.record(v.class, 1);
            return Err(UaError::denied(
                "egress_refused",
                format!("refusing to export ledger event on {channel:?}: {} ({})", v.detail, v.class),
            ));
        }
        Ok(())
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

/// Inspect a ledger event `(channel, payload_str)` for forbidden private or
/// secret content. Shared by both the exporter and the offline verifier.
pub fn find_forbidden_in_ledger_event(channel: &str, payload_str: &str) -> Option<EgressViolation> {
    if contains_session_credential(payload_str) {
        return Some(EgressViolation {
            class: CLASS_SESSION_CREDENTIALS,
            detail: "contains hub session credential (uas_...)".into(),
        });
    }
    let lower_ch = channel.to_ascii_lowercase();
    if lower_ch.starts_with("private.") || lower_ch.contains(".private.") {
        return Some(EgressViolation {
            class: CLASS_PRIVATE_RECORDS,
            detail: format!("private channel {channel:?}"),
        });
    }
    if let Ok(parsed) = serde_json::from_str::<Value>(payload_str) {
        if let Some(v) = find_forbidden_in_value(&parsed) {
            return Some(v);
        }
        // Private message/mailbox channels carrying a non-empty body marked private.
        if (lower_ch.starts_with("agent.message.") || lower_ch.starts_with("agent.mailbox."))
            && let Some(obj) = parsed.as_object()
            && obj.get("body").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
        {
            return Some(EgressViolation {
                class: CLASS_PRIVATE_MESSAGES,
                detail: format!("message body present on {channel:?}"),
            });
        }
    }
    None
}

/// Recursively inspect any JSON value for forbidden private markers, secret
/// values, or `uas_...` credentials. Shared by exporter and verifier.
pub fn find_forbidden_in_value(value: &Value) -> Option<EgressViolation> {
    match value {
        Value::String(s) => {
            if contains_session_credential(s) {
                return Some(EgressViolation {
                    class: CLASS_SESSION_CREDENTIALS,
                    detail: "contains hub session credential (uas_...)".into(),
                });
            }
            None
        }
        Value::Array(items) => items.iter().find_map(find_forbidden_in_value),
        Value::Object(map) => {
            for (k, v) in map {
                let lk = k.to_ascii_lowercase();
                // Private markers (`private: true`, `visibility: "private"`, `sensitivity: "private"`).
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
                // Forbidden secret / credential keys carrying non-empty values
                // (explicit `[redacted]` placeholders are allowed).
                if FORBIDDEN_SECRET_KEYS.contains(&lk.as_str())
                    && let Some(s) = v.as_str()
                    && !s.trim().is_empty()
                    && !s.eq_ignore_ascii_case("[redacted]")
                    && !s.eq_ignore_ascii_case("[redacted-credential]")
                {
                    let class = if lk.contains("token") {
                        CLASS_AUTH_TOKENS
                    } else if lk.contains("api_key") || lk.contains("apikey") || lk.contains("client_secret")
                    {
                        CLASS_PROVIDER_CREDENTIALS
                    } else {
                        CLASS_MANAGED_SECRETS
                    };
                    return Some(EgressViolation {
                        class,
                        detail: format!("non-redacted secret field {k:?}"),
                    });
                }
                if let Some(found) = find_forbidden_in_value(v) {
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

/// Detect a hub session credential (`uas_<16+ token chars>`).
pub fn contains_session_credential(text: &str) -> bool {
    let mut rest = text;
    while let Some(pos) = rest.find(CREDENTIAL_PREFIX) {
        let boundary = rest[..pos].chars().next_back().is_none_or(|c| !is_cred_char(c));
        let tail_start = pos + CREDENTIAL_PREFIX.len();
        let tail_len = rest[tail_start..].chars().take_while(|c| is_cred_char(*c)).count();
        if boundary && tail_len >= CREDENTIAL_MIN_TAIL {
            return true;
        }
        rest = &rest[tail_start + tail_len..];
    }
    false
}

fn count_table_rows(conn: &Connection, table: &str, org_id: Option<&str>) -> UaResult<u64> {
    let exists: bool = conn
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1", [table], |_| Ok(true))
        .optional()?
        .unwrap_or(false);
    if !exists {
        return Ok(0);
    }
    let has_org: bool = conn
        .query_row(&format!("SELECT 1 FROM pragma_table_info('{table}') WHERE name = 'org_id'"), [], |_| {
            Ok(true)
        })
        .optional()?
        .unwrap_or(false);
    let n: i64 = match (org_id, has_org) {
        (Some(org), true) => {
            conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\" WHERE org_id = ?1"), [org], |r| {
                r.get(0)
            })?
        }
        // In org scope, hub-global identity tables without org_id (e.g. passkeys,
        // provider_accounts) are not counted globally to avoid leaking hub-wide volume.
        (Some(_), false) => 0,
        (None, _) => conn.query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| r.get(0))?,
    };
    Ok(u64::try_from(n).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn egress_filter_catches_every_forbidden_class() {
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
            find_forbidden_in_value(&json!({ "secret_value": "top-secret" })).unwrap().class,
            CLASS_MANAGED_SECRETS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "api_key": "sk-123456" })).unwrap().class,
            CLASS_PROVIDER_CREDENTIALS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "access_token": "tok-abc" })).unwrap().class,
            CLASS_AUTH_TOKENS
        );
        assert_eq!(
            find_forbidden_in_value(&json!({ "note": "leaked uas_0123456789abcdef0123" })).unwrap().class,
            CLASS_SESSION_CREDENTIALS
        );
        assert_eq!(
            find_forbidden_in_ledger_event("agent.message.request", r#"{"body":"secret dm"}"#).unwrap().class,
            CLASS_PRIVATE_MESSAGES
        );
        // Redacted placeholders and clean payloads pass.
        assert!(find_forbidden_in_value(&json!({ "api_key": "[redacted]", "ok": true })).is_none());
        assert!(find_forbidden_in_ledger_event("agent.task.created", r#"{"task_id":1}"#).is_none());
    }
}
