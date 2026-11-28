//! The egress allow-list: which ledger channels an evidence bundle carries in
//! clear, and the type of every field it may carry (`docs/evidence-export.md`,
//! What an auditor can read).
//!
//! A ledger row is exported in clear only when its channel has an
//! [`Disposition::Export`] rule here, every payload key is listed in that rule
//! with a value of its declared type, and the pattern scanner (the backstop)
//! finds nothing. Every other row is a hash-only stub:
//! - [`CLASS_UNLISTED_PAYLOAD`]: a channel with no rule (client `sdk.*` and
//!   `agent.log` payloads, unknown channels), or a listed channel whose row
//!   carries a key or value the rule does not allow;
//! - [`CLASS_FREE_TEXT_PAYLOAD`]: a listed channel whose row carries free text
//!   (a title, a note, a reason), or a hub-authored channel stubbed whole by
//!   its rule;
//! - [`super::egress::CLASS_SCANNER_WITHHELD`]: a row the backstop scanner
//!   flagged.
//!
//! A row is never edited field by field: `hash_v` 1 and 2 commit to the
//! payload bytes as one string, so replacing a free-text field with its digest
//! would leave the row's `entry_hash` unverifiable. A row with free text is
//! therefore stubbed whole.
//!
//! Every hub channel literal in the workspace must match a rule here (or be a
//! restricted channel); `tests/evidence_bundle.rs`
//! (`every_hub_channel_is_classified_for_egress`) fails on a new channel that
//! is not classified on purpose.

use serde_json::Value;

use crate::evidence::CheckpointClass;

/// A channel with no rule, or a row whose keys or values its rule does not
/// allow. Client payloads (`sdk.*`, `agent.log`) always land here.
pub const CLASS_UNLISTED_PAYLOAD: &str = "unlisted_payload";
/// A hub-authored row carrying free text (titles, notes, reasons, bodies), or
/// a hub channel whose rule stubs it whole.
pub const CLASS_FREE_TEXT_PAYLOAD: &str = "free_text_payload";

/// The type of one exported payload field. `null` is accepted for every type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// An integer.
    Int,
    Bool,
    /// One of the listed strings.
    Enum(&'static [&'static str]),
    /// A 26-character ULID.
    Ulid,
    /// An opaque identifier: an integer, or 1..=128 characters of
    /// `[A-Za-z0-9._:-]`.
    Id,
    /// 1..=128 hexadecimal characters (a digest).
    Hex,
    /// An RFC 3339 timestamp.
    Timestamp,
    /// A known-safe label (an identity, a tool or secret name, a repository
    /// slug, a path): 1..=200 characters of `[A-Za-z0-9._:@/+-]`, no
    /// whitespace.
    Label,
    /// An array of integers (ids).
    IntArray,
    /// An array of [`FieldType::Id`] values.
    IdArray,
    /// An array of [`FieldType::Label`] values.
    LabelArray,
    /// Operator configuration text (a policy diff): exported in clear only in
    /// operator-only `hub` bundles; free text in an `org` bundle.
    HubOnlyText,
    /// Free text: `null` or `""` export; anything else stubs the row.
    FreeText,
}

/// What a bundle does with a channel's rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Export in clear when every key is listed with a value of its type.
    Export(&'static [(&'static str, FieldType)]),
    /// Always a hash-only stub under the named class.
    Stub(&'static str),
}

/// One channel rule. `prefix` rules match the channel itself and any
/// channel under it (`agent.plan` matches `agent.plan.created`); an exact
/// rule takes precedence over a prefix rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelRule {
    pub channel: &'static str,
    pub prefix: bool,
    pub disposition: Disposition,
}

const fn export(channel: &'static str, fields: &'static [(&'static str, FieldType)]) -> ChannelRule {
    ChannelRule { channel, prefix: false, disposition: Disposition::Export(fields) }
}

const fn stub_family(channel: &'static str) -> ChannelRule {
    ChannelRule { channel, prefix: true, disposition: Disposition::Stub(CLASS_FREE_TEXT_PAYLOAD) }
}

const fn stub_exact(channel: &'static str) -> ChannelRule {
    ChannelRule { channel, prefix: false, disposition: Disposition::Stub(CLASS_FREE_TEXT_PAYLOAD) }
}

use FieldType::{
    Bool, Enum, FreeText, Hex, HubOnlyText, Id, IdArray, Int, IntArray, Label, LabelArray, Timestamp,
};

const DELIVERABLE_RELEASE_FIELDS: &[(&str, FieldType)] = &[
    ("task_id", Int),
    ("deliverable_id", Int),
    ("revision_id", Int),
    ("sha256", Label),
    ("size_bytes", Int),
    ("approval_id", Int),
    ("approver", Label),
    ("destination", Label),
    ("root_identity", Label),
];

/// The checked-in egress table. Exact `Export` rules name the hub-authored
/// channels an auditor reads in clear; `Stub` family rules classify every
/// other hub channel on purpose. A channel no rule matches is stubbed as
/// [`CLASS_UNLISTED_PAYLOAD`].
pub static CHANNEL_RULES: &[ChannelRule] = &[
    // Approvals (`ua-tools/src/approvals.rs`).
    export(
        "agent.approval.requested",
        &[
            ("approval_id", Int),
            ("tool", Label),
            ("requested_by", Label),
            ("payload_sha256", Hex),
            ("via", Label),
        ],
    ),
    export(
        "agent.approval.resolved",
        &[
            ("approval_id", Int),
            ("tool", Label),
            ("decision", Enum(&["approve", "deny", "revoke"])),
            ("resolved_by", Label),
            ("transport", Label),
            ("payload_sha256", Hex),
            ("expires_at", Timestamp),
        ],
    ),
    export(
        "agent.approval.consumed",
        &[("approval_id", Int), ("tool", Label), ("payload_sha256", Hex), ("via", Label)],
    ),
    // Refusals carry the presented payload's changed field names and a reason.
    stub_exact("agent.approval.refused"),
    // Policy, profile and approval-rule revisions (`ua-tools/src/config_revisions.rs`).
    export(
        "agent.config.revision",
        &[
            ("schema", Int),
            ("kind", Enum(&["policy", "profile", "approval_rule"])),
            ("revision", Int),
            ("action", Enum(&["capture", "commit", "rollback"])),
            ("actor", Label),
            ("parent_revision", Int),
            ("restores_revision", Int),
            ("document_sha256", Hex),
            ("raw_sha256", Hex),
            ("approval_id", Int),
            ("diff", HubOnlyText),
        ],
    ),
    stub_exact("agent.config"),
    // Deliverables (`ua-deliverables`).
    export(
        "agent.deliverable.created",
        &[("org_id", Label), ("deliverable_id", Int), ("task_id", Int), ("kind", Label), ("repo", Label)],
    ),
    export(
        "agent.deliverable.revised",
        &[
            ("org_id", Label),
            ("deliverable_id", Int),
            ("task_id", Int),
            ("revision_id", Int),
            ("rev_no", Int),
            ("kind", Label),
            ("identity", Label),
            ("repo", Label),
            ("size_bytes", Int),
        ],
    ),
    export("agent.deliverable.release_authorized", DELIVERABLE_RELEASE_FIELDS),
    export("agent.deliverable.released", DELIVERABLE_RELEASE_FIELDS),
    export("agent.deliverable.release_cancelled", DELIVERABLE_RELEASE_FIELDS),
    export(
        "agent.deliverable.tampered",
        &[("task_id", Int), ("deliverable_id", Int), ("revision_id", Int), ("sha256", Label)],
    ),
    // Agent tokens and OAuth sessions (`ua-tools/src/families/tokens.rs`,
    // `governance/lifecycle.rs`, `ua-server/src/oauth`).
    export("agent.token.issued", &[("agent", Label), ("token_id", Int)]),
    export("agent.token.rotated", &[("agent", Label), ("previous_token_id", Int), ("new_token_id", Int)]),
    export(
        "agent.token.revoked",
        &[("agent", Label), ("token_ids", IntArray), ("reason", FreeText), ("revoked_at", Timestamp)],
    ),
    export(
        "agent.oauth.sessions_revoked",
        &[
            ("identity", Label),
            ("revoked_sessions", Int),
            ("revoked_tokens", Int),
            ("reason", FreeText),
            ("session_id", Id),
            ("sessions", Int),
        ],
    ),
    export(
        "agent.oauth.refresh_reuse",
        &[("client_id", Id), ("identity", Label), ("session_id", Id), ("revoked_tokens", Int)],
    ),
    export("agent.oauth.code_reuse", &[("client_id", Id), ("session_id", Id)]),
    // Node session credentials (`ua-tools/src/families/node_queue/credentials.rs`).
    export(
        "hub.session_credential.minted",
        &[
            ("credential_id", Id),
            ("item_id", Id),
            ("attempt", Int),
            ("node", Label),
            ("task_id", Int),
            ("run_id", Id),
            ("agent_label", Label),
            ("tools", LabelArray),
            ("idle_expires_at", Timestamp),
            ("expires_at", Timestamp),
            ("superseded", IdArray),
        ],
    ),
    export("hub.session_credential.revoked", &[("credential_id", Id), ("reason", Label), ("actor", Label)]),
    export("hub.session_credential.refused", &[("check", Label), ("credential_id", Id)]),
    // MCP server registry (`ua-tools/src/families/mcp/mod.rs`): secret names
    // only, never values.
    export(
        "agent.mcp_server",
        &[
            ("op", Label),
            ("name", Label),
            ("spec_sha256", Hex),
            ("approval_id", Int),
            ("orphaned_secrets", LabelArray),
        ],
    ),
    // Tasks: ids only; a title is free text.
    export(
        "agent.task.created",
        &[("task_id", Int), ("title", FreeText), ("priority", Int), ("parent_id", Int)],
    ),
    export("agent.task.completed", &[("task_id", Int)]),
    export("agent.session.reaped", &[("session_ids", IntArray), ("count", Int)]),
    // Evidence key store and checkpoints (`ua-store/src/evidence.rs`).
    export("evidence.key.added", &[("key_id", Label), ("algorithm", Label)]),
    export("evidence.key.retired", &[("key_id", Label), ("retired_at", Timestamp)]),
    export("evidence.key.revoked", &[("key_id", Label), ("revoked_at", Timestamp)]),
    export(
        "evidence.checkpoint.written",
        &[("checkpoint_id", Label), ("class", Enum(&["hub", "org"])), ("key_id", Label)],
    ),
    export("evidence.checkpoint.signed", &[("checkpoint_id", Label), ("key_id", Label)]),
    // Every other hub family is stubbed whole: their payloads carry titles,
    // notes, bodies, paths, commands or caller-supplied text.
    stub_family("agent.agent"),
    stub_family("agent.audit"),
    stub_family("agent.cmd"),
    stub_family("agent.code"),
    stub_family("agent.cycle"),
    stub_family("agent.delegation"),
    stub_family("agent.deliverable"),
    stub_family("agent.dispatch"),
    stub_family("agent.export"),
    stub_family("agent.fs"),
    stub_family("agent.gateway"),
    stub_family("agent.git"),
    stub_family("agent.github"),
    stub_family("agent.goal"),
    stub_family("agent.graph"),
    stub_family("agent.harness_config"),
    stub_family("agent.journal"),
    stub_family("agent.lifecycle"),
    stub_family("agent.mcp_gateway"),
    stub_family("agent.memory"),
    stub_family("agent.node"),
    stub_family("agent.notify"),
    stub_family("agent.oauth"),
    stub_family("agent.org"),
    stub_family("agent.plan"),
    stub_family("agent.profile"),
    stub_family("agent.project"),
    stub_family("agent.python_lint"),
    stub_family("agent.queue"),
    stub_family("agent.routine"),
    stub_family("agent.session"),
    stub_family("agent.slack"),
    stub_family("agent.state"),
    stub_family("agent.task"),
    stub_family("agent.token"),
    stub_family("agent.ui"),
    stub_family("agent.vault"),
    stub_family("agent.wake"),
    stub_family("agent.workflow"),
    stub_family("agent.zulip"),
    stub_family("evidence"),
    stub_family("github.credential"),
    stub_family("hub.session_credential"),
    // Client-written payloads: never exported in clear.
    ChannelRule {
        channel: "agent.log",
        prefix: true,
        disposition: Disposition::Stub(CLASS_UNLISTED_PAYLOAD),
    },
    ChannelRule { channel: "sdk", prefix: true, disposition: Disposition::Stub(CLASS_UNLISTED_PAYLOAD) },
];

fn rule_matches(rule: &ChannelRule, channel: &str) -> bool {
    if rule.prefix {
        channel == rule.channel
            || (channel.len() > rule.channel.len()
                && channel.starts_with(rule.channel)
                && channel.as_bytes()[rule.channel.len()] == b'.')
    } else {
        channel == rule.channel
    }
}

/// The rule for `channel`: an exact rule first, then the longest prefix rule.
pub fn rule_for(channel: &str) -> Option<&'static ChannelRule> {
    if let Some(r) = CHANNEL_RULES.iter().find(|r| !r.prefix && r.channel == channel) {
        return Some(r);
    }
    CHANNEL_RULES.iter().filter(|r| r.prefix && rule_matches(r, channel)).max_by_key(|r| r.channel.len())
}

fn is_ulid(s: &str) -> bool {
    s.len() == 26
        && s.bytes().all(|b| {
            b.is_ascii_digit()
                || (b.is_ascii_alphabetic() && !matches!(b.to_ascii_uppercase(), b'I' | b'L' | b'O' | b'U'))
        })
}

fn is_id_str(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Whether `s` is a known-safe label: 1..=200 characters of
/// `[A-Za-z0-9._:@/+-]`.
pub fn is_safe_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'@' | b'/' | b'+' | b'-'))
}

/// The outcome of checking one field value against its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldCheck {
    Ok,
    /// Non-empty free text: the row is stubbed as free text.
    FreeText,
    /// The value is not of the declared type: the row is stubbed as unlisted.
    Invalid,
}

/// Check one value against its declared type in a bundle of `class`.
pub fn check_field(ty: FieldType, v: &Value, class: CheckpointClass) -> FieldCheck {
    if v.is_null() {
        return FieldCheck::Ok;
    }
    let ok = |b: bool| if b { FieldCheck::Ok } else { FieldCheck::Invalid };
    match ty {
        Int => ok(v.as_i64().is_some() || v.as_u64().is_some()),
        Bool => ok(v.is_boolean()),
        Enum(allowed) => ok(v.as_str().is_some_and(|s| allowed.contains(&s))),
        FieldType::Ulid => ok(v.as_str().is_some_and(is_ulid)),
        Id => ok(v.as_i64().is_some() || v.as_u64().is_some() || v.as_str().is_some_and(is_id_str)),
        Hex => ok(v
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_hexdigit()))),
        Timestamp => ok(v.as_str().is_some_and(|s| s.len() <= 64 && ua_core::time::parse_ts(s).is_some())),
        Label => ok(v.as_str().is_some_and(is_safe_label)),
        IntArray => {
            ok(v.as_array().is_some_and(|a| a.len() <= 4096 && a.iter().all(|x| x.as_i64().is_some())))
        }
        IdArray => ok(v.as_array().is_some_and(|a| {
            a.len() <= 4096 && a.iter().all(|x| x.as_i64().is_some() || x.as_str().is_some_and(is_id_str))
        })),
        LabelArray => ok(v
            .as_array()
            .is_some_and(|a| a.len() <= 4096 && a.iter().all(|x| x.as_str().is_some_and(is_safe_label)))),
        HubOnlyText => match v.as_str() {
            Some("") => FieldCheck::Ok,
            Some(_) if class == CheckpointClass::Hub => FieldCheck::Ok,
            Some(_) => FieldCheck::FreeText,
            None => FieldCheck::Invalid,
        },
        FreeText => match v.as_str() {
            Some("") => FieldCheck::Ok,
            Some(_) => FieldCheck::FreeText,
            None => FieldCheck::Invalid,
        },
    }
}

/// Whether a row's envelope fields (originator, episode, causal parent,
/// dedupe key) are typed: each absent, or a safe label.
pub fn envelope_is_typed(fields: &[Option<&str>]) -> bool {
    fields.iter().all(|f| f.is_none_or(is_safe_label))
}

/// Why a row may not be exported in clear, as its stub class, or `None` when
/// the channel's rule allows its parsed payload.
pub fn schema_stub_class(channel: &str, payload: &Value, class: CheckpointClass) -> Option<&'static str> {
    let Some(rule) = rule_for(channel) else {
        return Some(CLASS_UNLISTED_PAYLOAD);
    };
    let fields = match rule.disposition {
        Disposition::Stub(c) => return Some(c),
        Disposition::Export(fields) => fields,
    };
    let Some(obj) = payload.as_object() else {
        return Some(CLASS_UNLISTED_PAYLOAD);
    };
    let mut free_text = false;
    for (k, v) in obj {
        let Some((_, ty)) = fields.iter().find(|(name, _)| name == k) else {
            return Some(CLASS_UNLISTED_PAYLOAD);
        };
        match check_field(*ty, v, class) {
            FieldCheck::Ok => {}
            FieldCheck::FreeText => free_text = true,
            FieldCheck::Invalid => return Some(CLASS_UNLISTED_PAYLOAD),
        }
    }
    free_text.then_some(CLASS_FREE_TEXT_PAYLOAD)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const HUB: CheckpointClass = CheckpointClass::Hub;
    const ORG: CheckpointClass = CheckpointClass::Org;

    #[test]
    fn typed_hub_rows_export_and_everything_else_stubs() {
        assert_eq!(
            schema_stub_class("agent.token.issued", &json!({"agent":"builder-1","token_id":7}), HUB),
            None
        );
        assert_eq!(
            schema_stub_class(
                "hub.session_credential.minted",
                &json!({"credential_id":"a1b2c3d4e5f60718","item_id":1,"attempt":1,"task_id":42,
                        "run_id":"run-001","tools":["fs_read"],"superseded":[]}),
                HUB
            ),
            None
        );
        assert_eq!(
            schema_stub_class(
                "agent.mcp_server",
                &json!({"op":"revoked","name":"srv","spec_sha256":"abc","approval_id":3,
                        "orphaned_secrets":["GITHUB_DEPLOY_NAME"]}),
                HUB
            ),
            None
        );
        // Free text stubs the whole row; null free text exports.
        assert_eq!(
            schema_stub_class(
                "agent.task.created",
                &json!({"task_id":1,"title":"Rotate Bearer tokens"}),
                HUB
            ),
            Some(CLASS_FREE_TEXT_PAYLOAD)
        );
        assert_eq!(schema_stub_class("agent.task.created", &json!({"task_id":1,"title":null}), HUB), None);
        // Unknown keys and mistyped values stub as unlisted.
        assert_eq!(
            schema_stub_class("agent.token.issued", &json!({"agent":"b","token_id":7,"extra":1}), HUB),
            Some(CLASS_UNLISTED_PAYLOAD)
        );
        assert_eq!(
            schema_stub_class("agent.token.issued", &json!({"agent":"has space","token_id":7}), HUB),
            Some(CLASS_UNLISTED_PAYLOAD)
        );
        // Client payloads and unknown channels never export.
        for ch in ["sdk.note", "agent.log", "sdk.http", "something.new"] {
            assert_eq!(schema_stub_class(ch, &json!({"n":1}), HUB), Some(CLASS_UNLISTED_PAYLOAD), "{ch}");
        }
        // Hub families classified as stubs.
        assert_eq!(schema_stub_class("agent.plan.created", &json!({}), HUB), Some(CLASS_FREE_TEXT_PAYLOAD));
        // A policy diff is hub-only text.
        let rev = json!({"kind":"policy","revision":1,"document_sha256":"ab","diff":"+ rule"});
        assert_eq!(schema_stub_class("agent.config.revision", &rev, HUB), None);
        assert_eq!(schema_stub_class("agent.config.revision", &rev, ORG), Some(CLASS_FREE_TEXT_PAYLOAD));
    }
}
