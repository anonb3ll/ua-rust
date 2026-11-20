//! Slack ingress primitives: v0 request signatures and coordination commands.
//!
//! This module does not serve HTTP. A later adapter can call
//! [`verify_slack_signature`] on the raw body, then [`remember_signed_request`]
//! inside its write transaction, then [`parse_slack_command`]; nothing here
//! binds a route or dispatches a command into hub state. `docs/slack.md` lists
//! what that route must do before it is enabled.
//!
//! The signature is HMAC-SHA256 over `v0:{timestamp}:{body}`, compared in
//! constant time. Timestamps more than five minutes from the hub clock are
//! rejected. A signature that already passed is remembered in
//! `slack_seen_signatures` so the same signed bytes cannot be accepted twice.
//! The signing secret comes from `UA_SLACK_SIGNING_SECRET` and is never logged
//! or stored.
//!
//! Signature checking is deliberately not an agent tool: an agent holding a
//! signed body could otherwise burn its replay slot or probe the verifier.

use hmac::{Hmac, KeyInit, Mac};
use icu_properties::CodePointMapData;
use icu_properties::props::GeneralCategory;
use rusqlite::params;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "slack.v1",
    sql: "
CREATE TABLE IF NOT EXISTS slack_seen_signatures (
    request_sha TEXT PRIMARY KEY,
    seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS slack_seen_signatures_seen_at ON slack_seen_signatures (seen_at);
",
};

/// Slack's replay window: five minutes either side of the hub clock.
pub const SIGNATURE_MAX_AGE_S: i64 = 300;
/// Seen signatures older than this are pruned. Twice the window: a request
/// first seen earlier than that has a timestamp the window already refuses.
pub const SEEN_RETENTION_S: i64 = 2 * SIGNATURE_MAX_AGE_S;
/// Refuse bodies larger than this before doing any other work.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Longest command text [`parse_slack_command`] reads, in characters. Slack
/// caps slash-command text well below this.
pub const MAX_COMMAND_CHARS: usize = 4000;
/// A Unix timestamp in seconds has 10 digits until 2286; more is malformed.
const MAX_TIMESTAMP_DIGITS: usize = 12;
/// Longest numeric id the parser accepts (fits an `i64`).
const MAX_ID_DIGITS: usize = 18;

const COMMANDS: [&str; 9] =
    ["approve", "assign", "blocker", "contact", "plan", "progress", "review", "status", "task"];

/// Why a Slack signature was refused. Distinct from a parser error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Missing, malformed, or not the HMAC of this body.
    BadSignature,
    /// Timestamp is more than [`SIGNATURE_MAX_AGE_S`] from `now`.
    Stale,
}

/// `v0=` plus the lowercase hex HMAC-SHA256 of `v0:{timestamp}:{body}`.
pub fn slack_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"v0:");
    mac.update(timestamp.as_bytes());
    mac.update(b":");
    mac.update(body);
    format!("v0={}", hex::encode(mac.finalize().into_bytes()))
}

/// `v0=` followed by exactly 64 lowercase hex digits, as Slack sends it.
fn well_formed_signature(signature: &str) -> bool {
    signature.len() == 67
        && signature.starts_with("v0=")
        && signature.as_bytes()[3..].iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Check the Slack v0 signature. `now` is the hub clock as Unix seconds.
/// This does not record a replay; [`remember_signed_request`] does that.
///
/// The timestamp must be 1 to 12 ASCII digits (no sign); the signature must
/// be `v0=` and 64 lowercase hex digits. Anything else is `BadSignature`.
pub fn verify_slack_signature(
    secret: &str,
    timestamp: &str,
    body: &[u8],
    signature: &str,
    now: i64,
) -> Result<(), SignatureError> {
    if secret.is_empty()
        || timestamp.is_empty()
        || timestamp.len() > MAX_TIMESTAMP_DIGITS
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
        || !well_formed_signature(signature)
        || body.len() > MAX_BODY_BYTES
    {
        return Err(SignatureError::BadSignature);
    }
    let Ok(ts) = timestamp.parse::<i64>() else {
        return Err(SignatureError::BadSignature);
    };
    if now.abs_diff(ts) > SIGNATURE_MAX_AGE_S.unsigned_abs() {
        return Err(SignatureError::Stale);
    }
    let expected = slack_signature(secret, timestamp, body);
    // Both are 67 bytes here, so the comparison is constant time.
    if bool::from(expected.as_bytes().ct_eq(signature.as_bytes())) {
        Ok(())
    } else {
        Err(SignatureError::BadSignature)
    }
}

/// SHA-256 of the exact signed base `v0:{timestamp}:{body}`.
pub fn signed_request_sha(timestamp: &str, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"v0:");
    hasher.update(timestamp.as_bytes());
    hasher.update(b":");
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Record a signature that already verified, at `now` (Unix seconds). `Err`
/// with `replayed` when this base was accepted before. Rows older than
/// [`SEEN_RETENTION_S`] are pruned first. The body itself is not stored, and
/// the ledger event is attributed to the `system` actor: no agent made it.
pub fn remember_signed_request(tx: &mut WriteTx<'_>, timestamp: &str, body: &[u8], now: i64) -> UaResult<()> {
    tx.execute(
        "DELETE FROM slack_seen_signatures WHERE seen_at < ?1",
        params![now.saturating_sub(SEEN_RETENTION_S)],
    )?;
    let sha = signed_request_sha(timestamp, body);
    let inserted = tx.execute(
        "INSERT OR IGNORE INTO slack_seen_signatures (request_sha, seen_at) VALUES (?1, ?2)",
        params![sha, now],
    )?;
    if inserted == 0 {
        return Err(UaError::denied("replayed", "this signed Slack request was already accepted"));
    }
    ledger::append(
        tx,
        EventInput::new(
            "agent.slack.signature_accepted",
            json!({ "request_sha": sha, "timestamp": timestamp }),
        )
        .by("system"),
    )?;
    Ok(())
}

/// The text after any leading `<@U123>` / `<@U123|name>` mentions. Advances
/// an index; nothing is copied.
fn strip_mentions(text: &str) -> &str {
    let mut rest = text.trim();
    while let Some(after) = rest.strip_prefix("<@") {
        let Some(close) = after.find('>') else { break };
        let id = after[..close].split('|').next().unwrap_or("");
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            break;
        }
        rest = after[close + 1..].trim_start();
    }
    rest
}

/// Split on whitespace into at most `max_splits + 1` pieces (Python `split(maxsplit=n)`).
fn split_max(text: &str, max_splits: usize) -> Vec<String> {
    let mut parts = Vec::new();
    let mut rest = text.trim_start();
    for _ in 0..max_splits {
        if rest.is_empty() {
            break;
        }
        match rest.find(char::is_whitespace) {
            Some(i) => {
                parts.push(rest[..i].to_string());
                rest = rest[i..].trim_start();
            }
            None => {
                parts.push(rest.to_string());
                rest = "";
                break;
            }
        }
    }
    if !rest.is_empty() {
        parts.push(rest.to_string());
    }
    parts
}

/// A control or format character (bidirectional controls and isolates,
/// zero-width characters, tags) other than tab and line feed.
fn hidden_char(c: char) -> bool {
    if matches!(c, '\t' | '\n') {
        return false;
    }
    matches!(
        CodePointMapData::<GeneralCategory>::new().get(c),
        GeneralCategory::Control | GeneralCategory::Format
    )
}

/// Slack escapes `&`, `<` and `>` in message text. `&amp;` goes last so
/// `&amp;lt;` reads as the literal `&lt;`.
fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

fn task_id(s: &str) -> bool {
    s.strip_prefix("task-")
        .is_some_and(|n| !n.is_empty() && n.len() <= MAX_ID_DIGITS && n.bytes().all(|b| b.is_ascii_digit()))
}

fn numeric_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_ID_DIGITS && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse a slash-style coordination command. Anything outside the nine
/// commands is refused. This does not run the command.
///
/// Refused before parsing: text over [`MAX_COMMAND_CHARS`], control and
/// format characters (bidi included; tab and line feed pass), and Slack
/// special mentions (`<!channel>`, `<!here>`, `<!subteam^…>`, any `<!…>`).
/// Leading user mentions are dropped. Arguments are unescaped (`&amp;`,
/// `&lt;`, `&gt;`). Task ids must be `task-<digits>`; approval ids digits.
pub fn parse_slack_command(text: &str) -> UaResult<Value> {
    if text.len() > MAX_COMMAND_CHARS * 4 || text.chars().count() > MAX_COMMAND_CHARS {
        return Err(UaError::invalid(format!(
            "Slack request text is longer than {MAX_COMMAND_CHARS} characters"
        )));
    }
    if let Some(c) = text.chars().find(|&c| hidden_char(c)) {
        return Err(UaError::invalid(format!(
            "Slack request text contains a control or format character (U+{:04X})",
            c as u32
        )));
    }
    if text.contains("<!") {
        return Err(UaError::invalid(
            "Slack request text contains a special mention (<!channel>, <!here>, <!subteam>); remove it",
        ));
    }
    let clean = strip_mentions(text);
    if clean.is_empty() {
        return Err(UaError::invalid("empty Slack request"));
    }
    let parts = split_max(clean, 2);
    let command = parts[0].trim_start_matches('/').to_ascii_lowercase();
    if !COMMANDS.contains(&command.as_str()) {
        return Err(UaError::invalid(format!(
            "unsupported Slack command; use one of {}",
            COMMANDS.join(", ")
        )));
    }
    let args: Vec<String> = parts.into_iter().skip(1).map(|a| unescape(&a)).collect();
    if matches!(command.as_str(), "task" | "plan") && args.is_empty() {
        return Err(UaError::invalid(format!("/{command} requires text")));
    }
    if command == "assign" && args.len() < 2 {
        return Err(UaError::invalid("/assign requires an agent and task text"));
    }
    if matches!(command.as_str(), "progress" | "blocker" | "review") && args.len() < 2 {
        return Err(UaError::invalid(format!("/{command} requires task id and update")));
    }
    if command == "approve" && args.is_empty() {
        return Err(UaError::invalid("/approve requires an approval id"));
    }
    if command == "status" && args.is_empty() {
        return Err(UaError::invalid("/status requires a task id, such as status task-42"));
    }
    if matches!(command.as_str(), "progress" | "blocker" | "review" | "status") && !task_id(&args[0]) {
        return Err(UaError::invalid(format!("/{command} needs a task id such as task-42")));
    }
    if command == "approve" && !numeric_id(&args[0]) {
        return Err(UaError::invalid("/approve needs a numeric approval id"));
    }
    Ok(json!({ "command": command, "args": args }))
}

// --- tools --------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParseArgs {
    /// Command text. A leading `<@ID>` mention is ignored. An optional `/` prefixes the command.
    pub text: String,
}

async fn slack_parse_command(_ctx: ToolCtx, a: ParseArgs) -> UaResult<Value> {
    parse_slack_command(&a.text)
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "slack_parse_command",
            "Parse one Slack coordination command: contact, task, assign, progress, blocker, review, \
             plan, approve or status. A leading mention is stripped; special mentions (<!here>), \
             control and format characters and text over 4000 characters are refused. Returns \
             {command, args}. Does not run the command and does not serve HTTP.",
            slack_parse_command,
        )
        .family("slack")
        .read_only(),
    );
}
