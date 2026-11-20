//! Provider accounts: an operator-managed registry of the model-provider
//! accounts harnesses bill, and the quota state the hub observes for them.
//!
//! An account is metadata only: provider, label, billing (`api`,
//! `subscription` or `local`), enabled, notes. It holds no secret and no
//! secret name: a harness's credentials come from its `env_allowlist`,
//! passed through from the hub's environment. A harness names its account
//! with `provider_account` in `[harnesses.<name>]`.
//!
//! Observed state comes from the hub's own records, never from probing a
//! provider: each dispatch run records its harness's account, and a failed
//! run whose failure class is [`QUOTA_CLASS`] marks the account
//! rate-limited for its `cooldown_s`. Only a harness-declared signal sets
//! that class ([`quota_line`]): one of the harness's `quota_patterns` on the
//! child's standard error, or in the error text of a structured JSON error
//! event (`quota_json_errors`). The model's own output is never matched, and
//! a self-reported `failure_reason` is advisory ([`QUOTA_REPORTED_CLASS`]):
//! recorded, never rate-limiting. `dispatch_task` refuses a harness whose
//! account is disabled (`provider_account_disabled`) or rate-limited until a
//! future time (`provider_rate_limited`), or, with the harness's
//! `provider_fallback`, runs another harness whose account has the same
//! provider and billing type (any billing with
//! `provider_fallback_cross_billing`) and is available. A `subscription`
//! account's harness may not pass `*_API_KEY` names it does not deny
//! (`subscription_api_key_passthrough`).
//!
//! Tools: `provider_account_register`, `provider_account_update`,
//! `provider_account_disable` (operators), `provider_account_list` and
//! `provider_quota_status` (reads). Every change is ledgered on
//! `provider.account` in the same transaction.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use rusqlite::{Connection, OptionalExtension, Row, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::config::HarnessConfig;
use ua_core::{Config, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, WriteTx, ledger};

use super::agents::verified;
use super::governance;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "provider_accounts.v1",
    sql: "
CREATE TABLE IF NOT EXISTS provider_accounts (
    label TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    billing TEXT NOT NULL CHECK (billing IN ('api','subscription','local')),
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    cooldown_s INTEGER NOT NULL DEFAULT 3600,
    disabled_reason TEXT,
    rate_limited_until TEXT,
    last_error_class TEXT,
    last_error_at TEXT,
    last_error_run TEXT,
    last_success_at TEXT,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provider_accounts_provider ON provider_accounts(provider);
",
};

pub const CHANNEL: &str = "provider.account";
/// The failure class of a run that hit a provider usage or quota limit, as
/// its harness's declared signal shows.
pub const QUOTA_CLASS: &str = "provider_quota_exhausted";
/// The failure class of a self-reported failure whose reason reads like a
/// usage limit: recorded, never rate-limiting.
pub const QUOTA_REPORTED_CLASS: &str = "provider_quota_reported";
/// Characters of a matched quota line kept in the ledger.
const MAX_SIGNAL_CHARS: usize = 200;
pub const BILLING: [&str; 3] = ["api", "local", "subscription"];

const DEFAULT_COOLDOWN_S: i64 = 3600;
const MIN_COOLDOWN_S: i64 = 60;
const MAX_COOLDOWN_S: i64 = 7 * 86_400;
const MAX_NOTES: usize = 500;
const DEFAULT_RECENT: i64 = 20;
const MAX_RECENT: i64 = 200;

/// A plan or account usage ceiling, as the original hub classifies it. Used
/// only to label a self-report as advisory quota evidence.
static QUOTA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:usage\s+limit\s+(?:has\s+been\s+)?reached|quota\s+exhausted|provider\s+quota|rate[\s_-]?limit\s+reached|\b(?:\d+[\s-]?hour|session|weekly|daily|opus|sonnet)\s+limit\s+reached|hit\s+your\s+(?:usage\s+)?limit|insufficient_quota)",
    )
    .expect("quota pattern")
});

/// Text that reads like a credential value or assignment.
static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:access[_-]?token|api[_-]?key|auth(?:orization)?|client[_-]?secret|refresh[_-]?token|private[_-]?key|password|secret)\s*[:=]|(?:sk-|gh[pousr]_|xox[abprs]-)[A-Za-z0-9_-]{8,}",
    )
    .expect("secret pattern")
});

/// Whether `text` reads like a provider usage-limit or quota message.
pub fn quota_signal(text: &str) -> bool {
    QUOTA_RE.is_match(text)
}

/// The harness-declared quota signal of a failed run: `(source, line)` for
/// the first of `patterns` (case-insensitive) found on a line of `stderr`
/// (source `stderr`), else, when `json_stdout` is given, in the error text
/// of a structured JSON error event on standard output (source
/// `json_error`). The line is redacted and at most 200 characters. Without
/// patterns nothing ever matches; model text on standard output is never
/// read.
pub fn quota_line(
    patterns: &[String],
    stderr: &str,
    json_stdout: Option<&str>,
) -> Option<(&'static str, String)> {
    let needles: Vec<String> =
        patterns.iter().map(|p| p.trim().to_lowercase()).filter(|p| !p.is_empty()).collect();
    if needles.is_empty() {
        return None;
    }
    let hit = |text: &str| {
        let low = text.to_lowercase();
        needles.iter().any(|n| low.contains(n.as_str()))
    };
    for line in stderr.lines().rev() {
        if hit(line) {
            return Some(("stderr", bounded(line)));
        }
    }
    for line in json_stdout?.lines().rev() {
        if let Some(text) = json_error_text(line)
            && hit(&text)
        {
            return Some(("json_error", bounded(&text)));
        }
    }
    None
}

/// The error text of a structured JSON error event: a line that is a JSON
/// object with `type = "error"` (its `error`, `message` and `code` fields), or
/// one whose `message.stopReason` is `"error"` (its `message.errorMessage`).
/// Anything else, including model text inside events, is `None`.
fn json_error_text(line: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with('{') {
        return None;
    }
    let v: Value = serde_json::from_str(line).ok()?;
    let mut parts: Vec<String> = Vec::new();
    let mut push = |x: &Value| match x {
        Value::String(t) => parts.push(t.clone()),
        Value::Number(n) => parts.push(n.to_string()),
        _ => {}
    };
    if v.get("type").and_then(Value::as_str) == Some("error") {
        match v.get("error") {
            Some(Value::Object(e)) => {
                for k in ["type", "code", "message"] {
                    if let Some(x) = e.get(k) {
                        push(x);
                    }
                }
            }
            Some(x) => push(x),
            None => {}
        }
        for k in ["code", "message"] {
            if let Some(x) = v.get(k) {
                push(x);
            }
        }
    } else if let Some(m) =
        v.get("message").filter(|m| m.get("stopReason").and_then(Value::as_str) == Some("error"))
        && let Some(x) = m.get("errorMessage")
    {
        push(x);
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

/// A matched line as the ledger keeps it: credentials redacted, trimmed and
/// at most [`MAX_SIGNAL_CHARS`] characters.
fn bounded(line: &str) -> String {
    let red = SECRET_VALUE_RE.replace_all(line.trim(), "[redacted]");
    red.chars().take(MAX_SIGNAL_CHARS).collect()
}

/// Credential-looking runs of text in a matched line.
static SECRET_VALUE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:sk-|gh[pousr]_|xox[abprs]-|github_pat_|uas_|AKIA|AIza)[A-Za-z0-9_-]{8,}|\b(?:bearer|basic)\s+[A-Za-z0-9+/._~=-]{8,}|(?:access[_-]?token|api[_-]?key|client[_-]?secret|refresh[_-]?token|password|secret|token)\s*[:=]\s*\S+",
    )
    .expect("secret value pattern")
});

fn now() -> String {
    ua_core::time::now()
}

fn after(secs: i64) -> String {
    let t = jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_secs(secs))
        .unwrap_or(jiff::Timestamp::MAX);
    ua_core::time::format_ts(t)
}

/// Whether stored timestamp `ts` is still in the future.
fn future(ts: Option<&str>) -> bool {
    ts.and_then(ua_core::time::parse_ts).is_some_and(|t| t > jiff::Timestamp::now())
}

fn record(tx: &mut WriteTx<'_>, kind: &str, mut payload: Value, by: &str) -> UaResult<()> {
    payload["kind"] = json!(kind);
    ledger::append(tx, EventInput::new(CHANNEL, payload).by(by.to_string()))?;
    Ok(())
}

// --- rows -----------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct Account {
    pub label: String,
    pub provider: String,
    pub billing: String,
    pub enabled: bool,
    pub notes: String,
    pub cooldown_s: i64,
    pub disabled_reason: Option<String>,
    pub rate_limited_until: Option<String>,
    pub last_error_class: Option<String>,
    pub last_error_at: Option<String>,
    pub last_error_run: Option<String>,
    pub last_success_at: Option<String>,
    pub created_by: String,
    pub created_at: String,
    pub updated_by: String,
    pub updated_at: String,
}

const COLS: &str = "label, provider, billing, enabled, notes, cooldown_s, disabled_reason, \
    rate_limited_until, last_error_class, last_error_at, last_error_run, last_success_at, created_by, created_at, \
    updated_by, updated_at";

fn account_row(r: &Row<'_>) -> rusqlite::Result<Account> {
    Ok(Account {
        label: r.get(0)?,
        provider: r.get(1)?,
        billing: r.get(2)?,
        enabled: r.get::<_, i64>(3)? != 0,
        notes: r.get(4)?,
        cooldown_s: r.get(5)?,
        disabled_reason: r.get(6)?,
        rate_limited_until: r.get(7)?,
        last_error_class: r.get(8)?,
        last_error_at: r.get(9)?,
        last_error_run: r.get(10)?,
        last_success_at: r.get(11)?,
        created_by: r.get(12)?,
        created_at: r.get(13)?,
        updated_by: r.get(14)?,
        updated_at: r.get(15)?,
    })
}

pub(crate) fn load(c: &Connection, label: &str) -> UaResult<Option<Account>> {
    Ok(c.query_row(&format!("SELECT {COLS} FROM provider_accounts WHERE label = ?1"), [label], account_row)
        .optional()?)
}

fn all(c: &Connection) -> UaResult<Vec<Account>> {
    let mut stmt = c.prepare(&format!("SELECT {COLS} FROM provider_accounts ORDER BY provider, label"))?;
    let rows = stmt.query_map([], account_row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

impl Account {
    /// Why this account cannot take a run now: `(reason_code, message)`.
    pub fn block(&self) -> Option<(&'static str, String)> {
        if !self.enabled {
            return Some((
                "provider_account_disabled",
                format!(
                    "provider account {:?} is disabled{}",
                    self.label,
                    self.disabled_reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default()
                ),
            ));
        }
        if future(self.rate_limited_until.as_deref()) {
            return Some((
                "provider_rate_limited",
                format!(
                    "provider account {:?} is rate-limited until {}{}",
                    self.label,
                    self.rate_limited_until.as_deref().unwrap_or("?"),
                    self.last_error_class.as_deref().map(|c| format!(" ({c})")).unwrap_or_default()
                ),
            ));
        }
        None
    }

    fn public(&self) -> Value {
        json!({
            "label": self.label,
            "provider": self.provider,
            "billing": self.billing,
            "enabled": self.enabled,
            "notes": self.notes,
            "cooldown_s": self.cooldown_s,
            "disabled_reason": self.disabled_reason,
            "rate_limited_until": self.rate_limited_until,
            "rate_limited": future(self.rate_limited_until.as_deref()),
            "last_error_class": self.last_error_class,
            "last_error_at": self.last_error_at,
            "last_error_run": self.last_error_run,
            "last_success_at": self.last_success_at,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
        })
    }
}

// --- dispatch hooks ---------------------------------------------------------------

/// The harness a dispatch runs: `name` itself when it names no account or
/// its account can take a run; with `provider_fallback`, the first other
/// harness (by name) whose account has the same provider and the same
/// billing type (any billing with `provider_fallback_cross_billing`), is
/// available, and passes [`billing_env_block`]. Returns the chosen harness
/// and, when it was rerouted, what it replaced, with both accounts' billing.
/// Refusals carry `provider_account_unknown`, `provider_account_disabled` or
/// `provider_rate_limited`.
pub(crate) fn select_harness(
    c: &Connection,
    cfg: &Config,
    name: String,
    h: HarnessConfig,
) -> UaResult<(String, HarnessConfig, Option<Value>)> {
    let Some(label) = h.provider_account.clone() else { return Ok((name, h, None)) };
    let account = require(c, &label, &name)?;
    let Some((code, message)) = account.block() else { return Ok((name, h, None)) };
    if !h.provider_fallback {
        return Err(UaError::conflict_code(code, format!("harness {name:?}: {message}")));
    }
    for (other, oh) in &cfg.harnesses {
        if other == &name || oh.argv.first().is_none_or(|p| p.trim().is_empty()) {
            continue;
        }
        let Some(ol) = oh.provider_account.as_deref() else { continue };
        let Some(oa) = load(c, ol)? else { continue };
        let billing_ok = oa.billing == account.billing || h.provider_fallback_cross_billing;
        if oa.provider == account.provider
            && billing_ok
            && oa.block().is_none()
            && billing_env_block(&oa, other, oh).is_none()
        {
            let from = json!({
                "harness": name,
                "provider_account": label,
                "billing": account.billing,
                "reason": code,
                "to_provider_account": oa.label,
                "to_billing": oa.billing,
            });
            return Ok((other.clone(), oh.clone(), Some(from)));
        }
    }
    let scope = if h.provider_fallback_cross_billing {
        format!("{:?}", account.provider)
    } else {
        format!("{:?} {}", account.provider, account.billing)
    };
    Err(UaError::conflict_code(
        code,
        format!(
            "harness {name:?}: {message}; no other harness with an available {scope} account is configured"
        ),
    ))
}

/// Why a harness billing a `subscription` account may not run: its
/// `env_allowlist` passes a `*_API_KEY` name its `env_denylist` does not
/// deny, so the CLI could silently fall back to metered billing.
fn billing_env_block(account: &Account, name: &str, h: &HarnessConfig) -> Option<String> {
    if account.billing != "subscription" {
        return None;
    }
    let passed: Vec<&str> = h
        .env_allowlist
        .iter()
        .filter(|n| {
            let up = n.to_ascii_uppercase();
            (up == "API_KEY" || up.ends_with("_API_KEY")) && !h.env_denylist.iter().any(|d| d == *n)
        })
        .map(String::as_str)
        .collect();
    (!passed.is_empty()).then(|| {
        format!(
            "harness {name:?} bills subscription account {:?} but its env_allowlist passes {}; move them to \
             env_denylist so the run cannot fall back to metered billing",
            account.label,
            passed.join(", ")
        )
    })
}

/// Refuse (`subscription_api_key_passthrough`), before any approval, a
/// harness whose `subscription` account would see a metered API key.
pub(crate) fn check_billing_env(c: &Connection, name: &str, h: &HarnessConfig) -> UaResult<()> {
    let Some(label) = h.provider_account.as_deref() else { return Ok(()) };
    let Some(account) = load(c, label)? else { return Ok(()) };
    match billing_env_block(&account, name, h) {
        Some(why) => Err(UaError::conflict_code("subscription_api_key_passthrough", why)),
        None => Ok(()),
    }
}

fn require(c: &Connection, label: &str, harness: &str) -> UaResult<Account> {
    load(c, label)?.ok_or_else(|| {
        UaError::conflict_code(
            "provider_account_unknown",
            format!("harness {harness:?} names provider account {label:?}, which is not registered"),
        )
    })
}

/// Refuse a harness whose account cannot take a run (no rerouting): the
/// check `dispatch_resume` runs, since a resume must run what was approved.
pub(crate) fn check_available(c: &Connection, name: &str, h: &HarnessConfig) -> UaResult<()> {
    let Some(label) = h.provider_account.as_deref() else { return Ok(()) };
    match require(c, label, name)?.block() {
        Some((code, message)) => Err(UaError::conflict_code(code, format!("harness {name:?}: {message}"))),
        None => Ok(()),
    }
}

/// Note a run outcome against the run's provider account: a success time, or
/// the error class, and for a quota failure carrying its harness-declared
/// `signal` (`{source, line}`) a rate limit for the account's cooldown. An
/// advisory self-report ([`QUOTA_REPORTED_CLASS`]) is ledgered and never
/// rate-limits. Runs without an account are ignored.
pub(crate) fn observe_outcome(
    tx: &mut WriteTx<'_>,
    run_id: &str,
    state: &str,
    class: Option<&str>,
    signal: Option<&Value>,
    actor: &str,
) -> UaResult<()> {
    let label: Option<String> = tx
        .query_row("SELECT provider_account FROM dispatch_runs WHERE run_id = ?1", [run_id], |r| r.get(0))
        .optional()?
        .flatten();
    let Some(label) = label else { return Ok(()) };
    let Some(account) = load(tx, &label)? else { return Ok(()) };
    let ts = now();
    if state == "finished" {
        tx.execute("UPDATE provider_accounts SET last_success_at = ?2 WHERE label = ?1", params![label, ts])?;
        return Ok(());
    }
    if !matches!(state, "failed" | "retryable" | "blocked") {
        return Ok(());
    }
    let quota = class == Some(QUOTA_CLASS) && signal.is_some();
    let until = if quota {
        let candidate = after(account.cooldown_s);
        match account.rate_limited_until {
            Some(cur) if future(Some(&cur)) && cur > candidate => Some(cur),
            _ => Some(candidate),
        }
    } else {
        account.rate_limited_until.clone()
    };
    tx.execute(
        "UPDATE provider_accounts SET last_error_class = ?2, last_error_at = ?3, last_error_run = ?4, \
         rate_limited_until = ?5 WHERE label = ?1",
        params![label, class, ts, run_id, until],
    )?;
    if quota {
        record(
            tx,
            "rate_limited_observed",
            json!({
                "label": label, "provider": account.provider, "run_id": run_id, "until": until, "signal": signal,
            }),
            actor,
        )?;
    } else if class == Some(QUOTA_REPORTED_CLASS) {
        record(
            tx,
            "quota_reported",
            json!({ "label": label, "provider": account.provider, "run_id": run_id, "advisory": true }),
            actor,
        )?;
    }
    Ok(())
}

// --- validation -------------------------------------------------------------------

fn slug(field: &str, raw: &str, lower: bool) -> UaResult<String> {
    let v = raw.trim();
    let v = if lower { v.to_ascii_lowercase() } else { v.to_string() };
    let mut chars = v.chars();
    let ok = (1..=64).contains(&v.len())
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        return Err(UaError::invalid(format!(
            "{field} must be 1-64 chars of [A-Za-z0-9._-], starting alphanumeric"
        )));
    }
    Ok(v)
}

fn billing(raw: &str) -> UaResult<String> {
    let b = raw.trim().to_ascii_lowercase();
    if BILLING.contains(&b.as_str()) {
        Ok(b)
    } else {
        Err(UaError::invalid(format!("billing must be one of {}", BILLING.join(", "))))
    }
}

fn notes(raw: &str) -> UaResult<String> {
    let v = raw.trim();
    if v.chars().count() > MAX_NOTES {
        return Err(UaError::invalid(format!("notes must be at most {MAX_NOTES} characters")));
    }
    if SECRET_RE.is_match(v) {
        return Err(UaError::invalid("notes must not contain tokens, API keys, passwords or other secrets"));
    }
    Ok(v.to_string())
}

fn cooldown(v: i64) -> UaResult<i64> {
    if (MIN_COOLDOWN_S..=MAX_COOLDOWN_S).contains(&v) {
        Ok(v)
    } else {
        Err(UaError::invalid(format!("cooldown_s must be {MIN_COOLDOWN_S}-{MAX_COOLDOWN_S}")))
    }
}

fn operator(ctx: &ToolCtx, verb: &str) -> UaResult<String> {
    let who = verified(&ctx.caller).map(str::to_string).ok_or_else(|| {
        UaError::denied("identity_required", format!("{verb} requires an authenticated identity"))
    })?;
    if !governance::is_operator(ctx.hub.cfg(), &ctx.caller, &who) {
        return Err(UaError::denied(
            "operator_required",
            format!("{verb} is for operators (a human or a lifecycle operator); {who:?} is neither"),
        ));
    }
    Ok(who)
}

// --- tools ----------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterArgs {
    /// Provider family, e.g. `anthropic`, `openai`, `openai-codex`, `google`,
    /// `ollama` (1-64 of `[a-z0-9._-]`). Fallback routing stays within one.
    pub provider: String,
    /// Unique account label that harnesses name in `provider_account`.
    pub label: String,
    /// `api` (metered key), `subscription` (a plan's sign-in) or `local`.
    pub billing: String,
    /// Whether harnesses may use it now (default true).
    pub enabled: Option<bool>,
    /// Operator notes, at most 500 characters, no secrets.
    pub notes: Option<String>,
    /// Seconds an observed quota failure keeps the account rate-limited
    /// (60-604800, default 3600).
    pub cooldown_s: Option<i64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateArgs {
    /// The account to change.
    pub label: String,
    pub provider: Option<String>,
    pub billing: Option<String>,
    /// `true` re-enables a disabled account (clearing its reason); `false`
    /// disables it.
    pub enabled: Option<bool>,
    pub notes: Option<String>,
    pub cooldown_s: Option<i64>,
    /// Mark the account rate-limited until this RFC 3339 time; an empty
    /// string clears an observed or manual limit.
    pub rate_limited_until: Option<String>,
    /// Forget the last observed error.
    #[serde(default)]
    pub clear_error: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisableArgs {
    /// The account to disable.
    pub label: String,
    /// Why, at most 500 characters.
    pub reason: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Include disabled accounts (default true).
    pub include_disabled: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuotaArgs {
    /// One account; omitted, every account.
    pub label: Option<String>,
    /// Recent runs per account to summarize (1-200, default 20).
    pub recent: Option<i64>,
}

async fn register_account(ctx: ToolCtx, a: RegisterArgs) -> UaResult<Value> {
    let who = operator(&ctx, "provider_account_register")?;
    let provider = slug("provider", &a.provider, true)?;
    let label = slug("label", &a.label, false)?;
    let billing = billing(&a.billing)?;
    let notes = notes(a.notes.as_deref().unwrap_or(""))?;
    let cooldown_s = cooldown(a.cooldown_s.unwrap_or(DEFAULT_COOLDOWN_S))?;
    let enabled = a.enabled.unwrap_or(true);
    ctx.hub
        .db()
        .write_async(move |tx| {
            if load(tx, &label)?.is_some() {
                return Err(UaError::conflict_code(
                    "provider_account_exists",
                    format!("provider account {label:?} is already registered; use provider_account_update"),
                ));
            }
            let ts = now();
            tx.execute(
                "INSERT INTO provider_accounts (label, provider, billing, enabled, notes, cooldown_s, \
                 created_by, created_at, updated_by, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?7, ?8)",
                params![label, provider, billing, enabled, notes, cooldown_s, who, ts],
            )?;
            record(
                tx,
                "registered",
                json!({ "label": label, "provider": provider, "billing": billing, "enabled": enabled }),
                &who,
            )?;
            let acc = load(tx, &label)?.ok_or_else(|| UaError::internal("account vanished"))?;
            Ok(json!({ "account": acc.public() }))
        })
        .await
}

async fn update_account(ctx: ToolCtx, a: UpdateArgs) -> UaResult<Value> {
    let who = operator(&ctx, "provider_account_update")?;
    let label = slug("label", &a.label, false)?;
    let provider = a.provider.as_deref().map(|p| slug("provider", p, true)).transpose()?;
    let billing = a.billing.as_deref().map(billing).transpose()?;
    let notes = a.notes.as_deref().map(notes).transpose()?;
    let cooldown_s = a.cooldown_s.map(cooldown).transpose()?;
    let limit = match a.rate_limited_until.as_deref().map(str::trim) {
        None => None,
        Some("") => Some(None),
        Some(t) => match ua_core::time::parse_ts(t) {
            Some(ts) => Some(Some(ua_core::time::format_ts(ts))),
            None => return Err(UaError::invalid("rate_limited_until must be an RFC 3339 time")),
        },
    };
    let (enabled, clear_error) = (a.enabled, a.clear_error);
    ctx.hub
        .db()
        .write_async(move |tx| {
            let Some(before) = load(tx, &label)? else {
                return Err(UaError::not_found(format!("provider account {label:?} is not registered")));
            };
            let mut changed: Vec<&str> = Vec::new();
            let mut set = |field: &'static str, sql: &str, v: rusqlite::types::Value| -> UaResult<()> {
                tx.execute(
                    &format!("UPDATE provider_accounts SET {sql} WHERE label = ?1"),
                    params![label, v],
                )?;
                changed.push(field);
                Ok(())
            };
            use rusqlite::types::Value as V;
            let text = |s: Option<String>| s.map_or(V::Null, V::Text);
            if let Some(p) = provider.filter(|p| p != &before.provider) {
                set("provider", "provider = ?2", V::Text(p))?;
            }
            if let Some(b) = billing.filter(|b| b != &before.billing) {
                set("billing", "billing = ?2", V::Text(b))?;
            }
            if let Some(n) = notes.filter(|n| n != &before.notes) {
                set("notes", "notes = ?2", V::Text(n))?;
            }
            if let Some(c) = cooldown_s.filter(|c| *c != before.cooldown_s) {
                set("cooldown_s", "cooldown_s = ?2", V::Integer(c))?;
            }
            if let Some(e) = enabled.filter(|e| *e != before.enabled) {
                set("enabled", "enabled = ?2, disabled_reason = NULL", V::Integer(i64::from(e)))?;
            }
            if let Some(l) = limit.filter(|l| l != &before.rate_limited_until) {
                set("rate_limited_until", "rate_limited_until = ?2", text(l))?;
            }
            if clear_error && before.last_error_class.is_some() {
                tx.execute(
                    "UPDATE provider_accounts SET last_error_class = NULL, last_error_at = NULL, \
                     last_error_run = NULL WHERE label = ?1",
                    [&label],
                )?;
                changed.push("last_error");
            }
            if !changed.is_empty() {
                tx.execute(
                    "UPDATE provider_accounts SET updated_by = ?2, updated_at = ?3 WHERE label = ?1",
                    params![label, who, now()],
                )?;
                record(tx, "updated", json!({ "label": label, "changed": changed }), &who)?;
            }
            let acc = load(tx, &label)?.ok_or_else(|| UaError::internal("account vanished"))?;
            Ok(json!({ "account": acc.public(), "changed": changed }))
        })
        .await
}

async fn disable_account(ctx: ToolCtx, a: DisableArgs) -> UaResult<Value> {
    let who = operator(&ctx, "provider_account_disable")?;
    let label = slug("label", &a.label, false)?;
    let reason = governance::clean_reason(a.reason.as_deref(), None)?;
    ctx.hub
        .db()
        .write_async(move |tx| {
            let Some(before) = load(tx, &label)? else {
                return Err(UaError::not_found(format!("provider account {label:?} is not registered")));
            };
            let changed = before.enabled;
            if changed {
                tx.execute(
                    "UPDATE provider_accounts SET enabled = 0, disabled_reason = ?2, updated_by = ?3, updated_at = ?4 \
                     WHERE label = ?1",
                    params![label, (!reason.is_empty()).then_some(reason.clone()), who, now()],
                )?;
                record(tx, "disabled", json!({ "label": label, "reason": reason }), &who)?;
            }
            let acc = load(tx, &label)?.ok_or_else(|| UaError::internal("account vanished"))?;
            Ok(json!({ "account": acc.public(), "changed": changed }))
        })
        .await
}

async fn list_accounts(ctx: ToolCtx, a: ListArgs) -> UaResult<Value> {
    let include_disabled = a.include_disabled.unwrap_or(true);
    ctx.hub
        .db()
        .read_async(move |c| {
            let out: Vec<Value> =
                all(c)?.iter().filter(|a| include_disabled || a.enabled).map(Account::public).collect();
            Ok(json!({ "accounts": out, "count": out.len() }))
        })
        .await
}

/// Harness names by the account they name.
fn harnesses_by_account(cfg: &Config) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, h) in &cfg.harnesses {
        if let Some(l) = &h.provider_account {
            m.entry(l.clone()).or_default().push(name.clone());
        }
    }
    m
}

/// `(run_id, harness, state, failure_class, created_at)` of one run.
type RunRow = (String, Option<String>, String, Option<String>, String);

fn recent_runs(c: &Connection, label: &str, limit: i64) -> UaResult<Value> {
    let mut stmt = c.prepare(
        "SELECT run_id, harness, state, failure_class, created_at FROM dispatch_runs WHERE provider_account = ?1 \
         ORDER BY created_at DESC, run_id DESC LIMIT ?2",
    )?;
    let rows: Vec<RunRow> = stmt
        .query_map(params![label, limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
        .collect::<Result<_, _>>()?;
    let mut by_state: BTreeMap<String, i64> = BTreeMap::new();
    let mut by_class: BTreeMap<String, i64> = BTreeMap::new();
    for (_, _, state, class, _) in &rows {
        *by_state.entry(state.clone()).or_default() += 1;
        if let Some(cl) = class {
            *by_class.entry(cl.clone()).or_default() += 1;
        }
    }
    let last = rows.first().map(|(id, h, st, cl, at)| {
        json!({ "run_id": id, "harness": h, "state": st, "failure_class": cl, "created_at": at })
    });
    Ok(json!({
        "runs": rows.len(),
        "by_state": by_state,
        "by_failure_class": by_class,
        "quota_failures": by_class.get(QUOTA_CLASS).copied().unwrap_or(0),
        "last_run": last,
    }))
}

async fn quota_status(ctx: ToolCtx, a: QuotaArgs) -> UaResult<Value> {
    let limit = a.recent.unwrap_or(DEFAULT_RECENT);
    if !(1..=MAX_RECENT).contains(&limit) {
        return Err(UaError::invalid(format!("recent must be 1-{MAX_RECENT}")));
    }
    let label = a.label.as_deref().map(|l| slug("label", l, false)).transpose()?;
    let by_account = harnesses_by_account(ctx.hub.cfg());
    ctx.hub
        .db()
        .read_async(move |c| {
            let accounts = match &label {
                Some(l) => vec![load(c, l)?.ok_or_else(|| {
                    UaError::not_found(format!("provider account {l:?} is not registered"))
                })?],
                None => all(c)?,
            };
            let mut out = Vec::new();
            for acc in &accounts {
                let recent = recent_runs(c, &acc.label, limit)?;
                let availability = match acc.block() {
                    Some(("provider_account_disabled", _)) => "disabled",
                    Some(_) => "rate_limited",
                    // No observation is never reported as available.
                    None if recent["runs"] == json!(0) && acc.last_success_at.is_none() => "unknown",
                    None => "available",
                };
                let mut v = acc.public();
                v["availability"] = json!(availability);
                v["harnesses"] = json!(by_account.get(&acc.label).cloned().unwrap_or_default());
                v["recent"] = recent;
                out.push(v);
            }
            let known: Vec<&str> = accounts.iter().map(|a| a.label.as_str()).collect();
            let unregistered: Vec<Value> = if label.is_none() {
                by_account
                    .iter()
                    .filter(|(l, _)| !known.contains(&l.as_str()))
                    .map(|(l, hs)| json!({ "provider_account": l, "harnesses": hs }))
                    .collect()
            } else {
                Vec::new()
            };
            Ok(json!({
                "accounts": out,
                "count": out.len(),
                "unregistered_accounts": unregistered,
                "source": "dispatch runs and operator records; providers are never probed",
            }))
        })
        .await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "provider_account_register",
            "Operators: register a provider account harnesses bill: provider, unique label (named by a harness's \
             provider_account), billing api|subscription|local, enabled, notes and the cooldown an observed quota \
             failure applies. No secret or secret name is stored. Returns {account}.",
            register_account,
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "provider_account_update",
            "Operators: change a provider account (provider, billing, enabled, notes, cooldown_s), \
             mark it rate-limited until a time or clear that (rate_limited_until), or forget its last error \
             (clear_error). Returns {account, changed}.",
            update_account,
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "provider_account_disable",
            "Operators: disable a provider account. dispatch_task then refuses harnesses that bill it \
             (provider_account_disabled), or reroutes them when they set provider_fallback. Re-enable with \
             provider_account_update(enabled=true). Returns {account, changed}.",
            disable_account,
        )
        .family("dispatch"),
    );
    r.add(
        tool(
            "provider_account_list",
            "List registered provider accounts: provider, label, billing, enabled, notes and observed state \
             (rate_limited_until, last error class). No secrets are stored.",
            list_accounts,
        )
        .read_only()
        .family("dispatch"),
    );
    r.add(
        tool(
            "provider_quota_status",
            "Observed quota state per provider account: availability (available, rate_limited, disabled, or \
             unknown when nothing was observed), rate_limited_until, last error class, the harnesses that bill \
             it, and its recent dispatch run outcomes. Built from dispatch runs and operator records only; no \
             provider is probed.",
            quota_status,
        )
        .read_only()
        .family("dispatch"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_messages_are_recognized() {
        for t in [
            "Claude AI usage limit reached|1760000000",
            "5-hour limit reached ∙ resets 3am",
            "You've hit your limit · resets 10am",
            "Error: insufficient_quota",
            "rate_limit reached for requests",
        ] {
            assert!(quota_signal(t), "{t}");
        }
        for t in ["compile error: expected `;`", "exit_code:1", "rate limiting middleware configured"] {
            assert!(!quota_signal(t), "{t}");
        }
    }

    #[test]
    fn notes_hold_no_secrets() {
        assert!(notes("rotated monthly").is_ok());
        assert!(notes("password: hunter2").is_err());
    }

    /// Review finding: a usage-limit phrase anywhere in the run log (the
    /// model's own output) rate-limited a shared account. Only a declared
    /// pattern on stderr, or in a structured JSON error event, counts.
    #[test]
    fn only_a_declared_signal_on_stderr_or_a_json_error_counts() {
        let pats = vec!["usage limit".to_string(), "insufficient_quota".to_string()];
        assert_eq!(quota_line(&[], "usage limit reached", None), None, "no patterns, no signal");
        assert_eq!(
            quota_line(&pats, "warn: x\nError: Usage limit reached for key sk-abcdefghijklmnop\n", None),
            Some(("stderr", "Error: Usage limit reached for key [redacted]".to_string()))
        );
        // The model writing the phrase on stdout is not a signal.
        let stdout =
            r#"{"type":"message_update","message":{"role":"assistant","content":"usage limit reached"}}"#;
        assert_eq!(quota_line(&pats, "", Some(stdout)), None);
        assert_eq!(quota_line(&pats, "", Some("plain usage limit text")), None);
        let pi = r#"{"type":"message_end","message":{"stopReason":"error","errorMessage":"429 insufficient_quota"}}"#;
        assert_eq!(
            quota_line(&pats, "", Some(pi)),
            Some(("json_error", "429 insufficient_quota".to_string()))
        );
        let ev = r#"{"type":"error","error":{"type":"rate_limit","message":"Usage limit hit"}}"#;
        assert_eq!(quota_line(&pats, "", Some(ev)).map(|(s, _)| s), Some("json_error"));
        assert_eq!(quota_line(&pats, "", None), None);
        let long = format!("usage limit {}", "x".repeat(500));
        assert_eq!(quota_line(&pats, &long, None).unwrap().1.chars().count(), 200);
    }
}
