//! GitHub webhook ingestion (`POST /api/github/webhook`).
//!
//! In order, before anything is parsed or stored:
//!
//! 1. The secret is read from the variable `github_webhook_secret_env` names.
//!    Without one every delivery is refused (`not_configured`).
//! 2. `X-Hub-Signature-256` must be `sha256=<hex>` of HMAC-SHA256(secret,
//!    raw body), compared in constant time (`bad_signature`).
//! 3. The payload's own timestamps (`pull_request.merged_at` or
//!    `updated_at`, `check_run.completed_at`, `check_suite.updated_at`,
//!    `workflow_run.updated_at`, `repository.pushed_at`), when it has one,
//!    must be no older than `github_webhook_max_age_hours` (default 24;
//!    `stale`). A signed body captured long ago is not accepted again.
//! 4. Neither `X-GitHub-Delivery` (a well-formed id) nor the SHA-256 of the
//!    raw body may have been seen before (`replayed`). The delivery and event
//!    headers are not covered by the signature, so a signed body re-sent
//!    under a fresh delivery id is still a replay. Both are recorded in
//!    `ua_ingress::inbound` (source `github`, kinds `delivery_id` and
//!    `body_sha256`), kept 30 days, at most 20 000 of each, in one
//!    transaction, and accepted under this process's claim.
//!
//! Then the event is ledgered (`agent.github.webhook.received`) in the same
//! transaction, and handled only when its repository is bound to a project.
//! Afterwards both records are marked `finished`; when handling failed with
//! an internal error they are released instead, so GitHub's redelivery is
//! processed. A delivery that was accepted but never finished (the hub
//! stopped while handling it, or it has been in flight for 15 minutes) is
//! processed again when it is redelivered, not refused: every effect is
//! idempotent. The ledger event of such a redelivery says
//! `"redelivered": true`. Settling is by claim: records a redelivery took
//! over meanwhile are left to it. When the sweep abandons deliveries taken
//! on and never finished, one `agent.github.webhook.abandoned` event says
//! how many and which delivery ids.
//!
//! Effects, for a bound repository:
//!
//! - `pull_request` closed with `merged: true`: close the tasks it finishes
//!   (close-on-merge rules, `task_update` with the merge commit as evidence).
//! - `check_run`, `check_suite`, `workflow_run` completed: re-verify every
//!   recorded check with a CI reference at that head.
//! - `push`: re-verify checks recorded at the new head.
//! - `ping`: nothing.
//!
//! Anything else is acknowledged and ignored. The payload is trusted only
//! after the signature: it carries the merge commit and head, so no API call
//! is needed for these effects.

use hmac::{Hmac, KeyInit, Mac};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::UaError;
use ua_ingress::inbound;
use ua_store::{EventInput, ledger};

use super::client::{BoundRepo, full_sha};
use super::{GITHUB_ACTOR, github_caller, reverify_head};
use crate::Hub;
use crate::families::continuity::merged::{MergedPr, close_merged};

/// Delivery ids and body hashes are kept this many days for replay
/// protection, at most [`KEEP_MAX`] of each.
pub(crate) const KEEP_DAYS: i64 = 30;
const KEEP_MAX: i64 = 20_000;
/// A delivery accepted longer ago than this, or by a process that has
/// stopped, is taken on again when GitHub redelivers it.
const IN_FLIGHT_S: i64 = 15 * 60;
const SOURCE: &str = "github";
const KIND_ID: &str = "delivery_id";
const KIND_BODY: &str = "body_sha256";
const RULES: inbound::Rules =
    inbound::Rules { ttl_s: KEEP_DAYS * 86_400, in_flight_s: IN_FLIGHT_S, stale: inbound::Stale::Redeliver };
/// Marks a body-hash replay inside the dedupe transaction.
const REPLAYED_BODY: &str = "replayed_body";

/// One delivery as received: the three GitHub headers and the raw body.
#[derive(Debug, Clone, Copy)]
pub struct WebhookDelivery<'a> {
    /// `X-GitHub-Event`.
    pub event: &'a str,
    /// `X-GitHub-Delivery`.
    pub delivery_id: &'a str,
    /// `X-Hub-Signature-256`.
    pub signature: Option<&'a str>,
    pub body: &'a [u8],
}

/// Why a delivery was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookError {
    /// No webhook secret is configured.
    NotConfigured,
    /// Missing or wrong signature.
    BadSignature,
    /// The delivery id, or the same body, was already processed.
    Replayed,
    /// The payload's own timestamp is older than `github_webhook_max_age_hours`.
    Stale,
    BadRequest(String),
    Internal(String),
}

impl WebhookError {
    pub fn code(&self) -> &'static str {
        match self {
            WebhookError::NotConfigured => "not_configured",
            WebhookError::BadSignature => "bad_signature",
            WebhookError::Replayed => "replayed",
            WebhookError::Stale => "stale",
            WebhookError::BadRequest(_) => "bad_request",
            WebhookError::Internal(_) => "internal",
        }
    }

    /// The HTTP status the endpoint answers with.
    pub fn http_status(&self) -> u16 {
        match self {
            WebhookError::NotConfigured => 503,
            WebhookError::BadSignature => 401,
            WebhookError::Replayed => 409,
            WebhookError::Stale => 409,
            WebhookError::BadRequest(_) => 400,
            WebhookError::Internal(_) => 500,
        }
    }

    pub fn message(&self) -> String {
        match self {
            WebhookError::NotConfigured => {
                "no GitHub webhook secret is configured (github_webhook_secret_env)".into()
            }
            WebhookError::BadSignature => "missing or invalid X-Hub-Signature-256".into(),
            WebhookError::Replayed => "this delivery id or payload was already processed".into(),
            WebhookError::Stale => {
                "the payload's timestamp is older than github_webhook_max_age_hours; a stale delivery is not processed"
                    .into()
            }
            WebhookError::BadRequest(m) | WebhookError::Internal(m) => m.clone(),
        }
    }
}

impl From<UaError> for WebhookError {
    fn from(e: UaError) -> Self {
        WebhookError::Internal(e.to_string())
    }
}

/// The `X-Hub-Signature-256` value for `body` under `secret` (tests, tools).
pub fn signature_for(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// Whether `signature` (`sha256=<hex>`) signs `body` with `secret`.
pub fn signature_valid(secret: &[u8], body: &[u8], signature: Option<&str>) -> bool {
    let Some(hex_sig) = signature.map(str::trim).and_then(|s| s.strip_prefix("sha256=")) else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig) else { return false };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else { return false };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// A payload timestamp: RFC 3339 text or Unix seconds.
fn ts(v: &Value) -> Option<jiff::Timestamp> {
    match v {
        Value::String(s) => s.parse::<jiff::Timestamp>().ok(),
        Value::Number(n) => n.as_i64().and_then(|s| jiff::Timestamp::from_second(s).ok()),
        _ => None,
    }
}

/// The newest of the payload's own timestamps for `event`, if it has one.
pub(crate) fn payload_time(event: &str, payload: &Value) -> Option<jiff::Timestamp> {
    let fields: &[(&str, &str)] = match event {
        "pull_request" => {
            &[("pull_request", "merged_at"), ("pull_request", "updated_at"), ("pull_request", "closed_at")]
        }
        "check_run" => &[("check_run", "completed_at"), ("check_run", "started_at")],
        "check_suite" => &[("check_suite", "updated_at"), ("check_suite", "created_at")],
        "workflow_run" => &[("workflow_run", "updated_at"), ("workflow_run", "run_started_at")],
        "push" => &[("repository", "pushed_at"), ("head_commit", "timestamp")],
        _ => &[],
    };
    fields.iter().filter_map(|(obj, key)| ts(&payload[*obj][*key])).max()
}

fn record_key<'a>(kind: &'a str, key: &'a str) -> inbound::Delivery<'a> {
    inbound::Delivery { org_id: ua_core::DEFAULT_ORG, source: SOURCE, kind, key }
}

fn well_formed(s: &str, max: usize, extra: &[char]) -> bool {
    (1..=max).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// Check, record and handle one delivery.
pub async fn receive(hub: &Hub, d: WebhookDelivery<'_>) -> Result<Value, WebhookError> {
    let secret = hub.cfg().github_webhook_secret().ok_or(WebhookError::NotConfigured)?;
    if !signature_valid(secret.expose_secret().as_bytes(), d.body, d.signature) {
        return Err(WebhookError::BadSignature);
    }
    let delivery = d.delivery_id.trim().to_ascii_lowercase();
    if !well_formed(&delivery, 100, &['-']) {
        return Err(WebhookError::BadRequest("X-GitHub-Delivery is missing or malformed".into()));
    }
    let event = d.event.trim().to_ascii_lowercase();
    if !well_formed(&event, 64, &['_']) {
        return Err(WebhookError::BadRequest("X-GitHub-Event is missing or malformed".into()));
    }
    let payload: Value = serde_json::from_slice(d.body).map_err(|_| {
        WebhookError::BadRequest("the body is not JSON (set the content type to application/json)".into())
    })?;
    let max_age = hub.cfg().github_webhook_max_age_hours;
    if max_age > 0
        && let Some(at) = payload_time(&event, &payload)
    {
        let oldest = jiff::Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_hours(max_age.min(24 * 365) as i64))
            .unwrap_or_else(|_| jiff::Timestamp::now());
        if at < oldest {
            return Err(WebhookError::Stale);
        }
    }
    let action = payload["action"].as_str().unwrap_or_default().to_string();
    let repo = payload["repository"]["full_name"].as_str().unwrap_or_default().to_ascii_lowercase();
    let body_hash = hex::encode(Sha256::digest(d.body));

    let (dl, ev, ac, rp, bh) =
        (delivery.clone(), event.clone(), action.clone(), repo.clone(), body_hash.clone());
    let bound = hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now_ms() / 1000;
            let sweep =
                inbound::SweepRules { max_per_kind: Some(KEEP_MAX - 1), abandon_after_s: Some(IN_FLIGHT_S) };
            // One organization per sweep, so every row it abandons belongs to
            // the organization the event below is written under.
            let swept = inbound::sweep(tx, ua_core::DEFAULT_ORG, SOURCE, now, sweep)?;
            debug_assert!(swept.abandoned.iter().all(|a| a.org_id == ua_core::DEFAULT_ORG));
            if !swept.abandoned.is_empty() {
                ledger::append(tx, abandoned_event(&swept.abandoned).by(GITHUB_ACTOR.to_string()))?;
            }
            let by_id = inbound::record(tx, record_key(KIND_ID, &dl), now, RULES, Some(&ev))?;
            if let inbound::Sight::Duplicate { .. } = by_id {
                return Ok(None);
            }
            // The same signed body under a new delivery id is a replay too.
            // Returning here rolls the delivery id back with the transaction.
            let by_body = inbound::record(tx, record_key(KIND_BODY, &bh), now, RULES, Some(&dl))?;
            if let inbound::Sight::Duplicate { .. } = by_body {
                return Err(UaError::conflict_code(REPLAYED_BODY, "this payload was already processed"));
            }
            let (Some(id_claim), Some(body_claim)) = (by_id.claim().cloned(), by_body.claim().cloned())
            else {
                return Err(UaError::internal("a recorded delivery came back without a claim"));
            };
            inbound::accept(tx, record_key(KIND_ID, &dl), &id_claim, now, None)?;
            inbound::accept(tx, record_key(KIND_BODY, &bh), &body_claim, now, None)?;
            let bound = !rp.is_empty() && BoundRepo::check(tx, crate::families::tasks::TASK_ORG, &rp).is_ok();
            let mut payload =
                json!({ "delivery_id": dl, "event": ev, "action": ac, "repo": rp, "bound": bound });
            if matches!(by_id, inbound::Sight::Redelivered { .. })
                || matches!(by_body, inbound::Sight::Redelivered { .. })
            {
                payload["redelivered"] = json!(true);
            }
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG, "agent.github.webhook.received", payload)
                    .by(GITHUB_ACTOR.to_string()),
            )?;
            Ok(Some((bound, id_claim, body_claim)))
        })
        .await
        .map_err(|e| {
            if e.reason_code() == Some(REPLAYED_BODY) {
                WebhookError::Replayed
            } else {
                WebhookError::from(e)
            }
        })?;
    let Some((bound, id_claim, body_claim)) = bound else { return Err(WebhookError::Replayed) };
    let result = handle(hub, &event, &action, &repo, bound, &payload, &delivery).await;
    // An internal failure releases both records so GitHub's redelivery of
    // this event is processed (every effect is idempotent); any other
    // outcome finishes them, so a later copy is a replay. Only records still
    // under this delivery's claims are settled: one a redelivery took over
    // meanwhile belongs to that redelivery and is left alone.
    let retry = matches!(result, Err(WebhookError::Internal(_)));
    let (dl, bh) = (delivery.clone(), body_hash);
    let settled = hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now_ms() / 1000;
            let mut not_mine = Vec::new();
            for (kind, key, claim) in [(KIND_BODY, &bh, &body_claim), (KIND_ID, &dl, &id_claim)] {
                let outcome = if retry {
                    inbound::release(tx, record_key(kind, key), claim)?
                } else {
                    inbound::finish(tx, record_key(kind, key), claim, now)?
                };
                if let inbound::Settle::NotMine { state } = outcome {
                    not_mine.push((kind, state.map(inbound::State::as_str).unwrap_or("gone")));
                }
            }
            Ok(not_mine)
        })
        .await;
    match settled {
        Ok(not_mine) => {
            for (kind, state) in not_mine {
                tracing::info!(
                    delivery_id = %delivery,
                    kind,
                    state,
                    "a GitHub delivery record was taken over or settled by another handler; left as it is"
                );
            }
        }
        // The response stands. The records stay accepted, and a redelivery
        // after the in-flight bound is processed again.
        Err(e) => tracing::warn!(code = e.code(), "could not settle a GitHub delivery record"),
    }
    result
}

/// Most delivery ids one `agent.github.webhook.abandoned` event lists.
const ABANDONED_IDS_MAX: usize = 50;

/// `agent.github.webhook.abandoned`: deliveries the sweep found taken on and
/// never finished (the hub stopped, or they passed the in-flight bound).
/// Each may never have been handled. The count, the count per kind and up
/// to [`ABANDONED_IDS_MAX`] delivery ids; never a body or a body hash.
fn abandoned_event(rows: &[inbound::Abandoned]) -> EventInput {
    let per_kind = |k: &str| rows.iter().filter(|a| a.kind == k).count();
    let ids: Vec<&str> =
        rows.iter().filter(|a| a.kind == KIND_ID).map(|a| a.key.as_str()).take(ABANDONED_IDS_MAX).collect();
    EventInput::new(
        ua_core::DEFAULT_ORG,
        "agent.github.webhook.abandoned",
        json!({
            "count": rows.len(),
            "kinds": { KIND_ID: per_kind(KIND_ID), KIND_BODY: per_kind(KIND_BODY) },
            "delivery_ids": ids,
            "delivery_ids_truncated": per_kind(KIND_ID) > ids.len(),
        }),
    )
}

async fn handle(
    hub: &Hub,
    event: &str,
    action: &str,
    repo: &str,
    bound: bool,
    payload: &Value,
    delivery: &str,
) -> Result<Value, WebhookError> {
    let (event, action, repo) = (event.to_string(), action.to_string(), repo.to_string());
    let mut out =
        json!({ "ok": true, "delivery_id": delivery, "event": event, "action": action, "repo": repo });
    if event == "ping" {
        out["handled"] = json!("ping");
        return Ok(out);
    }
    if !bound {
        out["handled"] = json!(false);
        out["reason"] = json!("repository not bound to any project");
        return Ok(out);
    }
    match event.as_str() {
        "pull_request" => {
            let pr = &payload["pull_request"];
            if action != "closed" || pr["merged"].as_bool() != Some(true) {
                out["handled"] = json!(false);
                out["reason"] = json!("only a merged pull request has an effect");
                return Ok(out);
            }
            let number = pr["number"].as_u64().or_else(|| payload["number"].as_u64());
            let sha = pr["merge_commit_sha"].as_str().and_then(full_sha);
            let (Some(number), Some(merge_sha)) = (number, sha) else {
                return Err(WebhookError::BadRequest(
                    "a merged pull_request without number or merge_commit_sha".into(),
                ));
            };
            let merged = MergedPr {
                repo: repo.clone(),
                number,
                merge_sha,
                head_ref: pr["head"]["ref"].as_str().map(str::to_string),
                base_ref: pr["base"]["ref"].as_str().map(str::to_string),
                default_branch: payload["repository"]["default_branch"]
                    .as_str()
                    .or_else(|| pr["base"]["repo"]["default_branch"].as_str())
                    .map(str::to_string),
                merged_at: pr["merged_at"].as_str().map(str::to_string),
                url: pr["html_url"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{repo}#{number}")),
            };
            let result = close_merged(hub, &github_caller(), vec![merged], false).await?;
            out["handled"] = json!("closed_on_merge");
            out["result"] = result;
        }
        "check_run" | "check_suite" | "workflow_run" => {
            if action != "completed" {
                out["handled"] = json!(false);
                out["reason"] = json!("only a completed run has an effect");
                return Ok(out);
            }
            let head = payload[event.as_str()]["head_sha"].as_str().and_then(full_sha);
            let Some(head) = head else {
                return Err(WebhookError::BadRequest(format!("{event} without a full head_sha")));
            };
            let checks = reverify_head(hub, &repo, &head, "webhook").await?;
            out["handled"] = json!("reverified");
            out["head_sha"] = json!(head);
            out["checks"] = json!(checks);
        }
        "push" => {
            let head = payload["after"].as_str().and_then(full_sha).filter(|h| h.chars().any(|c| c != '0'));
            match head {
                Some(head) => {
                    let checks = reverify_head(hub, &repo, &head, "webhook").await?;
                    out["handled"] = json!("reverified");
                    out["head_sha"] = json!(head);
                    out["checks"] = json!(checks);
                }
                None => {
                    out["handled"] = json!(false);
                    out["reason"] = json!("a push without a new head (branch deleted)");
                }
            }
        }
        _ => {
            out["handled"] = json!(false);
            out["reason"] = json!("event type not handled");
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::signature_valid;

    #[test]
    fn signatures_match_githubs_documented_example() {
        // From GitHub's "Validating webhook deliveries" documentation.
        let sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
        assert!(signature_valid(b"It's a Secret to Everybody", b"Hello, World!", Some(sig)));
        assert!(!signature_valid(b"another secret", b"Hello, World!", Some(sig)));
        assert!(!signature_valid(b"It's a Secret to Everybody", b"Hello, World?", Some(sig)));
        assert!(!signature_valid(b"It's a Secret to Everybody", b"Hello, World!", None));
        assert!(!signature_valid(b"It's a Secret to Everybody", b"Hello, World!", Some("sha1=abc")));
        assert!(!signature_valid(b"It's a Secret to Everybody", b"Hello, World!", Some("sha256=zz")));
        assert_eq!(super::signature_for(b"It's a Secret to Everybody", b"Hello, World!"), sig);
    }
}
