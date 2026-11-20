//! GitHub webhook ingestion (`POST /api/github/webhook`).
//!
//! In order, before anything is parsed or stored:
//!
//! 1. The secret is read from the variable `github_webhook_secret_env` names.
//!    Without one every delivery is refused (`not_configured`).
//! 2. `X-Hub-Signature-256` must be `sha256=<hex>` of HMAC-SHA256(secret,
//!    raw body), compared in constant time (`bad_signature`).
//! 3. `X-GitHub-Delivery` must be a well-formed id that this hub has not
//!    seen (`replayed`). Ids are kept 30 days, at most 20 000 of them.
//!
//! Then the event is ledgered (`agent.github.webhook.received`) in the same
//! transaction that stores the delivery id, and handled only when its
//! repository is bound to a project:
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
use sha2::Sha256;
use ua_core::UaError;
use ua_store::{EventInput, ledger};

use super::client::{BoundRepo, full_sha};
use super::{GITHUB_ACTOR, github_caller, reverify_head};
use crate::Hub;
use crate::families::continuity::merged::{MergedPr, close_merged};

/// Delivery ids kept for replay protection.
const KEEP_DAYS: i64 = 30;
const KEEP_MAX: i64 = 20_000;

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
    /// The delivery id was already processed.
    Replayed,
    BadRequest(String),
    Internal(String),
}

impl WebhookError {
    pub fn code(&self) -> &'static str {
        match self {
            WebhookError::NotConfigured => "not_configured",
            WebhookError::BadSignature => "bad_signature",
            WebhookError::Replayed => "replayed",
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
            WebhookError::Replayed => "this delivery id was already processed".into(),
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
    let action = payload["action"].as_str().unwrap_or_default().to_string();
    let repo = payload["repository"]["full_name"].as_str().unwrap_or_default().to_ascii_lowercase();

    let (dl, ev, ac, rp) = (delivery.clone(), event.clone(), action.clone(), repo.clone());
    let bound = hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now();
            let cutoff = ua_core::time::format_ts(
                jiff::Timestamp::now()
                    .checked_sub(jiff::SignedDuration::from_hours(24 * KEEP_DAYS))
                    .unwrap_or_else(|_| jiff::Timestamp::now()),
            );
            tx.execute("DELETE FROM github_deliveries WHERE received_at < ?1", [&cutoff])?;
            tx.execute(
                "DELETE FROM github_deliveries WHERE delivery_id IN (SELECT delivery_id FROM github_deliveries \
                 ORDER BY received_at DESC LIMIT -1 OFFSET ?1)",
                [KEEP_MAX - 1],
            )?;
            let inserted = tx.execute(
                "INSERT INTO github_deliveries (delivery_id, event, received_at) VALUES (?1, ?2, ?3) \
                 ON CONFLICT (delivery_id) DO NOTHING",
                rusqlite::params![dl, ev, now],
            )?;
            if inserted == 0 {
                return Ok(None);
            }
            let bound = !rp.is_empty() && BoundRepo::check(tx, &rp).is_ok();
            ledger::append(
                tx,
                EventInput::new(
                    "agent.github.webhook.received",
                    json!({ "delivery_id": dl, "event": ev, "action": ac, "repo": rp, "bound": bound }),
                )
                .by(GITHUB_ACTOR.to_string()),
            )?;
            Ok(Some(bound))
        })
        .await?;
    let Some(bound) = bound else { return Err(WebhookError::Replayed) };
    let result = handle(hub, &event, &action, &repo, bound, &payload, &delivery).await;
    if let Err(WebhookError::Internal(_)) = &result {
        // Forget the id so GitHub's redelivery of this event is processed;
        // every effect is idempotent.
        let dl = delivery.clone();
        let _ = hub
            .db()
            .write_async(move |tx| {
                Ok(tx.execute("DELETE FROM github_deliveries WHERE delivery_id = ?1", [dl])?)
            })
            .await;
    }
    result
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
