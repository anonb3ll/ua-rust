//! GitHub webhook ingestion: `POST /api/github/webhook/{org}` for each
//! organization, and `POST /api/github/webhook` for the default
//! organization ([`receive_org`], [`receive`]).
//!
//! **Which organization a delivery belongs to.** The one its route names,
//! nothing else: not the repository in the payload, not a header, not
//! whichever secret happens to verify it. The bare route is the default
//! organization's. Each delivery costs one secret check: only the routed
//! organization's secret is loaded and only one MAC is computed, so an
//! unauthenticated caller cannot make the hub decrypt or hash once per
//! organization. Every organization's webhook secret should be distinct:
//! `github_credential_set` refuses a value another organization or the hub
//! configuration already uses, and the hub checks again at startup and
//! after every webhook-secret change, refusing every route whose secret
//! another route shares (fail closed; see [`Hub::webhook_route_shared`]).
//!
//! In order, before anything is parsed or stored:
//!
//! 1. `X-Hub-Signature-256` must be `sha256=` and 64 hex digits, checked
//!    before the database is touched.
//! 2. One database read, the same query for every organization id
//!    ([`credentials::webhook_route_lookup`]; a malformed id is looked up
//!    as one no organization has), then exactly one AES-GCM decryption, a
//!    dummy one when there is nothing real to decrypt
//!    ([`credentials::webhook_route_secret`]): the default organization's
//!    secret is the variable `github_webhook_secret_env` names, another
//!    active organization's its own managed secret `github:webhook-secret`.
//!    The signature must be HMAC-SHA256(that secret, raw body), compared in
//!    constant time, outside the database read.
//!
//! A malformed or wrong signature, an organization id that is unknown or
//! malformed (or not even UTF-8), a suspended organization, an organization
//! with no secret, one whose stored secret cannot be used and one whose
//! secret another route shares are all one refusal: 401 `bad_signature`,
//! the same body byte for byte, after the same steps (one read, one
//! decryption, one MAC, over a fixed dummy key when there is no secret).
//! Nothing in the answer says which it was. That is equal work, not
//! constant time: the database read finds a row or does not, and SQLite's
//! time for that is not equalised. The hub's log says, rate-limited, when
//! the default organization has no secret or a stored secret is unusable.
//!
//! **The response.** A delivery to the default organization is answered
//! with its result. Any other organization's is answered
//! organization-neutrally, `{"ok": true}`, with no organization id,
//! repository or task: those stay in its own ledger. An internal failure,
//! on any route (a database error while checking the signature included),
//! answers 500 with a fixed message, never the error's text, which the
//! hub's log carries.
//!
//! Then, for a verified delivery, in order:
//!
//! 3. The payload's own timestamps (`pull_request.merged_at` or
//!    `updated_at`, `check_run.completed_at`, `check_suite.updated_at`,
//!    `workflow_run.updated_at`, `repository.pushed_at`), when it has one,
//!    must be no older than `github_webhook_max_age_hours` (default 24;
//!    `stale`). A signed body captured long ago is not accepted again.
//! 4. Neither `X-GitHub-Delivery` (a well-formed id) nor the SHA-256 of the
//!    raw body may have been seen before in that organization (`replayed`).
//!    Replay records are per organization. The delivery and event
//!    headers are not covered by the signature, so a signed body re-sent
//!    under a fresh delivery id is still a replay. Both are recorded in
//!    `ua_ingress::inbound` (source `github`, kinds `delivery_id` and
//!    `body_sha256`), kept 30 days, at most 20 000 of each, in one
//!    transaction, and accepted under this process's claim.
//!
//! Then the event is ledgered (`agent.github.webhook.received`) in the same
//! transaction, and handled only when its repository is bound to a project
//! of that organization.
//! Afterwards both records are marked `finished`; when handling failed with
//! an internal error they are released instead, so a redelivery (by hand
//! from GitHub, which does not redeliver on its own) is processed. A
//! delivery that was accepted but never finished (the hub stopped while
//! handling it, or it has been in flight for 15 minutes) is processed
//! again when it is redelivered, not refused: every effect is
//! idempotent. The ledger event of such a redelivery says
//! `"redelivered": true`. Settling is by claim: records a redelivery took
//! over meanwhile are left to it. When the sweep abandons deliveries taken
//! on and never finished, one `agent.github.webhook.abandoned` event says
//! how many and which delivery ids.
//!
//! Effects, for a repository bound in the organization, on its tasks only:
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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use hmac::{Hmac, KeyInit, Mac};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use ua_core::UaError;
use ua_ingress::inbound;

use super::client::{BoundRepo, full_sha};
use super::credentials;
use super::{GITHUB_ACTOR, github_caller_for, reverify_head};
use crate::Hub;
use crate::families::continuity::merged::{MergedPr, close_merged};
use crate::families::managed_secrets;
use crate::families::tasks::{emit, ledger_text};

/// Delivery ids and body hashes are kept this many days for replay
/// protection, at most [`KEEP_MAX`] of each.
pub(crate) const KEEP_DAYS: i64 = 30;
const KEEP_MAX: i64 = 20_000;
/// A delivery accepted longer ago than this, or by a process that has
/// stopped, is taken on again when it is redelivered (by hand from GitHub,
/// which does not redeliver on its own).
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
    /// The delivery is not accepted on this route: a missing or wrong
    /// signature, or no usable secret for the routed organization (unknown,
    /// suspended, none set). One answer for all of them.
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
            WebhookError::BadSignature => 401,
            WebhookError::Replayed => 409,
            WebhookError::Stale => 409,
            WebhookError::BadRequest(_) => 400,
            WebhookError::Internal(_) => 500,
        }
    }

    pub fn message(&self) -> String {
        match self {
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
    parse_signature(signature).is_some_and(|mac| mac_valid(secret, body, &mac))
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

fn record_key<'a>(org: &'a str, kind: &'a str, key: &'a str) -> inbound::Delivery<'a> {
    inbound::Delivery { org_id: org, source: SOURCE, kind, key }
}

/// The 32-byte MAC an `X-Hub-Signature-256` header carries: exactly
/// `sha256=` and 64 hex digits (surrounding whitespace allowed). `None` for
/// anything else, which is refused before any secret is looked up.
pub(crate) fn parse_signature(signature: Option<&str>) -> Option<[u8; 32]> {
    let hex_sig = signature?.trim().strip_prefix("sha256=")?;
    if hex_sig.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_sig, &mut out).ok()?;
    Some(out)
}

/// Whether `mac` is HMAC-SHA256(`secret`, `body`), compared in constant time.
fn mac_valid(secret: &[u8], body: &[u8], mac: &[u8; 32]) -> bool {
    managed_secrets::trace_step("mac");
    let Ok(mut h) = Hmac::<Sha256>::new_from_slice(secret) else { return false };
    h.update(body);
    h.verify_slice(mac).is_ok()
}

/// Seconds between two warnings about one organization's webhook secret
/// (unusable, or the default organization's unset): every delivery meets
/// it, and one line per interval says enough.
const WARN_EVERY_S: i64 = 300;

/// Whether to log, now, the warning keyed `key`: once per [`WARN_EVERY_S`].
pub(crate) fn warn_now(key: &str) -> bool {
    static LAST: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    let now = ua_core::time::now_ms() / 1000;
    let Ok(mut last) = LAST.get_or_init(Mutex::default).lock() else { return false };
    if last.get(key).is_some_and(|at| now - at < WARN_EVERY_S) {
        return false;
    }
    if last.len() > 1024 {
        last.retain(|_, at| now - *at < WARN_EVERY_S);
    }
    last.insert(key.to_string(), now);
    true
}

/// The MAC key used when the routed organization has no usable secret, so
/// a refusal costs the same one MAC as a check. Never verifies anything a
/// sender can know to sign: the result is discarded.
const NO_SECRET_KEY: &[u8] = b"ua-github-webhook-no-secret";

/// Whether `org` can name an organization at all: 1-128 ASCII letters,
/// digits, `-`, `_` or `.`. Anything else is refused before the database.
fn route_org_shape(org: &str) -> bool {
    well_formed(org, 128, &['-', '_', '.'])
}

/// Verify `body` against organization `org`'s own webhook secret, and only
/// that one, with the same steps for every organization id: one database
/// read (the same query), one AES-GCM decryption (a dummy one when there is
/// nothing real to decrypt), one MAC in constant time, outside the database
/// read. Every refusal is [`WebhookError::BadSignature`] (see the module
/// documentation); a database failure is `Internal`.
async fn verify_for(hub: &Hub, org: &str, body: &[u8], signature: Option<&str>) -> Result<(), WebhookError> {
    let mac = parse_signature(signature).ok_or(WebhookError::BadSignature)?;
    // A malformed id is looked up as "", which no organization has: the
    // same read as any other id, never the sender's text in a query.
    let routed = if route_org_shape(org) { org } else { "" };
    let id = routed.to_string();
    let found = hub.db().read_async(move |c| credentials::webhook_route_lookup(c, &id)).await;
    managed_secrets::trace_step("read");
    let secret = credentials::webhook_route_secret(hub.cfg(), routed, found?);
    // A route whose secret another route shares verifies nothing.
    let secret = secret.filter(|_| !hub.webhook_route_shared(routed));
    // The same one MAC whether or not a secret was found.
    let key = secret.as_ref().map_or(NO_SECRET_KEY, |s| s.expose_secret().as_bytes());
    let valid = mac_valid(key, body, &mac);
    if valid && secret.is_some() { Ok(()) } else { Err(WebhookError::BadSignature) }
}

fn well_formed(s: &str, max: usize, extra: &[char]) -> bool {
    (1..=max).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// One delivery's checked headers and payload.
struct Parsed {
    delivery: String,
    event: String,
    action: String,
    repo: String,
    body_hash: String,
    payload: Value,
}

/// A delivery on the default organization's route, `POST /api/github/webhook`:
/// checked against the default organization's secret only.
pub async fn receive(hub: &Hub, d: WebhookDelivery<'_>) -> Result<Value, WebhookError> {
    receive_org(hub, ua_core::DEFAULT_ORG, d).await
}

/// A delivery on organization `org`'s route, `POST /api/github/webhook/{org}`:
/// checked against that organization's secret only, then recorded and
/// handled for it (see the module documentation). Any organization but the
/// default is answered organization-neutrally.
pub async fn receive_org(hub: &Hub, org: &str, d: WebhookDelivery<'_>) -> Result<Value, WebhookError> {
    let result = receive_checked(hub, org, d).await;
    match result {
        Err(WebhookError::Internal(m)) => {
            // Only an organization id that could exist is logged; the
            // sender is told nothing of the error's text, on any route.
            if route_org_shape(org) {
                tracing::warn!(org = %org, "GitHub webhook handling failed: {m}");
            } else {
                tracing::warn!("GitHub webhook handling failed: {m}");
            }
            Err(neutral_internal())
        }
        Ok(_) if org != ua_core::DEFAULT_ORG => Ok(json!({ "ok": true })),
        other => other,
    }
}

async fn receive_checked(hub: &Hub, org: &str, d: WebhookDelivery<'_>) -> Result<Value, WebhookError> {
    verify_for(hub, org, d.body, d.signature).await?;
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
    let p = Parsed {
        action: payload["action"].as_str().unwrap_or_default().to_string(),
        repo: payload["repository"]["full_name"].as_str().unwrap_or_default().to_ascii_lowercase(),
        body_hash: hex::encode(Sha256::digest(d.body)),
        delivery,
        event,
        payload,
    };
    receive_for(hub, org, &p).await
}

/// An internal failure as the sender sees it, on every route: no error
/// text, which could name an organization's rows or the hub's internals.
/// The text is in the hub's log.
fn neutral_internal() -> WebhookError {
    WebhookError::Internal("processing failed; a redelivery is processed".into())
}

/// Record and handle one delivery for organization `org`, whose secret
/// verified it: its own replay records, its bindings and tasks, its events.
async fn receive_for(hub: &Hub, org: &str, p: &Parsed) -> Result<Value, WebhookError> {
    let (og, dl, ev, ac, rp, bh) = (
        org.to_string(),
        p.delivery.clone(),
        p.event.clone(),
        p.action.clone(),
        p.repo.clone(),
        p.body_hash.clone(),
    );
    let bound = hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now_ms() / 1000;
            let sweep =
                inbound::SweepRules { max_per_kind: Some(KEEP_MAX - 1), abandon_after_s: Some(IN_FLIGHT_S) };
            // One organization per sweep, so every row it abandons belongs to
            // the organization the event below is written under.
            let swept = inbound::sweep(tx, &og, SOURCE, now, sweep)?;
            debug_assert!(swept.abandoned.iter().all(|a| a.org_id == og));
            if !swept.abandoned.is_empty() {
                let (channel, payload) = abandoned_event(&og, &swept.abandoned);
                emit(tx, &og, channel, payload, GITHUB_ACTOR)?;
            }
            let by_id = inbound::record(tx, record_key(&og, KIND_ID, &dl), now, RULES, Some(&ev))?;
            if let inbound::Sight::Duplicate { .. } = by_id {
                return Ok(None);
            }
            // The same signed body under a new delivery id is a replay too.
            // Returning here rolls the delivery id back with the transaction.
            let by_body = inbound::record(tx, record_key(&og, KIND_BODY, &bh), now, RULES, Some(&dl))?;
            if let inbound::Sight::Duplicate { .. } = by_body {
                return Err(UaError::conflict_code(REPLAYED_BODY, "this payload was already processed"));
            }
            let (Some(id_claim), Some(body_claim)) = (by_id.claim().cloned(), by_body.claim().cloned())
            else {
                return Err(UaError::internal("a recorded delivery came back without a claim"));
            };
            inbound::accept(tx, record_key(&og, KIND_ID, &dl), &id_claim, now, None)?;
            inbound::accept(tx, record_key(&og, KIND_BODY, &bh), &body_claim, now, None)?;
            // Only this organization's bindings: a repository another
            // organization binds is not bound here.
            let bound = !rp.is_empty() && BoundRepo::check(tx, &og, &rp).is_ok();
            let mut payload = json!({
                "org_id": og, "delivery_id": dl, "event": ev, "action": ac, "repo": ledger_text(&og, &rp),
                "bound": bound,
            });
            if matches!(by_id, inbound::Sight::Redelivered { .. })
                || matches!(by_body, inbound::Sight::Redelivered { .. })
            {
                payload["redelivered"] = json!(true);
            }
            emit(tx, &og, "agent.github.webhook.received", payload, GITHUB_ACTOR)?;
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
    let result = handle(hub, org, p, bound).await;
    // An internal failure releases both records so a redelivery of
    // this event is processed (every effect is idempotent); any other
    // outcome finishes them, so a later copy is a replay. Only records still
    // under this delivery's claims are settled: one a redelivery took over
    // meanwhile belongs to that redelivery and is left alone.
    let retry = matches!(result, Err(WebhookError::Internal(_)));
    let (og, dl, bh) = (org.to_string(), p.delivery.clone(), p.body_hash.clone());
    let settled = hub
        .db()
        .write_async(move |tx| {
            let now = ua_core::time::now_ms() / 1000;
            let mut not_mine = Vec::new();
            for (kind, key, claim) in [(KIND_BODY, &bh, &body_claim), (KIND_ID, &dl, &id_claim)] {
                let outcome = if retry {
                    inbound::release(tx, record_key(&og, kind, key), claim)?
                } else {
                    inbound::finish(tx, record_key(&og, kind, key), claim, now)?
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
                    delivery_id = %p.delivery,
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
fn abandoned_event(org: &str, rows: &[inbound::Abandoned]) -> (&'static str, Value) {
    let per_kind = |k: &str| rows.iter().filter(|a| a.kind == k).count();
    let ids: Vec<&str> =
        rows.iter().filter(|a| a.kind == KIND_ID).map(|a| a.key.as_str()).take(ABANDONED_IDS_MAX).collect();
    (
        "agent.github.webhook.abandoned",
        json!({
            "org_id": org,
            "count": rows.len(),
            "kinds": { KIND_ID: per_kind(KIND_ID), KIND_BODY: per_kind(KIND_BODY) },
            "delivery_ids": ids,
            "delivery_ids_truncated": per_kind(KIND_ID) > ids.len(),
        }),
    )
}

async fn handle(hub: &Hub, org: &str, p: &Parsed, bound: bool) -> Result<Value, WebhookError> {
    let (event, action, repo, payload) = (p.event.clone(), p.action.clone(), p.repo.clone(), &p.payload);
    let mut out = json!({
        "ok": true, "org_id": org, "delivery_id": p.delivery, "event": event, "action": action, "repo": repo,
    });
    if event == "ping" {
        out["handled"] = json!("ping");
        return Ok(out);
    }
    if !bound {
        out["handled"] = json!(false);
        out["reason"] = json!("repository not bound to any project of the organization");
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
            let result = close_merged(hub, &github_caller_for(org), vec![merged], false).await?;
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
            let checks = reverify_head(hub, org, &repo, &head, "webhook").await?;
            out["handled"] = json!("reverified");
            out["head_sha"] = json!(head);
            out["checks"] = json!(checks);
        }
        "push" => {
            let head = payload["after"].as_str().and_then(full_sha).filter(|h| h.chars().any(|c| c != '0'));
            match head {
                Some(head) => {
                    let checks = reverify_head(hub, org, &repo, &head, "webhook").await?;
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
