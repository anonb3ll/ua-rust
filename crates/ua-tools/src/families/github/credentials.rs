//! Per-organization GitHub credentials.
//!
//! Each organization's GitHub automation (the webhook, the poller, CI
//! verification and merged-PR reconciliation) runs under that
//! organization's own credentials, and an organization without one stays
//! off. This module is the credential layer every automation path asks
//! ([`github_credential_for`], [`orgs_holding`]).
//!
//! Two credentials per organization, each optional:
//!
//! - [`CredentialKind::Token`]: the API token the REST client sends.
//! - [`CredentialKind::WebhookSecret`]: the secret a webhook delivery's
//!   `X-Hub-Signature-256` is checked against.
//!
//! **Where they live.** The default organization's credentials are the
//! hub's configuration, exactly as before: `github_token_env` and
//! `github_webhook_secret_env` ([`Config::github_token`],
//! [`Config::github_webhook_secret`]). Every other organization's are
//! managed secrets of that organization, under the reserved names
//! [`TOKEN_SECRET`] (consumer [`API_CONSUMER`]) and [`WEBHOOK_SECRET`]
//! (consumer [`WEBHOOK_CONSUMER`]), encrypted at rest with the organization
//! bound into the associated data (`crate::families::managed_secrets`).
//!
//! **No fallback.** [`github_credential_for`] never answers one
//! organization with another's credential: the default organization never
//! reads a managed secret, and another organization never reads the hub's
//! configuration or another organization's row. An organization with no
//! credential resolves to `None` and is reported `off`.
//!
//! **Who may set or clear one.** A verified human of the credential's
//! organization ([`Authority::Operator`] in the caller's organization), in
//! that organization only: there is no argument naming another. Until
//! memberships exist only the default organization's humans hold that
//! authority, and the default organization's credentials are configuration,
//! so today `github_credential_set` and `github_credential_clear` refuse every
//! caller (fail closed): another organization's credential cannot be set by
//! its own callers (no authority yet) nor by the default organization's (a
//! hub operator does not reach into a tenant's secrets). Replacing a stored
//! credential needs a one-time human approval bound to the new value's
//! keyed fingerprint; clearing one always does.
//!
//! **Never a value.** No tool returns a credential's value.
//! `github_credential_status`, the `system_doctor` line and
//! `managed_secret_list` never show its keyed fingerprint either: they
//! report `configured`, `off` or `unusable` and where the credential comes
//! from. The fingerprint appears only where every managed secret's does: in
//! the one-time approval a replacement or a clear binds, which the approval
//! queue's readers can see.
//! Events (`github.credential.set`, `github.credential.cleared`) carry the
//! kind, whether a value was replaced and the approval id; they stay in the
//! default organization's ledger (`ORG-EVENT-DEFAULT`) with originator
//! `system` for another organization.

use rusqlite::{Connection, OptionalExtension};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ua_core::{Caller, Config, DEFAULT_ORG, UaError, UaResult};
use ua_store::{EventInput, ledger};

use crate::approvals;
use crate::families::managed_secrets::{self, Sealed};
use crate::registry::{Registry, ToolCtx, tool};
use ua_org::authz::{Authority, Authz};

/// The managed secret holding an organization's GitHub API token.
pub const TOKEN_SECRET: &str = "github:token";
/// The managed secret holding an organization's GitHub webhook secret.
pub const WEBHOOK_SECRET: &str = "github:webhook-secret";
/// The consumer [`TOKEN_SECRET`] is bound to.
pub const API_CONSUMER: &str = "github:api";
/// The consumer [`WEBHOOK_SECRET`] is bound to.
pub const WEBHOOK_CONSUMER: &str = "github:webhook";
/// Secret names only these tools write (case-insensitive).
pub const RESERVED_NAMES: [&str; 2] = [TOKEN_SECRET, WEBHOOK_SECRET];
/// The consumer kind only these tools write.
pub const RESERVED_CONSUMER_KIND: &str = "github";
/// Which organizations the GitHub automation serves, as reported: each
/// organization under its own credentials.
pub const AUTOMATION_SCOPE: &str = "per_organization";

/// Which of an organization's GitHub credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// The API token.
    Token,
    /// The webhook signature secret.
    WebhookSecret,
}

impl CredentialKind {
    pub const ALL: [CredentialKind; 2] = [CredentialKind::Token, CredentialKind::WebhookSecret];

    pub fn as_str(self) -> &'static str {
        match self {
            CredentialKind::Token => "token",
            CredentialKind::WebhookSecret => "webhook_secret",
        }
    }

    /// The managed secret holding it, outside the default organization.
    pub fn secret_name(self) -> &'static str {
        match self {
            CredentialKind::Token => TOKEN_SECRET,
            CredentialKind::WebhookSecret => WEBHOOK_SECRET,
        }
    }

    /// The consumer that secret is bound to.
    pub fn consumer(self) -> &'static str {
        match self {
            CredentialKind::Token => API_CONSUMER,
            CredentialKind::WebhookSecret => WEBHOOK_CONSUMER,
        }
    }

    /// The default organization's source in the hub configuration.
    fn config_key(self) -> &'static str {
        match self {
            CredentialKind::Token => "github_token_env",
            CredentialKind::WebhookSecret => "github_webhook_secret_env",
        }
    }

    fn configured_value(self, cfg: &Config) -> Option<SecretString> {
        match self {
            CredentialKind::Token => cfg.github_token(),
            CredentialKind::WebhookSecret => cfg.github_webhook_secret(),
        }
    }
}

/// Where a credential comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// The hub's configuration: the default organization only.
    HubConfig,
    /// A managed secret of the organization.
    ManagedSecret,
}

/// One organization's GitHub credential. `Debug` never shows the value.
pub struct GithubCredential {
    kind: CredentialKind,
    source: CredentialSource,
    secret: SecretString,
}

impl std::fmt::Debug for GithubCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubCredential").field("kind", &self.kind).field("source", &self.source).finish()
    }
}

impl GithubCredential {
    pub fn kind(&self) -> CredentialKind {
        self.kind
    }

    pub fn source(&self) -> CredentialSource {
        self.source
    }

    /// The value, for the one in-process consumer (a request header, a
    /// signature check). Never returned by a tool, stored elsewhere or logged.
    pub fn secret(&self) -> &SecretString {
        &self.secret
    }
}

/// A credential's value must be one non-empty line: it becomes a header or
/// an HMAC key.
fn check_value(value: &str) -> UaResult<()> {
    if value.trim().is_empty() || value.contains(['\r', '\n', '\0']) {
        return Err(UaError::invalid("a GitHub credential must be a single non-empty line"));
    }
    Ok(())
}

/// Organization `org`'s GitHub credential of `kind`, or `None` when it has
/// none. The default organization's is the hub's configuration; every other
/// organization's is its own managed secret. Never another organization's,
/// and never the hub's for an organization other than the default.
///
/// `Err` when a stored credential exists but cannot be used (its key is no
/// longer configured, it does not decrypt in this organization, or it is not
/// a single line): the caller treats the organization as off and reports why.
pub fn github_credential_for(
    conn: &Connection,
    cfg: &Config,
    org: &str,
    kind: CredentialKind,
) -> UaResult<Option<GithubCredential>> {
    if org == DEFAULT_ORG {
        return Ok(kind.configured_value(cfg).map(|secret| GithubCredential {
            kind,
            source: CredentialSource::HubConfig,
            secret,
        }));
    }
    if !managed_secrets::bound_to(conn, org, kind.secret_name(), kind.consumer())? {
        return Ok(None);
    }
    let (secret, _fingerprint) =
        managed_secrets::load_for_consumer(conn, cfg, org, kind.secret_name(), kind.consumer())?;
    if check_value(secret.expose_secret()).is_err() {
        return Err(UaError::denied(
            "github_credential_unusable",
            format!("the organization's GitHub {} is not a single line", kind.as_str()),
        ));
    }
    Ok(Some(GithubCredential { kind, source: CredentialSource::ManagedSecret, secret }))
}

/// Every organization that may hold a GitHub credential of `kind`, in a
/// fixed order: the default organization first (its credential is the hub
/// configuration), then each other active organization (a suspended one
/// is never served) that stores the managed secret bound to its consumer,
/// by id. Resolve each with
/// [`github_credential_for`]; nothing here decrypts.
pub fn orgs_holding(conn: &Connection, kind: CredentialKind) -> UaResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT m.org_id FROM managed_secrets m JOIN orgs o ON o.id = m.org_id AND o.status = 'active' \
         WHERE m.name = ?1 AND m.consumer = ?2 AND m.org_id <> ?3 ORDER BY m.org_id",
    )?;
    let others = stmt
        .query_map([kind.secret_name(), kind.consumer(), DEFAULT_ORG], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(std::iter::once(DEFAULT_ORG.to_string()).chain(others).collect())
}

/// What one webhook-route lookup read: whether the routed id is an active
/// organization, and its stored webhook-secret row if it has one. Holds no
/// plaintext.
pub(crate) struct RouteLookup {
    active: bool,
    row: Option<managed_secrets::SealedRow>,
}

/// The one database read a webhook delivery costs, the same query for
/// every organization id: active or not, known or not, with a secret or
/// without (a malformed id is looked up as `""`, which no organization has).
/// Nothing is decrypted here; see [`webhook_route_secret`].
pub(crate) fn webhook_route_lookup(conn: &Connection, org: &str) -> UaResult<RouteLookup> {
    type Row = (Option<String>, Option<String>, Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>);
    let found: Option<Row> = conn
        .query_row(
            "SELECT m.consumer, m.key_id, m.nonce, m.ciphertext, m.aad_v FROM orgs o \
             LEFT JOIN managed_secrets m ON m.org_id = o.id AND m.name = ?2 \
             WHERE o.id = ?1 AND o.status = 'active'",
            [org, WEBHOOK_SECRET],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some(found) = found else { return Ok(RouteLookup { active: false, row: None }) };
    let row = match found {
        (Some(consumer), Some(key_id), Some(nonce), Some(ciphertext), Some(aad_v)) => {
            Some(managed_secrets::SealedRow { consumer, key_id, nonce, ciphertext, aad_v })
        }
        _ => None,
    };
    Ok(RouteLookup { active: true, row })
}

/// Organization `org`'s webhook secret from what [`webhook_route_lookup`]
/// read, or `None` when the route must refuse the delivery: not an active
/// organization (the default organization always is), no secret, or a
/// stored secret that cannot be used. Exactly one AES-GCM decryption on
/// every path, a dummy one when there is nothing real to decrypt (the
/// default organization's secret is configuration, so its route always
/// takes the dummy). Never another organization's secret. An unusable
/// stored secret, and the default organization's unset one, are logged at
/// most once per interval each; never a secret.
pub(crate) fn webhook_route_secret(cfg: &Config, org: &str, found: RouteLookup) -> Option<SecretString> {
    let (name, consumer) = (WEBHOOK_SECRET, WEBHOOK_CONSUMER);
    if org == DEFAULT_ORG {
        let _ = managed_secrets::open_once(cfg, org, name, consumer, None);
        let secret = CredentialKind::WebhookSecret.configured_value(cfg);
        if secret.is_none() && super::webhook::warn_now("default:unset") {
            tracing::warn!(
                "a GitHub delivery reached the default organization's webhook route, but \
                 github_webhook_secret_env names no secret; it was refused"
            );
        }
        return secret;
    }
    let row = found.row.as_ref().filter(|_| found.active);
    let unusable = |code: &str| {
        if super::webhook::warn_now(&format!("unusable:{org}")) {
            tracing::warn!(
                org = %org,
                code,
                "a stored GitHub webhook secret is unusable; deliveries to its route are refused"
            );
        }
    };
    match managed_secrets::open_once(cfg, org, name, consumer, row) {
        Ok(Some(secret)) if check_value(secret.expose_secret()).is_ok() => Some(secret),
        Ok(Some(_)) => {
            unusable("github_credential_unusable");
            None
        }
        Ok(None) => None,
        Err(e) => {
            unusable(e.reason_code().unwrap_or(e.code()));
            None
        }
    }
}

/// The reason code of a refused shared webhook secret.
pub(crate) const SECRET_IN_USE: &str = "webhook_secret_in_use";

/// Webhook routes whose secret is not the organization's own, found by
/// [`scan_shared_webhook_secrets`]: by organization id, the default
/// organization's id standing for the bare route.
pub type SharedWebhookRoutes = std::collections::BTreeSet<String>;

/// Find webhook routes whose secret another route shares, at hub startup
/// and after a webhook secret is set or cleared. Two checks, by keyed
/// fingerprint, never by printing a value:
///
/// - the hub configuration's secret (the bare route) against every stored
///   `github:webhook-secret` row, under the key each row was sealed with:
///   a match puts the bare route and that organization's route in the set;
/// - stored rows against each other: each usable row is decrypted
///   in-process and fingerprinted under the write key, so rows sealed under
///   different keys compare too; every row of a matching group is in the set.
///
/// Rows of suspended organizations count (one may be reactivated). A row
/// that cannot be opened (its key is gone) verifies nothing and is not
/// compared. The default organization's own stored row, which no route
/// reads, is not compared.
pub fn scan_shared_webhook_secrets(conn: &Connection, cfg: &Config) -> UaResult<SharedWebhookRoutes> {
    let mut stmt = conn.prepare(
        "SELECT org_id, consumer, key_id, nonce, ciphertext, aad_v, fingerprint FROM managed_secrets \
         WHERE name = ?1 AND consumer = ?2 AND org_id <> ?3 ORDER BY org_id",
    )?;
    let rows = stmt
        .query_map([WEBHOOK_SECRET, WEBHOOK_CONSUMER, DEFAULT_ORG], |r| {
            Ok((
                r.get::<_, String>(0)?,
                managed_secrets::SealedRow {
                    consumer: r.get(1)?,
                    key_id: r.get(2)?,
                    nonce: r.get(3)?,
                    ciphertext: r.get(4)?,
                    aad_v: r.get(5)?,
                },
                r.get::<_, String>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut shared = SharedWebhookRoutes::new();
    if let Some(hub) = cfg.github_webhook_secret() {
        for (org, row, stored_fp) in &rows {
            let fp = managed_secrets::fingerprint_under_key(cfg, &row.key_id, hub.expose_secret());
            if fp.as_deref() == Some(stored_fp.as_str()) {
                shared.insert(DEFAULT_ORG.to_string());
                shared.insert(org.clone());
            }
        }
    }
    let mut by_value: std::collections::BTreeMap<String, Vec<&str>> = std::collections::BTreeMap::new();
    for (org, row, _) in &rows {
        let Ok(Some(value)) =
            managed_secrets::open_once(cfg, org, WEBHOOK_SECRET, WEBHOOK_CONSUMER, Some(row))
        else {
            continue;
        };
        if let Some(fp) = managed_secrets::config_fingerprint(cfg, value.expose_secret()) {
            by_value.entry(fp).or_default().push(org);
        }
    }
    for orgs in by_value.into_values().filter(|o| o.len() > 1) {
        shared.extend(orgs.into_iter().map(str::to_string));
    }
    Ok(shared)
}

/// Log the outcome of [`scan_shared_webhook_secrets`]: loudly, naming the
/// refused routes' organizations, never a value or a fingerprint. `None`
/// is a scan that failed, which refuses every webhook route (fail closed).
pub fn log_shared_webhook_secrets(found: Option<&SharedWebhookRoutes>) {
    match found {
        None => tracing::error!(
            "could not check GitHub webhook secrets for sharing; every GitHub webhook route is refused until a \
             check succeeds (the serving hub retries the check, backing off to once a minute; restart the hub if \
             it keeps failing)"
        ),
        Some(shared) if !shared.is_empty() => tracing::error!(
            routes = shared.len(),
            orgs = %shared.iter().cloned().collect::<Vec<_>>().join(", "),
            "GitHub webhook secrets are shared between routes (\"{DEFAULT_ORG}\" is the bare route and the hub \
             configuration); those routes refuse every delivery until each holds a secret of its own"
        ),
        Some(_) => {}
    }
}

/// Refuse `sealed` as organization `org`'s webhook secret when another
/// organization's stored webhook secret, or (outside the default
/// organization) the hub configuration's, is the same value. Compared by
/// keyed fingerprint only, under the key each stored row was sealed with
/// (a row whose key is no longer configured cannot verify anything and is
/// not compared); never by plaintext, and the refusal names no
/// organization. Suspended organizations count: one may be reactivated.
pub(crate) fn refuse_shared_webhook_secret(
    conn: &Connection,
    cfg: &Config,
    org: &str,
    sealed: &Sealed,
) -> UaResult<()> {
    let in_use = || {
        UaError::conflict_code(
            SECRET_IN_USE,
            "this webhook secret is already in use by another organization or the hub; every organization's \
             webhook secret must be its own, so choose a different value",
        )
    };
    if org != DEFAULT_ORG
        && let Some(hub) = cfg.github_webhook_secret()
        && managed_secrets::config_fingerprint(cfg, hub.expose_secret()).as_deref()
            == Some(sealed.fingerprint.as_str())
    {
        return Err(in_use());
    }
    let mut stmt = conn.prepare(
        "SELECT key_id, fingerprint FROM managed_secrets WHERE name = ?1 AND consumer = ?2 AND org_id <> ?3",
    )?;
    let rows = stmt
        .query_map([WEBHOOK_SECRET, WEBHOOK_CONSUMER, org], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    if rows.iter().any(|(key_id, fp)| sealed.fingerprint_under(key_id) == Some(fp.as_str())) {
        return Err(in_use());
    }
    Ok(())
}

/// Whether a credential is usable, without decrypting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Configured,
    Off,
    /// Stored, but sealed with a key the hub no longer has (or none is
    /// set), or in an associated-data form this organization refuses.
    Unusable,
}

/// One line of an organization's GitHub credential status. Never a value or
/// a fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CredentialStatus {
    pub kind: CredentialKind,
    pub state: CredentialState,
    pub source: Option<CredentialSource>,
    /// Where the credential is set: the configuration key for the default
    /// organization, the managed secret's name for another.
    pub set_with: &'static str,
}

/// The status of organization `org`'s credential of `kind`. Reads metadata
/// only: a stored credential is `configured` when the key it was sealed
/// with is still configured and its associated-data form is one this
/// organization opens.
pub fn credential_status(
    conn: &Connection,
    cfg: &Config,
    org: &str,
    kind: CredentialKind,
) -> UaResult<CredentialStatus> {
    if org == DEFAULT_ORG {
        let configured = kind.configured_value(cfg).is_some();
        return Ok(CredentialStatus {
            kind,
            state: if configured { CredentialState::Configured } else { CredentialState::Off },
            source: configured.then_some(CredentialSource::HubConfig),
            set_with: kind.config_key(),
        });
    }
    // Mirrors what github_credential_for would refuse without decrypting:
    // a key no longer configured, or an associated-data form this
    // organization never opens (form 1 outside the default organization, or
    // an unknown form).
    let state = match managed_secrets::sealed_with(conn, org, kind.secret_name())? {
        Some(found) if found.consumer == kind.consumer() => {
            let key = managed_secrets::key_ids(cfg).contains(&found.key_id);
            if key && managed_secrets::form_accepted(found.aad_v, org) {
                CredentialState::Configured
            } else {
                CredentialState::Unusable
            }
        }
        _ => CredentialState::Off,
    };
    Ok(CredentialStatus {
        kind,
        state,
        source: (state != CredentialState::Off).then_some(CredentialSource::ManagedSecret),
        set_with: kind.secret_name(),
    })
}

/// The status of both of organization `org`'s credentials, as reported.
pub fn status_json(conn: &Connection, cfg: &Config, org: &str) -> UaResult<Value> {
    let mut out = serde_json::Map::new();
    for kind in CredentialKind::ALL {
        let s = credential_status(conn, cfg, org, kind)?;
        out.insert(
            kind.as_str().into(),
            json!({ "state": s.state, "source": s.source, "set_with": s.set_with }),
        );
    }
    out.insert("automation_scope".into(), json!(AUTOMATION_SCOPE));
    Ok(Value::Object(out))
}

// --- authority -------------------------------------------------------------------

/// Refuse anyone who may not set or clear a GitHub credential of `org`, the
/// caller's own organization. In order: an anonymous caller; an
/// organization `orgs` does not hold; a caller without operator authority
/// there (today everyone outside the default organization, so another
/// organization's credential is refused to all: fail closed); and the
/// default organization, whose credentials are the hub's configuration.
fn require_credential_admin(
    c: &Connection,
    cfg: &Config,
    caller: &Caller,
    org: &str,
    doing: &str,
) -> UaResult<()> {
    managed_secrets::require_identity(caller, doing)?;
    managed_secrets::require_org(c, org)?;
    if !Authz::new(cfg).holds(caller, &[Authority::Operator], org) {
        return Err(UaError::denied(
            "operator_only",
            format!(
                "{doing} is for a verified human of the credential's organization; until memberships exist no \
                 caller holds that authority outside the default organization"
            ),
        ));
    }
    if org == DEFAULT_ORG {
        return Err(UaError::denied(
            "github_credential_in_hub_config",
            "the default organization's GitHub credentials are the hub's configuration (github_token_env, \
             github_webhook_secret_env); set them there",
        ));
    }
    Ok(())
}

// --- tools -----------------------------------------------------------------------

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetArgs {
    /// `token` (the API token) or `webhook_secret` (the webhook signature secret).
    pub kind: CredentialKind,
    /// The value, one line, 1-65536 bytes. Never returned by any tool.
    pub value: String,
}

impl std::fmt::Debug for SetArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SetArgs").field("kind", &self.kind).finish()
    }
}

/// What an approval of `github_credential_set` binds: the reserved name and
/// consumer, the keyed fingerprint and the size, never the value.
fn set_gate_payload(cfg: &Config, args: &Value) -> Value {
    let kind = args.get("kind").cloned().and_then(|k| serde_json::from_value::<CredentialKind>(k).ok());
    let value = args.get("value").and_then(Value::as_str).unwrap_or("");
    let fp = managed_secrets::config_fingerprint(cfg, value);
    let (name, consumer) = kind.map(|k| (k.secret_name(), k.consumer())).unwrap_or(("", ""));
    managed_secrets::set_payload(name, consumer, fp.as_deref(), value.len())
}

async fn github_credential_set(ctx: ToolCtx, a: SetArgs) -> UaResult<Value> {
    const TOOL: &str = "github_credential_set";
    let (cfg, caller) = (ctx.hub.cfg().clone(), ctx.caller.clone());
    let org = caller.org_id.clone();
    {
        let (cfg, caller, org) = (cfg.clone(), caller.clone(), org.clone());
        ctx.hub.db().read_async(move |c| require_credential_admin(c, &cfg, &caller, &org, TOOL)).await?;
    }
    check_value(&a.value)?;
    let kind = a.kind;
    let sealed: Sealed =
        managed_secrets::seal_value(&cfg, &org, kind.secret_name(), kind.consumer(), &a.value)?;
    drop(a.value);
    // With github_credential_set in approval_tools the registry has already
    // consumed a pass for this exact payload.
    let registry_gated = cfg.approval_tools.iter().any(|t| t == TOOL);
    let hub = ctx.hub.clone();
    let blocked_org = org.clone();
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_credential_admin(tx, hub.cfg(), &caller, &org, TOOL)?;
            let stored = match managed_secrets::put(
                tx,
                hub.cfg(),
                &caller,
                &org,
                TOOL,
                kind.secret_name(),
                kind.consumer(),
                &sealed,
                registry_gated,
            )? {
                Ok(s) => s,
                Err(not_stored) => return Ok(Err(not_stored)),
            };
            // ORG-EVENT-DEFAULT: use the credential's organization once
            // callers can resolve to other organizations and org_guard
            // allows it. The payload is enumerated values and ids only.
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "github.credential.set",
                    json!({ "kind": kind, "replaced": stored.replaced, "approval_id": stored.approval_id }),
                )
                .by(approvals::ledger_originator(&org, &caller.label)),
            )?;
            Ok(Ok(json!({
                "kind": kind, "state": CredentialState::Configured, "source": CredentialSource::ManagedSecret,
                "replaced": stored.replaced, "updated_at": stored.updated_at,
                "approval_id": stored.approval_id,
            })))
        })
        .await?;
    if out.is_ok() && kind == CredentialKind::Token {
        // A new token has its own rate limit.
        super::client::clear_blocks(&blocked_org);
    }
    if out.is_ok() && kind == CredentialKind::WebhookSecret {
        ctx.hub.rescan_shared_webhook_secrets().await;
    }
    out.map_err(|not_stored| not_stored.into_error(TOOL))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClearArgs {
    /// `token` or `webhook_secret`.
    pub kind: CredentialKind,
}

async fn github_credential_clear(ctx: ToolCtx, a: ClearArgs) -> UaResult<Value> {
    const TOOL: &str = "github_credential_clear";
    let (cfg, caller) = (ctx.hub.cfg().clone(), ctx.caller.clone());
    let org = caller.org_id.clone();
    {
        let (cfg, caller, org) = (cfg.clone(), caller.clone(), org.clone());
        ctx.hub.db().read_async(move |c| require_credential_admin(c, &cfg, &caller, &org, TOOL)).await?;
    }
    let kind = a.kind;
    let hub = ctx.hub.clone();
    let blocked_org = org.clone();
    let out = ctx
        .hub
        .db()
        .write_async(move |tx| {
            require_credential_admin(tx, hub.cfg(), &caller, &org, TOOL)?;
            match managed_secrets::sealed_with(tx, &org, kind.secret_name())? {
                Some(found) if found.consumer == kind.consumer() => {}
                _ => {
                    return Err(UaError::not_found(format!(
                        "the organization has no GitHub {} to clear",
                        kind.as_str()
                    )));
                }
            }
            let removed = managed_secrets::remove(tx, hub.cfg(), &caller, &org, TOOL, kind.secret_name())?;
            let (_, approval_id) = match removed {
                Ok(done) => done,
                Err(pending) => return Ok(Err(pending)),
            };
            // ORG-EVENT-DEFAULT: as in github_credential_set.
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "github.credential.cleared",
                    json!({ "kind": kind, "approval_id": approval_id }),
                )
                .by(approvals::ledger_originator(&org, &caller.label)),
            )?;
            Ok(Ok(json!({
                "kind": kind, "state": CredentialState::Off, "cleared": true, "approval_id": approval_id,
            })))
        })
        .await?;
    if out.is_ok() && kind == CredentialKind::Token {
        // No token, no block to keep: a token set later starts clean.
        super::client::clear_blocks(&blocked_org);
    }
    if out.is_ok() && kind == CredentialKind::WebhookSecret {
        ctx.hub.rescan_shared_webhook_secrets().await;
    }
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: TOOL.into(), approval_id })
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusArgs {}

async fn github_credential_status(ctx: ToolCtx, _a: StatusArgs) -> UaResult<Value> {
    let (cfg, org) = (ctx.hub.cfg().clone(), ctx.caller.org_id.clone());
    ctx.hub.db().read_async(move |c| status_json(c, &cfg, &org)).await
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "github_credential_set",
            "Store the caller's organization's GitHub credential: kind `token` (the API token) or \
             `webhook_secret` (the webhook signature secret), encrypted at rest. For a verified human of that \
             organization; the default organization's credentials are the hub configuration \
             (github_token_env, github_webhook_secret_env) and are refused here. The value is never returned \
             by any tool. Replacing a stored value needs a one-time human approval bound to the new value's \
             keyed fingerprint (the identical retry after approval stores it). Refused when the hub has no \
             managed_secret_key.",
            github_credential_set,
        )
        .gate_payload(set_gate_payload)
        .secret_args()
        .handler_may_gate(crate::HandlerGate::Always)
        .family("secrets"),
    );
    r.add(
        tool(
            "github_credential_clear",
            "Clear the caller's organization's GitHub `token` or `webhook_secret`, turning that part of its \
             GitHub automation off. For a verified human of that organization (not the default organization, \
             whose credentials are configuration), and always needs a one-time human approval bound to the \
             credential's current fingerprint; the identical retry after approval clears it.",
            github_credential_clear,
        )
        .always_gated()
        .gates_in_handler()
        .family("secrets"),
    );
    r.add(
        tool(
            "github_credential_status",
            "The caller's organization's GitHub credentials: for `token` and `webhook_secret`, whether each is \
             configured, off or unusable, and where it comes from. Never a value or a fingerprint.",
            github_credential_status,
        )
        .read_only()
        .family("secrets"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hub;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const ORG_B: &str = "org-b";
    const ORG_C: &str = "org-c";
    const HUB_TOKEN: &str = "fake-hub-token-not-real";
    const HUB_HOOK: &str = "fake-hub-webhook-not-real";
    const B_TOKEN: &str = "fake-org-b-token-not-real";
    const B_HOOK: &str = "fake-org-b-webhook-not-real";

    fn hub(with_hub_config: bool) -> Hub {
        let mut cfg = Config::for_home(std::env::temp_dir().join("ua-gh-credentials-unit"));
        cfg.managed_secret_key = Some(KEY.to_string().into());
        if with_hub_config {
            cfg.github_token_value = Some(HUB_TOKEN.to_string().into());
            cfg.github_webhook_secret_value = Some(HUB_HOOK.to_string().into());
        }
        let hub = Hub::in_memory(cfg).unwrap();
        hub.db()
            .write(|tx| {
                for org in [ORG_B, ORG_C] {
                    tx.execute(
                        "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at)
                         VALUES (?1, ?1, ?1, '[\"developer\"]', '2026-01-01T00:00:00+00:00')",
                        [org],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        hub
    }

    /// Org B's credentials, stored through the shared write path: no tool can
    /// store them until memberships exist.
    fn store(hub: &Hub, org: &str, kind: CredentialKind, value: &str) {
        let sealed =
            managed_secrets::seal_value(hub.cfg(), org, kind.secret_name(), kind.consumer(), value).unwrap();
        let caller = Caller::system_for(org);
        let cfg = hub.cfg().clone();
        let org = org.to_string();
        hub.db()
            .write(move |tx| {
                let out = managed_secrets::put(
                    tx,
                    &cfg,
                    &caller,
                    &org,
                    "github_credential_set",
                    kind.secret_name(),
                    kind.consumer(),
                    &sealed,
                    true,
                )?;
                assert!(out.is_ok());
                Ok(())
            })
            .unwrap();
    }

    /// Store through `put` under `cfg` and return what it said. A refusal
    /// `put` ledgers is committed, as the tool commits it.
    fn try_store(hub: &Hub, cfg: &Config, org: &str, kind: CredentialKind, value: &str) -> UaResult<()> {
        try_put(hub, cfg, org, kind, value, true)
    }

    /// [`try_store`], gated by `put` itself unless `registry_gated`.
    fn try_put(
        hub: &Hub,
        cfg: &Config,
        org: &str,
        kind: CredentialKind,
        value: &str,
        registry_gated: bool,
    ) -> UaResult<()> {
        let sealed =
            managed_secrets::seal_value(cfg, org, kind.secret_name(), kind.consumer(), value).unwrap();
        let caller = Caller::system_for(org);
        let (cfg, org) = (cfg.clone(), org.to_string());
        let out = hub.db().write(move |tx| {
            let out = managed_secrets::put(
                tx,
                &cfg,
                &caller,
                &org,
                "github_credential_set",
                kind.secret_name(),
                kind.consumer(),
                &sealed,
                registry_gated,
            )?;
            Ok(out.map(|_| ()))
        })?;
        out.map_err(|not_stored| not_stored.into_error("github_credential_set"))
    }

    /// Store `value` as `org`'s webhook secret under `cfg` with none of
    /// `put`'s checks, as a row from before the uniqueness rule.
    fn store_unchecked(hub: &Hub, cfg: &Config, org: &str, value: &str) {
        let kind = CredentialKind::WebhookSecret;
        let sealed =
            managed_secrets::seal_value(cfg, org, kind.secret_name(), kind.consumer(), value).unwrap();
        let org = org.to_string();
        hub.db()
            .write(move |tx| {
                managed_secrets::put_unchecked(tx, &org, kind.secret_name(), kind.consumer(), &sealed)
            })
            .unwrap();
    }

    fn scan(hub: &Hub, cfg: &Config) -> Vec<String> {
        let cfg = cfg.clone();
        hub.db().read(move |c| scan_shared_webhook_secrets(c, &cfg)).unwrap().into_iter().collect()
    }

    /// `(payload, originator)` of every `github.credential.refused` event.
    fn refused_events(hub: &Hub) -> Vec<(Value, String)> {
        hub.db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT payload, originator FROM event_log WHERE channel = 'github.credential.refused' \
                     ORDER BY seq",
                )?;
                let rows = stmt
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows.into_iter().map(|(p, o)| (serde_json::from_str(&p).unwrap(), o)).collect())
            })
            .unwrap()
    }

    /// Every refused shared webhook secret leaves a ledger record: the
    /// attempted value's keyed fingerprint, originator `system` for another
    /// organization, and nothing naming the value or the organization it
    /// collides with.
    #[test]
    fn a_refused_shared_webhook_secret_is_ledgered_by_fingerprint_only() {
        let hub = hub(true);
        let cfg = hub.cfg().clone();
        store(&hub, ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        for _ in 0..2 {
            let err = try_store(&hub, &cfg, ORG_C, CredentialKind::WebhookSecret, B_HOOK).unwrap_err();
            assert_eq!(err.reason_code(), Some(SECRET_IN_USE));
        }
        let events = refused_events(&hub);
        assert_eq!(events.len(), 2, "each probe is recorded");
        let want = managed_secrets::config_fingerprint(&cfg, B_HOOK).unwrap();
        for (payload, originator) in &events {
            assert_eq!(payload["fingerprint"], want.as_str());
            assert_eq!(payload["reason"], SECRET_IN_USE);
            assert_eq!(originator, approvals::NEUTRAL_ORIGINATOR);
            let text = payload.to_string();
            for leak in [B_HOOK, ORG_B, ORG_C] {
                assert!(!text.contains(leak), "{leak} in {text}");
            }
        }
        assert_eq!(webhook_rows(&hub), [ORG_B]);
    }

    /// Replacing a stored webhook secret answers nothing about the new value
    /// before a human approved it: the approval is requested first, and the
    /// uniqueness check (with its ledger record) only runs once it passes.
    #[test]
    fn a_replacement_is_checked_for_sharing_only_after_its_approval() {
        let hub = hub(true);
        let cfg = hub.cfg().clone();
        store(&hub, ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        store(&hub, ORG_C, CredentialKind::WebhookSecret, "fake-org-c-webhook-not-real");
        let err = try_put(&hub, &cfg, ORG_C, CredentialKind::WebhookSecret, B_HOOK, false).unwrap_err();
        assert!(matches!(err, UaError::ApprovalRequired { .. }), "{err:?}");
        assert!(refused_events(&hub).is_empty(), "no answer about the value before approval");
    }

    /// The startup check finds every route whose secret another route
    /// shares: rows stored before the uniqueness rule, compared with each
    /// other across key rotation (decrypted in-process, fingerprinted under
    /// the write key) and with the hub configuration under each row's own
    /// key. A row whose key is gone, the default organization's own unused
    /// row and a token are never compared.
    #[test]
    fn the_startup_check_finds_shared_webhook_secrets_across_keys_and_the_hub_configuration() {
        let hub = hub(true);
        let cfg = hub.cfg().clone();
        assert!(scan(&hub, &cfg).is_empty());
        store(&hub, ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        store(&hub, ORG_C, CredentialKind::Token, B_HOOK);
        assert!(scan(&hub, &cfg).is_empty(), "a token may share the value");

        // C's row holds B's value, sealed under a newer key.
        let mut newer = cfg.clone();
        newer.managed_secret_key = Some(base64_key().into());
        store_unchecked(&hub, &newer, ORG_C, B_HOOK);
        let mut both = cfg.clone();
        both.managed_secret_key = Some(format!("{},{KEY}", base64_key()).into());
        assert_eq!(scan(&hub, &both), [ORG_B, ORG_C]);
        // Under the old key alone C's row cannot be opened: it verifies
        // nothing, and is not compared.
        assert!(scan(&hub, &cfg).is_empty());

        // A row holding the hub configuration's value, sealed under the
        // older key, shares the bare route's secret.
        hub.db()
            .write(|tx| {
                tx.execute(
                    "DELETE FROM managed_secrets WHERE org_id = ?1 AND name = ?2",
                    [ORG_C, WEBHOOK_SECRET],
                )?;
                Ok(())
            })
            .unwrap();
        store_unchecked(&hub, &cfg, ORG_C, HUB_HOOK);
        assert_eq!(scan(&hub, &both), [DEFAULT_ORG, ORG_C]);
        let mut no_hub = both.clone();
        no_hub.github_webhook_secret_value = None;
        assert!(scan(&hub, &no_hub).is_empty());
        // The default organization's own row is never read by a route.
        store_unchecked(&hub, &cfg, DEFAULT_ORG, B_HOOK);
        assert_eq!(scan(&hub, &both), [DEFAULT_ORG, ORG_C]);
    }

    fn webhook_rows(hub: &Hub) -> Vec<String> {
        hub.db()
            .read(|c| {
                let mut stmt = c.prepare(
                    "SELECT org_id FROM managed_secrets WHERE name = 'github:webhook-secret' ORDER BY org_id",
                )?;
                Ok(stmt.query_map([], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?)
            })
            .unwrap()
    }

    /// An organization's webhook secret must be its own: `put` refuses a
    /// value another organization stores (even one sealed under an older
    /// key) or the hub configuration holds, by fingerprint, without naming
    /// either. The same value as a token, or the organization's own current
    /// value again, is fine.
    #[test]
    fn a_webhook_secret_another_organization_uses_is_refused_without_naming_it() {
        let hub = hub(true);
        let cfg = hub.cfg().clone();
        store(&hub, ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        for value in [B_HOOK, HUB_HOOK] {
            let err = try_store(&hub, &cfg, ORG_C, CredentialKind::WebhookSecret, value).unwrap_err();
            assert_eq!(err.reason_code(), Some("webhook_secret_in_use"), "{err:?}");
            let text = format!("{err:?} {err}");
            for leak in [ORG_B, DEFAULT_ORG, B_HOOK, HUB_HOOK, "fingerprint"] {
                assert!(!text.contains(leak), "{leak} in {text}");
            }
        }
        assert_eq!(webhook_rows(&hub), [ORG_B], "nothing stored for organization C");
        // A token may share the value; the rule is for webhook secrets.
        try_store(&hub, &cfg, ORG_C, CredentialKind::Token, B_HOOK).unwrap();
        // B storing its own value again is not a clash with itself.
        try_store(&hub, &cfg, ORG_B, CredentialKind::WebhookSecret, B_HOOK).unwrap();
        // A distinct value is stored.
        try_store(&hub, &cfg, ORG_C, CredentialKind::WebhookSecret, "fake-org-c-webhook-not-real").unwrap();
        assert_eq!(webhook_rows(&hub), [ORG_B, ORG_C]);

        // After a key rotation B's row is still sealed under the old key: the
        // candidate is compared under that key, and still refused.
        let mut rotated = cfg.clone();
        rotated.managed_secret_key = Some(format!("{},{KEY}", base64_key()).into());
        let err = try_store(&hub, &rotated, ORG_C, CredentialKind::WebhookSecret, B_HOOK).unwrap_err();
        assert_eq!(err.reason_code(), Some("webhook_secret_in_use"));
        // Without the hub configuration, its old value is free.
        let mut no_hub = cfg.clone();
        no_hub.github_webhook_secret_value = None;
        try_store(&hub, &no_hub, ORG_C, CredentialKind::WebhookSecret, HUB_HOOK).unwrap();
    }

    fn resolve(hub: &Hub, org: &str, kind: CredentialKind) -> UaResult<Option<GithubCredential>> {
        let cfg = hub.cfg().clone();
        let org = org.to_string();
        hub.db().read(move |c| github_credential_for(c, &cfg, &org, kind))
    }

    fn value(c: &Option<GithubCredential>) -> Option<String> {
        c.as_ref().map(|c| c.secret().expose_secret().to_string())
    }

    #[test]
    fn the_default_organization_resolves_to_the_hub_configuration_only() {
        let hub = hub(true);
        store(&hub, ORG_B, CredentialKind::Token, B_TOKEN);
        let t = resolve(&hub, DEFAULT_ORG, CredentialKind::Token).unwrap();
        assert_eq!(value(&t).as_deref(), Some(HUB_TOKEN));
        assert_eq!(t.unwrap().source(), CredentialSource::HubConfig);
        let w = resolve(&hub, DEFAULT_ORG, CredentialKind::WebhookSecret).unwrap();
        assert_eq!(value(&w).as_deref(), Some(HUB_HOOK));

        // Without the configuration the default organization is off, even
        // when another organization holds a credential.
        let bare = hub_without_config_but_org_b();
        assert!(resolve(&bare, DEFAULT_ORG, CredentialKind::Token).unwrap().is_none());
        assert!(resolve(&bare, DEFAULT_ORG, CredentialKind::WebhookSecret).unwrap().is_none());
    }

    fn hub_without_config_but_org_b() -> Hub {
        let hub = hub(false);
        store(&hub, ORG_B, CredentialKind::Token, B_TOKEN);
        store(&hub, ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        hub
    }

    #[test]
    fn another_organization_resolves_to_its_own_credential_and_never_falls_back() {
        let hub = hub(true);
        store(&hub, ORG_B, CredentialKind::Token, B_TOKEN);
        store(&hub, ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        let t = resolve(&hub, ORG_B, CredentialKind::Token).unwrap();
        assert_eq!(value(&t).as_deref(), Some(B_TOKEN));
        assert_eq!(t.unwrap().source(), CredentialSource::ManagedSecret);
        assert_eq!(
            value(&resolve(&hub, ORG_B, CredentialKind::WebhookSecret).unwrap()).as_deref(),
            Some(B_HOOK)
        );
        // Org C has none: neither the hub's nor org B's.
        assert!(resolve(&hub, ORG_C, CredentialKind::Token).unwrap().is_none());
        assert!(resolve(&hub, ORG_C, CredentialKind::WebhookSecret).unwrap().is_none());
        // And the default organization never sees org B's.
        assert_eq!(
            value(&resolve(&hub, DEFAULT_ORG, CredentialKind::Token).unwrap()).as_deref(),
            Some(HUB_TOKEN)
        );
    }

    #[test]
    fn a_credential_copied_into_another_organization_does_not_decrypt() {
        let hub = hub(false);
        store(&hub, ORG_B, CredentialKind::Token, B_TOKEN);
        hub.db()
            .write(|tx| {
                tx.execute(
                    "INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint, \
                     value_bytes, created_by, created_at, updated_by, updated_at, aad_v) \
                     SELECT ?1, name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, created_by, \
                     created_at, updated_by, updated_at, aad_v FROM managed_secrets WHERE org_id = ?2",
                    [ORG_C, ORG_B],
                )?;
                Ok(())
            })
            .unwrap();
        let err = resolve(&hub, ORG_C, CredentialKind::Token).unwrap_err();
        assert!(!format!("{err:?}").contains(B_TOKEN));
        assert_eq!(value(&resolve(&hub, ORG_B, CredentialKind::Token).unwrap()).as_deref(), Some(B_TOKEN));
    }

    #[test]
    fn status_reports_configured_off_and_unusable_without_values() {
        let hub = hub(true);
        store(&hub, ORG_B, CredentialKind::Token, B_TOKEN);
        let cfg = hub.cfg().clone();
        let (d, b, c) = hub
            .db()
            .read(|conn| {
                Ok((
                    status_json(conn, &cfg, DEFAULT_ORG)?,
                    status_json(conn, &cfg, ORG_B)?,
                    status_json(conn, &cfg, ORG_C)?,
                ))
            })
            .unwrap();
        assert_eq!(d["token"]["state"], "configured");
        assert_eq!(d["token"]["source"], "hub_config");
        assert_eq!(b["token"]["state"], "configured");
        assert_eq!(b["token"]["source"], "managed_secret");
        assert_eq!(b["webhook_secret"]["state"], "off");
        assert_eq!(c["token"]["state"], "off");
        assert_eq!(c["token"]["source"], Value::Null);
        for s in [&d, &b, &c] {
            let text = s.to_string();
            for v in [HUB_TOKEN, HUB_HOOK, B_TOKEN] {
                assert!(!text.contains(v), "{text}");
            }
            assert!(!text.contains("fingerprint"), "{text}");
        }

        // The key rotated away: stored, but unusable.
        let mut rotated = cfg.clone();
        rotated.managed_secret_key = Some(base64_key().into());
        let b = hub.db().read(|conn| status_json(conn, &rotated, ORG_B)).unwrap();
        assert_eq!(b["token"]["state"], "unusable");
        let err = hub
            .db()
            .read(|conn| github_credential_for(conn, &rotated, ORG_B, CredentialKind::Token))
            .unwrap_err();
        assert_eq!(err.reason_code(), Some("secret_key_missing"));
    }

    fn base64_key() -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([9u8; 32])
    }

    #[test]
    fn values_must_be_one_line() {
        assert!(check_value("fake-token-not-real").is_ok());
        assert!(check_value("").is_err());
        assert!(check_value("  ").is_err());
        assert!(check_value("a\nb").is_err());
        assert!(check_value("a\0b").is_err());
    }

    #[test]
    fn debug_never_shows_the_value() {
        let c = GithubCredential {
            kind: CredentialKind::Token,
            source: CredentialSource::ManagedSecret,
            secret: B_TOKEN.to_string().into(),
        };
        assert!(!format!("{c:?}").contains(B_TOKEN));
        let a = SetArgs { kind: CredentialKind::Token, value: B_TOKEN.into() };
        assert!(!format!("{a:?}").contains(B_TOKEN));
    }
}
