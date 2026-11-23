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

use rusqlite::Connection;
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
/// configuration), then each other organization that stores the managed
/// secret bound to its consumer, by id. Resolve each with
/// [`github_credential_for`]; nothing here decrypts.
pub fn orgs_holding(conn: &Connection, kind: CredentialKind) -> UaResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT m.org_id FROM managed_secrets m JOIN orgs o ON o.id = m.org_id \
         WHERE m.name = ?1 AND m.consumer = ?2 AND m.org_id <> ?3 ORDER BY m.org_id",
    )?;
    let others = stmt
        .query_map([kind.secret_name(), kind.consumer(), DEFAULT_ORG], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(std::iter::once(DEFAULT_ORG.to_string()).chain(others).collect())
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
                Err(pending) => return Ok(Err(pending)),
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
    out.map_err(|approval_id| UaError::ApprovalRequired { tool: TOOL.into(), approval_id })
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
