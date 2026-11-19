//! Clients, grants and tokens in the hub database (`oauth.v1`, defined in
//! `ua_tools::families::tokens`). Every credential is stored as a SHA-256
//! digest.

use rusqlite::{OptionalExtension, params};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use ua_core::{Config, UaResult};
use ua_store::{EventInput, WriteTx, ledger};
use ua_tools::families::tokens::digest;

use super::{ACCESS_PREFIX, REFRESH_PREFIX, cimd, random_token, ts_in};
use crate::AppState;

#[derive(Clone)]
pub enum ClientSecret {
    /// Public client: no secret, PKCE is the proof.
    None,
    /// Registered confidential client: SHA-256 of the secret.
    Hash(String),
    /// Configured `client_credentials` client.
    Configured(SecretString),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientKind {
    Registered,
    MetadataDocument,
    /// A `client_credentials` client pinned to one identity in configuration.
    Configured { identity: String },
}

#[derive(Clone)]
pub struct Client {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub secret: ClientSecret,
    pub kind: ClientKind,
}

impl Client {
    pub fn is_public(&self) -> bool {
        matches!(self.secret, ClientSecret::None)
    }

    pub fn allows_grant(&self, grant: &str) -> bool {
        self.grant_types.iter().any(|g| g == grant)
    }

    /// Constant-time check of a presented secret.
    pub fn secret_matches(&self, presented: &str) -> bool {
        match &self.secret {
            ClientSecret::None => false,
            ClientSecret::Hash(h) => bool::from(digest(presented).as_bytes().ct_eq(h.as_bytes())),
            ClientSecret::Configured(s) => {
                // Compare digests so the comparison length does not leak the secret length.
                bool::from(digest(presented).as_bytes().ct_eq(digest(s.expose_secret()).as_bytes()))
            }
        }
    }
}

/// Why a client id could not be resolved.
pub enum ClientLookup {
    Found(Client),
    Unknown,
    Rejected(String),
}

fn configured(cfg: &Config, client_id: &str) -> Option<Client> {
    cfg.oauth_client_credentials().into_iter().find(|(id, _, _)| id == client_id).map(|(id, secret, identity)| {
        Client {
            client_name: format!("{id} (configured)"),
            client_id: id,
            redirect_uris: Vec::new(),
            grant_types: vec!["client_credentials".into()],
            secret: ClientSecret::Configured(secret),
            kind: ClientKind::Configured { identity },
        }
    })
}

fn json_list(raw: &str) -> Vec<String> {
    serde_json::from_str(raw).unwrap_or_default()
}

/// Resolve a client id: configured clients, then registered ones, then (when
/// enabled) a Client ID Metadata Document.
pub async fn load_client(state: &AppState, client_id: &str) -> UaResult<ClientLookup> {
    let cfg = state.hub.cfg();
    if client_id.is_empty() || client_id.len() > 2048 {
        return Ok(ClientLookup::Unknown);
    }
    if let Some(c) = configured(cfg, client_id) {
        return Ok(ClientLookup::Found(c));
    }
    let id = client_id.to_string();
    let row = state
        .hub
        .db()
        .read_async(move |c| {
            Ok(c.query_row(
                "SELECT client_id, client_name, redirect_uris, grant_types, secret_hash FROM oauth_clients \
                 WHERE client_id = ?1",
                [&id],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?)
        })
        .await?;
    if let Some((client_id, name, redirects, grants, secret_hash)) = row {
        return Ok(ClientLookup::Found(Client {
            client_name: name.unwrap_or_else(|| client_id.clone()),
            client_id,
            redirect_uris: json_list(&redirects),
            grant_types: json_list(&grants),
            secret: secret_hash.map(ClientSecret::Hash).unwrap_or(ClientSecret::None),
            kind: ClientKind::Registered,
        }));
    }
    if cfg.oauth_cimd_enabled && cimd::looks_like_cimd(client_id) {
        return Ok(match cimd::resolve(client_id, &cfg.oauth_cimd_allow).await {
            Ok(c) => ClientLookup::Found(Client {
                client_id: c.client_id,
                client_name: c.client_name,
                redirect_uris: c.redirect_uris,
                grant_types: c.grant_types,
                secret: ClientSecret::None,
                kind: ClientKind::MetadataDocument,
            }),
            Err(e) => {
                tracing::info!(reason = %e, "client metadata document rejected");
                ClientLookup::Rejected(e.0)
            }
        });
    }
    Ok(ClientLookup::Unknown)
}

/// Tokens handed to a client.
pub struct Issued {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub scope: String,
}

impl Issued {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "scope": self.scope,
        });
        if let Some(r) = &self.refresh_token {
            v["refresh_token"] = json!(r);
        }
        v
    }
}

/// What a grant family is bound to.
pub struct GrantInfo<'a> {
    pub family_id: &'a str,
    pub client_id: &'a str,
    pub subject: &'a str,
    pub scope: &'a str,
    pub resource: &'a str,
}

/// Record a new grant (one approved sign-in or client-credentials session).
pub fn insert_grant(
    tx: &WriteTx<'_>,
    g: &GrantInfo<'_>,
    client_name: &str,
    approved_by: &str,
    grant_type: &str,
) -> UaResult<()> {
    tx.execute(
        "INSERT INTO oauth_grants (family_id, client_id, client_name, subject, approved_by, grant_type, scope, \
         resource, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            g.family_id,
            g.client_id,
            client_name,
            g.subject,
            approved_by,
            grant_type,
            g.scope,
            g.resource,
            ua_core::time::now()
        ],
    )?;
    Ok(())
}

/// Mint an access token (and optionally a refresh token) in a grant family.
pub fn issue_tokens(tx: &mut WriteTx<'_>, cfg: &Config, g: &GrantInfo<'_>, with_refresh: bool) -> UaResult<Issued> {
    let now = ua_core::time::now();
    let ttl = cfg.oauth_access_ttl_secs.clamp(60, 30 * 24 * 3600);
    let access = random_token(ACCESS_PREFIX);
    let insert = |tx: &WriteTx<'_>, raw: &str, kind: &str, expires: &str| -> UaResult<()> {
        tx.execute(
            "INSERT INTO oauth_tokens (token_hash, kind, family_id, client_id, subject, scope, resource, issued_at, \
             expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![digest(raw), kind, g.family_id, g.client_id, g.subject, g.scope, g.resource, now, expires],
        )?;
        Ok(())
    };
    insert(tx, &access, "access", &ts_in(ttl as i64))?;
    let refresh = if with_refresh {
        let r = random_token(REFRESH_PREFIX);
        let days = cfg.oauth_refresh_ttl_days.clamp(1, 365) as i64;
        insert(tx, &r, "refresh", &ts_in(days * 24 * 3600))?;
        Some(r)
    } else {
        None
    };
    tx.execute("UPDATE oauth_clients SET last_used_at = ?2 WHERE client_id = ?1", params![g.client_id, now])?;
    ledger::append(
        tx,
        EventInput::new(
            "agent.oauth.token_issued",
            json!({ "client_id": g.client_id, "identity": g.subject, "session_id": g.family_id, "refresh": with_refresh }),
        )
        .by(g.subject.to_string()),
    )?;
    Ok(Issued { access_token: access, refresh_token: refresh, expires_in: ttl, scope: g.scope.to_string() })
}

/// A live access token.
#[derive(Debug, Clone)]
pub struct AccessInfo {
    pub subject: String,
    pub client_id: String,
    pub resource: String,
    pub scope: String,
}

/// Look up a presented access token: active, unexpired, its grant unrevoked.
pub fn lookup_access(state: &AppState, token: &str) -> Option<AccessInfo> {
    if !token.starts_with(ACCESS_PREFIX) {
        return None;
    }
    let hash = digest(token);
    state
        .hub
        .db()
        .read(|c| {
            Ok(c.query_row(
                "SELECT t.subject, t.client_id, t.resource, t.scope FROM oauth_tokens t \
                 JOIN oauth_grants g ON g.family_id = t.family_id \
                 WHERE t.token_hash = ?1 AND t.kind = 'access' AND t.status = 'active' AND t.expires_at > ?2 \
                 AND g.revoked_at IS NULL",
                params![hash, ua_core::time::now()],
                |r| Ok(AccessInfo { subject: r.get(0)?, client_id: r.get(1)?, resource: r.get(2)?, scope: r.get(3)? }),
            )
            .optional()?)
        })
        .ok()
        .flatten()
}

/// A new grant family id (shown to operators as the session id).
pub fn new_family_id() -> String {
    ulid::Ulid::generate().to_string().to_lowercase()
}
