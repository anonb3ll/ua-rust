//! Profile bindings per (identity, client session) and the profile tools.

use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Profile, UaError, UaResult};
use ua_store::{EventInput, SchemaPart, ledger};

use crate::hub::Hub;
use crate::registry::{Registry, ToolCtx, tool};

pub const SCHEMA: SchemaPart = SchemaPart {
    name: "sessions.v1",
    sql: "
CREATE TABLE IF NOT EXISTS session_profiles (
    identity TEXT NOT NULL,
    session_key TEXT NOT NULL,
    profile TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (identity, session_key)
);
",
};

/// The profile an identity gets when nothing is activated.
pub fn default_profile(hub: &Hub, label: &str) -> Profile {
    hub.cfg().profiles.get(label).and_then(|p| p.parse().ok()).unwrap_or(Profile::Developer)
}

/// The profile currently bound to (identity, session), else the default.
pub fn resolve_profile(hub: &Hub, label: &str, session_key: Option<&str>) -> Profile {
    let bound = session_key.and_then(|key| {
        hub.db()
            .read(|c| {
                Ok(c.query_row(
                    "SELECT profile FROM session_profiles WHERE identity = ?1 AND session_key = ?2",
                    params![label, key],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
            })
            .ok()
            .flatten()
    });
    bound.and_then(|p| p.parse().ok()).unwrap_or_else(|| default_profile(hub, label))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivateArgs {
    /// Profile name, e.g. `research` or `steward`.
    pub profile: String,
}

fn status(ctx: &ToolCtx) -> Value {
    let c: &Caller = &ctx.caller;
    json!({
        "profile": c.profile.as_str(),
        "identity": c.label,
        "kind": c.kind,
        "session_scoped": c.session_key.is_some(),
        "enforced": c.enforce_profile,
        "default_profile": default_profile(&ctx.hub, &c.label).as_str(),
        "transport": c.transport,
    })
}

async fn bind(ctx: ToolCtx, profile: Option<Profile>) -> UaResult<Value> {
    let Some(key) = ctx.caller.session_key.clone() else {
        return Err(UaError::invalid("profile changes need a client session; this caller has none"));
    };
    let label = ctx.caller.label.clone();
    if let Some(p) = profile {
        let default = default_profile(&ctx.hub, &label);
        let escalates = p.rank() > default.rank();
        if escalates && ctx.caller.kind != ActorKind::Human {
            return Err(UaError::denied(
                "profile_escalation",
                format!("only a human may activate {p}, which is above the default {default}"),
            ));
        }
    }
    let now = ua_core::time::now();
    let label2 = label.clone();
    ctx.hub
        .db()
        .write_async(move |tx| {
            match profile {
                Some(p) => tx.execute(
                    "INSERT INTO session_profiles (identity, session_key, profile, updated_at) VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT(identity, session_key) DO UPDATE SET profile = excluded.profile, updated_at = excluded.updated_at",
                    params![label2, key, p.as_str(), now],
                )?,
                None => tx.execute(
                    "DELETE FROM session_profiles WHERE identity = ?1 AND session_key = ?2",
                    params![label2, key],
                )?,
            };
            ledger::append(
                tx,
                EventInput::new(
                    "agent.profile.changed",
                    json!({ "identity": label2, "profile": profile.map(Profile::as_str) }),
                )
                .by(label2.clone()),
            )?;
            Ok(())
        })
        .await?;
    let effective = profile.unwrap_or_else(|| default_profile(&ctx.hub, &label));
    Ok(
        json!({ "ok": true, "profile": effective.as_str(), "note": "applies to calls from this session from now on" }),
    )
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "profile_status",
            "Report the caller's verified identity and active profile.",
            |ctx: ToolCtx, _: NoArgs| async move { Ok(status(&ctx)) },
        )
        .family("profiles")
        .read_only(),
    );
    r.add(
        tool(
            "profile_activate",
            "Switch this session to another profile. Agents may only move to a profile no more privileged than their default.",
            |ctx: ToolCtx, a: ActivateArgs| async move {
                let p: Profile = a.profile.parse().map_err(UaError::invalid)?;
                bind(ctx, Some(p)).await
            },
        )
        .family("profiles"),
    );
    r.add(
        tool(
            "profile_reset",
            "Return this session to the identity's default profile.",
            |ctx: ToolCtx, _: NoArgs| async move { bind(ctx, None).await },
        )
        .family("profiles"),
    );
}
