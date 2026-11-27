//! Organization registry and settings tools. Argument structs and the call into `ua-org`.
//!
//! Tools: `org_registry_read`, `org_office_register`, `org_role_register`,
//! `org_seat_register`, `org_service_register`, `org_settings_update`.
//!
//! The organization is the caller's, never a tool argument: a request that
//! names `org_id` is refused with the other unknown fields. Every read and
//! write is scoped to `ctx.caller.org_id`, and `require_same_org` refuses a
//! caller whose organization differs from the row's before a row is read or
//! written. The write tools require a verified human operator in that
//! organization (`Authz::require`); `org_role_register` and
//! `org_settings_update` are always gated, so changing roles or remote-embedder
//! egress policy needs a one-time human approval. Registering grants no profile
//! and no approval.

use rusqlite::Connection;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::UaResult;
use ua_org::authz::{Authority, Authz, require_same_org};
use ua_org::{RegisterOffice, RegisterRole, RegisterSeat, RegisterService, UpdateOrgSettings};
use ua_store::SchemaPart;
use ua_store::org::SqliteOrg;

use crate::registry::{Registry, ToolCtx, tool};

pub fn schema_parts() -> Vec<SchemaPart> {
    ua_org::schema_parts()
}

/// `organization.v1.registry.tenant`: the generated `_org_exists` and
/// `_org_immutable` triggers of the four registry tables. They already carry
/// `org_id NOT NULL`, so this part adds no column and backfills nothing.
/// Applied after `organization.registry.v1` (see `ua_tools::schema_parts`).
pub const TENANT_PART: ua_store::Procedure = ua_store::org::tenant_part(
    "organization.v1.registry.tenant",
    &["offices", "org_role_grants", "org_seats", "org_service_identities"],
);

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    /// Closed identity roster. Omit when every well-formed label is admitted.
    /// An empty list admits nobody.
    agent_labels: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct OfficeArgs {
    /// Stable id: lowercase words and digits, separated by single hyphens.
    slug: String,
    /// Display name. Not an authority.
    name: String,
    /// Profiles a seat in this office may hold. At least one. A legacy profile
    /// name is stored under its current name.
    profiles: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RoleArgs {
    /// Identity label the role is granted to.
    label: String,
    /// `org_owner`, `org_admin`, `team_lead`, `member` or `auditor`.
    role: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SeatArgs {
    /// Agent label. One seat per label.
    label: String,
    /// Office slug or display name.
    office: String,
    /// Profile this seat holds. Must be one of the office's profiles.
    profile: String,
    /// `local` or `cloud`. Defaults to `local`.
    agent_kind: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ServiceArgs {
    /// Label that sends as a service. It holds no office, seat or role.
    label: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SettingsUpdateArgs {
    /// Whether this organization permits sending memory notes and queries to a
    /// non-loopback embedding endpoint. Defaults to false.
    allow_remote_embedder: bool,
}

fn agent_labels(c: &Connection, org: &str) -> UaResult<Vec<String>> {
    let mut stmt = c.prepare("SELECT label FROM agents WHERE org_id = ?1")?;
    let rows = stmt.query_map([org], |r| r.get(0))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(ua_core::UaError::from)
}

pub(crate) fn registry_health(c: &Connection, org: &str) -> UaResult<ua_org::Health> {
    let mut repo = SqliteOrg::new(c);
    let active = agent_labels(c, org)?;
    let registry = ua_org::load(&mut repo, org, None, &active)?;
    Ok(ua_org::health(&registry))
}

async fn read(ctx: ToolCtx, args: ReadArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    require_same_org(&ctx.caller, &org)?;
    let roster = args.agent_labels;
    ctx.hub
        .db()
        .read_async(move |c| {
            let mut repo = SqliteOrg::new(c);
            let active = agent_labels(c, &org)?;
            let registry = ua_org::load(&mut repo, &org, roster.as_deref(), &active)?;
            Ok(serde_json::to_value(&registry)?)
        })
        .await
}

/// Refuse a caller who is not a verified human operator in `org`, and refuse a
/// caller whose organization is not the row's. Until tenancy lands,
/// `ua_org::authz` admits only the default organization, so any other
/// organization is refused outright. The check runs before any row is read or
/// written, so a refused caller cannot reach the registry at all.
fn require_operator(ctx: &ToolCtx, org: &str) -> UaResult<()> {
    require_same_org(&ctx.caller, org)?;
    Authz::new(ctx.hub.cfg()).require(&ctx.caller, &[Authority::Operator], org)
}

async fn office(ctx: ToolCtx, args: OfficeArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    require_operator(&ctx, &org)?;
    let actor = ctx.caller.label.clone();
    let input = RegisterOffice { slug: args.slug, name: args.name, profiles: args.profiles };
    let outcome =
        ctx.hub.db().write_async(move |tx| ua_org::register_office(tx, &org, input, &actor)).await?;
    Ok(json!({ "changed": outcome.changed, "office": outcome.value }))
}

async fn role(ctx: ToolCtx, args: RoleArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    require_operator(&ctx, &org)?;
    let actor = ctx.caller.label.clone();
    let input = RegisterRole { label: args.label, role: args.role };
    let outcome = ctx.hub.db().write_async(move |tx| ua_org::register_role(tx, &org, input, &actor)).await?;
    Ok(json!({ "changed": outcome.changed, "role": outcome.value }))
}

async fn seat(ctx: ToolCtx, args: SeatArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    require_operator(&ctx, &org)?;
    let actor = ctx.caller.label.clone();
    let input = RegisterSeat {
        label: args.label,
        office: args.office,
        profile: args.profile,
        agent_kind: args.agent_kind,
    };
    let outcome = ctx.hub.db().write_async(move |tx| ua_org::register_seat(tx, &org, input, &actor)).await?;
    Ok(json!({ "changed": outcome.changed, "seat": outcome.value }))
}

async fn service(ctx: ToolCtx, args: ServiceArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    require_operator(&ctx, &org)?;
    let actor = ctx.caller.label.clone();
    let input = RegisterService { label: args.label };
    let outcome =
        ctx.hub.db().write_async(move |tx| ua_org::register_service(tx, &org, input, &actor)).await?;
    Ok(json!({ "changed": outcome.changed, "service_identity": outcome.value }))
}

async fn settings_update(ctx: ToolCtx, args: SettingsUpdateArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    require_operator(&ctx, &org)?;
    let actor = ctx.caller.label.clone();
    let input = UpdateOrgSettings { allow_remote_embedder: args.allow_remote_embedder };
    let outcome =
        ctx.hub.db().write_async(move |tx| ua_org::update_settings(tx, &org, input, &actor)).await?;
    Ok(json!({ "changed": outcome.changed, "settings": outcome.value }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "org_registry_read",
            "Read the organization registry: offices (capability scopes), role grants, agent seats and \
             service identities, plus validation findings. Active identities are the agent rows. Pass \
             agent_labels to check a closed roster; omit it for an open roster. Does not grant anything. \
             The organization is the caller's, never an argument.",
            read,
        )
        .family("org")
        .read_only(),
    );
    r.add(
        tool(
            "org_office_register",
            "Register an office: a slug, a display name and the profiles its seats may hold. The slug is \
             lowercase words and digits separated by hyphens. A legacy profile name is stored under its \
             current name. An office grants no authority. Returns {changed, office}.",
            office,
        )
        .family("org"),
    );
    r.add(
        tool(
            "org_role_register",
            "Grant a role to an identity label: org_owner, org_admin, team_lead, member or auditor. \
             The same label cannot also be a seat or a service identity. The last org_owner cannot be \
             demoted. Granting a role records the grant; it does not by itself change what the label \
             can do. Always needs a one-time human approval. Returns {changed, role}.",
            role,
        )
        .family("org")
        .always_gated(),
    );
    r.add(
        tool(
            "org_seat_register",
            "Seat an agent label in one office with one profile and a kind of local or cloud (default \
             local). The profile must be one of the office's profiles. One seat per label; seating it \
             again moves it. A seat is not a role and not a service identity. Returns {changed, seat}.",
            seat,
        )
        .family("org"),
    );
    r.add(
        tool(
            "org_service_register",
            "Declare a service identity: a label that may send as itself and holds no office, seat or \
             role. Declaring it grants nothing. Returns {changed, service_identity}.",
            service,
        )
        .family("org"),
    );
    r.add(
        tool(
            "org_settings_update",
            "Update organization settings for the caller's organization (currently \
             allow_remote_embedder) and append an agent.org.settings ledger event with old and new \
             values. Requires a verified human operator and always needs a one-time human approval. \
             The organization is the caller's, never an argument. Returns {changed, settings}.",
            settings_update,
        )
        .family("org")
        .always_gated(),
    );
}
