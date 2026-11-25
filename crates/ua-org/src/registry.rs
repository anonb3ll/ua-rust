//! Load, validate and register the organization chart.
//!
//! The chart is rows, not a file. Lookups and the validation findings follow
//! the original registry: an office resolves by slug or display name, a label's
//! office is the office of its seat, and the findings are the same four issue
//! codes. Identity labels compare case-insensitively, which is the
//! organization rule for the shared label namespace.

use serde::Serialize;
use serde_json::{Value, json};
use ua_core::{Profile, UaError, UaResult};
use ua_store::org::{NewSeat, OfficeRow, OrgRead, OrgWrite, RoleRow};

/// Ledger channel for a registry change. The payload's `kind` says which.
pub const CHANNEL: &str = "agent.org.registry";

/// The organization id of the default organization, the only one that exists
/// until tenancy lands. It is [`ua_core::DEFAULT_ORG`] under a registry-local
/// name; a caller's registry row belongs to the caller's organization, never
/// to this constant.
pub const DEFAULT_ORG_ID: &str = ua_core::DEFAULT_ORG;

pub const ISSUE_MEMBER_NOT_IN_ROSTER: &str = "member_not_in_agent_labels";
pub const ISSUE_ACTIVE_WITHOUT_OFFICE: &str = "active_identity_without_office";
pub const ISSUE_SERVICE_NOT_IN_ROSTER: &str = "service_identity_not_in_agent_labels";
pub const ISSUE_SERVICE_IN_OFFICE: &str = "service_identity_in_office";

const ROLES: [&str; 5] = ["org_owner", "org_admin", "team_lead", "member", "auditor"];
const LABEL_MAX: usize = 64;
const SLUG_MAX: usize = 64;
const NAME_MAX: usize = 200;

/// An office as callers read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Office {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub profiles: Vec<String>,
    pub created_at: String,
}

/// A role grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RoleGrant {
    pub label: String,
    pub role: String,
    pub added_by: String,
    pub added_at: String,
}

/// An agent seat. `office` is the office slug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Seat {
    pub label: String,
    pub office: String,
    pub profile: String,
    pub agent_kind: String,
    pub created_at: String,
}

/// One validation finding. `office` is the office slug, when the identity has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub identity: String,
    pub office: Option<String>,
    pub issue: String,
}

/// The registry projection, in charter order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Registry {
    pub org_id: String,
    pub offices: Vec<Office>,
    pub roles: Vec<RoleGrant>,
    pub seats: Vec<Seat>,
    pub service_identities: Vec<String>,
    pub findings: Vec<Finding>,
}

/// What a register call did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome<T> {
    pub changed: bool,
    pub value: T,
}

/// Doctor view of [`Registry::findings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    pub live: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct RegisterOffice {
    pub slug: String,
    pub name: String,
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RegisterRole {
    pub label: String,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct RegisterSeat {
    pub label: String,
    pub office: String,
    pub profile: String,
    pub agent_kind: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RegisterService {
    pub label: String,
}

/// The registry for `org_id`, with findings against `active` labels.
///
/// `roster` is the closed identity roster. `None` is an open roster: every
/// label counts as admitted, so the two "not in the roster" findings stay quiet.
pub fn load(
    repo: &mut impl OrgRead,
    org_id: &str,
    roster: Option<&[String]>,
    active: &[String],
) -> UaResult<Registry> {
    let offices: Vec<Office> = repo.offices(org_id)?.into_iter().map(office_view).collect();
    let roles: Vec<RoleGrant> = repo.roles(org_id)?.into_iter().map(role_view).collect();
    let seat_rows = repo.seats(org_id)?;
    let seats = seat_rows.iter().map(seat_view).collect::<Vec<_>>();
    let service_identities = repo.services(org_id)?;
    let findings = validate(&offices, &seats, &service_identities, roster, active);
    Ok(Registry { org_id: org_id.to_string(), offices, roles, seats, service_identities, findings })
}

/// Resolve an office by slug or by display name, case-insensitively.
/// Slug wins when a slug and another office's name fold to the same token.
pub fn find_office<'a>(registry: &'a Registry, query: &str) -> Option<&'a Office> {
    let token = query.trim();
    if token.is_empty() {
        return None;
    }
    registry
        .offices
        .iter()
        .find(|o| o.slug.eq_ignore_ascii_case(token))
        .or_else(|| registry.offices.iter().find(|o| o.name.eq_ignore_ascii_case(token)))
}

/// Office slugs that seat `label`, in charter order.
pub fn offices_for_identity(registry: &Registry, label: &str) -> Vec<String> {
    registry
        .seats
        .iter()
        .filter(|s| s.label.eq_ignore_ascii_case(label.trim()))
        .map(|s| s.office.clone())
        .collect()
}

/// The first office that seats `label`.
pub fn office_for_identity(registry: &Registry, label: &str) -> Option<String> {
    offices_for_identity(registry, label).into_iter().next()
}

/// Findings in the original order: services, then seated members, then active
/// labels that have no office and are not service identities.
pub fn validate(
    offices: &[Office],
    seats: &[Seat],
    services: &[String],
    roster: Option<&[String]>,
    active: &[String],
) -> Vec<Finding> {
    let mut services_sorted = services.to_vec();
    services_sorted.sort_by(|a, b| fold(a).cmp(&fold(b)).then(a.cmp(b)));
    let mut findings = Vec::new();
    for label in &services_sorted {
        if let Some(office) = seat_office(seats, label) {
            findings.push(finding(label, Some(office), ISSUE_SERVICE_IN_OFFICE));
        } else if !admitted(roster, label) {
            findings.push(finding(label, None, ISSUE_SERVICE_NOT_IN_ROSTER));
        }
    }
    for office in offices {
        for seat in seats.iter().filter(|s| s.office == office.slug) {
            if !admitted(roster, &seat.label) {
                findings.push(finding(&seat.label, Some(office.slug.clone()), ISSUE_MEMBER_NOT_IN_ROSTER));
            }
        }
    }
    let mut active_sorted = active.to_vec();
    active_sorted.sort_by(|a, b| fold(a).cmp(&fold(b)).then(a.cmp(b)));
    for label in active_sorted {
        let seated = seat_office(seats, &label).is_some();
        let service = services.iter().any(|s| s.eq_ignore_ascii_case(&label));
        if !seated && !service {
            findings.push(finding(&label, None, ISSUE_ACTIVE_WITHOUT_OFFICE));
        }
    }
    findings
}

/// `live` when [`Registry::findings`] is empty.
pub fn health(registry: &Registry) -> Health {
    if registry.findings.is_empty() {
        Health {
            live: true,
            detail: format!(
                "offices {}, seats {}, roles {}, service identities {}",
                registry.offices.len(),
                registry.seats.len(),
                registry.roles.len(),
                registry.service_identities.len()
            ),
        }
    } else {
        let detail = registry
            .findings
            .iter()
            .map(|f| format!("{}: {}", f.identity, f.issue))
            .collect::<Vec<_>>()
            .join("; ");
        Health { live: false, detail }
    }
}

/// The neutral originator a registry event records for a row outside the
/// default organization. The ledger event lands in the default organization's
/// ledger (`ORG-EVENT-DEFAULT`), and a registry row's label and office name are
/// people's and agents' names: another organization's row must not leak them
/// there. A default-organization row keeps its acting label.
pub const NEUTRAL_ORIGINATOR: &str = "system";

/// The originator a registry event records: the acting label in the default
/// organization, [`NEUTRAL_ORIGINATOR`] elsewhere.
fn ledger_originator(org_id: &str, actor: &str) -> String {
    if org_id == DEFAULT_ORG_ID { actor.to_string() } else { NEUTRAL_ORIGINATOR.to_string() }
}

/// A label or name for a registry event payload: the value in the default
/// organization, `null` elsewhere (the payload keeps its shape).
fn ledger_text(org_id: &str, value: &str) -> Value {
    if org_id == DEFAULT_ORG_ID { json!(value) } else { Value::Null }
}

pub fn register_office(
    repo: &mut impl OrgWrite,
    org_id: &str,
    input: RegisterOffice,
    actor: &str,
) -> UaResult<Outcome<Office>> {
    let slug = clean_slug(&input.slug)?;
    let name = clean_name(&input.name)?;
    let allowed = repo.allowed_profiles(org_id)?;
    let profiles = canonical_profiles(&input.profiles, &allowed)?;
    if repo.offices(org_id)?.iter().any(|o| o.slug == slug) {
        return Err(UaError::conflict(format!("office {slug:?} is already registered")));
    }
    let row = OfficeRow {
        id: ulid::Ulid::generate().to_string(),
        org_id: org_id.to_string(),
        slug,
        name,
        profiles,
        created_at: ua_core::time::now(),
    };
    repo.insert_office(&row)?;
    let office = office_view(row);
    repo.record(
        CHANNEL,
        json!({
            "kind": "office.registered",
            "org_id": org_id,
            "id": &office.id,
            "slug": ledger_text(org_id, &office.slug),
            "name": ledger_text(org_id, &office.name),
            "profiles": &office.profiles,
        }),
        &ledger_originator(org_id, actor),
    )?;
    Ok(Outcome { changed: true, value: office })
}

pub fn register_role(
    repo: &mut impl OrgWrite,
    org_id: &str,
    input: RegisterRole,
    actor: &str,
) -> UaResult<Outcome<RoleGrant>> {
    let label = clean_label(&input.label)?;
    let role = clean_role(&input.role)?;
    refuse_service(repo, org_id, &label)?;
    refuse_seat(repo, org_id, &label, "an identity label is a seat or a role, not both")?;
    let existing = repo.roles(org_id)?;
    if let Some(prev) = existing.iter().find(|r| r.label.eq_ignore_ascii_case(&label)) {
        if prev.role == role {
            return Ok(Outcome { changed: false, value: role_view(prev.clone()) });
        }
        if prev.role == "org_owner"
            && role != "org_owner"
            && existing.iter().filter(|r| r.role == "org_owner").count() == 1
        {
            return Err(UaError::conflict("the last org_owner cannot be demoted"));
        }
        let row = RoleRow {
            org_id: org_id.to_string(),
            label: prev.label.clone(),
            role: role.to_string(),
            added_by: actor.to_string(),
            added_at: ua_core::time::now(),
        };
        repo.update_role(&row)?;
        let value = role_view(row);
        repo.record(
            CHANNEL,
            json!({
                "kind": "role.updated",
                "org_id": org_id,
                "label": ledger_text(org_id, &value.label),
                "role": &value.role,
                "previous": &prev.role,
            }),
            &ledger_originator(org_id, actor),
        )?;
        return Ok(Outcome { changed: true, value });
    }
    let row = RoleRow {
        org_id: org_id.to_string(),
        label,
        role: role.to_string(),
        added_by: actor.to_string(),
        added_at: ua_core::time::now(),
    };
    repo.insert_role(&row)?;
    let value = role_view(row);
    repo.record(
        CHANNEL,
        json!({
            "kind": "role.registered",
            "org_id": org_id,
            "label": ledger_text(org_id, &value.label),
            "role": &value.role,
        }),
        &ledger_originator(org_id, actor),
    )?;
    Ok(Outcome { changed: true, value })
}

pub fn register_seat(
    repo: &mut impl OrgWrite,
    org_id: &str,
    input: RegisterSeat,
    actor: &str,
) -> UaResult<Outcome<Seat>> {
    let label = clean_label(&input.label)?;
    let kind = clean_kind(input.agent_kind.as_deref())?;
    let office_query = input.office.trim();
    let offices = repo.offices(org_id)?;
    let office = offices
        .iter()
        .find(|o| o.slug.eq_ignore_ascii_case(office_query) || o.name.eq_ignore_ascii_case(office_query))
        .ok_or_else(|| UaError::not_found(format!("unknown office {office_query:?}")))?;
    let allowed = repo.allowed_profiles(org_id)?;
    let profile = one_profile(&input.profile, &allowed)?;
    if !office.profiles.iter().any(|p| p == profile) {
        return Err(UaError::invalid(format!("profile {profile:?} is not in office {:?}", office.slug)));
    }
    refuse_service(repo, org_id, &label)?;
    refuse_role(repo, org_id, &label, "an identity label is a seat or a role, not both")?;
    let existing = repo.seats(org_id)?;
    if let Some(prev) = existing.iter().find(|s| s.label.eq_ignore_ascii_case(&label)) {
        if prev.office_id == office.id && prev.profile == profile && prev.agent_kind == kind {
            return Ok(Outcome { changed: false, value: seat_view(prev) });
        }
        let row = NewSeat {
            org_id: org_id.to_string(),
            label: prev.label.clone(),
            office_id: office.id.clone(),
            profile: profile.to_string(),
            agent_kind: kind.to_string(),
            created_at: prev.created_at.clone(),
        };
        repo.update_seat(&row)?;
        let value = Seat {
            label: prev.label.clone(),
            office: office.slug.clone(),
            profile: profile.to_string(),
            agent_kind: kind.to_string(),
            created_at: prev.created_at.clone(),
        };
        repo.record(
            CHANNEL,
            json!({
                "kind": "seat.updated",
                "org_id": org_id,
                "label": ledger_text(org_id, &value.label),
                "office": ledger_text(org_id, &value.office),
                "profile": &value.profile,
                "agent_kind": &value.agent_kind,
                "previous_office": ledger_text(org_id, &prev.office_slug),
            }),
            &ledger_originator(org_id, actor),
        )?;
        return Ok(Outcome { changed: true, value });
    }
    let created_at = ua_core::time::now();
    let row = NewSeat {
        org_id: org_id.to_string(),
        label: label.clone(),
        office_id: office.id.clone(),
        profile: profile.to_string(),
        agent_kind: kind.to_string(),
        created_at: created_at.clone(),
    };
    repo.insert_seat(&row)?;
    let value = Seat {
        label,
        office: office.slug.clone(),
        profile: profile.to_string(),
        agent_kind: kind.to_string(),
        created_at,
    };
    repo.record(
        CHANNEL,
        json!({
            "kind": "seat.registered",
            "org_id": org_id,
            "label": ledger_text(org_id, &value.label),
            "office": ledger_text(org_id, &value.office),
            "profile": &value.profile,
            "agent_kind": &value.agent_kind,
        }),
        &ledger_originator(org_id, actor),
    )?;
    Ok(Outcome { changed: true, value })
}

pub fn register_service(
    repo: &mut impl OrgWrite,
    org_id: &str,
    input: RegisterService,
    actor: &str,
) -> UaResult<Outcome<String>> {
    let label = clean_label(&input.label)?;
    if let Some(kept) = repo.services(org_id)?.into_iter().find(|s| s.eq_ignore_ascii_case(&label)) {
        return Ok(Outcome { changed: false, value: kept });
    }
    refuse_seat(repo, org_id, &label, "a service identity holds no office")?;
    refuse_role(repo, org_id, &label, "a service identity holds no role")?;
    repo.insert_service(org_id, &label)?;
    repo.record(
        CHANNEL,
        json!({ "kind": "service.registered", "org_id": org_id, "label": ledger_text(org_id, &label) }),
        &ledger_originator(org_id, actor),
    )?;
    Ok(Outcome { changed: true, value: label })
}

fn refuse_service(repo: &mut impl OrgRead, org_id: &str, label: &str) -> UaResult<()> {
    if repo.services(org_id)?.iter().any(|s| s.eq_ignore_ascii_case(label)) {
        return Err(UaError::conflict("a service identity holds no office and no role"));
    }
    Ok(())
}

fn refuse_seat(repo: &mut impl OrgRead, org_id: &str, label: &str, message: &str) -> UaResult<()> {
    if repo.seats(org_id)?.iter().any(|s| s.label.eq_ignore_ascii_case(label)) {
        return Err(UaError::conflict(message));
    }
    Ok(())
}

fn refuse_role(repo: &mut impl OrgRead, org_id: &str, label: &str, message: &str) -> UaResult<()> {
    if repo.roles(org_id)?.iter().any(|r| r.label.eq_ignore_ascii_case(label)) {
        return Err(UaError::conflict(message));
    }
    Ok(())
}

fn office_view(row: OfficeRow) -> Office {
    Office { id: row.id, slug: row.slug, name: row.name, profiles: row.profiles, created_at: row.created_at }
}

fn role_view(row: RoleRow) -> RoleGrant {
    RoleGrant { label: row.label, role: row.role, added_by: row.added_by, added_at: row.added_at }
}

fn seat_view(row: &ua_store::org::SeatRow) -> Seat {
    Seat {
        label: row.label.clone(),
        office: row.office_slug.clone(),
        profile: row.profile.clone(),
        agent_kind: row.agent_kind.clone(),
        created_at: row.created_at.clone(),
    }
}

fn finding(identity: &str, office: Option<String>, issue: &str) -> Finding {
    Finding { identity: identity.to_string(), office, issue: issue.to_string() }
}

fn seat_office(seats: &[Seat], label: &str) -> Option<String> {
    seats.iter().find(|s| s.label.eq_ignore_ascii_case(label)).map(|s| s.office.clone())
}

fn admitted(roster: Option<&[String]>, label: &str) -> bool {
    match roster {
        None => true,
        Some(labels) => labels.iter().any(|l| l.eq_ignore_ascii_case(label)),
    }
}

fn fold(label: &str) -> String {
    label.to_ascii_lowercase()
}

fn clean_label(raw: &str) -> UaResult<String> {
    let label = raw.trim();
    let ok = (1..=LABEL_MAX).contains(&label.len())
        && label.starts_with(|c: char| c.is_ascii_alphabetic())
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(UaError::invalid(format!("invalid identity label {raw:?}")));
    }
    Ok(label.to_string())
}

fn clean_slug(raw: &str) -> UaResult<String> {
    let slug = raw.trim();
    let ok = (1..=SLUG_MAX).contains(&slug.len())
        && slug.split('-').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
    if !ok {
        return Err(UaError::invalid(format!("invalid office slug {raw:?}")));
    }
    Ok(slug.to_string())
}

fn clean_name(raw: &str) -> UaResult<String> {
    let name = raw.trim();
    if name.is_empty() || name.len() > NAME_MAX || name.chars().any(char::is_control) {
        return Err(UaError::invalid("office name must be 1-200 characters without control characters"));
    }
    Ok(name.to_string())
}

fn clean_role(raw: &str) -> UaResult<&'static str> {
    let role = raw.trim();
    ROLES.into_iter().find(|r| *r == role).ok_or_else(|| UaError::invalid(format!("unknown role {raw:?}")))
}

fn clean_kind(raw: Option<&str>) -> UaResult<&'static str> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok("local"),
        Some("local") => Ok("local"),
        Some("cloud") => Ok("cloud"),
        Some(other) => Err(UaError::invalid(format!("unknown agent kind {other:?}"))),
    }
}

fn one_profile<'a>(name: &str, allowed: &'a [String]) -> UaResult<&'a str> {
    let profile = Profile::parse_assignable(name.trim()).map_err(UaError::invalid)?;
    allowed.iter().find(|p| p.as_str() == profile.as_str()).map(String::as_str).ok_or_else(|| {
        UaError::invalid(format!("profile {name:?} is outside this organization's allowed profiles"))
    })
}

fn canonical_profiles(names: &[String], allowed: &[String]) -> UaResult<Vec<String>> {
    if names.is_empty() {
        return Err(UaError::invalid("an office needs at least one profile"));
    }
    let mut profiles = Vec::new();
    for name in names {
        let profile = one_profile(name, allowed)?;
        if !profiles.iter().any(|p: &String| p == profile) {
            profiles.push(profile.to_string());
        }
    }
    profiles.sort();
    Ok(profiles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn office(slug: &str, name: &str) -> Office {
        Office {
            id: slug.into(),
            slug: slug.into(),
            name: name.into(),
            profiles: vec!["developer".into()],
            created_at: String::new(),
        }
    }

    fn seat(label: &str, office: &str) -> Seat {
        Seat {
            label: label.into(),
            office: office.into(),
            profile: "developer".into(),
            agent_kind: "local".into(),
            created_at: String::new(),
        }
    }

    #[test]
    fn validation_matches_the_registry_findings() {
        let offices = vec![office("platform", "Platform")];
        let seats = vec![seat("builder-1", "platform")];
        let missing = validate(&offices, &seats, &[], Some(&["builder-1".into()]), &[]);
        assert!(missing.is_empty());

        let unknown = validate(
            &offices,
            &[seat("Missing-One", "platform"), seat("builder-1", "platform")],
            &[],
            Some(&["builder-1".into()]),
            &[],
        );
        assert_eq!(unknown.len(), 1);
        assert_eq!(unknown[0].identity, "Missing-One");
        assert_eq!(unknown[0].issue, ISSUE_MEMBER_NOT_IN_ROSTER);
        assert_eq!(unknown[0].office.as_deref(), Some("platform"));

        let active = validate(&offices, &seats, &[], None, &["mystery-agent".into()]);
        assert_eq!(active[0].issue, ISSUE_ACTIVE_WITHOUT_OFFICE);

        let services = vec!["bridge-sender".into()];
        let exempt = validate(
            &offices,
            &seats,
            &services,
            Some(&["builder-1".into(), "bridge-sender".into()]),
            &["bridge-sender".into(), "mystery-agent".into()],
        );
        assert_eq!(exempt.len(), 1);
        assert_eq!(exempt[0].identity, "mystery-agent");

        let not_listed = validate(&offices, &seats, &services, Some(&["builder-1".into()]), &[]);
        assert_eq!(not_listed[0].issue, ISSUE_SERVICE_NOT_IN_ROSTER);

        let seated = vec![seat("builder-1", "platform")];
        let in_office = validate(&offices, &seated, &["builder-1".into()], Some(&["builder-1".into()]), &[]);
        assert!(
            in_office
                .iter()
                .any(|f| f.issue == ISSUE_SERVICE_IN_OFFICE && f.office.as_deref() == Some("platform"))
        );
    }

    #[test]
    fn an_open_roster_does_not_flag_members() {
        let findings = validate(
            &[office("platform", "Platform")],
            &[seat("builder-1", "platform")],
            &["bridge-sender".into()],
            None,
            &[],
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn office_lookup_is_case_insensitive_and_slug_wins() {
        let registry = Registry {
            org_id: DEFAULT_ORG_ID.into(),
            offices: vec![office("platform", "Review"), office("review", "Platform")],
            roles: vec![],
            seats: vec![seat("builder-1", "platform"), seat("reviewer-1", "review")],
            service_identities: vec![],
            findings: vec![],
        };
        // "Platform" matches the slug `platform` before the other office's name.
        assert_eq!(find_office(&registry, " Platform ").map(|o| o.slug.as_str()), Some("platform"));
        // "Review" matches the slug `review` before the other office's name.
        assert_eq!(find_office(&registry, "Review").map(|o| o.slug.as_str()), Some("review"));
        assert_eq!(offices_for_identity(&registry, "Builder-1"), vec!["platform".to_string()]);
        assert_eq!(office_for_identity(&registry, "reviewer-1").as_deref(), Some("review"));
        assert_eq!(office_for_identity(&registry, "nobody"), None);
    }

    #[test]
    fn labels_and_slugs_reject_the_malformed_shapes() {
        for label in ["bad label", "bad:label", "bad.label", "9lead", &"a".repeat(65)] {
            assert!(clean_label(label).is_err(), "{label}");
        }
        assert_eq!(clean_label("  builder-1 ").unwrap(), "builder-1");
        assert!(clean_slug("invalid/office").is_err());
        assert!(clean_slug("Platform").is_err());
        assert!(clean_slug("a--b").is_err());
        assert_eq!(clean_slug("platform-1").unwrap(), "platform-1");
        assert!(clean_role("owner").is_err());
        assert_eq!(clean_role(" org_admin ").unwrap(), "org_admin");
        assert_eq!(clean_kind(None).unwrap(), "local");
        assert!(clean_kind(Some("hosted")).is_err());
    }
}
