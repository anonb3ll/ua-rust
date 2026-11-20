//! The registry against a real database: offices, roles, seats, service
//! identities, the ledger event and the case-insensitive label key.

use rusqlite::OptionalExtension;
use serde_json::Value;
use ua_org::{
    DEFAULT_ORG_ID, ISSUE_ACTIVE_WITHOUT_OFFICE, RegisterOffice, RegisterRole, RegisterSeat, RegisterService,
    register_office, register_role, register_seat, register_service,
};
use ua_store::Db;

fn db() -> Db {
    Db::open_in_memory(&[ua_store::ledger::SCHEMA, ua_org::SCHEMA]).unwrap()
}

fn office(slug: &str, profiles: &[&str]) -> RegisterOffice {
    RegisterOffice {
        slug: slug.into(),
        name: slug.into(),
        profiles: profiles.iter().map(|p| (*p).to_string()).collect(),
    }
}

fn role(label: &str, role: &str) -> RegisterRole {
    RegisterRole { label: label.into(), role: role.into() }
}

fn seat(label: &str, office: &str, profile: &str, kind: Option<&str>) -> RegisterSeat {
    RegisterSeat {
        label: label.into(),
        office: office.into(),
        profile: profile.into(),
        agent_kind: kind.map(str::to_string),
    }
}

fn service(label: &str) -> RegisterService {
    RegisterService { label: label.into() }
}

fn events(db: &Db) -> Vec<Value> {
    db.read(|c| {
        let mut stmt =
            c.prepare("SELECT payload FROM event_log WHERE channel = 'agent.org.registry' ORDER BY seq")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?).unwrap());
        }
        Ok(out)
    })
    .unwrap()
}

#[test]
fn register_office_role_seat_and_service() {
    let db = db();
    db.write(|tx| {
        let created = register_office(tx, office("platform", &["developer", "cto"]), "operator")?;
        assert!(created.changed);
        assert_eq!(created.value.profiles, ["developer", "lead"]);
        assert_eq!(created.value.slug, "platform");

        let again = register_office(tx, office("platform", &["developer"]), "operator");
        assert_eq!(again.unwrap_err().code(), "conflict");

        let bad = register_office(tx, office("invalid/office", &["developer"]), "operator");
        assert_eq!(bad.unwrap_err().code(), "invalid_argument");

        let granted = register_role(tx, role("operator", "org_owner"), "operator")?;
        assert!(granted.changed);
        assert_eq!(granted.value.role, "org_owner");
        let same = register_role(tx, role("Operator", "org_owner"), "operator")?;
        assert!(!same.changed);
        assert_eq!(same.value.label, "operator");

        let seated = register_seat(tx, seat("builder-1", "Platform", "lead", Some("cloud")), "operator")?;
        assert!(seated.changed);
        assert_eq!(seated.value.office, "platform");
        assert_eq!(seated.value.profile, "lead");
        assert_eq!(seated.value.agent_kind, "cloud");

        let moved = register_seat(tx, seat("Builder-1", "platform", "developer", None), "operator")?;
        assert!(moved.changed);
        assert_eq!(moved.value.label, "builder-1");
        assert_eq!(moved.value.profile, "developer");
        assert_eq!(moved.value.agent_kind, "local");

        let declared = register_service(tx, service(" bridge-sender "), "operator")?;
        assert!(declared.changed);
        assert_eq!(declared.value, "bridge-sender");
        let service_again = register_service(tx, service("Bridge-Sender"), "operator")?;
        assert!(!service_again.changed);

        let registry = ua_org::load(tx, DEFAULT_ORG_ID, None, &["builder-1".into(), "stray-agent".into()])?;
        assert_eq!(registry.offices.len(), 1);
        assert_eq!(registry.roles.len(), 1);
        assert_eq!(registry.seats.len(), 1);
        assert_eq!(registry.service_identities, ["bridge-sender"]);
        assert_eq!(registry.findings.len(), 1);
        assert_eq!(registry.findings[0].issue, ISSUE_ACTIVE_WITHOUT_OFFICE);
        assert_eq!(registry.findings[0].identity, "stray-agent");
        assert!(!ua_org::health(&registry).live);
        Ok(())
    })
    .unwrap();

    let kinds: Vec<String> =
        events(&db).into_iter().map(|e| e["kind"].as_str().unwrap().to_string()).collect();
    assert_eq!(
        kinds,
        ["office.registered", "role.registered", "seat.registered", "seat.updated", "service.registered",]
    );
}

#[test]
fn a_seat_profile_must_belong_to_its_office() {
    let db = db();
    let err = db
        .write(|tx| {
            register_office(tx, office("platform", &["developer"]), "operator")?;
            register_seat(tx, seat("builder-1", "platform", "reviewer", None), "operator")?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("not in office"));
}

#[test]
fn the_last_owner_cannot_be_demoted_and_labels_do_not_overlap() {
    let db = db();
    db.write(|tx| {
        register_role(tx, role("operator", "org_owner"), "operator")?;
        register_role(tx, role("admin-1", "org_admin"), "operator")?;
        let err = register_role(tx, role("operator", "member"), "admin-1").unwrap_err();
        assert_eq!(err.code(), "conflict");
        register_role(tx, role("admin-1", "org_owner"), "operator")?;
        register_role(tx, role("operator", "member"), "admin-1")?;

        register_office(tx, office("platform", &["developer"]), "operator")?;
        register_seat(tx, seat("builder-1", "platform", "developer", None), "operator")?;
        let err = register_role(tx, role("builder-1", "member"), "operator").unwrap_err();
        assert_eq!(err.code(), "conflict");
        let err = register_service(tx, service("builder-1"), "operator").unwrap_err();
        assert_eq!(err.code(), "conflict");
        let err = register_seat(tx, seat("operator", "platform", "developer", None), "operator").unwrap_err();
        assert_eq!(err.code(), "conflict");
        Ok(())
    })
    .unwrap();
}

#[test]
fn a_session_credential_profile_cannot_be_an_office_profile() {
    let db = db();
    let err =
        db.write(|tx| register_office(tx, office("platform", &["acp-session"]), "operator")).unwrap_err();
    assert_eq!(err.code(), "invalid_argument");
}

#[test]
fn organizations_are_not_deleted_and_the_default_org_allows_every_profile() {
    let db = db();
    let err = db.write(|tx| Ok(tx.execute("DELETE FROM orgs", [])?)).unwrap_err();
    assert!(err.to_string().contains("never deleted"), "{err}");
    let allowed: Vec<String> = db
        .read(|c| {
            let raw: String =
                c.query_row("SELECT allowed_profiles FROM orgs WHERE id = 'default'", [], |r| r.get(0))?;
            Ok(serde_json::from_str(&raw).unwrap())
        })
        .unwrap();
    assert!(allowed.iter().any(|p| p == "coordinator"));
    assert!(allowed.iter().any(|p| p == "operator"));
    assert_eq!(allowed.len(), 10);
}

#[test]
fn role_labels_collide_case_insensitively() {
    let db = db();
    db.write(|tx| {
        register_role(tx, role("operator", "member"), "operator")?;
        Ok(())
    })
    .unwrap();
    let collided: Option<i64> = db
        .read(|c| {
            Ok(c.query_row(
                "SELECT 1 FROM org_role_grants WHERE label = 'OPERATOR' COLLATE NOCASE",
                [],
                |r| r.get(0),
            )
            .optional()?)
        })
        .unwrap();
    assert!(collided.is_some());
    let err = db
        .write(|tx| {
            tx.execute(
                "INSERT INTO org_role_grants (org_id, label, role, added_by, added_at) \
                 VALUES ('default', 'OPERATOR', 'auditor', 'operator', '2026-01-01T00:00:00+00:00')",
                [],
            )?;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(err.code(), "conflict");
}
