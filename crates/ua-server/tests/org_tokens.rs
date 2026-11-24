//! The HTTP resolver binds a caller to its credential's organization
//! (`docs/organization.md`, Resolution and the agents and sessions family):
//! a managed token resolves to its own organization, which must be its
//! agent's, and a static token, which is hub configuration, resolves to the
//! default organization and is refused while another organization's agent
//! holds its label. Every value here is fake.

mod common;

use axum::http::StatusCode;
use common::{TestHub, json_body, post_json};
use secrecy::SecretString;
use serde_json::json;

const ORG_B: &str = "org-b";
const B_AGENT: &str = "osprey-agent-not-real";
const B_TOKEN: &str = "b-managed-token-not-real-0123456789abcdef";
const A_TOKEN: &str = "a-managed-token-not-real-0123456789abcdef";
const ODD_TOKEN: &str = "odd-managed-token-not-real-0123456789abcd";
const STATIC_TOKEN: &str = "static-token-not-real-0123456789abcdef01";

fn sql(hub: &TestHub, sql: &str) {
    let sql = sql.to_string();
    hub.state
        .hub
        .db()
        .write(move |tx| {
            tx.execute_batch(&sql)?;
            Ok(())
        })
        .unwrap();
}

fn text(hub: &TestHub, sql: &str) -> String {
    let sql = sql.to_string();
    hub.state.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
}

fn digest(v: &str) -> String {
    ua_tools::families::tokens::digest(v)
}

fn hub() -> TestHub {
    let mut cfg = common::config();
    cfg.oauth_enabled = false;
    cfg.agent_tokens = Some(SecretString::from(format!("squatted-label:{STATIC_TOKEN}")));
    let hub = TestHub::new(cfg);
    sql(
        &hub,
        &format!(
            "INSERT INTO orgs (id, slug, display_name, status, allowed_profiles, created_at)
                 VALUES ('{ORG_B}', '{ORG_B}', 'Org', 'active', '[\"developer\"]', '2026-01-01T00:00:00+00:00');
             INSERT INTO agent_tokens (org_id, agent_label, token_hash, issued_at) VALUES
                 ('{ORG_B}', '{B_AGENT}', '{}', 't0'),
                 ('default', 'heron-agent', '{}', 't0'),
                 ('{ORG_B}', 'odd-agent', '{}', 't0');
             -- Only SQL can do this: every writer refuses a label another
             -- organization holds.
             INSERT INTO agents (org_id, label, created_at, updated_at) VALUES
                 ('default', 'odd-agent', 't0', 't0'),
                 ('{ORG_B}', 'squatted-label', 't0', 't0');",
            digest(B_TOKEN),
            digest(A_TOKEN),
            digest(ODD_TOKEN)
        ),
    );
    hub
}

async fn call(
    hub: &TestHub,
    token: &str,
    tool: &str,
    args: serde_json::Value,
) -> axum::http::Response<axum::body::Body> {
    let bearer = format!("Bearer {token}");
    hub.send(post_json(&format!("/api/tools/{tool}"), &args, &[("authorization", bearer.as_str())])).await
}

#[tokio::test]
async fn a_managed_token_acts_in_its_own_organization() {
    let hub = hub();
    let resp = call(&hub, B_TOKEN, "session_start", json!({ "kind": "interactive" })).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let sid = json_body(resp).await["session_id"].as_str().unwrap().to_string();
    assert_eq!(text(&hub, &format!("SELECT org_id FROM agent_sessions WHERE id = '{sid}'")), ORG_B);
    assert_eq!(text(&hub, &format!("SELECT org_id FROM agents WHERE label = '{B_AGENT}'")), ORG_B);

    // Each organization's token lists only its own sessions.
    let b_list = json_body(call(&hub, B_TOKEN, "session_list", json!({})).await).await;
    assert_eq!(b_list["total"], 1, "{b_list}");
    let a_list = json_body(call(&hub, A_TOKEN, "session_list", json!({})).await).await;
    assert_eq!(a_list["total"], 0, "{a_list}");
    assert!(!a_list.to_string().contains(&sid));
}

#[tokio::test]
async fn a_token_whose_organization_is_not_its_agents_is_refused() {
    let hub = hub();
    let resp = call(&hub, ODD_TOKEN, "session_list", json!({})).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // A static token is the default organization's; its label is held by
    // another organization's agent, so it does not authenticate.
    let resp = call(&hub, STATIC_TOKEN, "session_list", json!({})).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // The well-formed tokens still do.
    assert_eq!(call(&hub, A_TOKEN, "session_list", json!({})).await.status(), StatusCode::OK);
}
