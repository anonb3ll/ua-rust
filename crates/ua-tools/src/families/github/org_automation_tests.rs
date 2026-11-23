//! The GitHub and CI automation per organization, against a local mock of
//! the REST API: a webhook delivery belongs to the organizations whose own
//! secret verifies it, the poller polls each organization with its own token
//! and skips one without, CI lookups and merged reconciliation use the
//! task's organization's token and bindings, and no path ever sends the
//! hub's token for another organization.
//!
//! These live in the crate, not in `tests/`, because another organization's
//! credential can only be sealed (bound to its organization) through the
//! crate's own write path: until memberships exist no tool stores one, and
//! the public API has no test-only door. They need no Cargo feature.
//!
//! Every value is fake. The mock records a short SHA-256 fingerprint of each
//! request's `Authorization` header, never the header, and assertions print
//! fingerprints and organization ids only.

//!
//! The cases sit in a `#[cfg(test)]` module so the workspace's source guards
//! (`org_guard`, `authz_guard`, the insert guard), which skip test items,
//! treat them as the test code they are.

#[cfg(test)]
mod cases {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Request, State};
    use axum::http::{StatusCode, header};
    use axum::response::{IntoResponse, Response};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, identity::Transport};

    use super::super::credentials::CredentialKind;
    use super::super::webhook::{WebhookDelivery, WebhookError, receive, signature_for};
    use crate::Hub;
    use crate::families::managed_secrets;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const ORG_B: &str = "org-b";
    const ORG_C: &str = "org-c";
    const HUB_TOKEN: &str = "fake-hub-token-not-real-91c2";
    const HUB_HOOK: &str = "fake-hub-webhook-not-real-91c2";
    const B_TOKEN: &str = "fake-org-b-token-not-real-91c2";
    const B_HOOK: &str = "fake-org-b-webhook-not-real-91c2";
    const C_HOOK: &str = "fake-org-c-webhook-not-real-91c2";
    const WRONG_HOOK: &str = "fake-wrong-webhook-not-real-91c2";
    const SHARED: &str = "shared/repo";
    const B_OWN: &str = "owner-b/falcon";
    const MERGE_SHA: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    /// A short fingerprint of a bearer token, as the mock records it.
    fn fp(token: &str) -> String {
        hex::encode(Sha256::digest(format!("Bearer {token}").as_bytes()))[..16].to_string()
    }

    // --- the mock GitHub ------------------------------------------------------------------

    #[derive(Default)]
    struct Mock {
        /// Open pull requests by repository.
        open: HashMap<String, Vec<Value>>,
        /// Pull requests by (repository, number).
        pulls: HashMap<(String, u64), Value>,
        /// A token fingerprint the mock refuses with 401.
        refuse: Option<String>,
        /// (repository, rest of the path, token fingerprint), per request.
        log: Vec<(String, String, String)>,
    }

    type Shared = Arc<Mutex<Mock>>;

    async fn serve(State(m): State<Shared>, req: Request) -> Response {
        let path = req.uri().path().to_string();
        let Some(rest) = path.strip_prefix("/repos/") else { return StatusCode::BAD_REQUEST.into_response() };
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() < 2 {
            return StatusCode::BAD_REQUEST.into_response();
        }
        let repo = format!("{}/{}", parts[0], parts[1]);
        let tail = parts[2..].join("/");
        let auth = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
        let seen = hex::encode(Sha256::digest(auth.as_bytes()))[..16].to_string();
        let mut m = m.lock().unwrap();
        m.log.push((repo.clone(), tail.clone(), seen.clone()));
        if m.refuse.as_deref() == Some(seen.as_str()) {
            return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "message": "Bad credentials" })))
                .into_response();
        }
        let found = match parts[2..] {
            ["pulls"] => Some(json!(m.open.get(&repo).cloned().unwrap_or_default())),
            ["pulls", n] => n.parse::<u64>().ok().and_then(|n| m.pulls.get(&(repo.clone(), n)).cloned()),
            _ => None,
        };
        let mut resp = match found {
            Some(body) => (StatusCode::OK, axum::Json(body)).into_response(),
            None => (StatusCode::NOT_FOUND, axum::Json(json!({ "message": "Not Found" }))).into_response(),
        };
        resp.headers_mut().insert("x-ratelimit-remaining", "4999".parse().unwrap());
        resp
    }

    async fn start_mock() -> (Shared, String) {
        let state: Shared = Arc::default();
        let app = Router::new().fallback(serve).with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (state, format!("http://{addr}"))
    }

    fn merged_pr(repo: &str, number: u64) -> Value {
        json!({
            "number": number, "merged": true, "merged_at": ua_core::time::now(), "updated_at": ua_core::time::now(),
            "merge_commit_sha": MERGE_SHA, "html_url": format!("https://github.com/{repo}/pull/{number}"),
            "head": { "ref": format!("feature-{number}"), "sha": "f".repeat(40) },
            "base": { "ref": "main", "repo": { "full_name": repo, "default_branch": "main" } },
        })
    }

    fn open_pr(number: u64) -> Value {
        json!({ "number": number, "head": { "sha": "a".repeat(40) } })
    }

    // --- the hub --------------------------------------------------------------------------

    fn agent(org: &str) -> Caller {
        Caller {
            label: "builder-1".into(),
            kind: ActorKind::Agent,
            profile: Profile::Developer,
            enforce_profile: true,
            session_key: Some("builder-1-s".into()),
            transport: Transport::Mcp,
            org_id: org.into(),
        }
    }

    fn reason(e: &UaError) -> String {
        e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string())
    }

    struct H {
        hub: Hub,
        mock: Shared,
    }

    /// Which credentials each organization holds.
    struct Creds {
        hub: bool,
        b_token: bool,
        b_hook: Option<&'static str>,
        c_hook: Option<&'static str>,
    }

    const ALL: Creds = Creds { hub: true, b_token: true, b_hook: Some(B_HOOK), c_hook: Some(C_HOOK) };

    impl H {
        async fn new(creds: Creds) -> Self {
            let (mock, base) = start_mock().await;
            let mut cfg = Config::for_home(std::env::temp_dir().join("ua-gh-org-automation"));
            cfg.managed_secret_key = Some(KEY.to_string().into());
            cfg.fetch_allow_loopback = true;
            cfg.github_api_url = base;
            cfg.github_web_host = Some("github.com".into());
            if creds.hub {
                cfg.github_token_value = Some(HUB_TOKEN.to_string().into());
                cfg.github_webhook_secret_value = Some(HUB_HOOK.to_string().into());
            }
            let hub = Hub::in_memory(cfg).unwrap();
            let h = H { hub, mock };
            h.sql(&format!(
            "INSERT INTO orgs (id, slug, display_name, allowed_profiles, created_at) VALUES
                ('{ORG_B}', '{ORG_B}', '{ORG_B}', '[\"developer\"]', '2026-01-01T00:00:00+00:00'),
                ('{ORG_C}', '{ORG_C}', '{ORG_C}', '[\"developer\"]', '2026-01-01T00:00:00+00:00');
             INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at) VALUES
                ('{DEFAULT_ORG}', 'web', '{SHARED}', 'main', 'operator', 'x'),
                ('{ORG_B}', 'web', '{SHARED}', 'main', 'operator', 'x'),
                ('{ORG_B}', 'falcon', '{B_OWN}', 'main', 'operator', 'x'),
                ('{ORG_C}', 'web', '{SHARED}', 'main', 'operator', 'x');"
        ));
            if creds.b_token {
                h.store(ORG_B, CredentialKind::Token, B_TOKEN);
            }
            if let Some(v) = creds.b_hook {
                h.store(ORG_B, CredentialKind::WebhookSecret, v);
            }
            if let Some(v) = creds.c_hook {
                h.store(ORG_C, CredentialKind::WebhookSecret, v);
            }
            h
        }

        fn sql(&self, sql: &str) {
            let sql = sql.to_string();
            self.hub
                .db()
                .write(move |tx| {
                    tx.execute_batch(&sql)?;
                    Ok(())
                })
                .unwrap();
        }

        fn text(&self, sql: &str) -> Option<String> {
            let sql = sql.to_string();
            self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0)).ok())).unwrap()
        }

        fn count(&self, sql: &str) -> i64 {
            let sql = sql.to_string();
            self.hub.db().read(move |c| Ok(c.query_row(&sql, [], |r| r.get(0))?)).unwrap()
        }

        /// Another organization's credential, through the shared write path.
        fn store(&self, org: &str, kind: CredentialKind, value: &str) {
            let cfg = self.hub.cfg().clone();
            let sealed =
                managed_secrets::seal_value(&cfg, org, kind.secret_name(), kind.consumer(), value).unwrap();
            let org = org.to_string();
            self.hub
                .db()
                .write(move |tx| {
                    let caller = Caller::system_for(org.as_str());
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

        async fn call(&self, who: &Caller, tool: &str, args: Value) -> Result<Value, UaError> {
            crate::builtin_registry_shared().call(&self.hub, who, tool, args).await
        }

        async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
            match self.call(who, tool, args.clone()).await {
                Ok(v) => v,
                Err(e) => panic!("{tool} in {} failed: {e:?}", who.org_id),
            }
        }

        /// A task of `org` in `project` whose evidence names `link`.
        async fn task(&self, org: &str, project: &str, link: &str) -> i64 {
            let args = json!({ "title": "ships", "project": project, "evidence_ref": link });
            self.ok(&agent(org), "task_add", args).await["id"].as_i64().unwrap()
        }

        fn status(&self, id: i64) -> String {
            self.text(&format!("SELECT status FROM tasks WHERE id = {id}")).unwrap()
        }

        /// The token fingerprints the mock saw for `repo`, in order.
        fn tokens_for(&self, repo: &str) -> Vec<String> {
            self.mock
                .lock()
                .unwrap()
                .log
                .iter()
                .filter(|(r, ..)| r == repo)
                .map(|(.., f)| f.clone())
                .collect()
        }

        fn all_tokens(&self) -> Vec<String> {
            self.mock.lock().unwrap().log.iter().map(|(.., f)| f.clone()).collect()
        }

        async fn deliver(
            &self,
            secret: Option<&str>,
            event: &str,
            id: &str,
            body: &[u8],
        ) -> Result<Value, WebhookError> {
            let sig = secret.map(|s| signature_for(s.as_bytes(), body));
            receive(&self.hub, WebhookDelivery { event, delivery_id: id, signature: sig.as_deref(), body })
                .await
        }
    }

    fn merge_body(repo: &str, number: u64) -> Vec<u8> {
        let pr = merged_pr(repo, number);
        serde_json::to_vec(&json!({
            "action": "closed", "number": number, "pull_request": pr,
            "repository": { "full_name": repo, "default_branch": "main" },
        }))
        .unwrap()
    }

    fn closed_ids(out: &Value) -> Vec<i64> {
        out["result"]["closed"]
            .as_array()
            .map_or(Vec::new(), |a| a.iter().filter_map(|c| c["task_id"].as_i64()).collect())
    }

    // --- webhook --------------------------------------------------------------------------

    /// The same merged-PR body, for a repository three organizations bind, is
    /// signed once with organization B's secret and once with the default
    /// organization's: each delivery belongs to the organization whose secret
    /// verified it, closes only that organization's task, and is recorded under
    /// that organization's own replay keys (so the identical body is not a
    /// replay for the other).
    #[tokio::test]
    async fn a_delivery_belongs_to_the_organization_whose_secret_verifies_it() {
        let h = H::new(ALL).await;
        let link = format!("{SHARED}#8");
        let (ta, tb, tc) = (
            h.task(DEFAULT_ORG, "web", &link).await,
            h.task(ORG_B, "web", &link).await,
            h.task(ORG_C, "web", &link).await,
        );
        let body = merge_body(SHARED, 8);

        let out = h.deliver(Some(B_HOOK), "pull_request", "merge-8-b", &body).await.unwrap();
        assert_eq!(out["org_id"], ORG_B, "{out}");
        assert_eq!(closed_ids(&out), [tb], "{out}");
        assert_eq!((h.status(ta), h.status(tb), h.status(tc)), ("open".into(), "done".into(), "open".into()));
        // Its event is organization B's: repository redacted, neutral originator.
        let (repo, by) = (
        h.text(
            "SELECT json_extract(payload, '$.repo') FROM event_log WHERE channel = 'agent.github.webhook.received' \
             AND json_extract(payload, '$.org_id') = 'org-b'",
        ),
        h.text(
            "SELECT originator FROM event_log WHERE channel = 'agent.github.closed_on_merge' \
             AND json_extract(payload, '$.org_id') = 'org-b'",
        ),
    );
        assert_eq!(repo, None, "another organization's repository stays out of the default ledger");
        assert_eq!(by.as_deref(), Some("system"));

        // The identical body, signed with the default organization's secret.
        let out = h.deliver(Some(HUB_HOOK), "pull_request", "merge-8-d", &body).await.unwrap();
        assert_eq!(out["org_id"], DEFAULT_ORG, "{out}");
        assert_eq!(closed_ids(&out), [ta], "{out}");
        assert_eq!(h.status(tc), "open", "organization C's secret signed nothing");

        // Each organization's replay keys are its own.
        for org in [DEFAULT_ORG, ORG_B] {
            let n = h.count(&format!(
            "SELECT count(*) FROM inbound_deliveries WHERE org_id = '{org}' AND source = 'github' AND kind = 'body_sha256'"
        ));
            assert_eq!(n, 1, "{org}");
        }
        assert_eq!(h.count("SELECT count(*) FROM inbound_deliveries WHERE org_id = 'org-c'"), 0);
        // A webhook never calls the API for a merge: no token was sent at all.
        assert!(h.all_tokens().is_empty());
        // And a resend of B's under a fresh id is still a replay for B.
        assert_eq!(
            h.deliver(Some(B_HOOK), "pull_request", "merge-8-b2", &body).await.unwrap_err(),
            WebhookError::Replayed
        );
    }

    #[tokio::test]
    async fn an_unsigned_or_wrongly_signed_delivery_is_refused_and_touches_nothing() {
        let h = H::new(ALL).await;
        let link = format!("{SHARED}#9");
        let ids = [h.task(DEFAULT_ORG, "web", &link).await, h.task(ORG_B, "web", &link).await];
        let body = merge_body(SHARED, 9);
        for (secret, id) in [(None, "u-1"), (Some(WRONG_HOOK), "u-2")] {
            let e = h.deliver(secret, "pull_request", id, &body).await.unwrap_err();
            assert_eq!(e, WebhookError::BadSignature);
        }
        // A signature with another organization's secret over a changed body.
        let sig = signature_for(B_HOOK.as_bytes(), &body);
        let mut tampered = body.clone();
        tampered.push(b' ');
        let e = receive(
            &h.hub,
            WebhookDelivery {
                event: "pull_request",
                delivery_id: "u-3",
                signature: Some(&sig),
                body: &tampered,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(e, WebhookError::BadSignature);
        for id in ids {
            assert_eq!(h.status(id), "open");
        }
        assert_eq!(h.count("SELECT count(*) FROM inbound_deliveries WHERE source = 'github'"), 0);
        assert_eq!(h.count("SELECT count(*) FROM event_log WHERE channel GLOB 'agent.github.*'"), 0);
    }

    #[tokio::test]
    async fn with_no_secret_anywhere_every_delivery_is_refused() {
        let h = H::new(Creds { hub: false, b_token: false, b_hook: None, c_hook: None }).await;
        let body = merge_body(SHARED, 1);
        let e = h.deliver(Some(HUB_HOOK), "pull_request", "n-1", &body).await.unwrap_err();
        assert_eq!(e, WebhookError::NotConfigured);
        // The default organization off, organization B's secret alone still
        // verifies only B's deliveries.
        h.store(ORG_B, CredentialKind::WebhookSecret, B_HOOK);
        assert_eq!(
            h.deliver(Some(HUB_HOOK), "ping", "n-2", b"{}").await.unwrap_err(),
            WebhookError::BadSignature
        );
        let out = h.deliver(Some(B_HOOK), "ping", "n-3", b"{}").await.unwrap();
        assert_eq!((out["org_id"].as_str(), out["handled"].as_str()), (Some(ORG_B), Some("ping")), "{out}");
    }

    /// The multi-match rule: two organizations configured with the same secret
    /// both verify a delivery, and it is processed for each, in a fixed order,
    /// against each one's own tasks.
    #[tokio::test]
    async fn a_secret_two_organizations_share_processes_the_delivery_for_each() {
        let h =
            H::new(Creds { hub: true, b_token: false, b_hook: Some(B_HOOK), c_hook: Some(HUB_HOOK) }).await;
        let link = format!("{SHARED}#4");
        let (ta, tb, tc) = (
            h.task(DEFAULT_ORG, "web", &link).await,
            h.task(ORG_B, "web", &link).await,
            h.task(ORG_C, "web", &link).await,
        );
        let body = merge_body(SHARED, 4);
        let out = h.deliver(Some(HUB_HOOK), "pull_request", "multi-4", &body).await.unwrap();
        let orgs: Vec<&str> =
            out["orgs"].as_array().unwrap().iter().map(|o| o["org_id"].as_str().unwrap()).collect();
        assert_eq!(orgs, [DEFAULT_ORG, ORG_C], "{out}");
        let per: Vec<Vec<i64>> =
            out["orgs"].as_array().unwrap().iter().map(|o| closed_ids(&o["result"])).collect();
        assert_eq!(per, [vec![ta], vec![tc]], "{out}");
        assert_eq!(h.status(tb), "open", "organization B's secret did not sign it");
        // Again: a replay for both.
        assert_eq!(
            h.deliver(Some(HUB_HOOK), "pull_request", "multi-4b", &body).await.unwrap_err(),
            WebhookError::Replayed
        );
    }

    // --- CI re-verification ---------------------------------------------------------------

    /// A push signed by organization B re-verifies B's check with B's token; one
    /// signed by organization C, which has no token, reports its check
    /// credential-off and sends no request. The hub's token is never used for
    /// either.
    #[tokio::test]
    async fn ci_lookups_use_the_tasks_organization_token_or_report_it_off() {
        let h = H::new(ALL).await;
        let head = "d".repeat(40);
        let mut tasks = HashMap::new();
        for org in [ORG_B, ORG_C] {
            let id = h.ok(&agent(org), "task_add", json!({ "title": "ci", "project": "web" })).await["id"]
                .as_i64()
                .unwrap();
            h.ok(&agent(org), "task_claim", json!({ "id": id })).await;
            h.ok(
                &agent(org),
                "coordination_manage",
                json!({ "action": "task_check_record", "params": {
                "task_id": id, "name": "ci", "outcome": "pass", "head_sha": head,
                "ref": { "kind": "ci_run", "ref": "41" }, "verify": false } }),
            )
            .await;
            tasks.insert(org, id);
        }
        let body =
            serde_json::to_vec(&json!({ "after": head, "repository": { "full_name": SHARED } })).unwrap();

        let out = h.deliver(Some(B_HOOK), "push", "push-b", &body).await.unwrap();
        let checks: Vec<i64> =
            out["checks"].as_array().unwrap().iter().map(|c| c["task_id"].as_i64().unwrap()).collect();
        assert_eq!(checks, [tasks[ORG_B]], "{out}");
        let seen = h.tokens_for(SHARED);
        assert!(!seen.is_empty() && seen.iter().all(|f| *f == fp(B_TOKEN)), "{seen:?}");

        let before = h.all_tokens().len();
        let out = h.deliver(Some(C_HOOK), "push", "push-c", &body).await.unwrap();
        let checks: Vec<i64> =
            out["checks"].as_array().unwrap().iter().map(|c| c["task_id"].as_i64().unwrap()).collect();
        assert_eq!(checks, [tasks[ORG_C]], "{out}");
        assert_eq!(out["checks"][0]["verdict"], "unverifiable", "{out}");
        assert_eq!(h.all_tokens().len(), before, "organization C made no request");
        let detail = h
            .text(&format!(
                "SELECT json_extract(verification_json, '$.detail') FROM task_checks WHERE task_id = {}",
                tasks[ORG_C]
            ))
            .unwrap();
        assert!(detail.contains("credential off"), "{detail}");
        assert!(
            !h.all_tokens().contains(&fp(HUB_TOKEN)),
            "the hub's token never served another organization"
        );
    }

    // --- the poller -----------------------------------------------------------------------

    /// Each organization with a token is polled with its own; one without is
    /// skipped; a merged PR closes only the polling organization's task; one
    /// organization's refused token does not stop the others and is counted.
    #[tokio::test]
    async fn the_poller_polls_each_organization_with_its_own_token() {
        let h = H::new(ALL).await;
        let tb = h.task(ORG_B, "falcon", &format!("{B_OWN}#6")).await;
        let (ta_shared, tb_shared) = (
            h.task(DEFAULT_ORG, "web", &format!("{SHARED}#7")).await,
            h.task(ORG_B, "web", &format!("{SHARED}#7")).await,
        );
        {
            let mut m = h.mock.lock().unwrap();
            m.open.insert(B_OWN.into(), vec![open_pr(6)]);
            m.open.insert(SHARED.into(), vec![open_pr(7)]);
            m.pulls.insert((B_OWN.into(), 6), merged_pr(B_OWN, 6));
            m.pulls.insert((SHARED.into(), 7), merged_pr(SHARED, 7));
        }
        let first = super::super::poll_once(&h.hub).await.unwrap();
        let states: Vec<(&str, &str)> = first["orgs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o["org_id"].as_str().unwrap(), o["state"].as_str().unwrap()))
            .collect();
        assert_eq!(states, [(DEFAULT_ORG, "polled"), (ORG_B, "polled")], "{first}");
        // Organization C holds no token and is not listed as one that may: it is
        // never polled, and nothing is sent for it.
        assert_eq!(h.tokens_for(B_OWN), [fp(B_TOKEN)]);
        let mut shared = h.tokens_for(SHARED);
        shared.sort();
        let mut want = vec![fp(HUB_TOKEN), fp(B_TOKEN)];
        want.sort();
        assert_eq!(
            shared, want,
            "the shared repository is polled once per organization, each with its own token"
        );
        assert_eq!(h.count("SELECT count(*) FROM github_poll_repos WHERE org_id = 'org-b'"), 2);
        assert_eq!(h.count("SELECT count(*) FROM github_poll_repos WHERE org_id = 'default'"), 1);

        // Both PRs merge: each organization closes its own tasks only.
        {
            let mut m = h.mock.lock().unwrap();
            m.open.clear();
        }
        super::super::poll_once(&h.hub).await.unwrap();
        assert_eq!(
            (h.status(tb), h.status(tb_shared), h.status(ta_shared)),
            ("done".into(), "done".into(), "done".into())
        );
        // Every request for B's own repository carried B's token.
        assert!(h.tokens_for(B_OWN).iter().all(|f| *f == fp(B_TOKEN)));
        let b_lookup = h
            .mock
            .lock()
            .unwrap()
            .log
            .iter()
            .any(|(r, t, f)| r == B_OWN && t == "pulls/6" && *f == fp(B_TOKEN));
        assert!(b_lookup);

        // B's token is refused: the default organization is still polled, B's
        // failure is recorded (no value) and counted by the doctor.
        h.mock.lock().unwrap().refuse = Some(fp(B_TOKEN));
        let third = super::super::poll_once(&h.hub).await.unwrap();
        let default_repos = third["orgs"][0]["repos"].as_array().unwrap();
        assert_eq!(default_repos.len(), 1, "{third}");
        assert!(default_repos[0].get("error").is_none(), "{third}");
        let b_repos = third["orgs"][1]["repos"].as_array().unwrap();
        assert!(b_repos.iter().all(|r| r["error"].as_str().is_some_and(|e| e.contains("401"))), "{third}");
        assert_eq!(
            h.count(
                "SELECT count(*) FROM github_poll_repos WHERE org_id = 'org-b' AND last_error IS NOT NULL"
            ),
            2
        );
        assert_eq!(
            h.count(
                "SELECT count(*) FROM github_poll_repos WHERE org_id = 'default' AND last_error IS NOT NULL"
            ),
            0
        );
        let stored: String = h.text("SELECT group_concat(last_error) FROM github_poll_repos").unwrap();
        for v in [HUB_TOKEN, B_TOKEN] {
            assert!(!stored.contains(v));
        }
    }

    #[tokio::test]
    async fn an_organization_without_a_token_is_skipped_not_served_by_the_hub() {
        let h = H::new(Creds { hub: true, b_token: false, b_hook: Some(B_HOOK), c_hook: None }).await;
        let out = super::super::poll_once(&h.hub).await.unwrap();
        let orgs: Vec<&str> =
            out["orgs"].as_array().unwrap().iter().map(|o| o["org_id"].as_str().unwrap()).collect();
        assert_eq!(orgs, [DEFAULT_ORG], "{out}");
        assert!(
            h.tokens_for(B_OWN).is_empty(),
            "organization B's repository is never polled with the hub's token"
        );
        assert!(h.all_tokens().iter().all(|f| *f == fp(HUB_TOKEN)));

        // No token anywhere: the poll is skipped.
        let bare = H::new(Creds { hub: false, b_token: false, b_hook: None, c_hook: None }).await;
        let out = super::super::poll_once(&bare.hub).await.unwrap();
        assert!(out["skipped"].is_string(), "{out}");
        assert!(bare.all_tokens().is_empty());
    }

    // --- merged reconciliation ------------------------------------------------------------

    /// `queue_close_merged` runs in the caller's organization with its token: B
    /// sees only its own tasks and sends B's token; C, without a token, is
    /// credential-off.
    #[tokio::test]
    async fn merged_reconciliation_runs_in_the_callers_organization() {
        let h = H::new(ALL).await;
        let link = format!("{SHARED}#5");
        let (ta, tb) = (h.task(DEFAULT_ORG, "web", &link).await, h.task(ORG_B, "web", &link).await);
        let tb_own = h.task(ORG_B, "falcon", &format!("{B_OWN}#3")).await;
        {
            let mut m = h.mock.lock().unwrap();
            m.pulls.insert((SHARED.into(), 5), merged_pr(SHARED, 5));
            m.pulls.insert((B_OWN.into(), 3), merged_pr(B_OWN, 3));
        }
        let dry = h
            .ok(&agent(ORG_B), "coordination_manage", json!({ "action": "queue_close_merged", "params": {} }))
            .await;
        let mut would: Vec<i64> =
            dry["would_close"].as_array().unwrap().iter().map(|m| m["task_id"].as_i64().unwrap()).collect();
        would.sort();
        assert_eq!(would, [tb, tb_own], "{dry}");
        assert!(!dry.to_string().contains(&format!("\"task_id\":{ta}")), "{dry}");
        assert!(h.all_tokens().iter().all(|f| *f == fp(B_TOKEN)), "{:?}", h.all_tokens());

        let e = h
            .call(
                &agent(ORG_C),
                "coordination_manage",
                json!({ "action": "queue_close_merged", "params": {} }),
            )
            .await
            .unwrap_err();
        assert_eq!(reason(&e), "github_credential_off", "{e}");
        assert!(!h.all_tokens().contains(&fp(HUB_TOKEN)));
        for t in [ta, tb, tb_own] {
            assert_eq!(h.status(t), "open", "a dry run changes nothing");
        }
    }
}
