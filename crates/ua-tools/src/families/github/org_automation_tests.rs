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
    /// A check name distinctive enough to search event payloads for.
    const CHECK_NAME: &str = "lint-check-name-91c2";

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
        /// A token fingerprint whose rate limit the mock reports exhausted
        /// (`x-ratelimit-remaining: 0`, reset in ten minutes).
        limited: Option<String>,
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
        if m.limited.as_deref() == Some(seen.as_str()) {
            let reset = ua_core::time::now_ms() / 1000 + 600;
            resp.headers_mut().insert("x-ratelimit-remaining", "0".parse().unwrap());
            resp.headers_mut().insert("x-ratelimit-reset", reset.to_string().parse().unwrap());
        } else {
            resp.headers_mut().insert("x-ratelimit-remaining", "4999".parse().unwrap());
        }
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
        merged_into(repo, number, "main")
    }

    /// A merged pull request whose base branch is `base`.
    fn merged_into(repo: &str, number: u64, base: &str) -> Value {
        json!({
            "number": number, "merged": true, "merged_at": ua_core::time::now(), "updated_at": ua_core::time::now(),
            "merge_commit_sha": MERGE_SHA, "html_url": format!("https://github.com/{repo}/pull/{number}"),
            "head": { "ref": format!("feature-{number}"), "sha": "f".repeat(40) },
            "base": { "ref": base, "repo": { "full_name": repo, "default_branch": "main" } },
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
            self.task_titled(org, project, link, "ships").await
        }

        async fn task_titled(&self, org: &str, project: &str, link: &str, title: &str) -> i64 {
            let args = json!({ "title": title, "project": project, "evidence_ref": link });
            self.ok(&agent(org), "task_add", args).await["id"].as_i64().unwrap()
        }

        /// The payloads of `org`'s events on `channel`, oldest first.
        fn events(&self, channel: &str, org: &str) -> Vec<Value> {
            let (channel, org) = (channel.to_string(), org.to_string());
            self.hub
                .db()
                .read(move |c| {
                    let mut stmt = c.prepare(
                        "SELECT payload FROM event_log WHERE channel = ?1 \
                         AND json_extract(payload, '$.org_id') = ?2 ORDER BY rowid",
                    )?;
                    let rows = stmt
                        .query_map([&channel, &org], |r| r.get::<_, String>(0))?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows.iter().map(|p| serde_json::from_str(p).unwrap()).collect())
                })
                .unwrap()
        }

        /// Replace `to`'s stored credential of `kind` with `from`'s sealed
        /// row, as if its ciphertext were moved across organizations: it is
        /// sealed to `from`, so it never opens in `to`.
        fn move_sealed(&self, from: &str, to: &str, kind: CredentialKind) {
            let name = kind.secret_name();
            self.sql(&format!(
                "DELETE FROM managed_secrets WHERE org_id = '{to}' AND name = '{name}';
                 INSERT INTO managed_secrets (org_id, name, consumer, key_id, nonce, ciphertext, fingerprint,
                    value_bytes, created_by, created_at, updated_by, updated_at, aad_v)
                 SELECT '{to}', name, consumer, key_id, nonce, ciphertext, fingerprint, value_bytes, created_by,
                    created_at, updated_by, updated_at, aad_v
                 FROM managed_secrets WHERE org_id = '{from}' AND name = '{name}';"
            ));
        }

        /// The doctor's `github_credentials` detail, as the hub's own agent sees it.
        async fn doctor_line(&self) -> String {
            let report = self.ok(&agent(DEFAULT_ORG), "system_doctor", json!({ "refresh": true })).await;
            let line = report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["capability"] == "github_credentials")
                .cloned()
                .unwrap();
            line["detail"].as_str().unwrap().to_string()
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
        // Another organization's delivery is answered neutrally; what it did
        // is in its own ledger.
        assert_eq!(out, json!({ "ok": true, "matched": 1, "statuses": [200] }));
        let closed: Vec<i64> = h
            .events("agent.github.closed_on_merge", ORG_B)
            .iter()
            .map(|e| e["task_id"].as_i64().unwrap())
            .collect();
        assert_eq!(closed, [tb]);
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
        assert_eq!(out, json!({ "ok": true, "matched": 1, "statuses": [200] }));
        assert_eq!(h.events("agent.github.webhook.received", ORG_B).len(), 1);
        assert!(h.events("agent.github.webhook.received", DEFAULT_ORG).is_empty());
    }

    /// The multi-match rule: two organizations configured with the same secret
    /// both verify a delivery, and it is processed for each, in a fixed order,
    /// against each one's own tasks. The answer is organization-neutral: no
    /// organization id, title or task of either reaches the sender.
    #[tokio::test]
    async fn a_secret_two_organizations_share_processes_the_delivery_for_each() {
        const C_TITLE: &str = "org-c-private-title-4";
        let h =
            H::new(Creds { hub: true, b_token: false, b_hook: Some(B_HOOK), c_hook: Some(HUB_HOOK) }).await;
        let link = format!("{SHARED}#4");
        let (ta, tb, tc) = (
            h.task_titled(DEFAULT_ORG, "web", &link, "default-title-4").await,
            h.task(ORG_B, "web", &link).await,
            h.task_titled(ORG_C, "web", &link, C_TITLE).await,
        );
        let body = merge_body(SHARED, 4);
        let out = h.deliver(Some(HUB_HOOK), "pull_request", "multi-4", &body).await.unwrap();
        assert_eq!(out, json!({ "ok": true, "matched": 2, "statuses": [200, 200] }));
        let text = out.to_string();
        for leak in [C_TITLE, "default-title-4", ORG_C, DEFAULT_ORG, "task_id", SHARED] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        assert_eq!((h.status(ta), h.status(tc)), ("done".into(), "done".into()));
        // Each organization's own ledger has its closure.
        for (org, id) in [(DEFAULT_ORG, ta), (ORG_C, tc)] {
            let closed: Vec<i64> = h
                .events("agent.github.closed_on_merge", org)
                .iter()
                .map(|e| e["task_id"].as_i64().unwrap())
                .collect();
            assert_eq!(closed, [id], "{org}");
        }
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
                "task_id": id, "name": CHECK_NAME, "outcome": "pass", "head_sha": head,
                "ref": { "kind": "ci_run", "ref": "41" }, "verify": false } }),
            )
            .await;
            tasks.insert(org, id);
        }
        let body =
            serde_json::to_vec(&json!({ "after": head, "repository": { "full_name": SHARED } })).unwrap();

        let out = h.deliver(Some(B_HOOK), "push", "push-b", &body).await.unwrap();
        assert_eq!(out, json!({ "ok": true, "matched": 1, "statuses": [200] }));
        let reverified = h.events("agent.github.checks_reverified", ORG_B);
        assert_eq!(reverified.len(), 1);
        let checks: Vec<i64> = reverified[0]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["task_id"].as_i64().unwrap())
            .collect();
        assert_eq!(checks, [tasks[ORG_B]]);
        // Another organization's event names no check and no repository.
        let text = reverified[0].to_string();
        for leak in [CHECK_NAME, SHARED] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        assert_eq!(reverified[0]["repo"], Value::Null);
        let seen = h.tokens_for(SHARED);
        assert!(!seen.is_empty() && seen.iter().all(|f| *f == fp(B_TOKEN)), "{seen:?}");

        let before = h.all_tokens().len();
        h.deliver(Some(C_HOOK), "push", "push-c", &body).await.unwrap();
        let reverified = h.events("agent.github.checks_reverified", ORG_C);
        assert_eq!(reverified.len(), 1);
        assert_eq!(reverified[0]["checks"][0]["task_id"].as_i64(), Some(tasks[ORG_C]));
        assert_eq!(reverified[0]["checks"][0]["verdict"], "unverifiable");
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
        // Organization B's poll events carry counts and numbers, never its
        // repositories' names.
        let polled = h.events("agent.github.polled", ORG_B);
        assert!(!polled.is_empty());
        for e in &polled {
            let text = e.to_string();
            assert!(!text.contains(B_OWN) && !text.contains(SHARED), "{text}");
            assert_eq!(e["repo"], Value::Null, "{text}");
        }
        let default_polled = h.events("agent.github.polled", DEFAULT_ORG);
        assert!(
            default_polled.iter().any(|e| e["repo"] == SHARED),
            "the default organization's keep the name"
        );

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
        // A fixed code, never library text or a value.
        let stored: String =
            h.text("SELECT group_concat(DISTINCT last_error) FROM github_poll_repos").unwrap();
        assert_eq!(stored, "unauthorized");

        // The doctor counts both, then only what is still polled: a
        // repository unbound since, or an organization whose token was
        // cleared since, is no longer a failure.
        let line = h.doctor_line().await;
        assert!(line.contains("2 bound repositories whose last poll failed"), "{line}");
        h.sql(&format!("DELETE FROM project_repo_bindings WHERE org_id = '{ORG_B}' AND project = 'falcon'"));
        let line = h.doctor_line().await;
        assert!(line.contains("1 bound repository whose last poll failed"), "{line}");
        h.sql(&format!("DELETE FROM managed_secrets WHERE org_id = '{ORG_B}' AND name = 'github:token'"));
        let line = h.doctor_line().await;
        assert!(line.contains("0 bound repositories whose last poll failed"), "{line}");
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

    // --- the signature header -------------------------------------------------------------

    /// A missing or malformed `X-Hub-Signature-256` is refused (401) before
    /// any secret is looked up: on a hub with no secret at all, where any
    /// lookup would answer `not_configured` (503), it still answers
    /// `bad_signature`. A well-formed one reaches the lookup.
    #[tokio::test]
    async fn a_missing_or_malformed_signature_is_refused_before_any_lookup() {
        let h = H::new(Creds { hub: false, b_token: false, b_hook: None, c_hook: None }).await;
        let body = b"{}";
        let hex64 = "a".repeat(64);
        let malformed = [
            None,
            Some(String::new()),
            Some("sha256=".to_string()),
            Some(format!("sha1={hex64}")),
            Some(format!("sha256={}", &hex64[..63])),
            Some(format!("sha256={hex64}a")),
            Some(format!("sha256={}", "g".repeat(64))),
            Some(format!("SHA256={hex64}")),
        ];
        for sig in &malformed {
            let e = receive(
                &h.hub,
                WebhookDelivery { event: "ping", delivery_id: "sig-1", signature: sig.as_deref(), body },
            )
            .await
            .unwrap_err();
            assert_eq!(e, WebhookError::BadSignature, "{sig:?}");
            assert_eq!(e.http_status(), 401);
        }
        let well_formed = format!("sha256={hex64}");
        let e = receive(
            &h.hub,
            WebhookDelivery { event: "ping", delivery_id: "sig-2", signature: Some(&well_formed), body },
        )
        .await
        .unwrap_err();
        assert_eq!(e, WebhookError::NotConfigured, "a well-formed header goes on to the lookup");
        assert_eq!(h.count("SELECT count(*) FROM inbound_deliveries"), 0);
    }

    // --- unusable and suspended -----------------------------------------------------------

    /// Organization C's stored secret is organization B's ciphertext moved
    /// across: it never opens in C, so C is skipped. A delivery signed with
    /// B's secret belongs to B alone (C is never handed B's secret), and one
    /// signed with C's old secret verifies nowhere.
    #[tokio::test]
    async fn an_unusable_stored_secret_is_skipped_and_never_replaced() {
        let h = H::new(ALL).await;
        h.move_sealed(ORG_B, ORG_C, CredentialKind::WebhookSecret);
        let link = format!("{SHARED}#21");
        let (tb, tc) = (h.task(ORG_B, "web", &link).await, h.task(ORG_C, "web", &link).await);
        let body = merge_body(SHARED, 21);
        let out = h.deliver(Some(B_HOOK), "pull_request", "moved-1", &body).await.unwrap();
        assert_eq!(out, json!({ "ok": true, "matched": 1, "statuses": [200] }));
        assert_eq!((h.status(tb), h.status(tc)), ("done".into(), "open".into()));
        assert!(h.events("agent.github.webhook.received", ORG_C).is_empty());
        assert_eq!(
            h.deliver(Some(C_HOOK), "pull_request", "moved-2", &body).await.unwrap_err(),
            WebhookError::BadSignature
        );
        assert_eq!(h.status(tc), "open");
    }

    /// A suspended organization's secret is never consulted.
    #[tokio::test]
    async fn a_suspended_organizations_secret_verifies_nothing() {
        let h = H::new(ALL).await;
        h.sql(&format!("UPDATE orgs SET status = 'suspended' WHERE id = '{ORG_C}'"));
        let held = h
            .hub
            .db()
            .read(|c| super::super::credentials::orgs_holding(c, CredentialKind::WebhookSecret))
            .unwrap();
        assert_eq!(held, [DEFAULT_ORG, ORG_B]);
        assert_eq!(
            h.deliver(Some(C_HOOK), "ping", "suspended-1", b"{}").await.unwrap_err(),
            WebhookError::BadSignature
        );
        assert!(h.events("agent.github.webhook.received", ORG_C).is_empty());
    }

    // --- multi-match outcomes -------------------------------------------------------------

    /// The default organization and C share a secret. C's handling fails
    /// (an injected database failure): the delivery answers 500, C's records
    /// are released, and the default organization's are kept. GitHub's
    /// redelivery is then processed for C only; the default organization
    /// reports a replay. The PR merged off the merge branch, so each
    /// organization ledgers `merged_to_non_default`: the default
    /// organization's names the branches, C's does not.
    #[tokio::test]
    async fn a_partial_failure_is_redelivered_to_the_failed_organization_only() {
        const BASE: &str = "release-branch-91c2";
        let h = H::new(Creds { hub: true, b_token: false, b_hook: None, c_hook: Some(HUB_HOOK) }).await;
        let link = format!("{SHARED}#12");
        let (ta, tc) = (h.task(DEFAULT_ORG, "web", &link).await, h.task(ORG_C, "web", &link).await);
        let body = serde_json::to_vec(&json!({
            "action": "closed", "number": 12, "pull_request": merged_into(SHARED, 12, BASE),
            "repository": { "full_name": SHARED, "default_branch": "main" },
        }))
        .unwrap();
        h.sql(
            "CREATE TRIGGER fail_org_c_off_branch BEFORE INSERT ON event_log
             WHEN NEW.channel = 'agent.github.merged_to_non_default'
              AND json_extract(NEW.payload, '$.org_id') = 'org-c'
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END;",
        );
        let e = h.deliver(Some(HUB_HOOK), "pull_request", "partial-12", &body).await.unwrap_err();
        assert!(matches!(e, WebhookError::Internal(_)), "{e:?}");
        assert_eq!(e.http_status(), 500);
        assert!(!e.message().contains(ORG_C), "{}", e.message());
        assert_eq!(h.events("agent.github.merged_to_non_default", DEFAULT_ORG).len(), 1);
        assert!(h.events("agent.github.merged_to_non_default", ORG_C).is_empty());

        h.sql("DROP TRIGGER fail_org_c_off_branch;");
        let out = h.deliver(Some(HUB_HOOK), "pull_request", "partial-12", &body).await.unwrap();
        assert_eq!(out, json!({ "ok": true, "matched": 2, "statuses": [409, 200] }));
        assert_eq!(
            h.events("agent.github.merged_to_non_default", DEFAULT_ORG).len(),
            1,
            "not processed twice"
        );
        let c_events = h.events("agent.github.merged_to_non_default", ORG_C);
        assert_eq!(c_events.len(), 1);
        // Redaction: C's event keeps ids, numbers and the merge commit, never
        // the repository or a branch.
        let c = &c_events[0];
        assert_eq!(c["task_id"].as_i64(), Some(tc));
        assert_eq!(
            (c["repo"].clone(), c["base_ref"].clone(), c["merge_branch"].clone()),
            (Value::Null, Value::Null, Value::Null)
        );
        let text = c.to_string();
        for leak in [BASE, SHARED, "\"main\""] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
        let d = &h.events("agent.github.merged_to_non_default", DEFAULT_ORG)[0];
        assert_eq!((d["base_ref"].as_str(), d["merge_branch"].as_str()), (Some(BASE), Some("main")));
        assert_eq!((h.status(ta), h.status(tc)), ("open".into(), "open".into()));
        // A third copy is a replay for both.
        assert_eq!(
            h.deliver(Some(HUB_HOOK), "pull_request", "partial-12", &body).await.unwrap_err(),
            WebhookError::Replayed
        );
    }

    /// When every matched organization refuses a delivery as a bad request,
    /// the answer is 400, as for a single match.
    #[tokio::test]
    async fn every_matched_organization_refusing_it_answers_bad_request() {
        let h = H::new(Creds { hub: true, b_token: false, b_hook: None, c_hook: Some(HUB_HOOK) }).await;
        let mut pr = merged_pr(SHARED, 13);
        pr.as_object_mut().unwrap().remove("merge_commit_sha");
        let body = serde_json::to_vec(&json!({
            "action": "closed", "number": 13, "pull_request": pr,
            "repository": { "full_name": SHARED, "default_branch": "main" },
        }))
        .unwrap();
        let e = h.deliver(Some(HUB_HOOK), "pull_request", "bad-13", &body).await.unwrap_err();
        assert!(matches!(e, WebhookError::BadRequest(_)), "{e:?}");
        assert_eq!(e.http_status(), 400);
        // Both organizations finished it: the next copy is a replay for both.
        assert_eq!(
            h.deliver(Some(HUB_HOOK), "pull_request", "bad-13", &body).await.unwrap_err(),
            WebhookError::Replayed
        );
    }

    // --- the poller: unusable token, rate limits -----------------------------------------

    /// Organization C's stored token is B's ciphertext moved across: C is
    /// reported `unusable` and never polled, while B and the default
    /// organization are.
    #[tokio::test]
    async fn the_poller_reports_an_unusable_token() {
        let h = H::new(ALL).await;
        h.move_sealed(ORG_B, ORG_C, CredentialKind::Token);
        let out = super::super::poll_once(&h.hub).await.unwrap();
        let states: Vec<(&str, &str)> = out["orgs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o["org_id"].as_str().unwrap(), o["state"].as_str().unwrap()))
            .collect();
        assert_eq!(states, [(DEFAULT_ORG, "polled"), (ORG_B, "polled"), (ORG_C, "unusable")], "{out}");
        // The shared repository: once for the default organization, once for B.
        assert_eq!(h.tokens_for(SHARED).len(), 2);
        assert_eq!(h.count("SELECT count(*) FROM github_poll_repos WHERE org_id = 'org-c'"), 0);
    }

    /// Organization B's token exhausts its rate limit: B's next poll sends
    /// nothing and records `rate_limited`; the default organization, on the
    /// same host, is polled as before.
    #[tokio::test]
    async fn one_organizations_rate_limit_does_not_block_another() {
        let h = H::new(ALL).await;
        h.mock.lock().unwrap().limited = Some(fp(B_TOKEN));
        super::super::poll_once(&h.hub).await.unwrap();
        let count = |f: &str| h.all_tokens().iter().filter(|t| *t == f).count();
        let (b_before, d_before) = (count(&fp(B_TOKEN)), count(&fp(HUB_TOKEN)));
        assert!(b_before >= 1 && d_before == 1, "{b_before} {d_before}");

        let out = super::super::poll_once(&h.hub).await.unwrap();
        assert_eq!(count(&fp(B_TOKEN)), b_before, "B is blocked: nothing sent");
        assert_eq!(count(&fp(HUB_TOKEN)), d_before + 1, "the default organization is polled");
        let default_repos = out["orgs"][0]["repos"].as_array().unwrap();
        assert!(default_repos.iter().all(|r| r.get("error").is_none()), "{out}");
        let b_repos = out["orgs"][1]["repos"].as_array().unwrap();
        assert!(
            b_repos.iter().all(|r| r["error"].as_str().is_some_and(|e| e.contains("rate limit"))),
            "{out}"
        );
        assert_eq!(
            h.text("SELECT group_concat(DISTINCT last_error) FROM github_poll_repos WHERE org_id = 'org-b'")
                .as_deref(),
            Some("rate_limited")
        );
        assert_eq!(
            h.count(
                "SELECT count(*) FROM github_poll_repos WHERE org_id = 'default' AND last_error IS NOT NULL"
            ),
            0
        );
    }

    // --- the migration --------------------------------------------------------------------

    /// `github.v2.poll_repos` copies every row of the old hub-wide
    /// `github_poll_state` into `github_poll_repos` under the default
    /// organization, field for field, and keeps the old table; run again it
    /// changes nothing.
    #[test]
    fn the_migration_copies_every_poll_row_into_the_default_organization() {
        let c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(super::super::SCHEMA.sql).unwrap();
        c.execute_batch(
            "INSERT INTO github_poll_state (repo, etag, open_json, polled_at, changed_at) VALUES
                ('a/one', 'W/\"e1\"', '{\"1\":\"aaaa\"}', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'),
                ('b/two', NULL, '{}', '2026-01-02T00:00:00Z', NULL),
                ('c/three', 'W/\"e3\"', '{\"7\":\"cccc\"}', '2026-01-03T00:00:00Z', NULL);",
        )
        .unwrap();
        type OldRow = (String, Option<String>, String, String, Option<String>);
        let old = |c: &rusqlite::Connection| -> Vec<OldRow> {
            let mut stmt = c
                .prepare("SELECT repo, etag, open_json, polled_at, changed_at FROM github_poll_state ORDER BY repo")
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        let before = old(&c);
        for _ in 0..2 {
            c.execute_batch(super::super::POLL_REPOS_SCHEMA.sql).unwrap();
        }
        let mut stmt = c
            .prepare(
                "SELECT org_id, repo, etag, open_json, polled_at, changed_at, last_error FROM github_poll_repos \
                 ORDER BY repo",
            )
            .unwrap();
        type Row = (String, String, Option<String>, String, String, Option<String>, Option<String>);
        let copied: Vec<Row> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(copied.len(), before.len());
        for ((org, repo, etag, open, polled, changed, err), (r0, e0, o0, p0, c0)) in
            copied.iter().zip(&before)
        {
            assert_eq!(org, DEFAULT_ORG);
            assert_eq!((repo, etag, open, polled, changed), (r0, e0, o0, p0, c0));
            assert_eq!(*err, None);
        }
        assert_eq!(old(&c), before, "the old table is kept as it was");
    }
}
