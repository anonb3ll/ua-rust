//! The public relay (`relay_manage`) through the governed registry: every
//! gate, the approval binding, and the GitHub adapter against a loopback mock.
//!
//! Sensitive-looking strings (home paths, shared-range addresses, private DNS
//! names) are assembled at run time so this file itself stays free of them.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode, Uri};
use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_tools::{Hub, Registry, builtin_registry};

const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TOKEN: &str = "relay-test-T0KEN-value";
const TARGET: &str = "acme/widgets#42";
const CLEAN: &str = "Thanks for the report. The fix is in the next release; see the changelog for details.";

// --- the mock GitHub API ---------------------------------------------------------------

#[derive(Debug, Clone)]
struct Seen {
    path: String,
    auth: String,
    body: Value,
}

#[derive(Clone)]
struct Mock {
    seen: Arc<Mutex<Vec<Seen>>>,
    status: Arc<Mutex<u16>>,
}

impl Mock {
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn answer(&self, status: u16) {
        *self.status.lock().unwrap() = status;
    }
}

async fn start_mock() -> (String, Mock) {
    let mock = Mock { seen: Arc::default(), status: Arc::new(Mutex::new(201)) };
    let m = mock.clone();
    let app = axum::Router::new().fallback(move |uri: Uri, headers: HeaderMap, body: Bytes| {
        let m = m.clone();
        async move {
            let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
            m.seen.lock().unwrap().push(Seen { path: uri.path().to_string(), auth, body });
            let status = *m.status.lock().unwrap();
            let reply = if status == 201 {
                json!({ "id": 1001, "html_url": "https://github.example/acme/widgets/issues/42#issuecomment-1001" })
            } else {
                json!({ "message": "Not Found" })
            };
            (StatusCode::from_u16(status).unwrap(), axum::Json(reply))
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://127.0.0.1:{port}"), mock)
}

// --- hub helpers ---------------------------------------------------------------------------

fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

fn human() -> Caller {
    Caller { enforce_profile: false, ..caller("operator", ActorKind::Human, Profile::Operator) }
}

/// An agent on a profile that sees the relay.
fn agent() -> Caller {
    caller("relay-agent", ActorKind::Agent, Profile::ChiefOfStaff)
}

fn other_agent() -> Caller {
    caller("other-agent", ActorKind::Agent, Profile::ChiefOfStaff)
}

fn reason(e: &UaError) -> String {
    match e {
        UaError::ApprovalRequired { .. } => "approval_required".into(),
        e => e.reason_code().map(str::to_string).unwrap_or_else(|| e.code().to_string()),
    }
}

struct H {
    hub: Hub,
    reg: Registry,
    mock: Mock,
}

impl H {
    async fn new() -> Self {
        Self::with(|_| {}).await
    }

    /// A hub whose relay posts to the mock, with the token stored.
    async fn with(f: impl FnOnce(&mut Config)) -> Self {
        let (url, mock) = start_mock().await;
        let mut cfg = Config::for_home(std::env::temp_dir());
        cfg.human_identities = vec!["operator".into()];
        cfg.managed_secret_key = Some(KEY.to_string().into());
        cfg.relay_github_repos = vec!["acme/widgets".into(), "Acme/Docs".into()];
        cfg.relay_github_secret = Some("relay-gh".into());
        cfg.relay_github_api_url = url;
        cfg.fetch_allow_loopback = true;
        cfg.relay_internal_hosts = vec!["atlas".into()];
        cfg.relay_denylist = vec![SecretString::from("project[- ]falcon")];
        cfg.relay_max_chars = 500;
        cfg.relay_checks_per_hour = 1000;
        f(&mut cfg);
        let h = Self { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), mock };
        h.ok(
            &human(),
            "managed_secret_set",
            json!({ "name": "relay-gh", "consumer": "relay:github", "value": TOKEN }),
        )
        .await;
        h
    }

    async fn call(&self, who: &Caller, action: &str, params: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, who, "relay_manage", json!({ "action": action, "params": params })).await
    }

    async fn ok(&self, who: &Caller, tool: &str, args: Value) -> Value {
        self.reg
            .call(&self.hub, who, tool, args.clone())
            .await
            .unwrap_or_else(|e| panic!("{tool}({args}) failed: {e:?}"))
    }

    async fn relay(&self, who: &Caller, action: &str, params: Value) -> Value {
        self.call(who, action, params.clone())
            .await
            .unwrap_or_else(|e| panic!("{action}({params}) failed: {e:?}"))
    }

    async fn refused(&self, who: &Caller, action: &str, params: Value) -> UaError {
        match self.call(who, action, params.clone()).await {
            Ok(v) => panic!("{action}({params}) should fail, got {v}"),
            Err(e) => e,
        }
    }

    async fn gate(&self, text: &str) -> Value {
        self.relay(&agent(), "check", json!({ "target": TARGET, "text": text })).await
    }

    async fn approve(&self, approval_id: i64) {
        self.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" })).await;
    }

    /// Draft `text` and request approval; returns (draft_id, approval_id).
    async fn requested(&self, text: &str) -> (i64, i64) {
        let d = self.relay(&agent(), "draft", json!({ "target": TARGET, "text": text })).await;
        assert_eq!(d["status"], "draft", "{d}");
        let id = d["draft_id"].as_i64().unwrap();
        let r = self.relay(&agent(), "request_send", json!({ "draft_id": id })).await;
        assert_eq!(r["status"], "pending_approval");
        (id, r["approval_id"].as_i64().unwrap())
    }

    fn ledger(&self) -> String {
        self.hub
            .db()
            .read(|c| {
                let mut stmt = c.prepare("SELECT channel || ' ' || payload FROM event_log ORDER BY seq")?;
                let rows: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
                Ok(rows.join("\n"))
            })
            .unwrap()
    }

    fn events(&self, channel: &str) -> Vec<Value> {
        let channel = channel.to_string();
        self.hub
            .db()
            .read(move |c| {
                let mut stmt = c.prepare("SELECT payload FROM event_log WHERE channel = ?1 ORDER BY seq")?;
                let rows: Vec<String> = stmt.query_map([channel], |r| r.get(0))?.collect::<Result<_, _>>()?;
                Ok(rows.iter().map(|s| serde_json::from_str(s).unwrap()).collect())
            })
            .unwrap()
    }
}

fn categories(v: &Value) -> Vec<String> {
    v["categories"].as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default()
}

/// Asserts the gate result for `text` has exactly the `expected` categories.
async fn expect(h: &H, text: &str, expected: &[&str]) {
    let v = h.gate(text).await;
    let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(categories(&v), want, "gates on {text:?}: {v}");
    assert_eq!(v["verdict"], if expected.is_empty() { "pass" } else { "block" });
}

fn home(root: &str, user: &str) -> String {
    format!("/{root}/{user}/src/app.rs")
}

// --- gates -------------------------------------------------------------------------------------

#[tokio::test]
async fn secret_gate_refuses_credentials_and_lets_placeholders_through() {
    let h = H::new().await;
    let gh = format!("ghp_{}", "a1B2".repeat(10));
    expect(&h, &format!("try the token {gh} again"), &["secret"]).await;
    expect(&h, "aws key AKIAIOSFODNN7ABCDEFG leaked", &["secret"]).await;
    expect(&h, "set DEPLOY_TOKEN=s3cr3tvalue99 in CI", &["secret"]).await;
    expect(&h, "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", &["secret"]).await;
    expect(&h, "-----BEGIN OPENSSH PRIVATE KEY-----", &["private_key"]).await;
    // A zero-width space inside the token neither hides it nor goes unnoticed.
    let split = format!("ghp_{}\u{200B}{}", "a1B2".repeat(5), "a1B2".repeat(5));
    expect(&h, &split, &["hidden_unicode", "secret"]).await;
    // Refused, not redacted: the excerpt is masked and nothing is rewritten.
    let v = h.gate(&format!("token {gh}")).await;
    assert!(!v.to_string().contains(&gh), "{v}");
    assert!(v.get("text").is_none(), "the gates never return rewritten text");

    expect(&h, "export GITHUB_TOKEN=${GITHUB_TOKEN} before running", &[]).await;
    expect(&h, "set `DEPLOY_TOKEN=<your-token>` in CI", &[]).await;
    // Outside code GitHub would take `<your-token>` for an HTML tag and drop it.
    expect(&h, "set DEPLOY_TOKEN=<your-token> in CI", &["markup"]).await;
    expect(&h, "`Authorization: Bearer <token>`", &[]).await;
    expect(&h, "-----BEGIN PUBLIC KEY-----", &[]).await;
    expect(&h, CLEAN, &[]).await;
}

#[tokio::test]
async fn hidden_unicode_gate_refuses_invisible_and_bidi_characters() {
    let h = H::new().await;
    for c in [
        '\u{202E}',
        '\u{2066}',
        '\u{200D}',
        '\u{FEFF}',
        '\u{00AD}',
        '\u{E0041}',
        '\u{FE0F}',
        '\u{1B}',
        '\u{2028}',
        // Invisible or blank characters outside the format category.
        '\u{034F}',
        '\u{180B}',
        '\u{180F}',
        '\u{2800}',
        '\u{2000}',
        '\u{200A}',
        '\u{00A0}',
        '\u{3164}',
        // Private use, unassigned, noncharacter.
        '\u{E000}',
        '\u{FFF0}',
        '\u{FDD0}',
    ] {
        let v = h.gate(&format!("looks fine{c} here")).await;
        assert_eq!(categories(&v), vec!["hidden_unicode"], "U+{:04X}: {v}", c as u32);
        assert_eq!(v["findings"][0]["excerpt"], format!("U+{:04X}", c as u32));
        assert_eq!(v["findings"][0]["offset"], 10);
    }
    expect(&h, "line one\nline two\twith a tab, café, 日本語 and 🚀", &[]).await;
    expect(&h, "windows line\r\nendings", &[]).await;
}

#[tokio::test]
async fn address_gate_refuses_private_loopback_and_shared_ranges() {
    let h = H::new().await;
    let shared = format!("100.{}.3.4", 64 + 37);
    for addr in [
        "10.1.2.3",
        "172.16.5.4",
        "192.168.0.10",
        "127.0.0.1",
        "169.254.169.254",
        shared.as_str(),
        "fd12:3456::1",
        "::1",
        "fe80::1",
        "::ffff:10.0.0.1",
    ] {
        expect(&h, &format!("the service at {addr} answered"), &["private_address"]).await;
    }
    for text in [
        "resolve 8.8.8.8 first",
        "docs use 192.0.2.10 and 2001:db8::1",
        "released 1.2.3.4 today",
        "at 12:30:45 the std::io::Error appeared",
        "build 10.1.2.3.4 is out",
        "100.20.3.4 is public",
    ] {
        expect(&h, text, &[]).await;
    }
}

#[tokio::test]
async fn host_gate_refuses_internal_names() {
    let h = H::new().await;
    let magic = format!("box.tail1234.{}{}", "ts", ".net");
    for text in [
        "ssh to db.internal",
        "printer.local is down",
        "see wiki.corp for details",
        magic.as_str(),
        "open http://buildbox:8080/status",
        "deploy to Atlas now",
    ] {
        expect(&h, text, &["internal_host"]).await;
    }
    for text in [
        "see github.com/acme/widgets",
        "run it on http://localhost:3000/",
        "self.internal_state is private",
        "atlases are big",
        "the .local suffix is reserved",
    ] {
        expect(&h, text, &[]).await;
    }
}

#[tokio::test]
async fn home_path_gate_refuses_account_paths() {
    let h = H::new().await;
    for path in
        [home("home", "alice"), home("Users", "bob"), home("var/home", "dana"), "C:\\Users\\carol\\x".into()]
    {
        expect(&h, &format!("the file at {path} fails"), &["home_path"]).await;
    }
    for path in
        [home("home", "runner"), home("home", "user"), "~/projects/app.rs".into(), "/data/home2/x".into()]
    {
        expect(&h, &format!("the file at {path} fails"), &[]).await;
    }
}

#[tokio::test]
async fn pii_gate_refuses_emails_phones_ids_and_cards() {
    let h = H::new().await;
    expect(&h, "write to jane.doe@mailhost.org", &["email"]).await;
    expect(&h, "call (415) 555-0132 or 415-555-0199", &["phone"]).await;
    expect(&h, "or +14155550132", &["phone"]).await;
    expect(&h, "ssn 123-45-6789", &["national_id"]).await;
    expect(&h, "card 4111 1111 1111 1111 expired", &["payment_card"]).await;
    for text in [
        "mail dev@example.com",
        "clone git@github.com:acme/widgets.git",
        "co-author 123+bot@users.noreply.github.com",
        "pin react@18.3.1",
        "released on 2024-11-20",
        "ts 1700000000000",
        "card 4111 1111 1111 1112 is invalid",
        "id 12-345-6789",
    ] {
        expect(&h, text, &[]).await;
    }
}

#[tokio::test]
async fn length_gate_bounds_the_text() {
    let h = H::new().await;
    expect(&h, &"a".repeat(500), &[]).await;
    let v = h.gate(&"a".repeat(501)).await;
    assert_eq!(categories(&v), vec!["length"], "{v}");
    let empty = h.refused(&agent(), "check", json!({ "target": TARGET, "text": "  \n " })).await;
    assert_eq!(reason(&empty), "invalid_argument");
}

#[tokio::test]
async fn denylist_matches_are_never_echoed() {
    let h = H::new().await;
    let v = h.gate("an update on Project Falcon").await;
    assert_eq!(categories(&v), vec!["denylist"], "{v}");
    let f = &v["findings"][0];
    assert!(f.get("excerpt").is_none() && f.get("offset").is_none(), "{f}");
    // Another finding overlapping a denylisted term loses its excerpt too.
    let v = h.gate("mail project-falcon@mailhost.org").await;
    assert_eq!(categories(&v), vec!["denylist", "email"], "{v}");
    let low = v.to_string().to_lowercase();
    assert!(!low.contains("falcon") && !low.contains("pr…"), "{v}");
    // A blocked draft's ledger entry carries counts only.
    let d = h.relay(&agent(), "draft", json!({ "target": TARGET, "text": "Project Falcon ships" })).await;
    assert_eq!(d["status"], "blocked");
    assert!(
        !h.ledger().to_lowercase().contains("falcon"),
        "the ledger must not hold the term or the pattern"
    );
    expect(&h, "a falcon flew by", &[]).await;
}

#[tokio::test]
async fn a_denylist_entry_that_does_not_compile_fails_closed() {
    let h = H::with(|c| c.relay_denylist = vec![SecretString::from("secret-codename(")]).await;
    let e = h.refused(&agent(), "check", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "relay_denylist_invalid");
    assert!(!e.to_string().contains("codename"), "{e}");
}

// --- lifecycle and approval binding ---------------------------------------------------------------

#[tokio::test]
async fn approved_text_is_sent_exactly_once() {
    let h = H::new().await;
    let (id, approval_id) = h.requested(CLEAN).await;

    // The human sees the exact text and destination in the approval queue.
    let queue = h.ok(&human(), "approval_pending", json!({ "tool": "relay_manage" })).await;
    let pending = &queue["pending"][0];
    assert_eq!(pending["id"], approval_id);
    assert_eq!(pending["payload"]["text"], CLEAN);
    assert_eq!(pending["payload"]["target"], TARGET);

    let early = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&early), "approval_required");
    assert!(h.mock.requests().is_empty());

    h.approve(approval_id).await;
    // Decided: the approval keeps the hash and sizes, not the text.
    let decided = h.ok(&human(), "approval_pending", json!({ "tool": "relay_manage" })).await;
    let pass = &decided["approved_unconsumed"][0]["payload"];
    assert_eq!((pass["text"].clone(), pass["text_escaped"].clone()), (Value::Null, Value::Null), "{pass}");
    assert_eq!(pass["text_sha256"], hex_sha(CLEAN));
    let sent = h.relay(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(sent["status"], "sent", "{sent}");
    assert_eq!(sent["receipt"]["comment_id"], 1001);
    assert_eq!(sent["approval_id"], approval_id);

    let reqs = h.mock.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].path, "/repos/acme/widgets/issues/42/comments");
    assert_eq!(reqs[0].auth, format!("Bearer {TOKEN}"));
    assert_eq!(reqs[0].body, json!({ "body": CLEAN }), "the body is the approved text, byte for byte");

    let again = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&again), "conflict");
    assert_eq!(h.mock.requests().len(), 1, "never sent twice");

    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!(st["status"], "sent");
    assert_eq!(st["approval_status"], "consumed");
    assert_eq!(st["resolved_by"], "operator");

    let ledger = h.ledger();
    assert!(!ledger.contains(TOKEN), "the token never reaches the ledger");
    assert!(!ledger.contains("next release"), "the text never reaches the ledger");
    let sent_ev = &h.events("relay.sent")[0];
    assert_eq!(sent_ev["target"], TARGET);
    assert_eq!(sent_ev["chars"], CLEAN.chars().count());
    assert_eq!(sent_ev["comment_id"], 1001);
    assert_eq!(h.events("relay.drafted")[0]["verdict"], "pass");
}

#[tokio::test]
async fn changing_one_character_after_approval_is_refused() {
    let h = H::new().await;
    let (id, approval_id) = h.requested(CLEAN).await;
    h.approve(approval_id).await;

    let altered = CLEAN.replacen("next", "Next", 1);
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": altered })).await;
    assert_eq!(reason(&e), "text_mismatch");
    let e = h
        .refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN, "target": "acme/widgets#43" }))
        .await;
    assert_eq!(reason(&e), "target_mismatch");
    assert!(h.mock.requests().is_empty());

    // The stored draft changed behind the hub's back (one character, hash
    // kept consistent): the approval no longer binds it.
    let tampered = CLEAN.replacen('.', "!", 1);
    let (t, sha) = (tampered.clone(), hex_sha(&tampered));
    h.hub
        .db()
        .write(move |tx| {
            tx.execute(
                "UPDATE relay_messages SET text = ?2, text_sha256 = ?3 WHERE id = ?1",
                (id, &t, &sha),
            )?;
            Ok(())
        })
        .unwrap();
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": tampered })).await;
    assert_eq!(reason(&e), "approval_mismatch");
    // Text changed without the hash: refused as well.
    h.hub
        .db()
        .write(move |tx| {
            tx.execute(
                "UPDATE relay_messages SET text = ?2 WHERE id = ?1",
                (id, CLEAN.replacen('T', "t", 1)),
            )?;
            Ok(())
        })
        .unwrap();
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN.replacen('T', "t", 1) })).await;
    assert_eq!(reason(&e), "approval_mismatch");
    assert!(h.mock.requests().is_empty(), "nothing was sent");
    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!(st["approval_status"], "approved", "the pass was not spent");
}

fn hex_sha(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s.as_bytes()))
}

#[tokio::test]
async fn blocked_drafts_keep_no_text_and_cannot_be_sent() {
    let h = H::new().await;
    let email = "reach me at jane.doe@mailhost.org";
    let d = h.relay(&agent(), "draft", json!({ "target": TARGET, "text": email })).await;
    assert_eq!(d["status"], "blocked");
    assert_eq!(d["findings"][0]["category"], "email");
    let id = d["draft_id"].as_i64().unwrap();
    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!(st["text"], Value::Null, "a blocked draft is stored without its text");
    assert!(!h.ledger().contains("jane.doe"));
    assert_eq!(h.events("relay.drafted")[0]["categories"], json!({ "email": 1 }));
    let e = h.refused(&agent(), "request_send", json!({ "draft_id": id })).await;
    assert_eq!(reason(&e), "conflict");
}

#[tokio::test]
async fn allowlist_and_credential_are_checked_before_a_human_is_asked() {
    let h = H::new().await;
    let e = h.refused(&agent(), "draft", json!({ "target": "elsewhere/repo#1", "text": CLEAN })).await;
    assert_eq!(reason(&e), "relay_target_not_allowed");
    let e = h.refused(&agent(), "draft", json!({ "target": "acme/widgets", "text": CLEAN })).await;
    assert_eq!(reason(&e), "invalid_argument");
    let e =
        h.refused(&agent(), "draft", json!({ "channel": "zulip", "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "invalid_argument");
    // The allowlist is case-insensitive.
    let ok = h.relay(&agent(), "check", json!({ "target": "acme/docs#7", "text": CLEAN })).await;
    assert_eq!(ok["target"], "acme/docs#7");

    let h = H::with(|c| c.relay_github_secret = Some("not-stored".into())).await;
    let d = h.relay(&agent(), "draft", json!({ "target": TARGET, "text": CLEAN })).await;
    let e = h.refused(&agent(), "request_send", json!({ "draft_id": d["draft_id"] })).await;
    assert_eq!(reason(&e), "relay_unavailable");
    let queue = h.ok(&human(), "approval_pending", json!({ "tool": "relay_manage" })).await;
    assert_eq!(queue["pending"], json!([]), "no human was asked");
}

#[tokio::test]
async fn failures_are_recorded_and_an_uncertain_send_is_not_repeated() {
    let h = H::new().await;
    h.mock.answer(404);
    let (id, a) = h.requested(CLEAN).await;
    h.approve(a).await;
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&e), "invalid_argument", "{e}");
    let msg = e.to_string();
    assert!(msg.contains("rejected by GitHub or never reached it (HTTP 404)"), "{msg}");
    assert!(!msg.contains("before reaching GitHub"), "{msg}");
    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!(st["status"], "failed");
    assert_eq!(h.events("relay.send_failed")[0]["http_status"], 404);

    h.mock.answer(502);
    let (id2, a2) = h.requested(CLEAN).await;
    h.approve(a2).await;
    let e = h.refused(&agent(), "send", json!({ "draft_id": id2, "text": CLEAN })).await;
    assert_eq!(reason(&e), "relay_uncertain");
    assert_eq!(h.relay(&agent(), "status", json!({ "draft_id": id2 })).await["status"], "uncertain");

    // The same text to the same target while an earlier attempt has no
    // known outcome: refused before the pass is spent.
    h.mock.answer(201);
    let (id3, a3) = h.requested(CLEAN).await;
    h.approve(a3).await;
    let e = h.refused(&agent(), "send", json!({ "draft_id": id3, "text": CLEAN })).await;
    assert_eq!(reason(&e), "relay_duplicate");
    assert_eq!(h.mock.requests().len(), 2);
    assert_eq!(h.relay(&agent(), "status", json!({ "draft_id": id3 })).await["approval_status"], "approved");

    // Only a human who checked the thread records the uncertain outcome.
    let e = h.refused(&agent(), "resolve", json!({ "draft_id": id2, "outcome": "not_delivered" })).await;
    assert_eq!(reason(&e), "not_human");
    let e = h.refused(&human(), "resolve", json!({ "draft_id": id, "outcome": "delivered" })).await;
    assert_eq!(reason(&e), "conflict", "a definite failure has its outcome already");
    let r = h.relay(&human(), "resolve", json!({ "draft_id": id2, "outcome": "not_delivered" })).await;
    assert_eq!((r["status"].as_str(), r["reposted"].as_bool()), (Some("failed"), Some(false)));
    assert_eq!(h.mock.requests().len(), 2, "resolving never posts");
    assert_eq!(h.events("relay.resolved")[0]["outcome"], "not_delivered");
    let sent = h.relay(&agent(), "send", json!({ "draft_id": id3, "text": CLEAN })).await;
    assert_eq!(sent["status"], "sent");
    assert_eq!(h.mock.requests().len(), 3);
}

#[tokio::test]
async fn ownership_cancel_and_profiles() {
    let h = H::new().await;
    let (id, approval_id) = h.requested(CLEAN).await;

    let e = h.refused(&other_agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&e), "not_requester");
    let e = h.refused(&other_agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!(reason(&e), "not_found");
    let theirs = h.relay(&other_agent(), "list", json!({})).await;
    assert_eq!(theirs["count"], 0);
    let all = h.relay(&human(), "list", json!({ "status": "pending_approval" })).await;
    assert_eq!(all["count"], 1);
    assert!(all["drafts"][0].get("text").is_none(), "lists never carry text");

    let c = h.relay(&agent(), "cancel", json!({ "draft_id": id, "reason": "superseded" })).await;
    assert_eq!(c["approval_status"], "denied");
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&e), "conflict");
    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!((st["status"].as_str(), st["text"].as_str()), (Some("cancelled"), None), "{st}");
    assert_eq!(h.events("relay.cancelled")[0]["approval_id"], approval_id);
}

#[tokio::test]
async fn withdrawn_approvals_cannot_be_resolved_and_developers_do_not_see_the_relay() {
    let h = H::new().await;
    let (id, approval_id) = h.requested(CLEAN).await;
    h.relay(&agent(), "cancel", json!({ "draft_id": id })).await;
    let e = h
        .reg
        .call(&h.hub, &human(), "approval_resolve", json!({ "id": approval_id, "decision": "approve" }))
        .await
        .unwrap_err();
    assert_eq!(reason(&e), "conflict");

    let dev = caller("builder-1", ActorKind::Agent, Profile::Developer);
    let e = h.refused(&dev, "check", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "profile_denied");
    // The reviewer profile (steward) does not speak publicly either.
    let reviewer = caller("reviewer-1", ActorKind::Agent, Profile::Steward);
    let e = h.refused(&reviewer, "draft", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "profile_denied");
    let anon = Caller { enforce_profile: false, ..caller("anon", ActorKind::Anonymous, Profile::Public) };
    let e = h.refused(&anon, "draft", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "identity_required");
}

#[tokio::test]
async fn a_token_swapped_after_approval_does_not_post() {
    let h = H::with(|c| c.human_identities.push("operator-2".into())).await;
    let (id, approval_id) = h.requested(CLEAN).await;
    h.approve(approval_id).await;
    // Another human replaces the relay's token; a replacement needs its own
    // approval, given here by the first human.
    let second = caller("operator-2", ActorKind::Human, Profile::Operator);
    let args = json!({ "name": "relay-gh", "consumer": "relay:github", "value": "ghp_other_account_token_value_0000000000" });
    match h.reg.call(&h.hub, &second, "managed_secret_set", args.clone()).await {
        Err(UaError::ApprovalRequired { approval_id, .. }) => {
            h.approve(approval_id).await;
            h.ok(&second, "managed_secret_set", args).await;
        }
        Ok(_) => {}
        Err(e) => panic!("replacing the token failed: {e:?}"),
    }
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&e), "approval_mismatch", "{e:?}");
    assert!(h.mock.requests().is_empty(), "nothing was posted under the new token");
}

// --- review fixes ---------------------------------------------------------------------------------

fn approval_payload(h: &H, approval_id: i64) -> Value {
    h.hub
        .db()
        .read(move |c| {
            let p: String =
                c.query_row("SELECT payload FROM approvals WHERE id = ?1", [approval_id], |r| r.get(0))?;
            Ok(serde_json::from_str(&p).unwrap())
        })
        .unwrap()
}

fn gh_token() -> String {
    format!("ghp_{}", "a1B2".repeat(10))
}

#[tokio::test]
async fn the_approver_sees_an_escaped_view_and_every_link_host() {
    let h = H::new().await;
    let text = "Café fix: see [the notes](https://docs.rs/serde) and https://github.com/acme/widgets";
    let (_, approval_id) = h.requested(text).await;
    let queue = h.ok(&human(), "approval_pending", json!({ "tool": "relay_manage" })).await;
    let payload = &queue["pending"][0]["payload"];
    assert_eq!(queue["pending"][0]["id"], approval_id);
    assert_eq!(payload["text"], text);
    let escaped = payload["text_escaped"].as_str().unwrap();
    assert!(escaped.starts_with("Caf\\u{E9} fix"), "{escaped}");
    assert!(escaped.is_ascii());
    assert_eq!(payload["link_hosts"], json!(["docs.rs", "github.com"]));
}

#[tokio::test]
async fn markup_and_entities_cannot_smuggle_secrets_or_personal_data() {
    let h = H::new().await;
    let gh = gh_token();
    let entity_token = format!("try &#103;&#104;&#112;{} again", &gh[3..]);
    expect(&h, &entity_token, &["markup", "secret"]).await;
    let tagged = format!("try {}<b></b>{} again", &gh[..20], &gh[20..]);
    expect(&h, &tagged, &["markup", "secret"]).await;
    let commented = format!("try {}<!-- -->{} again", &gh[..20], &gh[20..]);
    expect(&h, &commented, &["markup", "secret"]).await;
    expect(&h, "the host 10&#46;0&#46;0&#46;1 answered", &["markup", "private_address"]).await;
    expect(&h, "write to jane.doe&#64;mailhost.org", &["markup", "email"]).await;
    expect(&h, "news on Project &#70;alcon", &["denylist", "markup"]).await;
    expect(&h, "news on Proj<i></i>ect Falcon", &["denylist", "markup"]).await;
    expect(&h, "news on Prоject Fаlcon", &["denylist"]).await; // Cyrillic о and а
    expect(&h, "a hidden <!-- note --> comment", &["markup"]).await;
    expect(&h, "returns Vec<String> now", &["markup"]).await;
    expect(&h, "a &amp; b", &["markup"]).await;
    // Code is shown literally, so markup inside it is fine.
    expect(&h, "returns `Vec<String>` now", &[]).await;
    expect(&h, "```\n<div>&amp;</div>\n```", &[]).await;
    expect(&h, "R&D and Q&A, 1 < 2 > 0", &[]).await;

    // A link must open what its text shows.
    expect(&h, "see [https://github.com/acme/widgets](https://evil.example/x)", &["link"]).await;
    expect(&h, "see [github.com/acme/widgets](https://github.com/other/thing)", &["link"]).await;
    expect(&h, "see [the docs](https://docs.rs/serde) or [docs.rs](https://docs.rs/serde)", &[]).await;
    expect(&h, "see https://github.com/acme/widgets and www.example.com", &[]).await;
}

#[tokio::test]
async fn mentions_and_cross_references_are_refused_unless_allowed() {
    let h = H::new().await;
    expect(&h, "thanks @octocat for the report", &["mention"]).await;
    expect(&h, "ping @acme/maintainers", &["mention"]).await;
    expect(&h, "see other/repo#12", &["cross_reference"]).await;
    expect(&h, "see https://github.com/other/repo/issues/3", &["cross_reference"]).await;
    expect(&h, "see [this](https://github.com/other/repo/pull/3)", &["cross_reference"]).await;
    for text in [
        "fixed in acme/widgets#12 and #13",
        "see https://github.com/acme/docs/pull/3",
        "`@octocat` in code is not a mention",
        "mail dev@example.com, pin react@18.3.1",
    ] {
        expect(&h, text, &[]).await;
    }
    let h = H::with(|c| c.relay_mention_allowlist = vec!["Octocat".into(), "@acme/maintainers".into()]).await;
    expect(&h, "thanks @octocat, cc @acme/maintainers", &[]).await;
    expect(&h, "thanks @someone-else", &["mention"]).await;
}

#[tokio::test]
async fn secret_shapes_in_any_case_encoding_or_layout() {
    use base64::Engine;
    let h = H::new().await;
    let gh = gh_token();
    expect(&h, "set api_token = 'abc123def456' first", &["secret"]).await;
    expect(&h, r#"config {"token": "abc123def456ghi"}"#, &["secret"]).await;
    expect(&h, "password: hunter22", &["secret"]).await;
    expect(&h, &format!("the token is {}\n{} now", &gh[..22], &gh[22..]), &["secret"]).await;
    let b64 = base64::engine::general_purpose::STANDARD.encode(format!("token={gh}"));
    expect(&h, &format!("blob {b64} here"), &["secret"]).await;
    let pct = format!("q=%67hp%5F{}", &gh[4..]);
    expect(&h, &format!("url ?{pct} here"), &["secret"]).await;
    for text in [
        "the token: required",
        "pass `a token = <your-token>`",
        r#"set relay_github_secret = "relay-github""#,
        "the password field is optional",
    ] {
        expect(&h, text, &[]).await;
    }
}

#[tokio::test]
async fn short_form_addresses_and_redirectors_are_refused() {
    let h = H::new().await;
    for text in [
        "open http://10.1/ now",
        "ping 127.1 now",
        "ping 0177.0.0.1 now",
        "open http://0x7f.1:8080/x now",
        "open http://2130706433/ now",
        "listen on 10.1:8080 now",
        "open http://[::ffff:7f00:1]/ now",
    ] {
        expect(&h, text, &["private_address"]).await;
    }
    for text in ["version 10.0.1 is out", "the value 0xdeadbeef", "upgrade to 1.2.3", "at 10:30 today"] {
        expect(&h, text, &[]).await;
    }
    expect(&h, "see https://bit.ly/abc123", &["redirector"]).await;
    expect(&h, "see tinyurl.com/abc123", &["redirector"]).await;
    let h = H::with(|c| c.relay_redirector_hosts = vec!["go.example.org".into()]).await;
    expect(&h, "see https://bit.ly/abc123", &[]).await;
    expect(&h, "see https://go.example.org/x", &["redirector"]).await;
}

#[tokio::test]
async fn check_needs_an_identity_is_recorded_without_text_and_is_throttled() {
    let h = H::with(|c| c.relay_checks_per_hour = 3).await;
    let anon = Caller { enforce_profile: false, ..caller("anon", ActorKind::Anonymous, Profile::Public) };
    let e = h.refused(&anon, "check", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "identity_required");

    // A denylist hit leaves no offset or excerpt on any finding.
    let v = h.gate("mail jane.doe@mailhost.org about project falcon").await;
    assert_eq!(categories(&v), vec!["denylist", "email"], "{v}");
    for f in v["findings"].as_array().unwrap() {
        assert!(f.get("offset").is_none() && f.get("excerpt").is_none(), "{f}");
    }
    let ev = &h.events("relay.check")[0];
    assert_eq!(ev["verdict"], "block");
    assert_eq!(ev["categories"], json!({ "denylist": 1, "email": 1 }));
    assert!(ev.get("text").is_none() && ev.get("text_sha256").is_none(), "{ev}");
    let ledger = h.ledger().to_lowercase();
    assert!(!ledger.contains("falcon") && !ledger.contains("jane.doe"), "{ledger}");

    h.gate(CLEAN).await;
    h.relay(&agent(), "draft", json!({ "target": TARGET, "text": CLEAN })).await;
    let e = h.refused(&agent(), "check", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "rate_limited");
    let e = h.refused(&agent(), "draft", json!({ "target": TARGET, "text": CLEAN })).await;
    assert_eq!(reason(&e), "rate_limited");
    assert_eq!(h.events("relay.check").len(), 2, "a refused run is not recorded");
    // The budget is per caller.
    h.relay(&other_agent(), "check", json!({ "target": TARGET, "text": CLEAN })).await;
}

#[tokio::test]
async fn a_denied_approval_drops_the_text_everywhere() {
    let h = H::new().await;
    let (id, approval_id) = h.requested(CLEAN).await;
    assert_eq!(approval_payload(&h, approval_id)["text"], CLEAN, "kept while pending");
    h.ok(&human(), "approval_resolve", json!({ "id": approval_id, "decision": "deny", "reason": "no" }))
        .await;
    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!((st["status"].as_str(), st["text"].as_str()), (Some("cancelled"), None), "{st}");
    let p = approval_payload(&h, approval_id);
    assert_eq!((p["text"].clone(), p["text_escaped"].clone()), (Value::Null, Value::Null), "{p}");
    assert_eq!(p["text_sha256"], hex_sha(CLEAN));
    assert_eq!(p["chars"], CLEAN.chars().count());
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&e), "conflict");
    assert!(h.mock.requests().is_empty());

    // A denial recorded behind the relay's back is caught at send time.
    let (id, approval_id) = h.requested(CLEAN).await;
    h.hub
        .db()
        .write(move |tx| {
            tx.execute("UPDATE approvals SET status = 'denied' WHERE id = ?1", [approval_id])?;
            Ok(())
        })
        .unwrap();
    let e = h.refused(&agent(), "send", json!({ "draft_id": id, "text": CLEAN })).await;
    assert_eq!(reason(&e), "approval_denied");
    let st = h.relay(&agent(), "status", json!({ "draft_id": id })).await;
    assert_eq!((st["status"].as_str(), st["text"].as_str()), (Some("cancelled"), None), "{st}");
    assert_eq!(approval_payload(&h, approval_id)["text"], Value::Null);

    // Cancelling drops it from the approval as well as the draft.
    let (id, approval_id) = h.requested(CLEAN).await;
    h.relay(&agent(), "cancel", json!({ "draft_id": id })).await;
    assert_eq!(approval_payload(&h, approval_id)["text"], Value::Null);
    assert!(h.mock.requests().is_empty());
}
