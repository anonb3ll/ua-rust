//! Slack signature checks and the coordination command parser.
//!
//! No HTTP server is started. Replay is the seen-signature table, not a route.

use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
use ua_store::ledger::{self, EventQuery};
use ua_tools::families::slack::{self, SignatureError};
use ua_tools::{Hub, Registry, builtin_registry};

const SECRET: &str = "signing";

fn caller() -> Caller {
    Caller {
        label: "builder-1".into(),
        kind: ActorKind::Agent,
        profile: Profile::Developer,
        enforce_profile: true,
        session_key: Some("s1".into()),
        transport: Transport::Mcp,
    }
}

struct Env {
    hub: Hub,
    reg: Registry,
    _home: tempfile::TempDir,
}

fn env() -> Env {
    let home = tempfile::tempdir().unwrap();
    let cfg = Config::for_home(home.path());
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

impl Env {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, &caller(), tool, args).await
    }

    async fn remember(&self, ts: &str, body: &str, now: i64) -> Result<(), UaError> {
        let (ts, body) = (ts.to_string(), body.as_bytes().to_vec());
        self.hub.db().write_async(move |tx| slack::remember_signed_request(tx, &ts, &body, now)).await
    }

    async fn seen_rows(&self) -> i64 {
        self.hub
            .db()
            .read_async(|c| Ok(c.query_row("SELECT COUNT(*) FROM slack_seen_signatures", [], |r| r.get(0))?))
            .await
            .unwrap()
    }
}

// --- signatures ------------------------------------------------------------------

/// Slack's published example ("Verifying requests from Slack"), copied
/// verbatim. The expected signature was not produced by this crate.
#[test]
fn signature_matches_slacks_published_example() {
    let secret = "8f742231b10e8888abcd99yyyzzz85a5";
    let ts = "1531420618";
    let body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
    let expected = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    assert_eq!(slack::verify_slack_signature(secret, ts, body.as_bytes(), expected, 1_531_420_618), Ok(()));
    assert_eq!(slack::slack_signature(secret, ts, body.as_bytes()), expected);
    let mut tampered = body.as_bytes().to_vec();
    tampered.push(b'x');
    assert_eq!(
        slack::verify_slack_signature(secret, ts, &tampered, expected, 1_531_420_618),
        Err(SignatureError::BadSignature)
    );
}

#[test]
fn skew_of_300_seconds_passes_and_301_is_stale() {
    let body = br#"{"type":"event_callback"}"#;
    let ts = "1700000000";
    let base = 1_700_000_000;
    let sig = slack::slack_signature(SECRET, ts, body);
    for now in [base - 300, base, base + 300] {
        assert_eq!(slack::verify_slack_signature(SECRET, ts, body, &sig, now), Ok(()), "now={now}");
    }
    for now in [base - 301, base + 301] {
        assert_eq!(
            slack::verify_slack_signature(SECRET, ts, body, &sig, now),
            Err(SignatureError::Stale),
            "now={now}"
        );
    }
}

#[test]
fn malformed_timestamps_and_signatures_are_refused() {
    let body = br#"{"type":"event_callback"}"#;
    let now = 1_700_000_000;
    let ts = "1700000000";
    let sig = slack::slack_signature(SECRET, ts, body);
    let bad = |secret: &str, ts: &str, body: &[u8], sig: &str| {
        assert_eq!(
            slack::verify_slack_signature(secret, ts, body, sig, now),
            Err(SignatureError::BadSignature),
            "ts={ts} sig={sig}"
        );
    };
    // Timestamps: negative, 20 digits, empty, signed, padded.
    let neg = slack::slack_signature(SECRET, "-1", body);
    bad(SECRET, "-1", body, &neg);
    let long = "12345678901234567890";
    bad(SECRET, long, body, &slack::slack_signature(SECRET, long, body));
    bad(SECRET, "", body, &sig);
    bad(SECRET, "+1700000000", body, &slack::slack_signature(SECRET, "+1700000000", body));
    bad(SECRET, " 1700000000", body, &sig);
    // Signatures: another scheme version, uppercase hex, short, empty.
    bad(SECRET, ts, body, &sig.replacen("v0=", "v1=", 1));
    let upper = format!("v0={}", sig[3..].to_ascii_uppercase());
    assert_ne!(upper, sig);
    bad(SECRET, ts, body, &upper);
    bad(SECRET, ts, body, "v0=00");
    bad(SECRET, ts, body, "");
    bad(SECRET, ts, body, &sig[3..]);
    // Wrong secret, empty secret, tampered body, oversized body.
    bad("other", ts, body, &sig);
    bad("", ts, body, &sig);
    let mut tampered = body.to_vec();
    tampered.push(b' ');
    bad(SECRET, ts, &tampered, &sig);
    let huge = vec![0u8; slack::MAX_BODY_BYTES + 1];
    bad(SECRET, ts, &huge, &slack::slack_signature(SECRET, ts, &huge));
}

#[test]
fn an_empty_body_verifies_only_with_its_own_signature() {
    let ts = "1700000000";
    let now = 1_700_000_000;
    let sig = slack::slack_signature(SECRET, ts, b"");
    assert_eq!(slack::verify_slack_signature(SECRET, ts, b"", &sig, now), Ok(()));
    let other = slack::slack_signature(SECRET, ts, b"{}");
    assert_eq!(slack::verify_slack_signature(SECRET, ts, b"", &other, now), Err(SignatureError::BadSignature));
}

// --- replay table ---------------------------------------------------------------

#[tokio::test]
async fn a_signed_request_is_remembered_once_and_attributed_to_system() {
    let env = env();
    let now = 1_700_000_000;
    let body = r#"{"type":"event_callback","event_id":"Ev1"}"#;
    env.remember("1700000000", body, now).await.unwrap();
    let replay = env.remember("1700000000", body, now + 1).await.unwrap_err();
    assert_eq!(replay.reason_code(), Some("replayed"), "{replay}");
    assert!(!replay.to_string().contains(body), "{replay}");
    env.remember("1700000000", r#"{"event_id":"Ev2"}"#, now).await.unwrap();

    let events = env
        .hub
        .db()
        .read_async(|c| {
            ledger::query(
                c,
                &EventQuery {
                    channels: Some(vec!["agent.slack.signature_accepted".into()]),
                    ..Default::default()
                },
            )
        })
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    for e in &events {
        assert_eq!(e.originator.as_deref(), Some("system"));
        assert!(!e.payload.to_string().contains("event_callback"), "{}", e.payload);
    }
}

#[tokio::test]
async fn seen_signatures_older_than_twice_the_window_are_pruned() {
    let env = env();
    let t0 = 1_700_000_000;
    env.remember("1700000000", "a", t0).await.unwrap();
    env.remember("1700000100", "b", t0 + 100).await.unwrap();
    assert_eq!(env.seen_rows().await, 2);
    // Exactly at the retention edge: both kept.
    env.remember("1700000600", "c", t0 + slack::SEEN_RETENTION_S).await.unwrap();
    assert_eq!(env.seen_rows().await, 3);
    // One second past it: the first row goes.
    env.remember("1700000601", "d", t0 + slack::SEEN_RETENTION_S + 1).await.unwrap();
    assert_eq!(env.seen_rows().await, 3);
    // A pruned request is still refused by the timestamp window.
    let sig = slack::slack_signature(SECRET, "1700000000", b"a");
    assert_eq!(
        slack::verify_slack_signature(SECRET, "1700000000", b"a", &sig, t0 + slack::SEEN_RETENTION_S + 1),
        Err(SignatureError::Stale)
    );
}

#[tokio::test]
async fn signature_checking_is_not_an_agent_tool() {
    let env = env();
    let err = env
        .call("slack_verify_request", json!({"timestamp": "1700000000", "body": "{}", "signature": "v0=00"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("slack_verify_request"), "{err}");
    assert!(env.reg.get("slack_verify_request").is_none());
}

// --- parser ---------------------------------------------------------------------

#[tokio::test]
async fn parser_accepts_the_nine_commands_and_rejects_the_rest() {
    let env = env();
    let parsed = env
        .call("slack_parse_command", json!({"text": "<@UBOT> /blocker task-12 waiting on CI"}))
        .await
        .unwrap();
    assert_eq!(parsed, json!({"command": "blocker", "args": ["task-12", "waiting on CI"]}));

    let task = env.call("slack_parse_command", json!({"text": "/task investigate"})).await.unwrap();
    assert_eq!(task["command"], "task");
    assert_eq!(task["args"], json!(["investigate"]));

    for (text, command) in [
        ("/contact", "contact"),
        ("/assign builder-1 review the patch", "assign"),
        ("/progress task-3 moving", "progress"),
        ("/review task-3 ready", "review"),
        ("/plan compare options", "plan"),
        ("/approve 7", "approve"),
        ("status task-42", "status"),
        ("<@U1|bot> <@U2> /contact", "contact"),
    ] {
        let got = env.call("slack_parse_command", json!({"text": text})).await.unwrap();
        assert_eq!(got["command"], command, "{text}");
    }

    let shell = env.call("slack_parse_command", json!({"text": "/shell rm -rf /"})).await.unwrap_err();
    assert!(shell.to_string().contains("unsupported Slack command"), "{shell}");

    let assign = env.call("slack_parse_command", json!({"text": "/assign builder-1"})).await.unwrap_err();
    assert!(assign.to_string().contains("agent and task"), "{assign}");

    let status = env.call("slack_parse_command", json!({"text": "/status"})).await.unwrap_err();
    assert!(status.to_string().contains("task id"), "{status}");

    let empty = env.call("slack_parse_command", json!({"text": "<@UBOT>"})).await.unwrap_err();
    assert!(empty.to_string().contains("empty"), "{empty}");

    let extra = env.call("slack_parse_command", json!({"text": "/contact", "run": true})).await.unwrap_err();
    assert!(extra.to_string().contains("unknown field"), "{extra}");
}

#[test]
fn parser_refuses_overlong_text_before_parsing() {
    let ok = format!("/task {}", "a".repeat(slack::MAX_COMMAND_CHARS - 6));
    assert_eq!(ok.chars().count(), slack::MAX_COMMAND_CHARS);
    assert!(slack::parse_slack_command(&ok).is_ok());
    let long = format!("{ok}a");
    let err = slack::parse_slack_command(&long).unwrap_err();
    assert!(err.to_string().contains("longer than"), "{err}");
    // Many leading mentions: refused on length, never stripped one by one.
    let mentions = "<@U1> ".repeat(100_000);
    let err = slack::parse_slack_command(&mentions).unwrap_err();
    assert!(err.to_string().contains("longer than"), "{err}");
    // Within the limit, a run of mentions is stripped.
    let few = format!("{}/contact", "<@U1> ".repeat(500));
    assert_eq!(slack::parse_slack_command(&few).unwrap()["command"], "contact");
}

#[test]
fn parser_refuses_control_format_and_bidi_characters() {
    for bad in ["\u{202E}", "\u{2066}", "\u{200B}", "\u{200E}", "\u{FEFF}", "\u{0007}", "\r", "\u{E0041}", "\u{061C}"]
    {
        let text = format!("/task fix {bad}the build");
        let err = slack::parse_slack_command(&text).unwrap_err();
        assert!(err.to_string().contains("control or format"), "{bad:?}: {err}");
    }
    // Tab and line feed are whitespace, not hidden characters.
    let ok = slack::parse_slack_command("/task fix\tthe\nbuild").unwrap();
    assert_eq!(ok["args"], json!(["fix", "the\nbuild"]));
}

#[test]
fn parser_unescapes_slack_entities_in_arguments() {
    let got = slack::parse_slack_command("/task R&amp;D: 1 &lt; 2 &gt; 0, literal &amp;lt;").unwrap();
    assert_eq!(got["args"], json!(["R&D:", "1 < 2 > 0, literal &lt;"]));
}

#[test]
fn parser_refuses_special_mentions() {
    for text in [
        "/task ping <!channel>",
        "/task ping <!here>",
        "/task ping <!everyone>",
        "/task ping <!subteam^S123|@oncall>",
        "<!here> /contact",
        "/plan <!date^1392734382^{date}|Feb 18>",
    ] {
        let err = slack::parse_slack_command(text).unwrap_err();
        assert!(err.to_string().contains("special mention"), "{text}: {err}");
    }
}

#[test]
fn parser_validates_task_and_approval_ids() {
    for text in [
        "/progress 12 moving",
        "/blocker task- stuck",
        "/review task-1a ready",
        "/status TASK-42",
        "/status task-42x",
        "/status ../task-1",
        "/progress task-1234567890123456789 too long",
    ] {
        let err = slack::parse_slack_command(text).unwrap_err();
        assert!(err.to_string().contains("task id"), "{text}: {err}");
    }
    for text in ["/approve abc", "/approve -1", "/approve 7a", "/approve 1234567890123456789"] {
        let err = slack::parse_slack_command(text).unwrap_err();
        assert!(err.to_string().contains("numeric approval id"), "{text}: {err}");
    }
    assert_eq!(slack::parse_slack_command("/approve 42 looks good").unwrap()["args"], json!(["42", "looks good"]));
}
