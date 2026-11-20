//! Slack signature checks and the coordination command parser.
//!
//! No HTTP server is started. Replay is the seen-signature table, not a route.

use secrecy::SecretString;
use serde_json::{Value, json};
use ua_core::{ActorKind, Caller, Config, Profile, UaError, identity::Transport};
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

fn env(secret: Option<&str>) -> Env {
    let home = tempfile::tempdir().unwrap();
    let mut cfg = Config::for_home(home.path());
    cfg.slack_signing_secret = secret.map(SecretString::from);
    Env { hub: Hub::in_memory(cfg).unwrap(), reg: builtin_registry(), _home: home }
}

impl Env {
    async fn call(&self, tool: &str, args: Value) -> Result<Value, UaError> {
        self.reg.call(&self.hub, &caller(), tool, args).await
    }
}

fn now_s() -> i64 {
    jiff::Timestamp::now().as_second()
}

#[test]
fn signature_accepts_the_python_vector_and_rejects_skew_and_tampering() {
    let body = br#"{"type":"event_callback"}"#;
    let ts = "1700000000";
    let sig = slack::slack_signature(SECRET, ts, body);
    assert_eq!(slack::verify_slack_signature(SECRET, ts, body, &sig, 1_700_000_000), Ok(()));
    assert_eq!(
        slack::verify_slack_signature(SECRET, ts, body, &sig, 1_700_000_401),
        Err(SignatureError::Stale)
    );
    assert_eq!(
        slack::verify_slack_signature(SECRET, ts, body, &sig, 1_699_999_699),
        Err(SignatureError::Stale)
    );
    assert_eq!(
        slack::verify_slack_signature("other", ts, body, &sig, 1_700_000_000),
        Err(SignatureError::BadSignature)
    );
    let mut tampered = body.to_vec();
    tampered.push(b' ');
    assert_eq!(
        slack::verify_slack_signature(SECRET, ts, &tampered, &sig, 1_700_000_000),
        Err(SignatureError::BadSignature)
    );
    assert_eq!(
        slack::verify_slack_signature(SECRET, ts, body, "v0=00", 1_700_000_000),
        Err(SignatureError::BadSignature)
    );
    assert_eq!(
        slack::verify_slack_signature("", ts, body, &sig, 1_700_000_000),
        Err(SignatureError::BadSignature)
    );
    let huge = vec![0u8; slack::MAX_BODY_BYTES + 1];
    assert_eq!(
        slack::verify_slack_signature(SECRET, ts, &huge, &sig, 1_700_000_000),
        Err(SignatureError::BadSignature)
    );
}

#[tokio::test]
async fn tool_rejects_bad_signature_stale_timestamp_and_replay() {
    let env = env(Some(SECRET));
    let now = now_s().to_string();
    let body = r#"{"type":"event_callback","event_id":"Ev1"}"#;
    let sig = slack::slack_signature(SECRET, &now, body.as_bytes());

    let bad = env
        .call("slack_verify_request", json!({"timestamp": now, "body": body, "signature": "v0=deadbeef"}))
        .await
        .unwrap_err();
    assert_eq!(bad.reason_code(), Some("bad_signature"), "{bad}");
    assert!(!bad.to_string().contains(SECRET), "{bad}");

    let stale_sig = slack::slack_signature(SECRET, "1700000000", body.as_bytes());
    let stale = env
        .call(
            "slack_verify_request",
            json!({"timestamp": "1700000000", "body": body, "signature": stale_sig}),
        )
        .await
        .unwrap_err();
    assert_eq!(stale.reason_code(), Some("stale_timestamp"), "{stale}");

    let ok = env
        .call("slack_verify_request", json!({"timestamp": now, "body": body, "signature": sig}))
        .await
        .unwrap();
    assert_eq!(ok["ok"], true);

    let replay = env
        .call("slack_verify_request", json!({"timestamp": now, "body": body, "signature": sig}))
        .await
        .unwrap_err();
    assert_eq!(replay.reason_code(), Some("replayed"), "{replay}");
    assert!(!replay.to_string().contains(body), "{replay}");

    let other = r#"{"type":"event_callback","event_id":"Ev2"}"#;
    let other_sig = slack::slack_signature(SECRET, &now, other.as_bytes());
    let second = env
        .call("slack_verify_request", json!({"timestamp": now, "body": other, "signature": other_sig}))
        .await
        .unwrap();
    assert_eq!(second["ok"], true, "a different body at the same timestamp is not a replay");
}

#[tokio::test]
async fn verify_is_off_without_a_signing_secret() {
    let env = env(None);
    let err = env
        .call("slack_verify_request", json!({"timestamp": "1700000000", "body": "{}", "signature": "v0=00"}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not configured"), "{err}");
}

#[tokio::test]
async fn parser_accepts_the_nine_commands_and_rejects_the_rest() {
    let env = env(None);
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
