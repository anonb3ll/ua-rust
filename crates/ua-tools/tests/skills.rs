//! `skill_review` over temp trees of good and bad SKILL.md files.

use std::path::Path;

use serde_json::{Value, json};
use ua_core::{Caller, Config, identity::Transport};
use ua_tools::{Hub, builtin_registry};

struct Env {
    ws: tempfile::TempDir,
    _home: tempfile::TempDir,
    hub: Hub,
}

impl Env {
    fn new() -> Self {
        let (ws, home) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut cfg = Config::for_home(home.path());
        cfg.workspace = Some(ws.path().to_path_buf());
        Self { hub: Hub::in_memory(cfg).unwrap(), ws, _home: home }
    }

    fn skill(&self, dir: &str, text: &str) {
        let d = self.ws.path().join("skills").join(dir);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), text).unwrap();
    }

    async fn review(&self, args: Value) -> Result<Value, ua_core::UaError> {
        let who = Caller::local("local-dev", Transport::Cli);
        builtin_registry().call(&self.hub, &who, "skill_review", args).await
    }
}

const BODY: &str = "# Title\n\nStep one: do the thing.\nStep two: check the result.\nStep three: report.\n";

fn good(name: &str, desc: &str) -> String {
    format!("---\nname: {name}\ndescription: {desc}\n---\n{BODY}")
}

fn has(report: &Value, rule: &str, path: &str) -> bool {
    report["findings"].as_array().unwrap().iter().any(|f| f["rule"] == rule && f["path"] == path)
}

#[tokio::test]
async fn a_good_skill_passes() {
    let e = Env::new();
    e.skill(
        "pr-review",
        &good(
            "pr-review",
            "Reviews a pull request diff for correctness bugs. Use when the user asks for a code review.",
        ),
    );
    let r = e.review(json!({ "path": "skills/pr-review" })).await.unwrap();
    assert_eq!(r["status"], "pass", "{r}");
    assert_eq!(r["skills_reviewed"], json!(["pr-review"]));
    assert_eq!(r["truncated"], false);
}

#[tokio::test]
async fn bad_skills_are_flagged_by_rule() {
    let e = Env::new();
    e.skill("no-frontmatter", "# just a body\nwith no header at all\nand more lines\n");
    e.skill("unclosed", "---\nname: unclosed\ndescription: x\n# oops\n");
    e.skill("wrong-name", &good("other-name", "Formats release notes. Use when asked to draft a changelog."));
    e.skill("Bad_Case", &good("Bad_Case", "Formats release notes. Use when asked to draft a changelog."));
    e.skill("thin", &good("thin", "short"));
    e.skill("voice", &good("voice", "I review code and I am a robust, powerful, comprehensive helper"));
    e.skill(
        "buried",
        &format!("---\nname: buried\ndescription: Summarizes meeting transcripts into action items.\n---\n{BODY}Use when the user pastes a transcript.\n"),
    );
    e.skill(
        "links",
        &format!("---\nname: links\ndescription: Explains links. Use when asked about links.\n---\n{BODY}See [guide](docs/guide.md) and [web](https://example.com/x).\nBe thorough and think carefully.\n"),
    );
    e.skill("empty", "---\nname: empty\ndescription: Does nothing at all. Use when asked to do nothing.\n---\nOnly one line\n");

    let r = e.review(json!({ "path": "skills" })).await.unwrap();
    assert_eq!(r["status"], "fail");
    assert!(has(&r, "SKILL-FRONTMATTER", "no-frontmatter/SKILL.md"));
    assert!(has(&r, "SKILL-FRONTMATTER", "unclosed/SKILL.md"));
    assert!(has(&r, "SKILL-NAME", "wrong-name/SKILL.md"));
    assert!(has(&r, "SKILL-NAME", "Bad_Case/SKILL.md"));
    assert!(has(&r, "SKILL-DESC-LENGTH", "thin/SKILL.md"));
    assert!(has(&r, "SKILL-DESC-VOICE", "voice/SKILL.md"));
    assert!(has(&r, "SKILL-DESC-HYPE", "voice/SKILL.md"));
    let buried = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "SKILL-DESC-TRIGGER" && f["path"] == "buried/SKILL.md")
        .unwrap();
    assert_eq!(buried["severity"], "medium");
    assert!(has(&r, "SKILL-BROKEN-REF", "links/SKILL.md"));
    assert!(
        !r["findings"].as_array().unwrap().iter().any(
            |f| f["rule"] == "SKILL-BROKEN-REF" && f["message"].as_str().unwrap().contains("example.com")
        )
    );
    assert!(has(&r, "SKILL-BODY-FILLER", "links/SKILL.md"));
    assert!(has(&r, "SKILL-BODY-EMPTY", "empty/SKILL.md"));
    // Highest severity first.
    let sev: Vec<&str> =
        r["findings"].as_array().unwrap().iter().map(|f| f["severity"].as_str().unwrap()).collect();
    let rank = |s: &&str| ["high", "medium", "low", "info"].iter().position(|x| x == s).unwrap();
    assert!(sev.windows(2).all(|w| rank(&w[0]) <= rank(&w[1])));

    let high = e.review(json!({ "path": "skills", "min_severity": "high" })).await.unwrap();
    assert!(high["findings"].as_array().unwrap().iter().all(|f| f["severity"] == "high"));
    assert_eq!(high["status"], "fail", "status is computed before the filter");
}

const OVERLAP_A: &str = "Reviews pull request diffs for correctness bugs, security problems, missing tests and style regressions. Use when the user asks for code review.";
const OVERLAP_B: &str = "Reviews pull request diffs for correctness bugs, security problems, missing tests and style regressions. Use when the user wants a code review.";

#[tokio::test]
async fn sibling_overlap_is_found_for_a_directory_and_for_a_single_skill() {
    let e = Env::new();
    e.skill("review-a", &good("review-a", OVERLAP_A));
    e.skill("review-b", &good("review-b", OVERLAP_B));
    e.skill(
        "unrelated",
        &good(
            "unrelated",
            "Converts spreadsheets to CSV files with column headers. Use when asked to export tabular data.",
        ),
    );

    let all = e.review(json!({ "path": "skills" })).await.unwrap();
    assert!(has(&all, "SKILL-DESC-OVERLAP", "review-a/SKILL.md"));
    assert!(!has(&all, "SKILL-DESC-OVERLAP", "unrelated/SKILL.md"));

    // One skill is still compared with its siblings.
    let one = e.review(json!({ "path": "skills/review-a/SKILL.md" })).await.unwrap();
    assert_eq!(one["skills_reviewed"], json!(["review-a"]));
    assert!(has(&one, "SKILL-DESC-OVERLAP", "SKILL.md"));
    let other = e.review(json!({ "path": "skills/unrelated" })).await.unwrap();
    assert!(!other["findings"].as_array().unwrap().iter().any(|f| f["rule"] == "SKILL-DESC-OVERLAP"));
}

#[tokio::test]
async fn errors_are_reported() {
    let e = Env::new();
    e.skill("a", &good("a", "Does a thing for people. Use when asked about things."));
    std::fs::write(e.ws.path().join("skills/README.md"), "x").unwrap();
    std::fs::create_dir_all(e.ws.path().join("empty-dir")).unwrap();

    assert_eq!(e.review(json!({ "path": "skills/README.md" })).await.unwrap_err().code(), "invalid_argument");
    assert_eq!(e.review(json!({ "path": "missing" })).await.unwrap_err().code(), "not_found");
    assert_eq!(e.review(json!({ "path": "empty-dir" })).await.unwrap_err().code(), "not_found");
    assert_eq!(e.review(json!({ "min_severity": "bogus" })).await.unwrap_err().code(), "invalid_argument");
    let outside = tempfile::tempdir().unwrap();
    assert_eq!(
        e.review(json!({ "path": outside.path().to_str().unwrap() })).await.unwrap_err().code(),
        "denied"
    );
    let _ = Path::new("");
}

#[tokio::test]
async fn at_most_one_hundred_skills_are_reviewed() {
    let e = Env::new();
    for i in 0..101 {
        e.skill(
            &format!("s{i:03}"),
            &good(&format!("s{i:03}"), "Sorts items alphabetically. Use when asked to sort items."),
        );
    }
    let r = e.review(json!({ "path": "skills" })).await.unwrap();
    assert_eq!(r["skills_reviewed"].as_array().unwrap().len(), 100);
    assert_eq!(r["truncated"], true);
}

#[tokio::test]
async fn front_matter_that_grants_tools_is_flagged() {
    let e = Env::new();
    let desc = "Reviews a pull request diff for correctness bugs. Use when the user asks for a code review.";
    // Only allowlisted keys pass: a skill's own grant key, the keys a
    // subagent grants itself tools with, and any other key.
    for (dir, key) in [
        ("allowed", "allowed-tools: Bash"),
        ("tools", "tools: Bash, Edit"),
        ("disallowed", "disallowedTools: Read"),
        ("mode", "permissionMode: bypassPermissions"),
        ("servers", "mcpServers: [hub]"),
        ("permission", "permission: allow"),
        ("context", "context: fork"),
        ("agent", "agent: general-purpose"),
    ] {
        e.skill(dir, &format!("---\nname: {dir}\ndescription: {desc}\n{key}\n---\n{BODY}"));
    }
    let r = e.review(json!({ "path": "skills" })).await.unwrap();
    assert_eq!(r["status"], "fail", "{r}");
    for dir in ["allowed", "tools", "disallowed", "mode", "servers", "permission", "context", "agent"] {
        assert!(has(&r, "SKILL-PERMISSIONS", &format!("{dir}/SKILL.md")), "{dir}: {r}");
    }
}

#[tokio::test]
async fn agent_skills_descriptive_fields_pass_but_metadata_stays_plain() {
    let e = Env::new();
    let desc = "Reviews a pull request diff for correctness bugs. Use when the user asks for a code review.";
    e.skill(
        "described",
        &format!("---\nname: described\ndescription: {desc}\nlicense: MIT\nversion: 1.2.0\nmetadata: {{author: x}}\n---\n{BODY}"),
    );
    let r = e.review(json!({ "path": "skills/described" })).await.unwrap();
    assert_eq!(r["status"], "pass", "{r}");

    for (dir, meta) in
        [("nested-list", "metadata: {tools: [Bash]}"), ("nested-map", "metadata:\n  x:\n    tools: Bash")]
    {
        e.skill(dir, &format!("---\nname: {dir}\ndescription: {desc}\n{meta}\n---\n{BODY}"));
        let r = e.review(json!({ "path": format!("skills/{dir}") })).await.unwrap();
        assert_eq!(r["status"], "fail", "{dir}: {r}");
        assert!(has(&r, "SKILL-PERMISSIONS", "SKILL.md"), "{dir}: {r}");
    }
    // A permission-bearing key next to them is still refused.
    e.skill(
        "granting",
        &format!("---\nname: granting\ndescription: {desc}\nlicense: MIT\nallowed-tools: Bash\n---\n{BODY}"),
    );
    let r = e.review(json!({ "path": "skills/granting" })).await.unwrap();
    assert!(has(&r, "SKILL-PERMISSIONS", "SKILL.md"), "{r}");
}
