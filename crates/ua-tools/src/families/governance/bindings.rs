//! Project stream to source repository bindings.
//!
//! A durable binding from a project stream slug (the tasks' `project`) to a
//! normalized `owner/name` repository on an allowed forge host, with an
//! optional default branch. Bind is an upsert; unbind removes the row. Each
//! write appends a `project.repo.bound` or `project.repo.unbound` event in
//! the same transaction.
//!
//! A binding decides which repository a task's CI checks are verified
//! against (`task_check_record`), so bind and unbind are for a verified
//! lifecycle operator or human, attributed to that caller; get and list are
//! open to every caller.
//!
//! Bindings are keyed by `(org_id, project)` (`governance.v2.project_bindings_tenant_keys`).
//! Every tool reads and writes only the caller's organization's bindings, so
//! two organizations may bind the same project slug to different
//! repositories. Tasks carry no `org_id` yet and are all in the default
//! organization, so the task-driven readers ([`bound_repo`]) look up the
//! default organization's bindings.

use rusqlite::{Connection, OptionalExtension, params};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::{UaError, UaResult};
use ua_store::{EventInput, ledger};

use super::{now, verified_actor};
use crate::families::tasks::{acting_identity, check_slug, row_object};
use crate::registry::ToolCtx;
use ua_org::authz::{Authority, Authz};

/// Forge hosts a binding may name.
const ALLOWED_HOSTS: [&str; 2] = ["github.com", "www.github.com"];
const MAX_BRANCH: usize = 200;

fn segment_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 100
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Normalize a repository reference to lowercase `owner/name` on an allowed
/// host. Accepts `owner/name`, `github.com/owner/name`, `https://...`,
/// `ssh://git@...` and `git@host:owner/name.git`. Refuses credentials or
/// user info, other hosts, and anything that is not exactly two segments.
pub fn normalize_repo(raw: &str) -> UaResult<String> {
    let text = raw.trim();
    if text.is_empty() {
        return Err(UaError::invalid("repo must not be empty"));
    }
    if text.chars().any(char::is_whitespace) {
        return Err(UaError::invalid(format!("invalid repo {raw:?}: must not contain whitespace")));
    }
    let (host, path): (String, String) = if text.starts_with("ssh://") || text.contains("://") {
        let u = url::Url::parse(text).map_err(|_| UaError::invalid(format!("invalid repo URL {raw:?}")))?;
        match u.scheme() {
            "ssh" => {
                if u.password().is_some() || (!u.username().is_empty() && u.username() != "git") {
                    return Err(UaError::invalid(format!("repo URL must not carry credentials: {raw:?}")));
                }
            }
            "https" | "http" => {
                if !u.username().is_empty() || u.password().is_some() {
                    return Err(UaError::invalid(format!(
                        "repo URL must not carry credentials or userinfo: {raw:?}"
                    )));
                }
            }
            other => return Err(UaError::invalid(format!("unsupported repo URL scheme: {other:?}"))),
        }
        (u.host_str().unwrap_or("").to_string(), u.path().trim_start_matches('/').to_string())
    } else if let Some(rest) = text.strip_prefix("git@") {
        let Some((host, path)) = rest.split_once(':') else {
            return Err(UaError::invalid(format!("invalid scp-style repo url: {raw:?}")));
        };
        if host.contains('/') {
            return Err(UaError::invalid(format!("invalid scp-style repo url: {raw:?}")));
        }
        (host.to_string(), path.to_string())
    } else if let Some((first, rest)) = text.split_once('/') {
        if first.contains('@') {
            return Err(UaError::invalid(format!("repo must not carry credentials or userinfo: {raw:?}")));
        }
        if ALLOWED_HOSTS.contains(&first.to_ascii_lowercase().trim_end_matches('.')) {
            (first.to_string(), rest.to_string())
        } else {
            ("github.com".to_string(), text.to_string())
        }
    } else {
        return Err(UaError::invalid(format!("unrecognized repo format: {raw:?}")));
    };
    let host = host.to_ascii_lowercase();
    let host = host.trim_end_matches('.');
    if !ALLOWED_HOSTS.contains(&host) {
        return Err(UaError::invalid(format!(
            "repo host {host:?} is not allowed (allowed: {ALLOWED_HOSTS:?})"
        )));
    }
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() != 2 || segments.iter().any(|s| s.is_empty()) {
        return Err(UaError::invalid(format!(
            "repo must resolve to exactly owner/name, got {path:?} from {raw:?}"
        )));
    }
    if !segments.iter().all(|s| segment_ok(s)) {
        return Err(UaError::invalid(format!("invalid owner/name in repo {raw:?}")));
    }
    Ok(format!("{}/{}", segments[0].to_ascii_lowercase(), segments[1].to_ascii_lowercase()))
}

/// The normalized `owner/name` a project stream of organization `org` is
/// bound to, if any.
pub(crate) fn bound_repo(c: &Connection, org: &str, project: &str) -> UaResult<Option<String>> {
    Ok(c.query_row(
        "SELECT repo FROM project_repo_bindings WHERE org_id = ?1 AND project = ?2",
        [org, project],
        |r| r.get(0),
    )
    .optional()?)
}

/// One binding of organization `org`, without its `org_id` (the caller's own).
fn binding(c: &Connection, org: &str, project: &str) -> UaResult<Option<Value>> {
    let row = c
        .query_row(
            "SELECT project, repo, default_branch, bound_by, bound_at FROM project_repo_bindings \
             WHERE org_id = ?1 AND project = ?2",
            [org, project],
            row_object,
        )
        .optional()?;
    Ok(row.map(|mut m| {
        m.insert("source".into(), json!("db"));
        Value::Object(m)
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindArgs {
    /// Project stream slug.
    pub project: String,
    /// Repository: `owner/name`, `github.com/owner/name` or a clone URL.
    pub repo: String,
    /// Default branch, at most 200 characters.
    pub default_branch: Option<String>,
    /// Must name the verified caller when given (kept for compatibility).
    pub bound_by: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnbindArgs {
    /// Project stream slug.
    pub project: String,
    /// Must name the verified caller when given (kept for compatibility).
    pub unbound_by: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    /// Project stream slug.
    pub project: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {}

/// The verified operator changing a binding. A binding names the repository
/// a task's CI checks are verified against, and the repository merges and
/// policy authorizations name, and it is not approval-gated, so only an
/// operator (a verified human) may change it, under its own name: `named`
/// (the legacy `bound_by` / `unbound_by`) must be that caller when given. A
/// lifecycle operator may not.
fn binding_operator(ctx: &ToolCtx, named: Option<&str>, doing: &str) -> UaResult<String> {
    let who = verified_actor(&ctx.caller, doing)?;
    acting_identity(&ctx.caller, named)?;
    if !Authz::new(ctx.hub.cfg()).holds(&ctx.caller, &[Authority::Operator], &ctx.caller.org_id) {
        return Err(UaError::denied(
            "operator_required",
            format!("{doing} is for an operator (a verified human); {who:?} is not one"),
        ));
    }
    Ok(who)
}

/// Refuse an organization `orgs` does not hold. Runs before the write, and
/// again first in every write transaction: the `org_exists` trigger only
/// sees inserts, so an unbind would otherwise pass.
fn require_org(c: &Connection, org: &str) -> UaResult<()> {
    let known = c.query_row("SELECT 1 FROM orgs WHERE id = ?1", [org], |_| Ok(())).optional()?.is_some();
    if !known {
        return Err(UaError::denied(
            "unknown_organization",
            format!("unknown organization {org:?}; no binding was changed"),
        ));
    }
    Ok(())
}

/// Trim and validate an optional repository default branch name.
pub fn check_default_branch(raw: Option<&str>) -> UaResult<Option<String>> {
    let branch = raw.map(|b| b.trim().to_string()).filter(|b| !b.is_empty());
    if branch
        .as_ref()
        .is_some_and(|b| b.len() > MAX_BRANCH || b.starts_with('-') || b.contains(char::is_whitespace))
    {
        return Err(UaError::invalid(format!(
            "default_branch must be at most {MAX_BRANCH} characters, without whitespace or a leading '-'"
        )));
    }
    Ok(branch)
}

/// `coordination_manage(action="project_repo_bind")`.
pub(crate) async fn project_repo_bind(ctx: ToolCtx, a: BindArgs) -> UaResult<Value> {
    let project = check_slug("project", &a.project)?;
    let repo = normalize_repo(&a.repo)?;
    let org = ctx.caller.org_id.clone();
    // Refuse an unknown organization and a non-operator before taking the
    // writer lock; the transaction checks the organization again.
    let known = org.clone();
    ctx.hub.db().read_async(move |c| require_org(c, &known)).await?;
    let who = binding_operator(&ctx, a.bound_by.as_deref(), "binding a project repository")?;
    let branch = check_default_branch(a.default_branch.as_deref())?;
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            tx.execute(
                "INSERT INTO project_repo_bindings (org_id, project, repo, default_branch, bound_by, bound_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (org_id, project) DO UPDATE SET repo = excluded.repo, \
                 default_branch = excluded.default_branch, bound_by = excluded.bound_by, bound_at = excluded.bound_at",
                params![org, project, repo, branch, who, now()],
            )?;
            // ORG-EVENT-DEFAULT: use the binding's organization once callers
            // can resolve to other organizations and org_guard allows it.
            ledger::append(
                tx,
                EventInput::new(ua_core::DEFAULT_ORG,
                    "project.repo.bound",
                    json!({ "project": project, "repo": repo, "default_branch": branch, "bound_by": who }),
                )
                .by(who.clone()),
            )?;
            Ok(json!({ "binding": binding(tx, &org, &project)? }))
        })
        .await
}

/// `coordination_manage(action="project_repo_unbind")`.
pub(crate) async fn project_repo_unbind(ctx: ToolCtx, a: UnbindArgs) -> UaResult<Value> {
    let project = check_slug("project", &a.project)?;
    let org = ctx.caller.org_id.clone();
    // Refuse an unknown organization and a non-operator before taking the
    // writer lock; the transaction checks the organization again.
    let known = org.clone();
    ctx.hub.db().read_async(move |c| require_org(c, &known)).await?;
    let who = binding_operator(&ctx, a.unbound_by.as_deref(), "unbinding a project repository")?;
    ctx.hub
        .db()
        .write_async(move |tx| {
            require_org(tx, &org)?;
            let previous = binding(tx, &org, &project)?;
            tx.execute(
                "DELETE FROM project_repo_bindings WHERE org_id = ?1 AND project = ?2",
                [&org, &project],
            )?;
            // ORG-EVENT-DEFAULT: use the binding's organization once callers
            // can resolve to other organizations and org_guard allows it.
            ledger::append(
                tx,
                EventInput::new(
                    ua_core::DEFAULT_ORG,
                    "project.repo.unbound",
                    json!({ "project": project, "previous": previous }),
                )
                .by(who.clone()),
            )?;
            Ok(json!({ "unbound": previous.is_some(), "previous": previous }))
        })
        .await
}

/// `coordination_manage(action="project_repo_get")`.
pub(crate) async fn project_repo_get(ctx: ToolCtx, a: GetArgs) -> UaResult<Value> {
    let project = check_slug("project", &a.project)?;
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| Ok(json!({ "project": project, "binding": binding(c, &org, &project)? })))
        .await
}

/// `coordination_manage(action="project_repo_list")`: every project stream in
/// use by a task or a binding of the caller's organization, each with its
/// binding or `null`. Tasks are all in the default organization, so only its
/// callers see the task streams.
pub(crate) async fn project_repo_list(ctx: ToolCtx, _a: ListArgs) -> UaResult<Value> {
    let org = ctx.caller.org_id.clone();
    ctx.hub
        .db()
        .read_async(move |c| {
            let projects: Vec<String> = c
                .prepare(
                    "SELECT project FROM tasks WHERE ?1 = ?2 \
                     UNION SELECT project FROM project_repo_bindings WHERE org_id = ?1 ORDER BY 1",
                )?
                .query_map([org.as_str(), ua_core::DEFAULT_ORG], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let rows = projects
                .iter()
                .map(|p| Ok(json!({ "project": p, "binding": binding(c, &org, p)? })))
                .collect::<UaResult<Vec<_>>>()?;
            Ok(json!({ "projects": rows }))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::normalize_repo;

    #[test]
    fn repo_references_normalize_to_owner_name() {
        for ok in [
            "owner/name",
            "Owner/Name",
            "github.com/owner/name",
            "https://github.com/owner/name.git",
            "ssh://git@github.com/owner/name.git",
            "git@github.com:owner/name.git",
        ] {
            assert_eq!(normalize_repo(ok).unwrap(), "owner/name", "{ok}");
        }
        for bad in [
            "",
            "owner",
            "owner//name",
            "owner/name/extra",
            "https://user:pw@github.com/owner/name",
            "https://example.com/owner/name",
            "ftp://github.com/owner/name",
            "ssh://root@github.com/owner/name",
            "-x/name",
            "owner/ name",
        ] {
            assert!(normalize_repo(bad).is_err(), "{bad:?} should be refused");
        }
    }
}
