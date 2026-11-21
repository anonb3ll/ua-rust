//! The one place authority is decided (`docs/organization.md`, Authority
//! checks).
//!
//! The design's API is `require(caller, need, target_org)` over
//! `HubOwner`, `LifecycleOperator`, `OrgRole`, `TeamLead` and `Requester`.
//! Those need users, memberships and teams (`organization.v2` and later),
//! which do not exist yet. Until then authority comes from the hub
//! configuration (`human_identities`, `lifecycle_operators`), so [`Authz`]
//! carries the [`Config`], and each authority below names the design
//! authority that replaces it.
//!
//! **A profile never grants authority.** A profile is a permission set: it
//! decides which tools a session sees. Who may act on another agent's work,
//! read every mailbox, or see the hub's boundaries comes from identity only.

use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, UaError, UaResult};

/// One authority a caller may hold (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// Operator authority: a **verified caller of kind human** (a configured
    /// human identity that authenticated as itself: bearer token, browser
    /// session, Slack, or a local CLI `--label` after confirmation), and
    /// nothing else. An agent-kind caller is never an operator, even under a
    /// human's label: that is how an unattended routine owned by a human runs,
    /// precisely so that it carries no human authority. A label listed in
    /// `lifecycle_operators` is never an operator either.
    ///
    /// Replaced by `OrgRole { min: OrgAdmin }` (and `HubOwner` for hub-scoped
    /// rows) once users and memberships exist (`organization.v2`).
    Operator,
    /// A configured lifecycle operator, verified. A separate, explicitly
    /// named grant. It holds for a human whose label is in
    /// `lifecycle_operators` (or, when that list is unset, for any human: the
    /// list then defaults to `human_identities`), and for an agent whose label
    /// is **explicitly** listed in `lifecycle_operators` and is not a human
    /// identity. The unset-list fallback grants nothing to a non-human
    /// caller, and an agent-kind caller under a human's label (an unattended
    /// routine) never holds it.
    /// **not** operator authority: it never satisfies a requirement for
    /// [`Authority::Operator`]. It holds at the design's agent and node
    /// lifecycle sites, and at the fleet-maintenance sites that list it next
    /// to `Operator` (closing, parking and folding tasks, releasing holds,
    /// worktree cleanup, handoff recovery, wake handling, workflow records and
    /// node-queue administration).
    LifecycleOperator,
    /// A caller with no verified label: an unverified local caller (the local
    /// full-surface model when auth enforcement is off: stdio, or HTTP
    /// without `enforce_auth`), or the hub's own system jobs.
    ///
    /// With no verified identity there is nothing to scope a read by, so
    /// mailboxes and conversations are a message board: such a caller may
    /// **read** all of them. That is all this grants. It is a read grant
    /// only: it never satisfies a requirement for [`Authority::Operator`],
    /// [`Authority::LifecycleOperator`] or a human (so it approves nothing),
    /// and a site that changes state must not list it.
    LocalTrustReader,
    /// A caller of kind human: a label in `human_identities` that
    /// authenticated as itself (bearer token, browser session, or a local CLI
    /// `--label` after confirmation).
    ///
    /// Replaced by `HubOwner` and `OrgRole` once `users` and memberships
    /// exist (`organization.v2`).
    TransitionalHuman,
}

impl Authority {
    /// A stable name for messages and logs (not the Rust variant name).
    pub fn name(&self) -> &'static str {
        match self {
            Authority::Operator => "operator",
            Authority::LifecycleOperator => "lifecycle operator",
            Authority::LocalTrustReader => "local trust reader",
            Authority::TransitionalHuman => "human",
        }
    }
}

/// The operator rule as a pure predicate: a verified human.
pub fn operator_rule(caller: &Caller) -> bool {
    human(caller)
}

/// The lifecycle-operator rule as a pure predicate (see
/// [`Authority::LifecycleOperator`]).
pub fn lifecycle_rule(cfg: &Config, caller: &Caller) -> bool {
    match caller.kind {
        ActorKind::Human => cfg.is_lifecycle_operator(&caller.label),
        ActorKind::Agent => {
            cfg.lifecycle_operators.as_ref().is_some_and(|list| list.iter().any(|l| l == &caller.label))
                && !cfg.is_human(&caller.label)
        }
        ActorKind::Anonymous | ActorKind::System => false,
    }
}

/// The caller's verified label: an authenticated agent or human. Anonymous,
/// system and internal callers have none.
fn verified_label(caller: &Caller) -> Option<&str> {
    matches!(caller.kind, ActorKind::Agent | ActorKind::Human).then_some(caller.label.as_str())
}

/// [`Authority::TransitionalHuman`], for code that has no [`Config`] at hand
/// (it does not read one).
pub fn human(caller: &Caller) -> bool {
    caller.kind == ActorKind::Human
}

/// Authority decisions over one hub configuration.
#[derive(Debug, Clone, Copy)]
pub struct Authz<'a> {
    cfg: &'a Config,
}

impl<'a> Authz<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        Self { cfg }
    }

    /// Whether `caller` holds at least one of `need` over a row of
    /// `target_org`.
    ///
    /// Until organizations other than the default exist, `target_org` must
    /// be [`DEFAULT_ORG`] and the caller's organization; anything else holds
    /// nothing (it is refused, not ignored).
    pub fn holds(&self, caller: &Caller, need: &[Authority], target_org: &str) -> bool {
        self.org_ok(caller, target_org).is_ok() && need.iter().any(|a| self.holds_one(caller, a))
    }

    /// [`Authz::holds`] as a refusal naming what was needed.
    pub fn require(&self, caller: &Caller, need: &[Authority], target_org: &str) -> UaResult<()> {
        self.org_ok(caller, target_org)?;
        if need.iter().any(|a| self.holds_one(caller, a)) {
            return Ok(());
        }
        Err(UaError::denied(
            "authority_required",
            format!(
                "{:?} holds none of the required authorities: {}",
                caller.label,
                need.iter().map(Authority::name).collect::<Vec<_>>().join(", ")
            ),
        ))
    }

    fn org_ok(&self, caller: &Caller, target_org: &str) -> UaResult<()> {
        if target_org != DEFAULT_ORG || caller.org_id != DEFAULT_ORG {
            return Err(UaError::denied(
                "org_mismatch",
                format!(
                    "only the {DEFAULT_ORG:?} organization exists; refusing a check for organization \
                     {target_org:?} by a caller in {:?}",
                    caller.org_id
                ),
            ));
        }
        Ok(())
    }

    fn holds_one(&self, caller: &Caller, a: &Authority) -> bool {
        let verified = verified_label(caller);
        match *a {
            Authority::Operator => operator_rule(caller),
            Authority::LocalTrustReader => verified.is_none(),
            Authority::LifecycleOperator => lifecycle_rule(self.cfg, caller),
            Authority::TransitionalHuman => human(caller),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ua_core::Profile;
    use ua_core::identity::Transport;

    fn cfg() -> Config {
        Config {
            human_identities: vec!["operator".into()],
            lifecycle_operators: Some(vec!["fleet-bot".into()]),
            ..Config::default()
        }
    }

    fn caller(label: &str, kind: ActorKind, profile: Profile) -> Caller {
        Caller { kind, profile, ..Caller::local(label, Transport::Http) }
    }

    fn holds(c: &Caller, a: Authority) -> bool {
        let cfg = cfg();
        Authz::new(&cfg).holds(c, &[a], DEFAULT_ORG)
    }

    #[test]
    fn operator_is_a_verified_human_and_not_a_lifecycle_agent() {
        let human = caller("operator", ActorKind::Human, Profile::Developer);
        assert!(holds(&human, Authority::Operator));
        for c in [
            // An unattended routine owned by the human: agent kind, human label.
            caller("operator", ActorKind::Agent, Profile::Coordinator),
            caller("fleet-bot", ActorKind::Agent, Profile::Developer),
            caller("builder-1", ActorKind::Agent, Profile::Operator),
            caller("lead-1", ActorKind::Agent, Profile::Coordinator),
            caller("operator", ActorKind::Anonymous, Profile::Coordinator),
            Caller::system(),
        ] {
            assert!(!holds(&c, Authority::Operator), "{} {:?} {:?}", c.label, c.kind, c.profile);
        }
    }

    /// A lifecycle operator is never an operator, and only a site that
    /// lists both admits it.
    #[test]
    fn lifecycle_operator_is_a_separate_grant_never_an_operator() {
        let cfg = cfg();
        let authz = Authz::new(&cfg);
        let fleet = caller("fleet-bot", ActorKind::Agent, Profile::Developer);
        assert!(!operator_rule(&fleet));
        assert!(!authz.holds(&fleet, &[Authority::Operator], DEFAULT_ORG));
        assert!(authz.holds(&fleet, &[Authority::Operator, Authority::LifecycleOperator], DEFAULT_ORG));
        let human = caller("operator", ActorKind::Human, Profile::Developer);
        assert!(authz.holds(&human, &[Authority::Operator, Authority::LifecycleOperator], DEFAULT_ORG));
        // An unverified caller claiming a lifecycle or human label holds neither.
        for label in ["fleet-bot", "operator"] {
            let anon = caller(label, ActorKind::Anonymous, Profile::Coordinator);
            assert!(!authz.holds(&anon, &[Authority::Operator, Authority::LifecycleOperator], DEFAULT_ORG));
        }
    }

    #[test]
    fn local_trust_reader_is_a_caller_without_a_verified_label() {
        assert!(holds(
            &caller("local", ActorKind::Anonymous, Profile::Developer),
            Authority::LocalTrustReader
        ));
        assert!(holds(&Caller::system(), Authority::LocalTrustReader));
        for kind in [ActorKind::Agent, ActorKind::Human] {
            assert!(
                !holds(&caller("x", kind, Profile::Coordinator), Authority::LocalTrustReader),
                "{kind:?}"
            );
        }
    }

    /// The local-trust grant is a read grant: whatever label an unverified
    /// caller gives, it holds no operator, lifecycle or human authority.
    #[test]
    fn local_trust_reader_holds_no_other_authority() {
        let others = [Authority::Operator, Authority::LifecycleOperator, Authority::TransitionalHuman];
        for label in ["local", "operator", "fleet-bot", "builder-1"] {
            for profile in [Profile::Developer, Profile::Coordinator, Profile::Operator] {
                let anon = caller(label, ActorKind::Anonymous, profile);
                assert!(holds(&anon, Authority::LocalTrustReader));
                for a in others {
                    assert!(!holds(&anon, a), "{label} {profile:?} {a:?}");
                }
            }
        }
    }

    #[test]
    fn lifecycle_operator_is_a_verified_configured_label() {
        assert!(holds(
            &caller("fleet-bot", ActorKind::Agent, Profile::Developer),
            Authority::LifecycleOperator
        ));
        assert!(!holds(
            &caller("fleet-bot", ActorKind::Anonymous, Profile::Developer),
            Authority::LifecycleOperator
        ));
        assert!(!holds(
            &caller("builder-1", ActorKind::Agent, Profile::Coordinator),
            Authority::LifecycleOperator
        ));
        // With lifecycle_operators set, a human not listed there is not one.
        assert!(!holds(
            &caller("operator", ActorKind::Human, Profile::Developer),
            Authority::LifecycleOperator
        ));
    }

    /// The unset-list fallback (`lifecycle_operators` defaults to
    /// `human_identities`) grants humans only; an unattended routine under a
    /// human's label never holds the grant, listed or not.
    #[test]
    fn the_lifecycle_fallback_grants_nothing_to_a_non_human_caller() {
        let unset = Config { human_identities: vec!["operator".into()], ..Config::default() };
        let routine = caller("operator", ActorKind::Agent, Profile::Developer);
        let human = caller("operator", ActorKind::Human, Profile::Developer);
        assert!(lifecycle_rule(&unset, &human), "a human, by the fallback");
        assert!(!lifecycle_rule(&unset, &routine), "the fallback grants a routine nothing");
        // Even when the human's label is listed explicitly.
        let listed = Config {
            human_identities: vec!["operator".into()],
            lifecycle_operators: Some(vec!["operator".into(), "fleet-bot".into()]),
            ..Config::default()
        };
        assert!(lifecycle_rule(&listed, &human));
        assert!(!lifecycle_rule(&listed, &routine));
        assert!(lifecycle_rule(&listed, &caller("fleet-bot", ActorKind::Agent, Profile::Developer)));
        assert!(!lifecycle_rule(&unset, &caller("fleet-bot", ActorKind::Agent, Profile::Developer)));
        assert!(!lifecycle_rule(&listed, &Caller::system()));
    }

    #[test]
    fn human_is_the_human_kind() {
        assert!(holds(
            &caller("operator", ActorKind::Human, Profile::Operator),
            Authority::TransitionalHuman
        ));
        for kind in [ActorKind::Agent, ActorKind::Anonymous, ActorKind::System] {
            assert!(
                !holds(&caller("operator", kind, Profile::Coordinator), Authority::TransitionalHuman),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn another_organization_is_refused_not_ignored() {
        let cfg = cfg();
        let authz = Authz::new(&cfg);
        let human = caller("operator", ActorKind::Human, Profile::Operator);
        assert!(!authz.holds(&human, &[Authority::TransitionalHuman], "org-b"));
        let err = authz.require(&human, &[Authority::TransitionalHuman], "org-b").unwrap_err();
        assert_eq!(err.reason_code(), Some("org_mismatch"));
        let elsewhere = Caller { org_id: "org-b".into(), ..human.clone() };
        assert!(!authz.holds(&elsewhere, &[Authority::TransitionalHuman], DEFAULT_ORG));
        assert!(authz.require(&human, &[Authority::TransitionalHuman], DEFAULT_ORG).is_ok());
    }

    #[test]
    fn require_names_what_was_needed_and_accepts_any_one() {
        let cfg = cfg();
        let authz = Authz::new(&cfg);
        let dev = caller("builder-1", ActorKind::Agent, Profile::Developer);
        let err = authz.require(&dev, &[Authority::TransitionalHuman], DEFAULT_ORG).unwrap_err();
        assert_eq!(err.reason_code(), Some("authority_required"));
        assert!(err.to_string().ends_with("holds none of the required authorities: human"), "{err}");
        assert!(!err.to_string().contains("Transitional"), "{err}");
        let err = authz
            .require(
                &dev,
                &[Authority::TransitionalHuman, Authority::Operator, Authority::LifecycleOperator],
                DEFAULT_ORG,
            )
            .unwrap_err();
        assert!(err.to_string().ends_with("authorities: human, operator, lifecycle operator"), "{err}");
        let fleet = caller("fleet-bot", ActorKind::Agent, Profile::Coordinator);
        let any = [Authority::Operator, Authority::LifecycleOperator];
        assert!(authz.require(&fleet, &any, DEFAULT_ORG).is_ok());
        assert!(authz.require(&fleet, &[], DEFAULT_ORG).is_err(), "nothing needed is nothing held");
    }
}
