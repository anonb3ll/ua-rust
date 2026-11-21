//! The one place authority is decided (`docs/organization.md`, Authority
//! checks).
//!
//! The design's API is `require(caller, need, target_org)` over
//! `HubOwner`, `LifecycleOperator`, `OrgRole`, `TeamLead` and `Requester`.
//! Those need users, memberships and teams (`organization.v2` and later),
//! which do not exist yet. Until then authority comes from the hub
//! configuration (`human_identities`, `lifecycle_operators`, `[profiles]`), so
//! [`Authz`] carries the [`Config`], and the authorities below are
//! **transitional**: each reproduces one rule the tree uses today, exactly,
//! and names the design authority that replaces it.
//!
//! Some transitional authorities use a **profile as authority**. The design
//! forbids that (a profile decides which tools a session sees, never what it
//! may do); they are kept only to preserve today's behaviour, are marked
//! below, and the guard test counts their uses so they can only go down.

use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile, UaError, UaResult};

/// One authority a caller may hold. All of these are transitional (see the
/// module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority<'a> {
    /// A caller of kind human: a label in `human_identities` that
    /// authenticated as itself (bearer token, browser session, or a local CLI
    /// `--label` after confirmation).
    ///
    /// Replaced by `HubOwner` and `OrgRole` once `users` and memberships
    /// exist (`organization.v2`).
    TransitionalHuman,
    /// Operator authority over other agents' work: a **verified** caller
    /// (agent or human) that is a human, or whose label `who` is a configured
    /// human identity or lifecycle operator. `who` is the label the call site
    /// acts as; an unverified caller never holds this, whatever it claims.
    ///
    /// Replaced by `OrgRole { min: OrgAdmin }` of the target's organization,
    /// and `LifecycleOperator` for node retirement (`organization.v2`).
    TransitionalOperator { who: &'a str },
    /// Acting for another agent in dispatch: a caller that is not anonymous
    /// and is a human or runs under the `operator` profile. A configured
    /// lifecycle operator does **not** hold it.
    ///
    /// **Profile used as authority; the design forbids this; kept to preserve
    /// behaviour.** Replaced by `OrgRole { min: OrgAdmin }`.
    TransitionalProfileOperator,
    /// Seeing the hub's boundaries in the capability catalog (read-only): a
    /// human, a caller under the `coordinator` or `operator` profile, or a
    /// verified caller whose label is a configured human or lifecycle
    /// operator.
    ///
    /// **Profile used as authority; the design forbids this; kept to preserve
    /// behaviour.** Replaced by `HubOwner` for hub boundaries.
    TransitionalHubView,
    /// Reading every conversation: a **verified** caller that is a human,
    /// whose label is a configured human, or that runs under the
    /// `coordinator` profile. An unverified caller never holds it.
    ///
    /// **Profile used as authority; the design forbids this; kept to preserve
    /// behaviour.** Replaced by `OrgRole` (an auditor or admin reads the
    /// organization's mail).
    TransitionalMailboxReader,
    /// Reading every mailbox in the messaging tools: an **unverified** local
    /// caller (the local full-surface model: stdio, or HTTP with auth off),
    /// or a caller that is a human, whose verified label is a configured
    /// human, or that runs under the `coordinator` profile.
    ///
    /// **Profile used as authority; the design forbids this; kept to preserve
    /// behaviour.** Differs from [`Authority::TransitionalMailboxReader`] for
    /// an unverified caller, which holds this one but not that one. Replaced
    /// by `OrgRole`.
    TransitionalLocalMailboxReader,
}

impl Authority<'_> {
    /// A stable name for messages and logs (not the Rust variant name).
    pub fn name(&self) -> &'static str {
        match self {
            Authority::TransitionalHuman => "human",
            Authority::TransitionalOperator { .. } => "operator",
            Authority::TransitionalProfileOperator => "dispatch operator",
            Authority::TransitionalHubView => "hub view",
            Authority::TransitionalMailboxReader => "mailbox reader",
            Authority::TransitionalLocalMailboxReader => "local mailbox reader",
        }
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
    pub fn holds(&self, caller: &Caller, need: &[Authority<'_>], target_org: &str) -> bool {
        self.org_ok(caller, target_org).is_ok() && need.iter().any(|a| self.holds_one(caller, a))
    }

    /// [`Authz::holds`] as a refusal naming what was needed.
    pub fn require(&self, caller: &Caller, need: &[Authority<'_>], target_org: &str) -> UaResult<()> {
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

    fn configured(&self, label: &str) -> bool {
        self.cfg.is_human(label) || self.cfg.is_lifecycle_operator(label)
    }

    fn holds_one(&self, caller: &Caller, a: &Authority<'_>) -> bool {
        let verified = verified_label(caller);
        match *a {
            Authority::TransitionalHuman => human(caller),
            Authority::TransitionalOperator { who } => {
                verified.is_some() && (human(caller) || self.configured(who))
            }
            Authority::TransitionalProfileOperator => {
                caller.kind != ActorKind::Anonymous && (human(caller) || caller.profile == Profile::Operator)
            }
            Authority::TransitionalHubView => {
                human(caller)
                    || matches!(caller.profile, Profile::Coordinator | Profile::Operator)
                    || verified.is_some_and(|l| self.configured(l))
            }
            Authority::TransitionalMailboxReader => verified.is_some_and(|l| {
                human(caller) || self.cfg.is_human(l) || caller.profile == Profile::Coordinator
            }),
            Authority::TransitionalLocalMailboxReader => {
                verified.is_none()
                    || human(caller)
                    || verified.is_some_and(|l| self.cfg.is_human(l))
                    || caller.profile == Profile::Coordinator
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn holds(c: &Caller, a: Authority<'_>) -> bool {
        let cfg = cfg();
        Authz::new(&cfg).holds(c, &[a], DEFAULT_ORG)
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
    fn operator_needs_a_verified_caller() {
        let human = caller("operator", ActorKind::Human, Profile::Operator);
        assert!(holds(&human, Authority::TransitionalOperator { who: "operator" }));
        let fleet = caller("fleet-bot", ActorKind::Agent, Profile::Developer);
        assert!(holds(&fleet, Authority::TransitionalOperator { who: "fleet-bot" }));
        let dev = caller("builder-1", ActorKind::Agent, Profile::Operator);
        assert!(
            !holds(&dev, Authority::TransitionalOperator { who: "builder-1" }),
            "a profile is not operator"
        );
        // An unverified caller naming a configured human or lifecycle
        // operator never holds it (this is the rule a future unverified
        // call site would be held to).
        for who in ["operator", "fleet-bot"] {
            let anon = caller(who, ActorKind::Anonymous, Profile::Developer);
            assert!(!holds(&anon, Authority::TransitionalOperator { who }), "{who}");
        }
        let system = Caller::system();
        assert!(
            !holds(&system, Authority::TransitionalOperator { who: "operator" }),
            "system is not verified"
        );
    }

    #[test]
    fn profile_operator_is_the_operator_profile_and_not_a_lifecycle_operator() {
        assert!(holds(
            &caller("builder-1", ActorKind::Agent, Profile::Operator),
            Authority::TransitionalProfileOperator
        ));
        assert!(holds(
            &caller("operator", ActorKind::Human, Profile::Developer),
            Authority::TransitionalProfileOperator
        ));
        assert!(!holds(
            &caller("fleet-bot", ActorKind::Agent, Profile::Developer),
            Authority::TransitionalProfileOperator
        ));
        assert!(!holds(
            &caller("local", ActorKind::Anonymous, Profile::Operator),
            Authority::TransitionalProfileOperator
        ));
    }

    #[test]
    fn hub_view_admits_coordinator_and_operator_profiles_and_configured_labels() {
        for p in [Profile::Coordinator, Profile::Operator] {
            assert!(
                holds(&caller("local", ActorKind::Anonymous, p), Authority::TransitionalHubView),
                "{p:?}"
            );
        }
        assert!(holds(
            &caller("fleet-bot", ActorKind::Agent, Profile::Developer),
            Authority::TransitionalHubView
        ));
        assert!(!holds(
            &caller("fleet-bot", ActorKind::Anonymous, Profile::Developer),
            Authority::TransitionalHubView
        ));
        assert!(!holds(
            &caller("builder-1", ActorKind::Agent, Profile::Developer),
            Authority::TransitionalHubView
        ));
    }

    #[test]
    fn the_two_mailbox_readers_differ_only_for_an_unverified_caller() {
        let anon = caller("local", ActorKind::Anonymous, Profile::Developer);
        assert!(!holds(&anon, Authority::TransitionalMailboxReader));
        assert!(holds(&anon, Authority::TransitionalLocalMailboxReader));
        let coord = caller("lead-1", ActorKind::Agent, Profile::Coordinator);
        let dev = caller("builder-1", ActorKind::Agent, Profile::Developer);
        let human = caller("operator", ActorKind::Human, Profile::Operator);
        for (c, expect) in [(&coord, true), (&dev, false), (&human, true)] {
            assert_eq!(holds(c, Authority::TransitionalMailboxReader), expect, "{}", c.label);
            assert_eq!(holds(c, Authority::TransitionalLocalMailboxReader), expect, "{}", c.label);
        }
        // Lifecycle operators are not mailbox readers.
        let fleet = caller("fleet-bot", ActorKind::Agent, Profile::Developer);
        assert!(!holds(&fleet, Authority::TransitionalMailboxReader));
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
                &[Authority::TransitionalHuman, Authority::TransitionalOperator { who: "x" }],
                DEFAULT_ORG,
            )
            .unwrap_err();
        assert!(err.to_string().ends_with("authorities: human, operator"), "{err}");
        let coord = caller("lead-1", ActorKind::Agent, Profile::Coordinator);
        let any = [Authority::TransitionalHuman, Authority::TransitionalMailboxReader];
        assert!(authz.require(&coord, &any, DEFAULT_ORG).is_ok());
        assert!(authz.require(&coord, &[], DEFAULT_ORG).is_err(), "nothing needed is nothing held");
    }
}
