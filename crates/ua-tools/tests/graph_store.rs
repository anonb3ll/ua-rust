//! End-to-end registry tests for the C1 governed graph store tools
//! (`families/graph_store.rs`, `docs/graph.md`).

use serde_json::{Value, json};
use ua_core::identity::Transport;
use ua_core::{ActorKind, Caller, Config, DEFAULT_ORG, Profile};
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckPolicy, EdgeKind, EdgeState, EnsureNodeRequest, NodeKind,
    OwnerType, PrincipalId, Provenance, SourceKind, Visibility, assert_edge, graph_node_ensure,
};
use ua_store::graph::VisibilityScope;
use ua_tools::{Hub, builtin_registry};

fn hub_with_config(cfg: Config) -> (Hub, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut cfg = cfg;
    cfg.home = dir.path().to_path_buf();
    cfg.db_path = Some(dir.path().join("ua.db"));
    let hub = Hub::open(cfg).expect("open hub");
    // Seed a second organization (`org-b`) for isolation & pre-#2790 tests.
    hub.db()
        .write(|tx| {
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, status, created_at) \
                 VALUES ('org-b', 'org-b', 'Org B', 'active', ?1)",
                [ua_core::time::now()],
            )?;
            Ok(())
        })
        .expect("seed org-b");
    (hub, dir)
}

fn caller(label: &str, kind: ActorKind, profile: Profile, org_id: &str) -> Caller {
    Caller {
        label: label.into(),
        kind,
        profile,
        enforce_profile: true,
        session_key: None,
        transport: Transport::Http,
        org_id: org_id.into(),
    }
}

fn seed_node(
    hub: &Hub,
    org_id: &str,
    kind: NodeKind,
    ext: &str,
    vis: Visibility,
    owner: Option<(OwnerType, &str)>,
) -> String {
    let prov = if org_id == DEFAULT_ORG {
        Provenance {
            asserted_by: PrincipalId::new("builder-1").unwrap(),
            asserted_by_kind: AssertedByKind::Agent,
            source_kind: SourceKind::Event,
            source_ref: "tool:seed".into(),
        }
    } else {
        Provenance {
            asserted_by: PrincipalId::system(),
            asserted_by_kind: AssertedByKind::System,
            source_kind: SourceKind::Import,
            source_ref: "import:seed".into(),
        }
    };
    hub.db()
        .write(|tx| {
            let (row, _) = graph_node_ensure(
                tx,
                EnsureNodeRequest {
                    org_id: org_id.into(),
                    kind,
                    external_id: ext.into(),
                    display_label: Some(format!("{kind}:{ext}")),
                    visibility: vis,
                    team_id: None,
                    owner_type: owner.map(|(t, _)| t),
                    owner_id: owner.map(|(_, id)| id.to_string()),
                    provenance: prov,
                    meta_json: None,
                    max_nodes_per_org: 0,
                },
            )?;
            Ok(row.id)
        })
        .expect("seed node")
}

#[tokio::test]
async fn no_public_graph_node_upsert_and_profile_exposure_is_enforced() {
    let reg = builtin_registry();
    assert!(reg.get("graph_node_upsert").is_none(), "C1 must never expose a public graph_node_upsert tool");
    for read_tool in
        ["graph_node_get", "graph_neighbors", "graph_traverse", "graph_shortest_path", "graph_expand"]
    {
        let def = reg.get(read_tool).unwrap_or_else(|| panic!("{read_tool} must be registered"));
        assert!(def.read_only, "{read_tool} must be marked read_only");
        for p in [
            Profile::Developer,
            Profile::Lead,
            Profile::Reviewer,
            Profile::Coordinator,
            Profile::Research,
            Profile::Operator,
        ] {
            assert!(p.allows_tool(read_tool), "{p} must see {read_tool}");
        }
    }
    for write_tool in ["graph_edge_assert", "graph_edge_retract"] {
        let def = reg.get(write_tool).unwrap_or_else(|| panic!("{write_tool} must be registered"));
        assert!(!def.read_only, "{write_tool} must not be read_only");
        for p in [Profile::Public, Profile::Research, Profile::Reviewer] {
            assert!(!p.allows_tool(write_tool), "read-only profile {p} must not see {write_tool}");
        }
        for p in [Profile::Developer, Profile::Lead, Profile::Coordinator] {
            assert!(p.allows_tool(write_tool), "{p} must see {write_tool}");
        }
    }
}

#[tokio::test]
async fn generic_tools_refuse_evidence_mentions_and_other_domain_owned_edges() {
    let (hub, _dir) = hub_with_config(Config::default());
    let reg = builtin_registry();
    let dev = caller("builder-1", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);

    let note1 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "n1", Visibility::Org, None);
    let note2 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "n2", Visibility::Org, None);
    let ent1 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryEntity, "task:1", Visibility::Org, None);
    let task1 = seed_node(&hub, DEFAULT_ORG, NodeKind::Task, "1", Visibility::Org, None);
    let task2 = seed_node(&hub, DEFAULT_ORG, NodeKind::Task, "2", Visibility::Org, None);

    // Refused through graph_edge_assert: evidence, mentions, depends_on, supersedes, etc.
    for (kind, src, dst) in [
        ("evidence", &note1, &note2),
        ("mentions", &note1, &ent1),
        ("depends_on", &task1, &task2),
        ("supersedes", &note1, &note2),
        ("derives", &note1, &note2),
        ("approved_by", &task1, &task2),
        ("governed_by", &task1, &task2),
    ] {
        let err = reg
            .call(&hub, &dev, "graph_edge_assert", json!({ "src_id": src, "dst_id": dst, "kind": kind }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "denied", "kind {kind}");
        assert_eq!(err.reason_code(), Some("domain_owned_edge"), "kind {kind}");
    }

    // Seed domain-owned `evidence` and `mentions` edges via internal domain write,
    // and verify `graph_edge_retract` ALSO refuses them with `domain_owned_edge`.
    let (ev_id, men_id) = hub
        .db()
        .write(|tx| {
            let ev = assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: note1.clone(),
                    dst_id: note2.clone(),
                    kind: EdgeKind::Evidence,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: Provenance {
                        asserted_by: PrincipalId::new("builder-1").unwrap(),
                        asserted_by_kind: AssertedByKind::Agent,
                        source_kind: SourceKind::Mirror,
                        source_ref: "mirror:memory:1".into(),
                    },
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            let men = assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: note1.clone(),
                    dst_id: ent1.clone(),
                    kind: EdgeKind::Mentions,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: Provenance {
                        asserted_by: PrincipalId::new("builder-1").unwrap(),
                        asserted_by_kind: AssertedByKind::Agent,
                        source_kind: SourceKind::Mirror,
                        source_ref: "mirror:memory:1".into(),
                    },
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            Ok((ev.id, men.id))
        })
        .unwrap();

    for edge_id in [ev_id, men_id] {
        let err =
            reg.call(&hub, &dev, "graph_edge_retract", json!({ "edge_id": edge_id })).await.unwrap_err();
        assert_eq!(err.code(), "denied");
        assert_eq!(err.reason_code(), Some("domain_owned_edge"));
    }
}

#[tokio::test]
async fn generic_assert_retract_authority_and_ledger_linkage() {
    let cfg = Config {
        human_identities: vec!["operator".into()],
        lifecycle_operators: Some(vec!["fleet-bot".into()]),
        ..Config::default()
    };
    let (hub, _dir) = hub_with_config(cfg);
    let reg = builtin_registry();

    let author = caller("builder-1", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let other_agent = caller("builder-2", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let human_op = caller("operator", ActorKind::Human, Profile::Developer, DEFAULT_ORG);
    let fleet_op = caller("fleet-bot", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let anon = caller("local", ActorKind::Anonymous, Profile::Developer, DEFAULT_ORG);

    let n1 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "a1", Visibility::Org, None);
    let n2 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "a2", Visibility::Org, None);
    let n3 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "a3", Visibility::Org, None);
    let plan1 = seed_node(&hub, DEFAULT_ORG, NodeKind::Plan, "p1", Visibility::Org, None);
    let task1 = seed_node(&hub, DEFAULT_ORG, NodeKind::Task, "t1", Visibility::Org, None);

    // Anonymous caller cannot write.
    let anon_err = reg
        .call(&hub, &anon, "graph_edge_assert", json!({ "src_id": n1, "dst_id": n2, "kind": "extends" }))
        .await
        .unwrap_err();
    assert_eq!(anon_err.code(), "denied");
    assert_eq!(anon_err.reason_code(), Some("unverified_identity"));

    // Unknown org_id field rejected (deny_unknown_fields).
    let unk_err = reg
        .call(&hub, &author, "graph_node_get", json!({ "node_id": n1, "org_id": "org-b" }))
        .await
        .unwrap_err();
    assert_eq!(unk_err.code(), "invalid_argument");

    // Generic `contradicts` cannot be asserted as `active`; defaults to `proposed`.
    let active_contradict = reg
        .call(
            &hub,
            &author,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n2, "kind": "contradicts", "state": "active" }),
        )
        .await
        .unwrap_err();
    assert_eq!(active_contradict.code(), "invalid_argument");

    let prop = reg
        .call(
            &hub,
            &author,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n2, "kind": "contradicts" }),
        )
        .await
        .unwrap();
    assert_eq!(prop["edge"]["state"], "proposed");
    assert!(prop["edge"]["source_ref"].as_str().unwrap().starts_with("event:"));

    // Generic `extends` and `plan_tracks` succeed.
    let ext1 = reg
        .call(&hub, &author, "graph_edge_assert", json!({ "src_id": n1, "dst_id": n2, "kind": "extends" }))
        .await
        .unwrap();
    let e1_id = ext1["edge"]["id"].as_str().unwrap().to_string();
    let ext2 = reg
        .call(&hub, &author, "graph_edge_assert", json!({ "src_id": n2, "dst_id": n3, "kind": "extends" }))
        .await
        .unwrap();
    let e2_id = ext2["edge"]["id"].as_str().unwrap().to_string();
    let pt = reg
        .call(
            &hub,
            &author,
            "graph_edge_assert",
            json!({ "src_id": plan1, "dst_id": task1, "kind": "plan_tracks" }),
        )
        .await
        .unwrap();
    assert_eq!(pt["edge"]["kind"], "plan_tracks");

    // Another agent cannot retract author's edge.
    let deny =
        reg.call(&hub, &other_agent, "graph_edge_retract", json!({ "edge_id": e1_id })).await.unwrap_err();
    assert_eq!(deny.code(), "denied");
    assert_eq!(deny.reason_code(), Some("authority_required"));

    // Verified human Operator CAN retract author's edge; original asserted_by stays intact.
    let retracted_by_op =
        reg.call(&hub, &human_op, "graph_edge_retract", json!({ "edge_id": e1_id })).await.unwrap();
    assert_eq!(retracted_by_op["edge"]["asserted_by"], "builder-1");
    assert!(retracted_by_op["edge"]["valid_to"].is_string());

    // LifecycleOperator CAN retract another edge too.
    let retracted_by_fleet =
        reg.call(&hub, &fleet_op, "graph_edge_retract", json!({ "edge_id": e2_id })).await.unwrap();
    assert_eq!(retracted_by_fleet["edge"]["asserted_by"], "builder-1");
    assert!(retracted_by_fleet["edge"]["valid_to"].is_string());

    // Verify ledger events recorded retractor cleanly.
    let retracted_events: Vec<(String, String)> = hub
        .db()
        .read(|conn| {
            let mut stmt = conn.prepare(
                "SELECT originator, payload FROM event_log WHERE channel = 'agent.graph.edge_retracted' ORDER BY seq",
            )?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap();
    assert_eq!(retracted_events.len(), 2);
    let p0: Value = serde_json::from_str(&retracted_events[0].1).unwrap();
    let p1: Value = serde_json::from_str(&retracted_events[1].1).unwrap();
    assert_eq!(p0["retracted_by"], "operator");
    assert_eq!(p1["retracted_by"], "fleet-bot");
}

#[tokio::test]
async fn cross_org_zero_oracle_and_non_default_org_write_refusal() {
    let (hub, _dir) = hub_with_config(Config::default());
    let reg = builtin_registry();

    let org_a_dev = caller("builder-1", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let org_b_dev = caller("builder-b", ActorKind::Agent, Profile::Developer, "org-b");

    let n_a = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "only-a", Visibility::Org, None);
    let n_b1 = seed_node(&hub, "org-b", NodeKind::MemoryNote, "only-b1", Visibility::Org, None);
    let n_b2 = seed_node(&hub, "org-b", NodeKind::MemoryNote, "only-b2", Visibility::Org, None);

    // Non-default org generic write is refused with principal_id_required.
    let w_err = reg
        .call(
            &hub,
            &org_b_dev,
            "graph_edge_assert",
            json!({ "src_id": n_b1, "dst_id": n_b2, "kind": "extends" }),
        )
        .await
        .unwrap_err();
    assert_eq!(w_err.code(), "denied");
    assert_eq!(w_err.reason_code(), Some("principal_id_required"));

    // Cross-org reads from org A targeting org B's node match nonexistent ID identically.
    let foreign_get =
        reg.call(&hub, &org_a_dev, "graph_node_get", json!({ "node_id": n_b1 })).await.unwrap_err();
    let missing_get = reg
        .call(&hub, &org_a_dev, "graph_node_get", json!({ "node_id": "01NONEXISTENT0000000000000" }))
        .await
        .unwrap_err();
    assert_eq!(foreign_get.code(), "not_found");
    assert_eq!(foreign_get.to_string(), missing_get.to_string());

    let foreign_sp = reg
        .call(&hub, &org_a_dev, "graph_shortest_path", json!({ "from_id": n_a, "to_id": n_b1 }))
        .await
        .unwrap_err();
    let missing_sp = reg
        .call(
            &hub,
            &org_a_dev,
            "graph_shortest_path",
            json!({ "from_id": n_a, "to_id": "01NONEXISTENT0000000000000" }),
        )
        .await
        .unwrap_err();
    assert_eq!(foreign_sp.code(), "not_found");
    assert_eq!(foreign_sp.to_string(), missing_sp.to_string());

    // Traversal and expand silently return empty results on foreign seed IDs.
    let trav = reg.call(&hub, &org_a_dev, "graph_traverse", json!({ "seed_ids": [n_b1] })).await.unwrap();
    assert!(trav["nodes"].as_array().unwrap().is_empty());

    let exp = reg
        .call(&hub, &org_a_dev, "graph_expand", json!({ "seeds": [{ "node_id": n_b1, "weight": 1.0 }] }))
        .await
        .unwrap();
    assert!(exp["results"].as_array().unwrap().is_empty());

    // Private node owned by builder-1 is invisible to builder-2 via graph_node_get.
    let priv_id = seed_node(
        &hub,
        DEFAULT_ORG,
        NodeKind::MemoryNote,
        "priv-note",
        Visibility::Private,
        Some((OwnerType::Agent, "builder-1")),
    );
    let other = caller("builder-2", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let priv_err = reg.call(&hub, &other, "graph_node_get", json!({ "node_id": priv_id })).await.unwrap_err();
    assert_eq!(priv_err.code(), "not_found");
    assert_eq!(priv_err.to_string(), missing_get.to_string());
    let own_ok = reg.call(&hub, &org_a_dev, "graph_node_get", json!({ "node_id": priv_id })).await.unwrap();
    assert_eq!(own_ok["node"]["id"], priv_id);

    // Endpoint-kind error via registry tool.
    let task1 = seed_node(&hub, DEFAULT_ORG, NodeKind::Task, "tk-1", Visibility::Org, None);
    let kind_err = reg
        .call(
            &hub,
            &org_a_dev,
            "graph_edge_assert",
            json!({ "src_id": n_a, "dst_id": task1, "kind": "extends" }),
        )
        .await
        .unwrap_err();
    assert_eq!(kind_err.code(), "invalid_argument");
    assert_eq!(kind_err.reason_code(), Some("invalid_endpoint_kind"));
}

#[tokio::test]
async fn retract_checks_asserted_by_kind_and_tool_layer_refusals_are_not_masked() {
    let cfg = Config { graph_max_live_edges_per_node: 2, ..Config::default() };
    let (hub, _dir) = hub_with_config(cfg);
    let reg = builtin_registry();

    let human_same_label = caller("shared-principal", ActorKind::Human, Profile::Developer, DEFAULT_ORG);
    let agent_same_label = caller("shared-principal", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let other_agent = caller("builder-2", ActorKind::Agent, Profile::Developer, DEFAULT_ORG);
    let org_b_dev = caller("builder-b", ActorKind::Agent, Profile::Developer, "org-b");

    let n1 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "r1", Visibility::Org, None);
    let n2 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "r2", Visibility::Org, None);
    let n3 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "r3", Visibility::Org, None);
    let n4 = seed_node(&hub, DEFAULT_ORG, NodeKind::MemoryNote, "r4", Visibility::Org, None);

    // 1. Generic graph_edge_assert rejects assertion_scope (unknown field via deny_unknown_fields).
    let scope_err = reg
        .call(
            &hub,
            &agent_same_label,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n2, "kind": "extends", "assertion_scope": "note:1" }),
        )
        .await
        .unwrap_err();
    assert_eq!(scope_err.code(), "invalid_argument");

    // 2. Retract compares BOTH asserted_by AND asserted_by_kind:
    //    Human "shared-principal" asserts edge -> Agent with identical label CANNOT retract it.
    let human_edge = reg
        .call(
            &hub,
            &human_same_label,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n2, "kind": "extends" }),
        )
        .await
        .unwrap();
    let human_edge_id = human_edge["edge"]["id"].as_str().unwrap().to_string();
    assert_eq!(human_edge["edge"]["asserted_by"], "shared-principal");
    assert_eq!(human_edge["edge"]["asserted_by_kind"], "person");

    let spoof_err = reg
        .call(&hub, &agent_same_label, "graph_edge_retract", json!({ "edge_id": human_edge_id }))
        .await
        .unwrap_err();
    assert_eq!(spoof_err.code(), "denied");
    assert_eq!(spoof_err.reason_code(), Some("authority_required"));

    // The originating Human CAN retract their own edge.
    let retracted = reg
        .call(&hub, &human_same_label, "graph_edge_retract", json!({ "edge_id": human_edge_id }))
        .await
        .unwrap();
    assert!(retracted["edge"]["valid_to"].is_string());

    // 3. Tool-layer refusal tests that CANNOT be masked by ua-graph:
    //    Passing an invalid `state: "bogus"` forces `parse_edge_state` to return `invalid_argument`
    //    if either the `ua-tools` non-default-org check or the `ua-tools` domain-owned check is removed.
    let tool_org_err = reg
        .call(
            &hub,
            &org_b_dev,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n2, "kind": "extends", "state": "bogus" }),
        )
        .await
        .unwrap_err();
    assert_eq!(tool_org_err.code(), "denied");
    assert_eq!(tool_org_err.reason_code(), Some("principal_id_required"));

    let tool_domain_err = reg
        .call(
            &hub,
            &agent_same_label,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n2, "kind": "evidence", "state": "bogus" }),
        )
        .await
        .unwrap_err();
    assert_eq!(tool_domain_err.code(), "denied");
    assert_eq!(tool_domain_err.reason_code(), Some("domain_owned_edge"));

    // Retract tool-layer non-default-org refusal runs before empty edge_id validation.
    let retract_org_err =
        reg.call(&hub, &org_b_dev, "graph_edge_retract", json!({ "edge_id": "" })).await.unwrap_err();
    assert_eq!(retract_org_err.code(), "denied");
    assert_eq!(retract_org_err.reason_code(), Some("principal_id_required"));

    // Retract tool-layer domain-owned refusal runs before Authz::require (`authority_required`):
    // a different non-operator agent gets `domain_owned_edge`, not `authority_required`.
    let dom_edge_id = hub
        .db()
        .write(|tx| {
            let e = assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: n1.clone(),
                    dst_id: n2.clone(),
                    kind: EdgeKind::Evidence,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: Provenance {
                        asserted_by: PrincipalId::new("builder-1").unwrap(),
                        asserted_by_kind: AssertedByKind::Agent,
                        source_kind: SourceKind::Mirror,
                        source_ref: "mirror:memory:99".into(),
                    },
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 0,
                    max_live_edges_per_node: 0,
                    cycle_bounds: CycleCheckPolicy::default(),
                },
            )?;
            Ok(e.id)
        })
        .unwrap();
    let retract_dom_err = reg
        .call(&hub, &other_agent, "graph_edge_retract", json!({ "edge_id": dom_edge_id }))
        .await
        .unwrap_err();
    assert_eq!(retract_dom_err.code(), "denied");
    assert_eq!(retract_dom_err.reason_code(), Some("domain_owned_edge"));

    // 4. Per-node live-edge cap wired from Config (`graph_max_live_edges_per_node = 2`):
    //    n1 already has 1 live edge (`dom_edge_id` above; `human_edge_id` was retracted).
    //    Adding n1 -> n3 reaches 2 live edges; adding n1 -> n4 is refused with `node_edge_limit_exceeded`.
    reg.call(
        &hub,
        &agent_same_label,
        "graph_edge_assert",
        json!({ "src_id": n1, "dst_id": n3, "kind": "extends" }),
    )
    .await
    .unwrap();
    let cap_err = reg
        .call(
            &hub,
            &agent_same_label,
            "graph_edge_assert",
            json!({ "src_id": n1, "dst_id": n4, "kind": "extends" }),
        )
        .await
        .unwrap_err();
    assert_eq!(cap_err.code(), "denied");
    assert_eq!(cap_err.reason_code(), Some("node_edge_limit_exceeded"));

    // 5. Verified caller whose label is the reserved `'system'` literal (any case)
    //    is refused on both graph_edge_assert and graph_edge_retract.
    for reserved in ["system", "SYSTEM"] {
        let spoof = caller(reserved, ActorKind::Agent, Profile::Coordinator, DEFAULT_ORG);
        let err = reg
            .call(&hub, &spoof, "graph_edge_assert", json!({ "src_id": n3, "dst_id": n4, "kind": "extends" }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument", "{reserved}: {err:?}");
        assert_eq!(err.reason_code(), Some("reserved_principal_id"), "{reserved}: {err:?}");

        let retract_err = reg
            .call(&hub, &spoof, "graph_edge_retract", json!({ "edge_id": "nonexistent" }))
            .await
            .unwrap_err();
        assert_eq!(retract_err.code(), "invalid_argument", "{reserved}: {retract_err:?}");
        assert_eq!(retract_err.reason_code(), Some("reserved_principal_id"), "{reserved}: {retract_err:?}");
    }
}
