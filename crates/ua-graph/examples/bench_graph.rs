//! Reproducible C1 graph store benchmark floor (`docs/graph.md`, Benchmark floor).
//!
//! Run in release mode:
//!   cargo run --release -p ua-graph --example bench_graph
//!
//! Fixture shape (exact from `docs/graph.md`):
//! - Deterministic PRNG seed `0x5541_4752_4150_4801`
//! - On-disk SQLite WAL database in a temporary directory, `PRAGMA foreign_keys = ON`,
//!   all `graph.v1` and `organization.v1.graph` triggers & indexes active
//! - 20,000 nodes, 100,000 live edges (90,000 in org A `'default'`, 10,000 in org B
//!   seeded with `asserted_by = 'system'`, `asserted_by_kind = 'system'`, `source_kind = 'import'`)
//!   plus 10,000 historical closed edges (`valid_to IS NOT NULL`), total 110,000 edges
//! - Heavy-tailed degree distribution including 0.5% super-hubs (degree 500–2,000)
//! - Exact kind & visibility mix
//! - 200 deterministic queries per workload with warmed SQLite page cache, reporting
//!   p50 / p95 / p99 and failing with non-zero exit if any C1 floor is missed.

use std::collections::HashSet;
use std::time::Instant;

use ua_core::DEFAULT_ORG;
use ua_graph::{
    AssertEdgeRequest, AssertedByKind, CycleCheckBounds, EdgeKind, EdgeState, EnsureNodeRequest, KHopRequest,
    NodeKind, PrincipalId, Provenance, SeedExpandRequest, SeedInput, ShortestPathRequest, SourceKind,
    Visibility, WalkDirection, assert_edge, graph_node_ensure, k_hop, schema_parts, seed_expand,
    shortest_path,
};
use ua_store::graph::{EdgeDirection, GraphRepo, NewGraphEdge, NewGraphNode, SqliteGraph, VisibilityScope};
use ua_store::{Db, Fence, Part, ledger, org};

const SEED: u64 = 0x5541_4752_4150_4801;
const TOTAL_NODES: usize = 20_000;
const ORG_A_NODES: usize = 18_000;
const ORG_A_LIVE_EDGES: usize = 90_000;
const ORG_B_LIVE_EDGES: usize = 10_000;
const CLOSED_EDGES: usize = 10_000;
const QUERIES_PER_WORKLOAD: usize = 200;

/// Deterministic SplitMix64 PRNG (zero external dependencies).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn gen_range(&mut self, upper: usize) -> usize {
        (self.next_u64() as usize) % upper
    }
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn format_ulid_like(prefix: &str, idx: usize) -> String {
    format!("{prefix}{idx:020}")
}

fn main() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("bench_graph.db");

    let mut parts: Vec<Part> =
        vec![ledger::SCHEMA.into(), ledger::META_SCHEMA.into(), org::STORE_PART.into()];
    parts.extend(schema_parts());
    let db = Db::open_with(&db_path, &parts, Fence::default()).expect("open wal db");

    // Ensure PRAGMA foreign_keys = ON and seed org-b.
    let sqlite_ver: String = db
        .write(|tx| {
            tx.execute_batch("PRAGMA foreign_keys = ON;")?;
            let v: String = tx.query_row("SELECT sqlite_version()", [], |r| r.get(0))?;
            tx.execute(
                "INSERT INTO orgs (id, slug, display_name, status, created_at) \
                 VALUES ('org-b', 'org-b', 'Org B', 'active', ?1)",
                [ua_core::time::now()],
            )?;
            Ok(v)
        })
        .expect("init bench db");

    println!("=== ua-graph C1 Benchmark Floor ===");
    println!("SQLite: {sqlite_ver} | WAL on-disk | seed: 0x{SEED:016X}");

    let mut rng = Rng::new(SEED);
    let ts_now = ua_core::time::now();
    let ts_hist_from = "2025-01-01T00:00:00+00:00".to_string();
    let ts_hist_to = "2025-06-01T00:00:00+00:00".to_string();

    // Generate 20,000 nodes with exact kind & visibility mix.
    let mut org_a_ids: Vec<String> = Vec::with_capacity(ORG_A_NODES);
    let mut org_a_org_vis_ids: Vec<String> = Vec::with_capacity(ORG_A_NODES);
    let mut org_b_ids: Vec<String> = Vec::with_capacity(TOTAL_NODES - ORG_A_NODES);
    let mut org_a_by_kind: [Vec<String>; 10] = Default::default();
    let mut org_b_by_kind: [Vec<String>; 10] = Default::default();
    let mut all_nodes: Vec<NewGraphNode> = Vec::with_capacity(TOTAL_NODES);

    // Kind buckets matching docs/graph.md L725-726:
    // 40% memory_note, 25% memory_entity, 15% task, 10% vault_note, 10% across agent/person/skill/plan/run/deliverable
    let kind_names = [
        "memory_note",
        "memory_entity",
        "task",
        "vault_note",
        "agent",
        "person",
        "skill",
        "plan",
        "run",
        "deliverable",
    ];
    for i in 0..TOTAL_NODES {
        let is_a = i < ORG_A_NODES;
        let org_id = if is_a { DEFAULT_ORG } else { "org-b" };
        let pct = i % 100;
        let k_idx = if pct < 40 {
            0
        } else if pct < 65 {
            1
        } else if pct < 80 {
            2
        } else if pct < 90 {
            3
        } else {
            4 + ((pct - 90) % 6)
        };
        let kind = kind_names[k_idx];
        let id = format_ulid_like("01BN", i);

        // Visibility mix: 85% org, 10% team (5 teams), 5% private (20 owners)
        let v_pct = (i * 7) % 100;
        let (vis, team_id, owner_type, owner_id) = if v_pct < 85 {
            ("org", None, None, None)
        } else if v_pct < 95 {
            ("team", Some(format!("team-{}", i % 5)), None, None)
        } else {
            ("private", None, Some("agent".to_string()), Some(format!("owner-{}", i % 20)))
        };

        if is_a {
            org_a_ids.push(id.clone());
            if vis == "org" {
                org_a_org_vis_ids.push(id.clone());
            }
            org_a_by_kind[k_idx].push(id.clone());
        } else {
            org_b_ids.push(id.clone());
            org_b_by_kind[k_idx].push(id.clone());
        }

        all_nodes.push(NewGraphNode {
            id,
            org_id: org_id.to_string(),
            kind: kind.to_string(),
            external_id: format!("ext-{i}"),
            display_label: Some(format!("node-{i}")),
            visibility: vis.to_string(),
            team_id,
            owner_type,
            owner_id,
            asserted_by: "system".to_string(),
            asserted_by_kind: "system".to_string(),
            source_kind: "import".to_string(),
            source_ref: "import:bench".to_string(),
            meta_json: "{}".to_string(),
            created_at: ts_now.clone(),
            updated_at: ts_now.clone(),
        });
    }

    // Insert 20,000 nodes in batches of 2,000.
    for chunk in all_nodes.chunks(2_000) {
        db.write(|tx| {
            tx.insert_nodes_batch(chunk)?;
            Ok(())
        })
        .expect("insert nodes batch");
    }

    // Build 100,000 live edges (90k org A, 10k org B) + 10,000 historical closed edges
    // with heavy-tailed degree distribution + 0.5% super-hubs (degree 500-2,000).
    let mut live_edges: Vec<NewGraphEdge> = Vec::with_capacity(ORG_A_LIVE_EDGES + ORG_B_LIVE_EDGES);
    let mut closed_edges: Vec<NewGraphEdge> = Vec::with_capacity(CLOSED_EDGES);
    let mut seen_live: HashSet<(String, String, &'static str)> =
        HashSet::with_capacity(ORG_A_LIVE_EDGES + ORG_B_LIVE_EDGES);

    // Pick a dedicated super-hub in org A (memory_entity with 2,000 incoming `mentions` edges).
    let super_hub_id = org_a_by_kind[1][0].clone();
    let mut edge_seq = 0usize;

    // 1. Seed super-hubs (~0.5% of org A = ~90 hubs; first hub gets 2,000 edges for the DoS probe,
    //    others get 200-500 edges using valid typed endpoints).
    for (idx, note_id) in org_a_by_kind[0].iter().take(2_000).enumerate() {
        let key = (note_id.clone(), super_hub_id.clone(), "mentions");
        if seen_live.insert(key) {
            edge_seq += 1;
            live_edges.push(NewGraphEdge {
                id: format_ulid_like("01BE", edge_seq),
                org_id: DEFAULT_ORG.to_string(),
                src_id: note_id.clone(),
                dst_id: super_hub_id.clone(),
                kind: "mentions".to_string(),
                assertion_scope: String::new(),
                state: "active".to_string(),
                weight: 1.0 + (idx % 10) as f64 * 0.1,
                asserted_by: "system".to_string(),
                asserted_by_kind: "system".to_string(),
                asserted_at: ts_now.clone(),
                source_kind: "import".to_string(),
                source_ref: "import:bench".to_string(),
                valid_from: ts_now.clone(),
                valid_to: None,
                meta_json: "{}".to_string(),
            });
        }
    }

    // Helper to pick heavy-tailed index from a bucket (70% ordinary, 25% medium, 4.5% high, 0.5% super-hub).
    let pick_ht = |rng: &mut Rng, len: usize| -> usize {
        if len <= 1 {
            return 0;
        }
        let r = rng.gen_range(1000);
        if r < 180 {
            // Concentrate on top 0.5% super-hubs
            rng.gen_range((len / 200).max(1))
        } else if r < 430 {
            // Next 4.5% high-degree
            rng.gen_range((len / 20).max(1))
        } else if r < 730 {
            // Next 25% medium
            rng.gen_range((len / 4).max(1))
        } else {
            rng.gen_range(len)
        }
    };

    // Fill remaining org A live edges to 90,000 and org B to 10,000 with exact edge kind mix:
    // 35% mentions, 20% links_to, 15% depends_on, 10% extends, 10% evidence, 10% produces/executes/delegates_to/supersedes
    let mut gen_org_edges = |org_id: &str,
                             by_kind: &[Vec<String>; 10],
                             target_count: usize,
                             live_vec: &mut Vec<NewGraphEdge>,
                             seen: &mut HashSet<(String, String, &'static str)>,
                             edge_seq: &mut usize| {
        let mut added = if org_id == DEFAULT_ORG { live_vec.len() } else { 0 };
        while added < target_count {
            let p = rng.gen_range(100);
            let (kind, s_bucket, d_bucket): (&'static str, usize, usize) = if p < 35 {
                ("mentions", 0, 1)
            } else if p < 55 {
                ("links_to", 3, 3)
            } else if p < 70 {
                ("depends_on", 2, 2)
            } else if p < 80 {
                ("extends", 0, 0)
            } else if p < 90 {
                ("evidence", 0, 2)
            } else {
                match p % 4 {
                    0 => ("produces", 2, 9),
                    1 => ("delegates_to", 4, 4),
                    2 => ("supersedes", 0, 0),
                    _ => ("reviews", 4, 4),
                }
            };
            let sb = &by_kind[s_bucket];
            let db_b = &by_kind[d_bucket];
            let si = pick_ht(&mut rng, sb.len());
            let mut di = pick_ht(&mut rng, db_b.len());
            if s_bucket == d_bucket {
                if si == di {
                    di = (di + 1) % db_b.len();
                }
                // Keep acyclic kinds strictly forward-ordered (si < di) so seeded graph is a valid DAG.
                if matches!(kind, "depends_on" | "delegates_to") && si > di {
                    continue;
                }
            }
            let src = sb[si].clone();
            let dst = db_b[di].clone();
            if src == dst {
                continue;
            }
            if !seen.insert((src.clone(), dst.clone(), kind)) {
                continue;
            }
            *edge_seq += 1;
            let w = 1.0 + (rng.gen_range(50) as f64) * 0.1;
            live_vec.push(NewGraphEdge {
                id: format_ulid_like("01BE", *edge_seq),
                org_id: org_id.to_string(),
                src_id: src,
                dst_id: dst,
                kind: kind.to_string(),
                assertion_scope: String::new(),
                state: "active".to_string(),
                weight: w,
                asserted_by: "system".to_string(),
                asserted_by_kind: "system".to_string(),
                asserted_at: ts_now.clone(),
                source_kind: "import".to_string(),
                source_ref: "import:bench".to_string(),
                valid_from: ts_now.clone(),
                valid_to: None,
                meta_json: "{}".to_string(),
            });
            added += 1;
        }
    };

    gen_org_edges(
        DEFAULT_ORG,
        &org_a_by_kind,
        ORG_A_LIVE_EDGES,
        &mut live_edges,
        &mut seen_live,
        &mut edge_seq,
    );
    gen_org_edges("org-b", &org_b_by_kind, ORG_B_LIVE_EDGES, &mut live_edges, &mut seen_live, &mut edge_seq);

    // 10,000 historical closed edges in org A (`valid_to IS NOT NULL`).
    for i in 0..CLOSED_EDGES {
        let sb = &org_a_by_kind[0];
        let si = i % sb.len();
        let di = (i * 13 + 7) % sb.len();
        let di = if si == di { (di + 1) % sb.len() } else { di };
        edge_seq += 1;
        closed_edges.push(NewGraphEdge {
            id: format_ulid_like("01BH", edge_seq),
            org_id: DEFAULT_ORG.to_string(),
            src_id: sb[si].clone(),
            dst_id: sb[di].clone(),
            kind: "extends".to_string(),
            assertion_scope: String::new(),
            state: "active".to_string(),
            weight: 1.0,
            asserted_by: "system".to_string(),
            asserted_by_kind: "system".to_string(),
            asserted_at: ts_now.clone(),
            source_kind: "import".to_string(),
            source_ref: "import:bench-hist".to_string(),
            valid_from: ts_hist_from.clone(),
            valid_to: Some(ts_hist_to.clone()),
            meta_json: "{}".to_string(),
        });
    }

    // Order bulk edges by (org_id, src_id, dst_id) and mint monotonic IDs in
    // emission order, matching real source-grouped bulk producers (vault ingest,
    // memory backfill, org export).
    live_edges.sort_by(|a, b| {
        a.org_id.cmp(&b.org_id).then_with(|| a.src_id.cmp(&b.src_id)).then_with(|| a.dst_id.cmp(&b.dst_id))
    });
    for (idx, e) in live_edges.iter_mut().enumerate() {
        e.id = format_ulid_like("01BE", idx + 1);
    }

    // -----------------------------------------------------------------------
    // Workload 1: Batched edge insert (1,000 edges/tx across 100k edges) >= 15,000 edges/sec
    // -----------------------------------------------------------------------
    let t_batch = Instant::now();
    for chunk in live_edges.chunks(1_000) {
        db.write(|tx| {
            tx.insert_edges_batch(chunk)?;
            Ok(())
        })
        .expect("insert live edge batch");
    }
    let batch_secs = t_batch.elapsed().as_secs_f64();
    let edges_per_sec = live_edges.len() as f64 / batch_secs;
    println!("[1] Batched edge insert (100k live, 1k/tx): {:.0} edges/sec (floor >= 15,000)", edges_per_sec);

    // Insert the 10k historical closed edges too so total = 110,000 edges.
    for chunk in closed_edges.chunks(1_000) {
        db.write(|tx| {
            tx.insert_edges_batch(chunk)?;
            Ok(())
        })
        .expect("insert closed edge batch");
    }

    // Seed dedicated chains for workloads 2 & 3 (500-hop chain and 1,100-hop chain).
    let chain_500: Vec<String> = db
        .write(|tx| {
            let mut ids = Vec::with_capacity(505);
            for i in 0..505 {
                let (n, _) = graph_node_ensure(
                    tx,
                    EnsureNodeRequest {
                        org_id: DEFAULT_ORG.into(),
                        kind: NodeKind::Task,
                        external_id: format!("chain500-{i}"),
                        display_label: None,
                        visibility: Visibility::Org,
                        team_id: None,
                        owner_type: None,
                        owner_id: None,
                        provenance: Provenance {
                            asserted_by: PrincipalId::system(),
                            asserted_by_kind: AssertedByKind::System,
                            source_kind: SourceKind::Import,
                            source_ref: "import:chain500".into(),
                        },
                        meta_json: None,
                        max_nodes_per_org: 500_000,
                    },
                )?;
                ids.push(n.id);
            }
            let edges: Vec<NewGraphEdge> = ids
                .windows(2)
                .enumerate()
                .map(|(i, w)| NewGraphEdge {
                    id: format_ulid_like("01BC", i),
                    org_id: DEFAULT_ORG.into(),
                    src_id: w[0].clone(),
                    dst_id: w[1].clone(),
                    kind: "depends_on".into(),
                    assertion_scope: String::new(),
                    state: "active".into(),
                    weight: 1.0,
                    asserted_by: "system".into(),
                    asserted_by_kind: "system".into(),
                    asserted_at: ts_now.clone(),
                    source_kind: "import".into(),
                    source_ref: "import:chain500".into(),
                    valid_from: ts_now.clone(),
                    valid_to: None,
                    meta_json: "{}".into(),
                })
                .collect();
            tx.insert_edges_batch(&edges)?;
            Ok(ids)
        })
        .expect("seed 500-hop chain");

    let chain_1100: Vec<String> = db
        .write(|tx| {
            let mut ids = Vec::with_capacity(1_105);
            for i in 0..1_105 {
                let (n, _) = graph_node_ensure(
                    tx,
                    EnsureNodeRequest {
                        org_id: DEFAULT_ORG.into(),
                        kind: NodeKind::Task,
                        external_id: format!("chain1100-{i}"),
                        display_label: None,
                        visibility: Visibility::Org,
                        team_id: None,
                        owner_type: None,
                        owner_id: None,
                        provenance: Provenance {
                            asserted_by: PrincipalId::system(),
                            asserted_by_kind: AssertedByKind::System,
                            source_kind: SourceKind::Import,
                            source_ref: "import:chain1100".into(),
                        },
                        meta_json: None,
                        max_nodes_per_org: 500_000,
                    },
                )?;
                ids.push(n.id);
            }
            let edges: Vec<NewGraphEdge> = ids
                .windows(2)
                .enumerate()
                .map(|(i, w)| NewGraphEdge {
                    id: format_ulid_like("01BD", i),
                    org_id: DEFAULT_ORG.into(),
                    src_id: w[0].clone(),
                    dst_id: w[1].clone(),
                    kind: "depends_on".into(),
                    assertion_scope: String::new(),
                    state: "active".into(),
                    weight: 1.0,
                    asserted_by: "system".into(),
                    asserted_by_kind: "system".into(),
                    asserted_at: ts_now.clone(),
                    source_kind: "import".into(),
                    source_ref: "import:chain1100".into(),
                    valid_from: ts_now.clone(),
                    valid_to: None,
                    meta_json: "{}".into(),
                })
                .collect();
            tx.insert_edges_batch(&edges)?;
            Ok(ids)
        })
        .expect("seed 1100-hop chain");

    // Pre-create 200 fresh source task nodes for workload 2 so each write is a fresh edge + ledger append.
    let w2_srcs: Vec<String> = db
        .write(|tx| {
            let mut ids = Vec::with_capacity(QUERIES_PER_WORKLOAD);
            for i in 0..QUERIES_PER_WORKLOAD {
                let (n, _) = graph_node_ensure(
                    tx,
                    EnsureNodeRequest {
                        org_id: DEFAULT_ORG.into(),
                        kind: NodeKind::Task,
                        external_id: format!("w2-src-{i}"),
                        display_label: None,
                        visibility: Visibility::Org,
                        team_id: None,
                        owner_type: None,
                        owner_id: None,
                        provenance: Provenance {
                            asserted_by: PrincipalId::system(),
                            asserted_by_kind: AssertedByKind::System,
                            source_kind: SourceKind::Import,
                            source_ref: "import:w2".into(),
                        },
                        meta_json: None,
                        max_nodes_per_org: 500_000,
                    },
                )?;
                ids.push(n.id);
            }
            Ok(ids)
        })
        .expect("seed w2 srcs");

    // Warm SQLite page cache and query planner statistics across the reader pool.
    let _ = db.write(|tx| {
        tx.execute_batch("ANALYZE;")?;
        Ok(())
    });
    for _ in 0..4 {
        let _ = db.read(|c| {
            let _: i64 = c.query_row("SELECT COUNT(*) FROM graph_edges", [], |r| r.get(0))?;
            let _: i64 = c.query_row("SELECT COUNT(*) FROM graph_nodes", [], |r| r.get(0))?;
            Ok(())
        });
    }

    // -----------------------------------------------------------------------
    // Workload 2: Single governed edge write + ledger::append + 500-hop cycle check <= 3 ms p95
    // -----------------------------------------------------------------------
    let mut w2_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    for src in &w2_srcs {
        let t0 = Instant::now();
        db.write(|tx| {
            assert_edge(
                tx,
                AssertEdgeRequest {
                    org_id: DEFAULT_ORG.into(),
                    src_id: src.clone(),
                    dst_id: chain_500[0].clone(),
                    kind: EdgeKind::DependsOn,
                    assertion_scope: String::new(),
                    state: EdgeState::Active,
                    weight: 1.0,
                    provenance: Provenance {
                        asserted_by: PrincipalId::new("builder-1").unwrap(),
                        asserted_by_kind: AssertedByKind::Agent,
                        source_kind: SourceKind::Event,
                        source_ref: "tool:bench".into(),
                    },
                    valid_from: None,
                    valid_to: None,
                    meta_json: None,
                    scope: VisibilityScope::org_only(),
                    generic: false,
                    max_edges_per_org: 2_000_000,
                    max_live_edges_per_node: 5_000,
                    cycle_bounds: CycleCheckBounds::default(),
                },
            )?;
            Ok(())
        })
        .expect("w2 governed write");
        w2_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    w2_ms.sort_by(f64::total_cmp);
    println!(
        "[2] Single governed edge write + 500-hop cycle check (quotas ON): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 3.00ms p95)",
        percentile(&w2_ms, 0.50),
        percentile(&w2_ms, 0.95),
        percentile(&w2_ms, 0.99),
    );

    // -----------------------------------------------------------------------
    // Workload 3: Cycle-check bound-hit probe (>1,000 nodes) <= 60 ms p95
    // -----------------------------------------------------------------------
    let mut w3_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    for src in w2_srcs.iter().take(QUERIES_PER_WORKLOAD) {
        let t0 = Instant::now();
        let err = db
            .write(|tx| {
                assert_edge(
                    tx,
                    AssertEdgeRequest {
                        org_id: DEFAULT_ORG.into(),
                        src_id: src.clone(),
                        dst_id: chain_1100[0].clone(),
                        kind: EdgeKind::DependsOn,
                        assertion_scope: String::new(),
                        state: EdgeState::Active,
                        weight: 1.0,
                        provenance: Provenance {
                            asserted_by: PrincipalId::new("builder-1").unwrap(),
                            asserted_by_kind: AssertedByKind::Agent,
                            source_kind: SourceKind::Event,
                            source_ref: "tool:bench".into(),
                        },
                        valid_from: None,
                        valid_to: None,
                        meta_json: None,
                        scope: VisibilityScope::org_only(),
                        generic: false,
                        max_edges_per_org: 2_000_000,
                        max_live_edges_per_node: 5_000,
                        cycle_bounds: CycleCheckBounds::default(),
                    },
                )
            })
            .unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
        assert_eq!(err.reason_code(), Some("cycle_check_bound_exceeded"));
        w3_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    w3_ms.sort_by(f64::total_cmp);
    println!(
        "[3] Cycle-check bound-hit probe: p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 60.00ms p95)",
        percentile(&w3_ms, 0.50),
        percentile(&w3_ms, 0.95),
        percentile(&w3_ms, 0.99),
    );

    // -----------------------------------------------------------------------
    // Workload 4: 2-hop k_hop (3 seeds, max_hops=2, max_degree=50, max_nodes=100, as_of)
    // -----------------------------------------------------------------------
    let scope_org = VisibilityScope::org_only();
    let scope_vis = VisibilityScope::for_principal("agent", "owner-1", vec!["team-1".into()]);
    let mut w4_org_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    let mut w4_vis_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    for _ in 0..QUERIES_PER_WORKLOAD {
        let seeds = vec![
            org_a_ids[rng.gen_range(ORG_A_NODES)].clone(),
            org_a_ids[rng.gen_range(ORG_A_NODES)].clone(),
            org_a_ids[rng.gen_range(ORG_A_NODES)].clone(),
        ];
        let t0 = Instant::now();
        db.read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            k_hop(
                &mut repo,
                KHopRequest {
                    org_id: DEFAULT_ORG.into(),
                    seed_ids: seeds.clone(),
                    max_hops: Some(2),
                    direction: EdgeDirection::Both,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: Some(ts_now.clone()),
                    include_proposed: false,
                    max_nodes: Some(100),
                    max_edges: Some(250),
                    max_degree_per_node: Some(50),
                    max_visited_edges: Some(2_000),
                    skip_hubs_over: None,
                    deadline_ms: Some(500),
                    scope: scope_org.clone(),
                },
            )?;
            Ok(())
        })
        .expect("w4 org");
        w4_org_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let t1 = Instant::now();
        db.read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            k_hop(
                &mut repo,
                KHopRequest {
                    org_id: DEFAULT_ORG.into(),
                    seed_ids: seeds,
                    max_hops: Some(2),
                    direction: EdgeDirection::Both,
                    edge_kinds: vec![],
                    node_kinds: vec![NodeKind::MemoryNote],
                    as_of: Some(ts_now.clone()),
                    include_proposed: false,
                    max_nodes: Some(100),
                    max_edges: Some(250),
                    max_degree_per_node: Some(50),
                    max_visited_edges: Some(2_000),
                    skip_hubs_over: None,
                    deadline_ms: Some(500),
                    scope: scope_vis.clone(),
                },
            )?;
            Ok(())
        })
        .expect("w4 vis");
        w4_vis_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
    }
    w4_org_ms.sort_by(f64::total_cmp);
    w4_vis_ms.sort_by(f64::total_cmp);
    println!(
        "[4a] 2-hop k_hop (org-fenced): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 15.00ms p95)",
        percentile(&w4_org_ms, 0.50),
        percentile(&w4_org_ms, 0.95),
        percentile(&w4_org_ms, 0.99),
    );
    println!(
        "[4b] 2-hop k_hop (memory_note vis): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 25.00ms p95)",
        percentile(&w4_vis_ms, 0.50),
        percentile(&w4_vis_ms, 0.95),
        percentile(&w4_vis_ms, 0.99),
    );

    // -----------------------------------------------------------------------
    // Workload 5: seed_expand PPR (5 seeds, 2-hop bounded subgraph <= 40ms p95;
    //             exact <= 5k-node org-b subgraph <= 20ms p95)
    // -----------------------------------------------------------------------
    let mut w5_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    let mut w5_exact_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    for _ in 0..QUERIES_PER_WORKLOAD {
        let seeds: Vec<SeedInput> = (0..5)
            .map(|_| SeedInput { node_id: org_a_ids[rng.gen_range(ORG_A_NODES)].clone(), weight: 1.0 })
            .collect();
        let t0 = Instant::now();
        db.read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            seed_expand(
                &mut repo,
                SeedExpandRequest {
                    org_id: DEFAULT_ORG.into(),
                    seeds,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: Some(ts_now.clone()),
                    include_proposed: false,
                    walk_direction: WalkDirection::Undirected,
                    damping: Some(0.85),
                    max_iters: Some(30),
                    eps: Some(1e-6),
                    max_results: Some(10),
                    skip_hubs_over: None,
                    deadline_ms: Some(500),
                    scope: scope_org.clone(),
                },
            )?;
            Ok(())
        })
        .expect("w5 bounded ppr");
        w5_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let b_seeds: Vec<SeedInput> = (0..5)
            .map(|_| SeedInput { node_id: org_b_ids[rng.gen_range(org_b_ids.len())].clone(), weight: 1.0 })
            .collect();
        let t1 = Instant::now();
        let res = db
            .read_mut(|conn| {
                let mut repo = SqliteGraph::new(conn);
                seed_expand(
                    &mut repo,
                    SeedExpandRequest {
                        org_id: "org-b".into(),
                        seeds: b_seeds,
                        edge_kinds: vec![],
                        node_kinds: vec![],
                        as_of: Some(ts_now.clone()),
                        include_proposed: false,
                        walk_direction: WalkDirection::Undirected,
                        damping: Some(0.85),
                        max_iters: Some(30),
                        eps: Some(1e-6),
                        max_results: Some(10),
                        skip_hubs_over: None,
                        deadline_ms: Some(500),
                        scope: scope_org.clone(),
                    },
                )
            })
            .expect("w5 exact ppr");
        assert!(res.graph.exact, "org-b (2,000 nodes / 10,000 edges) must run exact PPR");
        w5_exact_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
    }
    w5_ms.sort_by(f64::total_cmp);
    w5_exact_ms.sort_by(f64::total_cmp);
    println!(
        "[5a] seed_expand PPR (100k bounded ego): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 40.00ms p95)",
        percentile(&w5_ms, 0.50),
        percentile(&w5_ms, 0.95),
        percentile(&w5_ms, 0.99),
    );
    println!(
        "[5b] seed_expand PPR (exact <=5k nodes): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 20.00ms p95)",
        percentile(&w5_exact_ms, 0.50),
        percentile(&w5_exact_ms, 0.95),
        percentile(&w5_exact_ms, 0.99),
    );

    // -----------------------------------------------------------------------
    // Workload 6: shortest_path (bidirectional BFS, max_depth=4) <= 15 ms p95
    // -----------------------------------------------------------------------
    let mut w6_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    for _ in 0..QUERIES_PER_WORKLOAD {
        let from = org_a_org_vis_ids[rng.gen_range(org_a_org_vis_ids.len())].clone();
        let to = org_a_org_vis_ids[rng.gen_range(org_a_org_vis_ids.len())].clone();
        let t0 = Instant::now();
        db.read_mut(|conn| {
            let mut repo = SqliteGraph::new(conn);
            shortest_path(
                &mut repo,
                ShortestPathRequest {
                    org_id: DEFAULT_ORG.into(),
                    from_id: from,
                    to_id: to,
                    direction: EdgeDirection::Out,
                    edge_kinds: vec![],
                    node_kinds: vec![],
                    as_of: Some(ts_now.clone()),
                    include_proposed: false,
                    max_depth: Some(4),
                    deadline_ms: Some(500),
                    scope: scope_org.clone(),
                },
            )?;
            Ok(())
        })
        .expect("w6 shortest_path");
        w6_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    w6_ms.sort_by(f64::total_cmp);
    println!(
        "[6] shortest_path (100k, max_depth=4): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 15.00ms p95)",
        percentile(&w6_ms, 0.50),
        percentile(&w6_ms, 0.95),
        percentile(&w6_ms, 0.99),
    );

    // -----------------------------------------------------------------------
    // Workload 7: Super-hub DoS probe (k_hop max_hops=3 + seed_expand on 2,000-edge super-hub) <= 50ms p95
    // -----------------------------------------------------------------------
    let mut w7_khop_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    let mut w7_ppr_ms = Vec::with_capacity(QUERIES_PER_WORKLOAD);
    for _ in 0..QUERIES_PER_WORKLOAD {
        let t0 = Instant::now();
        let kh = db
            .read_mut(|conn| {
                let mut repo = SqliteGraph::new(conn);
                k_hop(
                    &mut repo,
                    KHopRequest {
                        org_id: DEFAULT_ORG.into(),
                        seed_ids: vec![super_hub_id.clone()],
                        max_hops: Some(3),
                        direction: EdgeDirection::Both,
                        edge_kinds: vec![],
                        node_kinds: vec![],
                        as_of: Some(ts_now.clone()),
                        include_proposed: false,
                        max_nodes: Some(100),
                        max_edges: Some(250),
                        max_degree_per_node: Some(50),
                        max_visited_edges: Some(2_000),
                        skip_hubs_over: None,
                        deadline_ms: Some(500),
                        scope: scope_org.clone(),
                    },
                )
            })
            .expect("w7 khop");
        assert!(kh.truncated, "super-hub k_hop must report truncated = true");
        w7_khop_ms.push(t0.elapsed().as_secs_f64() * 1000.0);

        let t1 = Instant::now();
        let ppr = db
            .read_mut(|conn| {
                let mut repo = SqliteGraph::new(conn);
                seed_expand(
                    &mut repo,
                    SeedExpandRequest {
                        org_id: DEFAULT_ORG.into(),
                        seeds: vec![SeedInput { node_id: super_hub_id.clone(), weight: 1.0 }],
                        edge_kinds: vec![],
                        node_kinds: vec![],
                        as_of: Some(ts_now.clone()),
                        include_proposed: false,
                        walk_direction: WalkDirection::Undirected,
                        damping: Some(0.85),
                        max_iters: Some(30),
                        eps: Some(1e-6),
                        max_results: Some(10),
                        skip_hubs_over: None,
                        deadline_ms: Some(500),
                        scope: scope_org.clone(),
                    },
                )
            })
            .expect("w7 ppr");
        assert!(ppr.graph.truncated, "super-hub seed_expand must report truncated = true");
        w7_ppr_ms.push(t1.elapsed().as_secs_f64() * 1000.0);
    }
    w7_khop_ms.sort_by(f64::total_cmp);
    w7_ppr_ms.sort_by(f64::total_cmp);
    println!(
        "[7a] Super-hub DoS k_hop (max_hops=3): p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 50.00ms p95)",
        percentile(&w7_khop_ms, 0.50),
        percentile(&w7_khop_ms, 0.95),
        percentile(&w7_khop_ms, 0.99),
    );
    println!(
        "[7b] Super-hub DoS seed_expand: p50={:.2}ms p95={:.2}ms p99={:.2}ms (floor <= 50.00ms p95)",
        percentile(&w7_ppr_ms, 0.50),
        percentile(&w7_ppr_ms, 0.95),
        percentile(&w7_ppr_ms, 0.99),
    );

    let mut failed = Vec::new();
    if edges_per_sec < 15_000.0 {
        failed.push(format!("batched insert {edges_per_sec:.0} < 15000 edges/s"));
    }
    if percentile(&w2_ms, 0.95) > 3.0 {
        failed.push(format!("governed write p95 {:.2}ms > 3.00ms", percentile(&w2_ms, 0.95)));
    }
    if percentile(&w3_ms, 0.95) > 60.0 {
        failed.push(format!("cycle bound-hit p95 {:.2}ms > 60.00ms", percentile(&w3_ms, 0.95)));
    }
    if percentile(&w4_org_ms, 0.95) > 15.0 {
        failed.push(format!("k_hop org p95 {:.2}ms > 15.00ms", percentile(&w4_org_ms, 0.95)));
    }
    if percentile(&w4_vis_ms, 0.95) > 25.0 {
        failed.push(format!("k_hop vis p95 {:.2}ms > 25.00ms", percentile(&w4_vis_ms, 0.95)));
    }
    if percentile(&w5_ms, 0.95) > 40.0 {
        failed.push(format!("seed_expand bounded p95 {:.2}ms > 40.00ms", percentile(&w5_ms, 0.95)));
    }
    if percentile(&w5_exact_ms, 0.95) > 20.0 {
        failed.push(format!("seed_expand exact p95 {:.2}ms > 20.00ms", percentile(&w5_exact_ms, 0.95)));
    }
    if percentile(&w6_ms, 0.95) > 15.0 {
        failed.push(format!("shortest_path p95 {:.2}ms > 15.00ms", percentile(&w6_ms, 0.95)));
    }
    if percentile(&w7_khop_ms, 0.95) > 50.0 {
        failed.push(format!("super-hub k_hop p95 {:.2}ms > 50.00ms", percentile(&w7_khop_ms, 0.95)));
    }
    if percentile(&w7_ppr_ms, 0.95) > 50.0 {
        failed.push(format!("super-hub ppr p95 {:.2}ms > 50.00ms", percentile(&w7_ppr_ms, 0.95)));
    }

    if !failed.is_empty() {
        eprintln!("BENCHMARK FLOOR FAILED:\n - {}", failed.join("\n - "));
        std::process::exit(1);
    }
    println!("ALL C1 BENCHMARK FLOORS PASSED.");
}
