//! Rank fusion: competition ranks, the OR fallback query, the feedback
//! posterior and prior bounds, and the conflict hint.

use ua_memory::rank::*;

#[test]
fn competition_ranks_share_ties() {
    let items: Vec<String> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
    let r = competition_ranks(&items, |i| match i {
        "a" => 1,
        "b" | "c" => 2,
        _ => 3,
    });
    assert_eq!((r["a"], r["b"], r["c"], r["d"]), (1, 2, 2, 4));
}

#[test]
fn or_query_drops_stopwords() {
    let t: Vec<String> = ["the", "deploy", "of", "Deploy", "hub"].iter().map(|s| s.to_string()).collect();
    assert_eq!(or_query(&t), "\"deploy\" OR \"hub\"");
}

#[test]
fn posterior_and_prior_bounds() {
    assert_eq!(posterior([0, 0, 0, 0]), (1.0, 1.0));
    assert_eq!(posterior([2, 1, 2, 1]), (3.0, 1.0 + 1.0 + 1.0 + 2.0));
    let (p, _) = prior_multiplier(1.0, 1.0, 1.0, 1.0);
    assert!(p <= PRIOR_MAX);
    let (p, _) = prior_multiplier(0.0, 0.0, 0.0, 0.5);
    assert!(p >= PRIOR_MIN);
}

#[test]
fn conflicts() {
    assert!(detect_conflict("port: 8080", "port: 9090"));
    assert!(detect_conflict("the cache is enabled", "the cache is disabled"));
    assert!(!detect_conflict("port: 8080", "port: 8080"));
}
