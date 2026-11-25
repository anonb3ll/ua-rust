//! Every schema part name ever shipped stays known to every build.
//!
//! A database records the parts it was given by name, and a build refuses a
//! database that records a name it does not know (the unknown-part fence,
//! `docs/operations.md`, "Older builds and a newer database"). So a name must
//! never leave a build's known list: not when its Cargo feature is compiled
//! out (a lean build would refuse a full build's database of the same
//! version), and not when a later change retires or renames the part (that
//! build would refuse every database an earlier build made).
//!
//! The list in `fixtures/schema_part_names.txt` is checked in. This test reads
//! the build's own lists, so running it with `--no-default-features` checks the
//! lean build too.

use std::collections::BTreeSet;

fn pinned() -> Vec<&'static str> {
    include_str!("fixtures/schema_part_names.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

#[test]
fn every_shipped_part_name_is_known_to_this_build() {
    let known: BTreeSet<&str> = ua_tools::known_schema_part_names().into_iter().collect();
    let missing: Vec<&str> = pinned().into_iter().filter(|n| !known.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "this build no longer knows the shipped schema parts {missing:?}: a database that records them would be \
         refused. Keep every shipped part in ua_tools::schema_parts or ua_tools::optional_schema_parts (a part \
         whose feature is off goes in optional_schema_parts); never retire or rename one"
    );
}

#[test]
fn every_known_part_name_is_pinned() {
    let pinned: BTreeSet<&str> = pinned().into_iter().collect();
    let new: Vec<&str> =
        ua_tools::known_schema_part_names().into_iter().filter(|n| !pinned.contains(n)).collect();
    assert!(new.is_empty(), "add the new schema parts {new:?} to tests/fixtures/schema_part_names.txt");
}

#[test]
fn the_pinned_list_has_no_duplicates() {
    let all = pinned();
    let unique: BTreeSet<&str> = all.iter().copied().collect();
    assert_eq!(all.len(), unique.len());
}
