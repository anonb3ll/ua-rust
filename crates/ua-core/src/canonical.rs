//! Canonical JSON: the one text form every hash and stored comparison of a
//! JSON value uses.
//!
//! Compact (no whitespace), object keys sorted by their UTF-8 bytes (the same
//! order as Unicode code points, so Python's `json.dumps(sort_keys=True,
//! separators=(",", ":"), ensure_ascii=False)` agrees), at every depth.
//! Arrays keep their order.
//!
//! The sort is done here, explicitly. `serde_json::to_string` happens to sort
//! keys only while serde_json's `preserve_order` feature is off; Cargo unifies
//! features across the dependency graph, so any crate enabling it would
//! silently change every approval payload, proposal digest and config hash.
//! (Today one build dependency, tree-sitter's build script, enables it on its
//! own host copy of serde_json.)

use serde_json::Value;

/// The canonical text of `v`.
pub fn to_string(v: &Value) -> String {
    let mut out = String::new();
    write(&mut out, v);
    out
}

/// `v` with every object rebuilt in canonical key order. Serializing the
/// result with `serde_json` gives [`to_string`] only while `preserve_order`
/// is off; hash [`to_string`] instead.
pub fn sorted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            Value::Object(entries.into_iter().map(|(k, v)| (k.clone(), sorted(v))).collect())
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

fn write(out: &mut String, v: &Value) {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(&String, &Value)> = m.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                scalar(out, &Value::String(k.clone()));
                out.push(':');
                write(out, val);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, val) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write(out, val);
            }
            out.push(']');
        }
        other => scalar(out, other),
    }
}

/// A string, number, boolean or null, in serde_json's compact form.
fn scalar(out: &mut String, v: &Value) {
    // Serializing a scalar cannot fail.
    out.push_str(&serde_json::to_string(v).unwrap_or_else(|_| "null".into()));
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::*;

    /// Build `{"b":…, "a":…}` with insertion order taken literally, whatever
    /// serde_json's map type is.
    fn obj(pairs: &[(&str, Value)]) -> Value {
        let mut m = Map::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), v.clone());
        }
        Value::Object(m)
    }

    #[test]
    fn the_same_value_built_in_any_key_order_has_one_text() {
        let inner_ab = obj(&[("alpha", json!(1)), ("beta", json!([3, 2, 1]))]);
        let inner_ba = obj(&[("beta", json!([3, 2, 1])), ("alpha", json!(1))]);
        let forward = obj(&[
            ("tool", json!("task_update")),
            ("args", inner_ab.clone()),
            ("Z", json!(null)),
            ("é", json!("x")),
            ("list", json!([inner_ab.clone(), inner_ba.clone()])),
        ]);
        let reverse = obj(&[
            ("list", json!([inner_ba.clone(), inner_ab.clone()])),
            ("é", json!("x")),
            ("Z", json!(null)),
            ("args", inner_ba),
            ("tool", json!("task_update")),
        ]);
        let want = r#"{"Z":null,"args":{"alpha":1,"beta":[3,2,1]},"list":[{"alpha":1,"beta":[3,2,1]},{"alpha":1,"beta":[3,2,1]}],"tool":"task_update","é":"x"}"#;
        assert_eq!(to_string(&forward), want);
        assert_eq!(to_string(&reverse), want);
        assert_eq!(to_string(&sorted(&reverse)), want);
    }

    /// The canonical text is byte-identical to what serde_json printed for a
    /// sorted map, so payloads stored before this module still match.
    #[test]
    fn matches_the_previous_serde_json_form() {
        let v = json!({
            "s": "quote \" backslash \\ newline \n tab \t nul \u{0} bell \u{7} emoji 🦀",
            "n": [0, -1, 1.5, 1e300, u64::MAX, i64::MIN],
            "b": [true, false, null],
            "nested": { "z": {}, "a": [] },
        });
        assert_eq!(to_string(&v), serde_json::to_string(&sorted(&v)).unwrap());
    }
}
