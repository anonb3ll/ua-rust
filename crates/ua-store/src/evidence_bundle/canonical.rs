//! Strict canonical JSON encoder for evidence bundle files
//! (`docs/evidence-export.md`, Bundle layout).
//!
//! Rules:
//! - Object keys sorted by UTF-8 bytes at every depth.
//! - Compact formatting (no whitespace).
//! - Integers only: floating-point numbers are refused.
//! - Strings escaped with standard JSON escaping; explicit `null` where fields
//!   carry `null`.
//!
//! This is the **bundle** encoder. Ledger rows are re-hashed with the ledger's
//! own `py_json_str` encoder selected by `hash_v` (`1` or `2`), because imported
//! Python rows may contain floats in their raw `payload` string.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use ua_core::{UaError, UaResult};

/// SHA-256 of `bytes` as lowercase 64-char hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// SHA-256 of an empty byte slice, used as the `org_chain_hash` when an
/// organization has zero rows from genesis.
pub fn empty_org_chain_hash() -> String {
    sha256_hex(b"")
}

/// One step of the per-organization running chain fold:
/// `H(prev_org_chain_hash || entry_hash)` (`docs/evidence-export.md`).
///
/// At genesis (`org_seq == 1`), `prev_org_chain_hash` is `""`.
pub fn org_chain_fold(prev_org_chain_hash: &str, entry_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_org_chain_hash.as_bytes());
    hasher.update(entry_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// Serialize `value` to canonical bundle JSON bytes, refusing any float.
pub fn to_canonical_bytes<T: Serialize>(value: &T) -> UaResult<Vec<u8>> {
    let v = serde_json::to_value(value)
        .map_err(|e| UaError::invalid(format!("bundle value is not JSON-serializable: {e}")))?;
    to_canonical_string(&v).map(String::into_bytes)
}

/// Encode a `serde_json::Value` to canonical bundle JSON text, refusing floats.
pub fn to_canonical_string(v: &Value) -> UaResult<String> {
    let mut out = String::new();
    write_value(&mut out, v)?;
    Ok(out)
}

fn write_value(out: &mut String, v: &Value) -> UaResult<()> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                out.push_str(&n.to_string());
            } else {
                return Err(UaError::invalid(format!(
                    "bundle canonical JSON forbids floating-point numbers (got {n})"
                )));
            }
        }
        Value::String(s) => {
            out.push_str(
                &serde_json::to_string(s)
                    .map_err(|e| UaError::internal(format!("failed to escape JSON string: {e}")))?,
            );
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, elem)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(k)
                        .map_err(|e| UaError::internal(format!("failed to escape JSON key: {e}")))?,
                );
                out.push(':');
                write_value(out, val)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_sorts_keys_and_refuses_floats() {
        let v = json!({ "z": 1, "a": { "d": null, "b": [true, "hi"] } });
        assert_eq!(to_canonical_string(&v).unwrap(), r#"{"a":{"b":[true,"hi"],"d":null},"z":1}"#);
        let float_v = json!({ "score": 0.5 });
        let err = to_canonical_string(&float_v).unwrap_err().to_string();
        assert!(err.contains("floating-point"), "{err}");
    }

    #[test]
    fn org_chain_fold_is_deterministic() {
        let h1 = org_chain_fold("", "aaa");
        let h2 = org_chain_fold(&h1, "bbb");
        assert_eq!(h1, sha256_hex(b"aaa"));
        assert_eq!(h2, sha256_hex(format!("{h1}bbb").as_bytes()));
        assert_ne!(h1, h2);
    }
}
