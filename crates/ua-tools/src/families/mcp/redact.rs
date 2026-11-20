//! Redaction of injected credentials from what a downstream server returns.
//!
//! A reflecting or hostile server can echo a credential in many shapes. For
//! each injected value the [`Redactor`] matches:
//!
//! * the value itself, case-sensitively;
//! * its percent-encoding (RFC 3986 unreserved bytes kept, and every byte
//!   encoded) and its hex form, case-insensitively;
//! * its base64 (standard and URL-safe, padded or not) at all three byte
//!   offsets, so the value inside a larger encoded blob (`Basic
//!   base64("user:" + v)`, `base64("Bearer " + v)`) is found wherever it
//!   starts. Only the characters that depend on the value alone are matched;
//!   the zero to three around it carry a few bits of the neighbours at most;
//! * all of the above with whitespace ignored, so a value split by spaces or
//!   line breaks is still found;
//! * a partial echo: any substring of a form at least `max(12, len/2)` long.
//!
//! A shorter fragment (at least `max(8, len/3)`) that survives, in one string
//! or across the strings of a result read in order, cannot be redacted
//! cleanly: the caller withholds the whole result instead.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde_json::Value;

pub const REDACTED: &str = "[redacted]";
/// The n-gram the index is built on; no threshold is shorter.
const GRAM: usize = 8;
const MIN_REDACT: usize = 12;
const MIN_FRAGMENT: usize = 8;
/// A base64 core shorter than this is not matched (too many false hits).
const MIN_CORE: usize = 4;

struct Form {
    /// Whitespace removed; lowercased when `ci`.
    bytes: Vec<u8>,
    ci: bool,
    /// Whether a substring counts (else only the whole form).
    partial: bool,
}

impl Form {
    fn redact_len(&self) -> usize {
        let n = self.bytes.len();
        if self.partial { n.min(MIN_REDACT.max(n.div_ceil(2))) } else { n }
    }

    fn fragment_len(&self) -> usize {
        let n = self.bytes.len();
        if self.partial { n.min(MIN_FRAGMENT.max(n.div_ceil(3))) } else { n }
    }
}

/// One match in the whitespace-free view: `[start, end)` and its form.
struct Hit {
    start: usize,
    end: usize,
    form: usize,
}

/// n-gram -> (form, offset) for the forms at least [`GRAM`] long.
type GramIndex = HashMap<[u8; GRAM], Vec<(usize, usize)>>;

#[derive(Default)]
pub struct Redactor {
    forms: Vec<Form>,
    /// The n-gram index, one table per case mode (sensitive, insensitive).
    grams: [GramIndex; 2],
}

fn strip_ws(b: &[u8]) -> Vec<u8> {
    b.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn percent(v: &[u8], all: bool) -> String {
    let mut out = String::with_capacity(v.len() * 3);
    for &b in v {
        if !all && (b.is_ascii_alphanumeric() || b"-._~".contains(&b)) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The base64 characters of `v` that depend on `v` alone, when it starts
/// `offset` bytes into the encoded data.
fn base64_core(engine: &impl Engine, v: &[u8], offset: usize) -> String {
    let mut data = vec![0u8; offset];
    data.extend_from_slice(v);
    let enc = engine.encode(&data);
    let skip = [0, 2, 3][offset];
    let tail = usize::from(!data.len().is_multiple_of(3));
    enc.get(skip..enc.len().saturating_sub(tail)).unwrap_or("").to_string()
}

impl Redactor {
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let mut r = Self::default();
        for v in values {
            let raw = v.as_bytes();
            if strip_ws(raw).is_empty() {
                continue;
            }
            r.push(raw, false, true);
            r.push(percent(raw, false).as_bytes(), true, true);
            r.push(percent(raw, true).as_bytes(), true, true);
            r.push(hex::encode(raw).as_bytes(), true, true);
            for offset in 0..3 {
                for core in
                    [base64_core(&STANDARD_NO_PAD, raw, offset), base64_core(&URL_SAFE_NO_PAD, raw, offset)]
                {
                    if core.len() >= MIN_CORE {
                        r.push(core.as_bytes(), false, true);
                    }
                }
            }
            // The whole header value, so it goes as one piece.
            let bearer = format!("Bearer {v}");
            r.push(STANDARD_NO_PAD.encode(&bearer).as_bytes(), false, false);
            r.push(URL_SAFE_NO_PAD.encode(&bearer).as_bytes(), false, false);
        }
        r
    }

    fn push(&mut self, bytes: &[u8], ci: bool, partial: bool) {
        let mut bytes = strip_ws(bytes);
        if ci {
            bytes.make_ascii_lowercase();
        }
        if bytes.is_empty()
            || self.forms.iter().any(|f| f.bytes == bytes && f.ci == ci && f.partial == partial)
        {
            return;
        }
        let idx = self.forms.len();
        if bytes.len() >= GRAM {
            let table = &mut self.grams[usize::from(ci)];
            for (p, w) in bytes.windows(GRAM).enumerate() {
                let key: [u8; GRAM] = w.try_into().expect("window is GRAM long");
                table.entry(key).or_default().push((idx, p));
            }
        }
        self.forms.push(Form { bytes, ci, partial });
    }

    pub fn is_empty(&self) -> bool {
        self.forms.is_empty()
    }

    /// Every maximal match at least as long as its form's fragment length.
    fn hits(&self, view: &[u8]) -> Vec<Hit> {
        let lower = view.to_ascii_lowercase();
        let mut out = Vec::new();
        for (ci, hay) in [(false, view), (true, lower.as_slice())] {
            let table = &self.grams[usize::from(ci)];
            if !table.is_empty() && hay.len() >= GRAM {
                for i in 0..=hay.len() - GRAM {
                    let key: [u8; GRAM] = hay[i..i + GRAM].try_into().expect("window is GRAM long");
                    let Some(at) = table.get(&key) else { continue };
                    for &(f, p) in at {
                        let form = &self.forms[f].bytes;
                        // Only the left end of a run; its continuations are inside it.
                        if i > 0 && p > 0 && hay[i - 1] == form[p - 1] {
                            continue;
                        }
                        let mut k = GRAM;
                        while i + k < hay.len() && p + k < form.len() && hay[i + k] == form[p + k] {
                            k += 1;
                        }
                        if k >= self.forms[f].fragment_len() {
                            out.push(Hit { start: i, end: i + k, form: f });
                        }
                    }
                }
            }
            // Forms too short for the index: whole matches only.
            for (f, form) in self.forms.iter().enumerate() {
                if form.ci != ci || form.bytes.len() >= GRAM || form.bytes.len() > hay.len() {
                    continue;
                }
                for (i, w) in hay.windows(form.bytes.len()).enumerate() {
                    if w == form.bytes.as_slice() {
                        out.push(Hit { start: i, end: i + w.len(), form: f });
                    }
                }
            }
        }
        out
    }

    /// Redact `s`. The flag is true when a fragment too short to redact
    /// cleanly is left in it.
    pub fn scrub_text(&self, s: &str) -> (String, bool) {
        if self.is_empty() {
            return (s.to_string(), false);
        }
        let mut view = Vec::with_capacity(s.len());
        let mut at = Vec::with_capacity(s.len());
        for (i, b) in s.bytes().enumerate() {
            if !b.is_ascii_whitespace() {
                view.push(b);
                at.push(i);
            }
        }
        let hits = self.hits(&view);
        let mut cut: Vec<(usize, usize)> = hits
            .iter()
            .filter(|h| h.end - h.start >= self.forms[h.form].redact_len())
            .map(|h| (h.start, h.end))
            .collect();
        cut = merge(cut);
        let covered = |h: &Hit| cut.iter().any(|&(a, b)| a <= h.start && h.end <= b);
        let residual = hits.iter().any(|h| !covered(h));
        if cut.is_empty() {
            return (s.to_string(), residual);
        }
        // Back to byte offsets in `s`, widened to whole characters.
        let mut spans: Vec<(usize, usize)> = cut
            .into_iter()
            .map(|(a, b)| {
                let (mut start, mut end) = (at[a], at[b - 1] + 1);
                while !s.is_char_boundary(start) {
                    start -= 1;
                }
                while !s.is_char_boundary(end) {
                    end += 1;
                }
                (start, end)
            })
            .collect();
        spans = merge(spans);
        let mut out = String::with_capacity(s.len());
        let mut last = 0;
        for (a, b) in spans {
            out.push_str(&s[last..a]);
            out.push_str(REDACTED);
            last = b;
        }
        out.push_str(&s[last..]);
        (out, residual)
    }

    /// Whether `s` holds any fragment of a form (whitespace ignored).
    #[cfg(test)]
    fn leaks(&self, s: &str) -> bool {
        !self.is_empty() && !self.hits(&strip_ws(s.as_bytes())).is_empty()
    }

    /// Whether a fragment runs across two of `parts` read in order: a value
    /// split between strings, which no per-string redaction removes cleanly.
    pub fn crosses(&self, parts: &[&str]) -> bool {
        if self.is_empty() {
            return false;
        }
        let mut view = Vec::new();
        let mut bounds = Vec::new();
        for p in parts {
            view.extend(strip_ws(p.as_bytes()));
            bounds.push(view.len());
        }
        self.hits(&view).iter().any(|h| bounds.iter().any(|&b| h.start < b && b < h.end))
    }

    /// Redact every string and key in `v`. True when a fragment survives, in
    /// one string or split across consecutive string values (an array's
    /// items, an object's values in key order): the caller must then
    /// withhold `v`. A caller that knows another reading order (content
    /// blocks) checks it with [`Self::crosses`] as well.
    pub fn scrub_value(&self, v: &mut Value) -> bool {
        if self.is_empty() {
            return false;
        }
        let mut parts = Vec::new();
        collect(v, &mut parts);
        let crossing = self.crosses(&parts);
        let mut residual = false;
        self.walk(v, &mut residual);
        residual || crossing
    }

    fn walk(&self, v: &mut Value, residual: &mut bool) {
        match v {
            Value::String(s) => {
                let (out, r) = self.scrub_text(s);
                *residual |= r;
                *s = out;
            }
            Value::Array(a) => a.iter_mut().for_each(|x| self.walk(x, residual)),
            Value::Object(m) => {
                let old = std::mem::take(m);
                for (k, mut x) in old {
                    self.walk(&mut x, residual);
                    let (k, r) = self.scrub_text(&k);
                    *residual |= r;
                    m.insert(k, x);
                }
            }
            _ => {}
        }
    }
}

/// Every string value in `v`, in order (keys are scrubbed on their own).
fn collect<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
        Value::Object(m) => m.values().for_each(|x| collect(x, out)),
        _ => {}
    }
}

/// Sort and join overlapping or touching ranges.
fn merge(mut r: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    r.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(r.len());
    for (a, b) in r {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    use serde_json::json;

    use super::*;

    const V: &str = "fake-downstream-T0KEN/with+symbols";

    fn r() -> Redactor {
        Redactor::new([V])
    }

    /// Redacted, with nothing of the value left that a fragment check finds.
    fn clean(text: &str) {
        let (out, residual) = r().scrub_text(text);
        assert!(out.contains(REDACTED), "nothing redacted in {text:?}: {out:?}");
        assert!(!residual, "a fragment survived in {out:?}");
        assert!(!r().leaks(&out), "{out:?}");
    }

    #[test]
    fn the_value_and_its_split_forms() {
        clean(&format!("token={V} end"));
        clean(&format!("a {} b", V.replace('-', " - ")));
        clean(&format!("x {}\n{} y", &V[..17], &V[17..]));
        let (out, _) = r().scrub_text(&format!("t={V}!"));
        assert_eq!(out, "t=[redacted]!");
    }

    #[test]
    fn hex_and_percent_in_either_case() {
        clean(&hex::encode(V));
        clean(&hex::encode(V).to_ascii_uppercase());
        clean(&percent(V.as_bytes(), false));
        clean(&percent(V.as_bytes(), false).to_ascii_lowercase());
        clean(&percent(V.as_bytes(), true));
        clean(&percent(V.as_bytes(), true).to_ascii_lowercase());
    }

    #[test]
    fn base64_at_every_offset_and_alphabet() {
        for prefix in ["", "a", "ab", "user:", "Bearer ", "xy:"] {
            let data = format!("{prefix}{V}");
            for enc in [
                STANDARD.encode(&data),
                STANDARD_NO_PAD.encode(&data),
                URL_SAFE.encode(&data),
                URL_SAFE_NO_PAD.encode(&data),
            ] {
                clean(&format!("Authorization: Basic {enc}"));
                // Wrapped like MIME base64.
                let wrapped: String = enc
                    .as_bytes()
                    .chunks(10)
                    .map(|c| std::str::from_utf8(c).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n");
                clean(&wrapped);
            }
        }
    }

    #[test]
    fn long_partial_echoes_are_redacted() {
        // At least max(12, len/2) of the value.
        clean(&format!("prefix {} suffix", &V[..V.len() / 2 + 1]));
        clean(&format!("mid {} mid", &V[5..25]));
        clean(&format!("hex {}", &hex::encode(V)[..40]));
    }

    #[test]
    fn short_leftovers_are_flagged_not_passed() {
        // 13 characters: too short to redact as a partial, long enough to flag.
        let (_, residual) = r().scrub_text(&format!("x {} y", &V[..13]));
        assert!(residual);
        // A value split across two strings of a result, each part alone too
        // short to flag or cleanly redacted.
        let mut v = json!({ "content": [{ "text": &V[..10] }, { "text": &V[10..] }] });
        assert!(r().scrub_value(&mut v), "{v}");
        assert!(r().crosses(&["a fake-down", "stream-T0KEN/with+symbols b"]));
        assert!(!r().crosses(&["fake-downstream-T0KEN/with+symbols", "fake-downstream-T0KEN/with+symbols"]));
        let mut v = json!({ "content": [{ "text": format!("a {}", &V[..17]) }, { "text": &V[17..] }] });
        assert!(r().scrub_value(&mut v), "{v}");
        // An ordinary result passes untouched.
        let mut ok = json!({ "content": [{ "text": "nothing to see here, fake-down only" }] });
        assert!(!r().scrub_value(&mut ok));
        assert_eq!(ok["content"][0]["text"], "nothing to see here, fake-down only");
    }

    #[test]
    fn keys_and_multibyte_text_survive() {
        let mut v = json!({ V: format!("é{V}é"), "b": ["ü", V] });
        assert!(!r().scrub_value(&mut v));
        let text = v.to_string();
        assert!(!text.contains(V) && !text.contains("T0KEN"), "{text}");
        assert_eq!(v[REDACTED], "é[redacted]é");
    }

    #[test]
    fn short_values_match_whole_only() {
        let r = Redactor::new(["abc12"]);
        assert_eq!(r.scrub_text("x abc12 y").0, "x [redacted] y");
        assert_eq!(r.scrub_text("abc1").0, "abc1");
        assert!(Redactor::new([" "]).is_empty());
    }
}
