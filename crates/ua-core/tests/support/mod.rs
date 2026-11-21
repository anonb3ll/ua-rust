//! Source scanning shared by the guard tests (`org_guard`, `authz_guard`):
//! a small lexer that blanks comments, strings and char literals, removal of
//! `#[cfg(test)]` items, and the workspace's non-test source files.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Blank out comments, string and char literal contents (keeping offsets and
/// newlines), so brace matching and pattern search see code only.
pub fn mask(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != b'\n' {
                *c = b' ';
            }
        }
    };
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = src[i..].find('\n').map_or(b.len(), |n| i + n);
                blank(&mut out, i, end);
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = src[i + 2..].find("*/").map_or(b.len(), |n| i + 2 + n + 2);
                blank(&mut out, i, end);
                i = end;
            }
            b'r' if (b.get(i + 1) == Some(&b'"') || b.get(i + 1) == Some(&b'#'))
                && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_')) =>
            {
                let hashes = b[i + 1..].iter().take_while(|c| **c == b'#').count();
                if b.get(i + 1 + hashes) != Some(&b'"') {
                    i += 1;
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let start = i + 2 + hashes;
                let end = src[start..].find(&close).map_or(b.len(), |n| start + n + close.len());
                blank(&mut out, start, end - close.len());
                i = end;
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    j += if b[j] == b'\\' { 2 } else { 1 };
                }
                blank(&mut out, i + 1, j.min(b.len()));
                i = j + 1;
            }
            // A char literal ('x', '\n', '\''), not a lifetime ('a).
            b'\'' => {
                let end = if b.get(i + 1) == Some(&b'\\') {
                    // Skip the escaped character itself (`'\''`).
                    src.get(i + 3..).and_then(|r| r.find('\'')).map(|n| i + 3 + n)
                } else if b.get(i + 2) == Some(&b'\'') {
                    Some(i + 2)
                } else {
                    src[i + 1..].chars().next().and_then(|c| {
                        let after = i + 1 + c.len_utf8();
                        (b.get(after) == Some(&b'\'')).then_some(after)
                    })
                };
                match end {
                    Some(e) => {
                        blank(&mut out, i + 1, e);
                        i = e + 1;
                    }
                    None => i += 1,
                }
            }
            _ => i += 1,
        }
    }
    String::from_utf8(out).expect("masking keeps UTF-8 boundaries for ASCII delimiters")
}

/// Index just past the brace that opens at `open` in masked text.
pub fn close_brace(m: &str, open: usize) -> usize {
    let mut depth = 0usize;
    for (i, c) in m[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open + i + 1;
                }
            }
            _ => {}
        }
    }
    m.len()
}

/// Masked source with every `#[cfg(test)]` item blanked.
pub fn without_tests(src: &str) -> String {
    let mut m = mask(src);
    while let Some(at) = m.find("#[cfg(test)]") {
        let after = at + "#[cfg(test)]".len();
        // The item ends at its matching brace, or at `;` when it has none.
        let brace = m[after..].find('{').map(|n| after + n);
        let semi = m[after..].find(';').map(|n| after + n);
        let end = match (brace, semi) {
            (Some(b), Some(s)) if s < b => s + 1,
            (Some(b), _) => close_brace(&m, b),
            (None, Some(s)) => s + 1,
            (None, None) => m.len(),
        };
        let blank: String = m[at..end].chars().map(|c| if c == '\n' { '\n' } else { ' ' }).collect();
        m.replace_range(at..end, &blank);
    }
    m
}

/// Non-test source of every workspace crate.
pub fn sources() -> Vec<(PathBuf, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(crates).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            rust_files(&src, &mut files);
        }
    }
    files.sort();
    files.into_iter().map(|p| (p.clone(), std::fs::read_to_string(&p).unwrap())).collect()
}

pub fn line_of(m: &str, at: usize) -> usize {
    m[..at].matches('\n').count() + 1
}

/// Start offsets of `pat` in `m` that begin a path segment.
pub fn find_all<'a>(m: &'a str, pat: &'a str) -> impl Iterator<Item = usize> + 'a {
    m.match_indices(pat).map(|(i, _)| i).filter(move |&i| {
        i == 0 || !m[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}
