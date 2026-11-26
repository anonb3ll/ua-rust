//! Overlapping embedding chunks for long memory notes.
//!
//! Exact port of the Python hub's `memory_chunks.py` so imported and native
//! hubs split and embed identical text windows. All lengths and offsets are
//! Unicode code points (matching Python's `len`), never UTF-8 byte offsets,
//! and piece trimming uses Python's `str.isspace()` definition (which
//! includes ASCII separator controls `\x1c`–`\x1f`).

/// Approximate characters per token used for the chunker window sizes.
pub const CHARS_PER_TOKEN: usize = 4;
/// Target chunk window size in tokens.
pub const CHUNK_TOKENS: usize = 400;
/// Overlap between adjacent chunk windows in tokens.
pub const OVERLAP_TOKENS: usize = 80;
/// Target chunk window size in Unicode code points (1,600).
pub const CHUNK_CHARS: usize = CHUNK_TOKENS * CHARS_PER_TOKEN;
/// Overlap between adjacent windows in Unicode code points (320).
pub const OVERLAP_CHARS: usize = OVERLAP_TOKENS * CHARS_PER_TOKEN;
/// Notes up to this length (512 tokens ≈ 2,048 code points) keep a single
/// vector only; longer notes also get chunk vectors.
pub const SINGLE_VECTOR_MAX_CHARS: usize = 512 * CHARS_PER_TOKEN;
/// Maximum number of chunks embedded per note; any tail past this is skipped.
pub const MAX_CHUNKS: usize = 16;
/// Search window at the end of a chunk for a newline or space snap point.
pub const SNAP_CHARS: usize = 80;
/// Notes embedded per maintenance backfill batch.
pub const BACKFILL_BATCH: usize = 8;

/// The exact text embedded for a note: title, a blank line, then content.
pub fn embed_source(title: Option<&str>, content: &str) -> String {
    format!("{}\n\n{}", title.unwrap_or(""), content)
}

/// True when a note's embedded source exceeds the single-vector threshold.
pub fn needs_chunks(title: Option<&str>, content: &str) -> bool {
    embed_source(title, content).chars().count() > SINGLE_VECTOR_MAX_CHARS
}

/// Python 3's `str.isspace()` definition: the 25 Unicode `White_Space` code
/// points plus the 4 ASCII separator controls (`\x1c`–`\x1f`), which Rust's
/// `char::is_whitespace` does not treat as whitespace.
pub const fn is_py_space(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{001C}'..='\u{001F}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// Strip leading and trailing whitespace using Python's `str.isspace()`.
pub fn py_strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// Overlapping windows, or `[]` when one vector already covers `text`.
///
/// Mirrors `memory_chunks.py::chunk_text` character for character:
/// - counts length and indices in Unicode code points;
/// - snaps the window end to the last `\n` (else `' '`) in the final
///   [`SNAP_CHARS`] code points, only if the resulting window keeps at least
///   `CHUNK_CHARS / 2` (800) code points;
/// - trims each piece with Python's [`is_py_space`] and skips empty pieces;
/// - emits at most [`MAX_CHUNKS`] (16) chunks.
pub fn chunk_text(text: &str) -> Vec<String> {
    let mut chars: Vec<(usize, char)> = text.char_indices().collect();
    let length = chars.len();
    if length <= SINGLE_VECTOR_MAX_CHARS {
        return Vec::new();
    }
    // Sentinel byte offset at the end so `byte_at(i)` is O(1) for `0..=length`.
    chars.push((text.len(), '\0'));
    let byte_at = |idx: usize| chars[idx].0;

    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < length && chunks.len() < MAX_CHUNKS {
        let mut end = (start + CHUNK_CHARS).min(length);
        if end < length {
            let window_len = end - start;
            let floor = window_len.saturating_sub(SNAP_CHARS);
            let mut snap = None;
            for rel in (floor..window_len).rev() {
                if chars[start + rel].1 == '\n' {
                    snap = Some(rel);
                    break;
                }
            }
            if snap.is_none() {
                for rel in (floor..window_len).rev() {
                    if chars[start + rel].1 == ' ' {
                        snap = Some(rel);
                        break;
                    }
                }
            }
            // Keep the window from collapsing to a sliver on an early snap.
            if let Some(pos) = snap
                && pos >= CHUNK_CHARS / 2
            {
                end = start + pos;
            }
        }
        if end <= start {
            end = (start + CHUNK_CHARS).min(length);
        }
        let piece = py_strip(&text[byte_at(start)..byte_at(end)]);
        if !piece.is_empty() {
            chunks.push(piece.to_string());
        }
        if end >= length {
            break;
        }
        let nxt = end.saturating_sub(OVERLAP_CHARS);
        start = if nxt <= start { end } else { nxt };
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_python_chunker() {
        assert_eq!(CHARS_PER_TOKEN, 4);
        assert_eq!(CHUNK_TOKENS, 400);
        assert_eq!(OVERLAP_TOKENS, 80);
        assert_eq!(CHUNK_CHARS, 1600);
        assert_eq!(OVERLAP_CHARS, 320);
        assert_eq!(SINGLE_VECTOR_MAX_CHARS, 2048);
        assert_eq!(MAX_CHUNKS, 16);
        assert_eq!(SNAP_CHARS, 80);
        assert_eq!(BACKFILL_BATCH, 8);
    }

    #[test]
    fn py_space_matches_exact_29_unicode_code_points() {
        let expected: &[u32] = &[
            0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x001C, 0x001D, 0x001E, 0x001F, 0x0020, 0x0085, 0x00A0,
            0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
            0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
        ];
        let got: Vec<u32> =
            (0..=0x10FFFFu32).filter_map(char::from_u32).filter(|&c| is_py_space(c)).map(u32::from).collect();
        assert_eq!(got, expected);
        // Rust's trim leaves ASCII separator controls intact; py_strip removes them.
        assert_eq!("\x1c\x1dhello\x1e\x1f".trim(), "\x1c\x1dhello\x1e\x1f");
        assert_eq!(py_strip("\x1c\x1dhello\x1e\x1f"), "hello");
    }

    #[test]
    fn threshold_is_strictly_above_2048_code_points() {
        let exact = "a".repeat(SINGLE_VECTOR_MAX_CHARS);
        assert!(chunk_text(&exact).is_empty());

        let one_over = "a".repeat(SINGLE_VECTOR_MAX_CHARS + 1);
        let chunks = chunk_text(&one_over);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].chars().count(), 1600);
        assert_eq!(chunks[1].chars().count(), 2049 - (1600 - 320));
    }

    #[test]
    fn non_ascii_counts_code_points_not_bytes() {
        // 2,048 multi-byte chars (4 bytes each = 8,192 bytes) still fit in one vector.
        let fit = "é".repeat(SINGLE_VECTOR_MAX_CHARS);
        assert!(fit.len() > SINGLE_VECTOR_MAX_CHARS);
        assert!(chunk_text(&fit).is_empty());

        // 2,100 4-byte emoji code points split at code-point boundaries, never panicking.
        let emoji = "🦀".repeat(2100);
        let chunks = chunk_text(&emoji);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].chars().count(), 1600);
        assert_eq!(chunks[1].chars().count(), 2100 - 1280);
    }

    #[test]
    fn boundary_snap_prefers_newline_over_space_in_last_80_chars() {
        // Place a newline at 1540 and a space at 1580 (both inside [1520, 1600)).
        let mut s = "x".repeat(1540);
        s.push('\n');
        s.push_str(&"y".repeat(39));
        s.push(' ');
        s.push_str(&"z".repeat(1000));
        let chunks = chunk_text(&s);
        assert_eq!(chunks[0].chars().count(), 1540);
        assert!(chunks[0].chars().all(|c| c == 'x'));
        // Next chunk starts at 1540 - 320 = 1220, so it carries 320 'x's then '\n' then 'y's.
        assert!(chunks[1].starts_with(&format!("{}\n{}", "x".repeat(320), "y".repeat(39))));
    }

    #[test]
    fn boundary_snap_uses_space_when_no_newline_in_last_80_chars() {
        // Put a newline before floor (at 1500) and a space inside [1520, 1600) (at 1560).
        let mut s = "a".repeat(1500);
        s.push('\n');
        s.push_str(&"b".repeat(59));
        s.push(' ');
        s.push_str(&"c".repeat(1000));
        let chunks = chunk_text(&s);
        assert_eq!(chunks[0].chars().count(), 1560);
        assert!(chunks[0].ends_with(&"b".repeat(59)));
    }

    #[test]
    fn no_snap_when_whitespace_only_before_800_chars() {
        // Whitespace only at index 500 (< 800 and outside final 80 chars): must cut at 1600.
        let mut s = "a".repeat(500);
        s.push('\n');
        s.push_str(&"b".repeat(2000));
        let chunks = chunk_text(&s);
        assert_eq!(chunks[0].chars().count(), 1600);
    }

    #[test]
    fn control_separator_padding_is_stripped_like_python() {
        let s = format!("{}{}{}", "\x1c".repeat(20), "m".repeat(2200), "\x1f".repeat(20));
        let chunks = chunk_text(&s);
        assert!(!chunks.is_empty());
        assert!(!chunks[0].starts_with('\x1c'));
        assert!(!chunks.last().unwrap().ends_with('\x1f'));
    }

    #[test]
    fn caps_at_max_chunks() {
        let huge = "w".repeat(30_000);
        let chunks = chunk_text(&huge);
        assert_eq!(chunks.len(), MAX_CHUNKS);
    }

    #[test]
    fn exact_parity_with_python_reference_outputs() {
        // Golden lengths and edge slices produced by Python `memory_chunks.py::chunk_text`.
        let non_ascii = "café 🦀 ".repeat(320);
        let cs = chunk_text(&non_ascii);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].chars().count(), 1595);
        assert_eq!(cs[1].chars().count(), 964);
        assert!(cs[0].starts_with("café 🦀 caf"));
        assert!(cs[0].ends_with("é 🦀 café 🦀"));
        assert!(cs[1].starts_with("afé 🦀 café"));
        assert!(cs[1].ends_with("é 🦀 café 🦀"));

        let x1c = format!(
            "{}{}{}{}{}",
            "\x1c".repeat(20),
            "m".repeat(1570),
            "\x1c".repeat(40),
            "n".repeat(900),
            "\x1f".repeat(20)
        );
        let cs = chunk_text(&x1c);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].chars().count(), 1570);
        assert_eq!(cs[1].chars().count(), 1250);
        assert!(cs[0].chars().all(|c| c == 'm'));
        assert!(cs[1].starts_with("mmmmmmmmmm"));
        assert!(cs[1].ends_with("nnnnnnnnnn"));

        // A window whose middle is entirely Python separator whitespace skips the empty piece.
        let all_space = format!("{}{}{}", "a".repeat(100), "\x1c".repeat(1600), "b".repeat(1000));
        let cs = chunk_text(&all_space);
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].chars().count(), 100);
        assert_eq!(cs[1].chars().count(), 1000);
        assert!(cs[0].chars().all(|c| c == 'a'));
        assert!(cs[1].chars().all(|c| c == 'b'));
    }
}
