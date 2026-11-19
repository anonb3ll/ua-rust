//! `read_image` and the image header helpers `web_fetch` shares.
//!
//! Format and dimensions come from header bytes only (no image decoder), so
//! a truncated or odd file yields unknown dimensions rather than an error.

use base64::Engine;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use ua_core::safety::resolve_in_root;
use ua_core::{UaError, UaResult};

use crate::families::workspace::{Sandbox, sandbox};
use crate::registry::{Registry, ToolCtx, blocking, tool};

/// Largest image `read_image` returns.
pub const IMAGE_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadImageArgs {
    /// Image path inside the workspace root.
    pub path: String,
}

/// The image MIME type from magic bytes, or `None`.
pub fn sniff_image_mime(data: &[u8]) -> Option<&'static str> {
    if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    const TABLE: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"BM", "image/bmp"),
    ];
    TABLE.iter().find(|(magic, _)| data.starts_with(magic)).map(|(_, m)| *m)
}

fn be16(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from(u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?])))
}

fn le16(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from(u16::from_le_bytes([*d.get(i)?, *d.get(i + 1)?])))
}

fn be32(d: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(i..i + 4)?.try_into().ok()?))
}

fn le32i(d: &[u8], i: usize) -> Option<i32> {
    Some(i32::from_le_bytes(d.get(i..i + 4)?.try_into().ok()?))
}

/// Best-effort `(width, height)` from header bytes.
pub fn image_dimensions(mime: &str, d: &[u8]) -> (Option<u32>, Option<u32>) {
    let dims = match mime {
        "image/png" => be32(d, 16).zip(be32(d, 20)),
        "image/gif" => le16(d, 6).zip(le16(d, 8)),
        "image/bmp" => le32i(d, 18).zip(le32i(d, 22)).map(|(w, h)| (w.unsigned_abs(), h.unsigned_abs())),
        "image/jpeg" => jpeg_dimensions(d),
        "image/webp" => webp_dimensions(d),
        _ => None,
    };
    match dims {
        Some((w, h)) => (Some(w), Some(h)),
        None => (None, None),
    }
}

fn jpeg_dimensions(d: &[u8]) -> Option<(u32, u32)> {
    let mut i = 2;
    while i + 9 < d.len() {
        if d[i] != 0xFF {
            i += 1;
            continue;
        }
        let marker = d[i + 1];
        if matches!(marker, 0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF) {
            return Some((be16(d, i + 7)?, be16(d, i + 5)?));
        }
        if matches!(marker, 0xD8 | 0xD9 | 0xD0..=0xD7 | 0xFF) {
            i += if marker == 0xFF { 1 } else { 2 };
            continue;
        }
        i += 2 + be16(d, i + 2)? as usize;
    }
    None
}

fn webp_dimensions(d: &[u8]) -> Option<(u32, u32)> {
    if d.len() < 30 {
        return None;
    }
    match &d[12..16] {
        b"VP8 " => Some((le16(d, 26)? & 0x3FFF, le16(d, 28)? & 0x3FFF)),
        b"VP8L" => {
            let (b0, b1, b2, b3) = (u32::from(d[21]), u32::from(d[22]), u32::from(d[23]), u32::from(d[24]));
            Some((((b1 & 0x3F) << 8 | b0) + 1, ((b3 & 0x0F) << 10 | b2 << 2 | (b1 & 0xC0) >> 6) + 1))
        }
        b"VP8X" => {
            let w = u32::from(d[24]) | u32::from(d[25]) << 8 | u32::from(d[26]) << 16;
            let h = u32::from(d[27]) | u32::from(d[28]) << 8 | u32::from(d[29]) << 16;
            Some((w + 1, h + 1))
        }
        _ => None,
    }
}

pub fn human_bytes(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.0} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1024.0 * 1024.0))
    }
}

/// One deterministic line: format, dimensions, size. No OCR.
pub fn describe_image(mime: &str, w: Option<u32>, h: Option<u32>, nbytes: usize) -> String {
    let fmt = mime.rsplit('/').next().unwrap_or(mime).to_uppercase();
    let dims = match (w, h) {
        (Some(w), Some(h)) if w > 0 && h > 0 => format!("{w}x{h}"),
        _ => "unknown size".into(),
    };
    format!("{fmt} image, {dims}, {}", human_bytes(nbytes))
}

fn read_image(sb: &Sandbox, path: &str) -> UaResult<Value> {
    let p = resolve_in_root(path, std::slice::from_ref(&sb.root), false)?;
    let meta = std::fs::metadata(&p).map_err(|_| UaError::not_found(format!("no file at {path:?}")))?;
    if !meta.is_file() {
        return Err(UaError::not_found(format!("no file at {path:?}")));
    }
    if meta.len() > IMAGE_MAX_BYTES {
        return Err(UaError::invalid(format!(
            "image is {}, over the {} cap",
            human_bytes(meta.len() as usize),
            human_bytes(IMAGE_MAX_BYTES as usize)
        )));
    }
    let data = std::fs::read(&p).map_err(|e| UaError::invalid(format!("cannot read {path}: {e}")))?;
    let Some(mime) = sniff_image_mime(&data) else {
        return Err(UaError::invalid(format!(
            "{path:?} is not a recognized image (PNG/JPEG/GIF/WebP/BMP); read it with fs_read if it is text"
        )));
    };
    let (w, h) = image_dimensions(mime, &data);
    Ok(json!({
        "base64": base64::engine::general_purpose::STANDARD.encode(&data),
        "mime": mime,
        "width": w,
        "height": h,
        "bytes": data.len(),
        "description": describe_image(mime, w, h, data.len()),
    }))
}

pub fn register(r: &mut Registry) {
    r.add(
        tool(
            "read_image",
            "Read a workspace image (PNG, JPEG, GIF, WebP, BMP; max 2 MB). Returns {base64, mime, width, \
             height, bytes, description}; the description is format, pixel size and byte size (no OCR).",
            |ctx: ToolCtx, a: ReadImageArgs| async move {
                let sb = sandbox(&ctx)?;
                blocking(move || read_image(&sb, &a.path)).await
            },
        )
        .family("code")
        .read_only(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_header() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
        png.extend_from_slice(&640u32.to_be_bytes());
        png.extend_from_slice(&480u32.to_be_bytes());
        assert_eq!(sniff_image_mime(&png), Some("image/png"));
        assert_eq!(image_dimensions("image/png", &png), (Some(640), Some(480)));
        assert_eq!(describe_image("image/png", Some(640), Some(480), 2048), "PNG image, 640x480, 2 KB");
    }
}
