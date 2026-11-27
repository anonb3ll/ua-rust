//! Pinned local embedding model catalog and offline verification.
//!
//! Save, search, and `system_doctor` NEVER download models. This module holds
//! the pinned revision and SHA-256 digests of supported local ONNX models and
//! verifies files already present under `<cfg.home>/models/<slug>/<revision>/`.
//! Offline preparation is performed exclusively by `ua memory models fetch`
//! (also invoked by `ua init`).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// One pinned file inside a local embedding model bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedFile {
    /// Relative path inside both the Hugging Face repository and the local model dir.
    pub rel_path: &'static str,
    /// Expected exact size in bytes.
    pub size_bytes: u64,
    /// Expected lowercase hex SHA-256 digest.
    pub sha256: &'static str,
}

/// A pinned local ONNX embedding model specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedModel {
    /// Canonical model name used in vector identities (`local:<canonical_id>@<revision>`).
    pub canonical_id: &'static str,
    /// Filesystem-safe directory slug under `<home>/models/`.
    pub slug: &'static str,
    /// Source Hugging Face repository hosting the ONNX export.
    pub hf_repo: &'static str,
    /// Pinned Git commit SHA on Hugging Face.
    pub revision: &'static str,
    /// Accepted configuration names / aliases.
    pub aliases: &'static [&'static str],
    /// Required files, in fetch and verification order.
    pub files: &'static [PinnedFile],
}

/// Default local English embedding model: `BAAI/bge-small-en-v1.5` (384-dim,
/// CLS pooling, MIT license) exported as ONNX in `Xenova/bge-small-en-v1.5`
/// at pinned revision `ea104dacec62c0de699686887e3f920caeb4f3e3`.
pub const BGE_SMALL_EN_V15: PinnedModel = PinnedModel {
    canonical_id: "BAAI/bge-small-en-v1.5",
    slug: "bge-small-en-v1.5",
    hf_repo: "Xenova/bge-small-en-v1.5",
    revision: "ea104dacec62c0de699686887e3f920caeb4f3e3",
    aliases: &["BAAI/bge-small-en-v1.5", "Xenova/bge-small-en-v1.5", "BGESmallENV15", "bge-small-en-v1.5"],
    files: &[
        PinnedFile {
            rel_path: "onnx/model.onnx",
            size_bytes: 133_093_490,
            sha256: "828e1496d7fabb79cfa4dcd84fa38625c0d3d21da474a00f08db0f559940cf35",
        },
        PinnedFile {
            rel_path: "tokenizer.json",
            size_bytes: 711_396,
            sha256: "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
        },
        PinnedFile {
            rel_path: "config.json",
            size_bytes: 683,
            sha256: "fa73f90bf92c8cace1fbcb709626306f2bdbc9ea3e5b5f94b440df9b6aa56350",
        },
        PinnedFile {
            rel_path: "special_tokens_map.json",
            size_bytes: 125,
            sha256: "b6d346be366a7d1d48332dbc9fdf3bf8960b5d879522b7799ddba59e76237ee3",
        },
        PinnedFile {
            rel_path: "tokenizer_config.json",
            size_bytes: 366,
            sha256: "9261e7d79b44c8195c1cada2b453e55b00aeb81e907a6664974b4d7776172ab3",
        },
    ],
};

/// All pinned local models supported by this build.
pub const PINNED_MODELS: &[PinnedModel] = &[BGE_SMALL_EN_V15];

/// Look up a pinned model specification by canonical id or alias (case-insensitive).
pub fn lookup_pinned_model(name: &str) -> Option<&'static PinnedModel> {
    let trimmed = name.trim();
    PINNED_MODELS.iter().find(|m| m.aliases.iter().any(|a| a.eq_ignore_ascii_case(trimmed)))
}

/// Local directory where `spec`'s pinned files live: `<home>/models/<slug>/<revision>`.
pub fn model_dir(home: &Path, spec: &PinnedModel) -> PathBuf {
    home.join("models").join(spec.slug).join(spec.revision)
}

/// Upstream HTTPS URL for one pinned file at the pinned Git revision.
pub fn file_url(spec: &PinnedModel, file: &PinnedFile) -> String {
    format!("https://huggingface.co/{}/resolve/{}/{}", spec.hf_repo, spec.revision, file.rel_path)
}

/// Fast, non-blocking metadata check of whether a pinned model is present on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalModelPresence {
    Present { dir: PathBuf, spec: &'static PinnedModel },
    Missing { dir: PathBuf, spec: &'static PinnedModel, missing_or_wrong_size: Vec<&'static str> },
    UnknownModel { requested: String },
}

/// Check whether every pinned file for `model_name` exists on disk with its
/// expected byte size. Never touches the network and never hashes 133 MB on
/// hot request paths; full SHA-256 verification runs once when the model loads.
pub fn check_local_model_presence(home: &Path, model_name: &str) -> LocalModelPresence {
    let Some(spec) = lookup_pinned_model(model_name) else {
        return LocalModelPresence::UnknownModel { requested: model_name.to_string() };
    };
    let dir = model_dir(home, spec);
    let mut bad = Vec::new();
    for f in spec.files {
        let p = dir.join(f.rel_path);
        match fs::metadata(&p) {
            Ok(meta) if meta.is_file() && meta.len() == f.size_bytes => {}
            _ => bad.push(f.rel_path),
        }
    }
    if bad.is_empty() {
        LocalModelPresence::Present { dir, spec }
    } else {
        LocalModelPresence::Missing { dir, spec, missing_or_wrong_size: bad }
    }
}

/// Compute lowercase hex SHA-256 of a file on disk without loading it whole into RAM.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Verified bytes of a local model ready to pass into ONNX Runtime with zero
/// network access.
#[derive(Debug)]
pub struct VerifiedLocalModel {
    pub spec: &'static PinnedModel,
    pub onnx_file: Vec<u8>,
    pub tokenizer_file: Vec<u8>,
    pub config_file: Vec<u8>,
    pub special_tokens_map_file: Vec<u8>,
    pub tokenizer_config_file: Vec<u8>,
}

/// Read and SHA-256 verify every file of a pinned local model on disk.
/// Never touches the network.
pub fn load_verified_local_model(home: &Path, model_name: &str) -> Result<VerifiedLocalModel, String> {
    let Some(spec) = lookup_pinned_model(model_name) else {
        return Err(format!("unknown pinned local embedding model {model_name:?}"));
    };
    load_verified_pinned_model(home, spec)
}

/// Read and SHA-256 verify every file of a specific [`PinnedModel`] manifest on
/// disk. Never touches the network.
pub fn load_verified_pinned_model(
    home: &Path,
    spec: &'static PinnedModel,
) -> Result<VerifiedLocalModel, String> {
    let dir = model_dir(home, spec);
    let mut loaded: Vec<(&'static str, Vec<u8>)> = Vec::with_capacity(spec.files.len());
    for f in spec.files {
        let path = dir.join(f.rel_path);
        let bytes = fs::read(&path).map_err(|e| {
            format!(
                "local embedding model {} is missing {} ({e}); run `ua memory models fetch`",
                spec.canonical_id, f.rel_path
            )
        })?;
        if bytes.len() as u64 != f.size_bytes {
            return Err(format!(
                "local embedding model {} file {} has size {} bytes, expected {}; re-run `ua memory models fetch --force`",
                spec.canonical_id,
                f.rel_path,
                bytes.len(),
                f.size_bytes
            ));
        }
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != f.sha256 {
            return Err(format!(
                "local embedding model {} file {} failed SHA-256 verification (expected {}, got {}); re-run `ua memory models fetch --force`",
                spec.canonical_id, f.rel_path, f.sha256, actual
            ));
        }
        loaded.push((f.rel_path, bytes));
    }
    let mut take = |name: &str| -> Result<Vec<u8>, String> {
        let pos = loaded
            .iter()
            .position(|(k, _)| *k == name)
            .ok_or_else(|| format!("missing {name} in manifest"))?;
        Ok(loaded.swap_remove(pos).1)
    };
    Ok(VerifiedLocalModel {
        spec,
        onnx_file: take("onnx/model.onnx")?,
        tokenizer_file: take("tokenizer.json")?,
        config_file: take("config.json")?,
        special_tokens_map_file: take("special_tokens_map.json")?,
        tokenizer_config_file: take("tokenizer_config.json")?,
    })
}

/// Verify SHA-256 digests of all pinned files on disk without keeping them in memory.
pub fn verify_local_model_on_disk(home: &Path, model_name: &str) -> Result<&'static PinnedModel, String> {
    let Some(spec) = lookup_pinned_model(model_name) else {
        return Err(format!("unknown pinned local embedding model {model_name:?}"));
    };
    let dir = model_dir(home, spec);
    for f in spec.files {
        let path = dir.join(f.rel_path);
        let meta = fs::metadata(&path).map_err(|e| format!("missing {} ({e})", f.rel_path))?;
        if !meta.is_file() || meta.len() != f.size_bytes {
            return Err(format!("{} has size {} bytes, expected {}", f.rel_path, meta.len(), f.size_bytes));
        }
        let actual = sha256_file(&path).map_err(|e| format!("reading {} ({e})", f.rel_path))?;
        if actual != f.sha256 {
            return Err(format!("{} SHA-256 mismatch (expected {}, got {actual})", f.rel_path, f.sha256));
        }
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_matches_aliases_case_insensitively() {
        for alias in
            ["BAAI/bge-small-en-v1.5", "baai/bge-small-en-v1.5", "Xenova/bge-small-en-v1.5", "BGESmallENV15"]
        {
            let m = lookup_pinned_model(alias).expect(alias);
            assert_eq!(m.canonical_id, "BAAI/bge-small-en-v1.5");
        }
        assert!(lookup_pinned_model("unknown/model").is_none());
    }

    #[test]
    fn presence_reports_missing_when_empty_and_load_fails_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let status = check_local_model_presence(dir.path(), "BAAI/bge-small-en-v1.5");
        assert!(matches!(status, LocalModelPresence::Missing { .. }), "{status:?}");
        let err = load_verified_local_model(dir.path(), "BAAI/bge-small-en-v1.5").unwrap_err();
        assert!(err.contains("ua memory models fetch"), "{err}");
    }

    #[test]
    fn load_verified_pinned_model_rejects_same_size_corruption_and_size_mismatch() {
        const ONNX: &[u8] = b"fake-onnx-bytes-0123";
        const TOK: &[u8] = b"{\"tok\":1}";
        const CFG: &[u8] = b"{\"cfg\":1}";
        const SPEC: &[u8] = b"{\"spc\":1}";
        const TCFG: &[u8] = b"{\"tcf\":1}";

        let sha = |b: &[u8]| -> &'static str { Box::leak(hex::encode(Sha256::digest(b)).into_boxed_str()) };
        let files: &'static [PinnedFile] = Box::leak(
            vec![
                PinnedFile { rel_path: "onnx/model.onnx", size_bytes: ONNX.len() as u64, sha256: sha(ONNX) },
                PinnedFile { rel_path: "tokenizer.json", size_bytes: TOK.len() as u64, sha256: sha(TOK) },
                PinnedFile { rel_path: "config.json", size_bytes: CFG.len() as u64, sha256: sha(CFG) },
                PinnedFile {
                    rel_path: "special_tokens_map.json",
                    size_bytes: SPEC.len() as u64,
                    sha256: sha(SPEC),
                },
                PinnedFile {
                    rel_path: "tokenizer_config.json",
                    size_bytes: TCFG.len() as u64,
                    sha256: sha(TCFG),
                },
            ]
            .into_boxed_slice(),
        );
        let pinned: &'static PinnedModel = Box::leak(Box::new(PinnedModel {
            canonical_id: "test/tiny-local",
            aliases: &[],
            slug: "tiny-local",
            hf_repo: "test/tiny-local",
            revision: "deadbeef1234",
            files,
        }));

        let dir = tempfile::tempdir().unwrap();
        let mdir = model_dir(dir.path(), pinned);
        fs::create_dir_all(mdir.join("onnx")).unwrap();
        fs::write(mdir.join("onnx/model.onnx"), ONNX).unwrap();
        fs::write(mdir.join("tokenizer.json"), TOK).unwrap();
        fs::write(mdir.join("config.json"), CFG).unwrap();
        fs::write(mdir.join("special_tokens_map.json"), SPEC).unwrap();
        fs::write(mdir.join("tokenizer_config.json"), TCFG).unwrap();

        // Valid files load cleanly.
        let ok = load_verified_pinned_model(dir.path(), pinned).expect("valid model loads");
        assert_eq!(ok.onnx_file, ONNX);

        // Same-size 1-byte corruption MUST be refused by SHA-256 verification (catches M10).
        let mut corrupt = ONNX.to_vec();
        corrupt[0] ^= 0xff;
        assert_eq!(corrupt.len(), ONNX.len());
        fs::write(mdir.join("onnx/model.onnx"), &corrupt).unwrap();
        let err = load_verified_pinned_model(dir.path(), pinned).unwrap_err();
        assert!(err.contains("SHA-256 verification"), "expected SHA-256 failure, got: {err}");

        // Wrong-size file is refused before hashing.
        fs::write(mdir.join("onnx/model.onnx"), b"short").unwrap();
        let err_sz = load_verified_pinned_model(dir.path(), pinned).unwrap_err();
        assert!(err_sz.contains("has size 5 bytes"), "expected size failure, got: {err_sz}");
    }
}
