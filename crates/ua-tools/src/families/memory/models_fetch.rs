//! Offline preparation for local ONNX embedding models (`ua memory models fetch`).
//!
//! Downloads every file in the pinned manifest through `ua_ingress::Outbound`
//! (`MODEL_DOWNLOAD`: HTTPS only, public addresses, no scheme downgrade, no
//! proxy), streams directly to a temporary file while verifying its exact
//! byte size and SHA-256 digest, and atomically installs it into
//! `<home>/models/<slug>/<revision>/`.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};
use ua_ingress::policy::MODEL_DOWNLOAD;
use ua_ingress::{Outbound, Request, Url};
use ua_memory::models::{
    LocalModelPresence, PinnedModel, check_local_model_presence, file_url, lookup_pinned_model, model_dir,
    sha256_file, verify_local_model_on_disk,
};

/// Result of fetching or checking a pinned local embedding model.
#[derive(Debug, Clone, Serialize)]
pub struct ModelFetchReport {
    pub model: String,
    pub revision: String,
    pub dir: String,
    pub downloaded: Vec<String>,
    pub already_present: Vec<String>,
    pub verified: bool,
}

/// Read-only status of a pinned local embedding model on disk (never downloads).
#[derive(Debug, Clone, Serialize)]
pub struct ModelStatusReport {
    pub requested: String,
    pub canonical_id: Option<String>,
    pub revision: Option<String>,
    pub dir: Option<String>,
    pub present: bool,
    pub verified: Option<bool>,
    pub detail: String,
}

/// Inspect a local embedding model on disk without touching the network.
pub fn local_model_status(home: &Path, model_name: &str, verify_sha: bool) -> ModelStatusReport {
    match check_local_model_presence(home, model_name) {
        LocalModelPresence::UnknownModel { requested } => ModelStatusReport {
            requested,
            canonical_id: None,
            revision: None,
            dir: None,
            present: false,
            verified: None,
            detail: "not a pinned local model".into(),
        },
        LocalModelPresence::Missing { dir, spec, missing_or_wrong_size } => ModelStatusReport {
            requested: model_name.to_string(),
            canonical_id: Some(spec.canonical_id.into()),
            revision: Some(spec.revision.into()),
            dir: Some(dir.display().to_string()),
            present: false,
            verified: Some(false),
            detail: format!(
                "missing or mismatched file(s): {}; run `ua memory models fetch`",
                missing_or_wrong_size.join(", ")
            ),
        },
        LocalModelPresence::Present { dir, spec } => {
            if verify_sha {
                match verify_local_model_on_disk(home, model_name) {
                    Ok(_) => ModelStatusReport {
                        requested: model_name.to_string(),
                        canonical_id: Some(spec.canonical_id.into()),
                        revision: Some(spec.revision.into()),
                        dir: Some(dir.display().to_string()),
                        present: true,
                        verified: Some(true),
                        detail: "all pinned files present and SHA-256 verified".into(),
                    },
                    Err(err) => ModelStatusReport {
                        requested: model_name.to_string(),
                        canonical_id: Some(spec.canonical_id.into()),
                        revision: Some(spec.revision.into()),
                        dir: Some(dir.display().to_string()),
                        present: false,
                        verified: Some(false),
                        detail: format!("verification failed: {err}"),
                    },
                }
            } else {
                ModelStatusReport {
                    requested: model_name.to_string(),
                    canonical_id: Some(spec.canonical_id.into()),
                    revision: Some(spec.revision.into()),
                    dir: Some(dir.display().to_string()),
                    present: true,
                    verified: None,
                    detail: "all pinned files present on disk".into(),
                }
            }
        }
    }
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Download and SHA-256 verify every file of the pinned local model `model_name`
/// into `<home>/models/<slug>/<revision>/`.
pub async fn fetch_local_model(
    home: &Path,
    model_name: &str,
    force: bool,
) -> anyhow::Result<ModelFetchReport> {
    let spec = lookup_pinned_model(model_name).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown pinned local embedding model {model_name:?}; supported: {}",
            ua_memory::models::PINNED_MODELS.iter().map(|m| m.canonical_id).collect::<Vec<_>>().join(", ")
        )
    })?;
    let client = Outbound::new(MODEL_DOWNLOAD)?;
    fetch_pinned_with_client(home, spec, &client, None, force).await
}

/// Download a pinned model with a caller-supplied `Outbound` client and optional
/// base URL override (used in offline tests).
pub async fn fetch_pinned_with_client(
    home: &Path,
    spec: &'static PinnedModel,
    client: &Outbound,
    base_url_override: Option<&str>,
    force: bool,
) -> anyhow::Result<ModelFetchReport> {
    let dir = model_dir(home, spec);
    fs::create_dir_all(&dir)?;

    let mut downloaded = Vec::new();
    let mut already_present = Vec::new();

    for file in spec.files {
        let dest = dir.join(file.rel_path);
        if !force
            && let Ok(meta) = fs::metadata(&dest)
            && meta.is_file()
            && meta.len() == file.size_bytes
            && sha256_file(&dest).ok().as_deref() == Some(file.sha256)
        {
            already_present.push(file.rel_path.to_string());
            continue;
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw_url = match base_url_override {
            Some(base) => format!("{}/{}", base.trim_end_matches('/'), file.rel_path),
            None => file_url(spec, file),
        };
        let url = Url::parse(&raw_url)?;
        let resp = client.send(Request::get(url)).await?;
        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("fetching {} returned HTTP {}", file.rel_path, status.as_u16());
        }

        static PART_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let seq = PART_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base_name = dest.file_name().and_then(|s| s.to_str()).unwrap_or("model");
        let tmp_path: PathBuf = dest.with_file_name(format!("{base_name}.{}.{seq}.part", std::process::id()));
        let write_res = async {
            let f = File::create(&tmp_path)?;
            let mut hw = HashingWriter { inner: f, hasher: Sha256::new() };
            let written = resp.stream_to_writer(&mut hw).await?;
            hw.flush()?;
            let actual_sha = hex::encode(hw.hasher.finalize());
            if written as u64 != file.size_bytes {
                anyhow::bail!("{} downloaded {} bytes, expected {}", file.rel_path, written, file.size_bytes);
            }
            if actual_sha != file.sha256 {
                anyhow::bail!(
                    "{} SHA-256 mismatch (expected {}, got {actual_sha})",
                    file.rel_path,
                    file.sha256
                );
            }
            fs::rename(&tmp_path, &dest)?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        downloaded.push(file.rel_path.to_string());
    }

    Ok(ModelFetchReport {
        model: spec.canonical_id.into(),
        revision: spec.revision.into(),
        dir: dir.display().to_string(),
        downloaded,
        already_present,
        verified: true,
    })
}
