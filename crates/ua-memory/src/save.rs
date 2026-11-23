//! Saving a note (`memory_save`): create, update, append, a cross-author
//! overwrite, supersede, and the compare-and-set and idempotency guards.

use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};
use ua_core::{Caller, Config, UaError, UaResult};
use ua_store::{Db, WriteTx};

use super::embed::{self, BruteForceIndex, VectorIndex, embedder_for};
use super::note::{
    self, Eligibility, Note, assert_privileged, embed_text, emit, json_opt, json_text, ledger_label,
    ledger_text, linked_note, text_sha, write_author,
};
use super::rank;
use crate::blocking;

/// What to save. The `memory_save` tool documents each field for agents.
#[derive(Debug, Clone, Default)]
pub struct SaveRequest {
    /// Note text (Markdown). Must not be empty.
    pub content: String,
    /// Short title. On update, omitted keeps the stored title.
    pub title: Option<String>,
    /// Tags. On update, omitted keeps the stored tags; `[]` clears them. The
    /// `broadcast` tag is reserved for a verified human.
    pub tags: Option<Vec<String>>,
    /// Existing note id to update. Omit to create a note.
    pub id: Option<String>,
    /// Your agent label. A verified caller's identity is stamped instead; a
    /// claim that contradicts it is refused.
    pub author: Option<String>,
    /// Append an attributed block to an existing note instead of replacing
    /// its content. Safe on a peer's note. Needs `id`.
    pub append: bool,
    /// Replace a note owned by another author. The replaced content is kept
    /// as an attributed tombstone at the end of the new content.
    pub overwrite: bool,
    /// On create: only report similar existing notes, write nothing.
    pub check_only: bool,
    /// Importance 0-1 (default 0.5). Above 0.8 is reserved for a verified human.
    pub salience: Option<f64>,
    /// Author-stated confidence 0-1.
    pub confidence: Option<f64>,
    /// ISO date or datetime after which the note drops out of default search
    /// and listing. It is never deleted.
    pub expires_at: Option<String>,
    /// Remove a stored expiry.
    pub clear_expires_at: bool,
    /// Client token for retry safety: a replay returns the first receipt.
    pub idempotency_key: Option<String>,
    /// `fact` (observed) or `inferred` (concluded; needs `evidence`).
    pub epistemic: Option<String>,
    /// Supporting refs `<kind>:<id>`; kind one of approval, commit,
    /// delegation, event, memory, pr, run, session, task, url, vault. At most
    /// 20; merged with stored refs on update.
    pub evidence: Option<Vec<String>>,
    /// ISO date or datetime the claim became true.
    pub valid_from: Option<String>,
    /// On create only: id of a live note this one replaces. The old note
    /// leaves default search and listing but stays readable and restorable.
    pub supersedes: Option<String>,
    /// Ids of notes this one disputes without replacing them. On update a
    /// list replaces the stored links and `[]` clears them.
    pub contradicts: Option<Vec<String>>,
    /// On update: replace the stored evidence with `evidence` instead of merging.
    pub evidence_replace: bool,
    /// On update: the `revision` `memory_get` returned. If the note changed
    /// since, nothing is written and the call fails with `conflict`.
    pub expected_revision: Option<String>,
}

/// Validated arguments.
struct Prepared {
    content: String,
    title: Option<String>,
    tags: Option<Vec<String>>,
    id: Option<String>,
    author: Option<String>,
    append: bool,
    overwrite: bool,
    check_only: bool,
    salience: Option<f64>,
    confidence: Option<f64>,
    expires_at: Option<String>,
    clear_expires_at: bool,
    idempotency_key: Option<String>,
    epistemic: Option<String>,
    evidence: Vec<String>,
    valid_from: Option<String>,
    supersedes: Option<String>,
    contradicts: Option<Vec<String>>,
    evidence_replace: bool,
    expected_revision: Option<String>,
}

fn unit_interval(v: Option<f64>, field: &str) -> UaResult<Option<f64>> {
    match v {
        Some(x) if !x.is_finite() || !(0.0..=1.0).contains(&x) => {
            Err(UaError::invalid(format!("{field} must be between 0 and 1; got {x}")))
        }
        other => Ok(other),
    }
}

impl Prepared {
    fn new(caller: &Caller, a: SaveRequest) -> UaResult<Self> {
        if a.content.trim().is_empty() {
            return Err(UaError::invalid("content must not be empty"));
        }
        let author = write_author(caller, a.author)?;
        let epistemic = match a.epistemic.as_deref().map(|s| s.trim().to_lowercase()) {
            None => None,
            Some(e) if e == "fact" || e == "inferred" => Some(e),
            Some(other) => {
                return Err(UaError::invalid(format!(
                    "epistemic must be one of fact, inferred; got {other:?}"
                )));
            }
        };
        let evidence = note::normalize_evidence(a.evidence)?;
        let contradicts = match a.contradicts {
            None => None,
            Some(list) => Some(note::normalize_ids(Some(list), "contradicts")?),
        };
        let valid_from =
            a.valid_from.as_deref().map(|v| note::parse_instant(v, "valid_from", true)).transpose()?;
        let supersedes = match a.supersedes {
            None => None,
            Some(s) if s.trim().is_empty() => {
                return Err(UaError::invalid("supersedes must be a memory note id"));
            }
            Some(s) => Some(s.trim().to_string()),
        };
        if supersedes.is_some() && a.id.is_some() {
            return Err(UaError::invalid(
                "supersedes is only supported when creating the replacement note (omit id)",
            ));
        }
        if a.append && a.overwrite {
            return Err(UaError::invalid("pass at most one of append or overwrite"));
        }
        if a.append && a.id.is_none() {
            return Err(UaError::invalid("append=True requires an existing note id to append to"));
        }
        if a.check_only && a.id.is_some() {
            return Err(UaError::invalid(
                "check_only=True is only supported when creating a new note (omitting id)",
            ));
        }
        if let Some(rev) = &a.expected_revision {
            if a.id.is_none() {
                return Err(UaError::invalid(
                    "expected_revision applies to an update; pass the note id with it",
                ));
            }
            let ok = rev.strip_prefix("sha256:").is_some_and(|h| {
                h.len() == 64 && h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
            });
            if !ok {
                return Err(UaError::invalid(
                    "expected_revision must be the `revision` memory_get returned ('sha256:' + 64 lowercase hex)",
                ));
            }
        }
        if a.expires_at.is_some() && a.clear_expires_at {
            return Err(UaError::invalid("pass either expires_at or clear_expires_at=True, not both"));
        }
        let expires_at =
            a.expires_at.as_deref().map(|v| note::parse_instant(v, "expires_at", true)).transpose()?;
        let tags = a.tags.map(|t| {
            let mut t: Vec<String> =
                t.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
            t.sort();
            t.dedup();
            t
        });
        let salience = unit_interval(a.salience, "salience")?;
        let confidence = unit_interval(a.confidence, "confidence")?;
        // A requested broadcast tag or high salience is gated before anything
        // is read; tags kept from the stored note are checked again later.
        if tags.is_some() || salience.is_some() {
            assert_privileged(caller, tags.as_deref().unwrap_or(&[]), salience)?;
        }
        Ok(Self {
            content: a.content,
            title: a.title,
            tags,
            id: a.id.map(|s| s.trim().to_string()),
            author,
            append: a.append,
            overwrite: a.overwrite,
            check_only: a.check_only,
            salience,
            confidence,
            expires_at,
            clear_expires_at: a.clear_expires_at,
            idempotency_key: a.idempotency_key.filter(|k| !k.trim().is_empty()),
            epistemic,
            evidence,
            valid_from,
            supersedes,
            contradicts,
            evidence_replace: a.evidence_replace,
            expected_revision: a.expected_revision,
        })
    }
}

struct Outcome {
    result: Value,
    /// Note to (re-)embed after commit: id, title, content.
    embed_after: Option<(String, Option<String>, String)>,
}

/// Create a note (no `id`) or update one, as `caller`, in the caller's
/// organization. Returns `{id, created, revision}` (and `similar` on create),
/// or `{similar}` for `check_only`. Only the caller's organization's notes
/// are read, updated, superseded, contradicted or reported as similar.
///
/// With an available embedder, a new note is embedded before the write so
/// its vector commits with it; an updated note is re-embedded after the
/// commit, and the vector is stored only if the note still holds that text.
pub async fn save(db: &Db, cfg: &Config, caller: &Caller, req: SaveRequest) -> UaResult<Value> {
    let p = Prepared::new(caller, req)?;
    let embedder = embedder_for(cfg);
    let model = embedder.model().to_string();

    // Create: embed first, so the vector commits with the note and the
    // similar-note check can run. Failure only drops the semantic part.
    let mut create_vec: Option<Vec<f32>> = None;
    let mut similar: Vec<Value> = Vec::new();
    if p.id.is_none() && embedder.available() {
        let (e, text) = (embedder.clone(), embed_text(p.title.as_deref(), &p.content));
        match blocking(move || Ok(embed::embed_one(&*e, text))).await? {
            Ok(v) => create_vec = Some(v),
            Err(err) => {
                tracing::debug!(category = err.category, error = %err.message, "memory_save: no embedding")
            }
        }
        if let Some(v) = create_vec.clone() {
            let (m, content, org) = (model.clone(), p.content.clone(), caller.org_id.clone());
            similar = db.read_async(move |c| similar_notes(c, &org, &m, &v, &content)).await?;
        }
    }
    if p.check_only {
        return Ok(json!({ "similar": similar }));
    }

    let org = caller.org_id.clone();
    let caller = caller.clone();
    let m = model.clone();
    let creating = p.id.is_none();
    let outcome = db.write_async(move |tx| write(tx, &caller, p, create_vec.map(|v| (m, v)))).await?;
    let mut result = outcome.result;
    if creating && result.get("similar").is_some() {
        result["similar"] = json!(similar);
    }

    // Update: embed the committed text, and store the vector only if the
    // note still holds that text.
    if let Some((id, title, content)) = outcome.embed_after
        && embedder.available()
    {
        let text = embed_text(title.as_deref(), &content);
        let sha = text_sha(&text);
        let e = embedder.clone();
        match blocking(move || Ok(embed::embed_one(&*e, text))).await? {
            Ok(v) => {
                let res = db
                    .write_async(move |tx| {
                        if let Some(n) = note::fetch(tx, &org, &id)?
                            && text_sha(&embed_text(n.title.as_deref(), &n.content)) == sha
                        {
                            embed::store_vector(tx, &org, &id, &model, &v, &sha)?;
                        }
                        Ok(())
                    })
                    .await;
                if let Err(e) = res {
                    tracing::warn!(error = %e, "memory_save: could not store embedding");
                }
            }
            Err(err) => {
                tracing::debug!(category = err.category, error = %err.message, "memory_save: no embedding")
            }
        }
    }
    Ok(result)
}

/// Organization `org`'s live notes at least [`rank::DEDUP_THRESHOLD`]
/// similar to a new note's vector.
fn similar_notes(
    conn: &rusqlite::Connection,
    org: &str,
    model: &str,
    v: &[f32],
    content: &str,
) -> UaResult<Vec<Value>> {
    let elig = Eligibility {
        org: org.to_string(),
        include_expired: true,
        now: ua_core::time::now(),
        ..Default::default()
    };
    let hits = BruteForceIndex.nearest(conn, model, v, &elig.filter(), rank::DEDUP_THRESHOLD, 10)?;
    let mut out = Vec::new();
    for (id, sim) in hits {
        if let Some(n) = note::fetch(conn, org, &id)? {
            out.push(json!({
                "id": id,
                "title": n.title,
                "similarity": sim,
                "conflict": rank::detect_conflict(content, &n.content),
            }));
        }
    }
    Ok(out)
}

/// The stored key of a save's `idempotency_key`: scoped to `memory_save` and
/// to the caller, so a memory key never shares a row with another tool's key
/// (a `message_send` client id, say) or another caller's. `%` and `/` in the
/// label are escaped, so the caller part always ends at the first `/` after
/// the prefix and two callers' keys never meet.
///
/// `idempotency_keys` is still a hub-wide table (its `(org_id, principal,
/// key)` rebuild is a later change), so another organization's key is
/// prefixed with its organization, in the form the task family's `idem_key`
/// uses (`org:<org>/…`): the same label and key in two organizations are two
/// rows, and neither replays the other's receipt. The default organization
/// keeps the `memory_save/<label>/<key>` form.
fn scoped_key(caller: &Caller, key: &str) -> String {
    let label = caller.label.replace('%', "%25").replace('/', "%2F");
    if caller.org_id == ua_core::DEFAULT_ORG {
        format!("{SAVE_TOOL}/{label}/{key}")
    } else {
        format!("org:{}/{SAVE_TOOL}/{label}/{key}", caller.org_id)
    }
}

const SAVE_TOOL: &str = "memory_save";

/// The saved receipt of an earlier save under `key`: this caller's scoped key,
/// else a pre-upgrade raw key that `memory_save` itself wrote. Only
/// `memory_save` rows are read, so another tool's use of the same text is
/// invisible and the key answers like a fresh one.
///
/// A raw key was hub-wide, so its receipt replays only for the caller that
/// wrote or last updated the note it names; for anyone else the key is fresh
/// and the save goes ahead under that caller's scoped key, rather than being
/// silently answered with another caller's receipt.
fn saved_receipt(tx: &WriteTx<'_>, caller: &Caller, key: &str) -> UaResult<Option<String>> {
    let read = |k: &str| -> UaResult<Option<String>> {
        Ok(tx
            .query_row(
                "SELECT result_json FROM idempotency_keys WHERE key = ?1 AND tool = ?2",
                params![k, SAVE_TOOL],
                |r| r.get(0),
            )
            .optional()?)
    };
    if let Some(raw) = read(&scoped_key(caller, key))? {
        return Ok(Some(raw));
    }
    // Every pre-upgrade key was the default organization's.
    if caller.org_id != ua_core::DEFAULT_ORG {
        return Ok(None);
    }
    let Some(raw) = read(key)? else { return Ok(None) };
    let id = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_string));
    let Some(id) = id else { return Ok(None) };
    let mine = note::fetch(tx, &caller.org_id, &id)?.is_some_and(|n| {
        let me = Some(caller.label.as_str());
        n.author.as_deref() == me || n.updated_by.as_deref() == me
    });
    Ok(mine.then_some(raw))
}

fn idempotent_replay(tx: &WriteTx<'_>, caller: &Caller, p: &Prepared) -> UaResult<Option<Value>> {
    let Some(key) = &p.idempotency_key else { return Ok(None) };
    let Some(raw) = saved_receipt(tx, caller, key)? else { return Ok(None) };
    let cached: Value = serde_json::from_str(&raw).map_err(|e| UaError::internal(e.to_string()))?;
    // The receipt is returned only if this caller could make the save now.
    let check_id = p.id.clone().or_else(|| cached.get("id").and_then(Value::as_str).map(str::to_string));
    let mut replay_tags = p.tags.clone().unwrap_or_default();
    if let Some(id) = check_id
        && let Some(n) = note::fetch(tx, &caller.org_id, &id)?
    {
        if n.is_deleted() {
            return Err(UaError::invalid(format!(
                "memory note {id:?} is deleted. memory_get can still read the tombstone; \
                 a save cannot clear meta:deleted or restore the note."
            )));
        }
        if p.tags.is_none() {
            replay_tags = n.tags;
        }
    }
    assert_privileged(caller, &replay_tags, p.salience)?;
    Ok(Some(cached))
}

fn record_idempotency(tx: &WriteTx<'_>, caller: &Caller, p: &Prepared, result: &Value) -> UaResult<()> {
    if let Some(key) = &p.idempotency_key {
        tx.execute(
            "INSERT INTO idempotency_keys (key, tool, result_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![scoped_key(caller, key), SAVE_TOOL, result.to_string(), ua_core::time::now()],
        )?;
    }
    Ok(())
}

fn write(
    tx: &mut WriteTx<'_>,
    caller: &Caller,
    p: Prepared,
    vector: Option<(String, Vec<f32>)>,
) -> UaResult<Outcome> {
    note::require_org(tx, &caller.org_id)?;
    if let Some(cached) = idempotent_replay(tx, caller, &p)? {
        return Ok(Outcome { result: cached, embed_after: None });
    }
    let ts = ua_core::time::now();
    match p.id.clone() {
        Some(id) => update(tx, caller, p, &id, &ts),
        None => create(tx, caller, p, vector, &ts),
    }
}

fn update(tx: &mut WriteTx<'_>, caller: &Caller, p: Prepared, id: &str, ts: &str) -> UaResult<Outcome> {
    let org = caller.org_id.as_str();
    let old = note::fetch(tx, org, id)?.ok_or_else(|| {
        UaError::not_found(format!("no memory note with id {id:?}; omit id to create a new note"))
    })?;
    if let Some(expected) = &p.expected_revision {
        // Checked before the deleted refusal: a copy read before a delete is
        // a conflict with the current revision.
        let current = old.revision();
        if &current != expected {
            return Err(UaError::conflict(format!(
                "memory note {id:?} changed since your read: expected revision {expected}, current revision \
                 {current}. Nothing was written: memory_get it, merge your change into the current content, \
                 and save again with the new revision"
            )));
        }
    }
    if old.is_deleted() {
        return Err(UaError::invalid(format!(
            "memory note {id:?} is deleted. memory_get can still read the tombstone; \
             a save cannot clear meta:deleted or restore the note."
        )));
    }
    let author = p.author.as_deref();
    let owner = old.author.as_deref();
    let peer = owner.is_some() && owner != author;
    // Clobber guard. The message deliberately does not coach the overwrite flag.
    if !p.append && peer && !p.overwrite {
        return Err(UaError::denied(
            "not_owner",
            format!(
                "memory note {id:?} is owned by {:?}; you are {}. Pass append=True to add an attributed block \
                 without destroying it. Replacing another agent's note is refused; leave the note to its owner \
                 or add to it instead.",
                owner.unwrap_or_default(),
                author.unwrap_or("anonymous")
            ),
        ));
    }

    let final_title = p.title.clone().or_else(|| old.title.clone());
    let final_content = if p.append {
        format!("{}\n\n---\n*[{} · {ts}]*\n\n{}", old.content, author.unwrap_or("unknown"), p.content)
    } else if peer {
        // A cross-author replace keeps the peer's work as a tombstone.
        format!(
            "{}{}",
            p.content,
            note::tombstone_block(owner, old.title.as_deref(), &old.content, author, ts)
        )
    } else {
        p.content.clone()
    };
    let final_tags = p.tags.clone().unwrap_or_else(|| old.tags.clone());
    // A note that stays tagged broadcast stays human-only even when `tags` was omitted.
    assert_privileged(caller, &final_tags, None)?;

    // Epistemic metadata stays with the owner unless the caller overwrites;
    // evidence refs may be added by anyone.
    if peer
        && !p.overwrite
        && (p.epistemic.is_some() || p.valid_from.is_some() || p.contradicts.is_some() || p.evidence_replace)
    {
        return Err(UaError::denied(
            "not_owner",
            format!(
                "memory note {id:?} is owned by {:?}; its epistemic, valid_from and contradicts fields and its \
                 existing evidence stay with its owner. You may add evidence refs or append an attributed block.",
                owner.unwrap_or_default()
            ),
        ));
    }
    let final_epistemic = p.epistemic.clone().or_else(|| old.epistemic.clone());
    let mut final_evidence = if p.evidence_replace { Vec::new() } else { old.evidence.clone() };
    for r in &p.evidence {
        if !final_evidence.contains(r) {
            final_evidence.push(r.clone());
        }
    }
    if final_evidence.len() > note::MAX_EVIDENCE_REFS {
        return Err(UaError::invalid(format!(
            "evidence accepts at most {} refs per note; pass evidence_replace=True with the refs to keep",
            note::MAX_EVIDENCE_REFS
        )));
    }
    if final_epistemic.as_deref() == Some("inferred") && final_evidence.is_empty() {
        return Err(UaError::invalid("an inferred note must carry evidence refs"));
    }
    if let Some(list) = &p.contradicts {
        for linked in list {
            if linked == id {
                return Err(UaError::invalid("a note cannot contradict itself"));
            }
            linked_note(tx, org, linked, "contradicts")?;
        }
    }
    let final_contradicts = p.contradicts.clone().unwrap_or_else(|| old.contradicts.clone());
    // Labelling a legacy note: it has been valid since it was created.
    let mut final_valid_from = p.valid_from.clone().or_else(|| old.valid_from.clone());
    if final_valid_from.is_none() && (final_epistemic.is_some() || !final_evidence.is_empty()) {
        final_valid_from = Some(old.created_at.clone());
    }
    let final_salience = p.salience.unwrap_or(old.salience);
    let final_confidence = p.confidence.or(old.confidence);
    let final_expires =
        if p.clear_expires_at { None } else { p.expires_at.clone().or_else(|| old.expires_at.clone()) };

    tx.execute(
        "UPDATE memory SET content = ?1, title = ?2, tags = ?3, updated_at = ?4, updated_by = ?5, salience = ?6, \
         confidence = ?7, expires_at = ?8, epistemic = ?9, evidence = ?10, valid_from = ?11, contradicts = ?12 \
         WHERE id = ?13 AND org_id = ?14",
        params![
            final_content,
            final_title,
            json_text(&final_tags),
            ts,
            author,
            final_salience,
            final_confidence,
            final_expires,
            final_epistemic,
            json_opt(&final_evidence),
            final_valid_from,
            json_opt(&final_contradicts),
            id,
            org
        ],
    )?;
    let saved = note::require(tx, org, id)?;
    let revision = saved.revision();
    emit(
        tx,
        org,
        "agent.memory.saved",
        json!({
            "id": id,
            "created": false,
            "mode": if p.append { "append" } else { "replace" },
            "author": ledger_label(org, author),
            "title": ledger_text(org, json!(saved.title)),
            "tags": ledger_text(org, json!(saved.tags)),
            "revision": ledger_text(org, json!(revision)),
        }),
        &caller.label,
    )?;
    let result = json!({ "id": id, "created": false, "revision": revision });
    record_idempotency(tx, caller, &p, &result)?;
    let changed =
        (old.title.as_deref(), old.content.as_str()) != (saved.title.as_deref(), saved.content.as_str());
    let embed_after = changed.then(|| (id.to_string(), saved.title.clone(), saved.content.clone()));
    Ok(Outcome { result, embed_after })
}

/// When a superseded note stopped being valid: the replacement's
/// `valid_from` when it is after the old note's start, else now. A note
/// superseded within the second it started ends one second later; one whose
/// validity has not begun cannot be superseded now.
fn supersede_valid_to(old: &Note, replacement_from: Option<&str>, ts: &str) -> UaResult<String> {
    let start = old.valid_from.clone().unwrap_or_else(|| old.created_at.clone());
    if let Some(r) = replacement_from
        && r > start.as_str()
    {
        return Ok(r.to_string());
    }
    if ts > start.as_str() {
        return Ok(ts.to_string());
    }
    if ts == start {
        return note::plus_secs(&start, 1).ok_or_else(|| UaError::internal("bad stored timestamp"));
    }
    Err(UaError::invalid(format!(
        "memory note {:?} only becomes valid at {start}; superseding it now would leave it no valid instant. \
         Give the replacement a valid_from after {start}, or correct the note's valid_from first.",
        old.id
    )))
}

fn new_note_id(tx: &WriteTx<'_>) -> UaResult<String> {
    for _ in 0..8 {
        let id: String = uuid::Uuid::new_v4().simple().to_string().chars().take(12).collect();
        let taken: bool =
            tx.query_row("SELECT EXISTS (SELECT 1 FROM memory WHERE id = ?1)", [&id], |r| r.get(0))?;
        if !taken {
            return Ok(id);
        }
    }
    Err(UaError::internal("could not allocate a memory note id"))
}

fn create(
    tx: &mut WriteTx<'_>,
    caller: &Caller,
    p: Prepared,
    vector: Option<(String, Vec<f32>)>,
    ts: &str,
) -> UaResult<Outcome> {
    let org = caller.org_id.as_str();
    let author = p.author.as_deref();
    if p.epistemic.as_deref() == Some("inferred") && p.evidence.is_empty() {
        return Err(UaError::invalid("an inferred note must carry evidence refs"));
    }
    let contradicts = p.contradicts.clone().unwrap_or_default();
    for linked in &contradicts {
        linked_note(tx, org, linked, "contradicts")?;
    }
    let target = match &p.supersedes {
        None => None,
        Some(sid) => {
            let target = linked_note(tx, org, sid, "supersedes")?;
            if let Some(by) = &target.superseded_by {
                return Err(UaError::invalid(format!(
                    "memory note {sid:?} is already superseded by {by:?}; supersede that note instead"
                )));
            }
            let target_owner = target.author.as_deref();
            if target_owner.is_some() && target_owner != author && !p.overwrite {
                return Err(UaError::denied(
                    "not_owner",
                    format!(
                        "memory note {sid:?} is owned by {:?}; you are {}. Superseding another agent's note is \
                         refused; save yours with contradicts=[...] so its owner can resolve it.",
                        target_owner.unwrap_or_default(),
                        author.unwrap_or("anonymous")
                    ),
                ));
            }
            assert_privileged(caller, &target.tags, None)?;
            if contradicts.contains(sid) {
                return Err(UaError::invalid("pass a note in supersedes or contradicts, not both"));
            }
            Some(target)
        }
    };

    let id = new_note_id(tx)?;
    let tags = p.tags.clone().unwrap_or_default();
    // A labelled note is valid from its creation unless told otherwise.
    let valid_from = p
        .valid_from
        .clone()
        .or_else(|| (p.epistemic.is_some() || !p.evidence.is_empty()).then(|| ts.to_string()));
    let host = note::source_host(tx, caller);
    tx.execute(
        "INSERT INTO memory (org_id, id, title, content, tags, author, updated_by, created_at, updated_at, \
         salience, confidence, source_host, expires_at, epistemic, evidence, valid_from, contradicts) \
         VALUES (?15, ?1, ?2, ?3, ?4, ?5, ?5, ?6, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            id,
            p.title,
            p.content,
            json_text(&tags),
            author,
            ts,
            p.salience.unwrap_or(0.5),
            p.confidence,
            host,
            p.expires_at,
            p.epistemic,
            json_opt(&p.evidence),
            valid_from,
            json_opt(&contradicts),
            org
        ],
    )?;

    if let Some(target) = &target {
        // Invalidate, never delete: the old note keeps its content and
        // memory_restore reverses the pointer.
        let valid_to = supersede_valid_to(target, valid_from.as_deref(), ts)?;
        let n = tx.execute(
            "UPDATE memory SET superseded_by = ?1, valid_to = ?2 \
             WHERE id = ?3 AND org_id = ?4 AND superseded_by IS NULL",
            params![id, valid_to, target.id, org],
        )?;
        if n != 1 {
            return Err(UaError::conflict(format!(
                "memory note {:?} was superseded concurrently; re-read it and supersede the current note instead",
                target.id
            )));
        }
        emit(
            tx,
            org,
            "agent.memory.superseded",
            json!({
                "id": target.id,
                "superseded_by": id,
                "valid_to": valid_to,
                "actor": ledger_label(org, author),
            }),
            &caller.label,
        )?;
    }

    if let Some((model, v)) = vector {
        let sha = text_sha(&embed_text(p.title.as_deref(), &p.content));
        embed::store_vector(tx, org, &id, &model, &v, &sha)?;
    }

    let saved = note::require(tx, org, &id)?;
    let revision = saved.revision();
    emit(
        tx,
        org,
        "agent.memory.saved",
        json!({
            "id": id,
            "created": true,
            "mode": "create",
            "author": ledger_label(org, author),
            "title": ledger_text(org, json!(saved.title)),
            "tags": ledger_text(org, json!(saved.tags)),
            "revision": ledger_text(org, json!(revision)),
            "supersedes": p.supersedes,
        }),
        &caller.label,
    )?;
    let mut result = json!({ "id": id, "created": true, "similar": [], "revision": revision });
    if let Some(sid) = &p.supersedes {
        result["supersedes"] = json!(sid);
    }
    record_idempotency(tx, caller, &p, &result)?;
    Ok(Outcome { result, embed_after: None })
}
