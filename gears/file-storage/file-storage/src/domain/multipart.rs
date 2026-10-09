//! Domain types for multipart upload sessions and parts.

use time::OffsetDateTime;
use toolkit_macros::domain_model;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::storage_layout;
use crate::infra::content::hash_mode::HashMode;

/// State of a multipart upload session.
#[domain_model]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartUploadState {
    InProgress,
    /// A `complete` call holds the completion lease and is assembling on the backend. A
    /// crashed completer leaves the state here until `lease_until` passes, after which the
    /// next `complete` takes the lease over.
    Completing,
    Completed,
    Aborted,
}

impl MultipartUploadState {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Completing => "completing",
            Self::Completed => "completed",
            Self::Aborted => "aborted",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "in_progress" => Some(Self::InProgress),
            "completing" => Some(Self::Completing),
            "completed" => Some(Self::Completed),
            "aborted" => Some(Self::Aborted),
            _ => None,
        }
    }
}

/// An in-flight multipart upload session.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MultipartUploadSession {
    pub upload_id: Uuid,
    pub file_id: Uuid,
    pub version_id: Uuid,
    pub backend_upload_handle: String,
    pub state: MultipartUploadState,
    pub declared_mime: String,
    pub mime_validated: bool,
    /// Total file size declared at initiate time (bytes).
    pub declared_size: u64,
    /// Server-chosen plan unit (bytes, uniform except the final part).
    pub part_size: u64,
    /// Whether `complete` binds the finalized version itself (`false`: client binds manually).
    pub auto_bind: bool,
    /// Completion-lease expiry while `state == Completing`.
    pub lease_until: Option<OffsetDateTime>,
    /// Persisted JSON of the successful complete response (`StoredCompleteResult`) once
    /// `state == Completed`; an idempotent re-complete replays it.
    pub complete_result: Option<String>,
    /// Backend the upload targets, recorded at initiate time from the pending version.
    /// `None` only for a session created before `m20260924_000001_upload_flow_redesign`.
    pub backend_id: Option<String>,
    /// Backend object path of the upload, same provenance as `backend_id`; used by the
    /// expired-session cleanup when the `file_versions` row is already gone.
    pub backend_path: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl MultipartUploadSession {
    /// The persisted backend path, or the deterministic path recomputed from
    /// `(file_id, version_id)` for a legacy session created before the column existed.
    #[must_use]
    pub fn backend_path_or_default(&self) -> String {
        self.backend_path
            .clone()
            .unwrap_or_else(|| storage_layout::backend_path(self.file_id, self.version_id))
    }

    /// The persisted backend id, or `default` for a legacy session created before the column
    /// existed. A caller must prefer the backend the session initiated against over the
    /// registry's current default.
    #[must_use]
    pub fn backend_id_or(&self, default: &str) -> String {
        self.backend_id
            .clone()
            .unwrap_or_else(|| default.to_owned())
    }
}

/// Outcome of `complete_multipart_upload`: the finished result, or "another caller holds the
/// completion lease" (the caller answers `202`; the client re-issues the idempotent `complete`).
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub enum MultipartCompleteOutcome {
    Completed(CompletedMultipartUpload),
    Completing { retry_after_secs: u64 },
}

impl MultipartCompleteOutcome {
    /// Unwrap the `Completed` variant, for tests and single-completer contexts.
    ///
    /// # Panics
    /// Panics when the outcome is [`Self::Completing`].
    #[must_use]
    pub fn unwrap_completed(self) -> CompletedMultipartUpload {
        match self {
            Self::Completed(c) => c,
            Self::Completing { .. } => {
                panic!("complete is still in progress (completion lease held elsewhere)")
            }
        }
    }
}

/// Serializable snapshot of a successful complete response, persisted on the session row
/// (`multipart_uploads.complete_result`) in the same transaction that flips the state to
/// `completed`; every idempotent re-complete replays it.
///
/// Carries no `manifest`: `version_hash_manifest` is already the durable copy, and
/// `replay_completed` re-reads it from there.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredCompleteResult {
    pub version_id: Uuid,
    pub size: i64,
    /// Hex-encoded content hash.
    pub content_hash: String,
    /// `HashMode::as_str` spelling.
    pub hash_mode: String,
    pub part_count: i32,
    /// `BindState::as_str` spelling.
    pub bind_state: String,
    pub etag: Option<String>,
    pub current_etag: Option<String>,
}

impl StoredCompleteResult {
    #[must_use]
    pub fn from_completed(c: &CompletedMultipartUpload) -> Self {
        Self {
            version_id: c.version_id,
            size: c.size,
            content_hash: hex::encode(&c.content_hash),
            hash_mode: c.hash_mode.as_str().to_owned(),
            part_count: c.part_count,
            bind_state: c.bind_state.as_str().to_owned(),
            etag: c.etag.clone(),
            current_etag: c.current_etag.clone(),
        }
    }

    /// Rebuild the response, with `manifest` re-read from `version_hash_manifest` by the
    /// caller. `None` for an unparsable or internally inconsistent snapshot (the caller
    /// falls back to rebuilding from the version row).
    #[must_use]
    pub fn into_completed(self, manifest: Option<String>) -> Option<CompletedMultipartUpload> {
        let hash_mode = HashMode::parse(&self.hash_mode)?;
        let bind_state = match self.bind_state.as_str() {
            "bound" => BindState::Bound,
            "conflict" => BindState::Conflict,
            "manual" => BindState::Manual,
            _ => return None,
        };
        // Cross-field consistency: an inconsistent snapshot is as untrustworthy as an
        // unrecognized spelling, so `None` (the caller rebuilds from the version row).
        //
        // `hash_mode` vs `part_count`/manifest: a one-part plan is always `whole-sha256` with
        // `part_count == 1` and no manifest (ADR-0006 single-part amendment); a one-part
        // `multipart-composite-sha256` row is a valid legacy state, so only `part_count < 1`
        // is rejected there.
        match hash_mode {
            HashMode::WholeSha256 if self.part_count != 1 || manifest.is_some() => return None,
            HashMode::MultipartCompositeSha256 if self.part_count < 1 => return None,
            // Two or more parts always persist a manifest in the same transaction as this
            // snapshot, so a missing one means corruption. A legacy one-part composite is
            // excluded: its manifest is looked up separately.
            HashMode::MultipartCompositeSha256 if self.part_count >= 2 && manifest.is_none() => {
                return None;
            }
            _ => {}
        }
        // `bind_state` vs `etag`/`current_etag`, as `resolve_bind_state` writes them: `Bound`
        // has `etag` only, `Conflict` has `current_etag` only, `Manual` has neither.
        let consistent = match bind_state {
            BindState::Bound => self.etag.is_some() && self.current_etag.is_none(),
            BindState::Conflict => self.etag.is_none() && self.current_etag.is_some(),
            BindState::Manual => self.etag.is_none() && self.current_etag.is_none(),
        };
        if !consistent {
            return None;
        }
        // Both hash modes are SHA-256, so any digest other than exactly 32 bytes is corrupt.
        let content_hash = hex::decode(&self.content_hash)
            .ok()
            .filter(|d| d.len() == 32)?;
        Some(CompletedMultipartUpload {
            version_id: self.version_id,
            size: self.size,
            hash_algorithm: crate::infra::content::hash::ALGORITHM,
            content_hash,
            hash_mode,
            part_count: self.part_count,
            manifest,
            bind_state,
            etag: self.etag,
            current_etag: self.current_etag,
        })
    }
}

/// Result of a successful `complete_multipart_upload`.
///
/// `manifest` lets a client re-verify the composite hash without a second round-trip
/// (~90 bytes per part, ~1 MiB at the [`MAX_PART_COUNT`] ceiling).
#[domain_model]
#[derive(Debug, Clone)]
pub struct CompletedMultipartUpload {
    pub version_id: Uuid,
    pub size: i64,
    /// Always `"SHA-256"`.
    pub hash_algorithm: &'static str,
    /// Composite root `sha256(manifest)`; for a one-part plan, plain `sha256(object bytes)`.
    pub content_hash: Vec<u8>,
    /// `MultipartCompositeSha256` for two or more parts, `WholeSha256` for a one-part plan.
    pub hash_mode: HashMode,
    pub part_count: i32,
    /// Wire-format manifest text (`Manifest::to_wire_string`); `None` for a one-part plan.
    pub manifest: Option<String>,
    /// Bind outcome, see [`BindState`].
    pub bind_state: BindState,
    /// The file's content `ETag` after a successful bind (`Bound` only).
    pub etag: Option<String>,
    /// The file's current content `ETag` when the bind CAS was lost (`Conflict` only); the
    /// `If-Match` value for a manual rebind.
    pub current_etag: Option<String>,
}

/// Bind outcome shared by both upload paths: the multipart `complete` response's
/// `bind_state` and the single-part `PUT` response's `X-FS-Bound` header.
///
/// * `Bound`: the upload bound its version as the file's current content (CAS won).
/// * `Conflict`: an auto-bind was requested but the CAS lost. The upload SUCCEEDED (the
///   version is `available`); a manual `bind` with the current `ETag` as `If-Match`
///   makes it live without re-uploading.
/// * `Manual`: no bind was requested; the client binds explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindState {
    Bound,
    Conflict,
    Manual,
}

impl BindState {
    /// Wire spelling; the `X-FS-Bound` header spells `Bound` as `"true"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bound => "bound",
            Self::Conflict => "conflict",
            Self::Manual => "manual",
        }
    }
}

/// Derive the bind state from a file's current content pointer: bound to this version is
/// `Bound` (+ new `ETag`); an auto-bind that lost the CAS is `Conflict` (+ the current
/// `ETag`); no bind requested is `Manual`.
///
/// Used by both upload paths' idempotent retries so a retry reports the state the
/// original call decided, with no new CAS.
#[must_use]
pub fn resolve_bind_state(
    file_id: Uuid,
    content_id: Option<Uuid>,
    version_id: Uuid,
    auto_bind: bool,
) -> (BindState, Option<String>, Option<String>) {
    if content_id == Some(version_id) {
        (
            BindState::Bound,
            Some(crate::domain::etag::content_etag(file_id, version_id)),
            None,
        )
    } else if auto_bind {
        (
            BindState::Conflict,
            None,
            content_id.map(|cid| crate::domain::etag::content_etag(file_id, cid)),
        )
    } else {
        (BindState::Manual, None, None)
    }
}

/// Single-part idempotent-retry counterpart of [`resolve_bind_state`]: replays the original
/// finalize's bind decision instead of re-reading the current content pointer, which a
/// legitimate rebind may have moved since (a retry must not turn `Bound` into `Conflict`).
///
/// `bound_on_finalize` is the version's persisted flag, set in the same transaction as the
/// CAS it records: `true` means this finalize won it, so the answer is `Bound`. `false`
/// (lost CAS, or manual mode later bound by a separate `bind`) falls back to the live read.
#[must_use]
pub fn replay_finalize_bind_state(
    file_id: Uuid,
    content_id: Option<Uuid>,
    version_id: Uuid,
    bound_on_finalize: bool,
    auto_bind: bool,
) -> (BindState, Option<String>, Option<String>) {
    if bound_on_finalize {
        return (
            BindState::Bound,
            Some(crate::domain::etag::content_etag(file_id, version_id)),
            None,
        );
    }
    resolve_bind_state(file_id, content_id, version_id, auto_bind)
}

/// Result of `GET /files/{id}/multipart/{upload_id}`: session state plus received and
/// missing parts.
///
/// `upload_url` on each [`MissingPart`] is populated only while the session is
/// `in_progress` and unexpired; terminal or expired sessions get no resume URLs.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MultipartUploadStatus {
    pub upload_id: Uuid,
    pub version_id: Uuid,
    pub state: MultipartUploadState,
    pub declared_mime: String,
    pub declared_size: u64,
    pub part_size: u64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    /// Parts already reported by the sidecar, in ascending `part_number` order.
    pub received: Vec<ReceivedPart>,
    /// Parts not yet reported, in ascending `part_number` order.
    pub missing: Vec<MissingPart>,
}

/// One already-uploaded part, as reported by the sidecar.
#[domain_model]
#[derive(Debug, Clone)]
pub struct ReceivedPart {
    pub part_number: u32,
    pub size: i64,
    pub uploaded_at: OffsetDateTime,
}

/// One part not yet uploaded: planned bounds recomputed from the session's
/// `(declared_size, part_size)` and, when resumable, a fresh signed upload URL.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MissingPart {
    pub part_number: u32,
    pub offset: u64,
    pub size: u64,
    /// `Some` only for a live `in_progress` session; token expiry is capped at the
    /// session's `expires_at`, so a resume URL never outlives its session.
    pub upload_url: Option<String>,
}

/// One uploaded part of a multipart session.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MultipartPart {
    pub upload_id: Uuid,
    pub part_number: u32,
    pub backend_etag: String,
    pub part_hash: Vec<u8>,
    pub size: i64,
    pub uploaded_at: OffsetDateTime,
}

/// One planned part returned in the initiate response. The client must `PUT` exactly
/// `size` bytes to the signed `upload_url` (which carries the `size` claim).
#[domain_model]
#[derive(Debug, Clone)]
pub struct MultipartPartPlan {
    /// 1-based part number (S3 convention).
    pub part_number: u32,
    /// Byte offset of this part within the final assembled object.
    pub offset: u64,
    /// Exact byte length of this part.
    pub size: u64,
    /// Sidecar signed URL the client `PUT`s this part's bytes to.
    pub upload_url: String,
}

/// The server-authoritative parts plan returned by `POST /files/{id}/multipart`.
#[domain_model]
#[derive(Debug, Clone)]
pub struct MultipartPlan {
    pub upload_id: Uuid,
    pub version_id: Uuid,
    /// The hash algorithm used for per-part hashes (`"SHA-256"`).
    pub part_hash_algorithm: String,
    /// Uniform part size (bytes); the final part may be smaller.
    pub part_size: u64,
    /// One entry per part, in ascending `part_number` order.
    pub parts: Vec<MultipartPartPlan>,
    /// Token expiry; all per-part URLs share this expiry.
    pub expires_at: OffsetDateTime,
}

/// Minimum part size when the backend declares none: the S3 minimum for all parts but the
/// last. Also the lower bound for a client-supplied `preferred_part_size`.
pub const DEFAULT_MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// Maximum accepted `preferred_part_size` hint: S3's absolute maximum part size. Larger
/// values are rejected at the service boundary; `compute_plan` still uses checked
/// arithmetic as defense-in-depth.
pub const MAX_PART_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Hard ceiling on the parts of one plan, enforced by `compute_plan` independently of the
/// backend (ADR-0006: an unbounded manifest must not be possible).
///
/// `10_000` matches S3's own limit; it bounds the manifest size (~800 KB worst case) and the
/// per-initiate signed-URL minting cost for backends with no limit of their own.
pub const MAX_PART_COUNT: u64 = 10_000;

/// One raw part entry from `compute_plan`: `(part_number, offset, size)`.
pub type RawPartEntry = (u32, u64, u64);

/// Compute the server-chosen `part_size` and the plan skeleton (URLs are injected by
/// `MultipartService`). Returns `(part_size, parts)`.
///
/// `part_size = max(preferred, backend_min)` rounded up to a multiple of the minimum;
/// `parts = ceil(declared_size / part_size)`; the last part holds the remainder. If that
/// would exceed [`MAX_PART_COUNT`], `part_size` is widened (up to [`MAX_PART_SIZE`]) just
/// enough to fit. This runs before the plan `Vec` is allocated, so an attacker-controlled
/// `declared_size` is rejected without allocating memory proportional to it.
///
/// # Errors
/// Returns [`DomainError::Validation`] if the part-size arithmetic overflows `u64`, or if
/// even [`MAX_PART_SIZE`] cannot fit `declared_size` within [`MAX_PART_COUNT`] parts.
pub fn compute_plan(
    declared_size: u64,
    preferred_part_size: Option<u64>,
    backend_min_part_size: Option<u64>,
) -> Result<(u64, Vec<RawPartEntry>), DomainError> {
    let min = backend_min_part_size.unwrap_or(DEFAULT_MIN_PART_SIZE);
    let preferred = preferred_part_size.unwrap_or(min);
    let raw = preferred.max(min);
    let mut part_size = round_up_to(raw, min).ok_or_else(|| {
        DomainError::validation(
            "preferred_part_size",
            format!("part-size computation overflowed for preferred={preferred}, min={min}"),
        )
    })?;

    if declared_size == 0 {
        return Ok((part_size, vec![(1, 0, 0)]));
    }

    // Widen `part_size` to fit `MAX_PART_COUNT`, or reject if even `MAX_PART_SIZE` cannot.
    if declared_size.div_ceil(part_size) > MAX_PART_COUNT {
        let minimal_required = declared_size.div_ceil(MAX_PART_COUNT);
        if minimal_required > MAX_PART_SIZE {
            return Err(DomainError::validation(
                "declared_size",
                format!(
                    "declared_size {declared_size} bytes is too large for multipart upload on \
                     this backend: even at the maximum part size of {MAX_PART_SIZE} bytes it \
                     would require more than {MAX_PART_COUNT} parts"
                ),
            ));
        }
        part_size = minimal_required.max(part_size).min(MAX_PART_SIZE);
    }

    let n_parts = declared_size.div_ceil(part_size);
    let capacity = usize::try_from(n_parts).unwrap_or(usize::MAX);
    let mut parts = Vec::with_capacity(capacity);
    for i in 0..n_parts {
        let offset = i.checked_mul(part_size).ok_or_else(|| {
            DomainError::validation(
                "preferred_part_size",
                format!("part offset overflowed at part {}", i + 1),
            )
        })?;
        let size = if i + 1 == n_parts {
            declared_size - offset
        } else {
            part_size
        };
        let part_number = u32::try_from(i + 1).unwrap_or(u32::MAX);
        parts.push((part_number, offset, size));
    }
    Ok((part_size, parts))
}

/// Round `value` up to the next multiple of `align`; `None` on overflow.
fn round_up_to(value: u64, align: u64) -> Option<u64> {
    if align == 0 {
        return Some(value);
    }
    value.div_ceil(align).checked_mul(align)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_up_to_does_not_overflow_on_max_input() {
        assert_eq!(round_up_to(u64::MAX, DEFAULT_MIN_PART_SIZE), None);
        assert_eq!(round_up_to(u64::MAX, u64::MAX), Some(u64::MAX));
        assert_eq!(round_up_to(1, u64::MAX), Some(u64::MAX));
        assert_eq!(round_up_to(7, 5), Some(10));
        assert_eq!(round_up_to(10, 5), Some(10));
    }

    #[test]
    fn compute_plan_returns_validation_error_on_overflowing_preferred_part_size() {
        let err = compute_plan(u64::MAX, Some(u64::MAX), None).unwrap_err();
        assert!(matches!(err, DomainError::Validation { .. }));
    }

    #[test]
    fn compute_plan_rejects_absurd_declared_size_without_allocating() {
        let err = compute_plan(u64::MAX, None, None).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation { .. }),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn compute_plan_widens_part_size_to_stay_within_max_part_count() {
        // 15,000 parts at DEFAULT_MIN_PART_SIZE would exceed MAX_PART_COUNT.
        let declared_size = 15_000 * DEFAULT_MIN_PART_SIZE;
        let (part_size, parts) = compute_plan(declared_size, Some(DEFAULT_MIN_PART_SIZE), None)
            .expect("must widen instead of rejecting");

        assert!(
            part_size > DEFAULT_MIN_PART_SIZE,
            "part_size must have been widened above the caller's preferred value, got {part_size}"
        );
        assert!(
            part_size <= MAX_PART_SIZE,
            "widened part_size must never exceed MAX_PART_SIZE, got {part_size}"
        );
        assert!(
            (parts.len() as u64) <= MAX_PART_COUNT,
            "plan must fit within MAX_PART_COUNT parts, got {}",
            parts.len()
        );
        let total: u64 = parts.iter().map(|(_, _, size)| *size).sum();
        assert_eq!(
            total, declared_size,
            "sum of part sizes must equal declared_size"
        );
    }

    #[test]
    fn compute_plan_rejects_declared_size_beyond_max_part_size_times_max_part_count() {
        let declared_size = MAX_PART_SIZE * MAX_PART_COUNT + 1;
        let err = compute_plan(declared_size, None, None).unwrap_err();
        assert!(
            matches!(err, DomainError::Validation { .. }),
            "expected Validation, got {err:?}"
        );
    }

    #[test]
    fn compute_plan_accepts_declared_size_exactly_at_the_boundary() {
        let declared_size = MAX_PART_SIZE * MAX_PART_COUNT;
        let (part_size, parts) =
            compute_plan(declared_size, None, None).expect("boundary value must be accepted");
        assert_eq!(part_size, MAX_PART_SIZE);
        assert_eq!(parts.len() as u64, MAX_PART_COUNT);
    }

    /// Baseline snapshot that the negative tests below mutate one field away from.
    fn stored_bound() -> StoredCompleteResult {
        StoredCompleteResult {
            version_id: Uuid::now_v7(),
            size: 11,
            content_hash: hex::encode([0u8; 32]),
            hash_mode: HashMode::WholeSha256.as_str().to_owned(),
            part_count: 1,
            bind_state: BindState::Bound.as_str().to_owned(),
            etag: Some("\"etag-value\"".to_owned()),
            current_etag: None,
        }
    }

    #[test]
    fn into_completed_accepts_whole_sha256_bound_snapshot() {
        let completed = stored_bound()
            .into_completed(None)
            .expect("a valid whole-sha256/bound snapshot must be accepted unchanged");
        assert_eq!(completed.hash_mode, HashMode::WholeSha256);
        assert_eq!(completed.part_count, 1);
        assert_eq!(completed.bind_state, BindState::Bound);
        assert_eq!(completed.etag.as_deref(), Some("\"etag-value\""));
    }

    #[test]
    fn into_completed_accepts_composite_conflict_snapshot() {
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 3,
            bind_state: BindState::Conflict.as_str().to_owned(),
            etag: None,
            current_etag: Some("\"current-etag\"".to_owned()),
            ..stored_bound()
        };
        let completed = stored
            .into_completed(Some("v1,0:aa".to_owned()))
            .expect("a valid composite/conflict snapshot must be accepted unchanged");
        assert_eq!(completed.bind_state, BindState::Conflict);
        assert_eq!(completed.current_etag.as_deref(), Some("\"current-etag\""));
    }

    #[test]
    fn into_completed_accepts_manual_snapshot_with_no_etags() {
        let stored = StoredCompleteResult {
            bind_state: BindState::Manual.as_str().to_owned(),
            etag: None,
            current_etag: None,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_some(),
            "manual requires neither etag nor current_etag"
        );
    }

    #[test]
    fn into_completed_accepts_legacy_one_part_composite_snapshot() {
        // Legacy one-part composite (predates the ADR-0006 single-part amendment) is valid.
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 1,
            bind_state: BindState::Manual.as_str().to_owned(),
            etag: None,
            current_etag: None,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(Some("v1,0:aa".to_owned())).is_some(),
            "a legacy one-part composite snapshot must not be rejected"
        );
    }

    #[test]
    fn into_completed_rejects_whole_sha256_with_part_count_other_than_one() {
        let stored = StoredCompleteResult {
            part_count: 2,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_none(),
            "whole-sha256 with part_count != 1 must fall back, not be accepted as-is"
        );
    }

    #[test]
    fn into_completed_rejects_whole_sha256_with_unexpected_manifest() {
        let stored = stored_bound();
        assert!(
            stored.into_completed(Some("v1,0:aa".to_owned())).is_none(),
            "whole-sha256 must never carry a manifest"
        );
    }

    #[test]
    fn into_completed_rejects_composite_with_zero_part_count() {
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 0,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(Some("v1,0:aa".to_owned())).is_none(),
            "an impossible zero-part composite snapshot must fall back"
        );
    }

    #[test]
    fn into_completed_rejects_bound_without_etag() {
        let stored = StoredCompleteResult {
            etag: None,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_none(),
            "bind_state=bound without an etag must fall back"
        );
    }

    #[test]
    fn into_completed_rejects_conflict_without_current_etag() {
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 2,
            bind_state: BindState::Conflict.as_str().to_owned(),
            etag: None,
            current_etag: None,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(Some("v1,0:aa".to_owned())).is_none(),
            "bind_state=conflict without a current_etag must fall back"
        );
    }

    #[test]
    fn into_completed_rejects_bound_with_current_etag() {
        let stored = StoredCompleteResult {
            current_etag: Some("\"other\"".to_owned()),
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_none(),
            "bind_state=bound must not also carry a current_etag"
        );
    }

    #[test]
    fn into_completed_rejects_conflict_with_etag() {
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 2,
            bind_state: BindState::Conflict.as_str().to_owned(),
            etag: Some("\"new\"".to_owned()),
            current_etag: Some("\"current\"".to_owned()),
            ..stored_bound()
        };
        assert!(
            stored.into_completed(Some("v1,0:aa".to_owned())).is_none(),
            "bind_state=conflict must not also carry an etag"
        );
    }

    #[test]
    fn into_completed_rejects_manual_with_etags() {
        for (etag, current_etag) in [
            (Some("\"new\"".to_owned()), None),
            (None, Some("\"current\"".to_owned())),
        ] {
            let stored = StoredCompleteResult {
                bind_state: BindState::Manual.as_str().to_owned(),
                etag,
                current_etag,
                ..stored_bound()
            };
            assert!(
                stored.into_completed(None).is_none(),
                "bind_state=manual must carry neither etag nor current_etag"
            );
        }
    }

    #[test]
    fn into_completed_rejects_undersized_content_hash() {
        let stored = StoredCompleteResult {
            content_hash: hex::encode([0u8; 1]),
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_none(),
            "a content_hash that isn't exactly a 32-byte SHA-256 digest must fall back"
        );
    }

    #[test]
    fn into_completed_rejects_composite_with_two_parts_and_no_manifest() {
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 2,
            bind_state: BindState::Manual.as_str().to_owned(),
            etag: None,
            current_etag: None,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_none(),
            "a multi-part composite snapshot with no manifest is corrupt, not legacy"
        );
    }

    #[test]
    fn into_completed_accepts_legacy_one_part_composite_snapshot_without_manifest() {
        // A one-part composite never needs a manifest argument.
        let stored = StoredCompleteResult {
            hash_mode: HashMode::MultipartCompositeSha256.as_str().to_owned(),
            part_count: 1,
            bind_state: BindState::Manual.as_str().to_owned(),
            etag: None,
            current_etag: None,
            ..stored_bound()
        };
        assert!(
            stored.into_completed(None).is_some(),
            "a legacy one-part composite snapshot without a manifest must still be accepted"
        );
    }
}
