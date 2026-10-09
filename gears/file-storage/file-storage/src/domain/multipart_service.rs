//! `MultipartService` — multipart upload control-plane logic.
//!
//! Owns initiate (server-authoritative plan + per-part signed URLs), complete and abort.
//! Bytes flow only to the sidecar via the per-part signed URLs returned by initiate.
//!
//! Holds its own copies of the shared dependencies so it does not reference `FileService`.

// Domain terms (ETag, If-Match, FileStorage, GET/PUT, BLAKE3) appear in the docs.
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use time::OffsetDateTime;
use toolkit_gts::gts_id;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use crate::domain::audit::{AuditEntry, AuditOperation, FileEvent};
use crate::domain::authz::{Authorizer, actions};
use crate::domain::error::{DomainError, MULTIPART_SESSION_RECLAIMED_BY_CLEANUP_MESSAGE};
use crate::domain::etag;
use crate::domain::multipart::{
    BindState, CompletedMultipartUpload, DEFAULT_MIN_PART_SIZE, MAX_PART_SIZE, MissingPart,
    MultipartCompleteOutcome, MultipartPart, MultipartPartPlan, MultipartPlan,
    MultipartUploadSession, MultipartUploadState, MultipartUploadStatus, ReceivedPart,
    StoredCompleteResult, compute_plan,
};

/// `Retry-After` hint (seconds) on a `202 completing` answer; the client re-issues `complete`.
const COMPLETE_POLL_RETRY_SECS: u64 = 2;
use crate::domain::policy::{PolicyResolver, PolicyScope};
use crate::domain::ports::{
    AutoBindOnFinalize, FileStorageMetricsPort, MultipartFinishSnapshot, MultipartStore,
};
use crate::domain::storage_layout;
use crate::infra::backend::BackendRegistry;
use crate::infra::content::mime::{
    MIME_SNIFF_PREFIX_BYTES, enforce_size_ceiling_for_validated_mime, validate_and_resolve_mime,
};
use crate::infra::external_clients::{QuotaClient, QuotaDecision, UsageDelta, UsageReporter};
use crate::infra::metrics::NoopMetrics;
use crate::infra::signed_url::{Claims, Issuer, MultipartClaims, Op, UploadConstraints};

/// Quota metric name (same platform metric as in `service/mod.rs`).
const QUOTA_METRIC_NAME: &str = gts_id!("cf.qe.metric.type.v1~cf.qe.metric.file_storage_bytes.v1");

/// Diff the plan's expected part numbers against the parts actually reported,
/// returning the missing ones in ascending order.
///
/// `expected_count = ceil(declared_size / part_size)` mirrors `compute_plan`'s part count,
/// including the `declared_size == 0` case (one zero-byte part, never reported as missing).
pub(crate) fn missing_part_numbers(
    session: &MultipartUploadSession,
    parts: &[MultipartPart],
) -> Vec<u32> {
    let expected_count = if session.declared_size == 0 {
        1
    } else {
        session.declared_size.div_ceil(session.part_size.max(1))
    };
    let reported: std::collections::HashSet<u32> = parts.iter().map(|p| p.part_number).collect();
    (1..=expected_count)
        .filter_map(|n| u32::try_from(n).ok())
        .filter(|n| !reported.contains(n))
        .collect()
}

/// Recompute one part's `(offset, size)` from the session's `(declared_size, part_size)`,
/// mirroring `compute_plan`'s per-part math (`declared_size == 0` is one zero-byte part).
///
/// Saturating arithmetic guards against a corrupted session row; callers only pass numbers
/// returned by `missing_part_numbers`.
pub(crate) fn part_bounds(session: &MultipartUploadSession, part_number: u32) -> (u64, u64) {
    if session.declared_size == 0 {
        return (0, 0);
    }
    let part_size = session.part_size.max(1);
    let offset = u64::from(part_number.saturating_sub(1)).saturating_mul(part_size);
    let size = part_size.min(session.declared_size.saturating_sub(offset));
    (offset, size)
}

/// The multipart-upload service: all multipart control-plane operations, wired alongside
/// `FileService` in `gear.rs` under the same REST prefix.
#[allow(unknown_lints, de0309_must_have_domain_model)]
pub struct MultipartService {
    store: Arc<dyn MultipartStore>,
    backends: BackendRegistry,
    authorizer: Arc<dyn Authorizer>,
    quota_client: Option<Arc<dyn QuotaClient>>,
    /// Signed-URL issuer for minting per-part sidecar tokens.
    issuer: Arc<Issuer>,
    /// Base URL of the sidecar (e.g. `"http://sidecar.example.com"`).
    sidecar_base_url: String,
    /// Signed-URL TTL in seconds for every per-part upload URL (short, to bound the
    /// stale-permission window). Independent of `session_ttl_secs`.
    url_ttl_secs: i64,
    /// Lifetime (seconds) of the session itself (`expires_at` at initiate). Defaults to
    /// `url_ttl_secs`; `gear.rs` sets a much longer `multipart_session_ttl_secs`, since capping
    /// large uploads (and the resume-token expiry, which is capped at `expires_at`) at the URL TTL
    /// would defeat multipart.
    session_ttl_secs: i64,
    /// Seconds a `complete` may hold the `completing` state before another can take it over;
    /// sized to the backend-assembly budget (`multipart_complete_lease_secs`, default 120).
    complete_lease_secs: i64,
    /// Defaults to a no-op; `with_metrics` installs the real meter.
    metrics: Arc<dyn FileStorageMetricsPort>,
    /// `None` disables usage reporting.
    usage_reporter: Option<Arc<dyn UsageReporter>>,
}

impl MultipartService {
    pub fn new(
        store: Arc<dyn MultipartStore>,
        backends: BackendRegistry,
        authorizer: Arc<dyn Authorizer>,
        quota_client: Option<Arc<dyn QuotaClient>>,
        issuer: Arc<Issuer>,
        sidecar_base_url: String,
        url_ttl_secs: i64,
    ) -> Self {
        Self {
            store,
            backends,
            authorizer,
            quota_client,
            issuer,
            sidecar_base_url,
            url_ttl_secs,
            session_ttl_secs: url_ttl_secs,
            complete_lease_secs: 120,
            metrics: Arc::new(NoopMetrics),
            usage_reporter: None,
        }
    }

    /// Install a dedicated completion-lease duration.
    #[must_use]
    pub fn with_complete_lease_secs(mut self, complete_lease_secs: i64) -> Self {
        self.complete_lease_secs = complete_lease_secs;
        self
    }

    /// Install a multipart-session lifetime decoupled from the per-part URL TTL.
    #[must_use]
    pub fn with_session_ttl_secs(mut self, session_ttl_secs: i64) -> Self {
        self.session_ttl_secs = session_ttl_secs;
        self
    }

    /// Install a real metrics port (a builder step so `new()` keeps its signature).
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn FileStorageMetricsPort>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Install a usage-reporting sink.
    #[must_use]
    pub fn with_usage_reporter(mut self, usage_reporter: Option<Arc<dyn UsageReporter>>) -> Self {
        self.usage_reporter = usage_reporter;
        self
    }

    /// Fire-and-forget: a failing usage reporter must not block file operations.
    fn report_usage(&self, delta: UsageDelta) {
        if let Some(reporter) = self.usage_reporter.clone() {
            tokio::spawn(async move {
                reporter.report(delta).await;
            });
        }
    }

    fn tenant_scope(ctx: &SecurityContext) -> AccessScope {
        AccessScope::for_tenant(ctx.subject_tenant_id())
    }

    fn actor_kind(ctx: &SecurityContext) -> &'static str {
        match ctx.subject_type() {
            Some("app") => "app",
            _ => "user",
        }
    }

    fn audit_ok(
        ctx: &SecurityContext,
        file_id: Option<Uuid>,
        operation: AuditOperation,
        detail: serde_json::Value,
    ) -> AuditEntry {
        AuditEntry::success(
            ctx.subject_tenant_id(),
            Self::actor_kind(ctx),
            ctx.subject_id(),
            file_id,
            operation,
            detail,
        )
    }

    /// Resolve the effective policy for `(tenant_id, owner_id)`.
    async fn get_effective_policy_internal(
        &self,
        tenant_id: Uuid,
        owner_id: Uuid,
    ) -> Result<crate::domain::policy::EffectivePolicy, DomainError> {
        let scope = AccessScope::allow_all();
        let tenant_policy = self
            .store
            .get_policy(&scope, tenant_id, &PolicyScope::Tenant, None)
            .await?;
        let user_policy = self
            .store
            .get_policy(&scope, tenant_id, &PolicyScope::User, Some(owner_id))
            .await?;
        Ok(PolicyResolver::resolve(
            tenant_policy.as_ref().map(|p| &p.body),
            user_policy.as_ref().map(|p| &p.body),
        ))
    }

    /// Quota preflight for `additional_bytes` (the declared total at initiate).
    /// Fail-closed: a failing quota client denies the request.
    async fn check_quota_bytes(
        &self,
        tenant_id: Uuid,
        owner_id: Uuid,
        additional_bytes: u64,
    ) -> Result<(), DomainError> {
        let Some(qc) = &self.quota_client else {
            return Ok(());
        };
        match qc
            .check_storage_quota(tenant_id, owner_id, additional_bytes, QUOTA_METRIC_NAME)
            .await?
        {
            QuotaDecision::Allowed => Ok(()),
            QuotaDecision::Denied { reason } => {
                self.metrics
                    .record_quota_denied("initiate_multipart_upload");
                Err(DomainError::quota_exceeded(reason))
            }
        }
    }

    /// Best-effort cleanup after session persistence failed: abort the backend handle and
    /// delete the pending version row. Errors are logged, not propagated; leftovers are
    /// reclaimed by the cleanup sweep.
    async fn compensate_failed_session_create(
        &self,
        ctx: &SecurityContext,
        upload_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        backend_path: &str,
        backend_handle: &str,
    ) {
        let backend = self.backends.default_backend();
        if let Err(abort_err) = backend.abort_multipart(backend_path, backend_handle).await {
            self.metrics
                .record_backend_error(backend.id(), "abort_multipart");
            tracing::warn!(
                ?abort_err,
                %upload_id,
                "best-effort backend abort failed after session persistence error"
            );
        }
        if let Err(del_err) = self
            .store
            .delete_version(
                file_id,
                version_id,
                Self::audit_ok(
                    ctx,
                    Some(file_id),
                    AuditOperation::DeleteVersion,
                    serde_json::json!({
                        "version_id": version_id,
                        "reason": "multipart_session_create_failed"
                    }),
                ),
            )
            .await
        {
            tracing::warn!(
                ?del_err,
                %upload_id,
                "best-effort pending-version delete failed after session persistence error"
            );
        }
    }

    /// Mint one signed per-part upload URL. Shared by initiate (full-TTL tokens) and introspect
    /// (resume tokens, with `exp` capped at the session's remaining `expires_at`).
    #[allow(clippy::too_many_arguments)]
    fn mint_part_url(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        backend_id: &str,
        backend_path: &str,
        upload_id: Uuid,
        backend_handle: &str,
        part_number: u32,
        offset: u64,
        size: u64,
        exp: i64,
        request_id: &str,
        now: OffsetDateTime,
    ) -> Result<String, DomainError> {
        let claims = Claims {
            op: Op::MultipartPart,
            file_id,
            version_id,
            backend_id: backend_id.to_owned(),
            backend_path: backend_path.to_owned(),
            exp,
            upload: UploadConstraints::default(),
            multipart: MultipartClaims {
                upload_id,
                part_number,
                offset,
                size,
                backend_handle: backend_handle.to_owned(),
            },
            request_id: request_id.to_owned(),
            content_type: String::new(),
            etag: String::new(),
            // Multipart binds via `complete`, never via the per-part token.
            bind_on_finalize: false,
            content_sha256: String::new(),
        };
        let token = self.issuer.issue(claims, now)?;
        Ok(format!(
            "{}/api/file-storage-data/v1/multipart/{file_id}/{version_id}/parts/{part_number}?fs-token={token}",
            self.sidecar_base_url
        ))
    }

    /// `POST /files/{id}/multipart`: initiate a multipart upload session.
    ///
    /// Server-authoritative: validates the intent, pre-registers a `pending` version, creates
    /// the backend session, computes the exact parts plan and returns one signed sidecar URL
    /// per part. Gates: allowed MIME (`415`), declared size within the effective max (`413`),
    /// storage quota (`507`). The complete-time size check stays as defence in depth.
    #[tracing::instrument(skip_all)]
    /// `auto_bind`: when `true`, `complete` binds the finalized version itself (recorded on the
    /// session row). Only the merged `POST /files` path passes `true`.
    #[allow(clippy::too_many_arguments)]
    pub async fn initiate_multipart_upload(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        declared_mime: &str,
        declared_size: u64,
        preferred_part_size: Option<u64>,
        auto_bind: bool,
    ) -> Result<MultipartPlan, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let backend = self.backends.default_backend();
        if !backend.capabilities().multipart_native {
            return Err(DomainError::multipart_not_supported(backend.id()));
        }

        // Reject (not clamp) an out-of-range hint before it reaches `compute_plan`, where a
        // near-`u64::MAX` value risks overflow or a huge allocation.
        if let Some(preferred) = preferred_part_size
            && !(DEFAULT_MIN_PART_SIZE..=MAX_PART_SIZE).contains(&preferred)
        {
            return Err(DomainError::validation(
                "preferred_part_size",
                format!(
                    "must be between {DEFAULT_MIN_PART_SIZE} and {MAX_PART_SIZE} bytes \
                     (got {preferred})"
                ),
            ));
        }

        // Policy checks against the declared total size.
        let tenant_id = ctx.subject_tenant_id();
        let policy = self
            .get_effective_policy_internal(tenant_id, file.owner_id)
            .await?;
        PolicyResolver::check_allowed_mime(&policy, declared_mime)?;
        let effective_max = PolicyResolver::compute_effective_max_bytes(
            &policy,
            declared_mime,
            backend.capabilities().max_size_bytes,
        );

        // Reject at initiate rather than deferring to complete.
        if let Some(limit) = effective_max
            && declared_size > limit
        {
            return Err(DomainError::policy_size_exceeded(
                limit,
                "policy size limit",
            ));
        }

        // Quota check against the declared size, not the pessimistic `effective_max`.
        self.check_quota_bytes(tenant_id, file.owner_id, declared_size)
            .await?;

        let now = OffsetDateTime::now_utc();
        let upload_id = Uuid::now_v7();
        let version_id = Uuid::now_v7();
        let backend_path = storage_layout::backend_path(file_id, version_id);
        let backend_id = backend.id().to_owned();

        // Session lifetime is independent of the URL TTL (see `session_ttl_secs`). Computed before
        // any side effect so a failure here needs no compensation. `checked_add` and `.max(1)` are
        // defense in depth: `FileStorageConfig::validate()` bounds both TTLs and rejects 0.
        let session_expires_at = now
            .checked_add(time::Duration::seconds(self.session_ttl_secs.max(1)))
            .ok_or_else(|| {
                DomainError::database(
                    "multipart session TTL overflowed computing the session expiry",
                )
            })?;
        let url_expires_at = now
            .checked_add(time::Duration::seconds(self.url_ttl_secs.max(1)))
            .ok_or_else(|| {
                DomainError::database("signed-URL TTL overflowed computing the part URL expiry")
            })?;

        // `compute_plan` enforces `MAX_PART_COUNT` before allocating, so an adversarial
        // `declared_size` cannot drive an allocation proportional to it. The backend minimum
        // part size is not exposed by `BackendCapabilities`, hence `None` (default minimum).
        let (chosen_part_size, raw_parts) = compute_plan(declared_size, preferred_part_size, None)?;

        self.store
            .insert_pending_version(
                file_id,
                version_id,
                declared_mime,
                &backend_id,
                &backend_path,
                now,
            )
            .await?;

        let backend_handle = backend.initiate_multipart(&backend_path).await?;

        // On persistence failure, compensate so the backend handle and pending version
        // are not orphaned.
        if let Err(err) = self
            .store
            .create_multipart_upload(
                upload_id,
                file_id,
                version_id,
                &backend_handle,
                Some(&backend_id),
                Some(&backend_path),
                declared_mime,
                declared_size,
                chosen_part_size,
                auto_bind,
                session_expires_at,
                now,
            )
            .await
        {
            self.compensate_failed_session_create(
                ctx,
                upload_id,
                file_id,
                version_id,
                &backend_path,
                &backend_handle,
            )
            .await;
            return Err(err);
        }

        // One signed URL per part; each token carries the exact `size` the sidecar enforces.
        // All parts share one correlation id, echoed back as `x-request-id` on report-part.
        let exp = url_expires_at.unix_timestamp();
        let request_id = Uuid::now_v7().to_string();
        let mut parts = Vec::with_capacity(raw_parts.len());
        for (part_number, offset, size) in raw_parts {
            let upload_url = self.mint_part_url(
                file_id,
                version_id,
                &backend_id,
                &backend_path,
                upload_id,
                &backend_handle,
                part_number,
                offset,
                size,
                exp,
                &request_id,
                now,
            )?;
            parts.push(MultipartPartPlan {
                part_number,
                offset,
                size,
                upload_url,
            });
        }

        self.metrics
            .record_operation("initiate_multipart_upload", "ok");
        Ok(MultipartPlan {
            upload_id,
            version_id,
            part_hash_algorithm: "SHA-256".to_owned(),
            part_size: chosen_part_size,
            parts,
            expires_at: url_expires_at,
        })
    }

    /// Token-authenticated sidecar callback recording a written part
    /// (`.../multipart/{upload_id}/parts/{part_number}/report`).
    ///
    /// `claims` is already verified by the caller; this re-validates them against the session so
    /// a token for another (or no-longer-`in_progress`) session cannot alter this upload's part
    /// list, and rejects a `size` differing from `claims.multipart.size` so a token holder cannot
    /// forge part sizes that `complete` sums into `version.size`.
    pub async fn report_part(
        &self,
        claims: &Claims,
        backend_etag: String,
        hash_value: Vec<u8>,
        size: i64,
    ) -> Result<(), DomainError> {
        let upload_id = claims.multipart.upload_id;
        let session = self
            .store
            .get_multipart_upload(upload_id)
            .await?
            .ok_or_else(|| DomainError::multipart_upload_not_found(upload_id))?;

        // A foreign session is reported as "not found", indistinguishable from a missing one.
        if session.file_id != claims.file_id || session.version_id != claims.version_id {
            return Err(DomainError::multipart_upload_not_found(upload_id));
        }

        // Fast-path rejection on the loaded snapshot; `Store::upsert_multipart_part` re-checks
        // `in_progress` atomically with the write and returns the same error on a race.
        if session.state != MultipartUploadState::InProgress {
            return Err(DomainError::multipart_upload_not_in_progress(
                upload_id,
                session.state.as_str(),
            ));
        }

        let part_number = i32::try_from(claims.multipart.part_number)
            .map_err(|_| DomainError::validation("part_number", "part_number overflows i32"))?;

        // Security: the callback is anonymous + token-authenticated, so the caller-supplied `size`
        // is not trusted; `claims.multipart.size` is the exact size `compute_plan` assigned this
        // part, and is what gets persisted.
        let claimed_size = i64::try_from(claims.multipart.size)
            .map_err(|_| DomainError::validation("size", "size overflows i64"))?;
        if size != claimed_size {
            return Err(DomainError::validation(
                "size",
                "reported part size does not match the planned size for this part",
            ));
        }

        self.store
            .upsert_multipart_part(
                upload_id,
                part_number,
                &backend_etag,
                hash_value,
                claimed_size,
                OffsetDateTime::now_utc(),
            )
            .await
    }

    /// `POST /files/{id}/multipart/{upload_id}/complete`: finalize all parts.
    ///
    /// No DB lock or transaction is held across the backend assembly I/O; the session moves
    /// through conditional-UPDATE transitions
    /// `in_progress -> completing(lease_owner, lease_until) -> completed(complete_result)`
    /// (or `aborted`):
    ///
    /// * The caller that wins the lease CAS assembles in a **detached task** (a client disconnect
    ///   cannot cancel it), then commits one fast transaction: version `available` (+hash/manifest,
    ///   + auto-bind CAS for `auto_bind` sessions) and the session `completed` with the response
    ///   snapshot.
    /// * A concurrent `complete` that loses the CAS answers `MultipartCompleteOutcome::Completing`
    ///   (HTTP 202); the client re-issues the same idempotent `complete`.
    /// * Re-completing a `completed` session replays the snapshot: success, never 409.
    /// * If a completer died mid-assembly, the next `complete` after `lease_until` takes the lease
    ///   over, checks what landed (version already `available`: just finish; else re-assemble).
    ///   Sessions stuck in `completing` past `expires_at` are reclaimed by the cleanup sweep.
    #[tracing::instrument(skip_all)]
    pub async fn complete_multipart_upload(
        self: &Arc<Self>,
        ctx: &SecurityContext,
        file_id: Uuid,
        upload_id: Uuid,
        if_match: Option<&str>,
    ) -> Result<MultipartCompleteOutcome, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let session = self
            .store
            .get_multipart_upload(upload_id)
            .await?
            .ok_or_else(|| DomainError::multipart_upload_not_found(upload_id))?;

        // The session is loaded by `upload_id` alone: bind it to the authorized path `file_id`,
        // reporting a foreign one as "not found".
        if session.file_id != file_id {
            return Err(DomainError::multipart_upload_not_found(upload_id));
        }

        // Replay of a completed session is checked BEFORE `If-Match`: it is the recorded outcome of
        // an action that already happened, and the earlier success already moved the file's ETag,
        // so an honest retry with the same `If-Match` must get the persisted 200, not 412/409.
        if session.state == MultipartUploadState::Completed {
            self.metrics
                .record_operation("complete_multipart_upload", "replayed");
            return Ok(MultipartCompleteOutcome::Completed(
                self.replay_completed(file_id, &session).await?,
            ));
        }
        if session.state == MultipartUploadState::Aborted {
            return Err(DomainError::multipart_upload_not_in_progress(
                upload_id,
                session.state.as_str(),
            ));
        }

        // Optional `If-Match`: unlike `bind`, `None` stays unconditional (`complete` is keyed by
        // `upload_id`, not a rebind). `*` matches anything; otherwise it must equal the file's
        // current content ETag. For `auto_bind` sessions this is also the embedded bind's
        // precondition. Only reached for a new completion attempt (Completed/Aborted handled
        // above).
        if let Some(m) = if_match {
            let m = m.trim();
            if m != "*" {
                let current_etag = etag::etag_for(&file);
                if Some(m) != current_etag.as_deref() {
                    return Err(DomainError::precondition_failed(
                        "If-Match does not match the current content ETag",
                    ));
                }
            }
        }

        // Fast-path expiry rejection on the loaded snapshot: an expired session may still read as
        // live until cleanup reclaims it. The authoritative check is the lease CAS's
        // `WHERE expires_at > now` (`MultipartRepo::acquire_complete_lease`); a caller losing
        // that CAS is re-checked for expiry below.
        if session.expires_at <= OffsetDateTime::now_utc() {
            return Err(DomainError::multipart_upload_not_in_progress(
                upload_id, "expired",
            ));
        }

        // Acquire the completion lease with one conditional UPDATE (fresh `in_progress` acquire or
        // expired-`completing` takeover). Losing is not an error: answer 202 or replay.
        let now = OffsetDateTime::now_utc();
        let lease_owner = Uuid::now_v7().to_string();
        // `checked_add`/`.max(1)`: defense in depth, as for the TTLs in initiate.
        let lease_until = now
            .checked_add(time::Duration::seconds(self.complete_lease_secs.max(1)))
            .ok_or_else(|| {
                DomainError::database("complete lease TTL overflowed computing the lease expiry")
            })?;
        let acquired = self
            .store
            .acquire_multipart_complete_lease(upload_id, &lease_owner, lease_until, now)
            .await?;
        if !acquired {
            let fresh = self
                .store
                .get_multipart_upload(upload_id)
                .await?
                .ok_or_else(|| DomainError::multipart_upload_not_found(upload_id))?;
            return match fresh.state {
                // Checked first: a completed session replays even past `expires_at`.
                MultipartUploadState::Completed => {
                    self.metrics
                        .record_operation("complete_multipart_upload", "replayed");
                    Ok(MultipartCompleteOutcome::Completed(
                        self.replay_completed(file_id, &fresh).await?,
                    ))
                }
                // The CAS is fenced on `expires_at > now`, so losing it can mean the session
                // expired since `session` was loaded. Report that directly rather than a confusing
                // `in_progress` or a 202 forever; an `aborted` session keeps reporting `aborted`.
                MultipartUploadState::InProgress | MultipartUploadState::Completing
                    if fresh.expires_at <= now =>
                {
                    Err(DomainError::multipart_upload_not_in_progress(
                        upload_id, "expired",
                    ))
                }
                MultipartUploadState::Completing => Ok(MultipartCompleteOutcome::Completing {
                    retry_after_secs: COMPLETE_POLL_RETRY_SECS,
                }),
                _ => Err(DomainError::multipart_upload_not_in_progress(
                    upload_id,
                    fresh.state.as_str(),
                )),
            };
        }
        let takeover = session.state == MultipartUploadState::Completing;

        // Whether ANY `If-Match` (concrete or `*`) was supplied; it was already validated above, so
        // the embedded auto-bind CAS may target the observed pointer. With none, complete is
        // unconditional but must not also get an unconditional bind (see
        // `assemble_and_finish_inner`).
        let if_match_was_supplied = if_match.is_some();

        // Winner: assemble in a detached task so a dropped request cannot cancel it; the result is
        // persisted and any later `complete` replays it.
        let svc = Arc::clone(self);
        let ctx = ctx.clone();
        let handle = tokio::spawn(async move {
            svc.assemble_and_finish(
                &ctx,
                file,
                session,
                lease_owner,
                takeover,
                if_match_was_supplied,
            )
            .await
        });
        match handle.await {
            Ok(result) => result.map(MultipartCompleteOutcome::Completed),
            Err(join_err) => {
                tracing::error!(%upload_id, error = %join_err, "complete task panicked");
                Err(DomainError::InternalError)
            }
        }
    }

    /// Rebuild the response for an already-`completed` session from the persisted snapshot,
    /// falling back to the version row (pre-snapshot rows).
    ///
    /// The snapshot carries no `manifest`; it is re-read from `version_hash_manifest`, after
    /// confirming the version still exists (404 otherwise, not a silent `manifest: null`).
    async fn replay_completed(
        &self,
        file_id: Uuid,
        session: &MultipartUploadSession,
    ) -> Result<CompletedMultipartUpload, DomainError> {
        if let Some(json) = &session.complete_result
            && let Ok(stored) = serde_json::from_str::<StoredCompleteResult>(json)
        {
            // The version may have been deleted since completion (its manifest row cascades), so
            // confirm it exists before reading the manifest.
            if self
                .store
                .get_version(file_id, stored.version_id)
                .await?
                .is_none()
            {
                return Err(DomainError::version_not_found(file_id, stored.version_id));
            }
            let manifest = self.store.get_version_manifest(stored.version_id).await?;
            if let Some(completed) = stored.into_completed(manifest) {
                return Ok(completed);
            }
            tracing::warn!(
                upload_id = %session.upload_id,
                "multipart complete_result snapshot failed to parse or is internally \
                 inconsistent (unrecognized hash_mode/bind_state spelling, or a field \
                 combination resolve_bind_state/complete_multipart_upload never actually \
                 produces); falling back to rebuilding the response from the version row"
            );
        }
        // Fallback: rebuild from the version row, re-reading the file for a fresh content pointer.
        let file = self
            .store
            .require_file(&AccessScope::allow_all(), file_id)
            .await?;
        let version = self
            .store
            .get_version(file_id, session.version_id)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, session.version_id))?;
        if version.status != file_storage_sdk::VersionStatus::Available {
            return Err(DomainError::multipart_upload_not_in_progress(
                session.upload_id,
                session.state.as_str(),
            ));
        }
        let manifest = self.store.get_version_manifest(session.version_id).await?;
        let hash_mode = crate::infra::content::hash_mode::HashMode::parse(&version.hash_mode)
            .ok_or_else(|| {
                DomainError::database(format!(
                    "invalid hash_mode in DB for version {}: {}",
                    session.version_id, version.hash_mode
                ))
            })?;
        let (bind_state, bind_etag, current_etag) =
            Self::bind_state_for(&file, session, session.version_id);
        Ok(CompletedMultipartUpload {
            version_id: session.version_id,
            size: version.size,
            hash_algorithm: crate::infra::content::hash::ALGORITHM,
            content_hash: version.hash_value,
            hash_mode,
            part_count: version.part_count.unwrap_or(1),
            manifest,
            bind_state,
            etag: bind_etag,
            current_etag,
        })
    }

    /// Derive the shared bind state from the file's current pointer: bound to this version is
    /// `Bound`; an auto-bind session pointing elsewhere is `Conflict` (+ current ETag); a manual
    /// session is `Manual`.
    fn bind_state_for(
        file: &file_storage_sdk::File,
        session: &MultipartUploadSession,
        version_id: Uuid,
    ) -> (BindState, Option<String>, Option<String>) {
        crate::domain::multipart::resolve_bind_state(
            file.file_id,
            file.content_id,
            version_id,
            session.auto_bind,
        )
    }

    /// The lease-holder's assembly + finish path, run in a detached task. On error it releases
    /// the lease (best-effort) so the next `complete` retries immediately.
    async fn assemble_and_finish(
        &self,
        ctx: &SecurityContext,
        file: file_storage_sdk::File,
        session: MultipartUploadSession,
        lease_owner: String,
        takeover: bool,
        if_match_was_supplied: bool,
    ) -> Result<CompletedMultipartUpload, DomainError> {
        let upload_id = session.upload_id;
        let result = self
            .assemble_and_finish_inner(
                ctx,
                &file,
                &session,
                &lease_owner,
                takeover,
                if_match_was_supplied,
            )
            .await;
        if result.is_err()
            && let Err(release_err) = self
                .store
                .release_multipart_complete_lease(upload_id, &lease_owner)
                .await
        {
            tracing::warn!(%upload_id, error = %release_err, "failed to release completion lease");
        }
        result
    }

    // Single-owner state machine (assemble -> verify -> finalize -> finish), kept as one flat
    // sequence on purpose.
    #[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
    async fn assemble_and_finish_inner(
        &self,
        ctx: &SecurityContext,
        file: &file_storage_sdk::File,
        session: &MultipartUploadSession,
        lease_owner: &str,
        takeover: bool,
        if_match_was_supplied: bool,
    ) -> Result<CompletedMultipartUpload, DomainError> {
        let file_id = file.file_id;
        let upload_id = session.upload_id;

        // Already-finalized fast path, checked unconditionally, not only on `takeover`: a previous
        // completer may have died after the finalize transaction committed, or
        // `assemble_and_finish` released the lease (erasing `takeover`) after an error raised
        // post-finalize. Re-assembling would hit a consumed backend handle; just finish.
        if let Some(v) = self.store.get_version(file_id, session.version_id).await?
            && v.status == file_storage_sdk::VersionStatus::Available
        {
            let completed = self.replay_completed(file_id, session).await?;
            self.finish_session(ctx, session, lease_owner, &completed)
                .await?;
            return Ok(completed);
        }

        let parts = self.store.list_multipart_parts(upload_id).await?;

        // Backend from the version row, else the session's recorded `backend_id` (never the current
        // default); only a legacy session with neither falls back to the default.
        let version = self.store.get_version(file_id, session.version_id).await?;
        let backend_id = version.as_ref().map_or_else(
            || session.backend_id_or(self.backends.default_id()),
            |v| v.backend_id.clone(),
        );
        let backend = self.backends.get(&backend_id)?;
        let backend_path = session.backend_path_or_default();

        // Report the specific missing part numbers before the coarser size check below.
        let missing = missing_part_numbers(session, &parts);
        if !missing.is_empty() {
            return Err(DomainError::multipart_parts_missing(upload_id, missing));
        }

        let total_size: i64 = parts.iter().map(|p| p.size).sum();

        // Defence in depth: per-part sizes are enforced at the sidecar; this catches a
        // missing/extra part.
        if session.declared_size > 0 {
            let expected = i64::try_from(session.declared_size).unwrap_or(i64::MAX);
            if total_size != expected {
                return Err(DomainError::conflict(format!(
                    "multipart upload {upload_id}: assembled size {total_size} \
                     does not match declared_size {expected}"
                )));
            }
        }

        let policy = self
            .get_effective_policy_internal(ctx.subject_tenant_id(), file.owner_id)
            .await?;
        let effective_max = PolicyResolver::compute_effective_max_bytes(
            &policy,
            &session.declared_mime,
            backend.capabilities().max_size_bytes,
        );
        if let Some(limit) = effective_max
            && total_size > 0
            && total_size.cast_unsigned() > limit
        {
            return Err(DomainError::policy_size_exceeded(
                limit,
                "policy size limit",
            ));
        }

        // Backend parts with each part's byte offset (running sum of sizes) and SHA-256 digest.
        // `parts` is in ascending part-number order (gapless, per the missing-parts check above),
        // which for a valid plan equals offset order.
        let mut backend_parts: Vec<(u32, u64, [u8; 32], String)> = Vec::with_capacity(parts.len());
        let mut running_offset: u64 = 0;
        for p in &parts {
            let digest: [u8; 32] = p.part_hash.clone().try_into().map_err(|_| {
                DomainError::validation(
                    "part_hash",
                    format!(
                        "part {} hash is not a 32-byte SHA-256 digest",
                        p.part_number
                    ),
                )
            })?;
            backend_parts.push((
                p.part_number,
                running_offset,
                digest,
                p.backend_etag.clone(),
            ));
            running_offset += u64::try_from(p.size).unwrap_or(0);
        }

        // The backend builds the offset-manifest and `root` from the per-part digests and offsets
        // (no re-read of the assembled object, ADR-0006). `root` becomes the version's
        // `hash_value`; the manifest is persisted with the version row below.
        let (manifest, root) = match backend
            .complete_multipart(
                &backend_path,
                &session.backend_upload_handle,
                &backend_parts,
            )
            .await
        {
            Ok(assembled) => assembled,
            Err(assemble_err) if takeover => {
                // Takeover: the crashed completer may have already consumed the backend's multipart
                // handle. If the object exists, derive the same (manifest, root) locally from the
                // part rows (deterministic, identical to what the backend builds).
                let object_exists = backend.stat(&backend_path).await.ok().flatten().is_some();
                if !object_exists {
                    return Err(assemble_err);
                }
                let entries = backend_parts
                    .iter()
                    .map(
                        |(_, offset, digest, _)| crate::infra::content::hash_mode::ManifestEntry {
                            offset: *offset,
                            digest: *digest,
                        },
                    )
                    .collect();
                let manifest = crate::infra::content::hash_mode::Manifest::new(entries)?;
                let root = manifest.root();
                (manifest, root)
            }
            Err(e) => return Err(e),
        };
        // ADR-0006: a one-part plan degenerates to `whole-sha256` (the part's streaming digest is
        // `sha256(whole object)`), with no manifest row and `part_count` NULL. Plans of >= 2 parts
        // use the composite mode.
        let single_part = parts.len() == 1;
        let (hash_mode, content_hash, manifest_text) = if single_part {
            (
                crate::infra::content::hash_mode::HashMode::WholeSha256,
                backend_parts[0].2.to_vec(),
                None,
            )
        } else {
            (
                crate::infra::content::hash_mode::HashMode::MultipartCompositeSha256,
                root.to_vec(),
                Some(manifest.to_wire_string()),
            )
        };
        let part_count = i32::try_from(parts.len())
            .map_err(|_| DomainError::validation("part_count", "part count overflows i32"))?;

        // Sniff the assembled object's leading bytes and validate against `session.declared_mime`,
        // as the single-part finalize paths do (otherwise a MIME policy could be bypassed by
        // declaring an allowed type at initiate). Runs post-assembly: parts are not readable
        // before complete. An empty object has nothing to sniff, so the declared type is accepted.
        let mime_sniff_prefix = if total_size == 0 {
            Vec::new()
        } else {
            let sniff_len = u64::try_from(MIME_SNIFF_PREFIX_BYTES).unwrap_or(u64::MAX);
            backend
                .read_prefix(&backend_path, sniff_len)
                .await?
                .map(|b| b.to_vec())
                .unwrap_or_default()
        };
        // A mismatch fails before any DB finalize; the assembled blob is left as an orphan for the
        // cleanup sweep (a backend object may outlive a failed finalize).
        let validated_mime = validate_and_resolve_mime(&session.declared_mime, &mime_sniff_prefix)?;
        enforce_size_ceiling_for_validated_mime(
            &policy,
            &session.declared_mime,
            &validated_mime,
            backend.capabilities().max_size_bytes,
            total_size,
        )?;

        // Finalize the version row (the `complete` audit row is folded into this transaction).
        let finalize_audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::FinalizeVersion,
            serde_json::json!({ "version_id": session.version_id, "upload_id": upload_id, "size": total_size }),
        );
        // An `auto_bind` session binds inside this same finalize transaction.
        //
        // `file` was read at the top of `complete_multipart_upload` and may be stale (a rebind can
        // land between initiate and complete), so the CAS target depends on `If-Match`: if one was
        // supplied it was validated against this `content_id`, so the observed pointer is safe;
        // otherwise the CAS requires `content_id IS NULL` and can never overwrite unknown content.
        // A lost CAS is not an error: complete succeeds, `BindState::Conflict` + the current ETag
        // is reported, and a manual rebind needs no re-upload.
        let auto_bind_target = if if_match_was_supplied {
            file.content_id
        } else {
            None
        };
        let auto_bind = session.auto_bind.then(|| AutoBindOnFinalize {
            expected_content_id: auto_bind_target,
            audit: Self::audit_ok(
                ctx,
                Some(file_id),
                AuditOperation::PatchContent,
                serde_json::json!({
                    "version_id": session.version_id,
                    "upload_id": upload_id,
                    "auto_bind": true,
                }),
            ),
            event: Some(FileEvent {
                tenant_id: file.tenant_id,
                owner_id: file.owner_id,
                file_id,
                event_type: "file.content_updated".to_owned(),
                payload: serde_json::json!({ "version_id": session.version_id }),
            }),
        });

        // The terminal `completing -> completed` transition and the `complete_result` snapshot
        // are written in the SAME transaction as the finalize + auto-bind CAS (see
        // `MultipartStore::finalize_multipart_version`), so a crash cannot land between them.
        let session_audit = Self::multipart_complete_audit(ctx, session);
        let finalize_outcome = match self
            .store
            .finalize_multipart_version(
                file_id,
                manifest_text.clone(),
                Some(validated_mime),
                finalize_audit,
                auto_bind,
                MultipartFinishSnapshot {
                    upload_id,
                    version_id: session.version_id,
                    size: total_size,
                    content_hash: content_hash.clone(),
                    hash_mode,
                    // NULL for the one-part (`whole-sha256`) plan.
                    part_count: (!single_part).then_some(part_count),
                    session_audit,
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                // The object is already assembled; if the finalize was rejected because cleanup
                // reclaimed this session, no DB row will ever reference it, so delete it here
                // (the sweep only finds objects with rows).
                if matches!(
                    &e,
                    DomainError::Conflict { message }
                        if *message == MULTIPART_SESSION_RECLAIMED_BY_CLEANUP_MESSAGE
                ) {
                    self.best_effort_blob_delete(&backend_id, &backend_path)
                        .await;
                }
                return Err(e);
            }
        };
        let finalized = finalize_outcome.updated;
        let bound = finalize_outcome.bound;
        if !finalized {
            // A lost finalize CAS means someone else finished correctly (converge) or the row
            // is gone.
            return self
                .converge_or_error_after_lost_finalize_cas(
                    ctx,
                    file_id,
                    session,
                    lease_owner,
                    upload_id,
                )
                .await;
        }
        // The bind decision was made inside `finalize_multipart_version`'s transaction;
        // `current_etag` comes from there, not a post-commit read that could see a later rebind.
        // Authoritative for this call regardless of `session_completed`.
        let (bind_state, bind_etag, current_etag) = if bound {
            (
                BindState::Bound,
                Some(etag::content_etag(file_id, session.version_id)),
                None,
            )
        } else if session.auto_bind {
            (BindState::Conflict, None, finalize_outcome.current_etag)
        } else {
            (BindState::Manual, None, None)
        };

        let result = CompletedMultipartUpload {
            version_id: session.version_id,
            size: total_size,
            hash_algorithm: crate::infra::content::hash::ALGORITHM,
            content_hash,
            hash_mode,
            part_count,
            manifest: manifest_text,
            bind_state,
            etag: bind_etag,
            current_etag,
        };

        if !finalize_outcome.session_completed {
            // The finalize committed, but the same-transaction terminal session CAS lost (our lease
            // was taken over and closed by another completer). Close the session with THIS
            // snapshot rather than `replay_completed`, which would re-derive `bind_state` from the
            // file's current (possibly since rebound) pointer. `finish_session` converges
            // silently if the other completer closed it first.
            self.finish_session(ctx, session, lease_owner, &result)
                .await?;
        }

        // Credit the assembled bytes; `file_count_delta` is 0 (counted at `create_file`).
        self.report_usage(UsageDelta {
            tenant_id: file.tenant_id,
            owner_id: file.owner_id,
            bytes_delta: total_size,
            file_count_delta: 0,
        });

        self.metrics
            .record_operation("complete_multipart_upload", "ok");
        Ok(result)
    }

    /// Handle a lost finalize CAS in `assemble_and_finish_inner` (fenced by `status = 'pending'`,
    /// not by lease ownership). Re-reads the version:
    ///
    /// - `Available`: a lease-taken-over completer's finalize won correctly, so converge: rebuild
    ///   the response and finish the session (its CAS is filtered on `state = 'completing'` and
    ///   converges silently if already finished). Erroring here could strand the session in
    ///   `in_progress` via the other completer's lease release (repro:
    ///   `tests/pg_concurrency_test.rs`, `f2_stale_completer_converges_*`).
    /// - Otherwise the pending row is gone (concurrent abort or cleanup): a real error.
    ///
    /// Not used when this call's finalize won but its terminal session CAS lost; the caller has
    /// the authoritative outcome in that case and closes the session itself.
    async fn converge_or_error_after_lost_finalize_cas(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        session: &MultipartUploadSession,
        lease_owner: &str,
        upload_id: Uuid,
    ) -> Result<CompletedMultipartUpload, DomainError> {
        let converged_version = self.store.get_version(file_id, session.version_id).await?;
        if let Some(v) = converged_version
            && v.status == file_storage_sdk::VersionStatus::Available
        {
            let completed = self.replay_completed(file_id, session).await?;
            self.finish_session(ctx, session, lease_owner, &completed)
                .await?;
            return Ok(completed);
        }
        Err(DomainError::conflict(format!(
            "multipart upload {upload_id}: version row was removed before completion"
        )))
    }

    /// The `MultipartComplete` audit row, shared by `finish_session` and the main path (which
    /// folds it into the finalize transaction); both must record the identical shape.
    fn multipart_complete_audit(
        ctx: &SecurityContext,
        session: &MultipartUploadSession,
    ) -> AuditEntry {
        Self::audit_ok(
            ctx,
            Some(session.file_id),
            AuditOperation::MultipartComplete,
            serde_json::json!({ "upload_id": session.upload_id, "version_id": session.version_id }),
        )
    }

    /// Terminal `completing -> completed` transition, persisting the response snapshot and the
    /// audit row in one transaction. Only the takeover/converge recovery paths use it; the main
    /// path does this inside `finalize_multipart_version` so the snapshot agrees with the bind
    /// decision even across a crash.
    async fn finish_session(
        &self,
        ctx: &SecurityContext,
        session: &MultipartUploadSession,
        lease_owner: &str,
        result: &CompletedMultipartUpload,
    ) -> Result<(), DomainError> {
        let upload_id = session.upload_id;
        let audit = Self::multipart_complete_audit(ctx, session);
        let result_json = serde_json::to_string(&StoredCompleteResult::from_completed(result))
            .map_err(|_| DomainError::database("failed to serialize complete result"))?;
        let finished = self
            .store
            .complete_multipart_upload(upload_id, lease_owner, &result_json, audit)
            .await?;
        if !finished {
            // Our lease expired or was taken over. If the session is already `Completed` (by the
            // current owner) the outcome converges (same parts, same result): succeed.
            let fresh = self
                .store
                .get_multipart_upload(upload_id)
                .await?
                .ok_or_else(|| DomainError::multipart_upload_not_found(upload_id))?;
            if fresh.state != MultipartUploadState::Completed {
                return Err(DomainError::multipart_upload_not_in_progress(
                    upload_id,
                    fresh.state.as_str(),
                ));
            }
        }
        Ok(())
    }

    /// `GET /files/{id}/multipart/{upload_id}`: introspect a multipart upload session.
    ///
    /// Returns the state, the reported parts and the missing parts. A live session
    /// (`in_progress`, not expired) also gets fresh resume URLs for the missing parts; a terminal
    /// or expired one reports accounting only.
    ///
    /// Authorized on `actions::WRITE`, not `READ`, since it hands out live upload URLs.
    #[tracing::instrument(skip_all)]
    pub async fn introspect_multipart_upload(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        upload_id: Uuid,
    ) -> Result<MultipartUploadStatus, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let session = self
            .store
            .get_multipart_upload(upload_id)
            .await?
            .ok_or_else(|| DomainError::multipart_upload_not_found(upload_id))?;

        // Foreign `upload_id` is masked as "not found" (as in `complete_multipart_upload`).
        if session.file_id != file_id {
            return Err(DomainError::multipart_upload_not_found(upload_id));
        }

        let parts = self.store.list_multipart_parts(upload_id).await?;
        let missing_numbers = missing_part_numbers(&session, &parts);

        let now = OffsetDateTime::now_utc();
        let can_resume =
            session.state == MultipartUploadState::InProgress && session.expires_at > now;

        // Look up the backend only when a resume URL may be minted.
        let backend_id = if can_resume {
            let version = self.store.get_version(file_id, session.version_id).await?;
            // Same version, then session, then default fallback as `assemble_and_finish_inner`.
            version.map_or_else(
                || session.backend_id_or(self.backends.default_id()),
                |v| v.backend_id,
            )
        } else {
            String::new()
        };

        // Resume tokens expire at `min(session expiry, now + url_ttl_secs)`: the session's own
        // (long-lived) expiry would keep an early resume URL valid for the whole session, defeating
        // the short URL TTL. `checked_add`/`.max(1)` are defense in depth, as in initiate.
        let url_ttl_cap = now
            .checked_add(time::Duration::seconds(self.url_ttl_secs.max(1)))
            .ok_or_else(|| {
                DomainError::database("signed-URL TTL overflowed computing the resume URL cap")
            })?;
        let exp = session.expires_at.min(url_ttl_cap).unix_timestamp();
        let request_id = Uuid::now_v7().to_string();
        let backend_path = session.backend_path_or_default();

        let mut missing = Vec::with_capacity(missing_numbers.len());
        for part_number in missing_numbers {
            let (offset, size) = part_bounds(&session, part_number);
            let upload_url = if can_resume {
                Some(self.mint_part_url(
                    file_id,
                    session.version_id,
                    &backend_id,
                    &backend_path,
                    upload_id,
                    &session.backend_upload_handle,
                    part_number,
                    offset,
                    size,
                    exp,
                    &request_id,
                    now,
                )?)
            } else {
                None
            };
            missing.push(MissingPart {
                part_number,
                offset,
                size,
                upload_url,
            });
        }

        let received = parts
            .into_iter()
            .map(|p| ReceivedPart {
                part_number: p.part_number,
                size: p.size,
                uploaded_at: p.uploaded_at,
            })
            .collect();

        self.metrics
            .record_operation("introspect_multipart_upload", "ok");
        Ok(MultipartUploadStatus {
            upload_id,
            version_id: session.version_id,
            state: session.state,
            declared_mime: session.declared_mime,
            declared_size: session.declared_size,
            part_size: session.part_size,
            created_at: session.created_at,
            expires_at: session.expires_at,
            received,
            missing,
        })
    }

    /// `DELETE /files/{id}/multipart/{upload_id}`: abort a multipart upload.
    pub async fn abort_multipart_upload(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        upload_id: Uuid,
    ) -> Result<(), DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let session = self
            .store
            .get_multipart_upload(upload_id)
            .await?
            .ok_or_else(|| DomainError::multipart_upload_not_found(upload_id))?;

        // Foreign `upload_id` is masked as "not found" (as in `complete_multipart_upload`).
        if session.file_id != file_id {
            return Err(DomainError::multipart_upload_not_found(upload_id));
        }

        if session.state != MultipartUploadState::InProgress {
            return Err(DomainError::multipart_upload_not_in_progress(
                upload_id,
                session.state.as_str(),
            ));
        }

        // Same backend fallback as `assemble_and_finish_inner`; pure reads, safe before the CAS.
        let version = self.store.get_version(file_id, session.version_id).await?;
        let backend_id = version.as_ref().map_or_else(
            || session.backend_id_or(self.backends.default_id()),
            |v| v.backend_id.clone(),
        );
        let backend = self.backends.get(&backend_id)?;
        let backend_path = session.backend_path_or_default();

        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::MultipartAbort,
            serde_json::json!({ "upload_id": upload_id, "version_id": session.version_id }),
        );

        // CAS-first: win `in_progress -> aborted` BEFORE touching the backend handle, which could
        // otherwise race a concurrent `complete` assembling from it (same order as
        // `CleanupEngine::abort_expired_multipart_session`).
        let aborted = self.store.abort_multipart_upload(upload_id, audit).await?;
        if !aborted {
            // A concurrent complete/abort won. Stop: a concurrent `complete` may be assembling from
            // (or have finished with) this backend handle and version, so touching either would
            // corrupt it.
            return Err(DomainError::multipart_upload_not_in_progress(
                upload_id,
                session.state.as_str(),
            ));
        }

        // Best-effort: the DB abort is already committed, so a backend failure is logged and
        // counted, not propagated (a retry would only hit `multipart_upload_not_in_progress`); the
        // backend reclaims the orphaned handle itself.
        if let Err(err) = backend
            .abort_multipart(&backend_path, &session.backend_upload_handle)
            .await
        {
            self.metrics
                .record_backend_error(backend.id(), "abort_multipart");
            tracing::warn!(
                %upload_id,
                backend_id = backend.id(),
                error = %err,
                "abort_multipart_upload: backend abort_multipart failed after the session \
                 was already marked aborted in the DB; leaving the backend-side upload for \
                 the backend's own garbage collection"
            );
        }

        // Delete the pending version row. A DB error propagates; an already-missing row is the
        // desired end state.
        self.store
            .delete_version(
                file_id,
                session.version_id,
                Self::audit_ok(
                    ctx,
                    Some(file_id),
                    AuditOperation::DeleteVersion,
                    serde_json::json!({ "version_id": session.version_id, "reason": "multipart_abort" }),
                ),
            )
            .await?;

        Ok(())
    }

    /// Delete a backend blob, logging (not failing) on error; a failed delete leaves an orphan
    /// for the cleanup engine. Mirrors `FileService::best_effort_blob_delete`.
    async fn best_effort_blob_delete(&self, backend_id: &str, path: &str) {
        let Ok(backend) = self.backends.get(backend_id) else {
            return;
        };
        if let Err(err) = backend.delete(path).await {
            self.metrics.record_backend_error(backend_id, "delete");
            tracing::warn!(?err, path, "best-effort backend delete failed");
        }
    }
}
