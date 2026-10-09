//! Domain-owned capability ports.
//!
//! Each trait names only the `Store` methods one consumer needs; the concrete `Store`
//! implements them all, so consumers never import `crate::infra::storage::Store`.

use std::collections::HashMap;

use async_trait::async_trait;
use time::OffsetDateTime;
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{CustomMetadataEntry, File, FileVersion};

use crate::domain::audit::{AuditEntry, FileEvent};
use crate::domain::error::DomainError;
use crate::domain::multipart::{MultipartPart, MultipartUploadSession};
use crate::domain::policy::{
    PolicyBody, PolicyScope, RetentionRuleBody, RetentionScope, StoredPolicy, StoredRetentionRule,
};

/// Bind a just-finalized version as the file's current content in the **same
/// transaction** as the finalize (single-part `bind=auto`, multipart `auto_bind`).
///
/// `expected_content_id` is the optimistic-CAS precondition (`None` = the file must
/// still have no content); it is the same CAS a manual `bind` performs under `If-Match`.
#[derive(Debug, Clone)]
pub struct AutoBindOnFinalize {
    /// CAS precondition: the `files.content_id` the swap may replace (`None` = `NULL`).
    pub expected_content_id: Option<Uuid>,
    /// Audit row for the bind step (in addition to the finalize audit row).
    pub audit: AuditEntry,
    /// Optional `file.content_updated` event, enqueued only when the CAS wins.
    pub event: Option<FileEvent>,
}

/// Result of [`MultipartStore::finalize_version`] / `Store::finalize_version`.
#[derive(Debug, Clone, Copy)]
pub struct FinalizeVersionOutcome {
    /// The version row existed, was `pending`, and is now `available`.
    pub updated: bool,
    /// The auto-bind CAS was requested and won (always `false` when no
    /// [`AutoBindOnFinalize`] was passed, or when `updated` is `false`).
    pub bound: bool,
}

/// What is known about the completion before the bind outcome is decided: every
/// `StoredCompleteResult` field except `bind_state`/`etag`/`current_etag`, which depend
/// on the in-transaction bind.
#[derive(Debug, Clone)]
pub struct MultipartFinishSnapshot {
    pub upload_id: Uuid,
    pub version_id: Uuid,
    pub size: i64,
    /// Raw (not hex-encoded) content hash.
    pub content_hash: Vec<u8>,
    pub hash_mode: crate::infra::content::hash_mode::HashMode,
    /// `None` for the degenerate one-part plan (`whole-sha256` versions have no `part_count`).
    pub part_count: Option<i32>,
    /// The `MultipartComplete` audit row, written in the finalize transaction iff the
    /// `completing -> completed` CAS wins (see `FinalizeMultipartOutcome::session_completed`).
    pub session_audit: AuditEntry,
}

/// Result of [`MultipartStore::finalize_multipart_version`].
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct FinalizeMultipartOutcome {
    /// The version row existed, was `pending`, and is now `available`.
    pub updated: bool,
    /// The auto-bind CAS was requested and won (always `false` when no
    /// [`AutoBindOnFinalize`] was passed, or when `updated` is `false`).
    pub bound: bool,
    /// The terminal `completing -> completed` CAS won in this same transaction, persisting
    /// the `complete_result` snapshot. `false` when `updated` is `false`, or when this
    /// call's completion lease was taken over before the CAS; the caller then
    /// re-checks and converges.
    pub session_completed: bool,
    /// The file's current content `ETag`, read in this transaction when an auto-bind was
    /// requested but its CAS lost (`Some` only then). The caller must build the
    /// `BindState::Conflict` response from it, not from a later read, which could
    /// disagree with the persisted `complete_result` snapshot.
    pub current_etag: Option<String>,
}

/// Result of `Store::delete_file_collecting_versions` /
/// [`CleanupStore::delete_file_with_event_collecting_versions`].
///
/// The version list is collected inside the delete's transaction, so a concurrently
/// inserted version cannot be cascade-removed without the caller's blob cleanup seeing it.
#[derive(Debug, Clone)]
pub struct DeletedFile {
    /// Whether the `files` row (and its cascaded `file_versions`) was removed. `false`
    /// means a concurrent delete/expiry won; `versions` is empty and nothing was audited.
    pub removed: bool,
    /// Every version row that existed at deletion, for best-effort blob cleanup and usage.
    pub versions: Vec<FileVersion>,
}

/// Result of `Store::delete_version_or_whole_file`.
///
/// The "is this the only version?" decision is made inside the delete's transaction,
/// not from a pre-transaction snapshot.
#[derive(Debug, Clone)]
pub enum DeleteVersionOutcome {
    /// `version_id` does not exist for this file (or the file itself is
    /// already gone).
    NotFound,
    /// `version_id` is the file's current content; the caller must bind
    /// another version before it can be deleted.
    IsCurrent,
    /// Just `version_id` was removed; the file and its other versions are
    /// untouched.
    VersionRemoved(FileVersion),
    /// `version_id` was the file's only version, so the whole file was removed too.
    FileRemoved(FileVersion),
}

/// Persistence port for the cleanup engine.
#[async_trait]
pub trait CleanupStore: Send + Sync {
    /// List pending versions older than `older_than`, excluding any backing a live
    /// `in_progress` multipart session (`expires_at > now`). Versions of expired
    /// sessions are not excluded; they become reclaimable once the session is aborted.
    ///
    /// Ordered `(created_at, version_id)` ascending, up to `limit`. `after` is a keyset
    /// cursor (rows strictly greater): the sweep pages past candidates that were not
    /// reclaimed so a stuck head-of-line row cannot starve the rest of the backlog.
    /// The cursor is local to one sweep run, never persisted.
    async fn list_abandoned_pending_versions(
        &self,
        older_than: OffsetDateTime,
        now: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<FileVersion>, DomainError>;

    /// List `files` rows with no version at all (`content_id IS NULL` and zero
    /// `file_versions`) created before `created_before`, ordered `(created_at, file_id)`
    /// ascending, up to `limit`; `after` is the same keyset cursor as above.
    ///
    /// Covers files left behind by a crash or failed initiate between file creation and
    /// the pending-version insert, which the other listings cannot see.
    async fn list_versionless_orphan_files(
        &self,
        created_before: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<File>, DomainError>;

    /// Delete a version row + audit in one transaction. Returns `true` if removed.
    async fn delete_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError>;

    /// Delete a version row iff it is still `pending` + audit, in one transaction.
    /// Returns `true` if removed. Status-guarded so a version flipped to `available`
    /// by a racing `complete_multipart_upload` is never deleted.
    async fn delete_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError>;

    /// List `in_progress` (or lease-lapsed `completing`) multipart sessions whose
    /// `expires_at` is before `now`, ordered `(expires_at, upload_id)` ascending, up to
    /// `limit`; `after` is the same keyset cursor as above.
    async fn list_expired_multipart_uploads(
        &self,
        now: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<MultipartUploadSession>, DomainError>;

    /// Mark a multipart session as `aborted` + audit in one transaction.
    async fn abort_multipart_upload(
        &self,
        upload_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError>;

    /// Fetch a single version by `(file_id, version_id)`.
    async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<FileVersion>, DomainError>;

    /// List all retention rules across all tenants and scopes (sweep engine).
    async fn list_all_retention_rules(&self) -> Result<Vec<StoredRetentionRule>, DomainError>;

    /// List files across all tenants, keyset-paginated by `file_id`.
    async fn list_all_files_for_sweep(
        &self,
        after: Option<Uuid>,
        limit: u64,
    ) -> Result<Vec<File>, DomainError>;

    /// List all custom-metadata entries for a file.
    async fn list_metadata(&self, file_id: Uuid) -> Result<Vec<CustomMetadataEntry>, DomainError>;

    /// Batched [`Self::list_metadata`]: custom metadata of many files in one query, keyed
    /// by `file_id`; files without metadata are absent. Lets the retention sweep avoid a
    /// per-file query.
    async fn list_metadata_for_files(
        &self,
        file_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<CustomMetadataEntry>>, DomainError>;

    /// List all versions of a file, newest first.
    async fn list_versions(&self, file_id: Uuid) -> Result<Vec<FileVersion>, DomainError>;

    /// Fetch a file by id (unscoped -- the sweep runs across all tenants).
    async fn get_file(&self, file_id: Uuid) -> Result<Option<File>, DomainError>;

    /// Batched [`Self::get_file`] (unscoped): every file in `ids` that exists, in one query.
    /// Used to resolve a candidate batch's audit `tenant_id`s up front.
    async fn list_files_by_ids(&self, ids: &[Uuid]) -> Result<Vec<File>, DomainError>;

    /// Whether `file_id` has an active (`in_progress` or `completing`) multipart session,
    /// regardless of `expires_at`/`lease_until`. Guards the orphan-file delete: deleting
    /// the file would `ON DELETE CASCADE` a live session. `completing` blocks
    /// unconditionally; only the expired-multipart sweep's own CAS may declare a stuck
    /// lease abandoned.
    async fn has_active_multipart_for_file(&self, file_id: Uuid) -> Result<bool, DomainError>;

    /// Delete a file row, collecting its version rows for blob cleanup inside the same
    /// transaction, optionally enqueue a file-event, and audit, all atomically. See
    /// `Store::delete_file_collecting_versions`; `expected_etag` is `None` here because
    /// cleanup callers have already decided the file must go.
    async fn delete_file_with_event_collecting_versions(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_etag: Option<String>,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<DeletedFile, DomainError>;

    /// Delete the parent `files` row of an abandoned-pending-version orphan, re-verifying in
    /// the same transaction that it still has zero versions and a `NULL` `content_id`.
    /// Returns `true` if removed.
    async fn delete_orphan_file_with_event(
        &self,
        file_id: Uuid,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<bool, DomainError>;

    /// Delete at most `limit` `idempotency_keys` rows with `expires_at <= now`, oldest
    /// first (batched like the other sweep phases). Returns the number removed.
    async fn delete_expired_idempotency_keys(
        &self,
        now: OffsetDateTime,
        limit: u64,
    ) -> Result<u64, DomainError>;
}

/// Persistence port for the multipart upload service.
#[async_trait]
pub trait MultipartStore: Send + Sync {
    /// Fetch a file by `(scope, file_id)`, or return `FileNotFound`.
    async fn require_file(&self, scope: &AccessScope, file_id: Uuid) -> Result<File, DomainError>;

    /// Fetch the policy for a given `(policy_scope, scope_owner_id)` within a
    /// tenant. Returns `None` when none is configured.
    async fn get_policy(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        policy_scope: &PolicyScope,
        scope_owner_id: Option<Uuid>,
    ) -> Result<Option<StoredPolicy>, DomainError>;

    /// Insert a pending version row.
    #[allow(clippy::too_many_arguments)]
    async fn insert_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        mime_type: &str,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Create a multipart upload session row. `auto_bind` makes `complete` bind the
    /// finalized version itself. `backend_id`/`backend_path` locate the pending version's
    /// object; always `Some` from the real flow (`None` only for legacy-shaped test rows).
    #[allow(clippy::too_many_arguments)]
    async fn create_multipart_upload(
        &self,
        upload_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        backend_upload_handle: &str,
        backend_id: Option<&str>,
        backend_path: Option<&str>,
        declared_mime: &str,
        declared_size: u64,
        part_size: u64,
        auto_bind: bool,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// Fetch a multipart upload session by `upload_id`.
    async fn get_multipart_upload(
        &self,
        upload_id: Uuid,
    ) -> Result<Option<MultipartUploadSession>, DomainError>;

    /// Fetch a single version by `(file_id, version_id)`.
    async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<FileVersion>, DomainError>;

    /// Fetch the stored `version_hash_manifest` text (`multipart-composite-sha256` versions
    /// only); used by the idempotent re-complete path to rebuild the response.
    async fn get_version_manifest(&self, version_id: Uuid) -> Result<Option<String>, DomainError>;

    /// Insert or replace a multipart upload part.
    #[allow(clippy::too_many_arguments)]
    async fn upsert_multipart_part(
        &self,
        upload_id: Uuid,
        part_number: i32,
        backend_etag: &str,
        part_hash: Vec<u8>,
        size: i64,
        now: OffsetDateTime,
    ) -> Result<(), DomainError>;

    /// List all parts for a multipart upload.
    async fn list_multipart_parts(
        &self,
        upload_id: Uuid,
    ) -> Result<Vec<MultipartPart>, DomainError>;

    /// Record a version's size + hash and mark it `available`, optionally binding it as the
    /// file's current content in the same transaction.
    ///
    /// `hash_mode`/`part_count`/`manifest` (ADR-0006) are persisted with the version row;
    /// `manifest` is `Some` only for `multipart-composite-sha256`. `validated_mime` is the
    /// sniffed MIME type stored in place of the declared one.
    ///
    /// `auto_bind`, when `Some`, binds under the same CAS as a manual `bind`, in the same
    /// transaction. A lost CAS is not an error: `FinalizeVersionOutcome::bound` reports
    /// it and the version stays `available` and manually rebindable.
    #[allow(clippy::too_many_arguments)]
    async fn finalize_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
        hash_mode: crate::infra::content::hash_mode::HashMode,
        part_count: Option<i32>,
        manifest: Option<String>,
        validated_mime: Option<String>,
        audit: AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
    ) -> Result<FinalizeVersionOutcome, DomainError>;

    /// Finalize a multipart completion's version AND transition its session
    /// `completing -> completed` (persisting the `complete_result` snapshot) in one
    /// transaction with the auto-bind CAS. A crash can then never leave the version
    /// `available` with no snapshot, which would make a re-complete re-derive `bind_state`
    /// from the file's current (possibly since rebound) content. See
    /// [`MultipartFinishSnapshot`]/[`FinalizeMultipartOutcome`].
    #[allow(clippy::too_many_arguments)]
    async fn finalize_multipart_version(
        &self,
        file_id: Uuid,
        manifest: Option<String>,
        validated_mime: Option<String>,
        finalize_audit: AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
        finish: MultipartFinishSnapshot,
    ) -> Result<FinalizeMultipartOutcome, DomainError>;

    /// Terminal transition `completing -> completed` + persist the response snapshot
    /// (`result_json`) + audit, in one transaction.
    ///
    /// Used by the takeover/converge recovery paths, which re-derive the response from
    /// committed state; the first-attempt path uses [`Self::finalize_multipart_version`].
    /// `lease_owner` must still match the session's current lease owner.
    async fn complete_multipart_upload(
        &self,
        upload_id: Uuid,
        lease_owner: &str,
        result_json: &str,
        audit: AuditEntry,
    ) -> Result<bool, DomainError>;

    /// Acquire (or take over an expired) completion lease: one conditional
    /// UPDATE `in_progress|expired-completing → completing(owner, until)`.
    /// `false` = a live lease exists or the session is terminal.
    async fn acquire_multipart_complete_lease(
        &self,
        upload_id: Uuid,
        owner: &str,
        lease_until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError>;

    /// Release a held completion lease back to `in_progress` (assembly
    /// failed) — scoped to `owner`.
    async fn release_multipart_complete_lease(
        &self,
        upload_id: Uuid,
        owner: &str,
    ) -> Result<bool, DomainError>;

    /// Mark a multipart session as `aborted` + audit in one transaction.
    async fn abort_multipart_upload(
        &self,
        upload_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError>;

    /// Delete a version row + audit in one transaction. Returns `true` if removed.
    async fn delete_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError>;
}

/// Persistence port for the policy administration service.
#[async_trait]
pub trait PolicyStore: Send + Sync {
    /// Resolve a `file`-scope rule's `scope_target_id` to a `File`, so per-file `WRITE`
    /// can be re-authorized.
    async fn require_file(&self, scope: &AccessScope, file_id: Uuid) -> Result<File, DomainError>;

    /// Batched [`Self::require_file`]: every file in `ids` that exists and is visible under
    /// `scope`, in one query (chunked against the bind-parameter limit).
    async fn list_files_by_ids(
        &self,
        scope: &AccessScope,
        ids: &[Uuid],
    ) -> Result<Vec<File>, DomainError>;

    /// Fetch the raw policy for a given `(policy_scope, scope_owner_id)` within
    /// a tenant. Returns `None` when none is configured.
    async fn get_policy(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        policy_scope: &PolicyScope,
        scope_owner_id: Option<Uuid>,
    ) -> Result<Option<StoredPolicy>, DomainError>;

    /// Upsert the policy for a given `(policy_scope, scope_owner_id)`.
    /// Returns the `policy_id`.
    async fn upsert_policy(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        policy_scope: &PolicyScope,
        scope_owner_id: Option<Uuid>,
        body: &PolicyBody,
        now: OffsetDateTime,
    ) -> Result<Uuid, DomainError>;

    /// List all retention rules for a tenant (all scopes), unpaginated. Used by tests as a
    /// ground-truth read; REST listing uses [`Self::list_retention_rules_page`].
    async fn list_retention_rules(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
    ) -> Result<Vec<StoredRetentionRule>, DomainError>;

    /// List retention rules for a tenant, cursor-paginated in either direction. Unless `admin`
    /// (resolved by the caller via an `ADMIN_POLICY` probe), the visibility filter runs in SQL:
    /// tenant-scope rules, the subject's own user-scope rules, and file-scope rules on files
    /// owned by `(subject_kind, subject_id)`. Items are always in canonical order
    /// (`created_at DESC, rule_id DESC`); `cursor` resumes in the direction it carries.
    ///
    /// # Errors
    /// A cursor error (`domain::pagination`) for an unreadable/mismatched
    /// `cursor`, or the underlying store error.
    #[allow(clippy::too_many_arguments)]
    async fn list_retention_rules_page(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        admin: bool,
        subject_kind: &str,
        subject_id: Uuid,
        limit: u64,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<StoredRetentionRule>, DomainError>;

    /// Insert a new retention rule. Returns the assigned `rule_id`.
    async fn insert_retention_rule(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        retention_scope: &RetentionScope,
        scope_target_id: Option<Uuid>,
        body: &RetentionRuleBody,
        now: OffsetDateTime,
    ) -> Result<Uuid, DomainError>;

    /// Delete a retention rule by `rule_id`. Returns `true` if a row was removed.
    async fn delete_retention_rule(
        &self,
        scope: &AccessScope,
        rule_id: Uuid,
    ) -> Result<bool, DomainError>;

    /// Fetch a retention rule by `rule_id`; callers use it to re-authorize by
    /// scope/target (a bare id carries no ownership).
    async fn get_retention_rule(
        &self,
        scope: &AccessScope,
        rule_id: Uuid,
    ) -> Result<Option<StoredRetentionRule>, DomainError>;
}

/// Metrics port. `FileStorageMetricsMeter` is the `OTel`-backed implementation;
/// `NoopMetrics` is the default, real wiring is opted into via `.with_metrics(...)`.
pub trait FileStorageMetricsPort: Send + Sync {
    /// Record a control-plane operation outcome, e.g. `("create_file", "ok")`.
    fn record_operation(&self, op: &str, result: &str);

    /// Record a storage-backend operation failure (`backend_id`, `op`).
    fn record_backend_error(&self, backend_id: &str, op: &str);

    /// Record a quota-enforcement denial for `op` (e.g. `"create_file"`,
    /// `"initiate_multipart_upload"`).
    fn record_quota_denied(&self, op: &str);

    /// Record one cleanup sweep's tallies (mirrors `cleanup::SweepResult`).
    fn record_sweep_result(
        &self,
        abandoned_pending_deleted: u64,
        abandoned_files_deleted: u64,
        expired_multipart_aborted: u64,
        retention_expired_deleted: u64,
        idempotency_keys_deleted: u64,
    );

    /// Record bytes received from a client upload (sidecar ingress).
    fn record_ingress_bytes(&self, bytes: f64);

    /// Record bytes served to a client download (sidecar egress).
    fn record_egress_bytes(&self, bytes: f64);

    /// Record one sidecar HTTP request's route/method/status/latency.
    ///
    /// Only wired at the sidecar; control-plane routes get request metrics from the
    /// api-gateway.
    fn record_request(&self, route: &str, method: &str, status: u16, latency_ms: f64);
}
