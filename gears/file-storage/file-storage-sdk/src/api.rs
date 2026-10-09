//! Inter-gear client trait for the file-storage control plane.

use async_trait::async_trait;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use crate::FileStorageError;
use crate::Page;
use crate::models::{
    CreateFileOutcome, CustomMetadataPatch, EffectivePolicy, FileFetch, FileId, FileRecord,
    MultipartCompleteOutcome, MultipartIntent, MultipartPlan, MultipartStatus, NewFile,
    OwnerFilter, OwnerKind, Policy, PolicyBody, PolicyScope, RetentionRule, RetentionRuleBody,
    RetentionScope, Storage, UploadTicket, VersionId, VersionRecord,
};

/// Public client trait other gears resolve from `ClientHub`.
///
/// Control-plane operations run in-process and return models and signed URLs; the
/// trait never transfers file bytes. Callers `PUT`/`GET` bytes against the sidecar
/// over the signed URLs.
///
/// # Error envelope
///
/// Every fallible method returns `Result<_, FileStorageError>`, the same canonical
/// envelope the REST API maps `DomainError` into.
///
/// # Conditional requests
///
/// `If-Match`/`If-None-Match`/`If-Match-Metadata` are explicit `Option<_>`
/// parameters mirroring the control API's headers.
#[async_trait]
pub trait FileStorageClientV1: Send + Sync {
    /// Create a file and presign its first content upload.
    ///
    /// Returns [`CreateFileOutcome::SinglePart`] with no `multipart` intent (or one whose
    /// plan collapses to a single part), otherwise [`CreateFileOutcome::Multipart`]
    /// (no single-part version is pre-registered).
    ///
    /// `idempotency_key` is rejected together with a `multipart` intent. With
    /// `auto_bind` the upload binds the first content (sidecar finalize callback, or
    /// multipart `complete`); otherwise the caller binds via [`Self::bind`].
    async fn create_file(
        &self,
        ctx: &SecurityContext,
        new: NewFile,
        idempotency_key: Option<String>,
        auto_bind: bool,
        multipart: Option<MultipartIntent>,
    ) -> Result<CreateFileOutcome, FileStorageError>;

    /// Get a file's metadata, honoring an optional `If-None-Match`.
    ///
    /// Returns [`FileFetch::NotModified`] when `if_none_match` matches the current
    /// content `ETag` (or is `"*"` and one exists), mirroring the conditional `304`.
    async fn get_file(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        if_none_match: Option<&str>,
    ) -> Result<FileFetch, FileStorageError>;

    /// List files (with custom metadata) for a mandatory owner filter, cursor-paginated.
    /// `cursor` is a previous `next_cursor`/`prev_cursor` (`None` = first page).
    async fn list_files(
        &self,
        ctx: &SecurityContext,
        owner: OwnerFilter,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<Page<FileRecord>, FileStorageError>;

    /// `JSON`-merge-patch a file's custom metadata, optionally guarded by
    /// `If-Match-Metadata` (the file's `meta_version`).
    async fn update_metadata(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        patch: CustomMetadataPatch,
        if_match_metadata: Option<i64>,
    ) -> Result<FileRecord, FileStorageError>;

    /// Delete a file and all its versions. `if_match` (the content `ETag`, or
    /// `"*"`) is **required** — pass `Some("*")` to delete unconditionally
    /// when the `ETag` is unknown.
    async fn delete_file(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        if_match: Option<&str>,
    ) -> Result<(), FileStorageError>;

    /// Issue a signed download URL pinned to the current content (or a
    /// specific `version_id`).
    async fn download_url(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        version_id: Option<VersionId>,
    ) -> Result<crate::models::DownloadTicket, FileStorageError>;

    /// List a file's content versions, newest first, cursor-paginated (`cursor` as in
    /// `list_files`). A page may carry fewer than `limit` items, with
    /// `next_cursor` still set, when the ADR-0006 manifest-byte budget truncates it.
    async fn list_versions(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<Page<VersionRecord>, FileStorageError>;

    /// Presign a new content version on an existing file (bind it afterwards
    /// via [`Self::bind`]).
    async fn presign_version(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
    ) -> Result<UploadTicket, FileStorageError>;

    /// Swap the file's content pointer to `version_id` under optimistic CAS.
    /// `if_match` is the opaque content `ETag` (or `"*"`, or `None` for the
    /// first bind); rebinding already-bound content requires it.
    async fn bind(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        version_id: VersionId,
        if_match: Option<&str>,
    ) -> Result<FileRecord, FileStorageError>;

    /// Delete a single version. Deleting the file's only version is
    /// equivalent to deleting the file.
    async fn delete_version(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        version_id: VersionId,
    ) -> Result<(), FileStorageError>;

    /// Initiate a multipart upload for a new version of an existing file (bind it
    /// afterwards via [`Self::bind`]).
    async fn initiate_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        declared_mime: &str,
        declared_size: u64,
        preferred_part_size: Option<u64>,
    ) -> Result<MultipartPlan, FileStorageError>;

    /// Introspect a multipart upload: state, reported parts and, while resumable,
    /// fresh URLs for the missing parts.
    async fn introspect_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        upload_id: Uuid,
    ) -> Result<MultipartStatus, FileStorageError>;

    /// Finalize a multipart upload (idempotent). Returns
    /// [`MultipartCompleteOutcome::Completing`] while another caller holds the
    /// completion lease; poll by re-issuing the call.
    async fn complete_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        upload_id: Uuid,
        if_match: Option<&str>,
    ) -> Result<MultipartCompleteOutcome, FileStorageError>;

    /// Abort a multipart upload and discard all parts.
    async fn abort_multipart(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        upload_id: Uuid,
    ) -> Result<(), FileStorageError>;

    /// Transfer ownership of a file to a new owner.
    async fn transfer_ownership(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        new_owner_kind: OwnerKind,
        new_owner_id: Uuid,
    ) -> Result<FileRecord, FileStorageError>;

    /// Migrate a non-versioned file's content to a different storage backend.
    async fn migrate_backend(
        &self,
        ctx: &SecurityContext,
        file_id: FileId,
        target_backend_id: &str,
    ) -> Result<(), FileStorageError>;

    /// List configured storage backends and their capabilities.
    async fn list_storages(&self, ctx: &SecurityContext) -> Result<Vec<Storage>, FileStorageError>;

    /// Get one configured storage backend by id.
    async fn get_storage(
        &self,
        ctx: &SecurityContext,
        storage_id: &str,
    ) -> Result<Storage, FileStorageError>;

    /// Get the stored (own-level) policy for a scope, if one has been set.
    async fn get_policy(
        &self,
        ctx: &SecurityContext,
        scope: PolicyScope,
        scope_owner_id: Option<Uuid>,
    ) -> Result<Option<Policy>, FileStorageError>;

    /// Compute the effective (most-restrictive tenant ⊕ user) policy.
    async fn get_effective_policy(
        &self,
        ctx: &SecurityContext,
        user_owner_id: Option<Uuid>,
    ) -> Result<EffectivePolicy, FileStorageError>;

    /// Set (upsert) the policy for a scope.
    async fn put_policy(
        &self,
        ctx: &SecurityContext,
        scope: PolicyScope,
        scope_owner_id: Option<Uuid>,
        body: PolicyBody,
    ) -> Result<Policy, FileStorageError>;

    /// List the caller's visible retention rules, cursor-paginated. Admins see every
    /// rule in the tenant; others see tenant-scope rules, their own user-scope rules
    /// and file-scope rules on files they own.
    async fn list_retention_rules(
        &self,
        ctx: &SecurityContext,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<Page<RetentionRule>, FileStorageError>;

    /// Create a new retention rule.
    async fn create_retention_rule(
        &self,
        ctx: &SecurityContext,
        scope: RetentionScope,
        scope_target_id: Option<Uuid>,
        body: RetentionRuleBody,
    ) -> Result<RetentionRule, FileStorageError>;

    /// Delete a retention rule by id.
    async fn delete_retention_rule(
        &self,
        ctx: &SecurityContext,
        rule_id: Uuid,
    ) -> Result<(), FileStorageError>;
}

#[cfg(test)]
#[path = "api_tests.rs"]
mod api_tests;
