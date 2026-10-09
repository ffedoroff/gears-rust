//! Lifecycle / cleanup / sweep queries and idempotency-key lookup.
//!
//! Reclamation of superseded (non-current) versions is not implemented: it needs a
//! versioning-policy field that `RetentionRuleBody` does not have.

use time::OffsetDateTime;
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{File, FileVersion};

use crate::domain::error::DomainError;
use crate::domain::idempotency::IdempotencyRecord;
use crate::domain::multipart::MultipartUploadSession;
use crate::domain::policy::StoredRetentionRule;
use crate::infra::storage::db::db_err;
use crate::infra::storage::repo::AuditRow;
use crate::infra::storage::store::Store;

impl Store {
    /// Fetch an idempotency record if it exists and has not expired.
    pub async fn get_idempotency_key(
        &self,
        tenant_id: Uuid,
        owner_kind: &str,
        owner_id: Uuid,
        key: &str,
        now: OffsetDateTime,
    ) -> Result<Option<IdempotencyRecord>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .idempotency_keys
            .get(&conn, tenant_id, owner_kind, owner_id, key, now)
            .await
    }

    /// List audit rows for a file, ordered by occurrence time (tests only).
    pub async fn list_audit(&self, file_id: Uuid) -> Result<Vec<AuditRow>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos.audit.list_for_file(&conn, file_id).await
    }

    /// List `pending` versions older than `older_than`, excluding versions backing a
    /// live `in_progress` session (see `VersionRepo::list_pending_older_than`).
    pub async fn list_abandoned_pending_versions(
        &self,
        older_than: OffsetDateTime,
        now: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<FileVersion>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .list_pending_older_than(
                &conn,
                &AccessScope::allow_all(),
                older_than,
                now,
                limit,
                after,
            )
            .await
    }

    /// List `files` rows that never received any version; see
    /// [`crate::domain::ports::CleanupStore::list_versionless_orphan_files`].
    pub async fn list_versionless_orphan_files(
        &self,
        created_before: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<File>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .files
            .list_versionless_orphan_files(
                &conn,
                &AccessScope::allow_all(),
                created_before,
                limit,
                after,
            )
            .await
    }

    /// List `in_progress` multipart sessions whose `expires_at` is before `now`.
    pub async fn list_expired_multipart_uploads(
        &self,
        now: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<MultipartUploadSession>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .list_expired(&conn, now, limit, after)
            .await
    }

    /// List files across all tenants for the sweep, keyset-paginated by `file_id`;
    /// the caller loops with `after` until it gets fewer than `limit`.
    pub async fn list_all_files_for_sweep(
        &self,
        after: Option<Uuid>,
        limit: u64,
    ) -> Result<Vec<File>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .files
            .list_all_for_sweep(&conn, &AccessScope::allow_all(), after, limit)
            .await
    }

    /// List retention rules for a file (`scope = 'file'`), across all tenants.
    pub async fn list_file_retention_rules(
        &self,
        file_id: Uuid,
    ) -> Result<Vec<StoredRetentionRule>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .retention_rules
            .list_by_file_scope(&conn, &AccessScope::allow_all(), file_id)
            .await
    }

    /// List all retention rules across all tenants and scopes.
    pub async fn list_all_retention_rules(&self) -> Result<Vec<StoredRetentionRule>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .retention_rules
            .list_all(&conn, &AccessScope::allow_all())
            .await
    }

    /// Bulk-delete `idempotency_keys` rows expired at or before `now`; returns the count.
    pub async fn delete_expired_idempotency_keys(
        &self,
        now: OffsetDateTime,
        limit: u64,
    ) -> Result<u64, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .idempotency_keys
            .delete_expired(&conn, now, limit)
            .await
    }
}
