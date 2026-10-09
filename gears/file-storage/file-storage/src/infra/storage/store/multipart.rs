//! Multipart upload session intent methods.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::audit::AuditEntry;
use crate::domain::error::DomainError;
use crate::domain::multipart::{MultipartPart, MultipartUploadSession};
use crate::infra::storage::db::db_err;
use crate::infra::storage::store::Store;

impl Store {
    /// Create a multipart upload session row. `backend_id`/`backend_path` are the backend and
    /// object path of the pending version this session finalizes into.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_multipart_upload(
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
    ) -> Result<(), DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .create(
                &conn,
                upload_id,
                file_id,
                version_id,
                backend_upload_handle,
                backend_id,
                backend_path,
                declared_mime,
                declared_size,
                part_size,
                auto_bind,
                expires_at,
                now,
            )
            .await
    }

    /// Fetch a multipart upload session by `upload_id`.
    pub async fn get_multipart_upload(
        &self,
        upload_id: Uuid,
    ) -> Result<Option<MultipartUploadSession>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos.multipart.get(&conn, upload_id).await
    }

    /// Insert or replace a part, guarded and written in one transaction: the guard re-checks
    /// `state == 'in_progress'` under a row lock (see `MultipartRepo::upsert_part`). This closes
    /// two races: `complete` seeing a part missing between DELETE and INSERT, and a part INSERT
    /// landing after a concurrent abort deleted the parts (an orphan row nothing would clean).
    ///
    /// # Error contract
    ///
    /// Returns `DomainError::multipart_upload_not_in_progress` (`409`) if the session is no
    /// longer `in_progress`.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_multipart_part(
        &self,
        upload_id: Uuid,
        part_number: i32,
        backend_etag: &str,
        part_hash: Vec<u8>,
        size: i64,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let multipart = self.repos.multipart.clone();
        let backend_etag = backend_etag.to_owned();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let written = multipart
                        .upsert_part(
                            tx,
                            upload_id,
                            part_number,
                            &backend_etag,
                            part_hash,
                            size,
                            now,
                        )
                        .await?;
                    if written {
                        return Ok(());
                    }
                    // Guard lost: look up the state best-effort for the error; a lookup
                    // failure must not mask the guard failure.
                    let state = multipart
                        .get(tx, upload_id)
                        .await
                        .ok()
                        .flatten()
                        .map_or("gone", |session| session.state.as_str());
                    Err(DomainError::multipart_upload_not_in_progress(
                        upload_id, state,
                    ))
                })
            })
            .await
    }

    /// Whether `file_id` has an active (`in_progress` or `completing`) session, regardless of
    /// `expires_at`/`lease_until` (orphan-reconciliation guard).
    pub async fn has_active_multipart_for_file(&self, file_id: Uuid) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .has_active_for_file(&conn, file_id)
            .await
    }

    /// Force-set a session's `expires_at`. **Test-support only; do not call in production**
    /// (see `MultipartRepo::set_expires_at`).
    #[doc(hidden)]
    pub async fn set_multipart_expires_at_for_test(
        &self,
        upload_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .set_expires_at(&conn, upload_id, expires_at)
            .await
    }

    /// List all parts for a multipart upload.
    pub async fn list_multipart_parts(
        &self,
        upload_id: Uuid,
    ) -> Result<Vec<MultipartPart>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos.multipart.list_parts(&conn, upload_id).await
    }

    /// Mark a session `completed` (also setting `mime_validated`: the caller has already
    /// sniffed and validated the assembled object) and record the audit row in the same
    /// transaction.
    ///
    /// `lease_owner` must still match the session's current lease owner (see
    /// `MultipartRepo::finish_complete`). Only reached via `MultipartService::finish_session`
    /// (takeover and converge-after-lost-finalize-CAS), never right after this request's own
    /// finalize.
    pub async fn complete_multipart_upload(
        &self,
        upload_id: Uuid,
        lease_owner: &str,
        result_json: &str,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        let multipart = self.repos.multipart.clone();
        let audit_repo = self.repos.audit.clone();
        let lease_owner = lease_owner.to_owned();
        let result_json = result_json.to_owned();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    // Terminal transition from `completing`; persists the response snapshot
                    // for idempotent re-completes.
                    let updated = multipart
                        .finish_complete(tx, upload_id, Some(&lease_owner), &result_json)
                        .await?;
                    if updated {
                        audit_repo.insert(tx, &audit).await?;
                    }
                    Ok::<bool, DomainError>(updated)
                })
            })
            .await
    }

    /// Acquire (or take over an expired) completion lease — see
    /// `MultipartRepo::acquire_complete_lease`.
    pub async fn acquire_multipart_complete_lease(
        &self,
        upload_id: Uuid,
        owner: &str,
        lease_until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .acquire_complete_lease(&conn, upload_id, owner, lease_until, now)
            .await
    }

    /// Release a held completion lease after a failed assembly — see
    /// `MultipartRepo::release_complete_lease`.
    pub async fn release_multipart_complete_lease(
        &self,
        upload_id: Uuid,
        owner: &str,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .release_complete_lease(&conn, upload_id, owner)
            .await
    }

    /// Mark a session `aborted`, delete its part rows and record the audit row in one
    /// transaction, so a crash cannot leave an `aborted` session with dangling parts. Shared by
    /// the user abort and the cleanup sweep.
    pub async fn abort_multipart_upload(
        &self,
        upload_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        let multipart = self.repos.multipart.clone();
        let audit_repo = self.repos.audit.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let mut updated = multipart
                        .update_state(tx, upload_id, "in_progress", "aborted", None)
                        .await?;
                    if !updated {
                        // An expired `completing` lease (completer died) is abortable too;
                        // a live lease never is (the CAS requires `lease_until < now`).
                        updated = multipart
                            .abort_expired_completing(tx, upload_id, OffsetDateTime::now_utc())
                            .await?;
                    }
                    if updated {
                        multipart.delete_parts_for_upload(tx, upload_id).await?;
                        audit_repo.insert(tx, &audit).await?;
                    }
                    Ok::<bool, DomainError>(updated)
                })
            })
            .await
    }

    /// Delete all part rows for `upload_id`; returns the number removed.
    pub async fn delete_parts_for_upload(&self, upload_id: Uuid) -> Result<u64, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .multipart
            .delete_parts_for_upload(&conn, upload_id)
            .await
    }
}
