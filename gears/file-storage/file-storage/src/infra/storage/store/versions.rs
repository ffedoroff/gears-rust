//! Version-level queries and mutating operations.
//!
//! Version-level queries and mutating operations, including the bind and ownership-transfer
//! transactions.

use std::collections::HashMap;

use time::OffsetDateTime;
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{File, FileVersion, VersionStatus};

use crate::domain::audit::{AuditEntry, FileEvent};
use crate::domain::error::DomainError;
use crate::domain::etag;
use crate::domain::multipart::{BindState, MultipartUploadState, StoredCompleteResult};
use crate::domain::ports::{
    AutoBindOnFinalize, DeleteVersionOutcome, FinalizeMultipartOutcome, FinalizeVersionOutcome,
    MultipartFinishSnapshot,
};
use crate::infra::content::hash_mode::HashMode;
use crate::infra::storage::db::{db_err, transaction_with_bounded_retry};
use crate::infra::storage::store::{Store, pending_version};

/// "No limit" for callers that must see a file's complete version set (cascade delete,
/// backend migration, usage accounting, sweeps); a page cap would under-delete blobs or
/// miscount usage. Kept within `i64::MAX` because `LIMIT` is signed 64-bit on `SQLite`
/// and `Postgres`.
pub(super) const UNBOUNDED_VERSIONS: u64 = i64::MAX as u64;

impl Store {
    /// Insert a pending version row (for `presign_version`).
    pub async fn insert_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        mime_type: &str,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        let pending = pending_version(
            file_id,
            version_id,
            mime_type,
            backend_id,
            backend_path,
            now,
        );
        self.repos
            .versions
            .insert(&conn, &AccessScope::allow_all(), &pending)
            .await
    }

    /// Fetch a single version by `(file_id, version_id)`.
    pub async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<FileVersion>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .get(&conn, &AccessScope::allow_all(), file_id, version_id)
            .await
    }

    /// List **all** versions of a file, newest first (unbounded; see `UNBOUNDED_VERSIONS`).
    pub async fn list_versions(&self, file_id: Uuid) -> Result<Vec<FileVersion>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .list_by_file(
                &conn,
                &AccessScope::allow_all(),
                file_id,
                UNBOUNDED_VERSIONS,
                0,
            )
            .await
    }

    /// List a page of a file's versions, newest first, forward-only cursor-paginated
    /// (backs `GET /files/{id}/versions`). `limit` is already clamped by the caller; `cursor`
    /// is decoded against `versions_binding`, so a cursor from a different file is rejected
    /// with `400`.
    ///
    /// Fetches `limit + 1` rows to detect a next page (no `COUNT`), trims to `limit` and
    /// encodes `next_cursor` from the last returned row.
    pub async fn list_versions_page(
        &self,
        file_id: Uuid,
        limit: u64,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<FileVersion>, DomainError> {
        use crate::domain::pagination;

        let binding = pagination::versions_binding(file_id);
        let after = cursor
            .map(|token| {
                pagination::decode(token, pagination::VERSIONS_ID_FIELD, binding.as_deref())
            })
            .transpose()?;

        let conn = self.db.conn().map_err(db_err)?;
        let rows = self
            .repos
            .versions
            .list_by_file_page(
                &conn,
                &AccessScope::allow_all(),
                file_id,
                limit.saturating_add(1),
                after,
            )
            .await?;

        Ok(pagination::finish_page(
            rows,
            limit,
            after,
            pagination::VERSIONS_ID_FIELD,
            binding.as_deref(),
            |v| (v.created_at, v.version_id),
        )?)
    }

    /// MIME type of the file's current version; `Ok(None)` only when no content is bound
    /// (DB errors propagate).
    pub async fn current_version_mime(&self, file: &File) -> Result<Option<String>, DomainError> {
        let Some(content_id) = file.content_id else {
            return Ok(None);
        };
        Ok(self
            .get_version(file.file_id, content_id)
            .await?
            .map(|v| v.mime_type))
    }

    /// Record a version's size + hash, mark it `available` and write an audit row in one
    /// transaction. Returns `true` if the version row existed and was updated.
    ///
    /// `mime_type` is the sniffed content type to persist; `None` keeps the declared one
    /// (multipart complete does not validate MIME). `hash_mode`/`part_count` are set here; for
    /// `multipart-composite-sha256`, `manifest` is inserted in the same transaction.
    ///
    /// `auto_bind`: when `Some`, the version is also bound as the file's current content (same
    /// CAS and current-flag promotion as `bind_atomic_with_event`) in this transaction. A lost
    /// CAS is reported via `FinalizeVersionOutcome::bound`, not as an error; the version stays
    /// `available` and can be rebound later.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
        hash_mode: HashMode,
        part_count: Option<i32>,
        manifest: Option<String>,
        mime_type: Option<String>,
        audit: AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
    ) -> Result<FinalizeVersionOutcome, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let hash_mode_str = hash_mode.as_str();
        let now = OffsetDateTime::now_utc();
        let db = self.db.db();
        // Retryable: auto-bind locks `file_versions` then `files`, while
        // `Store::delete_file[_with_event]` locks `files` then cascades into `file_versions`;
        // the opposite order can deadlock (`40P01`).
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let hash_value = hash_value.clone();
            let manifest = manifest.clone();
            let mime_type = mime_type.clone();
            let audit = audit.clone();
            let auto_bind = auto_bind.clone();
            Box::pin(async move {
                let scope = AccessScope::allow_all();
                let updated = versions
                    .finalize(
                        tx,
                        &scope,
                        file_id,
                        version_id,
                        size,
                        hash_value,
                        hash_mode_str,
                        part_count,
                        mime_type,
                    )
                    .await?;
                let mut bound = false;
                if updated {
                    // Manifest and version row commit atomically.
                    if let Some(manifest) = manifest {
                        versions
                            .insert_manifest(tx, &scope, version_id, &manifest, now)
                            .await?;
                    }
                    audit_repo.insert(tx, &audit).await?;

                    // Bind in the same transaction, as in `bind_atomic_with_event`.
                    if let Some(ab) = auto_bind {
                        let swapped = files
                            .bind_content_cas(
                                tx,
                                &scope,
                                file_id,
                                ab.expected_content_id,
                                version_id,
                                now,
                            )
                            .await?;
                        if swapped {
                            versions.clear_current(tx, &scope, file_id).await?;
                            // A concurrent `delete_version` may remove this version before the
                            // promotion (`VersionRepo::set_current`); abort rather than leave
                            // `files.content_id` dangling.
                            let promoted = versions
                                .set_current(tx, &scope, file_id, version_id)
                                .await?;
                            if promoted == 0 {
                                return Err(DomainError::conflict(
                                    "target version no longer exists -- it was deleted concurrently",
                                ));
                            }
                            // Persist the CAS outcome for the idempotent-retry fast path of
                            // `finalize_upload_by_token`
                            // (`VersionRepo::mark_bound_on_finalize`).
                            versions
                                .mark_bound_on_finalize(tx, &scope, file_id, version_id)
                                .await?;
                            audit_repo.insert(tx, &ab.audit).await?;
                            if let Some(ev) = ab.event {
                                events_repo.enqueue(tx, &ev).await?;
                            }
                        }
                        bound = swapped;
                    }
                }
                Ok::<FinalizeVersionOutcome, DomainError>(FinalizeVersionOutcome {
                    updated,
                    bound,
                })
            })
        })
        .await
    }

    /// Multipart counterpart of `finalize_version`: the same finalize + auto-bind-CAS
    /// transaction, plus the session `completing -> completed` transition and the
    /// `complete_result` snapshot, all in ONE transaction (no crash gap between them).
    ///
    /// `bind_state`/`etag`/`current_etag` are derived here (as in
    /// `MultipartService::bind_state_for`) because they depend on the auto-bind CAS outcome
    /// and, on a lost CAS, on a re-read of the file pointer inside this transaction.
    ///
    /// The session row is locked first (`MultipartRepo::lock_session_state`) and its `state`
    /// re-checked: the finalize CAS is fenced only by `file_versions.status = 'pending'`, not
    /// by lease ownership, so a stale completer whose session the cleanup already aborted
    /// (`CleanupEngine::abort_expired_multipart_session`) could otherwise finalize and bind a
    /// version for it. Only a vanished row or `aborted` fails with `DomainError::conflict`
    /// (rolled back, version left `pending`); other states are handled further down:
    /// - `completing`: the ordinary case (original lease holder or takeover).
    /// - `completed`: a redundant completer arriving after another one committed; letting it
    ///   through is safe, the version CAS finds `status` already `available`, reports
    ///   `updated: false`, and the caller converges.
    /// - `in_progress`: a takeover released its lease before this older attempt landed; the
    ///   version CAS still wins and `MultipartRepo::finish_complete` (owner `None` arm also
    ///   matches `in_progress`) closes the session out to `completed`.
    pub async fn finalize_multipart_version(
        &self,
        file_id: Uuid,
        manifest: Option<String>,
        mime_type: Option<String>,
        finalize_audit: AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
        finish: MultipartFinishSnapshot,
    ) -> Result<FinalizeMultipartOutcome, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let multipart = self.repos.multipart.clone();
        let hash_mode_str = finish.hash_mode.as_str();
        let auto_bind_requested = auto_bind.is_some();
        let now = OffsetDateTime::now_utc();
        let db = self.db.db();
        // Retryable for the lock-order reason documented in `finalize_version`. Order here is
        // `multipart_uploads` -> `file_versions` -> `files`; `abort_multipart_upload` never
        // touches the latter two, so only the `file_versions` -> `files` half can deadlock.
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let multipart = multipart.clone();
            let manifest = manifest.clone();
            let mime_type = mime_type.clone();
            let finalize_audit = finalize_audit.clone();
            let auto_bind = auto_bind.clone();
            let finish = finish.clone();
            Box::pin(async move {
                let scope = AccessScope::allow_all();
                // First statement (see `MultipartRepo::lock_session_state`): reject a session
                // the cleanup already reclaimed; see the method doc for the allowed states.
                let session_state = multipart.lock_session_state(tx, finish.upload_id).await?;
                let reclaimed_by_cleanup = match session_state.as_deref() {
                    Some(state) => state == MultipartUploadState::Aborted.as_str(),
                    None => true,
                };
                if reclaimed_by_cleanup {
                    return Err(DomainError::conflict(
                        crate::domain::error::MULTIPART_SESSION_RECLAIMED_BY_CLEANUP_MESSAGE,
                    ));
                }
                let updated = versions
                    .finalize(
                        tx,
                        &scope,
                        file_id,
                        finish.version_id,
                        finish.size,
                        finish.content_hash.clone(),
                        hash_mode_str,
                        finish.part_count,
                        mime_type,
                    )
                    .await?;
                if !updated {
                    // Lost finalize CAS: the caller converges
                    // (`converge_or_error_after_lost_finalize_cas`).
                    return Ok::<FinalizeMultipartOutcome, DomainError>(FinalizeMultipartOutcome {
                        updated: false,
                        bound: false,
                        session_completed: false,
                        current_etag: None,
                    });
                }

                if let Some(manifest) = manifest {
                    versions
                        .insert_manifest(tx, &scope, finish.version_id, &manifest, now)
                        .await?;
                }
                audit_repo.insert(tx, &finalize_audit).await?;

                let bound = if let Some(ab) = auto_bind {
                    let swapped = files
                        .bind_content_cas(
                            tx,
                            &scope,
                            file_id,
                            ab.expected_content_id,
                            finish.version_id,
                            now,
                        )
                        .await?;
                    if swapped {
                        versions.clear_current(tx, &scope, file_id).await?;
                        // Abort rather than leave a dangling `files.content_id`.
                        let promoted = versions
                            .set_current(tx, &scope, file_id, finish.version_id)
                            .await?;
                        if promoted == 0 {
                            return Err(DomainError::conflict(
                                "target version no longer exists -- it was deleted concurrently",
                            ));
                        }
                        // Same flag as `finalize_version`; retries replay from `complete_result`.
                        versions
                            .mark_bound_on_finalize(tx, &scope, file_id, finish.version_id)
                            .await?;
                        audit_repo.insert(tx, &ab.audit).await?;
                        if let Some(ev) = ab.event {
                            events_repo.enqueue(tx, &ev).await?;
                        }
                    }
                    swapped
                } else {
                    false
                };

                // Bind state computed inside this transaction (see the method doc).
                let (bind_state, result_etag, current_etag) = if bound {
                    (
                        BindState::Bound,
                        Some(etag::content_etag(file_id, finish.version_id)),
                        None,
                    )
                } else if auto_bind_requested {
                    let fresh = files.get(tx, &scope, file_id).await?.ok_or_else(|| {
                        DomainError::database(
                            "file row missing during multipart finalize's fresh-etag read",
                        )
                    })?;
                    (BindState::Conflict, None, etag::etag_for(&fresh))
                } else {
                    (BindState::Manual, None, None)
                };

                let stored = StoredCompleteResult {
                    version_id: finish.version_id,
                    size: finish.size,
                    content_hash: hex::encode(&finish.content_hash),
                    hash_mode: hash_mode_str.to_owned(),
                    part_count: finish.part_count.unwrap_or(1),
                    bind_state: bind_state.as_str().to_owned(),
                    etag: result_etag,
                    current_etag: current_etag.clone(),
                };
                let result_json = serde_json::to_string(&stored)
                    .map_err(|_| DomainError::database("failed to serialize complete result"))?;

                // Owner `None`: the finalize CAS won above proves legitimate authorship, and an
                // owner check would re-strand the stale-completer race; `in_progress` is accepted
                // too (see `MultipartRepo::finish_complete`).
                let session_completed = multipart
                    .finish_complete(tx, finish.upload_id, None, &result_json)
                    .await?;
                if session_completed {
                    audit_repo.insert(tx, &finish.session_audit).await?;
                }

                // `current_etag` is returned so the live response uses this transaction's decision,
                // not a racy post-commit read (`FinalizeMultipartOutcome::current_etag`).
                Ok(FinalizeMultipartOutcome {
                    updated,
                    bound,
                    session_completed,
                    current_etag,
                })
            })
        })
        .await
    }

    /// Fetch the manifest text of a version, if any (`multipart-composite-sha256` only).
    pub async fn get_version_manifest(
        &self,
        version_id: Uuid,
    ) -> Result<Option<String>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .get_manifest(&conn, &AccessScope::allow_all(), version_id)
            .await
    }

    /// Batched `get_version_manifest` for a page of versions (one `IN (...)` query, keyed by
    /// `version_id`); versions without a manifest are absent from the map.
    pub async fn get_version_manifests(
        &self,
        version_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, String>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .get_manifests(&conn, &AccessScope::allow_all(), version_ids)
            .await
    }

    /// Delete a version row and record an audit row in the same transaction.
    ///
    /// Returns `false` if it does not exist or is current. The current check is re-read inside
    /// the transaction and `VersionRepo::delete` also guards `is_current = false`, so a
    /// concurrent `bind` cannot leave `files.content_id` dangling (the delete removes 0 rows).
    pub async fn delete_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let scope = AccessScope::allow_all();
                    // In-transaction re-read: `is_current` mirrors `files.content_id`.
                    let Some(existing) = versions.get(tx, &scope, file_id, version_id).await?
                    else {
                        return Ok::<bool, DomainError>(false);
                    };
                    if existing.is_current {
                        return Ok(false);
                    }
                    let rows_affected = versions.delete(tx, &scope, file_id, version_id).await?;
                    if rows_affected == 0 {
                        // Raced: a concurrent bind made it current after the read above.
                        return Ok(false);
                    }
                    audit_repo.insert(tx, &audit).await?;
                    Ok(true)
                })
            })
            .await
    }

    /// Delete a version row iff it is still `pending`, with an audit row in the same
    /// transaction. Used by the cleanup instead of `delete_version` so a version that a racing
    /// `complete_multipart_upload` made `available` is never deleted.
    pub async fn delete_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let removed = versions
                        .delete_if_status(
                            tx,
                            &AccessScope::allow_all(),
                            file_id,
                            version_id,
                            VersionStatus::Pending,
                        )
                        .await?;
                    if removed {
                        audit_repo.insert(tx, &audit).await?;
                    }
                    Ok::<bool, DomainError>(removed)
                })
            })
            .await
    }

    /// Delete `version_id`, or, if it is the file's only version, the whole file, deciding
    /// **inside one transaction**.
    ///
    /// The `files` row is locked first (`FileRepo::lock_for_update`) and the version list read
    /// after, so a concurrent `insert_pending_version` either commits before the lock (and is
    /// seen, taking the `VersionRemoved` branch) or fails its FK check once the whole-file
    /// branch removes the row. A caller-side snapshot could otherwise cascade-remove a newly
    /// inserted version.
    ///
    /// Returns `DeleteVersionOutcome::FileRemoved` (via `file_audit`/`file_event`) when the
    /// version is the only one, `VersionRemoved` (via `version_audit`) when others remain, and
    /// `IsCurrent` if it was current when read or a concurrent bind made it current (caught by
    /// the `is_current = false` guard in `VersionRepo::delete`).
    #[allow(clippy::too_many_arguments)]
    pub async fn delete_version_or_whole_file(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        version_audit: AuditEntry,
        file_audit: AuditEntry,
        file_event: Option<FileEvent>,
    ) -> Result<DeleteVersionOutcome, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let retention_rules = self.repos.retention_rules.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let db = self.db.db();
        // Retryable: the `FileRemoved` branch locks `files` then cascades into
        // `file_versions`, the opposite of `finalize_version`'s auto-bind (deadlock exposure).
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let retention_rules = retention_rules.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let version_audit = version_audit.clone();
            let file_audit = file_audit.clone();
            let file_event = file_event.clone();
            Box::pin(async move {
                let scope = AccessScope::allow_all();
                // Lock the parent row first; `None` means the file is already gone.
                if files.lock_for_update(tx, &scope, file_id).await?.is_none() {
                    return Ok(DeleteVersionOutcome::NotFound);
                }

                // In-transaction snapshot taken after the lock.
                let all = versions
                    .list_by_file(tx, &scope, file_id, UNBOUNDED_VERSIONS, 0)
                    .await?;
                let Some(target) = all.iter().find(|v| v.version_id == version_id).cloned() else {
                    return Ok(DeleteVersionOutcome::NotFound);
                };

                if all.len() == 1 {
                    // `target` is the only version: delete the whole file in this transaction.
                    let removed = files.delete(tx, &scope, file_id).await?;
                    if !removed {
                        // A concurrent delete/expiry won.
                        return Ok(DeleteVersionOutcome::NotFound);
                    }
                    // No FK to cascade the rules; see `delete_file_collecting_versions`.
                    retention_rules
                        .delete_file_scope_rules(tx, &scope, file_id)
                        .await?;
                    audit_repo.insert(tx, &file_audit).await?;
                    if let Some(ev) = file_event {
                        events_repo.enqueue(tx, &ev).await?;
                    }
                    return Ok(DeleteVersionOutcome::FileRemoved(target));
                }

                if target.is_current {
                    return Ok(DeleteVersionOutcome::IsCurrent);
                }
                let rows_affected = versions.delete(tx, &scope, file_id, version_id).await?;
                if rows_affected == 0 {
                    // Raced: a concurrent bind made it current (`is_current = false` guard in
                    // `VersionRepo::delete`) or a concurrent delete removed it; re-check in this
                    // transaction to tell them apart.
                    return Ok(match versions.get(tx, &scope, file_id, version_id).await? {
                        Some(_) => DeleteVersionOutcome::IsCurrent,
                        None => DeleteVersionOutcome::NotFound,
                    });
                }
                audit_repo.insert(tx, &version_audit).await?;
                Ok(DeleteVersionOutcome::VersionRemoved(target))
            })
        })
        .await
    }

    /// Swap the content pointer and promote `version_id` as current in one transaction
    /// (the bind CAS), writing an audit row on success.
    ///
    /// `scope` must be the authorized scope for the CAS; the `is_current` flip uses
    /// `allow_all()` since versions have no tenant column and the file was already
    /// checked. Returns `false` on a concurrent CAS conflict.
    pub async fn bind_atomic(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_content_id: Option<Uuid>,
        version_id: Uuid,
        now: OffsetDateTime,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        let bind_scope = scope.clone();
        let db = self.db.db();
        // Retryable: locks `files` then `file_versions`, the reverse of `finalize_version`'s
        // auto-bind (deadlock exposure).
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let audit_repo = audit_repo.clone();
            let bind_scope = bind_scope.clone();
            let audit = audit.clone();
            Box::pin(async move {
                let swapped = files
                    .bind_content_cas(
                        tx,
                        &bind_scope,
                        file_id,
                        expected_content_id,
                        version_id,
                        now,
                    )
                    .await?;
                if !swapped {
                    return Ok(false);
                }
                // Promote the new version as current (unique-current index honoured).
                versions
                    .clear_current(tx, &AccessScope::allow_all(), file_id)
                    .await?;
                // 0 rows: a concurrent `delete_version` removed the version after the CAS; abort
                // rather than leave `files.content_id` dangling.
                let promoted = versions
                    .set_current(tx, &AccessScope::allow_all(), file_id, version_id)
                    .await?;
                if promoted == 0 {
                    return Err(DomainError::conflict(
                        "target version no longer exists -- it was deleted concurrently",
                    ));
                }
                audit_repo.insert(tx, &audit).await?;
                Ok::<bool, DomainError>(true)
            })
        })
        .await
    }

    /// Like `bind_atomic`, additionally enqueuing an optional file-event in the same
    /// transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn bind_atomic_with_event(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_content_id: Option<Uuid>,
        version_id: Uuid,
        now: OffsetDateTime,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<bool, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let bind_scope = scope.clone();
        let db = self.db.db();
        // Retryable: same lock order and deadlock exposure as `bind_atomic`.
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let bind_scope = bind_scope.clone();
            let audit = audit.clone();
            let event = event.clone();
            Box::pin(async move {
                let swapped = files
                    .bind_content_cas(
                        tx,
                        &bind_scope,
                        file_id,
                        expected_content_id,
                        version_id,
                        now,
                    )
                    .await?;
                if !swapped {
                    return Ok(false);
                }
                versions
                    .clear_current(tx, &AccessScope::allow_all(), file_id)
                    .await?;
                // 0 rows: concurrent `delete_version` (see `bind_atomic`); abort.
                let promoted = versions
                    .set_current(tx, &AccessScope::allow_all(), file_id, version_id)
                    .await?;
                if promoted == 0 {
                    return Err(DomainError::conflict(
                        "target version no longer exists -- it was deleted concurrently",
                    ));
                }
                audit_repo.insert(tx, &audit).await?;
                if let Some(ev) = event {
                    events_repo.enqueue(tx, &ev).await?;
                }
                Ok::<bool, DomainError>(true)
            })
        })
        .await
    }

    /// Update a version's `backend_id`/`backend_path`, CAS-gated on the expected values and on
    /// `owner` still holding the migration lease (`VersionRepo::rebind_backend`), and write a
    /// `BackendMigrate` audit row in the same transaction. The lease is NOT released on a win;
    /// the caller releases it after best-effort deleting the superseded source object.
    ///
    /// `false` means the version is gone, another migration moved the pointer, or the lease
    /// moved on from `owner`; the caller must re-fetch to tell these apart.
    #[allow(clippy::too_many_arguments)]
    pub async fn rebind_version_backend(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        expected_backend_id: &str,
        expected_backend_path: &str,
        new_backend_id: &str,
        new_backend_path: &str,
        owner: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        let versions = self.repos.versions.clone();
        let audit_repo = self.repos.audit.clone();
        let expected_backend_id = expected_backend_id.to_owned();
        let expected_backend_path = expected_backend_path.to_owned();
        let new_backend_id = new_backend_id.to_owned();
        let new_backend_path = new_backend_path.to_owned();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let updated = versions
                        .rebind_backend(
                            tx,
                            &AccessScope::allow_all(),
                            file_id,
                            version_id,
                            &expected_backend_id,
                            &expected_backend_path,
                            &new_backend_id,
                            &new_backend_path,
                            owner,
                        )
                        .await?;
                    if updated {
                        audit_repo.insert(tx, &audit).await?;
                    }
                    Ok::<bool, DomainError>(updated)
                })
            })
            .await
    }

    /// Acquire (or take over, if expired by the database clock) the migration lease
    /// (`VersionRepo::acquire_migration_lease`). `false` means another live `migrate_backend`
    /// holds it; the caller surfaces `Conflict` (409).
    pub async fn acquire_migration_lease(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        owner: Uuid,
        lease: std::time::Duration,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        let backend = self.db.db().backend();
        // Config validation keeps the lease far below `i64::MAX`; fallback is defensive only.
        let lease_secs = i64::try_from(lease.as_secs()).unwrap_or(i64::MAX);
        self.repos
            .versions
            .acquire_migration_lease(
                &conn,
                &AccessScope::allow_all(),
                backend,
                file_id,
                version_id,
                owner,
                lease_secs,
            )
            .await
    }

    /// Release a held migration lease (`VersionRepo::release_migration_lease`) scoped to
    /// `owner`; `migrate_backend` calls it best-effort on every exit path. A lease no longer
    /// held is left to expire.
    pub async fn release_migration_lease(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        owner: Uuid,
    ) -> Result<bool, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .release_migration_lease(&conn, &AccessScope::allow_all(), file_id, version_id, owner)
            .await
    }

    /// Force-set a version's migration lease fields. **Test-support only; not for production.**
    #[doc(hidden)]
    pub async fn set_migration_lease_for_test(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        owner: Option<Uuid>,
        until: Option<OffsetDateTime>,
    ) -> Result<(), DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos
            .versions
            .set_migration_lease_for_test(&conn, file_id, version_id, owner, until)
            .await
    }

    /// Update `owner_kind`/`owner_id`, enqueue an optional event and record an audit
    /// row in one transaction.
    ///
    /// Returns `true` if the file row was found and updated.
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer_ownership_atomic(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        new_owner_kind: &str,
        new_owner_id: Uuid,
        now: OffsetDateTime,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<bool, DomainError> {
        let files = self.repos.files.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let transfer_scope = scope.clone();
        let new_owner_kind = new_owner_kind.to_owned();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    let updated = files
                        .update_owner(
                            tx,
                            &transfer_scope,
                            file_id,
                            &new_owner_kind,
                            new_owner_id,
                            now,
                        )
                        .await?;
                    if updated {
                        audit_repo.insert(tx, &audit).await?;
                        if let Some(ev) = event {
                            events_repo.enqueue(tx, &ev).await?;
                        }
                    }
                    Ok::<bool, DomainError>(updated)
                })
            })
            .await
    }
}
