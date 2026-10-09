//! File-level queries and mutating operations on the `files` table.

use time::OffsetDateTime;
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{File, NewFile, OwnerFilter};

use crate::domain::audit::{AuditEntry, FileEvent};
use crate::domain::error::DomainError;
use crate::domain::etag;
use crate::domain::ports::DeletedFile;
use crate::infra::storage::db::{db_err, transaction_with_bounded_retry};
use crate::infra::storage::store::versions::UNBOUNDED_VERSIONS;
use crate::infra::storage::store::{IdempotencyInsert, Store, pending_version};

/// Overwrite `detail`/`payload`'s top-level `"version_count"` with the version list length
/// counted inside the delete transaction (the caller cannot know it earlier). No-op without
/// that key.
fn patch_version_count(value: &mut serde_json::Value, count: usize) {
    if let serde_json::Value::Object(map) = value
        && map.contains_key("version_count")
    {
        map.insert("version_count".to_owned(), serde_json::json!(count));
    }
}

/// De-duplicate initial `custom_metadata` entries (last occurrence wins): a multi-row INSERT
/// with the same `(file_id, key)` twice would violate the primary key.
fn dedup_initial_metadata(entries: &[(String, String)]) -> Vec<(String, String)> {
    let mut deduped: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (k, v) in entries {
        deduped.insert(k.as_str(), v.as_str());
    }
    deduped
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

impl Store {
    /// Fetch a file by `(scope, file_id)`. Returns `None` when absent.
    pub async fn get_file(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<Option<File>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos.files.get(&conn, scope, file_id).await
    }

    /// Batched `get_file`: every file in `ids` that exists and is visible, in one query
    /// (chunked against the bind-parameter budget, see `FileRepo::list_by_ids`).
    pub async fn list_files_by_ids(
        &self,
        scope: &AccessScope,
        ids: &[Uuid],
    ) -> Result<Vec<File>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos.files.list_by_ids(&conn, scope, ids).await
    }

    /// Like `get_file` but errors with `FileNotFound` when absent.
    pub async fn require_file(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<File, DomainError> {
        self.get_file(scope, file_id)
            .await?
            .ok_or_else(|| DomainError::file_not_found(file_id))
    }

    /// List files for an owner filter, newest-first, keyset-paginated in either direction.
    /// `limit` is the caller's already-clamped page size; `cursor` is decoded and validated
    /// against `files_binding`, so a cursor from a different owner pair is rejected with `400`.
    ///
    /// Fetches `limit + 1` rows to detect a further page (no `COUNT`); `finish_page` trims,
    /// restores canonical order and builds both cursors.
    pub async fn list_files(
        &self,
        scope: &AccessScope,
        owner: OwnerFilter,
        limit: u64,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<File>, DomainError> {
        use crate::domain::pagination;

        let binding = pagination::files_binding(&owner);
        let after = cursor
            .map(|token| pagination::decode(token, pagination::FILES_ID_FIELD, binding.as_deref()))
            .transpose()?;

        let conn = self.db.conn().map_err(db_err)?;
        let rows = self
            .repos
            .files
            .list_page(&conn, scope, owner, limit.saturating_add(1), after)
            .await?;

        Ok(pagination::finish_page(
            rows,
            limit,
            after,
            pagination::FILES_ID_FIELD,
            binding.as_deref(),
            |f| (f.created_at, f.file_id),
        )?)
    }

    /// Insert a file row, a pending version and initial custom metadata plus an audit
    /// row in ONE transaction, so a partial failure leaves no file without a version.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_file_with_pending_version(
        &self,
        new: &NewFile,
        file_id: Uuid,
        version_id: Uuid,
        tenant_id: Uuid,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
        audit: AuditEntry,
    ) -> Result<(), DomainError> {
        let file = File {
            file_id,
            tenant_id,
            owner_kind: new.owner_kind,
            owner_id: new.owner_id,
            name: new.name.clone(),
            gts_file_type: new.gts_file_type.clone(),
            content_id: None,
            meta_version: 0,
            created_at: now,
            last_modified_at: now,
        };
        let pending = pending_version(
            file_id,
            version_id,
            &new.mime_type,
            backend_id,
            backend_path,
            now,
        );
        // Own the initial metadata entries so the transaction closure can move them.
        let metadata_entries: Vec<(String, String)> = new
            .custom_metadata
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();

        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let metadata = self.repos.metadata.clone();
        let audit_repo = self.repos.audit.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    files.create(tx, &AccessScope::allow_all(), &file).await?;
                    versions
                        .insert(tx, &AccessScope::allow_all(), &pending)
                        .await?;
                    let deduped_metadata = dedup_initial_metadata(&metadata_entries);
                    metadata
                        .insert_many(
                            tx,
                            &AccessScope::allow_all(),
                            file_id,
                            &deduped_metadata,
                            now,
                        )
                        .await?;
                    audit_repo.insert(tx, &audit).await?;
                    Ok::<(), DomainError>(())
                })
            })
            .await
    }

    /// Delete a file row, collecting its version rows for backend-blob cleanup, optionally
    /// enqueue a file-event, and write an audit row, all in one transaction.
    ///
    /// The `files` row is locked first (`FileRepo::lock_for_update`, `FOR UPDATE`). A
    /// concurrent `presign_version`/`initiate_multipart_upload` takes `FOR KEY SHARE` on it for
    /// its FK check, so that insert either commits before the lock (and is then visible in the
    /// version list read after it) or blocks and fails its FK check against the deleted row.
    /// No version can be cascade-removed without appearing in the returned list, which would
    /// leak its backend blob.
    ///
    /// `audit.detail`/`event.payload`'s `"version_count"`, if present, is overwritten with the
    /// freshly-counted length.
    ///
    /// `expected_etag` is the already-validated `If-Match` value, re-checked against the
    /// locked row's ETag (`etag::content_etag`); a mismatch rolls back with
    /// `precondition_failed`. `None` means no check (`If-Match: *` or an internal caller such
    /// as retention expiry). Without it a concurrent `bind`/`restore_version` could make the
    /// delete remove content the caller never approved.
    pub async fn delete_file_collecting_versions(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
        expected_etag: Option<String>,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<DeletedFile, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let retention_rules = self.repos.retention_rules.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let del_scope = scope.clone();
        let db = self.db.db();
        // Retryable: lock order (`files` then cascaded `file_versions`) is the opposite of
        // `finalize_version`'s auto-bind branch.
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let retention_rules = retention_rules.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let del_scope = del_scope.clone();
            let expected_etag = expected_etag.clone();
            let mut audit = audit.clone();
            let mut event = event.clone();
            Box::pin(async move {
                let scope_all = AccessScope::allow_all();
                // Lock the parent row first; `None` means a concurrent delete/expiry won.
                let Some(locked) = files.lock_for_update(tx, &del_scope, file_id).await? else {
                    return Ok::<DeletedFile, DomainError>(DeletedFile {
                        removed: false,
                        versions: Vec::new(),
                    });
                };

                // Re-check `If-Match` against the locked row.
                if let Some(expected) = expected_etag {
                    let current = locked
                        .content_id
                        .map(|cid| etag::content_etag(file_id, cid));
                    if current.as_deref() != Some(expected.as_str()) {
                        return Err(DomainError::precondition_failed(
                            "If-Match does not match the current content ETag",
                        ));
                    }
                }

                // In-transaction snapshot taken after the lock (see the method doc).
                let collected = versions
                    .list_by_file(tx, &scope_all, file_id, UNBOUNDED_VERSIONS, 0)
                    .await?;
                patch_version_count(&mut audit.detail, collected.len());
                if let Some(ev) = event.as_mut() {
                    patch_version_count(&mut ev.payload, collected.len());
                }

                let removed = files.delete(tx, &del_scope, file_id).await?;
                if removed {
                    // No FK from `retention_rules.scope_target_id`: remove `File`-scope rules
                    // in the same transaction.
                    retention_rules
                        .delete_file_scope_rules(tx, &scope_all, file_id)
                        .await?;
                    audit_repo.insert(tx, &audit).await?;
                    if let Some(ev) = event {
                        events_repo.enqueue(tx, &ev).await?;
                    }
                }
                Ok::<DeletedFile, DomainError>(DeletedFile {
                    removed,
                    versions: if removed { collected } else { Vec::new() },
                })
            })
        })
        .await
    }

    /// Delete the `files` row left by an abandoned pending-version orphan, re-checking
    /// **inside this transaction** (after locking the row, `FileRepo::lock_for_update`) that
    /// `content_id` is `NULL`, there are no versions and no active multipart session.
    ///
    /// Unlike `delete_file_collecting_versions` (unconditional, used by retention expiry), a
    /// version inserted or bound after the caller's pre-check aborts the deletion. The lock
    /// closes the race a lone `DELETE ... WHERE NOT EXISTS` leaves open under `READ COMMITTED`
    /// (a concurrent insert could be cascade-removed unseen). Returns `false` if a check
    /// failed or the row was already gone.
    pub async fn delete_orphan_file_with_event(
        &self,
        file_id: Uuid,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<bool, DomainError> {
        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let multipart = self.repos.multipart.clone();
        let retention_rules = self.repos.retention_rules.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let db = self.db.db();
        // Retryable: `files` is locked first, the reverse of `finalize_version`'s lock order.
        transaction_with_bounded_retry(&db, move |tx| {
            let files = files.clone();
            let versions = versions.clone();
            let multipart = multipart.clone();
            let retention_rules = retention_rules.clone();
            let audit_repo = audit_repo.clone();
            let events_repo = events_repo.clone();
            let audit = audit.clone();
            let event = event.clone();
            Box::pin(async move {
                let scope = AccessScope::allow_all();
                // Lock the parent row first.
                let Some(locked) = files.lock_for_update(tx, &scope, file_id).await? else {
                    return Ok::<bool, DomainError>(false); // already gone
                };
                if locked.content_id.is_some() {
                    return Ok(false); // content bound concurrently -- not an orphan
                }
                // `LIMIT 1`: existence, not a count.
                let has_version = !versions
                    .list_by_file(tx, &scope, file_id, 1, 0)
                    .await?
                    .is_empty();
                if has_version {
                    return Ok(false);
                }
                if multipart.has_active_for_file(tx, file_id).await? {
                    return Ok(false);
                }

                let removed = files.delete_if_orphan(tx, &scope, file_id).await? > 0;
                if removed {
                    // No FK to cascade the rules; see `delete_file_collecting_versions`.
                    retention_rules
                        .delete_file_scope_rules(tx, &scope, file_id)
                        .await?;
                    audit_repo.insert(tx, &audit).await?;
                    if let Some(ev) = event {
                        events_repo.enqueue(tx, &ev).await?;
                    }
                }
                Ok::<bool, DomainError>(removed)
            })
        })
        .await
    }

    /// Create a file + pending version + initial metadata + optional event in one
    /// transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_file_with_pending_version_and_event(
        &self,
        new: &NewFile,
        file_id: Uuid,
        version_id: Uuid,
        tenant_id: Uuid,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
        audit: AuditEntry,
        event: Option<FileEvent>,
        idempotency: Option<IdempotencyInsert>,
    ) -> Result<(), DomainError> {
        let file = File {
            file_id,
            tenant_id,
            owner_kind: new.owner_kind,
            owner_id: new.owner_id,
            name: new.name.clone(),
            gts_file_type: new.gts_file_type.clone(),
            content_id: None,
            meta_version: 0,
            created_at: now,
            last_modified_at: now,
        };
        let pending = pending_version(
            file_id,
            version_id,
            &new.mime_type,
            backend_id,
            backend_path,
            now,
        );
        let metadata_entries: Vec<(String, String)> = new
            .custom_metadata
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();

        let files = self.repos.files.clone();
        let versions = self.repos.versions.clone();
        let metadata = self.repos.metadata.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        let idempotency_repo = self.repos.idempotency_keys.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    files.create(tx, &AccessScope::allow_all(), &file).await?;
                    versions
                        .insert(tx, &AccessScope::allow_all(), &pending)
                        .await?;
                    let deduped_metadata = dedup_initial_metadata(&metadata_entries);
                    metadata
                        .insert_many(
                            tx,
                            &AccessScope::allow_all(),
                            file_id,
                            &deduped_metadata,
                            now,
                        )
                        .await?;
                    audit_repo.insert(tx, &audit).await?;
                    if let Some(ev) = event {
                        events_repo.enqueue(tx, &ev).await?;
                    }
                    // Same transaction, so a committed create always has a replay record; a
                    // live-key conflict (concurrent duplicate) rolls the creation back.
                    if let Some(idem) = idempotency {
                        idempotency_repo.insert(tx, &idem, file_id, now).await?;
                    }
                    Ok::<(), DomainError>(())
                })
            })
            .await
    }

    /// Create the file row (+ initial custom metadata, audit, optional event) WITHOUT a
    /// pending version, for the merged create+plan path where multipart initiate registers
    /// its own.
    pub async fn create_file_with_event(
        &self,
        new: &NewFile,
        file_id: Uuid,
        tenant_id: Uuid,
        now: OffsetDateTime,
        audit: AuditEntry,
        event: Option<FileEvent>,
    ) -> Result<(), DomainError> {
        let file = File {
            file_id,
            tenant_id,
            owner_kind: new.owner_kind,
            owner_id: new.owner_id,
            name: new.name.clone(),
            gts_file_type: new.gts_file_type.clone(),
            content_id: None,
            meta_version: 0,
            created_at: now,
            last_modified_at: now,
        };
        let metadata_entries: Vec<(String, String)> = new
            .custom_metadata
            .iter()
            .map(|e| (e.key.clone(), e.value.clone()))
            .collect();

        let files = self.repos.files.clone();
        let metadata = self.repos.metadata.clone();
        let audit_repo = self.repos.audit.clone();
        let events_repo = self.repos.events_outbox.clone();
        self.db
            .db()
            .transaction_ref_mapped(move |tx| {
                Box::pin(async move {
                    files.create(tx, &AccessScope::allow_all(), &file).await?;
                    let deduped_metadata = dedup_initial_metadata(&metadata_entries);
                    metadata
                        .insert_many(
                            tx,
                            &AccessScope::allow_all(),
                            file_id,
                            &deduped_metadata,
                            now,
                        )
                        .await?;
                    audit_repo.insert(tx, &audit).await?;
                    if let Some(ev) = event {
                        events_repo.enqueue(tx, &ev).await?;
                    }
                    Ok::<(), DomainError>(())
                })
            })
            .await
    }

    /// List file-event rows for a file ordered by occurrence time (tests only).
    pub async fn list_file_events(
        &self,
        file_id: Uuid,
    ) -> Result<Vec<crate::infra::storage::repo::FileEventRow>, DomainError> {
        let conn = self.db.conn().map_err(db_err)?;
        self.repos.events_outbox.list_for_file(&conn, file_id).await
    }
}
