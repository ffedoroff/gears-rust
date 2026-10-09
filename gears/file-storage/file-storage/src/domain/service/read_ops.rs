//! Read-only queries and version-lifecycle operations (download URL, restore, delete).

use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use file_storage_sdk::{CustomMetadataEntry, File, FileVersion, OwnerFilter};

use crate::domain::audit::AuditOperation;
use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::etag;
use crate::domain::ports::DeleteVersionOutcome;
use crate::domain::service::{DownloadTicket, FileService};
use crate::infra::content::hash_mode::HashMode;
use crate::infra::external_clients::UsageDelta;

impl FileService {
    /// Get a file's metadata.
    pub async fn get_file(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::READ, &file.gts_file_type, Some(file_id))
            .await?;
        self.store.require_file(&scope, file_id).await
    }

    /// Get a file plus its custom metadata.
    pub async fn get_file_with_metadata(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<(File, Vec<CustomMetadataEntry>), DomainError> {
        let file = self.get_file(ctx, file_id).await?;
        let meta = self.store.list_metadata(file_id).await?;
        Ok((file, meta))
    }

    /// Batched custom-metadata lookup (one `IN (...)` query) for a `list_files` page.
    ///
    /// Performs **no authorization of its own**: every id in `file_ids` must already come
    /// from an authorized listing for the current `SecurityContext`. Hence `pub(crate)`.
    pub(crate) async fn list_metadata_for_files(
        &self,
        file_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<CustomMetadataEntry>>, DomainError> {
        self.store.list_metadata_for_files(file_ids).await
    }

    /// List files for a mandatory owner filter, cursor-paginated in either direction.
    pub async fn list_files(
        &self,
        ctx: &SecurityContext,
        owner: OwnerFilter,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<File>, DomainError> {
        // Authorize, then always tenant-scope the query regardless of the PDP's constraints.
        self.authorizer
            .authorize(ctx, actions::READ, "", None)
            .await?;
        // The READ check above is resource-less and `owner` comes from the request, so
        // listing another owner's files requires `ADMIN_POLICY` (else any tenant member
        // could enumerate a victim's files). Compare `owner_kind` too: `User` and `App`
        // are disjoint owner spaces, so a matching id alone does not prove ownership.
        if owner.owner_id != ctx.subject_id() || owner.owner_kind.as_str() != Self::actor_kind(ctx)
        {
            self.authorizer
                .authorize(ctx, actions::ADMIN_POLICY, "", None)
                .await?;
        }
        let limit = crate::domain::pagination::clamp_limit(
            limit,
            self.cfg.default_page_size,
            self.cfg.max_page_size,
        )?;
        self.store
            .list_files(&Self::tenant_scope(ctx), owner, limit, cursor)
            .await
    }

    /// `GET /files` plus every file's custom metadata (one batched lookup for the page),
    /// shared by the REST handler and the SDK local client.
    pub async fn list_files_with_metadata(
        &self,
        ctx: &SecurityContext,
        owner: OwnerFilter,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<(File, Vec<CustomMetadataEntry>)>, DomainError> {
        let page = self.list_files(ctx, owner, limit, cursor).await?;
        let file_ids: Vec<Uuid> = page.items.iter().map(|f| f.file_id).collect();
        let mut metadata_by_file = self.list_metadata_for_files(&file_ids).await?;
        Ok(page.map_items(|f| {
            let meta = metadata_by_file.remove(&f.file_id).unwrap_or_default();
            (f, meta)
        }))
    }

    /// Authorize `GET /storages` and `GET /storages/{id}` (backend discovery) with the same
    /// resource-less `READ` check as the other coarse read paths. `list_backends` and
    /// `get_backend` stay synchronous and unauthorized; handlers call this first.
    pub async fn authorize_backends_read(&self, ctx: &SecurityContext) -> Result<(), DomainError> {
        self.authorizer
            .authorize(ctx, actions::READ, "", None)
            .await
            .map(|_| ())
    }

    /// `GET /files/{id}/download-url`: issue a signed download URL pinned to the
    /// current content (or a specific `version_id`).
    #[tracing::instrument(skip_all)]
    pub async fn download_url(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Option<Uuid>,
    ) -> Result<DownloadTicket, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::READ, &file.gts_file_type, Some(file_id))
            .await?;

        let target = match version_id {
            Some(v) => v,
            None => file
                .content_id
                .ok_or_else(|| DomainError::conflict("file has no bound content yet"))?,
        };
        let version = self
            .store
            .get_version(file_id, target)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, target))?;

        if version.status != file_storage_sdk::VersionStatus::Available {
            return Err(DomainError::conflict(
                "cannot issue a download URL for a version whose upload has not been finalized",
            ));
        }

        // One ETag source for both the GET token claims (the sidecar echoes it with no DB
        // lookup) and the returned ticket.
        let content_etag = etag::content_etag(file_id, target);
        // Only `whole-sha256` versions carry a hash the sidecar can verify against the
        // whole stream; a composite `hash_value` is a root over part digests (ADR-0006).
        // Empty means "no check".
        let content_sha256 = if HashMode::parse(&version.hash_mode) == Some(HashMode::WholeSha256) {
            hex::encode(&version.hash_value)
        } else {
            String::new()
        };
        let download_url = self.build_download_url(
            file_id,
            target,
            version.backend_id,
            version.backend_path,
            Some((version.mime_type, content_etag.clone(), content_sha256)),
        )?;
        self.metrics.record_operation("download_url", "ok");
        Ok(DownloadTicket {
            download_url,
            etag: content_etag,
            version_id: target,
        })
    }

    /// `GET /files/{id}/versions`: list a file's versions, newest first, cursor-paginated and
    /// capped at `ServiceConfig::max_page_size`.
    pub async fn list_versions(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<FileVersion>, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::READ, &file.gts_file_type, Some(file_id))
            .await?;
        let limit = crate::domain::pagination::clamp_limit(
            limit,
            self.cfg.default_page_size,
            self.cfg.max_page_size,
        )?;
        self.store.list_versions_page(file_id, limit, cursor).await
    }

    /// Batched manifest lookup (one `IN (...)` query) for a `list_versions` page; only
    /// `multipart-composite-sha256` versions have a manifest row.
    ///
    /// Performs **no authorization of its own**: the ids must come from an authorized
    /// `list_versions` call. Hence `pub(crate)`, like [`Self::list_metadata_for_files`].
    pub(crate) async fn manifests_for_versions(
        &self,
        version_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, String>, DomainError> {
        self.store.get_version_manifests(version_ids).await
    }

    /// `GET /files/{id}/versions` plus the ADR-0006 offset-manifest of each
    /// `multipart-composite-sha256` version, truncated to a manifest-byte budget (see
    /// [`fetch_manifests_within_budget`]). Shared by the REST handler and the SDK client.
    ///
    /// # Cursor vs. manifest-budget truncation
    ///
    /// [`Self::list_versions`] decides `next_cursor` before any manifest is read. If the
    /// budget then drops versions from the tail, that cursor is stale, so it is rebuilt
    /// from the new last item; otherwise it is left as computed.
    pub async fn list_versions_with_manifests(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        limit: Option<u64>,
        cursor: Option<&str>,
    ) -> Result<toolkit_odata::Page<(FileVersion, Option<String>)>, DomainError> {
        let mut page = self.list_versions(ctx, file_id, limit, cursor).await?;
        let fetched_len = page.items.len();
        let mut manifests = self
            .fetch_manifests_within_budget(&mut page.items, LIST_VERSIONS_MANIFEST_BUDGET_BYTES)
            .await?;
        let budget_truncated = page.items.len() < fetched_len;
        let next_cursor = if budget_truncated {
            page.items
                .last()
                .map(|v| {
                    crate::domain::pagination::encode(
                        v.created_at,
                        v.version_id,
                        crate::domain::pagination::VERSIONS_ID_FIELD,
                        crate::domain::pagination::versions_binding(file_id),
                        crate::domain::pagination::Direction::Forward,
                    )
                })
                .transpose()?
        } else {
            page.page_info.next_cursor.clone()
        };
        // Truncation only drops the tail, so `prev_cursor` (from the first item) stays valid.
        let prev_cursor = page.page_info.prev_cursor.clone();
        let items = page
            .items
            .into_iter()
            .map(|v| {
                let manifest = manifests.remove(&v.version_id);
                (v, manifest)
            })
            .collect();
        Ok(toolkit_odata::Page::new(
            items,
            toolkit_odata::PageInfo {
                next_cursor,
                prev_cursor,
                limit: page.page_info.limit,
            },
        ))
    }

    /// Fetch the composite versions' manifests for one page, in page order and in
    /// [`MANIFEST_FETCH_BATCH_SIZE`] batches, stopping (and truncating `versions` via
    /// [`manifest_budget_cutoff`]) once the running byte total would cross `budget_bytes`,
    /// so at most one batch is fetched past the cutoff.
    ///
    /// The cutoff runs only over the safe prefix whose composite manifests are all
    /// fetched; an unfetched manifest would look like "no manifest" and be admitted free.
    async fn fetch_manifests_within_budget(
        &self,
        versions: &mut Vec<FileVersion>,
        budget_bytes: u64,
    ) -> Result<std::collections::HashMap<Uuid, String>, DomainError> {
        // Composite version ids and their positions in `versions`, in page order.
        let mut composite_ids: Vec<Uuid> = Vec::new();
        let mut composite_positions: Vec<usize> = Vec::new();
        for (i, v) in versions.iter().enumerate() {
            if v.hash_mode == crate::infra::content::hash_mode::HashMode::MULTIPART_COMPOSITE_SHA256
            {
                composite_ids.push(v.version_id);
                composite_positions.push(i);
            }
        }

        let mut manifests: std::collections::HashMap<Uuid, String> =
            std::collections::HashMap::new();
        let mut fetched = 0usize;

        for chunk in composite_ids.chunks(MANIFEST_FETCH_BATCH_SIZE) {
            let batch = self.manifests_for_versions(chunk).await?;
            manifests.extend(batch);
            fetched += chunk.len();

            let safe_upto = composite_positions
                .get(fetched)
                .copied()
                .unwrap_or(versions.len());
            let cutoff = manifest_budget_cutoff(&versions[..safe_upto], &manifests, budget_bytes);
            if cutoff < safe_upto {
                versions.truncate(cutoff);
                return Ok(manifests);
            }
            if safe_upto == versions.len() {
                // End of page reached within budget.
                return Ok(manifests);
            }
        }
        Ok(manifests)
    }

    /// Restore a prior version as current (a rebind: pointer swap, no re-upload).
    pub async fn restore_version(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<file_storage_sdk::File, DomainError> {
        let file = self.get_file(ctx, file_id).await?;
        let if_match = etag::etag_for(&file);
        self.bind(ctx, file_id, version_id, if_match.as_deref())
            .await
    }

    /// `DELETE /files/{id}`: remove the file and all versions (FK cascade), then best-effort
    /// delete the backend blobs. `If-Match` is **required**; `"*"` deletes unconditionally.
    ///
    /// The precondition is checked here as a fast reject and again inside
    /// `delete_file_inner`'s transaction, because the content may be rebound in between.
    #[tracing::instrument(skip_all)]
    pub async fn delete_file(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        if_match: Option<&str>,
    ) -> Result<(), DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::DELETE, &file.gts_file_type, Some(file_id))
            .await?;

        // Validate `If-Match` against the current content ETag.
        let current_etag = etag::etag_for(&file);
        let expected_etag = match if_match {
            None => {
                return Err(DomainError::precondition_failed(
                    "If-Match is required to delete a file",
                ));
            }
            Some(m) => {
                let m = m.trim();
                if m != "*" && Some(m) != current_etag.as_deref() {
                    return Err(DomainError::precondition_failed(
                        "If-Match does not match the current content ETag",
                    ));
                }
                // `"*"` skips the check; anything else is re-verified in the delete transaction.
                (m != "*").then(|| m.to_owned())
            }
        };

        self.delete_file_inner(ctx, file_id, expected_etag).await?;
        self.metrics.record_operation("delete_file", "ok");
        Ok(())
    }

    /// Delete a file; the caller must have authorized the request. Removes the DB row (FK
    /// children cascade), then best-effort deletes the backend blobs.
    ///
    /// `expected_etag` re-verifies `If-Match` **inside** the delete transaction, against the
    /// row it locks; `None` skips the check (`If-Match: *`, or the retention sweep).
    ///
    /// The version list (for audit `version_count` and blob cleanup) is collected inside the
    /// same transaction by `Store::delete_file_collecting_versions`, so a concurrently added
    /// version cannot be cascade-removed without its blob being queued for cleanup.
    pub(super) async fn delete_file_inner(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        expected_etag: Option<String>,
    ) -> Result<(), DomainError> {
        // Callers already authorized and enforced the tenant boundary via `require_file`.
        let scope = AccessScope::allow_all();

        // Tenant/owner for the event payload must be read before deletion.
        let file_meta = self.store.get_file(&scope, file_id).await?;
        let (event_tenant, event_owner) = file_meta.as_ref().map_or_else(
            || (ctx.subject_tenant_id(), Uuid::nil()),
            |f| (f.tenant_id, f.owner_id),
        );

        // Placeholder `version_count`; the store patches in the real count.
        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::DeleteFile,
            serde_json::json!({ "version_count": 0 }),
        );
        let event = Some(Self::make_file_event(
            event_tenant,
            event_owner,
            file_id,
            "file.deleted",
            serde_json::json!({ "version_count": 0 }),
        ));

        let deleted = self
            .store
            .delete_file_collecting_versions(&scope, file_id, expected_etag, audit, event)
            .await?;
        if !deleted.removed {
            return Err(DomainError::file_not_found(file_id));
        }

        let total_bytes: i64 = deleted.versions.iter().map(|v| v.size).sum();
        self.report_usage(UsageDelta {
            tenant_id: event_tenant,
            owner_id: event_owner,
            bytes_delta: -total_bytes,
            file_count_delta: -1,
        });

        // A failed blob delete leaves an orphan for the cleanup engine.
        for v in deleted.versions {
            self.best_effort_blob_delete(&v.backend_id, &v.backend_path)
                .await;
        }
        Ok(())
    }

    /// Delete a single version and its blob; deleting the only version deletes the file.
    ///
    /// The "only version?" decision is made inside
    /// [`crate::infra::storage::Store::delete_version_or_whole_file`]'s transaction, so a
    /// concurrently added version cannot make a stale verdict delete the whole file.
    #[tracing::instrument(skip_all)]
    pub async fn delete_version(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<(), DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::DELETE, &file.gts_file_type, Some(file_id))
            .await?;

        let version_audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::DeleteVersion,
            serde_json::json!({ "version_id": version_id }),
        );
        // Built up front (no I/O) because the store decides transactionally which one is
        // persisted; `version_count` is 1 by construction on the whole-file branch.
        let file_audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::DeleteFile,
            serde_json::json!({ "version_count": 1 }),
        );
        let file_event = Some(Self::make_file_event(
            file.tenant_id,
            file.owner_id,
            file_id,
            "file.deleted",
            serde_json::json!({ "version_count": 1 }),
        ));

        let outcome = self
            .store
            .delete_version_or_whole_file(
                file_id,
                version_id,
                version_audit,
                file_audit,
                file_event,
            )
            .await?;

        match outcome {
            DeleteVersionOutcome::NotFound => {
                Err(DomainError::version_not_found(file_id, version_id))
            }
            DeleteVersionOutcome::IsCurrent => Err(DomainError::conflict(
                "cannot delete the current version; bind another version first",
            )),
            DeleteVersionOutcome::FileRemoved(removed) => {
                // Whole-file debit.
                self.report_usage(UsageDelta {
                    tenant_id: file.tenant_id,
                    owner_id: file.owner_id,
                    bytes_delta: -removed.size,
                    file_count_delta: -1,
                });
                self.best_effort_blob_delete(&removed.backend_id, &removed.backend_path)
                    .await;
                self.metrics.record_operation("delete_version", "ok");
                Ok(())
            }
            DeleteVersionOutcome::VersionRemoved(removed) => {
                // Debit this version's bytes only.
                self.report_usage(UsageDelta {
                    tenant_id: file.tenant_id,
                    owner_id: file.owner_id,
                    bytes_delta: -removed.size,
                    file_count_delta: 0,
                });
                self.best_effort_blob_delete(&removed.backend_id, &removed.backend_path)
                    .await;
                self.metrics.record_operation("delete_version", "ok");
                Ok(())
            }
        }
    }
}

/// Aggregate manifest-byte budget for one [`FileService::list_versions_with_manifests`]
/// page, enforced while manifests are fetched rather than as a cap on `?limit`.
const LIST_VERSIONS_MANIFEST_BUDGET_BYTES: u64 = 4 * 1024 * 1024;

/// Composite manifests fetched per DB round trip: small enough to bound the fetch past
/// an early budget cutoff, large enough that a page within budget needs few queries.
const MANIFEST_FETCH_BATCH_SIZE: usize = 8;

/// How many of `versions` (newest first) to keep so their summed `manifests` byte length
/// stays within `budget_bytes`.
///
/// The first version is always kept even if its manifest alone exceeds the budget: a
/// manifest is bounded (~1 MiB at `MAX_PART_COUNT`), and keeping it guarantees forward
/// progress for a client resuming after it.
///
/// Any truncation forces `next_cursor` to be rebuilt from the new last item (see
/// [`FileService::list_versions_with_manifests`]).
fn manifest_budget_cutoff(
    versions: &[FileVersion],
    manifests: &std::collections::HashMap<Uuid, String>,
    budget_bytes: u64,
) -> usize {
    let mut used_bytes: u64 = 0;
    for (i, v) in versions.iter().enumerate() {
        let Some(manifest) = manifests.get(&v.version_id) else {
            continue; // whole-sha256 (or no manifest found): no budget consumed
        };
        let size = manifest.len() as u64;
        if i > 0 && used_bytes.saturating_add(size) > budget_bytes {
            return i;
        }
        used_bytes = used_bytes.saturating_add(size);
    }
    versions.len()
}

#[cfg(test)]
#[path = "read_ops_tests.rs"]
mod read_ops_tests;
