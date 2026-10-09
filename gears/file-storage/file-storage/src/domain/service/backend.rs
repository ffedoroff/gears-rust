//! Backend migration and backend discovery.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use toolkit_security::SecurityContext;
use uuid::Uuid;

use crate::domain::audit::AuditOperation;
use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::service::FileService;
use crate::domain::storage_layout;
use crate::infra::backend::{BackendCapabilities, StorageBackend};
use crate::infra::content::hash_mode::{HashMode, Manifest};
use crate::infra::content::stream_verify;

impl FileService {
    /// Relocate a non-versioned file's content to another backend without changing its
    /// identity (`file_id`, ownership, metadata, content hash).
    ///
    /// The destination path is deterministic (`/{file_id}/{version_id}`), so a per-version
    /// migration lease (`file_versions.migration_lease_owner`/`migration_lease_until`,
    /// timed by the database clock) is held for the whole attempt. A live lease held by
    /// another attempt surfaces as `Conflict` (409).
    ///
    /// 1. Require exactly 1 version, `available`, and acquire the lease.
    /// 2. Under `tokio::time::timeout(migrate_timeout_secs, ..)`: stream the blob to the
    ///    destination verifying its hash on the same pass
    ///    (`Self::stream_verify_and_publish_to_dest`), re-`stat` the destination, then
    ///    transactionally rebind `backend_id`/`backend_path`, gated on the pre-migration
    ///    pointer snapshot and this call's lease. The lease stays held on a won CAS and the
    ///    superseded source object is best-effort deleted.
    /// 3. A timeout best-effort deletes the destination object, but only if this call created
    ///    it and its CAS had not started (see `Self::migrate_backend_transfer_and_commit`),
    ///    and returns a retryable `BackendUnavailable` (503 + `Retry-After`); the pointer is
    ///    never observed to change on a timeout.
    /// 4. The lease is released best-effort on every exit path, only after the source delete
    ///    has run: releasing earlier would let a second migration of the same version move it
    ///    back and then have this call's delayed delete destroy that live object. A failed
    ///    release is not fatal; the lease expires on its own.
    ///
    /// Returns `Ok(())` when the file already lives on the target backend (no-op), or after
    /// the migration completes.
    pub async fn migrate_backend(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        target_backend_id: &str,
    ) -> Result<(), DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let versions = self.store.list_versions(file_id).await?;
        if versions.len() != 1 {
            return Err(DomainError::versioned_file_migration_not_supported(file_id));
        }

        let version = &versions[0];

        if version.status != file_storage_sdk::VersionStatus::Available {
            return Err(DomainError::conflict(
                "cannot migrate a version whose upload has not been finalized",
            ));
        }

        if version.backend_id == target_backend_id {
            return Ok(());
        }

        let source = self.backends.get(&version.backend_id)?;
        let dest = self.backends.get(target_backend_id)?;

        // Moving content onto a non-durable backend risks data loss on restart, so it
        // requires the elevated admin-policy scope, not just WRITE.
        if !dest.capabilities().durable {
            self.authorizer
                .authorize(
                    ctx,
                    actions::ADMIN_POLICY,
                    &file.gts_file_type,
                    Some(file_id),
                )
                .await?;
        }

        // Acquire the migration lease before ANY write to the destination backend (expiry is
        // computed by the database, see `VersionRepo::acquire_migration_lease`).
        let owner = Uuid::now_v7();
        let lease_secs = self
            .migrate_timeout_secs
            .saturating_add(self.migrate_lease_margin_secs);
        let acquired = self
            .store
            .acquire_migration_lease(
                file_id,
                version.version_id,
                owner,
                Duration::from_secs(lease_secs),
            )
            .await?;
        if !acquired {
            return Err(DomainError::conflict(
                "a migration of this version is already in progress",
            ));
        }

        let expected_len = u64::try_from(version.size).unwrap_or(0);
        let dest_path = storage_layout::backend_path(file_id, version.version_id);

        // Shared with the timed-out branch below: whether our publish landed fresh bytes
        // and whether our CAS had started. Plain `AtomicBool`s: each is written once by the
        // task driving the timed future and read only after it stopped, so `Relaxed` suffices.
        let created_by_us = Arc::new(AtomicBool::new(false));
        let cas_started = Arc::new(AtomicBool::new(false));

        let timeout_secs = self.migrate_timeout_secs.max(1);
        let result = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            self.migrate_backend_transfer_and_commit(
                ctx,
                file_id,
                version,
                source.as_ref(),
                dest.as_ref(),
                target_backend_id,
                &dest_path,
                expected_len,
                owner,
                &created_by_us,
                &cas_started,
            ),
        )
        .await;

        // Best-effort release on every exit path (see the method doc, point 5). Errors are
        // only logged: a lease already lost to a takeover is left alone by owner fencing,
        // and otherwise the lease just expires on its own.
        if let Err(err) = self
            .store
            .release_migration_lease(file_id, version.version_id, owner)
            .await
        {
            tracing::warn!(?err, "best-effort migration-lease release failed");
        }

        match result {
            Ok(inner) => inner,
            Err(_elapsed) => {
                // Delete only an object this call created and whose CAS never started: once
                // the CAS is in flight it may have committed, and deleting would destroy a
                // live pointer (see the module doc's "Known gap").
                if created_by_us.load(Ordering::Relaxed) && !cas_started.load(Ordering::Relaxed) {
                    self.best_effort_blob_delete(dest.id(), &dest_path).await;
                }
                Err(DomainError::backend_unavailable(
                    dest.id(),
                    format!("backend migration timed out after {timeout_secs}s"),
                ))
            }
        }
    }

    /// The timed body of `migrate_backend`: transfer + verify, the pre-CAS `stat`, and the
    /// CAS itself (plus its lost-CAS recovery), split out so the caller wraps it in one
    /// `tokio::time::timeout`.
    ///
    /// `cas_started` is set immediately before the CAS: once it is in flight, a timeout
    /// cannot tell "never ran" from "applied but cancelled", so no cleanup is attempted.
    /// At worst an unreferenced destination object remains; it is reclaimed by
    /// `Self::stream_verify_and_publish_to_dest` on the next attempt.
    #[allow(clippy::too_many_arguments)]
    async fn migrate_backend_transfer_and_commit(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version: &file_storage_sdk::FileVersion,
        source: &dyn StorageBackend,
        dest: &dyn StorageBackend,
        target_backend_id: &str,
        dest_path: &str,
        expected_len: u64,
        owner: Uuid,
        created_by_us: &AtomicBool,
        cas_started: &AtomicBool,
    ) -> Result<(), DomainError> {
        self.stream_verify_and_publish_to_dest(
            source,
            dest,
            version,
            dest_path,
            expected_len,
            created_by_us,
        )
        .await?;

        // Re-confirm just before the CAS that the object is still there with the declared
        // size. This narrows, but cannot close, the window against an external delete
        // (issue #5013); another migration of this version is already excluded by the lease.
        match dest.stat(dest_path).await? {
            Some(actual_len) if actual_len == expected_len => {}
            Some(actual_len) => {
                return Err(DomainError::backend_unavailable(
                    dest.id(),
                    format!(
                        "destination object size changed before commit: expected \
                         {expected_len} byte(s), found {actual_len}"
                    ),
                ));
            }
            None => {
                return Err(DomainError::backend_unavailable(
                    dest.id(),
                    "destination object disappeared before commit",
                ));
            }
        }

        // Transactionally rebind the version and emit the audit row. The CAS predicate is
        // the pre-migration snapshot AND this call's lease ownership (see
        // `VersionRepo::rebind_backend`).
        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::BackendMigrate,
            serde_json::json!({
                "from_backend": version.backend_id,
                "to_backend": target_backend_id,
                "version_id": version.version_id,
            }),
        );
        cas_started.store(true, Ordering::Relaxed);
        let updated = self
            .store
            .rebind_version_backend(
                file_id,
                version.version_id,
                &version.backend_id,
                &version.backend_path,
                target_backend_id,
                dest_path,
                owner,
                audit,
            )
            .await?;
        if !updated {
            // The CAS lost: the version is gone, a concurrent migration moved the pointer, or
            // our lease was taken over. Re-fetch to tell which; it decides whether the
            // destination blob is safe to clean up.
            let current = self.store.get_version(file_id, version.version_id).await?;
            return match current {
                None => {
                    // Version gone: the blob we wrote is orphaned.
                    self.best_effort_blob_delete(dest.id(), dest_path).await;
                    Err(DomainError::version_not_found(file_id, version.version_id))
                }
                Some(now)
                    if now.backend_id == target_backend_id && now.backend_path == dest_path =>
                {
                    // A concurrent migration to the SAME target already committed this
                    // pointer (`dest_path` is deterministic). Successful no-op; do NOT delete
                    // the destination blob, it is the winner's live content.
                    Ok(())
                }
                Some(now) => {
                    // A different concurrent migration won; our destination write is not the
                    // live pointer, so cleanup is safe (guarded again below).
                    if !(now.backend_id == dest.id() && now.backend_path == dest_path) {
                        self.best_effort_blob_delete(dest.id(), dest_path).await;
                    }
                    Err(DomainError::conflict(
                        "concurrent backend migration in progress",
                    ))
                }
            };
        }

        // Best-effort delete of the superseded source blob.
        self.best_effort_blob_delete(source.id(), &version.backend_path)
            .await;

        Ok(())
    }

    /// The streaming transfer + verification half of `migrate_backend`: streams `version`'s
    /// bytes from `source` into `dest` at `dest_path` (create-exclusive), verifying its mode-aware
    /// hash incrementally, and returns `Ok(())` once fresh, verified bytes are in place.
    ///
    /// - If verification fails or the source stream breaks, the destination object is
    ///   best-effort deleted only if this call created it (`created: false` means another
    ///   write put the bytes there).
    /// - If `publish_exclusive` reported `created: false`, the held migration lease rules out a
    ///   legitimate concurrent writer, so the version's own pointer decides:
    ///   - pointer still on the pre-migration source: the object is a tail left by an
    ///     earlier interrupted attempt; delete it and retry the publish exactly once.
    ///   - pointer moved: a concurrent migration claimed the path as live content; leave it
    ///     untouched and fail with `Conflict`, without reading or hashing it.
    async fn stream_verify_and_publish_to_dest(
        &self,
        source: &dyn StorageBackend,
        dest: &dyn StorageBackend,
        version: &file_storage_sdk::FileVersion,
        dest_path: &str,
        expected_len: u64,
        created_by_us: &AtomicBool,
    ) -> Result<(), DomainError> {
        let hash_mode = HashMode::parse(&version.hash_mode).ok_or_else(|| {
            DomainError::database(format!(
                "version {} has an unrecognized hash_mode {:?}",
                version.version_id, version.hash_mode
            ))
        })?;
        let manifest = match hash_mode {
            HashMode::WholeSha256 => None,
            HashMode::MultipartCompositeSha256 => {
                let raw = self
                    .store
                    .get_version_manifest(version.version_id)
                    .await?
                    .ok_or_else(|| {
                        DomainError::database(format!(
                            "multipart-composite version {} is missing its version_hash_manifest row",
                            version.version_id
                        ))
                    })?;
                Some(Manifest::from_wire_string(&raw)?)
            }
        };

        // At most two attempts: the fresh write, and one retry after clearing a stale tail
        // left by an earlier interrupted attempt.
        let mut cleared_tail = false;
        loop {
            let source_stream = source
                .get_stream(&version.backend_path, expected_len)
                .await?;
            let (verified_stream, verify_slot) = stream_verify::verify_stream(
                source_stream,
                expected_len,
                hash_mode,
                version.hash_value.clone(),
                manifest.clone(),
            )?;

            let outcome = dest
                .publish_exclusive(dest_path, verified_stream, Some(expected_len))
                .await?;

            let verify_result = verify_slot
                .lock()
                .map_err(|_| {
                    DomainError::backend(dest.id(), "poisoned content-verification lock")
                })?
                .take()
                .unwrap_or_else(|| {
                    Err(DomainError::backend(
                        dest.id(),
                        "destination write completed without fully draining the verified source stream",
                    ))
                });
            if let Err(verify_err) = verify_result {
                if outcome.created {
                    self.best_effort_blob_delete(dest.id(), dest_path).await;
                }
                return Err(verify_err);
            }

            if outcome.created {
                created_by_us.store(true, Ordering::Relaxed);
                return Ok(());
            }

            if cleared_tail {
                // Already retried once after clearing a tail; a second `created: false` means
                // something keeps winning this path even under our lease: `Conflict`, no retry.
                return Err(DomainError::conflict(
                    "destination path is contended by another writer",
                ));
            }

            let current = self
                .store
                .get_version(version.file_id, version.version_id)
                .await?;
            let still_on_source = matches!(
                &current,
                Some(v) if v.backend_id == version.backend_id && v.backend_path == version.backend_path
            );
            if !still_on_source {
                return Err(DomainError::conflict(
                    "destination path already holds a concurrently-committed migration's content",
                ));
            }
            // Tail from an earlier interrupted attempt; safe to delete under our held lease.
            self.best_effort_blob_delete(dest.id(), dest_path).await;
            cleared_tail = true;
        }
    }

    /// `GET /storages`: configured backends and their capabilities.
    #[must_use]
    pub fn list_backends(&self) -> Vec<(String, BackendCapabilities)> {
        self.backends.list()
    }

    /// `GET /storages/{id}`.
    pub fn get_backend(&self, id: &str) -> Result<(String, BackendCapabilities), DomainError> {
        let b = self.backends.get(id)?;
        Ok((b.id().to_owned(), b.capabilities()))
    }
}
