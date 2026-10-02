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

// ── backend migration (P2-M4, upload-flow redesign lease) ──────────────────────

impl FileService {
    /// Relocate a non-versioned file's content from one backend to another
    /// without changing its identity (`file_id`, ownership, metadata, content
    /// hash).
    ///
    /// Because the destination path is deterministic
    /// (`storage_layout::backend_path`, `/{file_id}/{version_id}`), two
    /// migration attempts of the SAME version would otherwise race on the
    /// identical destination object. This is prevented by a per-version
    /// migration lease (`file_versions.migration_lease_owner`/
    /// `migration_lease_until`), acquired up front and held for the whole
    /// attempt:
    ///
    /// 1. Verify the file has exactly 1 version (non-versioned files only)
    ///    and that version is `available`.
    /// 2. Acquire the migration lease (`Store::acquire_migration_lease`,
    ///    sized `migrate_timeout_secs + migrate_lease_margin_secs`, timed by
    ///    the database's own clock). `false` -- a live lease already held by
    ///    another attempt -- surfaces as `Conflict` (409).
    /// 3. Under a `tokio::time::timeout(migrate_timeout_secs, ..)`: stream
    ///    the blob from the source backend into the destination, verifying
    ///    its content hash incrementally on the same pass
    ///    (`Self::stream_verify_and_publish_to_dest`, which also resolves a
    ///    destination tail from an interrupted earlier attempt -- see that
    ///    method's own doc); re-`stat` the destination immediately before
    ///    committing (cheap defense-in-depth against the object vanishing in
    ///    the narrow, structurally-unclosable window before the CAS -- see
    ///    issue #5013); then transactionally rebind `backend_id`/
    ///    `backend_path`, gated on both the pre-migration pointer snapshot
    ///    AND this call's own lease ownership. The lease is deliberately left
    ///    held on a won CAS -- see point 5 below and
    ///    `VersionRepo::rebind_backend`'s own doc for why -- and the
    ///    now-superseded source object is best-effort deleted immediately
    ///    after, still under that same lease.
    /// 4. A timeout best-effort deletes the destination object -- but ONLY
    ///    if this call is known to have created it AND its own CAS attempt
    ///    had not yet started (see `Self::migrate_backend_transfer_and_commit`'s
    ///    doc for why the second condition matters) -- and returns a
    ///    retryable `BackendUnavailable` (503 + `Retry-After`); the pointer
    ///    is never observed to change on a timeout.
    /// 5. The lease is released best-effort on every exit path (success,
    ///    error, or timeout), and only after that exit path's own attempt at
    ///    deleting the superseded source object has already run (on a won
    ///    CAS, that delete happens before `Self::migrate_backend_transfer_and_commit`
    ///    returns -- see point 3). Releasing any earlier would reopen exactly
    ///    the race this ordering exists to close: a second migration of the
    ///    SAME version could acquire the freed lease and move it back onto
    ///    the backend this call is still about to delete from (the
    ///    destination path is deterministic, so both migrations target the
    ///    identical path), and this call's delayed delete would then destroy
    ///    the second migration's live object instead of the stale one it was
    ///    meant to remove. A release that itself fails is not fatal: the
    ///    lease simply expires on its own.
    ///
    /// Returns `Ok(())` when the file already lives on the target backend
    /// (no-op), or after the migration completes successfully.
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

        // Only non-versioned files (exactly 1 version) may be migrated.
        let versions = self.store.list_versions(file_id).await?;
        if versions.len() != 1 {
            return Err(DomainError::versioned_file_migration_not_supported(file_id));
        }

        let version = &versions[0];

        // The version must be in the `available` state.
        if version.status != file_storage_sdk::VersionStatus::Available {
            return Err(DomainError::conflict(
                "cannot migrate a version whose upload has not been finalized",
            ));
        }

        // No-op if already on the target backend.
        if version.backend_id == target_backend_id {
            return Ok(());
        }

        let source = self.backends.get(&version.backend_id)?;
        let dest = self.backends.get(target_backend_id)?;

        // Migrating content onto a non-durable backend (e.g. a dev/test
        // `memory` backend) risks silent data loss on the next restart. An
        // ordinary WRITE-authorized caller may not do this implicitly — it
        // requires the elevated admin-policy scope.
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

        // Acquire the migration lease before ANY write to the destination
        // backend -- see this method's own doc for why, and
        // `VersionRepo::acquire_migration_lease` for why its expiry is
        // computed by the database itself rather than this instance's clock.
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

        // Shared with the timed-out branch below: whether this call's own
        // publish actually landed fresh bytes at `dest_path`, and whether
        // its own CAS attempt had already started -- see
        // `Self::migrate_backend_transfer_and_commit`'s doc for why both
        // matter to the timeout's best-effort cleanup decision. Plain
        // `AtomicBool`s (not a mutex): each is only ever written once, by
        // the single task driving the timed future, and read only after
        // that future has stopped running (either it finished, in which
        // case its result is used directly instead, or `timeout` gave up on
        // it) -- ordering the reads with `Relaxed` is fine, there is no
        // concurrent writer to synchronize against.
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

        // Best-effort release on every exit path -- see this method's own
        // doc, point 5. Errors are deliberately logged, not surfaced: a
        // lease this call no longer legitimately holds (already lost to a
        // takeover) is correctly left alone by `release_migration_lease`'s
        // own owner fencing (that isn't a real failure, just `Ok(false)`),
        // and any actual error here just means the lease expires on its own
        // instead of being freed early.
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
                // Only delete an object this call is known to have created,
                // and only if its own CAS attempt never started -- once the
                // CAS is in flight, this call can no longer tell whether it
                // silently committed before the timeout raced it (see the
                // module doc's "Known gap" section), and deleting the
                // object in that case could destroy a pointer this same
                // call just made live.
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

    /// The timed body of `migrate_backend`: transfer + verify, the pre-CAS
    /// `stat`, and the CAS itself (plus its lost-CAS recovery). Split out
    /// purely so `migrate_backend` can wrap it in one
    /// `tokio::time::timeout` call without the whole function living inside
    /// an inline `async move` block.
    ///
    /// `cas_started` is stamped `true` immediately before the CAS call --
    /// after that point, a cancellation from the enclosing timeout can no
    /// longer distinguish "the CAS never ran" from "the CAS's own `await`
    /// was cancelled after the database had already applied it" (an
    /// inherent limitation of racing a future against a timer, not
    /// something this gear's cancellation handling can close). Not
    /// attempting a cleanup in that ambiguous case is the safe choice: at
    /// worst a destination object this call created is left behind after a
    /// timeout despite the CAS never actually landing, which is exactly the
    /// tail scenario `Self::stream_verify_and_publish_to_dest` already
    /// reclaims on this version's next migration attempt -- as opposed to
    /// the alternative of deleting an object a just-committed CAS made
    /// live.
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

        // Immediately before committing the CAS below, re-confirm the object
        // this call is about to make live is actually still there and still
        // the size this version declares. This narrows -- it cannot fully
        // close -- the window between "verified" and "CAS": nothing
        // coordinates a delete that lands in between this `stat` and the CAS
        // call right below it either (issue #5013, an external actor or
        // direct backend surgery, not another migration attempt of this
        // version -- the lease already rules those out).
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

        // Transactionally update the version row and emit the audit row. The
        // CAS predicate is the pre-migration snapshot captured above (before
        // the source read / destination write) AND this call's own lease
        // ownership -- see `VersionRepo::rebind_backend`'s own doc for the
        // three distinct ways this can now lose.
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
            // The CAS lost: the version is gone, a concurrent migration
            // already moved the pointer away from the snapshot we started
            // from, or (structurally no longer reachable via a genuine
            // second `migrate_backend` call, since the lease excludes that)
            // this call's own lease was somehow taken over before the CAS
            // ran. Re-fetch to tell these apart — the destination blob we
            // just wrote may or may not be safe to clean up depending on
            // which case this is.
            let current = self.store.get_version(file_id, version.version_id).await?;
            return match current {
                None => {
                    // Version gone: the blob we wrote is genuinely orphaned.
                    self.best_effort_blob_delete(dest.id(), dest_path).await;
                    Err(DomainError::version_not_found(file_id, version.version_id))
                }
                Some(now)
                    if now.backend_id == target_backend_id && now.backend_path == dest_path =>
                {
                    // A concurrent migration to the SAME target already
                    // committed this exact pointer as the live one (dest_path
                    // is deterministic, so racers to the same backend collide
                    // on the same path). Treat as a successful no-op and, above
                    // all, do NOT delete the destination blob -- it is the
                    // winner's live content, not ours to clean up.
                    Ok(())
                }
                Some(now) => {
                    // A different concurrent migration won. Our destination
                    // write is not the live pointer, so it is safe to clean up
                    // -- guarded by the belt-and-suspenders check below in
                    // case the live pointer ever coincides with it for some
                    // other reason.
                    if !(now.backend_id == dest.id() && now.backend_path == dest_path) {
                        self.best_effort_blob_delete(dest.id(), dest_path).await;
                    }
                    Err(DomainError::conflict(
                        "concurrent backend migration in progress",
                    ))
                }
            };
        }

        // Best-effort delete the source blob.
        self.best_effort_blob_delete(source.id(), &version.backend_path)
            .await;

        Ok(())
    }

    /// The streaming transfer + verification half of `migrate_backend`:
    /// resolves `version`'s mode-aware hash spec (`hash_mode` and, for
    /// `multipart-composite-sha256`, its stored manifest), streams its bytes
    /// from `source` straight into `dest` at `dest_path` (create-exclusive —
    /// see [Concurrent-Migration Lease
    /// Resolution](../../../docs/features/backend-migration.md) for why),
    /// verifying incrementally on the same pass, and returns `Ok(())` only
    /// once fresh bytes are confirmed correct and in place at `dest_path`.
    ///
    /// - If this call's own write's source-stream verification fails (or the
    ///   source stream breaks mid-read), the destination object is
    ///   best-effort deleted only if this call actually created it
    ///   (`created: false` means something else already had bytes there
    ///   before this call, which this verification says nothing about).
    /// - If `publish_exclusive` reported `created: false` (the destination
    ///   already held bytes), this call already holds the migration lease on
    ///   this exact version, so nothing else can be a *legitimate* concurrent
    ///   writer to this exact deterministic path right now. That collapses
    ///   the question to one the version's own pointer already answers:
    ///   - the pointer is STILL on the pre-migration source snapshot this
    ///     call started from → the object cannot be anyone's live content;
    ///     it is a tail an earlier attempt at this same path left behind
    ///     (wrote successfully, then crashed, was cancelled, or timed out
    ///     before it ever reached its own CAS). Delete it and retry the
    ///     publish exactly once.
    ///   - the pointer has moved elsewhere → a concurrent migration (to this
    ///     same target or a different one) already claimed this path as live
    ///     content. Leave it untouched and fail with `Conflict` — never read
    ///     or hash-check it; the lease is what makes that check unnecessary,
    ///     not something this call still has to independently re-derive.
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

        // At most two attempts: the fresh write, and -- iff the first
        // attempt's `created: false` turns out to be a tail from an earlier
        // interrupted attempt at this same path -- one retry after clearing
        // it.
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
                // Already retried once after clearing a confirmed tail; a
                // second `created: false` means something keeps winning this
                // exact path even under our own held lease -- stay
                // conservative (`Conflict`, no further retry) rather than
                // looping.
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
            // Tail from an earlier interrupted attempt at this exact
            // deterministic path -- safe to delete under this call's own
            // held lease.
            self.best_effort_blob_delete(dest.id(), dest_path).await;
            cleared_tail = true;
        }
    }

    // ── backends discovery ────────────────────────────────────────────────────

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
