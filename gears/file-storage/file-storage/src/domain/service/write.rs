//! Write-path operations: finalize upload, bind (CAS), metadata update, and ownership transfer.

use std::collections::HashMap;

use time::OffsetDateTime;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use file_storage_sdk::{CustomMetadataEntry, CustomMetadataPatch, File};

use crate::domain::audit::{AuditEntry, AuditOperation};
use crate::domain::authz::actions;
use crate::domain::error::DomainError;
use crate::domain::etag;
use crate::domain::policy::PolicyResolver;
use crate::domain::ports::AutoBindOnFinalize;
use crate::domain::service::{FileService, FinalizeByTokenOutcome, VersionRef};
use crate::infra::backend::StorageBackend;
use crate::infra::content::mime::{
    MIME_SNIFF_PREFIX_BYTES, enforce_size_ceiling_for_validated_mime, validate_and_resolve_mime,
};
use crate::infra::external_clients::UsageDelta;
use crate::infra::signed_url::{Claims, Op, UploadConstraints};

/// Verify the object the sidecar reported as uploaded, without reading it back.
///
/// Finalize trust model: the callback is authenticated by the mandatory internal credential
/// and the sidecar measured the size and SHA-256 while streaming the PUT, so those are
/// trusted. This only checks the stored length via backend `stat` and reads the bounded
/// prefix (`MIME_SNIFF_PREFIX_BYTES`) needed to sniff the MIME type. A missing object is a
/// `validation("content")` error; other backend failures propagate unchanged.
///
/// Returns the MIME sniff prefix (empty for a zero-length object).
async fn check_uploaded_object(
    backend: &dyn StorageBackend,
    backend_path: &str,
    claimed_size: i64,
) -> Result<Vec<u8>, DomainError> {
    let no_content_err = || {
        DomainError::validation(
            "content",
            "no uploaded content found at the backend path; PUT was not completed",
        )
    };
    // `stat` (HEAD) distinguishes an absent object from a backend fault, which propagates.
    let actual_size = match backend.stat(backend_path).await? {
        Some(n) => i64::try_from(n).unwrap_or(i64::MAX),
        None => return Err(no_content_err()),
    };
    if actual_size != claimed_size {
        return Err(DomainError::validation(
            "size",
            "claimed size does not match the uploaded content",
        ));
    }
    if actual_size == 0 {
        return Ok(Vec::new());
    }
    let prefix_len = u64::try_from(MIME_SNIFF_PREFIX_BYTES).unwrap_or(u64::MAX);
    match backend.read_prefix(backend_path, prefix_len).await? {
        Some(prefix) => Ok(prefix.to_vec()),
        None => Err(no_content_err()),
    }
}

impl FileService {
    /// Authorize a write to `file_id` without mutating anything. The data plane calls this
    /// **before** writing bytes, so a rejected request never overwrites blob content
    /// (`finalize_upload` re-checks afterwards).
    pub async fn authorize_write(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
    ) -> Result<(), DomainError> {
        let file = self
            .store
            .require_file(&Self::tenant_scope(ctx), file_id)
            .await?;
        self.authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;
        Ok(())
    }

    /// Record an uploaded version's size and hash and mark it available (see
    /// `check_uploaded_object` for what is verified).
    #[tracing::instrument(skip_all)]
    pub async fn finalize_upload(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
    ) -> Result<(), DomainError> {
        if size < 0 {
            return Err(DomainError::validation("size", "must be non-negative"));
        }

        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let _scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        // Defense in depth: re-enforce the policy size ceiling (the signed URL already did).
        let version = self
            .store
            .get_version(file_id, version_id)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, version_id))?;
        let version_mime = version.mime_type.clone();
        let backend_id = version.backend_id.clone();
        let policy = self
            .get_effective_policy_internal(ctx.subject_tenant_id(), file.owner_id)
            .await?;
        let backend = if backend_id.is_empty() {
            self.backends.default_backend()
        } else {
            self.backends.get(&backend_id)?
        };
        let effective_max = PolicyResolver::compute_effective_max_bytes(
            &policy,
            &version_mime,
            backend.capabilities().max_size_bytes,
        );
        if let Some(limit) = effective_max
            && size > 0
            && size.cast_unsigned() > limit
        {
            return Err(DomainError::policy_size_exceeded(
                limit,
                "policy size limit",
            ));
        }

        let mime_sniff_prefix =
            check_uploaded_object(backend.as_ref(), &version.backend_path, size).await?;
        let actual_size = size;
        let actual_hash = hash_value;

        // The declared MIME is untrusted: the sniffed type wins when the bytes carry a
        // recognizable signature, a mismatch is rejected.
        let validated_mime = validate_and_resolve_mime(&version_mime, &mime_sniff_prefix)?;
        enforce_size_ceiling_for_validated_mime(
            &policy,
            &version_mime,
            &validated_mime,
            backend.capabilities().max_size_bytes,
            actual_size,
        )?;

        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::FinalizeVersion,
            serde_json::json!({ "version_id": version_id, "size": size }),
        );

        // `validated_mime` replaces the client's declaration.
        let ok = self
            .store
            .finalize_version(
                file_id,
                version_id,
                actual_size,
                actual_hash,
                // Single-part upload: whole-object SHA-256, no manifest.
                crate::infra::content::hash_mode::HashMode::WholeSha256,
                None,
                None,
                Some(validated_mime),
                audit,
                // No auto-bind on the user-facing finalize; binding stays an explicit `bind`.
                None,
            )
            .await?
            .updated;
        if !ok {
            // Already finalized (409) vs row gone (404), from the earlier `version` snapshot.
            return Err(
                if version.status == file_storage_sdk::VersionStatus::Available {
                    DomainError::conflict("version already finalized")
                } else {
                    DomainError::version_not_found(file_id, version_id)
                },
            );
        }

        // `create_file` already counted the file (bytes unknown then); credit the bytes here.
        self.report_usage(UsageDelta {
            tenant_id: file.tenant_id,
            owner_id: file.owner_id,
            bytes_delta: actual_size,
            file_count_delta: 0,
        });

        self.metrics.record_operation("finalize_upload", "ok");
        Ok(())
    }

    /// `POST /files/{id}/bind`: swap the content pointer to `version_id` under optimistic
    /// CAS guarded by the `If-Match` content ETag; `PreconditionFailed` on conflict.
    ///
    /// `if_match` is the opaque content ETag, `*`, or `None` for the first bind. The server
    /// recomputes the current ETag and compares; it never decodes an ETag.
    #[tracing::instrument(skip_all)]
    pub async fn bind(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
        if_match: Option<&str>,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let version = self
            .store
            .get_version(file_id, version_id)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, version_id))?;
        if version.status != file_storage_sdk::VersionStatus::Available {
            return Err(DomainError::conflict(
                "cannot bind a version whose upload has not been finalized",
            ));
        }

        let expected_content_id = file.content_id;
        let current_etag = expected_content_id.map(|c| etag::content_etag(file_id, c));
        match if_match {
            // Only the first bind may omit `If-Match`; a rebind without it would be an
            // unconditional overwrite.
            None => {
                if expected_content_id.is_some() {
                    return Err(DomainError::precondition_failed(
                        "If-Match is required to rebind already-bound content",
                    ));
                }
            }
            Some(m) => {
                let m = m.trim();
                if m != "*" && Some(m) != current_etag.as_deref() {
                    return Err(DomainError::precondition_failed(
                        "If-Match does not match the current content ETag",
                    ));
                }
            }
        }

        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::PatchContent,
            serde_json::json!({ "version_id": version_id }),
        );

        let event = Some(Self::make_file_event(
            file.tenant_id,
            file.owner_id,
            file_id,
            "file.content_updated",
            serde_json::json!({ "version_id": version_id }),
        ));

        // One transaction, so `files.content_id` and `file_versions.is_current` never diverge.
        let now = OffsetDateTime::now_utc();
        let swapped = self
            .store
            .bind_atomic_with_event(
                &scope,
                file_id,
                expected_content_id,
                version_id,
                now,
                audit,
                event,
            )
            .await?;
        if !swapped {
            return Err(DomainError::precondition_failed(
                "content pointer changed concurrently; re-read the ETag and rebind",
            ));
        }

        let bound = self.store.require_file(&scope, file_id).await?;
        self.metrics.record_operation("bind", "ok");
        Ok(bound)
    }

    /// Signed download URL for a version; `download_meta` is `(content_type, etag,
    /// content_sha256)`, with `content_sha256` empty unless the version is `whole-sha256`.
    pub(super) fn build_download_url(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        backend_id: String,
        backend_path: String,
        download_meta: Option<(String, String, String)>,
    ) -> Result<String, DomainError> {
        self.sign_url(
            Op::Get,
            &VersionRef {
                file_id,
                version_id,
                backend_id,
                backend_path,
            },
            UploadConstraints::default(),
            download_meta,
        )
    }

    /// `PATCH /files/{id}`: JSON-merge-patch the custom metadata and bump
    /// `meta_version`, optionally guarded by `If-Match-Metadata`. The audit row and
    /// `file.metadata_updated` event are enqueued in the same transaction.
    pub async fn update_metadata(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        patch: CustomMetadataPatch,
        expected_meta_version: Option<i64>,
    ) -> Result<File, DomainError> {
        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        // Validate the metadata as it will be after the patch.
        let policy = self
            .get_effective_policy_internal(ctx.subject_tenant_id(), file.owner_id)
            .await?;
        let existing = self.store.list_metadata(file_id).await?;
        let mut merged: HashMap<String, String> =
            existing.into_iter().map(|e| (e.key, e.value)).collect();
        for (key, value) in &patch.entries {
            match value {
                Some(v) => {
                    merged.insert(key.clone(), v.clone());
                }
                None => {
                    merged.remove(key);
                }
            }
        }
        let result_pairs: Vec<(String, String)> = merged.into_iter().collect();
        PolicyResolver::check_metadata_limits(&policy, &result_pairs)?;

        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::PatchMetadata,
            serde_json::json!({ "expected_meta_version": expected_meta_version }),
        );

        // The `meta_version` payload is stamped with the committed revision inside
        // `patch_metadata_atomic`'s transaction; an unconditional patch cannot know it here.
        let event = Some(Self::make_file_event(
            file.tenant_id,
            file.owner_id,
            file_id,
            "file.metadata_updated",
            serde_json::json!({}),
        ));

        // CAS and patch run in one transaction: a stale `expected_meta_version` aborts
        // first, and a failed insert rolls back the per-key delete-then-insert upsert.
        let now = OffsetDateTime::now_utc();
        let bumped = self
            .store
            .patch_metadata_atomic(
                &scope,
                file_id,
                expected_meta_version,
                patch,
                now,
                audit,
                event,
            )
            .await?;
        if !bumped {
            return Err(DomainError::precondition_failed(
                "metadata revision changed concurrently (If-Match-Metadata)",
            ));
        }
        self.store.require_file(&scope, file_id).await
    }

    /// `POST /files/{id}/transfer`: replace the file's owner kind and id, with audit and event
    /// in the same transaction. `tenant_id` comes from the stored file, never the request.
    /// A nil `new_owner_id` is rejected; its existence is not verified (the gear has no
    /// principal directory).
    pub async fn transfer_ownership(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        new_owner_kind: file_storage_sdk::OwnerKind,
        new_owner_id: Uuid,
    ) -> Result<(File, Vec<CustomMetadataEntry>), DomainError> {
        if new_owner_id.is_nil() {
            return Err(DomainError::validation(
                "new_owner_id",
                "must not be the nil UUID",
            ));
        }

        let prefetch = Self::tenant_scope(ctx);
        let file = self.store.require_file(&prefetch, file_id).await?;
        let scope = self
            .authorizer
            .authorize(ctx, actions::WRITE, &file.gts_file_type, Some(file_id))
            .await?;

        let now = OffsetDateTime::now_utc();
        let tenant_id = file.tenant_id;
        let old_owner_id = file.owner_id;
        let new_owner_kind_str = new_owner_kind.as_str().to_owned();

        let audit = Self::audit_ok(
            ctx,
            Some(file_id),
            AuditOperation::TransferOwnership,
            serde_json::json!({
                "from_owner_kind": file.owner_kind.as_str(),
                "from_owner_id": old_owner_id,
                "to_owner_kind": new_owner_kind_str,
                "to_owner_id": new_owner_id,
            }),
        );

        let event = Some(Self::make_file_event(
            tenant_id,
            new_owner_id,
            file_id,
            "file.owner_transferred",
            serde_json::json!({
                "from_owner_kind": file.owner_kind.as_str(),
                "from_owner_id": old_owner_id,
                "to_owner_kind": new_owner_kind_str,
                "to_owner_id": new_owner_id,
            }),
        ));

        let updated = self
            .store
            .transfer_ownership_atomic(
                &scope,
                file_id,
                &new_owner_kind_str,
                new_owner_id,
                now,
                audit,
                event,
            )
            .await?;

        if !updated {
            return Err(DomainError::file_not_found(file_id));
        }

        let total_bytes: i64 = self
            .store
            .list_versions(file_id)
            .await?
            .iter()
            .filter(|v| v.status == file_storage_sdk::VersionStatus::Available)
            .map(|v| v.size)
            .sum();
        self.report_usage(UsageDelta {
            tenant_id,
            owner_id: old_owner_id,
            bytes_delta: -total_bytes,
            file_count_delta: -1,
        });
        self.report_usage(UsageDelta {
            tenant_id,
            owner_id: new_owner_id,
            bytes_delta: total_bytes,
            file_count_delta: 1,
        });

        // Re-read under the tenant-only `prefetch` scope: the owner-constrained authz `scope`
        // no longer matches the row under its new owner (false 404), and the re-read also picks
        // up concurrent metadata writes. If the row vanished (concurrent DELETE) after the
        // commit, return `FileNotFound` rather than a stale snapshot.
        let meta = self.store.list_metadata(file_id).await?;
        let file = self.store.require_file(&prefetch, file_id).await?;
        Ok((file, meta))
    }

    /// Like `finalize_upload`, but authorized by the sidecar's signed upload token (minted at
    /// presign time) instead of a user `SecurityContext`.
    ///
    /// The caller has already verified `claims` (signature, expiry, `op == Put`, ids). The
    /// audit actor is `"sidecar"` with the nil UUID.
    #[tracing::instrument(skip_all)]
    /// Returns the bind outcome: `bind_state` is `Bound` only when the token carried
    /// `bind_on_finalize` and the `content_id IS NULL` CAS won (then `etag` is set). The sidecar
    /// echoes both as `X-FS-Bound`/`ETag` headers.
    ///
    /// Retries converge to the same success for both bind modes: a finalize for an
    /// already-`Available` version with matching size/hash replays the original decision (a won
    /// auto-bind via the persisted `bound_on_finalize`) instead of a 409.
    pub async fn finalize_upload_by_token(
        &self,
        claims: &Claims,
        size: i64,
        hash_value: Vec<u8>,
    ) -> Result<FinalizeByTokenOutcome, DomainError> {
        if size < 0 {
            return Err(DomainError::validation("size", "must be non-negative"));
        }

        let file_id = claims.file_id;
        let version_id = claims.version_id;

        // `allow_all`: the `(file_id, version_id)` pair was minted by the control plane.
        let file = self
            .store
            .require_file(&AccessScope::allow_all(), file_id)
            .await?;

        // Defense in depth: re-enforce the policy size ceiling (the signed URL already did).
        let version = self
            .store
            .get_version(file_id, version_id)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, version_id))?;

        // PUT-retry convergence: the sidecar retries a `PUT` whose response was lost,
        // `publish_exclusive` refuses the second write, and finalize arrives for an
        // already-available version. Converge to the original success (never a 409) only when
        // size and hash match; a mismatched replay is rejected. Applies to both bind modes.
        if version.status == file_storage_sdk::VersionStatus::Available {
            if version.size != size || version.hash_value != hash_value {
                return Err(DomainError::hash_mismatch(
                    hex::encode(&hash_value),
                    hex::encode(&version.hash_value),
                ));
            }
            // Replay the persisted bind decision (`version.bound_on_finalize`); re-deriving it
            // from the live `file.content_id` would disagree with the original response after
            // a legitimate rebind. `file.content_id` is still used for the `Conflict`/manual
            // branches.
            let (bind_state, etag, current_etag) =
                crate::domain::multipart::replay_finalize_bind_state(
                    file_id,
                    file.content_id,
                    version_id,
                    version.bound_on_finalize,
                    claims.bind_on_finalize,
                );
            return Ok(FinalizeByTokenOutcome {
                bind_state: Some(bind_state),
                etag,
                current_etag,
            });
        }

        let version_mime = version.mime_type.clone();
        let backend_id = version.backend_id.clone();
        let policy = self
            .get_effective_policy_internal(file.tenant_id, file.owner_id)
            .await?;
        let backend = if backend_id.is_empty() {
            self.backends.default_backend()
        } else {
            self.backends.get(&backend_id)?
        };
        let effective_max = PolicyResolver::compute_effective_max_bytes(
            &policy,
            &version_mime,
            backend.capabilities().max_size_bytes,
        );
        if let Some(limit) = effective_max
            && size > 0
            && size.cast_unsigned() > limit
        {
            return Err(DomainError::policy_size_exceeded(
                limit,
                "policy size limit",
            ));
        }

        let mime_sniff_prefix =
            check_uploaded_object(backend.as_ref(), &version.backend_path, size).await?;
        let actual_size = size;
        let actual_hash = hash_value;

        // The declared MIME is untrusted: the sniffed type wins when the bytes carry a
        // recognizable signature, a mismatch is rejected.
        let validated_mime = validate_and_resolve_mime(&version_mime, &mime_sniff_prefix)?;
        enforce_size_ceiling_for_validated_mime(
            &policy,
            &version_mime,
            &validated_mime,
            backend.capabilities().max_size_bytes,
            actual_size,
        )?;

        // Actor is "sidecar" with the nil UUID (no user identity in the callback).
        let audit = AuditEntry::success(
            file.tenant_id,
            "sidecar",
            Uuid::nil(),
            Some(file_id),
            AuditOperation::FinalizeVersion,
            serde_json::json!({ "version_id": version_id, "size": size }),
        );

        // A `bind_on_finalize` token also binds this version as the file's first content in
        // the same transaction, under a strict `content_id IS NULL` CAS (minted only by
        // `create_file` with `bind: "auto"`); it can never replace existing content.
        let auto_bind = claims.bind_on_finalize.then(|| AutoBindOnFinalize {
            expected_content_id: None,
            audit: AuditEntry::success(
                file.tenant_id,
                "sidecar",
                Uuid::nil(),
                Some(file_id),
                AuditOperation::PatchContent,
                serde_json::json!({ "version_id": version_id, "auto_bind": true }),
            ),
            event: Some(Self::make_file_event(
                file.tenant_id,
                file.owner_id,
                file_id,
                "file.content_updated",
                serde_json::json!({ "version_id": version_id, "auto_bind": true }),
            )),
        });
        let bind_attempted = auto_bind.is_some();

        // `validated_mime` replaces the client's declaration.
        let outcome = self
            .store
            .finalize_version(
                file_id,
                version_id,
                actual_size,
                actual_hash,
                // Single-part upload: whole-object SHA-256, no manifest.
                crate::infra::content::hash_mode::HashMode::WholeSha256,
                None,
                None,
                Some(validated_mime),
                audit,
                auto_bind,
            )
            .await?;
        if !outcome.updated {
            // Already finalized (409) vs row gone (404), from the earlier `version` snapshot.
            return Err(
                if version.status == file_storage_sdk::VersionStatus::Available {
                    DomainError::conflict("version already finalized")
                } else {
                    DomainError::version_not_found(file_id, version_id)
                },
            );
        }

        // Credit the bytes, as in `finalize_upload`.
        self.report_usage(UsageDelta {
            tenant_id: file.tenant_id,
            owner_id: file.owner_id,
            bytes_delta: actual_size,
            file_count_delta: 0,
        });

        self.metrics
            .record_operation("finalize_upload_by_token", "ok");
        if !bind_attempted {
            return Ok(FinalizeByTokenOutcome {
                bind_state: None,
                etag: None,
                current_etag: None,
            });
        }
        Ok(if outcome.bound {
            FinalizeByTokenOutcome {
                bind_state: Some(crate::domain::multipart::BindState::Bound),
                etag: Some(etag::content_etag(file_id, version_id)),
                current_etag: None,
            }
        } else {
            // Lost the `content_id IS NULL` CAS (the first finalize bound); report the winning
            // pointer so the client can resolve with a manual bind.
            let fresh = self
                .store
                .require_file(&AccessScope::allow_all(), file_id)
                .await?;
            FinalizeByTokenOutcome {
                bind_state: Some(crate::domain::multipart::BindState::Conflict),
                etag: None,
                current_etag: etag::etag_for(&fresh),
            }
        })
    }

    /// Delete a backend blob, logging (not failing) on error; a failure leaves an orphan
    /// for the cleanup engine.
    pub(super) async fn best_effort_blob_delete(&self, backend_id: &str, path: &str) {
        let Ok(backend) = self.backends.get(backend_id) else {
            return;
        };
        if let Err(err) = backend.delete(path).await {
            self.metrics.record_backend_error(backend_id, "delete");
            tracing::warn!(?err, path, "best-effort backend delete failed");
        }
    }
}
