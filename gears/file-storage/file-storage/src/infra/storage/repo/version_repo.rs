//! Repository for the `file_versions` table (immutable content versions).

use sea_orm::sea_query::{Expr, Query, SimpleExpr};
use sea_orm::{
    ColumnTrait, Condition, DbBackend, EntityTrait, ExprTrait, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureDeleteExt, SecureEntityExt, SecureUpdateExt, max_bind_params_for, secure_insert,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{FileVersion, VersionStatus};

use crate::domain::error::DomainError;
use crate::infra::storage::db::{db_err, file_not_found_on_foreign_key_violation};
use crate::infra::storage::entity::file_version::{ActiveModel, Column, Entity};
use crate::infra::storage::entity::multipart_upload::{
    Column as MultipartUploadColumn, Entity as MultipartUploadEntity,
};
use crate::infra::storage::entity::version_hash_manifest::{
    ActiveModel as ManifestActiveModel, Column as ManifestColumn, Entity as ManifestEntity,
};
use crate::infra::storage::mapper::file_version_from_model;

/// Repository over the `file_versions` table.
#[derive(Clone, Default)]
pub struct VersionRepo;

impl VersionRepo {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Pre-register a version row (typically `status = pending`).
    ///
    /// A foreign-key violation means the `files` row was deleted concurrently (see
    /// `FileRepo::lock_for_update`); it maps to `DomainError::FileNotFound`, not a 500.
    pub async fn insert<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        v: &FileVersion,
    ) -> Result<(), DomainError> {
        let am = ActiveModel {
            file_id: Set(v.file_id),
            version_id: Set(v.version_id),
            mime_type: Set(v.mime_type.clone()),
            size: Set(v.size),
            hash_algorithm: Set(v.hash_algorithm.clone()),
            hash_value: Set(v.hash_value.clone()),
            hash_mode: Set(v.hash_mode.clone()),
            part_count: Set(v.part_count),
            status: Set(v.status.as_str().to_owned()),
            is_current: Set(v.is_current),
            backend_id: Set(v.backend_id.clone()),
            backend_path: Set(v.backend_path.clone()),
            created_at: Set(v.created_at),
            bound_on_finalize: Set(v.bound_on_finalize),
            // A fresh version holds no migration lease (not part of the `FileVersion` model).
            migration_lease_owner: Set(None),
            migration_lease_until: Set(None),
        };
        secure_insert::<Entity>(am, scope, conn)
            .await
            .map_err(|e| file_not_found_on_foreign_key_violation(e, v.file_id))?;
        Ok(())
    }

    /// Fetch a single version by `(file_id, version_id)` with a direct two-column predicate,
    /// avoiding a scan of every version of the file on the `get`/`finalize`/`bind`/
    /// `download_url` hot path.
    pub async fn get<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<FileVersion>, DomainError> {
        let found = Entity::find()
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id)),
            )
            .secure()
            .scope_with(scope)
            .one(conn)
            .await
            .map_err(db_err)?;
        found.map(file_version_from_model).transpose()
    }

    /// List a page of a file's versions, newest first, offset-paginated, for internal callers
    /// (see [`UNBOUNDED_VERSIONS`]). The REST listing uses [`Self::list_by_file_page`].
    ///
    /// Ordered `(created_at, version_id)` descending; `version_id` is the tie-breaker so
    /// `OFFSET` pages are reproducible when versions share a `created_at`.
    pub async fn list_by_file<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<FileVersion>, DomainError> {
        let rows = Entity::find()
            .filter(Column::FileId.eq(file_id))
            .order_by_desc(Column::CreatedAt)
            .order_by_desc(Column::VersionId)
            .limit(limit)
            .offset(offset)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(file_version_from_model).collect()
    }

    /// List a page of a file's versions, newest first, keyset-paginated in either direction
    /// (backs `GET /files/{id}/versions`). Same canonical order as [`Self::list_by_file`];
    /// see `FileRepo::list_page` for the forward/backward predicates, mirrored on
    /// `version_id`. Callers fetch `limit + 1` rows to detect a further page.
    pub async fn list_by_file_page<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        limit: u64,
        after: Option<crate::domain::pagination::Seek>,
    ) -> Result<Vec<FileVersion>, DomainError> {
        use crate::domain::pagination::Direction;

        let mut filter = Condition::all().add(Column::FileId.eq(file_id));
        let direction = after.map_or(Direction::Forward, |s| s.direction);
        if let Some(seek) = after {
            let pred = match direction {
                Direction::Forward => super::tuple_lt(
                    (Entity, Column::CreatedAt),
                    (Entity, Column::VersionId),
                    seek.created_at,
                    seek.id,
                ),
                Direction::Backward => super::tuple_gt(
                    (Entity, Column::CreatedAt),
                    (Entity, Column::VersionId),
                    seek.created_at,
                    seek.id,
                ),
            };
            filter = filter.add(pred);
        }
        let mut query = Entity::find().filter(filter);
        query = match direction {
            Direction::Forward => query
                .order_by_desc(Column::CreatedAt)
                .order_by_desc(Column::VersionId),
            Direction::Backward => query
                .order_by_asc(Column::CreatedAt)
                .order_by_asc(Column::VersionId),
        };
        let rows = query
            .limit(limit)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(file_version_from_model).collect()
    }

    /// Record the content's size and hash and mark the version `available` (the sidecar calls
    /// this after durably writing the bytes).
    ///
    /// `hash_mode`/`part_count` (ADR-0006) are set here, not at insert time, since a pending
    /// row is created before it is known whether the upload is single-part or multipart.
    /// `hash_algorithm` is always `'SHA-256'` and never touched.
    #[allow(clippy::too_many_arguments)]
    pub async fn finalize<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
        hash_mode: &str,
        part_count: Option<i32>,
        mime_type: Option<String>,
    ) -> Result<bool, DomainError> {
        // Keyed on the full `(file_id, version_id)` so another file's version cannot be finalized.
        let mut update = Entity::update_many()
            .col_expr(Column::Size, Expr::value(size))
            .col_expr(Column::HashValue, Expr::value(hash_value))
            .col_expr(Column::HashMode, Expr::value(hash_mode))
            .col_expr(Column::PartCount, Expr::value(part_count))
            .col_expr(
                Column::Status,
                Expr::value(file_storage_sdk::VersionStatus::Available.as_str()),
            );
        // `mime_type` is rewritten only when given (single-part finalize); multipart
        // complete passes `None` and keeps the declared type.
        if let Some(mime_type) = mime_type {
            update = update.col_expr(Column::MimeType, Expr::value(mime_type));
        }
        let res = update
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id))
                    .add(Column::Status.eq(VersionStatus::Pending.as_str())),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected == 1)
    }

    /// Insert the `version_hash_manifest` row for a `multipart-composite-sha256` version, in
    /// the same transaction as [`Self::finalize`] so the manifest and the version row's
    /// `(hash_mode, part_count, hash_value = root)` commit atomically.
    pub async fn insert_manifest<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        version_id: Uuid,
        manifest: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        let am = ManifestActiveModel {
            version_id: Set(version_id),
            manifest: Set(manifest.to_owned()),
            created_at: Set(now),
        };
        secure_insert::<ManifestEntity>(am, scope, conn)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// Fetch the manifest text of a version, if any (`multipart-composite-sha256` only).
    pub async fn get_manifest<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        version_id: Uuid,
    ) -> Result<Option<String>, DomainError> {
        let found = ManifestEntity::find()
            .filter(ManifestColumn::VersionId.eq(version_id))
            .secure()
            .scope_with(scope)
            .one(conn)
            .await
            .map_err(db_err)?;
        Ok(found.map(|m| m.manifest))
    }

    /// Batched [`Self::get_manifest`]: manifest text for many versions in one `IN (...)`
    /// query, keyed by `version_id`; versions without a manifest are absent.
    ///
    /// `version_ids` is chunked to [`max_bind_params_for`] minus
    /// [`Self::GET_MANIFESTS_RESERVED_PARAMS`], one `SELECT` per chunk, so a large
    /// `max_page_size` cannot exceed the driver's bind-parameter limit.
    const GET_MANIFESTS_RESERVED_PARAMS: usize = 16;

    pub async fn get_manifests<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        version_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, String>, DomainError> {
        if version_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let chunk_size = max_bind_params_for(conn)
            .saturating_sub(Self::GET_MANIFESTS_RESERVED_PARAMS)
            .max(1);
        let mut manifests = std::collections::HashMap::new();
        for chunk in version_ids.chunks(chunk_size) {
            let rows = ManifestEntity::find()
                .filter(ManifestColumn::VersionId.is_in(chunk.iter().copied()))
                .secure()
                .scope_with(scope)
                .all(conn)
                .await
                .map_err(db_err)?;
            manifests.extend(rows.into_iter().map(|m| (m.version_id, m.manifest)));
        }
        Ok(manifests)
    }

    /// Clear `is_current` on all versions of a file (before promoting a new current one, to
    /// honour the unique-current index).
    ///
    /// Returns the rows cleared (0 or 1). `0` is **expected, not an error** (a brand-new
    /// file has no current version), unlike [`Self::set_current`], where `0` is fatal.
    pub async fn clear_current<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<u64, DomainError> {
        let res = Entity::update_many()
            .col_expr(Column::IsCurrent, Expr::value(false))
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::IsCurrent.eq(true)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }

    /// Promote one version to `is_current = true`.
    ///
    /// Returns the raw `rows_affected` (0 or 1, keyed on `(file_id, version_id)`).
    ///
    /// A current version cannot be deleted only **within the single transaction** doing the
    /// CAS-then-promote sequence ([`crate::infra::storage::repo::FileRepo::bind_content_cas`],
    /// then [`Self::clear_current`] + this method). A concurrent `delete_version` can still
    /// read this row as non-current, delete it (its `is_current = false` guard sees the same
    /// state) and commit before this `UPDATE` runs, so the predicate then matches zero rows.
    ///
    /// Callers MUST treat `0` as a fatal conflict and abort the transaction (e.g.
    /// `DomainError::conflict`), never commit past it: `files.content_id` would otherwise
    /// point at a deleted version with no error raised.
    pub async fn set_current<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<u64, DomainError> {
        let res = Entity::update_many()
            .col_expr(Column::IsCurrent, Expr::value(true))
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }

    /// Mark a version as having won its finalize-time bind CAS, in the same transaction as
    /// the CAS (right after [`Self::set_current`] confirms the promotion). The idempotent
    /// retry of `FileService::finalize_upload_by_token` replays this flag instead of
    /// re-deriving the outcome from a live `files.content_id`.
    ///
    /// Returns the raw `rows_affected` (0 or 1); `set_current` already matched the same row
    /// in the same transaction, so `0` cannot happen.
    pub async fn mark_bound_on_finalize<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<u64, DomainError> {
        let res = Entity::update_many()
            .col_expr(Column::BoundOnFinalize, Expr::value(true))
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }

    /// Delete a single version; returns the number of rows removed (0 or 1).
    ///
    /// Guarded with `is_current = false` in the same statement, so a concurrent `bind` that
    /// promoted this version cannot be raced into deleting the current content. The raw
    /// count lets [`crate::infra::storage::store::Store::delete_version`] tell "deleted"
    /// from "not found / guarded because current".
    pub async fn delete<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<u64, DomainError> {
        let res = Entity::delete_many()
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id))
                    .add(Column::IsCurrent.eq(false)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }

    /// Delete a version row iff its `status` matches `expected`; `false` if missing or already
    /// moved on. Lets the sweep avoid deleting a pending version that a racing
    /// `complete_multipart_upload` just made `available`.
    pub async fn delete_if_status<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
        expected: VersionStatus,
    ) -> Result<bool, DomainError> {
        let res = Entity::delete_many()
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id))
                    .add(Column::Status.eq(expected.as_str())),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// List `pending` versions created before `older_than`, excluding versions backing an
    /// active multipart session: a live `in_progress` one (`expires_at > now`), or any
    /// `completing` one. Used by the orphan-reconciliation sweep.
    ///
    /// A long multipart upload keeps its version `pending` for the whole session. An
    /// already-expired `in_progress` session is not excluded; the sweep aborts it first and
    /// the version becomes reclaimable on a later run. `completing` is excluded
    /// unconditionally (no `expires_at`/`lease_until` check): a completer may be assembling
    /// the object from this version; a stuck one is reaped by the expired-multipart CAS.
    ///
    /// Ordered `(created_at, version_id)` ascending, up to `limit`. `after` is a keyset
    /// cursor (`created_at > a OR (created_at = a AND version_id > b)`), local to one sweep
    /// run, so a candidate that keeps being returned does not block the rest.
    pub async fn list_pending_older_than<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        older_than: OffsetDateTime,
        now: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<FileVersion>, DomainError> {
        let mut filter = Condition::all()
            .add(Column::Status.eq(VersionStatus::Pending.as_str()))
            .add(Column::CreatedAt.lt(older_than))
            .add(
                Column::VersionId.not_in_subquery(
                    Query::select()
                        .column(MultipartUploadColumn::VersionId)
                        .from(MultipartUploadEntity)
                        .cond_where(
                            Condition::any()
                                .add(
                                    Condition::all()
                                        .add(MultipartUploadColumn::State.eq("in_progress"))
                                        .add(MultipartUploadColumn::ExpiresAt.gt(now)),
                                )
                                .add(MultipartUploadColumn::State.eq("completing")),
                        )
                        .to_owned(),
                ),
            );
        if let Some((after_created_at, after_version_id)) = after {
            filter = filter.add(super::tuple_gt(
                (Entity, Column::CreatedAt),
                (Entity, Column::VersionId),
                after_created_at,
                after_version_id,
            ));
        }
        let rows = Entity::find()
            .filter(filter)
            .order_by_asc(Column::CreatedAt)
            .order_by_asc(Column::VersionId)
            .limit(limit)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(file_version_from_model).collect()
    }

    /// Update `backend_id`/`backend_path`, CAS-gated on the current values **and** on `owner`
    /// still holding the migration lease (backend migration). `false` means the version is
    /// gone, another migration moved it, or the lease moved on from `owner`; the caller
    /// must re-fetch to tell which.
    ///
    /// A won CAS deliberately leaves the lease held until the caller's
    /// `release_migration_lease`, after `migrate_backend` has deleted the superseded source
    /// object. Otherwise a second migration could acquire the lease and land on the same
    /// deterministic destination path, and the delayed delete would remove its live object.
    ///
    /// A retried `migrate_backend` returns early on an already-migrated version, before
    /// reaching this CAS.
    #[allow(clippy::too_many_arguments)]
    pub async fn rebind_backend<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
        expected_backend_id: &str,
        expected_backend_path: &str,
        new_backend_id: &str,
        new_backend_path: &str,
        owner: Uuid,
    ) -> Result<bool, DomainError> {
        let res = Entity::update_many()
            .col_expr(Column::BackendId, Expr::value(new_backend_id))
            .col_expr(Column::BackendPath, Expr::value(new_backend_path))
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id))
                    .add(Column::BackendId.eq(expected_backend_id))
                    .add(Column::BackendPath.eq(expected_backend_path))
                    .add(Column::MigrationLeaseOwner.eq(owner)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Acquire (or take over, if expired) the migration lease on a version: one conditional
    /// `UPDATE` matching when no lease is held or the held one has expired. `false` means
    /// a live lease is held; `FileService::migrate_backend` surfaces that as `Conflict`.
    ///
    /// The lease is held through the source-object delete that follows the pointer swap;
    /// only `release_migration_lease` clears it.
    ///
    /// The expiry check and the new `migration_lease_until` are computed by the database
    /// (`now()` on Postgres, `datetime('now', ...)` on `SQLite`), never by this process's
    /// clock, so clock skew between instances cannot make a lease look expired early.
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire_migration_lease<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        backend: DbBackend,
        file_id: Uuid,
        version_id: Uuid,
        owner: Uuid,
        lease_secs: i64,
    ) -> Result<bool, DomainError> {
        let res = Entity::update_many()
            .col_expr(Column::MigrationLeaseOwner, Expr::value(owner))
            .col_expr(
                Column::MigrationLeaseUntil,
                migration_lease_until_expr(backend, lease_secs)?,
            )
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id))
                    .add(
                        Condition::any()
                            .add(Column::MigrationLeaseUntil.is_null())
                            .add(migration_lease_expired_filter(backend)?),
                    ),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Release a held migration lease, scoped to `owner` so a lease already taken over by
    /// another attempt is never clobbered. `false` (version gone, or lease moved on) is safe
    /// to ignore: `migrate_backend` calls this best-effort on every exit path and an
    /// unreleased lease simply expires.
    ///
    /// This is the only place that clears the lease after a successful migration.
    pub async fn release_migration_lease<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        version_id: Uuid,
        owner: Uuid,
    ) -> Result<bool, DomainError> {
        let res = Entity::update_many()
            .col_expr(
                Column::MigrationLeaseOwner,
                Expr::value(Option::<Uuid>::None),
            )
            .col_expr(
                Column::MigrationLeaseUntil,
                Expr::value(Option::<OffsetDateTime>::None),
            )
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id))
                    .add(Column::MigrationLeaseOwner.eq(owner)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Force-set a version's migration lease fields, bypassing the acquire/release CAS.
    /// **Test-support only; do not call in production.** `#[doc(hidden)]` rather than
    /// feature-gated because the external integration-test crate calls it.
    #[doc(hidden)]
    pub async fn set_migration_lease_for_test<C: DBRunner>(
        &self,
        conn: &C,
        file_id: Uuid,
        version_id: Uuid,
        owner: Option<Uuid>,
        until: Option<OffsetDateTime>,
    ) -> Result<(), DomainError> {
        Entity::update_many()
            .col_expr(Column::MigrationLeaseOwner, Expr::value(owner))
            .col_expr(Column::MigrationLeaseUntil, Expr::value(until))
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::VersionId.eq(version_id)),
            )
            .secure()
            .scope_with(&AccessScope::allow_all())
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}

/// SQL expression for "database-side `now() + secs` seconds", used to stamp
/// [`VersionRepo::acquire_migration_lease`]'s `migration_lease_until`.
///
/// # Errors
/// A backend other than Postgres/SQLite (unreachable in practice; startup refuses them).
fn migration_lease_until_expr(backend: DbBackend, secs: i64) -> Result<SimpleExpr, DomainError> {
    match backend {
        DbBackend::Postgres => Ok(Expr::cust(format!("now() + INTERVAL '{secs} seconds'"))),
        DbBackend::Sqlite => Ok(Expr::cust(format!("datetime('now', '+{secs} seconds')"))),
        other => Err(unsupported_migration_lease_backend(other)),
    }
}

/// SQL predicate for "`migration_lease_until` is database-side expired"
/// (`migration_lease_until < now()`). On `SQLite` both sides go through `datetime(...)` so
/// differently-formatted values compare in one canonical form.
fn migration_lease_expired_filter(backend: DbBackend) -> Result<SimpleExpr, DomainError> {
    match backend {
        DbBackend::Postgres => Ok(Expr::col(Column::MigrationLeaseUntil).lt(Expr::cust("now()"))),
        DbBackend::Sqlite => Ok(Expr::cust(
            "datetime(migration_lease_until) < datetime('now')",
        )),
        other => Err(unsupported_migration_lease_backend(other)),
    }
}

fn unsupported_migration_lease_backend(backend: DbBackend) -> DomainError {
    DomainError::database(format!(
        "file-storage supports Postgres and SQLite only, got {backend:?}"
    ))
}
