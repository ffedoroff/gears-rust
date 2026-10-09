//! Repository for the `files` table (logical file identity + content pointer).

use sea_orm::ExprTrait;
use sea_orm::sea_query::{Expr, LockType, Query};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect, Set};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureDeleteExt, SecureEntityExt, SecureUpdateExt, secure_insert,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::{File, OwnerFilter};

use crate::domain::error::DomainError;
use crate::infra::storage::db::db_err;
use crate::infra::storage::entity::file::{ActiveModel, Column, Entity, Model};
use crate::infra::storage::entity::file_version::{
    Column as VersionColumn, Entity as VersionEntity,
};
use crate::infra::storage::mapper::file_from_model;

/// Repository over the `files` table.
#[derive(Clone, Default)]
pub struct FileRepo;

impl FileRepo {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Insert a brand-new file row (no content bound yet).
    pub async fn create<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file: &File,
    ) -> Result<(), DomainError> {
        let am = ActiveModel {
            file_id: Set(file.file_id),
            tenant_id: Set(file.tenant_id),
            owner_kind: Set(file.owner_kind.as_str().to_owned()),
            owner_id: Set(file.owner_id),
            name: Set(file.name.clone()),
            gts_file_type: Set(file.gts_file_type.clone()),
            content_id: Set(file.content_id),
            meta_version: Set(file.meta_version),
            created_at: Set(file.created_at),
            last_modified_at: Set(file.last_modified_at),
        };
        secure_insert::<Entity>(am, scope, conn)
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// Fetch a file by id, tenant-scoped.
    pub async fn get<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<Option<File>, DomainError> {
        let found = Entity::find()
            .filter(Column::FileId.eq(file_id))
            .secure()
            .scope_with(scope)
            .one(conn)
            .await
            .map_err(db_err)?;
        found.map(file_from_model).transpose()
    }

    /// Lock a `files` row with `SELECT ... FOR UPDATE`, tenant-scoped.
    ///
    /// Call only with a transactional runner, as the first statement of the transaction.
    /// Concurrent inserts into FK children (`file_versions`, `multipart_uploads`) take
    /// `FOR KEY SHARE` on this row, which conflicts, so once this returns no such insert is in
    /// flight until commit/rollback. Returns the raw model for check-then-act callers. On
    /// `SQLite` the lock is a no-op; its single-writer model serializes writes instead.
    pub async fn lock_for_update<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<Option<Model>, DomainError> {
        Entity::find()
            .filter(Column::FileId.eq(file_id))
            .lock(LockType::Update)
            .secure()
            .scope_with(scope)
            .one(conn)
            .await
            .map_err(db_err)
    }

    /// Bind parameters reserved for the `WHERE` clause besides the `file_id IN (...)` list
    /// (what `scope_with` adds for the `AccessScope`); see
    /// `MetadataRepo::LIST_FOR_FILES_RESERVED_PARAMS`.
    const LIST_BY_IDS_RESERVED_PARAMS: usize = 16;

    /// Batched counterpart of [`Self::get`]: fetch every visible file in `ids`. A missing id
    /// simply has no entry in the result.
    ///
    /// `ids` is chunked to `max_bind_params_for` minus [`Self::LIST_BY_IDS_RESERVED_PARAMS`],
    /// one `SELECT` per chunk, so an unbounded id list cannot hit the driver's bind-parameter
    /// ceiling.
    pub async fn list_by_ids<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        ids: &[Uuid],
    ) -> Result<Vec<File>, DomainError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let chunk_size = toolkit_db::secure::max_bind_params_for(conn)
            .saturating_sub(Self::LIST_BY_IDS_RESERVED_PARAMS)
            .max(1);
        let mut files = Vec::with_capacity(ids.len());
        for chunk in ids.chunks(chunk_size) {
            let rows = Entity::find()
                .filter(Column::FileId.is_in(chunk.iter().copied()))
                .secure()
                .scope_with(scope)
                .all(conn)
                .await
                .map_err(db_err)?;
            for row in rows {
                files.push(file_from_model(row)?);
            }
        }
        Ok(files)
    }

    /// List files for a mandatory owner filter, newest first, keyset-paginated in either
    /// direction.
    ///
    /// Ordered `(created_at, file_id)` descending: `created_at` alone is not unique, so
    /// `file_id` (the primary key) is the tie-breaker that makes page boundaries deterministic.
    ///
    /// `after`, when `Some`, restricts the result to rows strictly past that position (`None`
    /// starts from the newest row). `Seek::direction` picks the predicate and query order:
    /// - `Forward`: `(created_at, file_id) < after`, canonical order, rows returned as-is.
    /// - `Backward`: mirrored predicate and ascending order, so `LIMIT` keeps the rows closest
    ///   to the cursor; `domain::pagination::finish_page` reverses them back.
    ///
    /// Callers fetch `limit + 1` rows to detect a further page; this method runs whatever
    /// `limit` it gets.
    pub async fn list_page<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        owner: OwnerFilter,
        limit: u64,
        after: Option<crate::domain::pagination::Seek>,
    ) -> Result<Vec<File>, DomainError> {
        use crate::domain::pagination::Direction;

        let mut filter = Condition::all()
            .add(Column::OwnerKind.eq(owner.owner_kind.as_str()))
            .add(Column::OwnerId.eq(owner.owner_id));
        let direction = after.map_or(Direction::Forward, |s| s.direction);
        if let Some(seek) = after {
            let pred = match direction {
                Direction::Forward => super::tuple_lt(
                    (Entity, Column::CreatedAt),
                    (Entity, Column::FileId),
                    seek.created_at,
                    seek.id,
                ),
                Direction::Backward => super::tuple_gt(
                    (Entity, Column::CreatedAt),
                    (Entity, Column::FileId),
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
                .order_by_desc(Column::FileId),
            Direction::Backward => query
                .order_by_asc(Column::CreatedAt)
                .order_by_asc(Column::FileId),
        };
        let rows = query
            .limit(limit)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(file_from_model).collect()
    }

    /// Compare-and-swap of the content pointer: sets `content_id` only if it equals
    /// `expected` (NULL for the first bind). Returns `false` on an `If-Match` conflict.
    pub async fn bind_content_cas<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        expected: Option<Uuid>,
        new_content: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let mut predicate = Condition::all().add(Column::FileId.eq(file_id));
        predicate = match expected {
            Some(v) => predicate.add(Column::ContentId.eq(v)),
            None => predicate.add(Column::ContentId.is_null()),
        };

        let res = Entity::update_many()
            .col_expr(Column::ContentId, Expr::value(new_content))
            .col_expr(Column::LastModifiedAt, Expr::value(now))
            .filter(predicate)
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Bump `meta_version` and `last_modified_at`, optionally guarded by
    /// `expected_meta_version` (`If-Match-Metadata`); `None` expected = unconditional.
    ///
    /// Returns the **committed** post-bump `meta_version`, or `None` if the guard matched no
    /// row. It is read back in the same transaction rather than derived as `expected + 1`,
    /// since a concurrent bump can make that wrong for an unconditional bump.
    pub async fn touch_meta<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        expected_meta_version: Option<i64>,
        now: OffsetDateTime,
    ) -> Result<Option<i64>, DomainError> {
        let mut predicate = Condition::all().add(Column::FileId.eq(file_id));
        if let Some(mv) = expected_meta_version {
            predicate = predicate.add(Column::MetaVersion.eq(mv));
        }

        let res = Entity::update_many()
            .col_expr(Column::MetaVersion, Expr::col(Column::MetaVersion).add(1))
            .col_expr(Column::LastModifiedAt, Expr::value(now))
            .filter(predicate)
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        if res.rows_affected == 0 {
            return Ok(None);
        }

        let row = Entity::find()
            .filter(Column::FileId.eq(file_id))
            .secure()
            .scope_with(scope)
            .one(conn)
            .await
            .map_err(db_err)?
            .ok_or_else(|| DomainError::database("file row missing after meta_version bump"))?;
        Ok(Some(row.meta_version))
    }

    /// Delete a file (FK cascade removes its versions and custom metadata).
    /// Returns `true` if a row was removed.
    pub async fn delete<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<bool, DomainError> {
        let res = Entity::delete_many()
            .filter(Column::FileId.eq(file_id))
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Delete a file row iff it is still a true orphan (`content_id IS NULL` and zero
    /// `file_versions` rows), as a single conditional `DELETE`.
    ///
    /// Under `READ COMMITTED` on `PostgreSQL` the `NOT EXISTS` subquery uses the statement's
    /// snapshot, and a concurrent `insert_pending_version` committing after it is not
    /// re-checked (the FK only locks the parent), so `ON DELETE CASCADE` could drop the new
    /// version. This is closed by every caller (`Store::delete_orphan_file_with_event`) taking
    /// `lock_for_update` on the row first and re-verifying "no versions"/"no active multipart
    /// session" under that lock; the `NOT EXISTS` guard is a second line of defense. `SQLite`'s
    /// single-writer model hides the race.
    ///
    /// Returns the rows removed (0 or 1); `0` means the file is gone, has content bound or has
    /// a version, without saying which.
    pub async fn delete_if_orphan<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<u64, DomainError> {
        // Negated `EXISTS (SELECT 1 FROM file_versions WHERE file_id = ?)`.
        let mut has_any_version = Query::select();
        has_any_version
            .expr(Expr::value(1))
            .from(VersionEntity)
            .and_where(VersionColumn::FileId.eq(file_id));
        let no_versions_exist = Condition::all().add(Expr::exists(has_any_version)).not();

        let res = Entity::delete_many()
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::ContentId.is_null())
                    .add(no_versions_exist),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected)
    }

    /// List `files` rows that never received any version (`content_id IS NULL` and zero
    /// `file_versions` rows) created before `created_before`, ordered by `(created_at, file_id)`
    /// ascending, up to `limit`. Feeds `CleanupEngine::sweep_versionless_files_page`.
    ///
    /// This is a plain `SELECT` that only finds candidates; each delete still goes through
    /// `delete_if_orphan` (via `Store::delete_orphan_file_with_event`), which re-verifies the
    /// condition inside its own transaction, so a version bound in between only makes the
    /// delete decline safely.
    /// `after`, when `Some((created_at, file_id))`, restricts the result to rows strictly past
    /// that key (keyset pagination, portable across `PostgreSQL` and `SQLite`); `None` starts
    /// from the oldest row. The caller resets it every cycle.
    pub async fn list_versionless_orphan_files<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        created_before: OffsetDateTime,
        limit: u64,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> Result<Vec<File>, DomainError> {
        let mut has_any_version = Query::select();
        has_any_version
            .expr(Expr::value(1))
            .from(VersionEntity)
            .and_where(Expr::col(VersionColumn::FileId).equals((Entity, Column::FileId)));
        let no_versions_exist = Condition::all().add(Expr::exists(has_any_version)).not();

        let mut filter = Condition::all()
            .add(Column::ContentId.is_null())
            .add(Column::CreatedAt.lt(created_before))
            .add(no_versions_exist);
        if let Some((after_created_at, after_file_id)) = after {
            filter = filter.add(super::tuple_gt(
                (Entity, Column::CreatedAt),
                (Entity, Column::FileId),
                after_created_at,
                after_file_id,
            ));
        }

        let rows = Entity::find()
            .filter(filter)
            .order_by_asc(Column::CreatedAt)
            .order_by_asc(Column::FileId)
            .limit(limit)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(file_from_model).collect()
    }

    /// List files across all tenants for the sweep, keyset-paginated by `file_id`:
    /// up to `limit` files strictly after `after`. Keyset (not offset) paging so
    /// deleting files mid-sweep does not shift the window and skip rows.
    pub async fn list_all_for_sweep<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        after: Option<Uuid>,
        limit: u64,
    ) -> Result<Vec<File>, DomainError> {
        let mut query = Entity::find();
        if let Some(after_id) = after {
            query = query.filter(Column::FileId.gt(after_id));
        }
        let rows = query
            .order_by_asc(Column::FileId)
            .limit(limit)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        rows.into_iter().map(file_from_model).collect()
    }

    /// Update `owner_kind`/`owner_id` and bump `last_modified_at`; `true` if a row matched.
    pub async fn update_owner<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        new_owner_kind: &str,
        new_owner_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        let res = Entity::update_many()
            .col_expr(Column::OwnerKind, Expr::value(new_owner_kind.to_owned()))
            .col_expr(Column::OwnerId, Expr::value(new_owner_id))
            .col_expr(Column::LastModifiedAt, Expr::value(now))
            .filter(Column::FileId.eq(file_id))
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }
}
