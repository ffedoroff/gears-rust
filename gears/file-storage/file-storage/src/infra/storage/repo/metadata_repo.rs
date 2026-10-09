//! Repository for the `files_custom_metadata` table (user key/value pairs).

use std::collections::HashMap;

use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, Set};
use time::OffsetDateTime;
use toolkit_db::secure::{
    DBRunner, SecureDeleteExt, SecureEntityExt, max_bind_params_for, secure_insert_many,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage_sdk::CustomMetadataEntry;

use crate::domain::error::DomainError;
use crate::infra::storage::db::db_err;
use crate::infra::storage::entity::custom_metadata::{ActiveModel, Column, Entity};

/// Repository over the `files_custom_metadata` table.
#[derive(Clone, Default)]
pub struct MetadataRepo;

impl MetadataRepo {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// List all custom-metadata entries of a file, ordered by key.
    pub async fn list<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<Vec<CustomMetadataEntry>, DomainError> {
        let rows = Entity::find()
            .filter(Column::FileId.eq(file_id))
            .order_by_asc(Column::Key)
            .secure()
            .scope_with(scope)
            .all(conn)
            .await
            .map_err(db_err)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Bind parameters reserved from `max_bind_params_for` for the `WHERE` clause besides the
    /// `file_id IN (...)` list (the caller's `AccessScope` predicates).
    const LIST_FOR_FILES_RESERVED_PARAMS: usize = 16;

    /// Batched `list`: custom-metadata entries for many files, grouped by `file_id`
    /// (see `Store::list_metadata_for_files`). A file without metadata has no map entry.
    ///
    /// `file_ids` is chunked to `max_bind_params_for` minus the reserved params, one
    /// `SELECT` per chunk, so a large page size cannot exceed the driver's bind-parameter limit.
    pub async fn list_for_files<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<CustomMetadataEntry>>, DomainError> {
        if file_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let chunk_size = max_bind_params_for(conn)
            .saturating_sub(Self::LIST_FOR_FILES_RESERVED_PARAMS)
            .max(1);
        let mut grouped: HashMap<Uuid, Vec<CustomMetadataEntry>> = HashMap::new();
        for chunk in file_ids.chunks(chunk_size) {
            let rows = Entity::find()
                .filter(Column::FileId.is_in(chunk.iter().copied()))
                .order_by_asc(Column::Key)
                .secure()
                .scope_with(scope)
                .all(conn)
                .await
                .map_err(db_err)?;
            for row in rows {
                grouped
                    .entry(row.file_id)
                    .or_default()
                    .push(CustomMetadataEntry {
                        key: row.key,
                        value: row.value,
                    });
            }
        }
        Ok(grouped)
    }

    /// Delete one key. Returns `true` if a row was removed.
    pub async fn delete_key<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        key: &str,
    ) -> Result<bool, DomainError> {
        let res = Entity::delete_many()
            .filter(
                Condition::all()
                    .add(Column::FileId.eq(file_id))
                    .add(Column::Key.eq(key)),
            )
            .secure()
            .scope_with(scope)
            .exec(conn)
            .await
            .map_err(db_err)?;
        Ok(res.rows_affected > 0)
    }

    /// Bind parameters reserved from `max_bind_params_for` for the `WHERE` clause besides the
    /// `key IN (...)` list (the `file_id` predicate and the `AccessScope` predicates).
    /// Headroom, not an exact count: a slightly smaller chunk is harmless, an overshoot is a 500.
    const DELETE_KEYS_RESERVED_PARAMS: usize = 16;

    /// Batched `delete_key`: deletes every row in `keys` for `file_id` and returns the number
    /// removed; no statements for an empty slice.
    ///
    /// `keys` is chunked to `max_bind_params_for` minus the reserved params, one `DELETE` per
    /// chunk, because `metadata_limits.max_pairs` may be unlimited. Safe to split only because
    /// the sole caller (`Store::patch_metadata_atomic`) runs it in a transaction; any other
    /// caller must wrap it in one.
    pub async fn delete_keys<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        keys: &[String],
    ) -> Result<u64, DomainError> {
        if keys.is_empty() {
            return Ok(0);
        }
        let chunk_size = max_bind_params_for(conn)
            .saturating_sub(Self::DELETE_KEYS_RESERVED_PARAMS)
            .max(1);
        let mut total_rows_affected: u64 = 0;
        for chunk in keys.chunks(chunk_size) {
            let res = Entity::delete_many()
                .filter(
                    Condition::all()
                        .add(Column::FileId.eq(file_id))
                        .add(Column::Key.is_in(chunk.iter().cloned())),
                )
                .secure()
                .scope_with(scope)
                .exec(conn)
                .await
                .map_err(db_err)?;
            total_rows_affected += res.rows_affected;
        }
        Ok(total_rows_affected)
    }

    /// Batched insert of `(key, value)` entries in one multi-row `INSERT`. Callers must have
    /// removed existing rows for these keys (e.g. via `delete_keys`); no statements for an
    /// empty slice.
    pub async fn insert_many<C: DBRunner>(
        &self,
        conn: &C,
        scope: &AccessScope,
        file_id: Uuid,
        entries: &[(String, String)],
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        if entries.is_empty() {
            return Ok(());
        }
        let models: Vec<ActiveModel> = entries
            .iter()
            .map(|(key, value)| ActiveModel {
                file_id: Set(file_id),
                key: Set(key.clone()),
                value: Set(value.clone()),
                set_at: Set(now),
            })
            .collect();
        secure_insert_many::<Entity>(models, scope, conn)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}
