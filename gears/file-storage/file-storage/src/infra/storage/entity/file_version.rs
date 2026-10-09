//! `SeaORM` entity for the `file_versions` table (immutable content versions).
//!
//! No `tenant_id` column: tenant scoping is enforced on the parent `files` row.

use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db_macros::Scopable;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "file_versions")]
#[secure(no_tenant, resource_col = "version_id", no_owner, no_type)]
pub struct Model {
    // `version_id` is globally unique, so it is the sole entity PK (the table keeps
    // the composite `(file_id, version_id)` PK).
    pub file_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: Uuid,
    pub mime_type: String,
    pub size: i64,
    pub hash_algorithm: String,
    pub hash_value: Vec<u8>,
    /// Content-hash mode: `'whole-sha256'` (default) or `'multipart-composite-sha256'`.
    pub hash_mode: String,
    /// Number of parts; `Some` only for `multipart-composite-sha256` (DB CHECK).
    pub part_count: Option<i32>,
    pub status: String,
    pub is_current: bool,
    pub backend_id: String,
    pub backend_path: String,
    pub created_at: OffsetDateTime,
    /// See [`file_storage_sdk::FileVersion::bound_on_finalize`]'s doc comment.
    pub bound_on_finalize: bool,
    /// Migration lease owner: a random `Uuid` stamped by `migrate_backend` before it writes
    /// to the destination, so a concurrent migration of the same version (same destination
    /// path) is rejected. `None` means no lease. Internal; not part of `FileVersion`.
    pub migration_lease_owner: Option<Uuid>,
    /// Migration lease expiry, set from the **database clock**
    /// (`VersionRepo::acquire_migration_lease`) so instance clock skew cannot make a live
    /// lease look expired or vice versa. `None` iff [`Self::migration_lease_owner`] is `None`.
    pub migration_lease_until: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
