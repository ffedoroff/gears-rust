//! `SeaORM` entity for the `file_versions` table (immutable content versions).
//!
//! No `tenant_id` column: versions are reached through the parent `files` row
//! (FK), so tenant scoping is enforced on the file, not re-declared here.

use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db_macros::Scopable;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "file_versions")]
#[secure(no_tenant, resource_col = "version_id", no_owner, no_type)]
pub struct Model {
    // `version_id` is globally unique, so it is the sole entity primary key
    // (the DB table keeps the composite `(file_id, version_id)` PK). This keeps
    // updates/deletes keyed off a single PK column.
    pub file_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub version_id: Uuid,
    pub mime_type: String,
    pub size: i64,
    pub hash_algorithm: String,
    pub hash_value: Vec<u8>,
    /// ADR-0006 content-hash mode: `'whole-sha256'` (non-multipart, the
    /// default for every pre-existing row) or `'multipart-composite-sha256'`.
    pub hash_mode: String,
    /// Number of parts, `Some` only for `multipart-composite-sha256`
    /// versions (enforced by the DB cross-column presence CHECK); `None`
    /// for `whole-sha256`.
    pub part_count: Option<i32>,
    pub status: String,
    pub is_current: bool,
    pub backend_id: String,
    pub backend_path: String,
    pub created_at: OffsetDateTime,
    /// See [`file_storage_sdk::FileVersion::bound_on_finalize`]'s doc comment.
    pub bound_on_finalize: bool,
    /// Migration lease owner (upload-flow redesign): a random `Uuid` a
    /// `migrate_backend` call stamps here (alongside
    /// [`Self::migration_lease_until`]) before it ever writes to the
    /// destination backend, so a concurrent migration attempt of this same
    /// version -- which would always target the same deterministic
    /// destination path -- is rejected instead of racing this one there.
    /// `None` means no migration currently holds the lease. Internal state
    /// only: deliberately **not** part of the public
    /// [`file_storage_sdk::FileVersion`] domain model (see that struct's own
    /// doc comment).
    pub migration_lease_owner: Option<Uuid>,
    /// Migration lease expiry (upload-flow redesign), timed by the
    /// **database's own clock** (`VersionRepo::acquire_migration_lease`
    /// writes it via `now()`/`CURRENT_TIMESTAMP`, never the acquiring
    /// instance's clock) so instance clock skew cannot make a live lease
    /// look expired -- or an expired one look live -- to a second attempt
    /// reading this row. `None` iff [`Self::migration_lease_owner`] is
    /// `None`. Internal state only -- see that field's doc comment.
    pub migration_lease_until: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
