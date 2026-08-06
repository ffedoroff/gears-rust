//! `SeaORM` entity for the AM-owned `tenant_id_tombstone` table.
//!
//! Mirrors the schema declared by `m0009_create_tenant_id_tombstone`
//! column-for-column. One row per tenant identifier the platform has
//! issued and later hard-deleted; rows are written inside the
//! hard-delete transaction and are never removed.
//!
//! The table records identifiers, not tenants: it carries no name, no
//! parent, no status and no hierarchy position, because none of those
//! survive the tenant and none are needed to answer the only question
//! asked of it — "has this identifier ever been in circulation?".
//!
//! Like `tenant_closure`, this table has no tenant-ownership column: a
//! retired identifier belongs to no live tenant by definition, so there
//! is nothing for a subtree clamp to filter on and the entity is
//! declared `no_tenant` / `no_resource` / `no_owner` / `no_type`.

use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db_macros::Scopable;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Scopable)]
#[sea_orm(table_name = "tenant_id_tombstone")]
#[secure(no_tenant, no_resource, no_owner, no_type)]
pub struct Model {
    /// The retired tenant identifier. Primary key — the create path
    /// probes this table by identifier and nothing else.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// When the identifier left circulation. Forensics only; nothing
    /// expires a tombstone, because a reusable identifier is exactly
    /// what this table exists to prevent.
    pub retired_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
