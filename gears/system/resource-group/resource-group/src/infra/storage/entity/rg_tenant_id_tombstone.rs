// Created: 2026-08-06 by Constructor Tech
//! `SeaORM` entity for `rg_tenant_id_tombstone` — tenant identifiers
//! this gear has issued and retired.
//!
//! One row per tenant-typed group that has been hard-deleted. Written
//! inside the delete transaction and never removed: an identifier that
//! becomes reusable is exactly what the table exists to prevent.
//!
//! Declared `no_tenant` / `no_resource` / `no_owner` / `no_type` like
//! `resource_group_closure`: a retired identifier belongs to no live
//! tenant by definition, so there is nothing for a scope clamp to filter
//! on. Clamping here would be actively harmful — a narrowed scope would
//! resolve the probe to "no row" and admit the reuse this table exists
//! to refuse.

use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
use toolkit_db_macros::Scopable;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Scopable)]
#[sea_orm(table_name = "rg_tenant_id_tombstone")]
#[secure(no_tenant, no_resource, no_owner, no_type)]
pub struct Model {
    /// The retired tenant identifier — the `id` of a tenant-typed group
    /// that has been deleted. Primary key: the only access pattern is an
    /// existence probe on the create path.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// When the identifier left circulation. Forensics only; nothing
    /// expires a tombstone.
    pub retired_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
