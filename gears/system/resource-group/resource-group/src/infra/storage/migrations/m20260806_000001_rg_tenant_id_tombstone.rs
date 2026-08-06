// Created: 2026-08-06 by Constructor Tech
//! Migration — `rg_tenant_id_tombstone`, the record of tenant
//! identifiers this gear has issued and retired.
//!
//! A group whose GTS type code carries the tenant prefix takes its own
//! `id` as its `tenant_id` (`create_group_inner`'s `effective_tenant_id`
//! derivation), so creating one issues a tenant identifier and deleting
//! one retires it. Once the row is gone the primary key stops guarding
//! the identifier, and `CreateGroupRequest::id` lets a caller name it —
//! so without a tombstone a later create could reuse the identity of a
//! tenant that no longer exists, silently re-pointing every audit
//! record, external reference and cached authorization decision that
//! still names it.
//!
//! **Scope of the guarantee.** This table covers identifiers *this
//! gear* retired. Account Management keeps the mirror-image record for
//! the ones it retires (`tenant_id_tombstone`, AM migration `m0009`).
//! Neither table can see the other: RG has no dependency on AM, and
//! adding one would close the cycle `RG → tenant-resolver →
//! rg-tr-plugin → RG`. A single platform-wide guarantee therefore
//! requires the ownership question to be settled first — until then
//! each store refuses to reissue what it retired, which is the strongest
//! statement either gear can make on its own.
//!
//! The name is prefixed `rg_` deliberately: in a monolith deployment
//! both gears migrate into the same database, where an unprefixed
//! `tenant_id_tombstone` would collide with AM's table of the same
//! meaning but different ownership.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        let sql = match backend {
            sea_orm::DatabaseBackend::Postgres => {
                r"
CREATE TABLE IF NOT EXISTS rg_tenant_id_tombstone (
    id UUID PRIMARY KEY,
    retired_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
                "
            }
            sea_orm::DatabaseBackend::Sqlite => {
                // SQLite has no native UUID or TIMESTAMPTZ types; sea_orm
                // serialises `Uuid` to canonical TEXT and `OffsetDateTime`
                // to ISO-8601 TEXT.
                r"
CREATE TABLE IF NOT EXISTS rg_tenant_id_tombstone (
    id TEXT PRIMARY KEY,
    retired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
                "
            }
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Custom(
                    "resource-group migrations: MySQL is not supported".to_owned(),
                ));
            }
        };

        conn.execute_unprepared(sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS rg_tenant_id_tombstone;")
            .await?;
        Ok(())
    }
}
