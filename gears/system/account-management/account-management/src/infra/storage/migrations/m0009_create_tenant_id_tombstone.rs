//! Migration `m0009` — `tenant_id_tombstone`, the permanent record of
//! tenant identifiers the platform has issued and retired.
//!
//! Why a separate table rather than keeping the `tenants` row:
//!
//! * Tenant identifiers are caller-supplied on import
//!   (`cpt-cf-account-management-fr-tenant-import-external-id`), so the
//!   `tenants` primary key alone stops guarding uniqueness the moment a
//!   hard delete removes the row — a later import could reuse the
//!   identifier and silently re-point every audit record, external
//!   reference and cached authorization decision that still names it.
//! * Retaining the `tenants` row instead would drag the retired tenant
//!   through every hierarchy query, closure invariant and status filter
//!   in the gear. A tombstone carries the one fact that must outlive the
//!   tenant and nothing else.
//!
//! Schema rationale:
//!
//! * `id` is the PRIMARY KEY — the only access pattern is an existence
//!   probe by identifier on the create path, so the PK index is the
//!   whole index budget.
//! * `retired_at` exists for operator forensics ("when did this
//!   identifier leave circulation"), not for expiry. Nothing prunes this
//!   table: an identifier that becomes reusable defeats its purpose.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

const MYSQL_NOT_SUPPORTED: &str = "account-management migrations: MySQL is not supported \
    (this migration set targets PostgreSQL/SQLite); add a dedicated MySQL migration set \
    before running against MySQL";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let conn = manager.get_connection();

        let statements: Vec<&str> = match backend {
            sea_orm::DatabaseBackend::Postgres => vec![
                "CREATE TABLE IF NOT EXISTS tenant_id_tombstone ( \
                    id UUID PRIMARY KEY, \
                    retired_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP \
                );",
            ],
            sea_orm::DatabaseBackend::Sqlite => vec![
                // SQLite has no native UUID or TIMESTAMPTZ types; sea_orm
                // serialises `Uuid` to canonical TEXT and `OffsetDateTime`
                // to ISO-8601 TEXT, matching `am_leases` in `m0007`.
                "CREATE TABLE IF NOT EXISTS tenant_id_tombstone ( \
                    id TEXT PRIMARY KEY, \
                    retired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP \
                );",
            ],
            sea_orm::DatabaseBackend::MySql => {
                return Err(DbErr::Custom(MYSQL_NOT_SUPPORTED.to_owned()));
            }
        };

        for sql in statements {
            conn.execute_unprepared(sql).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if matches!(backend, sea_orm::DatabaseBackend::MySql) {
            return Err(DbErr::Custom(MYSQL_NOT_SUPPORTED.to_owned()));
        }
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS tenant_id_tombstone;")
            .await?;
        Ok(())
    }
}
