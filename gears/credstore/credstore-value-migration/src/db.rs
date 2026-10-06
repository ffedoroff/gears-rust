// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Raw access helpers for both supported backends.

use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement, Value};

use crate::error::MigrationError;

/// Which of the two schema generations of `credstore_secrets` a database is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schema {
    /// Shipped `m0001` only: has `value_fp`, no `value_version`.
    Shipped,
    /// After `m0002`: has `value_version`, no `value_fp`.
    ValueVersions,
}

impl Schema {
    /// A name for messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Shipped => "shipped (m0001 only)",
            Self::ValueVersions => "migrated (m0002 applied)",
        }
    }
}

/// The backend of `db`, or an error when it is neither `PostgreSQL` nor `SQLite`.
pub fn backend(db: &DatabaseConnection) -> Result<DatabaseBackend, MigrationError> {
    match db.get_database_backend() {
        b @ (DatabaseBackend::Postgres | DatabaseBackend::Sqlite) => Ok(b),
        _ => Err(MigrationError::UnsupportedBackend),
    }
}

/// Positional placeholder `n` (1-based) for `backend`.
pub fn ph(backend: DatabaseBackend, n: usize) -> String {
    match backend {
        DatabaseBackend::Postgres => format!("${n}"),
        _ => format!("?{n}"),
    }
}

/// A statement with bound values.
pub fn stmt(backend: DatabaseBackend, sql: &str, values: Vec<Value>) -> Statement {
    Statement::from_sql_and_values(backend, sql, values)
}

/// Whether `sql` returns at least one row. Callers write existence checks
/// (`SELECT 1 ... LIMIT 1`): the tool never counts rows.
pub async fn exists(
    db: &impl ConnectionTrait,
    backend: DatabaseBackend,
    sql: &str,
    values: Vec<Value>,
) -> Result<bool, MigrationError> {
    Ok(db
        .query_one_raw(stmt(backend, sql, values))
        .await?
        .is_some())
}

/// Whether the table exists in the current schema.
pub async fn table_exists(
    db: &impl ConnectionTrait,
    backend: DatabaseBackend,
    table: &str,
) -> Result<bool, MigrationError> {
    let sql = match backend {
        DatabaseBackend::Postgres => {
            "SELECT 1 AS present FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = $1 LIMIT 1"
        }
        _ => "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?1",
    };
    exists(db, backend, sql, vec![table.into()]).await
}

async fn has_column(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    column: &str,
) -> Result<bool, MigrationError> {
    let sql = match backend {
        DatabaseBackend::Postgres => {
            "SELECT 1 AS present FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'credstore_secrets' \
             AND column_name = $1 LIMIT 1"
        }
        _ => "SELECT 1 AS present FROM pragma_table_info('credstore_secrets') WHERE name = ?1",
    };
    exists(db, backend, sql, vec![column.into()]).await
}

/// Determines the schema generation, failing when the table is missing or in
/// neither known shape.
pub async fn detect_schema(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
) -> Result<Schema, MigrationError> {
    let fp = has_column(db, backend, "value_fp").await?;
    let version = has_column(db, backend, "value_version").await?;
    match (fp, version) {
        (true, false) => Ok(Schema::Shipped),
        (false, true) => Ok(Schema::ValueVersions),
        (true, true) => Err(MigrationError::WrongSchema(
            "credstore_secrets has both value_fp and value_version: m0002 did not complete"
                .to_owned(),
        )),
        (false, false) => Err(MigrationError::WrongSchema(
            "credstore_secrets is missing or has neither value_fp nor value_version".to_owned(),
        )),
    }
}
