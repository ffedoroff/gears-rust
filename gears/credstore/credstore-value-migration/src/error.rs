// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Error type of the migration.

use uuid::Uuid;

use crate::legacy::LegacyError;

/// A run aborted. Nothing is silently skipped: every variant stops the run
/// (exit code `1`), the persisted progress is kept, and re-running the same
/// command resumes from it.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// A database statement failed.
    #[error("database error: {0}")]
    Db(#[from] sea_orm::DbErr),
    /// The database could not be opened, or the migration lock failed.
    #[error("database: {0}")]
    Connect(#[from] toolkit_db::DbError),
    /// The platform migration runner failed while applying the gear's schema.
    #[error("applying the gear migrations: {0}")]
    Schema(#[from] toolkit_db::migration_runner::MigrationError),
    /// The command line is incomplete.
    #[error("{0}")]
    Usage(String),
    /// The database backend is neither `PostgreSQL` nor `SQLite`.
    #[error("unsupported database backend (PostgreSQL and SQLite only)")]
    UnsupportedBackend,
    /// Another `migrate` or `cleanup` run holds the migration lock.
    #[error(
        "another credstore-value-migration run holds the migration lock on this database; \
         wait for it to finish (or stop it) and run this command again"
    )]
    AlreadyRunning,
    /// The database is not in a schema state this command can work with.
    #[error("wrong schema state: {0}")]
    WrongSchema(String),
    /// The tool's own progress tables contradict the database or each other.
    #[error("inconsistent migration state: {0}")]
    State(String),
    /// The old store failed (after the retries). `row` is the credential row
    /// being handled, when there was one.
    #[error("old store{}: {source}", row.map(|id| format!(" (row {id})")).unwrap_or_default())]
    Legacy {
        /// The row the call was for.
        row: Option<Uuid>,
        /// What the store said.
        source: LegacyError,
    },
    /// The new store failed (after the retries).
    #[error("new store: {0}")]
    Target(#[from] credstore_sdk::CredStoreError),
    /// Rows carry value fingerprints but the old store holds no fence key, so
    /// none of them can be verified.
    #[error(
        "the old store has no fence key, but rows carry a value fingerprint: nothing can be verified"
    )]
    FenceKeyAbsent,
    /// A stored column holds a value outside its documented encoding.
    #[error("row {id}: {reason}")]
    BadRow {
        /// Row id.
        id: Uuid,
        /// What is wrong.
        reason: String,
    },
    /// The new store returned other bytes than were written, or no bytes at
    /// all: a store failure, not a property of the data.
    #[error("read-back from the new store failed for record {id}: {reason}")]
    ReadBack {
        /// Record id.
        id: Uuid,
        /// What happened.
        reason: String,
    },
    /// An old reference has the shape of a new store key (a UUID equal to the
    /// id of a credential record); deleting it could remove a new value.
    #[error(
        "{count} old reference(s) look like new store keys (a UUID equal to a credential record \
         id), for example {reference} (tenant {tenant_id}): refusing to delete anything, the old \
         and the new store may share a mount; check them by hand"
    )]
    NewKeyShaped {
        /// The first offending reference.
        reference: String,
        /// Its tenant.
        tenant_id: Uuid,
        /// How many references are offending.
        count: usize,
    },
}

impl MigrationError {
    /// Names the credential row an old-store failure happened for.
    #[must_use]
    pub fn at_row(self, id: Uuid) -> Self {
        match self {
            Self::Legacy { source, .. } => Self::Legacy {
                row: Some(id),
                source,
            },
            other => other,
        }
    }
}
