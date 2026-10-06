// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Phase `schema`: apply the gear's own migrations with the PLATFORM runner, so
//! the new credstore finds them recorded in its migration history and has
//! nothing left to do for the table.
//!
//! This is exactly the call the platform runtime makes for the gear
//! (`run_migrations_for_gear` with the gear's name and its migration list; the
//! history table name derives from the gear name). A migration already
//! recorded is skipped, so a re-run (or the gear having applied `m0002`
//! itself) is a no-op.
//!
//! The `m0002` guard lets the migration through because the header names a
//! phase past copying (or `discard_values`).

use credstore::CredStoreGear;
use credstore::infra::storage::migrations::Migrator;
use toolkit_db::migration_runner::run_migrations_for_gear;
use toolkit_db::sea_orm_migration::MigratorTrait;

use crate::db::{self, Schema};
use crate::env::Env;
use crate::error::MigrationError;
use crate::report::{Out, say};
use crate::state::ROWS_TABLE;

/// Applies `m0001` and `m0002` through the platform runner.
///
/// # Errors
///
/// [`MigrationError::State`] when a credential row appeared after the
/// snapshot (the old credstore ran during the migration), or any failure of the
/// runner.
pub async fn run(env: &Env<'_>, out: Out<'_>) -> Result<(), MigrationError> {
    if db::detect_schema(env.db, env.backend).await? == Schema::Shipped {
        refuse_unknown_rows(env).await?;
    }
    say!(out, "schema: applying the gear's migrations");
    let result = run_migrations_for_gear(
        env.platform,
        CredStoreGear::MODULE_NAME,
        Migrator::migrations(),
    )
    .await?;
    say!(
        out,
        "schema: applied [{}], already applied: {}",
        result.applied_names.join(", "),
        result.skipped
    );
    if db::detect_schema(env.db, env.backend).await? != Schema::ValueVersions {
        return Err(MigrationError::WrongSchema(
            "the gear's migrations ran but credstore_secrets is not in the migrated shape"
                .to_owned(),
        ));
    }
    Ok(())
}

/// `m0002` cannot carry a value and is irreversible: a row the snapshot does not
/// know would lose its value silently. The old credstore must stay stopped.
async fn refuse_unknown_rows(env: &Env<'_>) -> Result<(), MigrationError> {
    let sql = format!(
        "SELECT 1 AS present FROM credstore_secrets s \
         WHERE NOT EXISTS (SELECT 1 FROM {ROWS_TABLE} r WHERE r.id = s.id) LIMIT 1"
    );
    if db::exists(env.db, env.backend, &sql, vec![]).await? {
        return Err(MigrationError::State(
            "credstore_secrets holds rows that were not there when the migration took its \
             snapshot: the old credstore must stay stopped during the migration; restore the \
             database snapshot and start over"
                .to_owned(),
        ));
    }
    Ok(())
}
