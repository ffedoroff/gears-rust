// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! What a run works with: the database, the two stores and the knobs. A leaf of
//! the module graph (it depends on `error`, `state` and `stores` only), so the
//! phases and the commands share it without importing each other.

use credstore_sdk::SecretValue;
use sea_orm::{DatabaseBackend, DatabaseConnection};
use toolkit_db::Db;

use crate::error::MigrationError;
use crate::state;
use crate::stores::{NewStore, OldAddress, OldStore, Tuning};

/// Everything a run needs: the database (the tool's own connection and the
/// platform handle the gear's migrations are applied through) and the stores.
pub struct Env<'a> {
    /// The tool's connection, for its raw statements.
    pub db: &'a DatabaseConnection,
    /// Its backend.
    pub backend: DatabaseBackend,
    /// The platform `Db` handle, for the migration runner.
    pub platform: &'a Db,
    /// The old store.
    pub old: OldStore<'a>,
    /// The new store.
    pub new: NewStore<'a>,
    /// Retry and batching knobs.
    pub tuning: &'a Tuning,
}

/// Reads the old fence key. When it is absent while `pending` rows carry a
/// fingerprint, nothing can be verified: an error.
pub(crate) async fn load_fence_key(env: &Env<'_>) -> Result<Option<SecretValue>, MigrationError> {
    let key = env.old.get(&OldAddress::fence_key()).await?;
    if key.is_none()
        && state::any_row(
            env.db,
            env.backend,
            "state = 'pending' AND value_fp IS NOT NULL",
        )
        .await?
    {
        return Err(MigrationError::FenceKeyAbsent);
    }
    Ok(key)
}
