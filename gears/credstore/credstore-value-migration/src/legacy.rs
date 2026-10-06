// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The OLD store, as the tool needs it.
//!
//! The tool reads the old store through this small trait: `get` the current
//! value at an old address, `delete` it. The address is exactly what the shipped
//! gear passed to its plugin: `(tenant_id, reference, owner_id)`, where
//! `owner_id` is `Some` only for a private record (the owner's key class) and
//! `None` for the tenant key class.
//!
//! An out-of-tree plugin that implements the published
//! `CredStorePluginClientV1` (`cf-gears-credstore-sdk` 0.2) does not implement
//! this trait by hand: the sibling crate `credstore-value-migration-v1` (outside
//! the workspace, because it depends on that published SDK) bridges it and
//! offers `run(old: Arc<dyn CredStorePluginClientV1>, new)` for an operator's
//! binary. This crate has no dependency on the published SDK on purpose: two
//! `cf-gears-credstore-sdk` versions in one workspace make every
//! `cargo -p cf-gears-credstore-sdk` ambiguous.

use async_trait::async_trait;
use credstore_sdk::SecretValue;
use uuid::Uuid;

/// Why the old store did not answer. The text must never contain a secret value.
#[derive(Debug, thiserror::Error)]
pub enum LegacyError {
    /// A transient failure (the store is unavailable, a timeout): retried with a
    /// bounded backoff.
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// A failure that retrying does not help: the run aborts.
    #[error("{0}")]
    Failed(String),
}

/// The old value store. Implementations never put a value into an error text.
#[async_trait]
pub trait LegacyStore: Send + Sync {
    /// The current value at the old address; `Ok(None)` when there is none.
    ///
    /// # Errors
    ///
    /// [`LegacyError`] when the store cannot answer.
    async fn get(
        &self,
        tenant_id: Uuid,
        reference: &str,
        owner_id: Option<Uuid>,
    ) -> Result<Option<SecretValue>, LegacyError>;

    /// Deletes the entry at the old address. An absent entry is success.
    ///
    /// # Errors
    ///
    /// [`LegacyError`] when the store cannot delete.
    async fn delete(
        &self,
        tenant_id: Uuid,
        reference: &str,
        owner_id: Option<Uuid>,
    ) -> Result<(), LegacyError>;
}
