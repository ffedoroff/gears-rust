// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
#![doc = include_str!("../README.md")]

pub mod vault;

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;

use async_trait::async_trait;
use credstore_sdk::{CredStorePluginClientV2, SecretValue};
use credstore_sdk_v02::{
    CredStoreError as OldError, CredStorePluginClientV1, OwnerId, SecretRef, TenantId,
};
use credstore_value_migration::{LegacyError, LegacyStore, TOOL_ID};
use toolkit_security_v02::SecurityContext;
use uuid::Uuid;

/// The engine's name for the old store, over a plugin of the published V1
/// contract (`cf-gears-credstore-sdk` 0.2, `CredStorePluginClientV1`).
///
/// Addressing is exactly what the shipped gear did: the owner is passed only for
/// a private record. A `ServiceUnavailable` answer is transient (the engine
/// retries it), `NotFound` is read as an absent entry, anything else is final.
pub struct V1Store {
    inner: Arc<dyn CredStorePluginClientV1>,
    ctx: SecurityContext,
}

impl V1Store {
    /// Wraps the old plugin. The calls carry the tool's fixed service identity.
    ///
    /// # Errors
    ///
    /// The security context cannot be built.
    pub fn new(inner: Arc<dyn CredStorePluginClientV1>) -> anyhow::Result<Self> {
        let ctx = SecurityContext::builder()
            .subject_id(TOOL_ID)
            .subject_tenant_id(TOOL_ID)
            .subject_type("service")
            .build()
            .map_err(|e| anyhow::anyhow!("cannot build the migration security context: {e}"))?;
        Ok(Self { inner, ctx })
    }
}

fn address(reference: &str) -> Result<SecretRef, LegacyError> {
    SecretRef::new(reference).map_err(|e| {
        LegacyError::Failed(format!("the reference is not valid for the old store: {e}"))
    })
}

fn failure(e: &OldError) -> LegacyError {
    match e {
        OldError::ServiceUnavailable { .. } => LegacyError::Unavailable(e.to_string()),
        _ => LegacyError::Failed(e.to_string()),
    }
}

#[async_trait]
impl LegacyStore for V1Store {
    async fn get(
        &self,
        tenant_id: Uuid,
        reference: &str,
        owner_id: Option<Uuid>,
    ) -> Result<Option<SecretValue>, LegacyError> {
        let key = address(reference)?;
        let owner = owner_id.map(OwnerId);
        match self
            .inner
            .get(&self.ctx, &TenantId(tenant_id), &key, owner.as_ref())
            .await
        {
            Ok(value) => Ok(value.map(|v| SecretValue::new(v.as_bytes().to_vec()))),
            Err(OldError::NotFound) => Ok(None),
            Err(e) => Err(failure(&e)),
        }
    }

    async fn delete(
        &self,
        tenant_id: Uuid,
        reference: &str,
        owner_id: Option<Uuid>,
    ) -> Result<(), LegacyError> {
        let key = address(reference)?;
        let owner = owner_id.map(OwnerId);
        match self
            .inner
            .delete(&self.ctx, &TenantId(tenant_id), &key, owner.as_ref())
            .await
        {
            Ok(()) | Err(OldError::NotFound) => Ok(()),
            Err(e) => Err(failure(&e)),
        }
    }
}

/// Runs the tool with `std::env::args`: `old` is the pre-ADR-0006 plugin through
/// its published V1 contract (only `get` and `delete` are called), `new` the
/// plugin of the immutable-versions store. See the engine's README for the
/// commands and the exit codes.
///
/// # Errors
///
/// Only when the old plugin's security context cannot be built or the output
/// cannot be written; every other failure is reported on stderr and returned as
/// exit code `1`.
pub async fn run(
    old: Arc<dyn CredStorePluginClientV1>,
    new: Arc<dyn CredStorePluginClientV2>,
) -> anyhow::Result<ExitCode> {
    credstore_value_migration::run(Arc::new(V1Store::new(old)?), new).await
}

/// Like [`run`] with explicit arguments (the first is the program name).
///
/// # Errors
///
/// As [`run`].
pub async fn run_from<I, T>(
    args: I,
    old: Arc<dyn CredStorePluginClientV1>,
    new: Arc<dyn CredStorePluginClientV2>,
) -> anyhow::Result<ExitCode>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    credstore_value_migration::run_from(args, Arc::new(V1Store::new(old)?), new).await
}
