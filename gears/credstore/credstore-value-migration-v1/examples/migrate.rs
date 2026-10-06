// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Skeleton of an operator binary. Copy it into your own crate, replace the
//! placeholder with your old plugin (read side, through the published V1
//! contract) and point the new store (write side, the Vault plugin built through
//! its public `client_from_config`) at the deployment's Vault, and build it.
//!
//! ```text
//! cargo run --example migrate -- --database-url sqlite://db.sqlite migrate
//! cargo run --example migrate -- --database-url sqlite://db.sqlite cleanup --dry-run
//! ```

use std::process::ExitCode;
use std::sync::Arc;

use async_trait::async_trait;
use credstore_sdk::CredStorePluginClientV2;
use credstore_sdk_v02::{
    CredStoreError as OldError, CredStorePluginClientV1, OwnerId, SecretRef,
    SecretValue as OldValue, TenantId as OldTenantId,
};
use toolkit_security_v02::SecurityContext as OldContext;
use vault_credstore_plugin::client_from_config;
use vault_credstore_plugin::config::VaultCredStorePluginConfig;

/// Placeholder for your pre-ADR-0006 plugin: the code that decrypts in-process.
/// Only `get` and `delete` are called; `owner_id` is `Some` only for a private
/// record (the owner's key class), exactly as the old gear passed it.
struct OldPlugin;

#[async_trait]
impl CredStorePluginClientV1 for OldPlugin {
    async fn get(
        &self,
        _ctx: &OldContext,
        _tenant_id: &OldTenantId,
        _key: &SecretRef,
        _owner_id: Option<&OwnerId>,
    ) -> Result<Option<OldValue>, OldError> {
        Err(OldError::internal(
            "placeholder: call your old plugin's get",
        ))
    }

    async fn put(
        &self,
        _ctx: &OldContext,
        _tenant_id: &OldTenantId,
        _key: &SecretRef,
        _value: OldValue,
        _owner_id: Option<&OwnerId>,
    ) -> Result<(), OldError> {
        Err(OldError::internal(
            "the migration never writes to the old store",
        ))
    }

    async fn delete(
        &self,
        _ctx: &OldContext,
        _tenant_id: &OldTenantId,
        _key: &SecretRef,
        _owner_id: Option<&OwnerId>,
    ) -> Result<(), OldError> {
        Err(OldError::internal(
            "placeholder: call your old plugin's delete",
        ))
    }
}

/// The new store: the Vault / `OpenBao` plugin of this repository, constructed directly
/// (outside the `ClientHub`, no gear) with the SAME configuration the new gear will use.
/// `client_from_config` validates it as the gear does and sends nothing to Vault. With a
/// different new plugin, return its `Arc<dyn CredStorePluginClientV2>` here instead.
fn build_new_store() -> anyhow::Result<Arc<dyn CredStorePluginClientV2>> {
    let cfg = VaultCredStorePluginConfig {
        address: std::env::var("VAULT_ADDR")?,
        token_env: Some("VAULT_TOKEN".to_owned()),
        mount: "secret".to_owned(),
        path_prefix: "credstore".to_owned(),
        ..VaultCredStorePluginConfig::default()
    };
    client_from_config(&cfg)
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let new = build_new_store()?;
    credstore_value_migration_v1::run(Arc::new(OldPlugin), new).await
}
