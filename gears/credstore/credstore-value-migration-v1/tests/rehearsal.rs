// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The end-to-end rehearsal on real services, as an operator would do it before
//! the downtime window: a Vault in Docker holds the OLD layout (written through
//! the tool's reference V1 implementation), a `PostgreSQL` in Docker holds the
//! shipped schema and rows with real fingerprints; `migrate` copies every value
//! into the NEW store (the real `cf-gears-vault-credstore-plugin`), every
//! credential is read back through the new plugin by the pointer in
//! `PostgreSQL`, and `cleanup` retires the old entries.
//!
//! All tests are `#[ignore]`d (they need Docker and never run in CI):
//!
//! ```text
//! CREDSTORE_MIGRATION_REQUIRE_DOCKER=1 cargo test -p cf-gears-credstore-value-migration \
//!     --test rehearsal -- --ignored
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::use_debug,
    reason = "tests"
)]

#[path = "../../credstore-value-migration/tests/common/mod.rs"]
mod common;
#[path = "support/vault.rs"]
mod vault;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use common::{FENCE_KEY, Fixture, Row, expect_exit, tenant};
use credstore_sdk::{
    CredStoreError, CredStorePluginClientV2, DestroySelector, SecretValue, StoreKey, TenantId,
    ValueVersion,
};
use credstore_sdk_v02::{
    CredStorePluginClientV1, OwnerId, SecretRef, SecretValue as OldValue, TenantId as OldTenantId,
};
use credstore_value_migration::Exit;
use credstore_value_migration::fence::FENCE_KEY_REF;
use credstore_value_migration_v1::V1Store;
use credstore_value_migration_v1::vault::{VaultV1, VaultV1Config};
use toolkit_security::SecurityContext;
use uuid::Uuid;
use vault::{MOUNT, VaultServer};
use vault_credstore_plugin::client_from_config;
use vault_credstore_plugin::config::{RetryConfig, VaultCredStorePluginConfig, VaultToken};

const OLD_PREFIX: &str = "credstore-old";
const NEW_PREFIX: &str = "credstore-new";

/// The new plugin, built from its configuration the way an operator's migration binary builds
/// it: through the plugin's public constructor, with no `ClientHub` and no gear.
fn new_plugin(server: &VaultServer, token: &str, prefix: &str) -> Arc<dyn CredStorePluginClientV2> {
    let cfg = VaultCredStorePluginConfig {
        address: server.address.clone(),
        token: Some(VaultToken::from(token)),
        mount: MOUNT.to_owned(),
        path_prefix: prefix.to_owned(),
        timeout_secs: 10,
        retry: RetryConfig {
            max_attempts: 3,
            base_delay_ms: 50,
        },
        ..VaultCredStorePluginConfig::default()
    };
    client_from_config(&cfg).unwrap()
}

/// The old store, through the reference V1 implementation.
fn old_store(server: &VaultServer, token: &str, prefix: &str) -> Arc<VaultV1> {
    Arc::new(
        VaultV1::new(VaultV1Config::new(
            server.address.clone(),
            token,
            MOUNT,
            prefix,
        ))
        .unwrap(),
    )
}

/// What the tool reads the old store through: the bridge over the V1 contract.
fn legacy(old: &Arc<VaultV1>) -> V1Store {
    V1Store::new(old.clone()).unwrap()
}

/// Writes one value at its old address through the V1 contract.
async fn put_old(old: &VaultV1, row: &Row, value: &[u8]) {
    let ctx = toolkit_security_v02_context();
    old.put(
        &ctx,
        &OldTenantId(row.tenant),
        &SecretRef::new(row.reference.clone()).unwrap(),
        OldValue::new(value.to_vec()),
        row.old_owner().map(OwnerId).as_ref(),
    )
    .await
    .unwrap();
}

fn toolkit_security_v02_context() -> toolkit_security_v02::SecurityContext {
    toolkit_security_v02::SecurityContext::anonymous()
}

async fn get_old(old: &VaultV1, row: &Row) -> Option<Vec<u8>> {
    let ctx = toolkit_security_v02_context();
    old.get(
        &ctx,
        &OldTenantId(row.tenant),
        &SecretRef::new(row.reference.clone()).unwrap(),
        row.old_owner().map(OwnerId).as_ref(),
    )
    .await
    .unwrap()
    .map(|v| v.as_bytes().to_vec())
}

/// Writes the old fence key.
async fn put_old_fence_key(old: &VaultV1) {
    let ctx = toolkit_security_v02_context();
    old.put(
        &ctx,
        &OldTenantId(Uuid::nil()),
        &SecretRef::new(FENCE_KEY_REF).unwrap(),
        OldValue::new(FENCE_KEY.to_vec()),
        None,
    )
    .await
    .unwrap();
}

/// A value for every shape a credential can have.
struct Dataset {
    rows: Vec<(Row, Vec<u8>)>,
    unfinished: (Row, Vec<u8>),
}

fn dataset() -> Dataset {
    let owner = Uuid::from_u128(0x77);
    let mut rows = Vec::new();
    let mut add = |row: Row, value: Vec<u8>| {
        // The fingerprint (when the row has one) is over the value the old store holds.
        let row = if row.fp.is_some() {
            let mut row = row;
            row.fp = Some(credstore_value_migration::fence::compute_fp(
                &FENCE_KEY, &value,
            ));
            row
        } else {
            row
        };
        rows.push((row, value));
    };
    add(
        Row::valued(1, tenant(1), "db-password"),
        b"s3cr3t \xe2\x9c\x93 text".to_vec(),
    );
    add(
        Row::valued(2, tenant(1), "db-password").private(owner),
        b"the owner's own value".to_vec(),
    );
    // Out-of-band seeded: no fingerprint; binary with NUL and invalid UTF-8.
    add(
        Row::valued(3, tenant(2), "binary").without_fp(),
        vec![0, 255, 254, 1, 2, 0, 128],
    );
    // A tenant-shared row with a 64 KiB value.
    let big: Vec<u8> = (0..65_536_u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    add(Row::valued(4, tenant(3), "large").sharing(3), big);
    add(Row::valued(5, tenant(3), "empty"), Vec::new());
    let unfinished = (
        Row::valued(6, tenant(2), "half-written").with_status(1),
        b"half".to_vec(),
    );
    Dataset { rows, unfinished }
}

/// Reads one credential through the NEW plugin by the pointer `PostgreSQL` holds.
async fn read_through_new(f: &Fixture, plugin: &dyn CredStorePluginClientV2, row: &Row) -> Vec<u8> {
    let (status, version, fallback, _) = f.secret(row.id).await.unwrap();
    assert_eq!((status, fallback), (2, 1), "{}", row.reference);
    let ctx = SecurityContext::anonymous();
    plugin
        .get(
            &ctx,
            &StoreKey::new(TenantId(row.tenant), row.id),
            &ValueVersion::new(version.expect("an active row has a pointer")),
        )
        .await
        .unwrap()
        .expect("the pointed-at version exists")
        .as_bytes()
        .to_vec()
}

/// Fails every `get` while `fail_gets` is above zero: a read-back that does not
/// work, to leave a version behind.
struct FlakyReadBack {
    inner: Arc<dyn CredStorePluginClientV2>,
    fail_gets: AtomicUsize,
}

#[async_trait]
impl CredStorePluginClientV2 for FlakyReadBack {
    async fn put(
        &self,
        ctx: &SecurityContext,
        key: &StoreKey,
        value: SecretValue,
    ) -> Result<ValueVersion, CredStoreError> {
        self.inner.put(ctx, key, value).await
    }

    async fn get(
        &self,
        ctx: &SecurityContext,
        key: &StoreKey,
        version: &ValueVersion,
    ) -> Result<Option<SecretValue>, CredStoreError> {
        if self
            .fail_gets
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(CredStoreError::service_unavailable("injected"));
        }
        self.inner.get(ctx, key, version).await
    }

    async fn delete_key(
        &self,
        ctx: &SecurityContext,
        key: &StoreKey,
    ) -> Result<(), CredStoreError> {
        self.inner.delete_key(ctx, key).await
    }

    fn supports_destroy(&self) -> bool {
        self.inner.supports_destroy()
    }

    async fn destroy(
        &self,
        ctx: &SecurityContext,
        key: &StoreKey,
        selector: DestroySelector,
    ) -> Result<(), CredStoreError> {
        self.inner.destroy(ctx, key, selector).await
    }
}

#[tokio::test]
#[ignore = "requires Docker (starts Vault and PostgreSQL containers); run manually with `-- --ignored`"]
async fn old_vault_layout_to_the_new_vault_plugin_then_cleanup() {
    let (Some(vault), Some(f)) = (VaultServer::start().await, Fixture::postgres().await) else {
        return;
    };
    let token = vault
        .token_for("rehearsal", &[OLD_PREFIX, NEW_PREFIX])
        .await;
    let old = old_store(&vault, &token, OLD_PREFIX);
    let new = FlakyReadBack {
        inner: new_plugin(&vault, &token, NEW_PREFIX),
        fail_gets: AtomicUsize::new(0),
    };

    // The old installation: the old Vault layout and the shipped rows.
    let data = dataset();
    put_old_fence_key(&old).await;
    for (row, value) in &data.rows {
        f.insert(row).await;
        put_old(&old, row, value).await;
    }
    f.insert(&data.unfinished.0).await;
    put_old(&old, &data.unfinished.0, &data.unfinished.1).await;
    // The reference layout, as documented: the tenant class and the owner class.
    let (shared, private) = (&data.rows[0].0, &data.rows[1].0);
    assert_ne!(get_old(&old, shared).await, get_old(&old, private).await);
    let (status, _) = vault
        .raw(
            "GET",
            &format!(
                "{MOUNT}/data/{OLD_PREFIX}/{}/db-password/owner/{}",
                private.tenant, private.owner
            ),
            None,
        )
        .await;
    assert_eq!(status, 200, "the owner class lives under .../owner/<owner>");

    // First run: the new store's read-back keeps failing, which leaves a version
    // behind and stops the run in the copy phase.
    new.fail_gets.store(3, Ordering::SeqCst);
    let first = f.run_with_stores(&legacy(&old), &new, &["migrate"]).await;
    expect_exit(&first, Exit::Failure);
    assert_eq!(f.phase().await, "copying");
    let first_row = &data.rows[0].0;
    let versions = vault
        .versions(
            NEW_PREFIX,
            &first_row.tenant.to_string(),
            &first_row.id.to_string(),
        )
        .await;
    assert_eq!(versions["1"]["destroyed"], false, "the orphan: {versions}");

    // The same command again: it resumes, finishes, and tidies the orphan.
    let second = f.run_with_stores(&legacy(&old), &new, &["migrate"]).await;
    expect_exit(&second, Exit::Success);
    assert_eq!(f.phase().await, "done");
    let versions = vault
        .versions(
            NEW_PREFIX,
            &first_row.tenant.to_string(),
            &first_row.id.to_string(),
        )
        .await;
    assert_eq!(versions["1"]["destroyed"], true, "{versions}");
    assert_eq!(versions["2"]["destroyed"], false, "{versions}");

    // Every credential reads back, byte for byte, through the new plugin by the
    // pointer in PostgreSQL.
    for (row, value) in &data.rows {
        assert_eq!(
            &read_through_new(&f, &new, row).await,
            value,
            "{}",
            row.reference
        );
    }
    // The unfinished row is gone with m0002, and was never copied.
    assert!(!f.row_exists(data.unfinished.0.id).await);
    // The old entries are still where they were (cleanup has not run).
    for (row, value) in &data.rows {
        assert_eq!(get_old(&old, row).await.as_ref(), Some(value));
    }

    // Cleanup retires the old layout and leaves the new values alone.
    let cleanup = f.run_with_stores(&legacy(&old), &new, &["cleanup"]).await;
    expect_exit(&cleanup, Exit::Success);
    for (row, _) in &data.rows {
        assert_eq!(get_old(&old, row).await, None, "{}", row.reference);
    }
    assert_eq!(get_old(&old, &data.unfinished.0).await, None);
    let (status, _) = vault
        .raw(
            "GET",
            &format!("{MOUNT}/data/{OLD_PREFIX}/{}/{FENCE_KEY_REF}", Uuid::nil()),
            None,
        )
        .await;
    assert_eq!(status, 200, "the fence key stays without the flag");
    for (row, value) in &data.rows {
        assert_eq!(
            &read_through_new(&f, &new, row).await,
            value,
            "{}",
            row.reference
        );
    }

    // The fence key last, with its flag; then the bookkeeping.
    expect_exit(
        &f.run_with_stores(
            &legacy(&old),
            &new,
            &["cleanup", "--include-fence-key", "--drop-state"],
        )
        .await,
        Exit::Success,
    );
    let (status, _) = vault
        .raw(
            "GET",
            &format!("{MOUNT}/data/{OLD_PREFIX}/{}/{FENCE_KEY_REF}", Uuid::nil()),
            None,
        )
        .await;
    assert_eq!(status, 404);
    assert!(!f.table_exists("credstore_value_migration").await);
}

#[tokio::test]
#[ignore = "requires Docker (starts Vault and PostgreSQL containers); run manually with `-- --ignored`"]
async fn on_a_shared_prefix_cleanup_refuses_the_old_address_that_is_a_new_key() {
    let (Some(vault), Some(f)) = (VaultServer::start().await, Fixture::postgres().await) else {
        return;
    };
    // The old and the new store share the mount AND the prefix.
    let token = vault.token_for("rehearsal-shared", &[OLD_PREFIX]).await;
    let old = old_store(&vault, &token, OLD_PREFIX);
    let new = new_plugin(&vault, &token, OLD_PREFIX);

    put_old_fence_key(&old).await;
    // `Y` is migrated before `X` (ids ascend), so its old value is read before `X`'s
    // new version lands on the same Vault key: Y's OLD address
    // `<prefix>/<tenant>/<X's id>` is X's NEW key.
    let x_id = common::rid(2);
    let y = Row::valued(1, tenant(1), &x_id.to_string());
    let x = Row::valued(2, tenant(1), "plain");
    for row in [&y, &x] {
        f.insert(row).await;
        put_old(&old, row, &row.value()).await;
    }

    expect_exit(
        &f.run_with_stores(&legacy(&old), &*new, &["migrate"]).await,
        Exit::Success,
    );
    assert_eq!(read_through_new(&f, &*new, &x).await, x.value());

    // Deleting Y's old address would delete X's new key. Cleanup refuses, and deletes nothing.
    let run = f.run_with_stores(&legacy(&old), &*new, &["cleanup"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("look like new store keys"), "{}", run.err);
    assert_eq!(read_through_new(&f, &*new, &x).await, x.value());
    assert_eq!(get_old(&old, &x).await, Some(x.value()));
}
