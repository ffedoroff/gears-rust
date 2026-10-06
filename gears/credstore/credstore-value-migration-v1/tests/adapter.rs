// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The bridge from the published V1 contract to the engine, with a V1
//! implementation written the way an out-of-tree plugin would write it, run
//! through the whole tool over `SQLite` (no Docker).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::use_debug,
    reason = "tests"
)]

#[path = "../../credstore-value-migration/tests/common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::{Fixture, Row, expect_exit, tenant};
use credstore_sdk::StoreKey;
use credstore_sdk_v02::{
    CredStoreError as OldError, CredStorePluginClientV1, OwnerId, SecretRef,
    SecretValue as OldValue, TenantId as OldTenantId,
};
use credstore_value_migration::{Exit, LegacyError, LegacyStore};
use credstore_value_migration_v1::V1Store;
use toolkit_security_v02::SecurityContext;
use uuid::Uuid;

type Key = (Uuid, String, Option<Uuid>);
type Failure = fn() -> OldError;

/// A V1 plugin as an out-of-tree one: its own storage, the published contract.
#[derive(Default)]
struct Plugin {
    values: Mutex<HashMap<Key, Vec<u8>>>,
    /// Every call answers with this error when set.
    fail_with: Mutex<Option<Failure>>,
}

impl Plugin {
    fn put(&self, tenant: Uuid, reference: &str, owner: Option<Uuid>, value: &[u8]) {
        self.values
            .lock()
            .unwrap()
            .insert((tenant, reference.to_owned(), owner), value.to_vec());
    }

    fn has(&self, tenant: Uuid, reference: &str, owner: Option<Uuid>) -> bool {
        self.values
            .lock()
            .unwrap()
            .contains_key(&(tenant, reference.to_owned(), owner))
    }
}

#[async_trait]
impl CredStorePluginClientV1 for Plugin {
    async fn get(
        &self,
        _ctx: &SecurityContext,
        tenant_id: &OldTenantId,
        key: &SecretRef,
        owner_id: Option<&OwnerId>,
    ) -> Result<Option<OldValue>, OldError> {
        if let Some(fail) = *self.fail_with.lock().unwrap() {
            return Err(fail());
        }
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(&(tenant_id.0, key.as_ref().to_owned(), owner_id.map(|o| o.0)))
            .cloned()
            .map(OldValue::new))
    }

    async fn put(
        &self,
        _ctx: &SecurityContext,
        tenant_id: &OldTenantId,
        key: &SecretRef,
        value: OldValue,
        owner_id: Option<&OwnerId>,
    ) -> Result<(), OldError> {
        self.put(
            tenant_id.0,
            key.as_ref(),
            owner_id.map(|o| o.0),
            value.as_bytes(),
        );
        Ok(())
    }

    async fn delete(
        &self,
        _ctx: &SecurityContext,
        tenant_id: &OldTenantId,
        key: &SecretRef,
        owner_id: Option<&OwnerId>,
    ) -> Result<(), OldError> {
        if let Some(fail) = *self.fail_with.lock().unwrap() {
            return Err(fail());
        }
        self.values.lock().unwrap().remove(&(
            tenant_id.0,
            key.as_ref().to_owned(),
            owner_id.map(|o| o.0),
        ));
        Ok(())
    }
}

fn store(plugin: &Arc<Plugin>) -> V1Store {
    V1Store::new(plugin.clone()).unwrap()
}

#[tokio::test]
async fn addressing_follows_the_owner_key_class_and_absent_is_none() {
    let plugin = Arc::new(Plugin::default());
    let (t, owner) = (tenant(1), Uuid::from_u128(0x77));
    plugin.put(t, "k", None, b"tenant class");
    plugin.put(t, "k", Some(owner), b"owner class");
    let store = store(&plugin);

    let tenant_value = store.get(t, "k", None).await.unwrap().unwrap();
    assert_eq!(tenant_value.as_bytes(), b"tenant class");
    let owner_value = store.get(t, "k", Some(owner)).await.unwrap().unwrap();
    assert_eq!(owner_value.as_bytes(), b"owner class");
    assert!(store.get(t, "missing", None).await.unwrap().is_none());
    assert!(store.get(tenant(2), "k", None).await.unwrap().is_none());

    // Delete follows the same addressing and an absent entry is success.
    store.delete(t, "k", Some(owner)).await.unwrap();
    assert!(!plugin.has(t, "k", Some(owner)));
    assert!(plugin.has(t, "k", None));
    store.delete(t, "k", Some(owner)).await.unwrap();
}

#[tokio::test]
async fn errors_are_classified_for_the_retry_policy() {
    let plugin = Arc::new(Plugin::default());
    let store = store(&plugin);

    for (fail, transient) in [
        ((|| OldError::service_unavailable("down")) as Failure, true),
        (|| OldError::internal("decrypt failed"), false),
        (|| OldError::AccessDenied, false),
    ] {
        *plugin.fail_with.lock().unwrap() = Some(fail);
        let err = store.get(tenant(1), "k", None).await.unwrap_err();
        assert_eq!(
            matches!(err, LegacyError::Unavailable(_)),
            transient,
            "{err}"
        );
        let err = store.delete(tenant(1), "k", None).await.unwrap_err();
        assert_eq!(
            matches!(err, LegacyError::Unavailable(_)),
            transient,
            "{err}"
        );
    }
    // A plugin that reports an absent entry as `NotFound` is read as absent.
    *plugin.fail_with.lock().unwrap() = Some(|| OldError::NotFound);
    assert!(store.get(tenant(1), "k", None).await.unwrap().is_none());
    store.delete(tenant(1), "k", None).await.unwrap();
}

#[tokio::test]
async fn a_reference_the_old_sdk_rejects_never_reaches_the_plugin() {
    let plugin = Arc::new(Plugin::default());
    *plugin.fail_with.lock().unwrap() = Some(|| panic!("the plugin must not be called"));
    let store = store(&plugin);
    for reference in ["has.a.dot", "", "with space", "colon:ed"] {
        let err = store.get(tenant(1), reference, None).await.unwrap_err();
        assert!(
            matches!(err, LegacyError::Failed(_)),
            "{reference:?}: {err}"
        );
    }
}

/// The whole tool through the bridge: a plugin of the published contract migrates
/// without any adapter of the operator's own.
#[tokio::test]
async fn a_published_v1_plugin_migrates_and_cleans_up_end_to_end() {
    let f = Fixture::sqlite().await;
    let plugin = Arc::new(Plugin::default());
    plugin.put(
        uuid::Uuid::nil(),
        "cfs-internal-fence-key",
        None,
        &common::FENCE_KEY,
    );
    let owner = Uuid::from_u128(0x77);
    let shared = Row::valued(1, tenant(1), "api-key");
    let private = Row::valued(2, tenant(1), "api-key").private(owner);
    let seeded = Row::valued(3, tenant(2), "seeded").without_fp();
    for row in [&shared, &private, &seeded] {
        f.insert(row).await;
        plugin.put(row.tenant, &row.reference, row.old_owner(), &row.value());
    }
    let legacy = store(&plugin);

    let run = f.run_with_stores(&legacy, &f.new, &["migrate"]).await;
    expect_exit(&run, Exit::Success);
    for row in [&shared, &private, &seeded] {
        let (status, version, _, _) = f.secret(row.id).await.unwrap();
        assert_eq!(status, 2, "{}", row.reference);
        let key = StoreKey::new(credstore_sdk::TenantId(row.tenant), row.id);
        assert_eq!(
            f.new.bytes(&key, &version.unwrap()).unwrap(),
            row.value(),
            "{}",
            row.reference
        );
        // Nothing was deleted from the old plugin by `migrate`.
        assert!(plugin.has(row.tenant, &row.reference, row.old_owner()));
    }

    let cleanup = f
        .run_with_stores(&legacy, &f.new, &["cleanup", "--include-fence-key"])
        .await;
    expect_exit(&cleanup, Exit::Success);
    for row in [&shared, &private, &seeded] {
        assert!(!plugin.has(row.tenant, &row.reference, row.old_owner()));
    }
    assert!(!plugin.has(Uuid::nil(), "cfs-internal-fence-key", None));
}
