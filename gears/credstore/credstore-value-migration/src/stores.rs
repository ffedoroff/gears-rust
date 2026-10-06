// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The two stores the tool talks to, wrapped with the retry policy.
//!
//! * the OLD store, through [`LegacyStore`] (only `get` and `delete`), addressed
//!   `(tenant, reference, owner)` the way the shipped gear addressed it;
//! * the NEW store, through the current `CredStorePluginClientV2`.
//!
//! A transient answer (`LegacyError::Unavailable`, `ServiceUnavailable`) is
//! retried with a bounded backoff; any other error is final for the run. After
//! the last attempt the error aborts the run (exit code `1`); what was
//! persisted so far stays.

use std::future::Future;
use std::time::Duration;

use credstore_sdk::{
    CredStoreError, CredStorePluginClientV2, DestroySelector, SecretValue, StoreKey, TenantId,
    ValueVersion,
};
use toolkit_security::SecurityContext;
use uuid::Uuid;

use crate::error::MigrationError;
use crate::fence::FENCE_KEY_REF;
use crate::legacy::{LegacyError, LegacyStore};
use crate::state::ProgressRow;

/// Knobs of a run. [`Tuning::default`] is what an operator gets.
#[derive(Debug, Clone)]
pub struct Tuning {
    /// Attempts per store call, the first one included (`1` disables retries).
    pub attempts: u32,
    /// Pause before the second attempt; it doubles for every further attempt.
    pub base_delay: Duration,
    /// Longest pause between two attempts.
    pub max_delay: Duration,
    /// Rows read from the progress table per batch (and per log line).
    pub batch_size: u32,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            attempts: 5,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            batch_size: 200,
        }
    }
}

impl Tuning {
    /// No pauses between attempts and small batches: for tests.
    #[must_use]
    pub fn immediate() -> Self {
        Self {
            attempts: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            batch_size: 2,
        }
    }

    /// The pause before attempt `next` (2-based: the pause after attempt 1 is
    /// `delay_before(2)`).
    fn delay_before(&self, next: u32) -> Duration {
        let doublings = next.saturating_sub(2).min(20);
        self.base_delay
            .saturating_mul(1_u32 << doublings)
            .min(self.max_delay)
    }
}

/// Runs `op` until it succeeds, fails with a final error, or `tuning.attempts`
/// attempts were used.
async fn retry<T, E, Fut>(
    tuning: &Tuning,
    what: &'static str,
    transient: impl Fn(&E) -> bool,
    mut op: impl FnMut() -> Fut,
) -> Result<T, E>
where
    E: std::fmt::Display,
    Fut: Future<Output = Result<T, E>>,
{
    let mut attempt = 1;
    loop {
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if transient(&e) && attempt < tuning.attempts => {
                attempt += 1;
                let pause = tuning.delay_before(attempt);
                tracing::warn!(
                    what,
                    attempt,
                    pause_ms = u64::try_from(pause.as_millis()).unwrap_or(u64::MAX),
                    error = %e,
                    "credstore value migration: transient store error, retrying"
                );
                tokio::time::sleep(pause).await;
            }
            Err(e) => return Err(e),
        }
    }
}

fn old_transient(e: &LegacyError) -> bool {
    matches!(e, LegacyError::Unavailable(_))
}

fn new_transient(e: &CredStoreError) -> bool {
    matches!(e, CredStoreError::ServiceUnavailable { .. })
}

/// The address of an entry in the old store.
#[derive(Debug, Clone)]
pub struct OldAddress {
    /// Tenant key.
    pub tenant_id: Uuid,
    /// Reference.
    pub reference: String,
    /// `Some` only for the owner's key class.
    pub owner_id: Option<Uuid>,
}

impl OldAddress {
    /// The old address of a snapshot row: private rows (`sharing = 1`) carry their
    /// owner, every other row is the tenant key class.
    #[must_use]
    pub fn of(row: &ProgressRow) -> Self {
        Self {
            tenant_id: row.tenant_id,
            reference: row.reference.clone(),
            owner_id: row.legacy_owner(),
        }
    }

    /// Where the old gear kept its fence key: nil tenant, tenant key class.
    #[must_use]
    pub fn fence_key() -> Self {
        Self {
            tenant_id: Uuid::nil(),
            reference: FENCE_KEY_REF.to_owned(),
            owner_id: None,
        }
    }
}

/// The old store with the retry policy.
pub struct OldStore<'a> {
    inner: &'a dyn LegacyStore,
    tuning: Tuning,
}

impl<'a> OldStore<'a> {
    /// Wraps the old store.
    #[must_use]
    pub fn new(inner: &'a dyn LegacyStore, tuning: Tuning) -> Self {
        Self { inner, tuning }
    }

    /// Reads the current value; `None` when the entry is absent.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Legacy`] when the store cannot answer.
    pub async fn get(&self, addr: &OldAddress) -> Result<Option<SecretValue>, MigrationError> {
        retry(&self.tuning, "old store get", old_transient, || {
            self.inner
                .get(addr.tenant_id, &addr.reference, addr.owner_id)
        })
        .await
        .map_err(|source| MigrationError::Legacy { row: None, source })
    }

    /// Deletes the entry; an absent entry is success.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Legacy`] when the store cannot delete.
    pub async fn delete(&self, addr: &OldAddress) -> Result<(), MigrationError> {
        retry(&self.tuning, "old store delete", old_transient, || {
            self.inner
                .delete(addr.tenant_id, &addr.reference, addr.owner_id)
        })
        .await
        .map_err(|source| MigrationError::Legacy { row: None, source })
    }
}

/// The new store with the retry policy.
pub struct NewStore<'a> {
    inner: &'a dyn CredStorePluginClientV2,
    ctx: SecurityContext,
    tuning: Tuning,
}

impl<'a> NewStore<'a> {
    /// Wraps the new plugin.
    #[must_use]
    pub fn new(
        inner: &'a dyn CredStorePluginClientV2,
        ctx: SecurityContext,
        tuning: Tuning,
    ) -> Self {
        Self { inner, ctx, tuning }
    }

    /// Whether the store can destroy versions (and so has ordered versions).
    #[must_use]
    pub fn supports_destroy(&self) -> bool {
        self.inner.supports_destroy()
    }

    /// Stores a new version of `key`. A `put` whose answer was lost leaves a
    /// version nobody points at; the tidy phase destroys it.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Target`] when the store cannot store.
    pub async fn put(&self, key: &StoreKey, value: &[u8]) -> Result<ValueVersion, MigrationError> {
        retry(&self.tuning, "new store put", new_transient, || {
            self.inner
                .put(&self.ctx, key, SecretValue::new(value.to_vec()))
        })
        .await
        .map_err(MigrationError::Target)
    }

    /// Reads a version back.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Target`] when the store cannot answer.
    pub async fn get(
        &self,
        key: &StoreKey,
        version: &ValueVersion,
    ) -> Result<Option<SecretValue>, MigrationError> {
        retry(&self.tuning, "new store get", new_transient, || {
            self.inner.get(&self.ctx, key, version)
        })
        .await
        .map_err(MigrationError::Target)
    }

    /// Destroys every version of `key` below `version`.
    ///
    /// # Errors
    ///
    /// [`MigrationError::Target`] when the store cannot destroy.
    pub async fn destroy_below(
        &self,
        key: &StoreKey,
        version: &ValueVersion,
    ) -> Result<(), MigrationError> {
        retry(&self.tuning, "new store destroy", new_transient, || {
            self.inner
                .destroy(&self.ctx, key, DestroySelector::Below(version.clone()))
        })
        .await
        .map_err(MigrationError::Target)
    }

    /// The pause policy, for the read-back loop.
    #[must_use]
    pub fn tuning(&self) -> &Tuning {
        &self.tuning
    }
}

/// The key of a record in the new store.
#[must_use]
pub fn store_key(row: &ProgressRow) -> StoreKey {
    StoreKey::new(TenantId(row.tenant_id), row.id)
}

/// Fixed identity of the migration tool, used as the subject and tenant of
/// the security context handed to both stores. Plugins use the context for
/// correlation only. Public so a bridge to another contract generation can hand
/// the old store the same identity.
pub const TOOL_ID: Uuid = Uuid::from_u128(0x6d69_6772_6174_696f_6e2d_746f_6f6c_0001);

/// The context for the NEW store.
pub(crate) fn tool_context() -> Result<SecurityContext, MigrationError> {
    SecurityContext::builder()
        .subject_id(TOOL_ID)
        .subject_tenant_id(TOOL_ID)
        .subject_type("service")
        .build()
        .map_err(|e| {
            MigrationError::State(format!("cannot build the migration security context: {e}"))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::use_debug, reason = "tests")]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn backoff_doubles_and_is_capped() {
        let t = Tuning::default();
        let pauses: Vec<u64> = (2..=7).map(|n| t.delay_before(n).as_secs()).collect();
        assert_eq!(pauses, [1, 2, 4, 8, 16, 30]);
        assert_eq!(Tuning::immediate().delay_before(5), Duration::ZERO);
    }

    #[tokio::test]
    async fn retry_stops_on_success_on_a_final_error_and_when_attempts_run_out() {
        let tuning = Tuning::immediate();
        let calls = AtomicU32::new(0);
        let transient = |e: &String| e == "again";

        // Transient twice, then success.
        let ok = retry(&tuning, "t", transient, || async {
            if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                Err("again".to_owned())
            } else {
                Ok(7)
            }
        })
        .await;
        assert_eq!((ok, calls.load(Ordering::SeqCst)), (Ok(7), 3));

        // A final error is not retried.
        calls.store(0, Ordering::SeqCst);
        let err: Result<u32, String> = retry(&tuning, "t", transient, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("fatal".to_owned())
        })
        .await;
        assert_eq!(
            (err, calls.load(Ordering::SeqCst)),
            (Err("fatal".to_owned()), 1)
        );

        // Transient forever: `attempts` tries, then the error.
        calls.store(0, Ordering::SeqCst);
        let err: Result<u32, String> = retry(&tuning, "t", transient, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            Err("again".to_owned())
        })
        .await;
        assert_eq!(
            (err, calls.load(Ordering::SeqCst)),
            (Err("again".to_owned()), tuning.attempts)
        );
    }

    #[test]
    fn only_service_unavailable_is_transient() {
        assert!(old_transient(&LegacyError::Unavailable("x".to_owned())));
        assert!(!old_transient(&LegacyError::Failed("x".to_owned())));
        assert!(new_transient(&CredStoreError::service_unavailable("x")));
        assert!(!new_transient(&CredStoreError::internal("x")));
    }

    fn row(sharing: i16, reference: &str) -> ProgressRow {
        use crate::state::RowState;
        ProgressRow {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            reference: reference.to_owned(),
            sharing,
            owner_id: Uuid::from_u128(3),
            status_before: 2,
            secret_type_uuid: Uuid::nil(),
            value_fp: None,
            fp_key_id: None,
            state: RowState::Pending,
            value_version: None,
            activated: false,
            tidied: false,
        }
    }

    #[test]
    fn the_old_address_of_a_row_is_what_the_shipped_gear_passed_to_the_plugin() {
        // Private: the owner's key class. Shared and tenant-wide: the tenant key class.
        let private = OldAddress::of(&row(1, "db-password"));
        assert_eq!(
            (
                private.tenant_id,
                private.reference.as_str(),
                private.owner_id
            ),
            (Uuid::from_u128(2), "db-password", Some(Uuid::from_u128(3)))
        );
        for sharing in [2, 3] {
            let a = OldAddress::of(&row(sharing, "db-password"));
            assert_eq!(a.owner_id, None, "sharing {sharing}");
        }
    }

    #[test]
    fn the_fence_key_address_is_the_nil_tenant_tenant_class() {
        let a = OldAddress::fence_key();
        assert_eq!(
            (a.tenant_id, a.reference.as_str(), a.owner_id),
            (Uuid::nil(), "cfs-internal-fence-key", None)
        );
    }
}
