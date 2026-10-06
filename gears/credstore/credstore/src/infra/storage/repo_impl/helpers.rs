// Updated: 2026-10-06 by Constructor Tech
//! Helpers shared across the `repo_impl` split: the repository adapter type,
//! entity/domain converters, and error mapping. Kept in one leaf module so
//! `reads`/`writes` and the parent depend on it one-way (no module cycle).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use credstore_sdk::{DestroySelector, OwnerId, SharingMode, StoreKey, TenantId, ValueVersion};
use sea_orm::{DbBackend, DbErr};
use toolkit_db::DBProvider;
use toolkit_db::secure::{DbTx, ScopeError, TxConfig};

use crate::domain::error::DomainError;
use crate::domain::secret::model::{
    CleanupDebt, CleanupTask, Fallback, HealFlags, SecretRow, SecretStatus,
};
use crate::infra::canonical_mapping::classify_db_err_to_domain;
use crate::infra::storage::entity;

pub type CredstoreDbProvider = DBProvider<DomainError>;

/// The boxed future a [`DBProvider::transaction`] closure returns.
pub(super) type TxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DomainError>> + Send + 'a>>;

/// The `DbErr` behind a repo failure, for the platform's transaction retry:
/// [`classify_db_err_to_domain`] keeps it as the cause of the errors the
/// retry may care about (`ServiceUnavailable` for a serialization failure,
/// `Internal` for the rest). A domain outcome carries none and is never
/// retried.
fn domain_db_err(e: &DomainError) -> Option<&DbErr> {
    let cause = match e {
        DomainError::ServiceUnavailable { cause, .. } | DomainError::Internal { cause, .. } => {
            cause.as_deref()?
        }
        _ => return None,
    };
    cause.downcast_ref::<DbErr>()
}

/// `SeaORM` repository adapter for
/// [`SecretRepo`](crate::domain::secret::repo::SecretRepo).
pub struct SecretRepoImpl {
    pub(crate) db: Arc<CredstoreDbProvider>,
}

impl SecretRepoImpl {
    #[must_use]
    pub fn new(db: Arc<CredstoreDbProvider>) -> Self {
        Self { db }
    }

    /// Runs `body` as ONE transaction through the platform's transaction
    /// retry (`Db::transaction_with_retry`: 3 attempts, millisecond backoff
    /// with jitter). Only an error the database rolled back definitively is
    /// retried (`PostgreSQL` serialization failure `40001`, deadlock
    /// `40P01`, `SQLite` busy); an ambiguous commit (the connection lost
    /// around `COMMIT`) is never retried here and surfaces as an error for
    /// the service's verification.
    ///
    /// `body` may run several times: it must contain SQL only and be
    /// idempotent (no store call, no metric, no "success" log), and it must
    /// clone whatever it needs into the future it returns.
    pub(super) async fn run_tx<T, F>(&self, body: F) -> Result<T, DomainError>
    where
        T: Send + 'static,
        F: for<'a> FnMut(&'a DbTx<'a>) -> TxFuture<'a, T> + Send,
    {
        self.db
            .db()
            .transaction_with_retry(TxConfig::default(), domain_db_err, body)
            .await
    }
}

/// The database's current instant as SQL text, in the column's own format:
/// `now()` on `PostgreSQL`, an ISO-8601 `strftime` on `SQLite` (timestamps are
/// TEXT there). Never bound from the process, so instances with skewed clocks
/// agree on when a lease is over.
pub(crate) fn db_now_sql(backend: DbBackend) -> &'static str {
    match backend {
        DbBackend::Sqlite => "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        _ => "now()",
    }
}

/// `credstore_store_cleanup.op` codes.
const OP_PURGE: i16 = 1;
const OP_DESTROY: i16 = 2;
/// `credstore_store_cleanup.selector` codes (destroy only).
const SELECTOR_BELOW: i16 = 1;
const SELECTOR_EXACT: i16 = 2;

/// The `(op, selector, version)` columns of a debt row for `task`.
pub(crate) fn task_to_columns(task: &CleanupTask) -> (i16, Option<i16>, Option<String>) {
    match task {
        CleanupTask::Purge(_) => (OP_PURGE, None, None),
        CleanupTask::Destroy { selector, .. } => match selector {
            DestroySelector::Below(v) => (OP_DESTROY, Some(SELECTOR_BELOW), Some(v.0.clone())),
            DestroySelector::Exactly(v) => (OP_DESTROY, Some(SELECTOR_EXACT), Some(v.0.clone())),
        },
    }
}

/// Map a `credstore_store_cleanup` row to the domain [`CleanupDebt`]. A
/// stored code outside the documented set is storage corruption, like any
/// other out-of-domain column.
pub(crate) fn entity_to_debt(m: entity::store_cleanup::Model) -> Result<CleanupDebt, DomainError> {
    let corrupt = |what: &str| DomainError::Internal {
        diagnostic: format!("credstore_store_cleanup out-of-domain {what}"),
        cause: None,
    };
    let key = StoreKey::new(TenantId(m.tenant_id), m.record_id);
    let task = match (m.op, m.selector, m.version) {
        (OP_PURGE, None, None) => CleanupTask::Purge(key),
        (OP_DESTROY, Some(SELECTOR_BELOW), Some(v)) => CleanupTask::Destroy {
            key,
            selector: DestroySelector::Below(ValueVersion(v)),
        },
        (OP_DESTROY, Some(SELECTOR_EXACT), Some(v)) => CleanupTask::Destroy {
            key,
            selector: DestroySelector::Exactly(ValueVersion(v)),
        },
        _ => return Err(corrupt("op/selector/version combination")),
    };
    Ok(CleanupDebt { id: m.id, task })
}

/// Map an entity row to the domain [`SecretRow`].
pub(crate) fn entity_to_model(m: entity::secrets::Model) -> Result<SecretRow, DomainError> {
    let sharing = sharing_from_i16(m.sharing).ok_or_else(|| DomainError::Internal {
        diagnostic: format!(
            "credstore_secrets.sharing out-of-domain value: {}",
            m.sharing
        ),
        cause: None,
    })?;
    let status = SecretStatus::from_smallint(m.status).ok_or_else(|| DomainError::Internal {
        diagnostic: format!("credstore_secrets.status out-of-domain value: {}", m.status),
        cause: None,
    })?;
    let fallback = Fallback::from_smallint(m.fallback).ok_or_else(|| DomainError::Internal {
        diagnostic: format!(
            "credstore_secrets.fallback out-of-domain value: {}",
            m.fallback
        ),
        cause: None,
    })?;
    Ok(SecretRow {
        id: m.id,
        tenant_id: TenantId(m.tenant_id),
        reference: m.reference,
        sharing,
        owner_id: OwnerId(m.owner_id),
        status,
        version: m.version,
        updated_at: m.updated_at,
        // Opaque here: the domain layer resolves the UUID to the type id +
        // traits via the types-registry, so non-catalog types round-trip.
        secret_type_uuid: m.secret_type_uuid,
        expires_at: m.expires_at,
        value_version: m.value_version.map(ValueVersion),
        fallback,
        heal: HealFlags::default(),
    })
}

/// Map [`SharingMode`] to its `SMALLINT` storage value.
pub(crate) fn sharing_to_i16(s: SharingMode) -> i16 {
    match s {
        SharingMode::Private => 1,
        SharingMode::Tenant => 2,
        SharingMode::Shared => 3,
    }
}

/// Map a `SMALLINT` storage value to [`SharingMode`].
pub(crate) fn sharing_from_i16(v: i16) -> Option<SharingMode> {
    match v {
        1 => Some(SharingMode::Private),
        2 => Some(SharingMode::Tenant),
        3 => Some(SharingMode::Shared),
        _ => None,
    }
}

/// Map a [`ScopeError`] to a [`DomainError`] outside a retry boundary.
pub(super) fn map_scope_err(err: ScopeError) -> DomainError {
    match err {
        ScopeError::Db(db) => classify_db_err_to_domain(db),
        ScopeError::Invalid(msg) => DomainError::Internal {
            diagnostic: format!("scope invalid: {msg}"),
            cause: None,
        },
        ScopeError::TenantNotInScope { .. } => DomainError::AccessDenied { cause: None },
        ScopeError::Denied(msg) => DomainError::Internal {
            diagnostic: format!("unexpected access denied in credstore repo: {msg}"),
            cause: None,
        },
        // `ScopeError` is `#[non_exhaustive]`: variants this gear has no
        // specific answer for (today the graph-query refusals, which it can
        // never trigger) map to an internal error, like `Invalid`.
        other => DomainError::Internal {
            diagnostic: format!("scope invalid: {other}"),
            cause: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, DbErr};
    use time::OffsetDateTime;
    use toolkit_db::secure::ScopeError;
    use uuid::Uuid;

    use super::{
        domain_db_err, entity_to_debt, entity_to_model, map_scope_err, sharing_from_i16,
        sharing_to_i16, task_to_columns,
    };
    use crate::domain::error::DomainError;
    use crate::domain::secret::model::{Fallback, SecretStatus};
    use crate::infra::storage::entity;
    use credstore_sdk::SharingMode;

    /// An `Active`, `Tenant`-shared row with every column in domain.
    fn row() -> entity::secrets::Model {
        entity::secrets::Model {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            reference: "openai-key".to_owned(),
            sharing: 2,
            owner_id: Uuid::nil(),
            status: 2,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH,
            version: 1,
            secret_type_uuid: Uuid::new_v4(),
            expires_at: None,
            value_version: Some("7".to_owned()),
            fallback: 1,
        }
    }

    #[test]
    fn sharing_round_trips_through_its_smallint_encoding() {
        for mode in [
            SharingMode::Private,
            SharingMode::Tenant,
            SharingMode::Shared,
        ] {
            assert_eq!(sharing_from_i16(sharing_to_i16(mode)), Some(mode));
        }
        // Codes outside the stored domain have no mode.
        assert_eq!(sharing_from_i16(0), None);
        assert_eq!(sharing_from_i16(4), None);
    }

    #[test]
    fn entity_to_model_maps_every_column_onto_the_domain_row() {
        let m = row();
        let (id, tenant_id) = (m.id, m.tenant_id);
        let mapped = entity_to_model(m).expect("in-domain row maps");
        assert_eq!(mapped.id, id);
        assert_eq!(mapped.tenant_id.0, tenant_id);
        assert_eq!(mapped.reference, "openai-key");
        assert_eq!(mapped.sharing, SharingMode::Tenant);
        assert_eq!(mapped.status, SecretStatus::Active);
        assert_eq!(mapped.fallback, Fallback::Inherit);
        assert_eq!(mapped.value_version.map(|v| v.0).as_deref(), Some("7"));
    }

    #[test]
    fn entity_to_model_reports_each_out_of_domain_column_as_internal() {
        for (column, m) in [
            (
                "sharing",
                entity::secrets::Model {
                    sharing: 9,
                    ..row()
                },
            ),
            ("status", entity::secrets::Model { status: 9, ..row() }),
            (
                "fallback",
                entity::secrets::Model {
                    fallback: 9,
                    ..row()
                },
            ),
        ] {
            let err = entity_to_model(m).expect_err("out-of-domain column must be rejected");
            let DomainError::Internal { diagnostic, .. } = err else {
                panic!("{column}: expected Internal");
            };
            assert!(
                diagnostic.contains(column),
                "{column}: diagnostic must name the column, got {diagnostic}"
            );
        }
    }

    #[test]
    fn debt_columns_round_trip_through_the_domain_task() {
        use crate::domain::secret::model::CleanupTask;
        use credstore_sdk::{DestroySelector, StoreKey, TenantId, ValueVersion};

        let key = StoreKey::new(TenantId(Uuid::new_v4()), Uuid::new_v4());
        for task in [
            CleanupTask::Purge(key.clone()),
            CleanupTask::Destroy {
                key: key.clone(),
                selector: DestroySelector::Below(ValueVersion("7".to_owned())),
            },
            CleanupTask::Destroy {
                key: key.clone(),
                selector: DestroySelector::Exactly(ValueVersion("7".to_owned())),
            },
        ] {
            let (op, selector, version) = task_to_columns(&task);
            let id = Uuid::new_v4();
            let debt = entity_to_debt(entity::store_cleanup::Model {
                id,
                tenant_id: key.tenant_id.0,
                record_id: key.record_id,
                op,
                selector,
                version,
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
            .expect("in-domain row maps");
            assert_eq!(debt.id, id);
            assert_eq!(debt.task, task);
        }
    }

    #[test]
    fn a_debt_row_with_a_corrupt_shape_is_internal() {
        let bad = |op: i16, selector: Option<i16>, version: Option<&str>| {
            entity_to_debt(entity::store_cleanup::Model {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                record_id: Uuid::new_v4(),
                op,
                selector,
                version: version.map(str::to_owned),
                created_at: OffsetDateTime::UNIX_EPOCH,
            })
        };
        for (op, selector, version) in [
            (9, None, None),
            (1, Some(1), None),
            (2, None, Some("7")),
            (2, Some(3), Some("7")),
        ] {
            assert!(matches!(
                bad(op, selector, version),
                Err(DomainError::Internal { .. })
            ));
        }
    }

    #[test]
    fn maps_each_scope_error_variant() {
        assert!(matches!(
            map_scope_err(ScopeError::Invalid("bad scope")),
            DomainError::Internal { .. }
        ));
        assert!(matches!(
            map_scope_err(ScopeError::TenantNotInScope {
                tenant_id: Uuid::new_v4()
            }),
            DomainError::AccessDenied { .. }
        ));
        assert!(matches!(
            map_scope_err(ScopeError::Denied("not accessible")),
            DomainError::Internal { .. }
        ));
        // Db errors delegate to the classification ladder (CHECK violations
        // are server-side invariants → Internal).
        assert!(matches!(
            map_scope_err(ScopeError::Db(DbErr::Custom(
                "CHECK constraint failed".to_owned()
            ))),
            DomainError::Internal { .. }
        ));
    }

    #[test]
    fn the_retry_sees_the_db_error_of_contention_but_not_of_domain_outcomes() {
        use toolkit_db::contention::is_retryable_contention;

        // A serialization failure and a deadlock keep their `DbErr` through
        // the classification, so the platform retry can recognise them.
        for msg in [
            "could not serialize access (SQLSTATE 40001)",
            "deadlock detected (SQLSTATE 40P01)",
        ] {
            let mapped = map_scope_err(ScopeError::Db(DbErr::Custom(msg.to_owned())));
            let db_err = domain_db_err(&mapped).expect("the cause is kept");
            assert!(is_retryable_contention(DbBackend::Postgres, db_err));
        }
        // A connection failure is visible but not retryable (it may be an
        // ambiguous commit); a domain outcome carries no `DbErr` at all.
        let lost = map_scope_err(ScopeError::Db(DbErr::Custom("connection reset".to_owned())));
        let db_err = domain_db_err(&lost).expect("the cause is kept");
        assert!(!is_retryable_contention(DbBackend::Postgres, db_err));
        assert!(domain_db_err(&DomainError::NotFound).is_none());
        assert!(domain_db_err(&DomainError::Conflict).is_none());
    }
}
