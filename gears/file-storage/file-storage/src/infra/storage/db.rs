//! Database error conversion helpers.
//!
//! Three tiers, from least to most specific:
//!
//! 1. `db_err`: any `Display` error becomes `DomainError::Database` (HTTP 500).
//! 2. `conflict_on_unique_violation` / `file_not_found_on_foreign_key_violation`: classify a
//!    typed error (`DbErr` or `ScopeError`) right at the failing query, mapping a unique
//!    violation to `Conflict` (409) and a foreign-key violation to `FileNotFound` (404).
//! 3. `transaction_with_bounded_retry`: retries a transaction on lock contention; it works on
//!    an already-mapped `DomainError` because the typed error is gone by then.

use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use sea_orm::{DbBackend, DbErr};
use toolkit_db::contention::is_retryable_contention;
use toolkit_db::secure::{
    DEFAULT_TX_RETRY_ATTEMPTS, Db, DbTx, ScopeError,
    is_foreign_key_violation as toolkit_is_foreign_key_violation,
    is_unique_violation as toolkit_is_unique_violation,
};
use uuid::Uuid;

use crate::domain::error::DomainError;

/// Extracts the raw SQLSTATE/vendor code from a `DbErr`, when the driver error carries one
/// (unlike the `Display` text, it is never translated by the server's `lc_messages`).
fn sqlstate(err: &DbErr) -> Option<String> {
    let (DbErr::Exec(sea_orm::RuntimeErr::SqlxError(e))
    | DbErr::Query(sea_orm::RuntimeErr::SqlxError(e))) = err
    else {
        return None;
    };
    let sea_orm::sqlx::Error::Database(driver_err) = e.as_ref() else {
        return None;
    };
    driver_err.code().map(std::borrow::Cow::into_owned)
}

/// SQLSTATE behind either of the two error shapes this gear passes to `db_err`, via a runtime
/// downcast.
fn sqlstate_of_any(e: &dyn std::any::Any) -> Option<String> {
    if let Some(db_err) = e.downcast_ref::<DbErr>() {
        return sqlstate(db_err);
    }
    if let Some(ScopeError::Db(db_err)) = e.downcast_ref::<ScopeError>() {
        return sqlstate(db_err);
    }
    None
}

/// Converts any displayable error into `DomainError::Database`; every classifier here falls
/// back to this shape.
///
/// When the error is (or wraps) a `DbErr` with a driver SQLSTATE, `(SQLSTATE <code>)` is
/// appended to the message, so `is_retryable_domain_error` can recognize contention even on
/// a non-English server.
pub fn db_err(e: impl Display + 'static) -> DomainError {
    let message = e.to_string();
    let message = match sqlstate_of_any(&e) {
        Some(code) => format!("{message} (SQLSTATE {code})"),
        None => message,
    };
    DomainError::database(message)
}

/// A database error that can report whether it wraps a constraint violation.
///
/// Implemented for the two shapes that reach this module: `DbErr` (raw queries) and
/// `ScopeError` (anything routed through `.secure()`).
pub trait ClassifiableDbError: Display {
    /// Whether `self` is a unique-constraint violation (detection rules in
    /// `toolkit_db::secure::error`).
    fn is_unique_violation(&self) -> bool;

    /// Whether `self` is a foreign-key violation.
    fn is_foreign_key_violation(&self) -> bool;
}

impl ClassifiableDbError for DbErr {
    fn is_unique_violation(&self) -> bool {
        toolkit_is_unique_violation(self)
    }

    fn is_foreign_key_violation(&self) -> bool {
        toolkit_is_foreign_key_violation(self)
    }
}

impl ClassifiableDbError for ScopeError {
    fn is_unique_violation(&self) -> bool {
        // Other variants are scope/validation errors the database never saw.
        match self {
            Self::Db(db_err) => toolkit_is_unique_violation(db_err),
            _ => false,
        }
    }

    fn is_foreign_key_violation(&self) -> bool {
        // Other variants are scope/validation errors the database never saw.
        match self {
            Self::Db(db_err) => toolkit_is_foreign_key_violation(db_err),
            _ => false,
        }
    }
}

/// A unique-constraint violation becomes `DomainError::Conflict` (409) with
/// `conflict_message`; anything else falls back to `db_err` (500).
///
/// `conflict_message` is sent to the client verbatim, so it must be safe to expose; the
/// original error text is only logged at `DEBUG`. Use it only where a unique index holds an
/// application-level invariant (`repo/idempotency_repo.rs::insert`,
/// `repo/policy_repo.rs::upsert`).
pub fn conflict_on_unique_violation<E: ClassifiableDbError + 'static>(
    e: E,
    conflict_message: impl Into<String>,
) -> DomainError {
    if e.is_unique_violation() {
        let message = conflict_message.into();
        tracing::debug!(
            error = %e,
            conflict_message = %message,
            "database unique-constraint violation classified as a conflict"
        );
        DomainError::conflict(message)
    } else {
        db_err(e)
    }
}

/// A foreign-key violation becomes `DomainError::FileNotFound` (404); anything else falls back
/// to `db_err` (500).
///
/// The only foreign key that can fail under a race is `file_versions.file_id` /
/// `multipart_uploads.file_id` -> `files.file_id`: the parent row was deleted concurrently
/// after the caller read it, which is exactly `FileNotFound`.
pub fn file_not_found_on_foreign_key_violation<E: ClassifiableDbError + 'static>(
    e: E,
    file_id: Uuid,
) -> DomainError {
    if e.is_foreign_key_violation() {
        tracing::debug!(
            error = %e,
            %file_id,
            "foreign-key violation against a deleted file classified as file-not-found"
        );
        DomainError::file_not_found(file_id)
    } else {
        db_err(e)
    }
}

/// Attempt budget for `transaction_with_bounded_retry`: the workspace-standard
/// `DEFAULT_TX_RETRY_ATTEMPTS` (first try plus two retries).
const TX_RETRY_ATTEMPTS: u32 = DEFAULT_TX_RETRY_ATTEMPTS;

/// Base delay, growth factor and cap for `retry_backoff_delay`; small because the retried
/// transactions are a few point writes.
const RETRY_BACKOFF_BASE_MS: u64 = 10;
const RETRY_BACKOFF_FACTOR: u64 = 2;
const RETRY_BACKOFF_MAX: Duration = Duration::from_millis(200);

/// Jittered exponential backoff before retry attempt `next_attempt` (`>= 2`; the first try is
/// never delayed). Reimplements the private `toolkit_db::secure::db` helper; the jitter keeps
/// two transactions that just deadlocked from retrying at the same instant.
fn retry_backoff_delay(next_attempt: u32) -> Duration {
    use tokio_retry::strategy::{ExponentialBackoff, jitter};

    debug_assert!(
        next_attempt >= 2,
        "attempt 1 (the first try) is never delayed"
    );
    let index = next_attempt.saturating_sub(2) as usize;

    let base = ExponentialBackoff::from_millis(RETRY_BACKOFF_BASE_MS)
        .factor(RETRY_BACKOFF_FACTOR)
        .max_delay(RETRY_BACKOFF_MAX)
        .nth(index)
        .unwrap_or(RETRY_BACKOFF_MAX);

    jitter(base)
}

/// Re-derives contention classification for an already-mapped `DomainError`.
///
/// The repositories have flattened the typed error into a `DomainError::Database` string, so
/// the stored message is re-wrapped in `DbErr::Custom` and matched by
/// `is_retryable_contention`. This is locale-independent when `db_err` appended a SQLSTATE;
/// without one it falls back to (locale-dependent) message matching. Other `DomainError`
/// variants are domain decisions and are never retried.
fn is_retryable_domain_error(e: &DomainError, backend: DbBackend) -> bool {
    match e {
        DomainError::Database { message } => {
            is_retryable_contention(backend, &DbErr::Custom(message.clone()))
        }
        _ => false,
    }
}

/// Runs a transaction, retrying a bounded number of times on lock contention (`PostgreSQL`
/// `40001`/`40P01`, `MySQL` deadlock, `SQLite` `BUSY`; see `toolkit_db::contention`).
///
/// Bespoke instead of `Db::transaction_with_retry`, which needs an accessor back to the
/// original `DbErr` that `DomainError::Database` (a `String`) cannot provide.
///
/// `body` is `FnMut`: call sites clone their captured state inside it once per attempt, since
/// `Db::transaction_ref_mapped` consumes an `FnOnce`.
///
/// `body` must have no side effects outside the transaction (network calls, spawned tasks),
/// as each retry re-runs it from a fresh `BEGIN`. Outbox rows are fine: they are written in
/// the same transaction. Not every transaction in the gear is wrapped.
///
/// # Errors
///
/// Returns the last `DomainError` once `TX_RETRY_ATTEMPTS` is exhausted, or immediately for a
/// non-retryable error.
pub async fn transaction_with_bounded_retry<T, F>(db: &Db, mut body: F) -> Result<T, DomainError>
where
    T: Send + 'static,
    F: for<'a> FnMut(
            &'a DbTx<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<T, DomainError>> + Send + 'a>>
        + Send,
{
    let backend = db.backend();
    let mut attempt: u32 = 1;

    loop {
        let result = db.transaction_ref_mapped(|tx| body(tx)).await;

        match result {
            Ok(value) => return Ok(value),
            Err(e) => {
                if attempt < TX_RETRY_ATTEMPTS && is_retryable_domain_error(&e, backend) {
                    let next_attempt = attempt + 1;
                    let delay = retry_backoff_delay(next_attempt);
                    tracing::warn!(
                        attempt,
                        max_attempts = TX_RETRY_ATTEMPTS,
                        delay = ?delay,
                        error = %e,
                        "retrying transaction after a likely lock-contention failure"
                    );
                    tokio::time::sleep(delay).await;
                    attempt = next_attempt;
                    continue;
                }
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use sea_orm::{DbBackend, DbErr, RuntimeErr};
    use toolkit_db::secure::ScopeError;

    use super::{
        TX_RETRY_ATTEMPTS, conflict_on_unique_violation, db_err, is_retryable_domain_error,
        transaction_with_bounded_retry,
    };
    use crate::domain::error::DomainError;

    #[test]
    fn unique_violation_dberr_becomes_conflict() {
        let err = DbErr::Custom(
            "duplicate key value violates unique constraint \
             \"policies_tenant_scope_unique_idx\""
                .to_owned(),
        );
        let mapped = conflict_on_unique_violation(err, "policy already exists for this scope");
        assert!(
            matches!(mapped, DomainError::Conflict { .. }),
            "expected Conflict, got {mapped:?}"
        );
    }

    #[test]
    fn non_unique_dberr_falls_back_to_database() {
        let err = DbErr::Custom("connection reset by peer".to_owned());
        let mapped = conflict_on_unique_violation(err, "should never be used");
        assert!(
            matches!(mapped, DomainError::Database { .. }),
            "expected Database (the db_err fallback), got {mapped:?}"
        );
    }

    #[test]
    fn unique_violation_scope_error_becomes_conflict() {
        let err = ScopeError::Db(DbErr::Custom(
            "UNIQUE constraint failed: idempotency_keys.idempotency_key".to_owned(),
        ));
        let mapped = conflict_on_unique_violation(err, "idempotency key already claimed");
        assert!(
            matches!(mapped, DomainError::Conflict { .. }),
            "expected Conflict, got {mapped:?}"
        );
    }

    #[test]
    fn non_db_scope_error_falls_back_to_database() {
        let err = ScopeError::Invalid("tenant_id is required");
        let mapped = conflict_on_unique_violation(err, "should never be used");
        assert!(
            matches!(mapped, DomainError::Database { .. }),
            "expected Database (the db_err fallback), got {mapped:?}"
        );
    }

    #[test]
    fn fallback_matches_db_err_exactly() {
        let err = DbErr::Custom("connection reset by peer".to_owned());
        let via_classifier = conflict_on_unique_violation(err.clone(), "unused");
        let via_db_err = db_err(err);
        match (via_classifier, via_db_err) {
            (DomainError::Database { message: a }, DomainError::Database { message: b }) => {
                assert_eq!(a, b);
            }
            other => panic!("expected two Database variants, got {other:?}"),
        }
    }

    #[test]
    fn retryable_contention_detected_through_the_db_err_round_trip() {
        let raw = DbErr::Exec(RuntimeErr::Internal(
            "error returned from database: deadlock detected".to_owned(),
        ));
        let domain_err = db_err(raw);
        assert!(is_retryable_domain_error(&domain_err, DbBackend::Postgres));
    }

    #[test]
    fn non_contention_database_error_not_retried() {
        let domain_err = DomainError::database("connection reset by peer");
        assert!(!is_retryable_domain_error(&domain_err, DbBackend::Postgres));
    }

    #[test]
    fn non_database_domain_error_never_retried() {
        let domain_err = DomainError::conflict("target version no longer exists (40P01)");
        assert!(!is_retryable_domain_error(&domain_err, DbBackend::Postgres));
    }

    #[test]
    fn db_err_leaves_message_unchanged_when_no_sqlstate_available() {
        let err = DbErr::Custom("some opaque error".to_owned());
        let expected = err.to_string();
        let mapped = db_err(err);
        assert!(
            matches!(&mapped, DomainError::Database { message } if *message == expected),
            "expected the plain Display text unchanged (no SQLSTATE to append), got {mapped:?}"
        );
    }

    // `sqlx::Error::Database` has crate-private constructors, so only the round trip of a
    // message that already carries the `(SQLSTATE <code>)` marker is unit-testable.
    #[test]
    #[allow(clippy::non_ascii_literal)]
    fn non_english_message_with_sqlstate_marker_is_still_recognized_as_retryable() {
        let domain_err = DomainError::database(
            "ошибка сериализации: не удалось сериализовать доступ из-за параллельного \
             обновления (SQLSTATE 40P01)",
        );
        assert!(
            is_retryable_domain_error(&domain_err, DbBackend::Postgres),
            "a non-English message must still classify as retryable once it carries \
             the driver's own SQLSTATE code, regardless of the surrounding text's language"
        );
    }

    #[test]
    #[allow(clippy::non_ascii_literal)]
    fn non_english_message_without_sqlstate_marker_is_not_retryable() {
        let domain_err = DomainError::database(
            "ошибка сериализации: не удалось сериализовать доступ из-за параллельного обновления",
        );
        assert!(
            !is_retryable_domain_error(&domain_err, DbBackend::Postgres),
            "with no SQLSTATE marker and no recognized English phrase, this must not be retried"
        );
    }

    // In-memory SQLite `Db`; no migrations, the bodies never touch a table.

    async fn retry_test_db() -> toolkit_db::secure::Db {
        let opts = toolkit_db::ConnectOpts {
            max_conns: Some(1),
            min_conns: Some(1),
            ..Default::default()
        };
        toolkit_db::connect_db("sqlite::memory:", opts)
            .await
            .expect("connect to in-memory SQLite")
    }

    /// A message `is_sqlite_busy` recognizes for the `Sqlite` backend.
    const RETRYABLE_SQLITE_MSG: &str = "(code: 5) database is locked";

    #[tokio::test]
    async fn bounded_retry_succeeds_after_transient_failures_within_budget() {
        let db = retry_test_db().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_body = Arc::clone(&calls);

        let result: Result<usize, DomainError> = transaction_with_bounded_retry(&db, move |_tx| {
            let calls = Arc::clone(&calls_for_body);
            Box::pin(async move {
                let attempt = calls.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt < TX_RETRY_ATTEMPTS as usize {
                    Err(DomainError::database(RETRYABLE_SQLITE_MSG))
                } else {
                    Ok(attempt)
                }
            })
        })
        .await;

        assert_eq!(
            result.expect("must succeed once the body stops failing"),
            TX_RETRY_ATTEMPTS as usize,
            "the successful attempt must be exactly the last one in the budget"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            TX_RETRY_ATTEMPTS as usize,
            "body must be invoked exactly once per attempt, no more"
        );
    }

    #[tokio::test]
    async fn bounded_retry_exhausts_budget_and_returns_last_error_unchanged() {
        let db = retry_test_db().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_body = Arc::clone(&calls);

        let result: Result<(), DomainError> = transaction_with_bounded_retry(&db, move |_tx| {
            let calls = Arc::clone(&calls_for_body);
            Box::pin(async move {
                let attempt = calls.fetch_add(1, Ordering::SeqCst) + 1;
                // Distinct message per attempt, to check the LAST error is returned.
                Err(DomainError::database(format!(
                    "{RETRYABLE_SQLITE_MSG} (attempt {attempt})"
                )))
            })
        })
        .await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            TX_RETRY_ATTEMPTS as usize,
            "must stop retrying once the attempt budget is exhausted, not loop forever"
        );
        match result {
            Err(DomainError::Database { message }) => {
                assert!(
                    message.contains(&format!("attempt {TX_RETRY_ATTEMPTS}")),
                    "expected the LAST attempt's error to be returned unchanged, got: {message}"
                );
            }
            other => panic!("expected a Database error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bounded_retry_never_retries_a_nonretryable_error() {
        let db = retry_test_db().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_for_body = Arc::clone(&calls);

        let result: Result<(), DomainError> = transaction_with_bounded_retry(&db, move |_tx| {
            let calls = Arc::clone(&calls_for_body);
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(DomainError::conflict("target version no longer exists"))
            })
        })
        .await;

        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a non-retryable error must stop the loop after the first attempt"
        );
        assert!(
            matches!(result, Err(DomainError::Conflict { .. })),
            "expected the original Conflict error to pass through unchanged, got {result:?}"
        );
    }
}
