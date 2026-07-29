#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "sqlite")]

//! Tests for [`Db::transaction_with_retry`] (and `_max`).
//!
//! These exercise the retry policy itself (extractor, attempt counting,
//! exhaustion, log on retry) using `sqlite::memory:`. The retryable case
//! constructs a real `SQLITE_BUSY` `DbErr` so that the helper's internal
//! call to [`toolkit_db::contention::is_retryable_contention`] flags it as
//! retryable for the `SQLite` backend.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use sea_orm::{DbErr, RuntimeErr};
use toolkit_db::{ConnectOpts, DEFAULT_TX_RETRY_ATTEMPTS, DbError, connect_db, secure::TxConfig};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Debug)]
enum TestError {
    /// Wraps a real `DbErr` whose string representation is recognised by
    /// `is_retryable_contention` as a `SQLite` BUSY (code 5).
    Retryable(DbErr),
    Permanent,
    #[allow(dead_code)]
    Db(DbError),
}

impl From<DbError> for TestError {
    fn from(e: DbError) -> Self {
        TestError::Db(e)
    }
}

fn extract_db_err(e: &TestError) -> Option<&DbErr> {
    match e {
        TestError::Retryable(err) => Some(err),
        _ => None,
    }
}

fn sqlite_busy_err() -> DbErr {
    DbErr::Exec(RuntimeErr::Internal(
        "Execution Error: error returned from database: (code: 5) database is locked".to_owned(),
    ))
}

#[tokio::test]
async fn retry_default_succeeds_after_transient_failures() {
    // The default budget is `DEFAULT_TX_RETRY_ATTEMPTS` (= 3), so a body
    // that fails twice and succeeds on the third attempt must succeed without
    // the caller specifying a max.
    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");
    let counter = Arc::new(AtomicU32::new(0));

    let counter_for_body = Arc::clone(&counter);
    let result: Result<u32, TestError> = db
        .transaction_with_retry(TxConfig::default(), extract_db_err, move |_tx| {
            let counter = Arc::clone(&counter_for_body);
            Box::pin(async move {
                let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
                if n < DEFAULT_TX_RETRY_ATTEMPTS {
                    Err(TestError::Retryable(sqlite_busy_err()))
                } else {
                    Ok(n)
                }
            })
        })
        .await;

    assert!(
        matches!(result, Ok(n) if n == DEFAULT_TX_RETRY_ATTEMPTS),
        "got {result:?}"
    );
    assert_eq!(counter.load(Ordering::SeqCst), DEFAULT_TX_RETRY_ATTEMPTS);
}

#[tokio::test]
async fn retry_returns_last_error_on_exhaustion() {
    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");
    let counter = Arc::new(AtomicU32::new(0));

    let counter_for_body = Arc::clone(&counter);
    let result: Result<(), TestError> = db
        .transaction_with_retry_max(TxConfig::default(), 3, extract_db_err, move |_tx| {
            let counter = Arc::clone(&counter_for_body);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Retryable(sqlite_busy_err()))
            })
        })
        .await;

    assert!(
        matches!(result, Err(TestError::Retryable(_))),
        "got {result:?}"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn non_retryable_error_returns_immediately() {
    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");
    let counter = Arc::new(AtomicU32::new(0));

    let counter_for_body = Arc::clone(&counter);
    let result: Result<(), TestError> = db
        .transaction_with_retry_max(TxConfig::default(), 3, extract_db_err, move |_tx| {
            let counter = Arc::clone(&counter_for_body);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Permanent)
            })
        })
        .await;

    assert!(
        matches!(result, Err(TestError::Permanent)),
        "got {result:?}"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn extractor_returning_none_skips_retry() {
    // A body whose error doesn't expose a `DbErr` (extractor → None) must
    // not be retried even if the helper has attempts remaining.
    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");
    let counter = Arc::new(AtomicU32::new(0));

    let counter_for_body = Arc::clone(&counter);
    let result: Result<(), TestError> = db
        .transaction_with_retry_max(TxConfig::default(), 3, extract_db_err, move |_tx| {
            let counter = Arc::clone(&counter_for_body);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Db(DbError::InvalidConfig("boom".to_owned())))
            })
        })
        .await;

    assert!(matches!(result, Err(TestError::Db(_))), "got {result:?}");
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn zero_max_attempts_treated_as_one() {
    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");
    let counter = Arc::new(AtomicU32::new(0));

    let counter_for_body = Arc::clone(&counter);
    let result: Result<(), TestError> = db
        .transaction_with_retry_max(TxConfig::default(), 0, extract_db_err, move |_tx| {
            let counter = Arc::clone(&counter_for_body);
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(TestError::Retryable(sqlite_busy_err()))
            })
        })
        .await;

    assert!(
        matches!(result, Err(TestError::Retryable(_))),
        "got {result:?}"
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

// ── Give-up diagnostics ──────────────────────────────────────────────
//
// `transaction_with_retry_max` can give up for two reasons that look
// identical to the caller (both are just `Err(e)`): the attempt budget ran
// out on a recognized contention error, or the error was never recognized
// as retryable in the first place. The two need different fixes (raise the
// budget / look at contention vs. extend `is_retryable_contention`), so the
// helper emits a distinguishing structured `tracing` event on each exit --
// these two tests demonstrate that the events fire, differ, and carry
// enough fields to tell the two outcomes apart.
//
// Capture approach: a minimal `tracing_subscriber::Layer` collecting a
// joined `field=value` string per event, installed via
// `tracing::subscriber::set_default` (thread-local -- fine here, no
// `tokio::spawn` is involved). This mirrors
// `libs/toolkit/tests/panic_tracing_tests.rs`'s `CapturedEvents`/
// `FieldCollector`, the established pattern in this repo for capturing
// `tracing` output from an external integration-test crate.

/// Captures every `tracing` event's fields (including the implicit
/// `message` field) as one joined `"name=value "` string, so tests can do
/// simple substring assertions instead of re-deriving a formatter.
#[derive(Clone, Default)]
struct CapturedEvents {
    lines: Arc<Mutex<Vec<String>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedEvents {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = FieldCollector(String::new());
        event.record(&mut visitor);
        self.lines.lock().unwrap().push(visitor.0);
    }
}

struct FieldCollector(String);

impl tracing::field::Visit for FieldCollector {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        #[allow(clippy::use_debug)]
        {
            _ = write!(self.0, "{}={:?} ", field.name(), value);
        }
    }
}

/// Installs the capturing layer as this thread's default subscriber.
///
/// Returns the captured-lines buffer plus the guard that keeps the
/// subscriber active -- callers must hold onto the guard (`let (lines,
/// _guard) = install_capture();`) for as long as capturing must stay live;
/// dropping it early restores the previous (no-op) default.
fn install_capture() -> (Arc<Mutex<Vec<String>>>, tracing::subscriber::DefaultGuard) {
    let captured = CapturedEvents::default();
    let lines = captured.lines.clone();
    let subscriber = tracing_subscriber::registry().with(captured);
    let guard = tracing::subscriber::set_default(subscriber);
    (lines, guard)
}

/// A `DbErr` shaped like a real Postgres/SQLite unique-constraint
/// violation: database-shaped (so `extract_db_err` yields `Some`), but not a
/// pattern `is_retryable_contention` recognizes -- the "unrecognized error"
/// side of the give-up split.
fn unique_violation_err() -> DbErr {
    DbErr::Exec(RuntimeErr::Internal(
        "Execution Error: error returned from database: (code: 19) UNIQUE constraint failed: \
         gts_type.schema_id"
            .to_owned(),
    ))
}

#[tokio::test]
async fn retry_exhaustion_emits_budget_exhausted_event() {
    let (lines, _guard) = install_capture();

    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");

    // Budget of 1 disables retries outright, so the very first (and only)
    // attempt's retryable failure immediately exhausts the budget -- the
    // simplest, fully deterministic way to force this outcome without
    // depending on how many attempts a real race actually needs.
    let result: Result<(), TestError> = db
        .transaction_with_retry_max(TxConfig::default(), 1, extract_db_err, move |_tx| {
            Box::pin(async move { Err(TestError::Retryable(sqlite_busy_err())) })
        })
        .await;
    assert!(
        matches!(result, Err(TestError::Retryable(_))),
        "got {result:?}"
    );

    let lines = lines.lock().unwrap();
    let exhausted = lines
        .iter()
        .find(|l| l.contains("transaction retry budget exhausted"))
        .unwrap_or_else(|| panic!("expected a budget-exhausted event, got: {lines:#?}"));
    assert!(
        exhausted.contains("attempt=1") && exhausted.contains("max_attempts=1"),
        "expected attempt=1 max_attempts=1 in: {exhausted}"
    );
    assert!(
        exhausted.contains("retryable=true"),
        "budget exhaustion must report retryable=true (it *was* recognized, it just ran out of \
         attempts): {exhausted}"
    );
    assert!(
        exhausted.contains("phase=body"),
        "the failure came from the body closure, not commit: {exhausted}"
    );
    // The two outcomes must be genuinely distinct events, not the same
    // message with different fields.
    assert!(
        !lines
            .iter()
            .any(|l| l.contains("not recognized as retryable")),
        "must not also emit the unrecognized-error event: {lines:#?}"
    );
}

#[tokio::test]
async fn non_retryable_db_error_emits_distinct_event() {
    let (lines, _guard) = install_capture();

    let db = connect_db("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("connect sqlite memory");

    // Plenty of budget left (3 attempts) -- the point is that this error is
    // never even offered a retry, because `is_retryable_contention` doesn't
    // recognize it, not because the budget ran out.
    let result: Result<(), TestError> = db
        .transaction_with_retry_max(TxConfig::default(), 3, extract_db_err, move |_tx| {
            Box::pin(async move { Err(TestError::Retryable(unique_violation_err())) })
        })
        .await;
    assert!(
        matches!(result, Err(TestError::Retryable(_))),
        "got {result:?}"
    );

    let lines = lines.lock().unwrap();
    let unrecognized = lines
        .iter()
        .find(|l| l.contains("not recognized as retryable"))
        .unwrap_or_else(|| panic!("expected an unrecognized-error event, got: {lines:#?}"));
    assert!(
        unrecognized.contains("attempt=1") && unrecognized.contains("max_attempts=3"),
        "expected attempt=1 max_attempts=3 (budget was NOT exhausted) in: {unrecognized}"
    );
    assert!(
        unrecognized.contains("retryable=false"),
        "must report retryable=false, distinguishing this from budget exhaustion: {unrecognized}"
    );
    assert!(
        unrecognized.contains("UNIQUE constraint failed"),
        "the compact error representation must carry the actual DbErr text: {unrecognized}"
    );
    // The two outcomes must be genuinely distinct events.
    assert!(
        !lines.iter().any(|l| l.contains("budget exhausted")),
        "must not also emit the budget-exhausted event: {lines:#?}"
    );
}
