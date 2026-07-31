//! Tests for [`crate::Error::classify`].
//!
//! Pure logic: no DB, no async runtime, no new test dependencies — plain
//! `#[test]` + `matches!` + a manual `Vec` and loop, per
//! `docs/toolkit_unified_system/12_unit_testing.md`.

use crate::{ClassifiedError, Error};
use toolkit_canonical_errors::CanonicalError;

/// The two buckets `Error::classify` sorts into. Kept local to the test
/// module purely so cases can be declared as `(Error, Category)` pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Category {
    Client,
    Infrastructure,
}

fn category_of(classified: &ClassifiedError) -> Category {
    match classified {
        ClassifiedError::Client(_) => Category::Client,
        ClassifiedError::Infrastructure(_) => Category::Infrastructure,
    }
}

/// Every `Error` variant, paired with the category `classify` must produce
/// for it. All 15 variants are listed — this is not a sample.
///
/// Note on what this `Vec` does and does not guard: adding a 16th variant to
/// `Error` does **not** make this list (or the loop below) fail to compile —
/// a `Vec` literal has no idea the enum grew. What *does* force a decision on
/// a new variant is the exhaustive `match` with no wildcard arm inside
/// `Error::classify` itself; that match fails to compile until the new
/// variant is triaged into `Client` or `Infrastructure`. This list only
/// pins down the expected category for each of today's 15 variants.
fn all_variants_with_expected_category() -> Vec<(Error, Category)> {
    vec![
        (
            Error::InvalidFilter("bad filter".to_owned()),
            Category::Client,
        ),
        (
            Error::InvalidOrderByField("bad field".to_owned()),
            Category::Client,
        ),
        (Error::OrderMismatch, Category::Client),
        (Error::FilterMismatch, Category::Client),
        (Error::InvalidCursor, Category::Client),
        (Error::InvalidLimit, Category::Client),
        (Error::OrderWithCursor, Category::Client),
        (Error::CursorInvalidBase64, Category::Client),
        (Error::CursorInvalidJson, Category::Client),
        (Error::CursorInvalidVersion, Category::Client),
        (Error::CursorInvalidKeys, Category::Client),
        (Error::CursorInvalidFields, Category::Client),
        (Error::CursorInvalidDirection, Category::Client),
        (
            Error::Db("connection refused".to_owned()),
            Category::Infrastructure,
        ),
        (
            Error::ParsingUnavailable("feature off"),
            Category::Infrastructure,
        ),
    ]
}

#[test]
fn classify_sorts_every_variant_into_the_expected_category() {
    let cases = all_variants_with_expected_category();
    // Sanity check that the table above hasn't silently lost an entry; see
    // the doc comment on `all_variants_with_expected_category` for what this
    // length check does and does not prove.
    assert_eq!(cases.len(), 15, "expected one entry per Error variant");

    for (err, expected) in cases {
        let debug_label = format!("{err:?}");
        let category = category_of(&err.classify());
        assert_eq!(category, expected, "unexpected category for {debug_label}");
    }
}

#[test]
fn classify_preserves_the_typed_error_value() {
    // `classify` must hand back the same variant it consumed, not just the
    // right bucket — callers pattern-match on the returned `Error` (e.g. to
    // read `Db`'s message), so the payload has to survive the round trip.
    match Error::InvalidLimit.classify() {
        ClassifiedError::Client(Error::InvalidLimit) => {}
        other => panic!("expected Client(InvalidLimit), got {other:?}"),
    }

    match Error::Db("timeout".to_owned()).classify() {
        ClassifiedError::Infrastructure(Error::Db(msg)) => assert_eq!(msg, "timeout"),
        other => panic!("expected Infrastructure(Db(\"timeout\")), got {other:?}"),
    }
}

/// Consistency check: `Error::classify` and `impl From<Error> for
/// CanonicalError` (in `crate::problem_mapping`) are two independent
/// `match` statements over the same 15 variants. Without this test they
/// could silently diverge — exactly the class of bug this task exists to
/// prevent. For every variant, the HTTP status category `CanonicalError`
/// assigns must agree with the bucket `classify` picked.
#[test]
fn classify_agrees_with_problem_mapping_status_category() {
    for (err, _) in all_variants_with_expected_category() {
        let debug_label = format!("{err:?}");
        let classified_category = category_of(&err.clone().classify());

        // Match on the canonical variant, not on `status_code()`: several
        // variants share a status (`InvalidArgument`, `FailedPrecondition` and
        // `OutOfRange` are all 400; `Internal`, `Unknown` and `DataLoss` are
        // all 500), so a status-only comparison would not notice the mapping
        // drifting from one category to another underneath the same code.
        let canonical = CanonicalError::from(err);
        let canonical_category = match canonical {
            CanonicalError::InvalidArgument { .. } => Category::Client,
            CanonicalError::Internal { .. } => Category::Infrastructure,
            other => panic!(
                "CanonicalError::from(Error) produced {} (HTTP {}) for {debug_label}; \
                 the two-bucket model this test rests on covers only InvalidArgument \
                 and Internal — extend both it and `classify` before trusting this test",
                other.gts_type(),
                other.status_code()
            ),
        };

        assert_eq!(
            classified_category, canonical_category,
            "classify() and CanonicalError::from(Error) disagree on category for {debug_label}"
        );
    }
}
