// Created: 2026-07-31 by Constructor Tech
//! Tests for [`crate::validate_cursor_against`] — the single shared
//! cursor/query consistency check (ML-8967).
//!
//! Pure logic: no DB, no async runtime, no new test dependencies — plain
//! `#[test]` + `matches!` + a manual `Vec` and loop, per
//! `docs/toolkit_unified_system/12_unit_testing.md`. The two async
//! `SeaORM` paginators that call through to this function are instead
//! covered end-to-end with `SQLite` `:memory:` in
//! `libs/toolkit-db/tests/secure_odata_sqlite.rs`
//! (`paginate_odata_rejects_asymmetric_filter_hash_cursor` and
//! `opager_rejects_asymmetric_filter_hash_cursor`), per the same doc's
//! guidance that DB-backed behavior belongs at the repository/DB seam.

use crate::{CursorV1, ODataOrderBy, OrderKey, SortDir};

/// An order + matching cursor `s` token that always satisfies the
/// order-half of `validate_cursor_against`, isolating every case below to
/// the filter-hash half under test.
fn order_and_signed_tokens() -> (ODataOrderBy, &'static str) {
    (
        ODataOrderBy(vec![OrderKey {
            field: "id".to_owned(),
            dir: SortDir::Asc,
        }]),
        "+id",
    )
}

fn cursor_with_hash(s: &str, f: Option<&str>) -> CursorV1 {
    CursorV1 {
        k: vec!["1".to_owned()],
        o: SortDir::Asc,
        s: s.to_owned(),
        f: f.map(str::to_owned),
        d: "fwd".to_owned(),
    }
}

/// One row of the `(query filter_hash, cursor.f)` table below.
struct Case {
    name: &'static str,
    query_hash: Option<&'static str>,
    cursor_hash: Option<&'static str>,
    expect_ok: bool,
}

/// The four `(query filter_hash, cursor.f)` combinations from the ML-8967
/// defect table. Before the fix, only the two same-hash-`Some` /
/// different-hash-`Some` rows were checked; the two asymmetric
/// `Some`/`None` rows were silently accepted. All four are asserted here
/// so a regression to the old `if let (Some(h), Some(cf)) = ...` shape
/// (which compiles fine and only breaks behavior) turns this test red.
#[test]
fn validate_cursor_against_checks_filter_hash_as_a_whole_option() {
    let (order, s) = order_and_signed_tokens();

    let cases = vec![
        Case {
            name: "Some(h) == Some(same h) -> accepted",
            query_hash: Some("h1"),
            cursor_hash: Some("h1"),
            expect_ok: true,
        },
        Case {
            name: "Some(h) vs Some(different) -> FilterMismatch",
            query_hash: Some("h1"),
            cursor_hash: Some("h2"),
            expect_ok: false,
        },
        Case {
            name: "Some(h) vs None -> FilterMismatch (new case)",
            query_hash: Some("h1"),
            cursor_hash: None,
            expect_ok: false,
        },
        Case {
            name: "None vs Some(h) -> FilterMismatch (new case)",
            query_hash: None,
            cursor_hash: Some("h1"),
            expect_ok: false,
        },
        Case {
            name: "None vs None -> accepted (no filter on either side)",
            query_hash: None,
            cursor_hash: None,
            expect_ok: true,
        },
    ];

    for case in cases {
        let cursor = cursor_with_hash(s, case.cursor_hash);
        let result = crate::validate_cursor_against(&cursor, &order, case.query_hash);

        if case.expect_ok {
            assert!(result.is_ok(), "{}: expected Ok, got {result:?}", case.name);
        } else {
            let err = result.expect_err(&format!("{}: expected an error", case.name));
            assert!(
                matches!(err, crate::Error::FilterMismatch),
                "{}: expected FilterMismatch, got {err:?}",
                case.name
            );
        }
    }
}

/// Order mismatch is still checked independently of the filter-hash half —
/// a passing filter-hash comparison must not mask a genuine order drift.
#[test]
fn validate_cursor_against_still_rejects_order_mismatch() {
    let (order, _s) = order_and_signed_tokens();
    // Cursor was minted under a different sort order ("-name" instead of
    // "+id"); filter hash matches on both sides so only OrderMismatch
    // should fire.
    let cursor = cursor_with_hash("-name", Some("h1"));

    let err = crate::validate_cursor_against(&cursor, &order, Some("h1"))
        .expect_err("order drift must be rejected even when the filter hash matches");
    assert!(
        matches!(err, crate::Error::OrderMismatch),
        "expected OrderMismatch, got {err:?}"
    );
}

/// Cross-path regression guard: a cursor minted the REST way — hash
/// computed by the extractor via `short_filter_hash` over the parsed
/// `$filter` AST (`libs/toolkit/src/api/odata.rs`) — must still validate
/// against a query built the in-process way, via
/// `ODataQuery::default().with_filter(expr)` (the new automatic-hash
/// invariant this task adds, e.g. `rg-tr-plugin`'s
/// `ODataQuery::default().with_filter(tenant_type_filter())`). Both sides
/// must derive the *same* hash from the *same* filter shape for the
/// strict comparison not to introduce spurious `FilterMismatch` on a
/// legitimate continuation — this is exactly the new failure class a
/// strict check can introduce if the two hash computations ever diverge.
///
/// **What this test does not cover.** It calls `short_filter_hash` directly
/// rather than driving the real extractor, so it proves `with_filter` agrees
/// with `short_filter_hash` — not that the extractor still routes through
/// either. Since the extractor now delegates to `with_filter`, this test
/// would stay green if it stopped doing so; the assertion that keeps the
/// extractor honest lives in its own test, in `toolkit`'s `odata_tests.rs`.
#[test]
fn with_filter_hashes_identically_to_the_short_filter_hash_a_minted_cursor_carries() {
    use crate::ast::{CompareOperator, Expr, Value};

    let expr = Expr::Compare(
        Box::new(Expr::Identifier("type".to_owned())),
        CompareOperator::Eq,
        Box::new(Expr::Value(Value::String("tenant".to_owned()))),
    );

    // Stands in for whatever minted the cursor: the hash carried in
    // `next_cursor.f` is `short_filter_hash` over the filter AST, wherever
    // it was computed.
    let rest_hash = crate::pagination::short_filter_hash(Some(&expr))
        .expect("a non-empty filter always hashes to Some");
    let cursor = cursor_with_hash("+id", Some(&rest_hash));

    // Simulates an in-process caller building the follow-up request via
    // the builder pattern instead of the REST path — the same filter
    // shape, hashed automatically by `with_filter`.
    let in_process_query = crate::ODataQuery::default().with_filter(expr);

    let (order, _s) = order_and_signed_tokens();

    crate::validate_cursor_against(&cursor, &order, in_process_query.filter_hash.as_deref())
        .expect(
            "a cursor minted via the REST extractor's hash must validate against an \
             in-process query built with the same filter through with_filter's automatic hash",
        );
}

/// Compatibility case explicitly called out for ML-8967: a legacy cursor
/// encoded before filter hashing existed never serialized an `f` key at
/// all (`CursorV1::encode`'s `Wire::f` is
/// `#[serde(skip_serializing_if = "Option::is_none")]`), and
/// `CursorV1::decode` fills the missing key back in as `None` via
/// `#[serde(default)]`. Once minted, replaying such a cursor against a
/// **filtered** query is now correctly rejected (the strict check can no
/// longer tell "no filter was ever hashed" apart from "no filter in
/// effect" any other way) — but the exact same cursor must still be
/// accepted when replayed against an **unfiltered** query, since `None`
/// vs `None` is a legitimate match, not a legacy artifact to punish.
#[test]
fn legacy_cursor_without_f_is_rejected_on_filtered_query_but_accepted_on_unfiltered_query() {
    let legacy = CursorV1 {
        k: vec!["1".to_owned()],
        o: SortDir::Asc,
        s: "+id".to_owned(),
        f: None,
        d: "fwd".to_owned(),
    };
    let encoded = legacy.encode().expect("legacy cursor encodes");
    let decoded = CursorV1::decode(&encoded).expect("legacy cursor decodes");
    assert_eq!(
        decoded.f, None,
        "a cursor encoded with f: None must decode back to f: None, not silently gain a value"
    );

    let (order, _s) = order_and_signed_tokens();

    let err = crate::validate_cursor_against(&decoded, &order, Some("current-filter-hash"))
        .expect_err(
            "a legacy no-hash cursor replayed against a now-filtered query must be rejected",
        );
    assert!(
        matches!(err, crate::Error::FilterMismatch),
        "expected FilterMismatch, got {err:?}"
    );

    crate::validate_cursor_against(&decoded, &order, None).expect(
        "the same legacy no-hash cursor must still be accepted when the query has no filter \
         either - this is the compatibility case, not a new rejection",
    );
}
