// Created: 2026-07-31 by Constructor Tech
//! Pure unit tests for the hierarchy `$filter` evaluator -- no database, no
//! `tokio`, `#[test]` only (`12_unit_testing.md`'s ярус 1). Companion file
//! via `#[path]`, not `tests/*.rs`: `HierarchyFilter`/`parse` are
//! `pub(crate)`, and `tests/*.rs` link against this crate as an *external*
//! crate, so `pub(crate)` items are not visible there
//! (`tests/domain_unit_test.rs:10` already relies on the public
//! `resource_group::domain::error::DomainError` for exactly that reason).
use super::*;

fn filter_query(raw: &str) -> ODataQuery {
    let parsed = toolkit_odata::parse_filter_string(raw)
        .unwrap_or_else(|e| panic!("fixture filter {raw:?} must parse: {e}"));
    ODataQuery::new().with_filter(parsed.into_expr())
}

// -- Rejections (parse is the only place this module can fail) --

/// `depth eq 2.0` is accepted and behaves as `depth eq 2`.
///
/// This is the whole reason the crate depends on `bigdecimal` rather than
/// checking the literal with `to_string().parse::<i64>()`: `"2.0"` does not
/// parse as an integer, so the naive route would reject a value that is
/// integral and legitimate for an `I64` field. `is_integer()` plus
/// `with_scale(0)` accepts it; nothing else in the numeric matrix does.
#[test]
fn hierarchy_filter_integral_decimal_literal_is_accepted() {
    let filter = parse(&filter_query("hierarchy/depth eq 2.0")).expect(
        "2.0 is integral and within i64, so it must be accepted, not rejected as non-integer",
    );

    assert!(filter.matches(2, SWEEP_MATCHING_TYPE), "depth 2 must match");
    assert!(
        !filter.matches(3, SWEEP_MATCHING_TYPE),
        "depth 3 must not match"
    );
    assert!(
        matches!(
            filter.traversal_bounds(HierarchyDirection::Descendant),
            TraversalBounds::Max(2)
        ),
        "an equality on 2 bounds the descendant traversal at 2"
    );
}

#[test]
fn hierarchy_filter_unknown_field_rejected() {
    let err = parse(&filter_query("bogus eq 1")).expect_err("unknown field must be rejected");
    assert!(matches!(err, DomainError::Validation { .. }));
}

#[test]
fn hierarchy_filter_depth_wrong_literal_type_rejected() {
    assert!(parse(&filter_query("hierarchy/depth eq 'x'")).is_err());
}

#[test]
fn hierarchy_filter_type_wrong_literal_type_rejected() {
    assert!(parse(&filter_query("type eq 1")).is_err());
}

// Field x operator matrix: the generic `convert_expr_to_filter_node` types
// these by `FieldKind` alone and would accept them (`hierarchy/depth` is
// `FieldKind::I64` so `in` collects fine; `type` is `FieldKind::String` so
// `gt`/`ge`/`lt`/`le` and the string functions all pass its type check) --
// this module must reject them anyway because the SDK contract
// (`resource-group-sdk/src/odata/hierarchy.rs:4-5`) never promised them.
// Each gets its own test per the plan: a shared "matrix" test that loops
// over cases can go green for the wrong reason if one arm's rejection path
// silently changes shape.

#[test]
fn hierarchy_filter_depth_in_rejected() {
    assert!(parse(&filter_query("hierarchy/depth in (1, 2, 3)")).is_err());
}

#[test]
fn hierarchy_filter_type_gt_rejected() {
    assert!(parse(&filter_query("type gt 'a'")).is_err());
}

#[test]
fn hierarchy_filter_type_ge_rejected() {
    assert!(parse(&filter_query("type ge 'a'")).is_err());
}

#[test]
fn hierarchy_filter_type_lt_rejected() {
    assert!(parse(&filter_query("type lt 'a'")).is_err());
}

#[test]
fn hierarchy_filter_type_le_rejected() {
    assert!(parse(&filter_query("type le 'a'")).is_err());
}

#[test]
fn hierarchy_filter_type_contains_rejected() {
    assert!(parse(&filter_query("contains(type, 'a')")).is_err());
}

#[test]
fn hierarchy_filter_type_startswith_rejected() {
    assert!(parse(&filter_query("startswith(type, 'a')")).is_err());
}

#[test]
fn hierarchy_filter_type_endswith_rejected() {
    assert!(parse(&filter_query("endswith(type, 'a')")).is_err());
}

// -- Numeric contract: integral within i64 (including outside i32) computes;
// fractional or outside i64 is rejected. --

#[test]
fn hierarchy_filter_depth_literal_fractional_rejected() {
    assert!(parse(&filter_query("hierarchy/depth eq 1.5")).is_err());
}

#[test]
fn hierarchy_filter_depth_literal_i64_max_plus_one_rejected() {
    assert!(parse(&filter_query("hierarchy/depth eq 9223372036854775808")).is_err());
}

#[test]
fn hierarchy_filter_depth_literal_i64_min_minus_one_rejected() {
    assert!(parse(&filter_query("hierarchy/depth eq -9223372036854775809")).is_err());
}

#[test]
fn hierarchy_filter_depth_literal_i64_max_accepted() {
    assert!(parse(&filter_query("hierarchy/depth eq 9223372036854775807")).is_ok());
}

#[test]
fn hierarchy_filter_depth_literal_i64_min_accepted() {
    assert!(parse(&filter_query("hierarchy/depth eq -9223372036854775808")).is_ok());
}

#[test]
fn hierarchy_filter_depth_literal_exceeds_i32_is_computed_not_rejected() {
    // 3_000_000_000 is outside i32 but inside i64: the SDK declares
    // `hierarchy/depth` as `FieldKind::I64`, so this is typo-correct and
    // must be evaluated, not rejected -- every real i32 depth is <= it.
    let filter = parse(&filter_query("hierarchy/depth le 3000000000"))
        .expect("value within i64 range must be accepted");
    assert!(filter.matches(i32::MAX, "t"));
    assert!(filter.matches(0, "t"));
}

#[test]
fn hierarchy_filter_depth_eq_out_of_i32_never_matches_a_real_depth() {
    let filter = parse(&filter_query("hierarchy/depth eq 3000000000")).expect("accepted");
    assert!(!filter.matches(i32::MAX, "t"));
    assert!(!filter.matches(0, "t"));
}

// -- Composition: or, not, in, ne, multiple predicates on one field, nesting --

#[test]
fn hierarchy_filter_no_filter_matches_everything() {
    let filter = parse(&ODataQuery::new()).expect("absent filter parses");
    assert!(filter.matches(0, "any"));
    assert!(filter.matches(-5, "any"));
    assert!(filter.matches(i32::MAX, "any"));
}

#[test]
fn hierarchy_filter_depth_ne_matches_all_but_excluded_value() {
    let filter = parse(&filter_query("hierarchy/depth ne 3")).expect("accepted");
    assert!(!filter.matches(3, "t"));
    assert!(filter.matches(4, "t"));
    assert!(filter.matches(-3, "t"));
}

#[test]
fn hierarchy_filter_type_ne_matches_all_but_excluded_type() {
    let filter = parse(&filter_query("type ne 'x'")).expect("accepted");
    assert!(!filter.matches(0, "x"));
    assert!(filter.matches(0, "y"));
}

#[test]
fn hierarchy_filter_type_in_matches_membership() {
    let filter = parse(&filter_query("type in ('a', 'b')")).expect("accepted");
    assert!(filter.matches(0, "a"));
    assert!(filter.matches(0, "b"));
    assert!(!filter.matches(0, "c"));
}

#[test]
fn hierarchy_filter_or_matches_either_branch() {
    let filter = parse(&filter_query(
        "hierarchy/depth eq 1 or hierarchy/depth eq 3",
    ))
    .expect("accepted");
    assert!(filter.matches(1, "t"));
    assert!(filter.matches(3, "t"));
    assert!(!filter.matches(2, "t"));
}

#[test]
fn hierarchy_filter_not_negates_inner_predicate() {
    let filter = parse(&filter_query("not (hierarchy/depth le 5)")).expect("accepted");
    assert!(!filter.matches(3, "t"));
    assert!(!filter.matches(5, "t"));
    assert!(filter.matches(6, "t"));
}

#[test]
fn hierarchy_filter_multiple_predicates_on_depth_intersect() {
    let filter = parse(&filter_query(
        "hierarchy/depth ge 1 and hierarchy/depth le 5",
    ))
    .expect("accepted");
    for d in 1..=5 {
        assert!(filter.matches(d, "t"), "depth {d} should be in [1,5]");
    }
    assert!(!filter.matches(0, "t"));
    assert!(!filter.matches(6, "t"));
}

#[test]
fn hierarchy_filter_nested_and_or_evaluates_correctly() {
    let filter = parse(&filter_query(
        "(hierarchy/depth eq 1 or hierarchy/depth eq 2) and type eq 'x'",
    ))
    .expect("accepted");
    assert!(filter.matches(1, "x"));
    assert!(filter.matches(2, "x"));
    assert!(!filter.matches(1, "y"), "type must also match");
    assert!(!filter.matches(3, "x"), "depth must also match");
}

#[test]
fn hierarchy_filter_contradictory_and_matches_nothing() {
    let filter = parse(&filter_query(
        "hierarchy/depth eq 1 and hierarchy/depth eq 3",
    ))
    .expect("accepted");
    for d in -10..=10 {
        assert!(
            !filter.matches(d, "t"),
            "contradictory filter must match no depth, but matched {d}"
        );
    }
}

// -- Traversal bounds: the four risk points from the plan, each pinned directly --

#[test]
fn hierarchy_filter_type_leaf_bound_is_top_not_bottom() {
    // Point 1: a lone `type` leaf must never contribute a fabricated
    // "nothing" bound that an `and` could intersect away a real depth bound.
    let filter = parse(&filter_query("type eq 'x'")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Unbounded
    );
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Ancestor),
        TraversalBounds::Unbounded
    );
}

#[test]
fn hierarchy_filter_type_leaf_does_not_narrow_and_bound() {
    // Same point, in composition: `and(type eq 'x', depth le 2)` must keep
    // the depth branch's bound intact, not intersect it down to nothing.
    let filter = parse(&filter_query("type eq 'x' and hierarchy/depth le 2")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Max(2)
    );
}

#[test]
fn hierarchy_filter_depth_ne_bound_is_top() {
    // Point 2: `ne` is a hole in the middle of the range, not representable
    // as a single upper bound in either direction.
    let filter = parse(&filter_query("hierarchy/depth ne 3")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Unbounded
    );
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Ancestor),
        TraversalBounds::Unbounded
    );
}

#[test]
fn hierarchy_filter_extreme_depth_literals_do_not_panic() {
    // Point 3: checked arithmetic everywhere. `i64::MIN` is the one value
    // whose negation and +/-1 neighbor are the classic overflow trap; this
    // must not panic in either direction.
    for raw in [
        "hierarchy/depth eq -9223372036854775808",
        "hierarchy/depth gt -9223372036854775808",
        "hierarchy/depth lt -9223372036854775808",
        "hierarchy/depth eq 9223372036854775807",
        "hierarchy/depth gt 9223372036854775807",
        "hierarchy/depth lt 9223372036854775807",
    ] {
        let filter = parse(&filter_query(raw)).expect("accepted");
        let _ = filter.traversal_bounds(HierarchyDirection::Descendant);
        let _ = filter.traversal_bounds(HierarchyDirection::Ancestor);
        let _ = filter.matches(0, "t");
        let _ = filter.matches(i32::MIN, "t");
        let _ = filter.matches(i32::MAX, "t");
    }
}

#[test]
fn hierarchy_filter_descendant_self_row_excluded_by_negative_bound_also_fails_match() {
    // Point 4: a negative descendant upper bound is only safe because the
    // self-row (depth=0) also fails the actual filter -- pin that both
    // halves of that argument hold together, not just the bound shape.
    let filter = parse(&filter_query("hierarchy/depth lt 0")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Max(-1)
    );
    assert!(
        !filter.matches(0, "t"),
        "self row must also fail the filter"
    );
}

#[test]
fn hierarchy_filter_ancestor_bound_gt_negative_literal_is_tight() {
    // The plan's worked example: `depth gt -3` on the ancestor direction
    // has a *tight* bound of 2 (mirroring: d < 3, i.e. d <= 2), not the
    // looser 4 a naive `(v - 1).abs()` formula would give.
    let filter = parse(&filter_query("hierarchy/depth gt -3")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Ancestor),
        TraversalBounds::Max(2)
    );
}

#[test]
fn hierarchy_filter_or_bound_requires_both_branches_bounded() {
    // `or` may only union bounds when every branch has one; a single
    // unbounded branch makes the whole union unbounded.
    let mixed = parse(&filter_query(
        "hierarchy/depth eq 1 or hierarchy/depth ne 3",
    ))
    .expect("accepted");
    assert_eq!(
        mixed.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Unbounded
    );

    let both_bounded = parse(&filter_query(
        "hierarchy/depth eq 1 or hierarchy/depth eq 3",
    ))
    .expect("accepted");
    assert_eq!(
        both_bounded.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Max(3)
    );
}

#[test]
fn hierarchy_filter_not_bound_is_top() {
    let filter = parse(&filter_query("not (hierarchy/depth le 5)")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Unbounded
    );
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Ancestor),
        TraversalBounds::Unbounded
    );
}

#[test]
fn hierarchy_filter_descendant_bound_eq_out_of_i32_is_empty() {
    // The one case that legitimately produces `Empty`: an exact-value
    // literal that cannot possibly be stored in the physical `INTEGER`
    // column, so no closure-table query is even worth issuing.
    let filter = parse(&filter_query("hierarchy/depth eq 3000000000")).expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Empty
    );
}

#[test]
fn hierarchy_filter_and_with_empty_child_is_empty() {
    let filter = parse(&filter_query(
        "hierarchy/depth eq 3000000000 and type eq 'x'",
    ))
    .expect("accepted");
    assert_eq!(
        filter.traversal_bounds(HierarchyDirection::Descendant),
        TraversalBounds::Empty
    );
}

// -- The invariant: derived bounds never exclude a depth `matches` accepts --

/// Depths to sweep per filter/direction: small values around zero (where
/// most real hierarchies live) plus both ends of the *reachable* range,
/// since `resource_group_closure.depth` is a physical `i32` column and the
/// ends are exactly where a saturating cast could go wrong.
///
/// Deliberately excludes `i32::MIN`: every real `depth` argument `matches`
/// is ever called with is derived from a closure-table row whose own
/// `depth` column is `CHECK (depth >= 0)` and physically `i32`, so
/// `row.depth` is always in `[0, i32::MAX]` and the relative depth passed
/// into `matches` (`row.depth` for descendants, `-row.depth` for ancestors,
/// `0` for the self row) is always in `[-i32::MAX, i32::MAX]` --
/// `i32::MIN` (`-i32::MAX - 1`) can never occur. It is also the one value
/// whose negation does not fit back into `i32`, so mirroring it for the
/// ancestor direction would require reasoning about a "closure depth" that
/// cannot physically exist -- an artifact of `i32`'s asymmetric range, not
/// a case the invariant needs to cover. `i32::MIN + 1` (`-i32::MAX`), which
/// *is* reachable, stays in the sweep.
/// The type path the sweep's `type eq 'x'` cases match, and one they do not.
/// Both are swept: with only a non-matching path, every filter containing a
/// type equality would make `matches` false for all depths, the assertion
/// body would never execute, and the property would go unchecked.
const SWEEP_MATCHING_TYPE: &str = "x";
const SWEEP_NON_MATCHING_TYPE: &str = "not-x";

const DEPTH_SWEEP: &[i32] = &[
    i32::MIN + 1,
    -1_000_000,
    -3,
    -2,
    -1,
    0,
    1,
    2,
    3,
    1_000_000,
    i32::MAX - 1,
    i32::MAX,
];

/// Assert the invariant for one filter expression, both traversal
/// directions, across [`DEPTH_SWEEP`]. Deliberately a hand-rolled sweep, not
/// `proptest`: the crate has no property-testing dev-dependency
/// (`12_unit_testing.md`'s "no new test dependencies" rule), and this is a
/// small enough domain that an explicit `vec![]` sweep is sufficient --
/// `12_unit_testing.md:97`'s own preferred shape.
///
/// The invariant is checked on the *depth projection* only: `matches` is
/// called with a fixed, filter-irrelevant type string, which is exactly
/// what point 1 above (`type` leaves are always `top`) makes safe to do --
/// if a `type` leaf could narrow a bound, this projection would not be
/// sound, but since it cannot, the type argument is inert for every filter
/// exercised here and the bound reduces cleanly to a function of depth
/// alone. Expectations are computed by direct comparison against the
/// literal in each `raw` string, not by calling `traversal_bounds` itself --
/// using the bound to check the bound would be a circular oracle.
fn assert_bound_never_excludes_a_match(raw: &str) {
    let filter = parse(&filter_query(raw)).unwrap_or_else(|e| panic!("{raw:?} must parse: {e}"));

    // Sweep both a type that the filter's type-leaves match and one they do
    // not. With a single fixed type path, every `type eq 'x' and ...` case
    // would be vacuous: `matches` returns false for every depth, the loop
    // body never runs, and the test passes without checking anything.
    for direction in [HierarchyDirection::Descendant, HierarchyDirection::Ancestor] {
        let bound = filter.traversal_bounds(direction);
        for type_path in [SWEEP_MATCHING_TYPE, SWEEP_NON_MATCHING_TYPE] {
            for &depth in DEPTH_SWEEP {
                if !filter.matches(depth, type_path) {
                    continue;
                }
                // `resource_group_closure.depth` for this direction, widened so
                // negating `i32::MIN` (the ancestor direction) cannot overflow.
                let closure_depth: i128 = match direction {
                    HierarchyDirection::Descendant => i128::from(depth),
                    HierarchyDirection::Ancestor => -i128::from(depth),
                };
                match bound {
                    TraversalBounds::Unbounded => {}
                    TraversalBounds::Empty => panic!(
                        "invariant violated: filter {raw:?} matches depth {depth} in \
                     {direction:?}, but its bound claims Empty"
                    ),
                    TraversalBounds::Max(m) => assert!(
                        closure_depth <= i128::from(m),
                        "invariant violated: filter {raw:?} matches depth {depth} in \
                     {direction:?} (closure depth {closure_depth}), but its bound Max({m}) \
                     excludes it"
                    ),
                }
            }
        }
    }
}

#[test]
fn hierarchy_filter_bounds_invariant_holds_across_shapes() {
    for raw in [
        "hierarchy/depth eq 1",
        "hierarchy/depth ne 1",
        "hierarchy/depth gt -3",
        "hierarchy/depth ge -3",
        "hierarchy/depth lt 5",
        "hierarchy/depth le 5",
        "hierarchy/depth gt 0",
        "hierarchy/depth ge 0",
        "hierarchy/depth lt 0",
        "hierarchy/depth le 0",
        "hierarchy/depth eq 1 or hierarchy/depth eq 3",
        "hierarchy/depth eq 1 and hierarchy/depth eq 3",
        "not (hierarchy/depth le 5)",
        "type eq 'x'",
        "type eq 'x' and hierarchy/depth le 2",
        "type eq 'x' or hierarchy/depth le 2",
        "hierarchy/depth eq 3000000000",
        "hierarchy/depth le 3000000000",
        "hierarchy/depth le 9223372036854775807",
        "hierarchy/depth ge -9223372036854775808",
        "hierarchy/depth eq -9223372036854775808",
        "hierarchy/depth eq 9223372036854775807",
    ] {
        assert_bound_never_excludes_a_match(raw);
    }
}
