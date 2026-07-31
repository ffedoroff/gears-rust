// Created: 2026-07-31 by Constructor Tech
//! Hierarchy `$filter` evaluator (ML-4182, ML-8813).
//!
//! Replaces the old `DepthFilter`/`TypeFilter` extractors, which walked the
//! typed `FilterNode` looking for a narrow set of shapes (`and` of depth
//! comparisons, a single `type eq`) and silently fell back to "no filter" —
//! `(None, None)` — for anything else (`or`, `not`, `in`, `type ne`, ...).
//! That fallback returned a *superset* with no signal that anything had
//! been dropped, so a client filtering on `type ne` (or any `or`/`in`
//! expression) got back every row, not a 400 and not the filtered set.
//!
//! This module is a two-stage replacement:
//!
//! 1. [`parse`] is the **only** place that can fail: it type-checks the
//!    `$filter` AST against the field x operator matrix this gear actually
//!    supports (see module docs on [`build_node`]) and rejects everything
//!    else with a [`DomainError::Validation`] (400).
//! 2. Everything after `parse` is **total**: [`HierarchyFilter::matches`]
//!    and [`HierarchyFilter::traversal_bounds`] never return `Option` and
//!    never have a "don't know" branch. A validated filter always has an
//!    answer for every `(depth, type_path)` pair.
//!
//! `matches` is the authority — it is exactly the predicate the `$filter`
//! expression describes. `traversal_bounds` is a *conservative* helper: it
//! derives an upper bound on the closure-table `depth` column so the
//! repository can narrow its SQL query, but the derived bound is always a
//! superset of what `matches` would actually accept. Composing them wrong
//! (returning a bound *narrower* than the true match set) is the single
//! most expensive mistake available in this module — see
//! [`HierarchyFilter::traversal_bounds`]'s doc comment.

use toolkit_macros::domain_model;
use toolkit_odata::ODataQuery;
use toolkit_odata::filter::{FilterNode, FilterOp, ODataValue};

use resource_group_sdk::odata::HierarchyFilterField;

use crate::domain::error::DomainError;

/// Which physical direction a traversal-bound query is being narrowed for.
///
/// The closure table only ever stores non-negative hop counts
/// (`resource_group_closure.depth INTEGER NOT NULL CHECK (depth >= 0)`),
/// but the user-facing `hierarchy/depth` field is *signed*: `0` is the
/// reference group, positive is a descendant, negative is an ancestor
/// (`docs/DESIGN.md`, "Ancestor depths are negative"). A single upper-bound
/// derivation cannot serve both routes: `hierarchy/depth le 5` bounds
/// descendants (`closure.depth <= 5`) but is *no constraint at all* on
/// ancestors (every ancestor's relative depth is `<= 0 <= 5`); conversely
/// `hierarchy/depth ge -3` bounds ancestors (`closure.depth <= 3`) but is no
/// constraint on descendants. `traversal_bounds` takes this direction so it
/// can mirror ancestor-side comparisons (`closure.depth = -relative_depth`)
/// before deriving the bound.
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyDirection {
    /// `/descendants`: closure rows where `relative_depth = closure.depth >= 0`.
    Descendant,
    /// `/ancestors`: closure rows where `relative_depth = -closure.depth <= 0`.
    Ancestor,
}

/// A conservative upper bound on the closure-table `depth` column, derived
/// from a [`HierarchyFilter`] for one [`HierarchyDirection`].
///
/// Three states, not two, because "nothing can match" and "no constraint at
/// all" are different facts for SQL: collapsing them would either force a
/// full closure-table fetch when the answer is provably empty, or (worse)
/// invite a caller to treat "no bound found" as "bound is zero".
#[domain_model]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalBounds {
    /// No upper bound could be (or needs to be) derived; fetch everything
    /// the closure table has for this direction and let [`HierarchyFilter::matches`]
    /// decide row by row.
    Unbounded,
    /// Provably no row can satisfy the filter in this direction (e.g. an
    /// exact-depth literal that cannot fit the physical `INTEGER` column,
    /// or a contradictory `and`). The caller can skip the closure query
    /// entirely.
    Empty,
    /// `closure.depth <= this value` is guaranteed to be a superset of the
    /// true match set. May be negative (still safe: the physical column's
    /// own `CHECK (depth >= 0)` makes `depth <= -1` correctly return zero
    /// rows) and is always saturated to fit `i32` — see [`finalize`].
    Max(i32),
}

/// A validated, total hierarchy `$filter`. Construct via [`parse`]; there is
/// no other way to build one, so every `HierarchyFilter` in existence has
/// already passed the field x operator matrix below.
#[domain_model]
#[derive(Debug, Clone)]
pub struct HierarchyFilter(Option<Node>);

/// Internal, validated AST. Deliberately narrower than
/// `toolkit_odata::filter::FilterNode`: only the shapes this gear's field x
/// operator matrix allows ever reach a `Node`, so every later pass over the
/// tree (`matches_node`, `bound_for`) can be total without re-checking
/// anything `build_node` already rejected. Module-private: never crosses a
/// layer boundary, so it is exempt from `#[domain_model]` (`02_gear_layout_
/// and_sdk_pattern.md`).
#[derive(Debug, Clone)]
enum Node {
    /// `hierarchy/depth <op> <literal>`. `op` is always one of
    /// `Eq/Ne/Gt/Ge/Lt/Le` — `build_node` never constructs any other
    /// variant here. The literal is the full `i64` value from the wire
    /// (see [`extract_i64_literal`]): depth comparisons compare by
    /// widening the row's `i32` depth to `i64`, never by narrowing the
    /// literal, so a literal like `3_000_000_000` (outside `i32`, inside
    /// `i64`) stays exactly representable and comparable.
    DepthCmp(FilterOp, i64),
    TypeEq(String),
    TypeNe(String),
    TypeIn(Vec<String>),
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
}

/// The `$filter` grammar this module accepts, in the form the REST layer
/// advertises it.
///
/// It lives here rather than in the route module because this is where the
/// grammar is actually decided — [`parse`] is the only thing that can accept
/// or reject an operator, so a description kept anywhere else would drift the
/// first time the matrix changes. `hierarchy_filter_tests` asserts that every
/// field/operator pair listed here is accepted by `parse` and every pair left
/// out is rejected, so the string cannot quietly outlive the code.
pub const FILTER_PARAM_DESCRIPTION: &str =
    "OData v4 filter expression\n- hierarchy/depth: eq|ne|gt|ge|lt|le\n- type: eq|ne|in";

/// Parse and validate an `OData` `$filter` against the hierarchy field x
/// operator matrix. The **only** place this module can fail.
///
/// Accepted: `hierarchy/depth` compared with `eq`/`ne`/`gt`/`ge`/`lt`/`le`
/// against an integral literal that fits `i64`; `type` compared with
/// `eq`/`ne` against a string, or `type in (...)`; any composition of the
/// above with `and`/`or`/`not`, arbitrarily nested.
///
/// Rejected with [`DomainError::Validation`] (400): an unknown field
/// (caught earlier, by `toolkit_odata::filter::convert_expr_to_filter_node`
/// itself); `hierarchy/depth in (...)` (the SDK contract promises only
/// single-value comparisons for depth,
/// `resource-group-sdk/src/odata/hierarchy.rs:4-5`); `type`
/// `gt`/`ge`/`lt`/`le` or any string function (`contains`/`startswith`/
/// `endswith`) — the generic converter accepts these because `type`'s
/// `FieldKind` is `String`, but the SDK never promised them; a
/// `hierarchy/depth` literal that is not an integer, or is an integer
/// outside `i64` (the parser hands back an arbitrary-precision
/// `BigDecimal`, and `FieldKind::I64` validation does not itself check
/// integrality or range — see [`extract_i64_literal`]).
///
/// # Errors
/// Returns `DomainError::Validation` for any of the rejections above.
pub fn parse(query: &ODataQuery) -> Result<HierarchyFilter, DomainError> {
    let Some(expr) = query.filter() else {
        return Ok(HierarchyFilter(None));
    };

    let filter_node =
        toolkit_odata::filter::convert_expr_to_filter_node::<HierarchyFilterField>(expr)
            .map_err(|e| DomainError::validation(format!("invalid $filter: {e}")))?;

    let node = build_node(&filter_node)?;
    Ok(HierarchyFilter(Some(node)))
}

/// Convert a generically-typed `FilterNode<HierarchyFilterField>` into the
/// narrower, fully-validated [`Node`]. See [`parse`] for the accept/reject
/// matrix this function enforces.
fn build_node(node: &FilterNode<HierarchyFilterField>) -> Result<Node, DomainError> {
    match node {
        FilterNode::Composite {
            op: FilterOp::And,
            children,
        } => Ok(Node::And(
            children.iter().map(build_node).collect::<Result<_, _>>()?,
        )),
        FilterNode::Composite {
            op: FilterOp::Or,
            children,
        } => Ok(Node::Or(
            children.iter().map(build_node).collect::<Result<_, _>>()?,
        )),
        FilterNode::Composite { op, .. } => Err(DomainError::validation(format!(
            "unsupported composite operator in hierarchy $filter: {op}"
        ))),
        FilterNode::Not(inner) => Ok(Node::Not(Box::new(build_node(inner)?))),

        FilterNode::Binary {
            field: HierarchyFilterField::HierarchyDepth,
            op:
                op @ (FilterOp::Eq
                | FilterOp::Ne
                | FilterOp::Gt
                | FilterOp::Ge
                | FilterOp::Lt
                | FilterOp::Le),
            value,
        } => {
            let ODataValue::Number(n) = value else {
                // Unreachable in practice: `convert_expr_to_filter_node` already
                // validated the value against `HierarchyFilterField::HierarchyDepth`'s
                // `FieldKind::I64`, which only accepts `ODataValue::Number`.
                return Err(DomainError::validation(
                    "hierarchy/depth filter value must be numeric",
                ));
            };
            let v = extract_i64_literal(n)?;
            Ok(Node::DepthCmp(*op, v))
        }
        FilterNode::Binary {
            field: HierarchyFilterField::HierarchyDepth,
            op,
            ..
        } => Err(DomainError::validation(format!(
            "unsupported operator for hierarchy/depth: {op} (only eq, ne, gt, ge, lt, le are supported)"
        ))),

        FilterNode::Binary {
            field: HierarchyFilterField::Type,
            op: FilterOp::Eq,
            value,
        } => Ok(Node::TypeEq(type_literal(value)?)),
        FilterNode::Binary {
            field: HierarchyFilterField::Type,
            op: FilterOp::Ne,
            value,
        } => Ok(Node::TypeNe(type_literal(value)?)),
        FilterNode::Binary {
            field: HierarchyFilterField::Type,
            op,
            ..
        } => Err(DomainError::validation(format!(
            "unsupported operator for type: {op} (only eq, ne, in are supported)"
        ))),

        FilterNode::InList {
            field: HierarchyFilterField::Type,
            values,
        } => {
            let items = values
                .iter()
                .map(type_literal)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Node::TypeIn(items))
        }
        FilterNode::InList {
            field: HierarchyFilterField::HierarchyDepth,
            ..
        } => Err(DomainError::validation(
            "unsupported operator for hierarchy/depth: in (only eq, ne, gt, ge, lt, le are supported)",
        )),
    }
}

/// Extract a `type` literal, which `HierarchyFilterField::Type`'s
/// `FieldKind::String` already guarantees is `ODataValue::String`.
fn type_literal(value: &ODataValue) -> Result<String, DomainError> {
    match value {
        ODataValue::String(s) => Ok(s.clone()),
        // Unreachable in practice, same reasoning as the `Number` case in `build_node`.
        _ => Err(DomainError::validation(
            "type filter value must be a string",
        )),
    }
}

/// Extract an `i64` from a `$filter` numeric literal, enforcing the
/// contract `FieldKind::I64` validation does not: the literal must be an
/// exact integer (no fractional part) that fits in `i64`.
///
/// `to_plain_string()` after `with_scale(0)` renders a bare integer digit
/// string (e.g. `"3000000000"` or `"-5"`) with no decimal point, so the
/// final `str::parse::<i64>()` is exactly the range check: it accepts
/// everything in `i64::MIN..=i64::MAX` and rejects everything else,
/// including `i64::MAX + 1` and `i64::MIN - 1`.
fn extract_i64_literal(n: &bigdecimal::BigDecimal) -> Result<i64, DomainError> {
    if !n.is_integer() {
        return Err(DomainError::validation(
            "hierarchy/depth filter value must be an integer",
        ));
    }
    n.with_scale(0)
        .to_plain_string()
        .parse::<i64>()
        .map_err(|_| {
            DomainError::validation(
                "hierarchy/depth filter value out of range (must fit a 64-bit signed integer)",
            )
        })
}

/// A depth bound in the unbounded, arbitrary-precision working domain used
/// while combining `and`/`or`. Kept as `i128` (never `i32`, never `i64`)
/// specifically so that mirroring a depth comparison for the ancestor
/// direction (negating, or negating-and-offsetting-by-one) can never
/// overflow: every `i64` literal's negation and +/-1 neighbor fits `i128`
/// with enormous room to spare. Saturating to `i32` happens exactly once,
/// in [`finalize`], which is also the only place this type's values ever
/// reach a caller.
#[derive(Debug, Clone, Copy)]
enum Bound {
    Unbounded,
    Empty,
    Val(i128),
}

/// The upper bound `i32` can represent, as `i128` (matches `resource_group_closure.depth INTEGER`).
const I32_MAX_128: i128 = i32::MAX as i128;
/// The lower bound `i32` can represent, as `i128`.
const I32_MIN_128: i128 = i32::MIN as i128;

/// An exact-value (`eq`) leaf bound: `Empty` if the value cannot possibly be
/// stored in the physical `INTEGER` column, `Val` otherwise.
///
/// This is deliberately **not** shared with the inequality leaves below
/// (`Le`/`Lt`/`Ge`/`Gt`-derived `Val`s are saturated, never promoted to
/// `Empty`, in [`finalize`]): an inequality bound that falls outside `i32`
/// is still a valid (if loose) superset once saturated to the column's own
/// range, but an *exact* value outside that range can never match any row,
/// full stop — that distinction is exactly why `TraversalBounds` has three
/// states instead of two.
fn exact_i32(v128: i128) -> Bound {
    if (I32_MIN_128..=I32_MAX_128).contains(&v128) {
        Bound::Val(v128)
    } else {
        Bound::Empty
    }
}

/// Derive the upper-bound contribution of a single `hierarchy/depth <op> v`
/// leaf, for one traversal direction.
///
/// For [`HierarchyDirection::Descendant`], `closure.depth` *is* the
/// relative depth (both range over `[0, ∞)`), so this is a direct
/// upper-bound table: `eq`/`le` are tight, `lt` tightens by one, and
/// `ge`/`gt`/`ne` give no upper bound at all (point 2 of the plan: `ne` is
/// always `top` — a hole in the middle of a range is not representable as
/// a single upper bound).
///
/// For [`HierarchyDirection::Ancestor`], `closure.depth = -relative_depth`,
/// so each leaf is mirrored first (substituting `d = -relative_depth`) and
/// then the same direct table is applied to the mirrored operator/literal:
/// `relative_depth op v` becomes `d op' (-v)`, where `op'` is `op` with
/// `Gt`/`Lt` swapped and `Ge`/`Le` swapped (`Eq`/`Ne` unchanged). Working
/// this through: `eq -> -v`, `ge -> -v`, `gt -> -v - 1`, and `le`/`lt`/`ne`
/// give no bound — matching the asymmetry point 4 of the plan calls out:
/// `depth gt -3` (ancestor direction) yields the tight bound `2`, not the
/// looser `4` a naive `abs()`-based formula would give.
fn leaf_bound(op: FilterOp, v: i64, direction: HierarchyDirection) -> Bound {
    let v128 = i128::from(v);
    match (direction, op) {
        (HierarchyDirection::Descendant, FilterOp::Eq) => exact_i32(v128),
        (HierarchyDirection::Descendant, FilterOp::Le) => Bound::Val(v128),
        (HierarchyDirection::Descendant, FilterOp::Lt) => Bound::Val(v128 - 1),

        (HierarchyDirection::Ancestor, FilterOp::Eq) => exact_i32(-v128),
        (HierarchyDirection::Ancestor, FilterOp::Ge) => Bound::Val(-v128),
        (HierarchyDirection::Ancestor, FilterOp::Gt) => Bound::Val(-v128 - 1),

        // Descendant Ge/Gt/Ne and Ancestor Le/Lt/Ne are all lower-bound-style
        // (or hole-in-the-range, for Ne) ops in their respective direction:
        // none of them constrains an upper bound on `closure.depth`.
        (HierarchyDirection::Descendant, FilterOp::Ge | FilterOp::Gt | FilterOp::Ne)
        | (HierarchyDirection::Ancestor, FilterOp::Le | FilterOp::Lt | FilterOp::Ne) => {
            Bound::Unbounded
        }

        // `Node::DepthCmp` is only ever constructed by `build_node` with one
        // of the six comparison ops matched above.
        _ => unreachable!("Node::DepthCmp only carries Eq/Ne/Gt/Ge/Lt/Le"),
    }
}

/// `and` combinator: the tightest (minimum) of the children's proven upper
/// bounds. A child with no bound (`Unbounded`) does not loosen the result —
/// intersecting with "no constraint" is a no-op — but a provably-`Empty`
/// child makes the whole intersection `Empty` immediately.
fn combine_and(children: impl Iterator<Item = Bound>) -> Bound {
    let mut acc: Option<i128> = None;
    for b in children {
        match b {
            Bound::Empty => return Bound::Empty,
            Bound::Unbounded => {}
            Bound::Val(v) => acc = Some(acc.map_or(v, |a: i128| a.min(v))),
        }
    }
    acc.map_or(Bound::Unbounded, Bound::Val)
}

/// `or` combinator: the loosest (maximum) of the children's bounds, and
/// **only** when every child has some bound — a single `Unbounded` child
/// makes the union `Unbounded` too, since the union must cover whatever
/// that child could match. An `Empty` child contributes nothing to the
/// union (it matches nothing), so it is skipped rather than propagated.
fn combine_or(children: impl Iterator<Item = Bound>) -> Bound {
    let mut acc: Option<i128> = None;
    for b in children {
        match b {
            Bound::Unbounded => return Bound::Unbounded,
            Bound::Empty => {}
            Bound::Val(v) => acc = Some(acc.map_or(v, |a: i128| a.max(v))),
        }
    }
    acc.map_or(Bound::Empty, Bound::Val)
}

/// Recursively derive a [`Bound`] for one traversal direction.
///
/// `type` leaves (and any future non-depth leaf) always give `Unbounded` —
/// point 1 of the plan: a `type` leaf must be `top`, never `bottom`, or
/// `and(type eq 'x', hierarchy/depth le 2)` would intersect a real depth
/// bound with a fabricated "nothing" from the type leaf and wrongly drop
/// every row. `not` always gives `Unbounded` too: negating a bounded set is
/// in general unbounded (`not(hierarchy/depth le 5)` is `hierarchy/depth gt
/// 5`, unbounded above), and deriving anything tighter would require
/// reasoning this module does not attempt — `matches` remains the
/// authority regardless.
fn bound_for(node: &Node, direction: HierarchyDirection) -> Bound {
    match node {
        Node::DepthCmp(op, v) => leaf_bound(*op, *v, direction),
        // Every non-depth leaf, and `not` of anything, contributes no bound.
        Node::TypeEq(_) | Node::TypeNe(_) | Node::TypeIn(_) | Node::Not(_) => Bound::Unbounded,
        Node::And(children) => combine_and(children.iter().map(|c| bound_for(c, direction))),
        Node::Or(children) => combine_or(children.iter().map(|c| bound_for(c, direction))),
    }
}

/// Materialize a working [`Bound`] into the public [`TraversalBounds`],
/// saturating a numeric value into `i32` if needed.
///
/// Saturating in **either** direction is safe here specifically because
/// `resource_group_closure.depth` is a physical `INTEGER` column: no real
/// row can ever hold a value outside `i32::MIN..=i32::MAX`, so clamping the
/// bound to that range can never exclude a representable row — it can only
/// ever make the bound compare equal to, or looser than, its true value
/// over the realizable domain. This is the "clamp to `i32::MAX` is provably
/// a superset" argument from the plan, applied symmetrically to the lower
/// side of the range.
fn finalize(bound: Bound) -> TraversalBounds {
    match bound {
        Bound::Unbounded => TraversalBounds::Unbounded,
        Bound::Empty => TraversalBounds::Empty,
        Bound::Val(v) => {
            let clamped = v.clamp(I32_MIN_128, I32_MAX_128);
            // Safe: `clamped` is provably within `i32::MIN..=i32::MAX` by
            // construction of the `clamp()` call immediately above, so this
            // cast never truncates. `i32::try_from` would be the usual
            // fallible-conversion idiom, but its `Result` has no non-panicking
            // way to report an error that cannot occur, and this crate denies
            // `clippy::expect_used` in production code.
            #[allow(clippy::cast_possible_truncation)]
            let narrowed = clamped as i32;
            TraversalBounds::Max(narrowed)
        }
    }
}

/// Evaluate a single `Node` against a candidate row. Total: every variant
/// [`build_node`] can construct has a defined outcome for every `(depth,
/// type_path)` pair.
fn matches_node(node: &Node, depth: i64, type_path: &str) -> bool {
    match node {
        Node::DepthCmp(op, v) => match op {
            FilterOp::Eq => depth == *v,
            FilterOp::Ne => depth != *v,
            FilterOp::Gt => depth > *v,
            FilterOp::Ge => depth >= *v,
            FilterOp::Lt => depth < *v,
            FilterOp::Le => depth <= *v,
            _ => unreachable!("Node::DepthCmp only carries Eq/Ne/Gt/Ge/Lt/Le"),
        },
        Node::TypeEq(s) => type_path == s,
        Node::TypeNe(s) => type_path != s,
        Node::TypeIn(list) => list.iter().any(|s| s == type_path),
        Node::And(children) => children.iter().all(|c| matches_node(c, depth, type_path)),
        Node::Or(children) => children.iter().any(|c| matches_node(c, depth, type_path)),
        Node::Not(inner) => !matches_node(inner, depth, type_path),
    }
}

impl HierarchyFilter {
    /// Whether a candidate row satisfies this filter. Total: `depth` is any
    /// `i32` (widened to `i64` for the comparison, never narrowed — see
    /// [`Node::DepthCmp`]) and `type_path` is any string. A filter built
    /// from an absent `$filter` (`parse` on a query with no filter) matches
    /// every row.
    pub(crate) fn matches(&self, depth: i32, type_path: &str) -> bool {
        match &self.0 {
            None => true,
            Some(node) => matches_node(node, i64::from(depth), type_path),
        }
    }

    /// A conservative upper bound on `resource_group_closure.depth` for one
    /// traversal direction, for narrowing the repository's SQL query.
    ///
    /// **The invariant that matters:** for every `depth` where
    /// `self.matches(depth, _)` can be `true` in this direction, the
    /// physical closure-table row's `depth` column satisfies the returned
    /// bound. Getting this backwards — returning a bound that excludes a
    /// depth `matches` would have accepted — is the single most expensive
    /// mistake available here: e.g. treating a `type` leaf as `bottom`
    /// instead of `top` would make `and(type eq 'x', hierarchy/depth le 2)`
    /// intersect a real bound with a fabricated empty one and silently
    /// drop every row, filter correctness be damned. `matches` is always
    /// the final authority; this is purely a query-narrowing optimization
    /// and is allowed to be loose (see [`leaf_bound`]'s doc comment for a
    /// case where it deliberately is), never tight-but-wrong.
    pub(crate) fn traversal_bounds(&self, direction: HierarchyDirection) -> TraversalBounds {
        match &self.0 {
            None => TraversalBounds::Unbounded,
            Some(node) => finalize(bound_for(node, direction)),
        }
    }
}

#[cfg(test)]
#[path = "hierarchy_filter_tests.rs"]
mod tests;
