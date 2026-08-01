//! Table-driven coverage for [`resolve_page_size`], the single policy that
//! replaces nine previously-duplicated "default/clamp" implementations
//! (ML-5024). This is the primary test for the merged policy: every input
//! shape that used to be handled ad hoc at each call site is exercised here
//! once.

use std::num::NonZeroU64;

use super::{LimitCfg, resolve_page_size};
use crate::Error;

fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}

#[test]
fn resolve_page_size_table() {
    let cfg = LimitCfg::new(25, 100);

    // (requested, expected Ok value; None means expected Err(InvalidLimit))
    let cases: Vec<(Option<u64>, Option<u64>)> = vec![
        (Some(0), None),        // zero is rejected, not clamped to 1
        (Some(1), Some(1)),     // smallest legal value passes through
        (None, Some(25)),       // absent -> cfg.default
        (Some(25), Some(25)),   // explicit value equal to default passes through
        (Some(100), Some(100)), // explicit value equal to max passes through
        (Some(101), Some(100)), // over max -> clamped down to max, not an error
    ];

    for (requested, expected) in cases {
        let result = resolve_page_size(requested, cfg);
        if let Some(want) = expected {
            let got = result.unwrap_or_else(|e| {
                panic!("requested={requested:?}: expected Ok({want}), got Err({e:?})")
            });
            assert_eq!(
                got,
                nz(want),
                "requested={requested:?}: expected {want}, got {got}"
            );
        } else {
            assert!(
                result.is_err(),
                "requested={requested:?}: expected Err, got Ok({result:?})"
            );
            assert!(
                matches!(result.unwrap_err(), Error::InvalidLimit),
                "requested={requested:?}: expected Error::InvalidLimit"
            );
        }
    }
}

/// A misconfigured `default > max` must not let an absent `limit` serve a
/// larger page than the endpoint's declared maximum. The `clamp_limit` this
/// policy replaced applied its ceiling *after* defaulting, so returning
/// `cfg.default` unclamped would be a silent regression against the old
/// behavior rather than a new edge case.
#[test]
fn absent_limit_is_clamped_when_default_exceeds_max() {
    let cfg = LimitCfg::new(500, 100);
    assert_eq!(resolve_page_size(None, cfg).unwrap(), nz(100));
}

#[test]
fn limit_cfg_new_exposes_configured_bounds() {
    let cfg = LimitCfg::new(25, 100);
    assert_eq!(cfg.default, nz(25));
    assert_eq!(cfg.max, nz(100));
}

#[test]
#[should_panic(expected = "LimitCfg::default must be non-zero")]
fn limit_cfg_new_panics_on_zero_default() {
    let _cfg = LimitCfg::new(0, 100);
}

#[test]
#[should_panic(expected = "LimitCfg::max must be non-zero")]
fn limit_cfg_new_panics_on_zero_max() {
    let _cfg = LimitCfg::new(25, 0);
}

/// The `saturating_add(1)` seam in `toolkit-db`'s `core.rs` /
/// `sea_orm_filter.rs` (the "fetch `limit + 1` to detect `has_more`"
/// pagination trick) depends on `resolve_page_size` never handing back
/// `u64::MAX` when `cfg.max` is a realistic cap — otherwise
/// `limit.saturating_add(1) == limit`, silently dropping the look-ahead
/// row. Pin that a request for `u64::MAX` against an ordinary cap is
/// clamped down, not passed through.
#[test]
fn resolve_page_size_clamps_u64_max_request_to_cfg_max() {
    let cfg = LimitCfg::new(25, 100);
    assert_eq!(resolve_page_size(Some(u64::MAX), cfg).unwrap(), nz(100));
}

/// `LimitCfg::new` rejects a zero bound but not `max == u64::MAX` —
/// nothing in the type or the constructor prevents a `LimitCfg` this
/// permissive. When one is configured this way, a caller-requested
/// `u64::MAX` resolves to `u64::MAX` verbatim — exactly the input on
/// which `toolkit-db`'s `limit.saturating_add(1)` seam degrades
/// (`fetch == limit`, not `limit + 1`; see `core.rs` /
/// `sea_orm_filter.rs`). Fixing that seam is not in scope here; this test
/// only pins the boundary so it stays visible instead of silently
/// depending on every call site choosing a realistic `max`.
#[test]
fn resolve_page_size_with_cfg_max_at_u64_max_returns_u64_max() {
    let cfg = LimitCfg::new(1, u64::MAX);
    assert_eq!(
        resolve_page_size(Some(u64::MAX), cfg).unwrap(),
        nz(u64::MAX)
    );
}
