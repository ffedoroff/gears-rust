//! Single shared policy for resolving an `OData` page size from a
//! client-supplied `limit`/`$top` and a per-endpoint [`LimitCfg`].
//!
//! Before this module existed, nine call sites across `toolkit-db` and
//! individual gears each re-implemented the same "default when absent, clamp
//! when over max" policy (some with a lower-bound clamp, most without one,
//! and with inconsistent handling of an explicit `0`). [`resolve_page_size`]
//! is the single place that policy is now defined; [`LimitCfg`] is the
//! per-endpoint default/max pair it is parameterized on.

use std::num::NonZeroU64;

use crate::Error;

/// Pagination limit configuration: default and maximum page size for one
/// endpoint.
///
/// Both bounds are `NonZeroU64` by construction: [`LimitCfg::new`] panics on
/// a zero `default` or `max` rather than returning a `Result` that every
/// unrelated call site would have to thread through.
///
/// That panic is the right trade-off only when the caller has already
/// ensured `default`/`max` can never be zero by the time `LimitCfg::new`
/// runs. Many call sites satisfy this trivially — a `const` binding at the
/// call site, where the value can't vary at runtime and a zero would be a
/// compile-time-visible bug. Not every call site is like that: one that
/// builds a `LimitCfg` from deserialized, runtime configuration (e.g. a
/// gear's service config populated from a YAML/JSON file with only serde
/// defaults, not from a validated constructor) is *not* a deployment-time
/// constant — it is user input in every sense that matters here, just
/// supplied by an operator instead of a request. Such a call site MUST
/// reject a zero bound during its own config validation, eagerly, at
/// load/boot time, before ever calling [`LimitCfg::new`]. Skipping that
/// validation does not remove the failure mode this design intends to
/// avoid; it just moves it from a `Result` every caller threads through to
/// a panic on the first request that reaches the constructor — worse, not
/// better, because the panic now fires per-request instead of at boot.
///
/// This is a different failure mode from the one [`resolve_page_size`]
/// handles: a client-supplied `limit=0` on an otherwise well-formed
/// `LimitCfg` is a per-request condition, reported as
/// `Err(Error::InvalidLimit)` rather than a panic.
#[derive(Clone, Copy, Debug)]
pub struct LimitCfg {
    /// Page size used when the caller does not specify one.
    pub default: NonZeroU64,
    /// Upper bound a caller-specified page size is clamped to.
    pub max: NonZeroU64,
}

impl LimitCfg {
    /// Construct a `LimitCfg` from plain integers.
    ///
    /// # Panics
    /// Panics if `default` or `max` is zero — a zero here is a
    /// configuration bug, not a per-request condition, and should fail
    /// fast at construction rather than silently producing an unusable
    /// page size at runtime. At a `const` binding call site this fails at
    /// compile time, which is the common case; a call site that builds
    /// `LimitCfg` from runtime configuration is responsible for rejecting
    /// a zero bound during its own config validation before ever calling
    /// this constructor — see the struct-level docs above.
    #[must_use]
    pub const fn new(default: u64, max: u64) -> Self {
        let Some(default) = NonZeroU64::new(default) else {
            panic!("LimitCfg::default must be non-zero")
        };
        let Some(max) = NonZeroU64::new(max) else {
            panic!("LimitCfg::max must be non-zero")
        };
        Self { default, max }
    }
}

/// Resolve the effective page size for one request.
///
/// Contract:
/// - `requested == Some(0)` — rejected: a client explicitly asking for zero
///   rows is a malformed request (see [`Error::InvalidLimit`]), not "give me
///   the smallest possible page". Silently coercing it to `1` (the previous
///   behavior at several call sites) is not chosen here because it hides
///   the request from the client instead of telling them it was invalid.
/// - `requested == None` — the endpoint's configured `cfg.default`, itself
///   clamped to `cfg.max`. The clamp is not redundant: a misconfigured
///   `default > max` would otherwise make an absent `limit` serve a larger
///   page than the endpoint's own declared maximum. The `clamp_limit` this
///   function replaced applied its ceiling after defaulting, so dropping the
///   clamp here would have been a silent regression.
/// - `requested == Some(n)` with `n > cfg.max` — clamped down to `cfg.max`.
///   This is a deliberate upper-bound clamp, not an error: a client asking
///   for more than the endpoint allows gets the largest page the endpoint
///   is willing to serve instead of a rejection.
/// - `requested == Some(n)` with `0 < n <= cfg.max` — `n`, unchanged.
///
/// # Errors
/// Returns [`Error::InvalidLimit`] when `requested` is `Some(0)`.
pub fn resolve_page_size(requested: Option<u64>, cfg: LimitCfg) -> Result<NonZeroU64, Error> {
    let Some(n) = requested else {
        return Ok(cfg.default.min(cfg.max));
    };
    let n = NonZeroU64::new(n).ok_or(Error::InvalidLimit)?;
    Ok(n.min(cfg.max))
}

#[cfg(test)]
#[path = "limit_cfg_tests.rs"]
mod limit_cfg_tests;
