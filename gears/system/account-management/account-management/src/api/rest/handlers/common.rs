//! Cross-handler helpers shared by the AM REST handler families.

use std::collections::HashMap;

use toolkit_odata::{LimitCfg, ODataQuery, resolve_page_size};

use crate::domain::error::DomainError;

/// Default page size when the caller omits `$top`, per the DNA canon
/// (`guidelines/DNA/REST/PAGINATION.md`).
const DEFAULT_LISTING_TOP: u64 = 25;

/// Clamp the `OData` `$top` against the per-endpoint deployment cap.
/// Repos already enforce an absolute ceiling (200), but a deployment
/// that has dropped `listing.max_top` below it would otherwise be
/// bypassed — clamp here so the service signature stays a thin
/// `(scope, target, &ODataQuery)` forward.
///
/// ML-5024: delegates to the shared [`resolve_page_size`] policy instead
/// of a crate-local clamp. One behavior changes as a result:
/// - `$top` absent used to default to `max_top` (the operator's cap,
///   i.e. the *largest* page the endpoint would ever serve by default);
///   it now defaults to the DNA canon [`DEFAULT_LISTING_TOP`] (25),
///   clamped down further if an operator has tightened `max_top` below
///   25 — the default can never exceed the deployment's own cap.
///
/// `$top=0` is defense-in-depth, not a wire-reachable fix: by the time an
/// `ODataQuery` reaches this function it has already passed through the
/// `OData` extractor (`toolkit::api::odata::extract_odata_query`), which
/// rejects `limit=0` with `400 InvalidArgument` before the handler ever
/// runs — this branch was unreachable from an HTTP request under the old
/// crate-local clamp too. What the switch to [`resolve_page_size`] closes
/// is the in-process gap: a caller that builds an `ODataQuery` directly
/// (bypassing the extractor) and hands it to [`clamp_listing_top`] used to
/// see `$top=0` pass straight through (`0.min(cap) == 0`) to the repo as
/// `LIMIT 0` and an always-empty page; it is now rejected as
/// [`DomainError::Validation`] instead.
///
/// # Errors
/// Returns [`DomainError::Validation`] if the caller's `$top` is `0`.
pub(super) fn clamp_listing_top(
    mut query: ODataQuery,
    max_top: u32,
) -> Result<ODataQuery, DomainError> {
    // Defensive floor: a misconfigured deployment with `listing.max_top =
    // 0` would otherwise make `LimitCfg::new` panic (`default`/`max` must
    // be non-zero) and turn every listing request into a 500. Treat it as
    // "no operator cap configured", mirroring the `max_top.max(1)` floor
    // in `handlers/users.rs::lower_odata_to_list_users_query`.
    let cap = u64::from(max_top).max(1);
    let cfg = LimitCfg::new(DEFAULT_LISTING_TOP.min(cap), cap);
    let resolved = resolve_page_size(query.limit, cfg).map_err(|e| DomainError::Validation {
        detail: e.to_string(),
    })?;
    query.limit = Some(resolved.get());
    Ok(query)
}

/// Reject any query parameter that does not start with `$`.
///
/// AM list endpoints use `OData` as the single filter / ordering /
/// pagination surface (`$filter`, `$orderby`, `$top`, `$skip`,
/// `$select`, `$count`). Without this guard, Axum silently drops
/// query keys that no extractor claimed — a caller writing in a
/// generic-REST convention like `?status=approved` would receive
/// HTTP 200 with the **unfiltered** result set and assume the filter
/// applied. That is a documented contract-drift surface (the e2e
/// pin `test_conversion_list_plain_status_param_silently_ignored`
/// in vhp-core asserts the 400 shape).
///
/// Mapping the violation to [`DomainError::Validation`] surfaces a
/// canonical HTTP 400 with the `$filter` hint embedded in `detail`
/// so clients see the canonical contract without parsing the
/// envelope.
///
/// `$`-prefixed keys are intentionally out of scope: the `OData`
/// extractor parses them and rejects unknown ones (`$filtre` etc.)
/// through its own `Validation` path. This check is the seam for
/// non-`OData` accidents only.
pub(super) fn reject_non_odata_params(query: &HashMap<String, String>) -> Result<(), DomainError> {
    if let Some(unknown) = query.keys().find(|k| !k.starts_with('$')) {
        return Err(DomainError::Validation {
            detail: format!(
                "unrecognized query parameter `{unknown}`; AM list endpoints \
                 accept OData parameters only (e.g. `$filter=status eq 'approved'`)"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "common_tests.rs"]
mod tests;
