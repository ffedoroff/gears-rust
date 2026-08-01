use oagw_sdk::field;
use toolkit::api::odata::{LimitCfg, resolve_page_size};
use toolkit_canonical_errors::Problem;
use uuid::Uuid;

use crate::api::rest::error::domain_error_to_problem;
use crate::domain::error::DomainError;
use crate::domain::gts_helpers;
use crate::domain::model::ListQuery;

/// Parse a GTS identifier, verifying that its schema prefix matches
/// `expected_schema` (e.g. `UPSTREAM_SCHEMA`). Returns a validation
/// `Problem` (with `instance` pre-populated from the supplied request
/// URI) if the prefix does not match.
#[allow(clippy::result_large_err)]
pub fn parse_gts_id(gts_str: &str, expected_schema: &str, instance: &str) -> Result<Uuid, Problem> {
    let (schema, uuid) = gts_helpers::parse_resource_gts(gts_str)
        .map_err(|e| domain_error_to_problem(e, instance))?;
    let expected_prefix = expected_schema.trim_end_matches('~');
    let actual_prefix = schema.trim_end_matches('~');
    if actual_prefix != expected_prefix {
        let err = DomainError::Validation {
            field: "gts_id",
            reason: field::INVALID_GTS_SCHEMA,
            detail: format!("expected GTS schema '{expected_schema}' but got '{schema}'"),
            instance: instance.to_string(),
        };
        return Err(domain_error_to_problem(err, instance));
    }
    Ok(uuid)
}

/// Pagination query parameters.
///
/// Naming note: the wire field is `limit` (not `top`); [`default_top`]
/// predates that rename and was left as-is rather than touched for a pure
/// rename — the field it defaults, `limit`, is what actually matters.
#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_top")]
    pub limit: u32,
    #[serde(default)]
    pub offset: u32,
}

fn default_top() -> u32 {
    50
}

/// Deployment-wide default/max page size for control-plane list endpoints
/// (ML-5024). `default` and [`default_top`] are kept at `50` by
/// convention, not by any runtime equivalence: `PaginationQuery::limit` is
/// a plain `u32` (not `Option`), so `#[serde(default = "default_top")]`
/// always populates it — from the query string when present, from
/// [`default_top`] otherwise — before [`PaginationQuery::to_list_query`]
/// calls [`resolve_page_size`] with `Some(...)`. `resolve_page_size`'s
/// `None` branch is structurally unreachable from this call site; nothing
/// here re-checks that the two constants agree if one of them drifts.
const PAGINATION_LIMIT_CFG: LimitCfg = LimitCfg::new(50, 100);

impl PaginationQuery {
    /// # Errors
    /// Returns [`DomainError::Validation`] if `limit` is `0`.
    pub fn to_list_query(&self) -> Result<ListQuery, DomainError> {
        let top =
            resolve_page_size(Some(u64::from(self.limit)), PAGINATION_LIMIT_CFG).map_err(|e| {
                DomainError::Validation {
                    field: "limit",
                    reason: field::INVALID_LIMIT,
                    detail: e.to_string(),
                    instance: String::new(),
                }
            })?;
        Ok(ListQuery {
            // `top` is bounded by `PAGINATION_LIMIT_CFG.max == 100`, well
            // within `u32`; `unwrap_or(u32::MAX)` is unreachable in
            // practice and only avoids a panic if that bound ever changes.
            top: u32::try_from(top.get()).unwrap_or(u32::MAX),
            skip: self.offset,
        })
    }
}
