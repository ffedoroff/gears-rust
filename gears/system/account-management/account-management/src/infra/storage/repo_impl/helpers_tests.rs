// Most of the repo_impl logic is exercised through integration tests
// against a real DB (Phase 3 owns cross-backend coverage). These unit
// tests cover the pure helpers only.
use super::*;
use account_management_sdk::error::AccountManagementError;
use time::OffsetDateTime;
use toolkit_canonical_errors::CanonicalError;

#[test]
fn entity_to_model_rejects_unknown_status() {
    let row = tenants::Model {
        id: Uuid::nil(),
        parent_id: None,
        name: "x".into(),
        status: 42,
        self_managed: false,
        tenant_type_uuid: Uuid::nil(),
        depth: 0,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        deleted_at: None,
        retention_window_secs: None,
        claimed_by: None,
        claimed_at: None,
        terminal_failure_at: None,
    };
    let err = entity_to_model(row).expect_err("unknown status");
    assert!(matches!(err, DomainError::Internal { .. }));
}

#[test]
fn entity_to_model_rejects_negative_depth() {
    let row = tenants::Model {
        id: Uuid::nil(),
        parent_id: None,
        name: "x".into(),
        status: 1,
        self_managed: false,
        tenant_type_uuid: Uuid::nil(),
        depth: -1,
        created_at: OffsetDateTime::UNIX_EPOCH,
        updated_at: OffsetDateTime::UNIX_EPOCH,
        deleted_at: None,
        retention_window_secs: None,
        claimed_by: None,
        claimed_at: None,
        terminal_failure_at: None,
    };
    let err = entity_to_model(row).expect_err("negative depth");
    assert!(matches!(err, DomainError::Internal { .. }));
}

/// `ScopeError::Db` MUST be lifted into the retry-aware `TxError::Db`
/// variant so [`with_serializable_retry`]'s `extract_db_err` can hand
/// the raw `DbErr` to `is_retryable_contention`. After retry exhaustion,
/// the helper translates the surviving `DbErr` into a typed
/// `DomainError` via `classify_db_err_to_domain` — domain code never
/// sees a `sea_orm::DbErr`.
#[test]
fn map_scope_to_tx_lifts_db_err_into_tx_db_variant() {
    use sea_orm::{DbErr, RuntimeErr};
    use toolkit_db::secure::ScopeError;
    let scope_err = ScopeError::Db(DbErr::Exec(RuntimeErr::Internal(
        "error returned from database: 40001: could not serialize access".to_owned(),
    )));
    let err = map_scope_to_tx(scope_err);
    assert!(matches!(err, TxError::Db(_)));
    assert!(err.db_err().is_some());
}

/// `ScopeError::TenantNotInScope` is a typed cross-tenant denial — it
/// MUST always map to `DomainError::CrossTenantDenied`, both inside
/// retry bodies (via `map_scope_to_tx`) and outside them (via
/// `map_scope_err`). The boundary mapping then converts that to
/// `CanonicalError::PermissionDenied` (HTTP 403).
#[test]
fn map_scope_err_preserves_tenant_not_in_scope_routing() {
    use toolkit_db::secure::ScopeError;
    let scope_err = ScopeError::TenantNotInScope {
        tenant_id: Uuid::nil(),
    };
    let err = map_scope_err(scope_err);
    assert!(matches!(err, DomainError::CrossTenantDenied { .. }));
    let ame = AccountManagementError::from(CanonicalError::from(err));
    assert!(matches!(
        ame,
        AccountManagementError::PermissionDenied { .. }
    ));
}

#[test]
fn map_scope_to_tx_preserves_tenant_not_in_scope_routing() {
    use toolkit_db::secure::ScopeError;
    let scope_err = ScopeError::TenantNotInScope {
        tenant_id: Uuid::nil(),
    };
    let err = map_scope_to_tx(scope_err);
    let TxError::Domain(domain) = err else {
        panic!("expected TxError::Domain");
    };
    assert!(matches!(domain, DomainError::CrossTenantDenied { .. }));
}

// ---------------------------------------------------------------------
// `map_odata_err` / `map_paginate_try_err` (ML-2864)
//
// `paginate_odata` / `paginate_odata_try` surface `toolkit_odata::Error`
// (15 variants). Only `Db` and `ParsingUnavailable` are infrastructure
// failures (contract in `toolkit_odata::lib` module docs and
// `toolkit_odata::problem_mapping`) — every other variant is a genuine
// client mistake (bad `$filter`, unknown `$orderby` field, malformed
// cursor, bad `$top`). Collapsing everything to `Validation` (as the
// pre-fix code did) means a DB outage is reported to the client as a
// rejected request instead of alerting operators.
// ---------------------------------------------------------------------

/// Every "client mistake" variant `toolkit_odata::Error` can produce:
/// 13 of the 15, the other two being `Db` / `ParsingUnavailable`.
///
/// This list does NOT protect against a variant being added upstream — it is
/// a `Vec` constructor, and a new variant compiles fine here. That protection
/// lives in `map_odata_err`, whose `match` is exhaustive with no wildcard, so
/// a new variant fails the build there and forces an explicit 400/500 call.
/// Keep this list in sync with that `match` when it happens.
fn client_odata_errors() -> Vec<ODataError> {
    vec![
        ODataError::InvalidFilter("bad filter".to_owned()),
        ODataError::InvalidOrderByField("nope".to_owned()),
        ODataError::OrderMismatch,
        ODataError::FilterMismatch,
        ODataError::InvalidCursor,
        ODataError::InvalidLimit,
        ODataError::OrderWithCursor,
        ODataError::CursorInvalidBase64,
        ODataError::CursorInvalidJson,
        ODataError::CursorInvalidVersion,
        ODataError::CursorInvalidKeys,
        ODataError::CursorInvalidFields,
        ODataError::CursorInvalidDirection,
    ]
}

/// The defect this closes: an infrastructure failure (`Db`) MUST NOT
/// be reported to the client as a rejected request. Before the fix
/// this asserted `Internal` and failed — the pre-fix helper returned
/// `Validation { detail: "test query rejected: database error: pool
/// exhausted" }`.
#[test]
fn map_odata_err_db_is_internal() {
    let err = map_odata_err(ODataError::Db("pool exhausted".to_owned()), "test query");
    let DomainError::Internal { diagnostic, cause } = err else {
        panic!("Error::Db MUST classify as DomainError::Internal (HTTP 500), got {err:?}");
    };
    assert!(
        diagnostic.contains("test query"),
        "diagnostic should keep the caller's operation label: {diagnostic}"
    );
    assert!(
        diagnostic.contains("failed"),
        "infra branch must talk about failure, not rejection: {diagnostic}"
    );
    assert!(
        !diagnostic.contains("rejected"),
        "infra branch must NOT read like a rejected client request: {diagnostic}"
    );
    assert!(
        cause.is_some(),
        "upstream Db error should ride the cause chain"
    );
}

/// Second (and last) infrastructure variant — a misconfigured `OData`
/// parser is an operator problem, not a bad request.
#[test]
fn map_odata_err_parsing_unavailable_is_internal() {
    let err = map_odata_err(ODataError::ParsingUnavailable("nom disabled"), "test query");
    assert!(
        matches!(err, DomainError::Internal { .. }),
        "Error::ParsingUnavailable MUST classify as DomainError::Internal, got {err:?}"
    );
}

/// Every client-mistake variant MUST classify as `Validation` (HTTP
/// 400) and MUST preserve the original explanatory text (the mapper's
/// diagnostic, e.g. "invalid `status` value ...") in the `detail`.
#[test]
fn map_odata_err_client_variants_are_validation() {
    for odata_err in client_odata_errors() {
        let rendered = odata_err.to_string();
        let err = map_odata_err(odata_err, "list_children query");
        let DomainError::Validation { detail } = err else {
            panic!("client OData error MUST classify as Validation, got {err:?}");
        };
        assert_eq!(
            detail,
            format!("list_children query rejected: {rendered}"),
            "client branch must preserve the existing \"<op> rejected: <err>\" wording"
        );
    }
}

/// `PaginateOdataTryError::OData(Db)` MUST still route through the
/// infra branch after unwrapping — the outer envelope must not swallow
/// the classification.
#[test]
fn map_paginate_try_err_odata_db_variant_is_internal() {
    let err = map_paginate_try_err(
        PaginateOdataTryError::OData(ODataError::Db("connection reset".to_owned())),
        "list_children query",
    );
    assert!(
        matches!(err, DomainError::Internal { .. }),
        "PaginateOdataTryError::OData(Db) MUST classify as Internal, got {err:?}"
    );
}

/// `PaginateOdataTryError::MapError` carries the caller's own domain
/// error (e.g. a row-shape drift already classified as `Internal` by
/// `entity_to_model`). It MUST pass through verbatim — `map_paginate_try_err`
/// must not re-derive or reformat it.
#[test]
fn map_paginate_try_err_map_error_passes_through_verbatim() {
    let inner = DomainError::Internal {
        diagnostic: "tenants.status out-of-domain value: 42".to_owned(),
        cause: None,
    };
    let err = map_paginate_try_err(
        PaginateOdataTryError::MapError(inner),
        "list_children query",
    );
    let DomainError::Internal { diagnostic, .. } = err else {
        panic!("MapError must pass through as Internal, got {err:?}");
    };
    assert_eq!(
        diagnostic, "tenants.status out-of-domain value: 42",
        "MapError's diagnostic must be preserved verbatim, not reformatted with the op label"
    );
}
