// Created: 2026-07-29 by Constructor Tech
//! VHP-2342: `AuthZ` gate coverage for the GTS type-registry CRUD surface.
//!
//! `/types-registry/v1/types` (list/create/read/update/delete) used to be
//! `.authenticated()`-only: any caller from any tenant could rewrite global
//! type rules. These tests cover the fix at the domain (`TypeService`)
//! level:
//!
//! 1. The `require_constraints` proof: `gts_type` is a platform-global table
//!    (no `tenant_id` column), so `RG_TYPE_RESOURCE` declares an empty
//!    `supported_properties` list. `access_scope_denied_by_default_require_constraints`
//!    demonstrates that the plain `PolicyEnforcer::access_scope` default
//!    (`require_constraints = true`) turns a legitimate allow-with-no-
//!    constraints PDP response into `EnforcerError::CompileFailed`
//!    (`ConstraintsRequiredButAbsent`) -- which `DomainError::from` maps to
//!    `InternalError`, a 500, not success. `access_scope_with_require_constraints_false_succeeds`
//!    shows the fix: the same PDP response compiles cleanly to
//!    `AccessScope::allow_all()`.
//! 2. Deny-all vs. allow-all-no-constraints coverage for each of the five
//!    gated `TypeService` methods.
//! 3. `seed_types` (and the `*_unscoped` methods it calls) still works with
//!    no `SecurityContext` at all -- even wired to a deny-all enforcer that
//!    would reject every gated call.
//!
//! `tests/api_rest_test.rs` covers the same five actions at the HTTP layer
//! (`list_types_denied_returns_403` etc.), asserting the actual wire status
//! code produced by the `DomainError` -> `CanonicalError` mapping.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use authz_resolver_sdk::pep::{AccessRequest, ConstraintCompileError, EnforcerError};
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, EvaluationRequest, EvaluationResponse,
    EvaluationResponseContext, PolicyEnforcer,
};

use resource_group::domain::error::DomainError;
use resource_group::domain::seeding::seed_types;
use resource_group::domain::type_service::{RG_TYPE_RESOURCE, TypeService};
use resource_group::infra::storage::type_repo::TypeRepository;
use resource_group_sdk::{CreateTypeRequest, UpdateTypeRequest};

/// Always permits, never attaches constraints -- the only PDP shape that
/// makes sense for a resource whose descriptor declares zero
/// `supported_properties` (see [`RG_TYPE_RESOURCE`]).
struct AllowAllNoConstraintsAuthZ;

#[async_trait]
impl AuthZResolverClient for AllowAllNoConstraintsAuthZ {
    async fn evaluate(
        &self,
        _request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        Ok(EvaluationResponse {
            decision: true,
            context: EvaluationResponseContext {
                constraints: vec![],
                deny_reason: None,
            },
        })
    }
}

/// Always denies.
struct DenyAllAuthZ;

#[async_trait]
impl AuthZResolverClient for DenyAllAuthZ {
    async fn evaluate(
        &self,
        _request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        Ok(EvaluationResponse {
            decision: false,
            context: EvaluationResponseContext {
                constraints: vec![],
                deny_reason: None,
            },
        })
    }
}

fn unique_code(suffix: &str) -> String {
    format!(
        "{}x.test.{}.i{}.v1~",
        toolkit_gts::gts_id!("cf.core.rg.type.v1~"),
        suffix,
        Uuid::now_v7().as_simple()
    )
}

// ═══════════════════════════════════════════════════════════════════════
// 1. require_constraints proof (the "which request form" experiment)
// ═══════════════════════════════════════════════════════════════════════

/// The plain `access_scope` default (`require_constraints = true`) fails a
/// legitimate allow decision for a resource with empty `supported_properties`:
/// the PDP correctly returns no constraints (there is nothing it *could*
/// constrain), but the default demands constraints be present regardless
/// and fails closed with `ConstraintsRequiredButAbsent`.
#[tokio::test]
async fn access_scope_denied_by_default_require_constraints() {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(AllowAllNoConstraintsAuthZ);
    let enforcer = PolicyEnforcer::new(authz);
    let ctx = common::make_ctx(Uuid::now_v7());

    let result = enforcer
        .access_scope(&ctx, &RG_TYPE_RESOURCE, "list", None)
        .await;

    assert!(
        result.is_err(),
        "default require_constraints=true must reject an allow-with-no-constraints response"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            EnforcerError::CompileFailed(ConstraintCompileError::ConstraintsRequiredButAbsent)
        ),
        "expected ConstraintsRequiredButAbsent"
    );

    // And that CompileFailed is exactly the failure mode that would surface
    // as an internal error (500), not a clean permission check -- the
    // reason TypeService does NOT use the `access_scope` default.
    let mapped = DomainError::from(EnforcerError::CompileFailed(
        ConstraintCompileError::ConstraintsRequiredButAbsent,
    ));
    assert!(
        matches!(mapped, DomainError::InternalError),
        "CompileFailed must map to InternalError, not AccessDenied: {mapped:?}"
    );
}

/// `access_scope_with(.., require_constraints(false))` -- the form
/// `TypeService` actually uses -- compiles the identical PDP response to
/// `AccessScope::allow_all()` instead of erroring.
#[tokio::test]
async fn access_scope_with_require_constraints_false_succeeds() {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(AllowAllNoConstraintsAuthZ);
    let enforcer = PolicyEnforcer::new(authz);
    let ctx = common::make_ctx(Uuid::now_v7());

    let scope = enforcer
        .access_scope_with(
            &ctx,
            &RG_TYPE_RESOURCE,
            "list",
            None,
            &AccessRequest::new().require_constraints(false),
        )
        .await
        .expect("require_constraints(false) must succeed on an allow-with-no-constraints permit");

    assert!(scope.is_unconstrained(), "scope should be allow_all");
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Per-action deny / allow coverage for TypeService's five gated methods
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn list_types_denied_returns_access_denied() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(DenyAllAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(Uuid::now_v7());

    let err = svc
        .list_types(&ctx, &toolkit_odata::ODataQuery::default())
        .await
        .expect_err("deny-all enforcer must reject list_types");
    assert!(
        matches!(err, DomainError::AccessDenied { .. }),
        "expected AccessDenied: {err:?}"
    );
}

#[tokio::test]
async fn create_type_denied_returns_access_denied() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(DenyAllAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(Uuid::now_v7());

    let err = svc
        .create_type(
            &ctx,
            CreateTypeRequest {
                code: unique_code("authzdeny"),
                can_be_root: true,
                allowed_parent_types: vec![],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .expect_err("deny-all enforcer must reject create_type");
    assert!(
        matches!(err, DomainError::AccessDenied { .. }),
        "expected AccessDenied: {err:?}"
    );
}

#[tokio::test]
async fn get_type_denied_returns_access_denied() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(DenyAllAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(Uuid::now_v7());

    // No type needs to exist -- the gate must run (and reject) before any lookup.
    let err = svc
        .get_type(&ctx, &unique_code("authzdenyget"))
        .await
        .expect_err("deny-all enforcer must reject get_type");
    assert!(
        matches!(err, DomainError::AccessDenied { .. }),
        "expected AccessDenied: {err:?}"
    );
}

#[tokio::test]
async fn update_type_denied_returns_access_denied() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(DenyAllAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(Uuid::now_v7());

    let err = svc
        .update_type(
            &ctx,
            &unique_code("authzdenyupd"),
            UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .expect_err("deny-all enforcer must reject update_type");
    assert!(
        matches!(err, DomainError::AccessDenied { .. }),
        "expected AccessDenied: {err:?}"
    );
}

#[tokio::test]
async fn delete_type_denied_returns_access_denied() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(DenyAllAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(Uuid::now_v7());

    let err = svc
        .delete_type(&ctx, &unique_code("authzdenydel"))
        .await
        .expect_err("deny-all enforcer must reject delete_type");
    assert!(
        matches!(err, DomainError::AccessDenied { .. }),
        "expected AccessDenied: {err:?}"
    );
}

/// Allow-all-no-constraints enforcer permits all five actions end to end.
#[tokio::test]
async fn all_five_actions_succeed_with_allow_all_no_constraints() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(AllowAllNoConstraintsAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(Uuid::now_v7());

    let code = unique_code("authzallow");
    let created = svc
        .create_type(
            &ctx,
            CreateTypeRequest {
                code: code.clone(),
                can_be_root: true,
                allowed_parent_types: vec![],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .expect("create_type should succeed");
    assert_eq!(created.code, code);

    svc.get_type(&ctx, &code)
        .await
        .expect("get_type should succeed");

    svc.list_types(&ctx, &toolkit_odata::ODataQuery::default())
        .await
        .expect("list_types should succeed");

    svc.update_type(
        &ctx,
        &code,
        UpdateTypeRequest {
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        },
    )
    .await
    .expect("update_type should succeed");

    svc.delete_type(&ctx, &code)
        .await
        .expect("delete_type should succeed");
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Seeding bypasses the gate entirely (no SecurityContext at gear init)
// ═══════════════════════════════════════════════════════════════════════

/// `seed_types` must succeed even when `TypeService` is wired with a
/// deny-all enforcer: seeding runs at gear init, before any caller
/// `SecurityContext` exists, and goes through the `*_unscoped` entry points
/// which never consult the `PolicyEnforcer` (VHP-2342).
#[tokio::test]
async fn seed_types_succeeds_with_deny_all_enforcer() {
    let db = common::test_db().await;
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(DenyAllAuthZ)),
        Arc::new(TypeRepository),
    );

    let code = unique_code("seedbypass");
    let seeds = vec![CreateTypeRequest {
        code: code.clone(),
        can_be_root: true,
        allowed_parent_types: vec![],
        allowed_membership_types: vec![],
        metadata_schema: None,
    }];

    let result = seed_types(&svc, &seeds)
        .await
        .expect("seed_types must succeed without any SecurityContext, even under a deny-all PDP");
    assert_eq!(result.created, 1);

    // A gated read would be denied by this same enforcer; the unscoped read
    // used internally by seeding must not be.
    let loaded = svc
        .get_type_unscoped(&code)
        .await
        .expect("get_type_unscoped must not consult the deny-all enforcer");
    assert_eq!(loaded.code, code);
}
