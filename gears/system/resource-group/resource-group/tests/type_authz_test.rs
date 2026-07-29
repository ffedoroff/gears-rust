// Created: 2026-07-29 by Constructor Tech
//! VHP-2342: `AuthZ` gate coverage for the GTS type-registry CRUD surface.
//!
//! `/types-registry/v1/types` (list/create/read/update/delete) used to be
//! `.authenticated()`-only: any caller from any tenant could rewrite global
//! type rules. These tests cover the fix at the domain (`TypeService`)
//! level:
//!
//! 1. The `require_constraints` proof: a PDP may permit with *zero*
//!    constraints at all (`decision: true, constraints: []`) --
//!    `access_scope_denied_by_default_require_constraints` demonstrates that
//!    the plain `PolicyEnforcer::access_scope` default (`require_constraints
//!    = true`) turns that legitimate allow-with-no-constraints PDP response
//!    into `EnforcerError::CompileFailed` (`ConstraintsRequiredButAbsent`) --
//!    which `DomainError::from` maps to `InternalError`, a 500, not success.
//!    `access_scope_with_require_constraints_false_succeeds` shows the fix:
//!    the same PDP response compiles cleanly to `AccessScope::allow_all()`.
//! 2. The `supported_properties` proof: real PDP plugins never actually
//!    return the no-constraints shape above -- `static-authz-plugin` and
//!    `tr-authz-plugin` both attach a baseline `In(OWNER_TENANT_ID)`
//!    constraint to *every* allow decision (see [`TenantClampAuthZ`]).
//!    `RG_TYPE_RESOURCE` originally declared an empty `supported_properties`
//!    list on the theory that `gts_type` (a platform-global table, no
//!    `tenant_id` column) has nothing to filter on -- but the compiler
//!    rejects a constraint whose property isn't declared *before* anything
//!    downstream gets a chance to ignore the resulting scope, so that empty
//!    list turned every allowed call into `AllConstraintsFailed` ->
//!    `InternalError` (a 500). `access_scope_with_realistic_tenant_clamp_constraint_succeeds`
//!    and `all_five_actions_succeed_with_realistic_tenant_clamp_constraint`
//!    reproduce and close that gap; see `RG_TYPE_RESOURCE`'s doc comment in
//!    `type_service.rs` for the full explanation.
//! 3. Deny-all vs. allow-all (both the no-constraints and realistic-clamp
//!    shapes) coverage for each of the five gated `TypeService` methods.
//! 4. `seed_types` (and the `*_unscoped` methods it calls) still works with
//!    no `SecurityContext` at all -- even wired to a deny-all enforcer that
//!    would reject every gated call.
//! 5. `ResourceGroupLocalClient` -- the `dyn ResourceGroupClient` adapter registered in
//!    `ClientHub` -- is gated exactly like `TypeService`'s direct entry
//!    points, with no exception for any caller shape:
//!    `local_client_type_lifecycle_denied_under_deny_all_enforcer_and_nil_tenant`
//!    drives all five type methods through `ResourceGroupLocalClient` with a deny-all
//!    enforcer and an `am.system`-shaped, nil-tenant `SecurityContext`
//!    (account-management's platform-scoped system actor,
//!    `system_actor.rs::for_gear_init`) and asserts every one comes back
//!    `PermissionDenied`. A prior commit (`484d0582`) briefly routed these
//!    five methods around the gate for exactly this caller; that bypass was
//!    reverted (owner decision -- see `docs/DESIGN.md` and the revert
//!    commit) because it handed every in-process `ClientHub` caller the
//!    same unscoped access, not just this one bootstrap path. This test is
//!    the replacement coverage and must keep failing (i.e. keep asserting
//!    denial) for as long as that decision stands.
//!
//! `tests/api_rest_test.rs` covers the same five actions at the HTTP layer
//! (`list_types_denied_returns_403` etc.), asserting the actual wire status
//! code produced by the `DomainError` -> `CanonicalError` mapping, plus a
//! realistic-clamp-mock check that a gated route succeeds end to end.

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use authz_resolver_sdk::constraints::{Constraint, InPredicate, Predicate};
use authz_resolver_sdk::pep::{AccessRequest, ConstraintCompileError, EnforcerError};
use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, EvaluationRequest, EvaluationResponse,
    EvaluationResponseContext, PolicyEnforcer,
};
use toolkit_security::{SecurityContext, pep_properties};

use resource_group::domain::error::DomainError;
use resource_group::domain::local_client::ResourceGroupLocalClient;
use resource_group::domain::seeding::seed_types;
use resource_group::domain::type_service::{RG_TYPE_RESOURCE, TypeService};
use resource_group::infra::storage::type_repo::TypeRepository;
use resource_group_sdk::{CreateTypeRequest, ResourceGroupClient, UpdateTypeRequest};

/// Always permits, never attaches constraints. This is *a* valid PDP permit
/// shape (`decision: true, constraints: []`) -- not the *only* one. It
/// covers the `require_constraints(false)` escape hatch (see
/// `access_scope_with_require_constraints_false_succeeds` below), but it is
/// NOT representative of what a real PDP plugin returns: both
/// `static-authz-plugin` and `tr-authz-plugin` always attach a baseline
/// `In(OWNER_TENANT_ID)` constraint on every allow decision, for every
/// resource, regardless of whether that resource has a tenant column. See
/// [`TenantClampAuthZ`] below for that shape -- it is the one that actually
/// caught the VHP-2342 empty-`supported_properties` regression that this
/// mock's original doc comment ("the only sensible shape") missed.
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

/// Realistic PDP mock: permit + the baseline `In(OWNER_TENANT_ID)`
/// constraint that every real `AuthZ` plugin in this repo attaches to
/// *every* allow decision, for *every* resource -- see
/// `static-authz-plugin`'s `Service::evaluate` ("Baseline `OWNER_TENANT_ID`
/// clamp -- the universal shape every PEP can bind") and
/// `tr-authz-plugin`'s mandatory `owner_tenant_id` property. It is the same
/// shape `tests/tenant_filtering_db_test.rs`'s `TenantScopingAuthZ` and
/// `tests/common/mod.rs`'s `AllowAllAuthZ` use for `GroupService`/
/// `MembershipService`.
///
/// This is the mock that exposes the VHP-2342 regression
/// `AllowAllNoConstraintsAuthZ` above cannot: against an empty
/// `supported_properties` list, `owner_tenant_id` is an "unsupported
/// property" to the compiler, and since it is the *only* constraint on the
/// response, `compile_to_access_scope` returns
/// `Err(ConstraintCompileError::AllConstraintsFailed)` -- fail-closed --
/// which `DomainError::from(EnforcerError)` maps to `InternalError` (a 500)
/// for what the PDP intended as an *allow*.
struct TenantClampAuthZ;

#[async_trait]
impl AuthZResolverClient for TenantClampAuthZ {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
        // `.unwrap_or(Uuid::nil())` rather than `.expect(..)`, matching
        // `common::AllowAllAuthZ` / `common::AllowAllAuthZ` in
        // `tests/api_rest_test.rs`: this is non-test code from clippy's
        // point of view (an `AuthZResolverClient` impl invoked *by* test
        // functions, not a `#[tokio::test]` fn itself), so
        // `allow-expect-in-tests` in `clippy.toml` does not cover it. Every
        // caller in this file goes through `common::make_ctx`, which always
        // sets a real tenant id, so the fallback path is unreachable here.
        let tenant_id = request
            .subject
            .properties
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or(Uuid::nil());

        Ok(EvaluationResponse {
            decision: true,
            context: EvaluationResponseContext {
                constraints: vec![Constraint {
                    predicates: vec![Predicate::In(InPredicate::new(
                        pep_properties::OWNER_TENANT_ID,
                        [tenant_id],
                    ))],
                }],
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

/// `access_scope_with(.., require_constraints(false))` against the
/// *realistic* PDP shape: permit + a present `In(OWNER_TENANT_ID)`
/// constraint (see [`TenantClampAuthZ`]), not the artificial
/// permit-with-zero-constraints shape the other `access_scope_with_*` test
/// above exercises. This must compile successfully once `RG_TYPE_RESOURCE`
/// declares `OWNER_TENANT_ID` as supported -- the scope it compiles to
/// legitimately carries a filter this time (`TypeService::gate` throws it
/// away regardless; this test only proves compilation succeeds).
#[tokio::test]
async fn access_scope_with_realistic_tenant_clamp_constraint_succeeds() {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(TenantClampAuthZ);
    let enforcer = PolicyEnforcer::new(authz);
    let ctx = common::make_ctx(Uuid::now_v7());

    enforcer
        .access_scope_with(
            &ctx,
            &RG_TYPE_RESOURCE,
            "list",
            None,
            &AccessRequest::new().require_constraints(false),
        )
        .await
        .expect(
            "realistic PDP permit (In(OWNER_TENANT_ID) constraint) must compile now that \
             RG_TYPE_RESOURCE declares OWNER_TENANT_ID as supported",
        );
}

/// End-to-end regression proof for VHP-2342's actual defect: a PDP that
/// responds the way real plugins do (permit + baseline `In(OWNER_TENANT_ID)`
/// constraint, see [`TenantClampAuthZ`]) must still permit all five gated
/// `TypeService` actions. Before `RG_TYPE_RESOURCE` declared
/// `OWNER_TENANT_ID`, every one of these calls failed closed with
/// `DomainError::InternalError` (`EnforcerError::CompileFailed(
/// ConstraintCompileError::AllConstraintsFailed { .. })`) instead of
/// succeeding -- i.e. every legitimately-allowed caller got a 500, not just
/// denied ones. `all_five_actions_succeed_with_allow_all_no_constraints`
/// above did not catch this because its mock never attaches a constraint at
/// all.
#[tokio::test]
async fn all_five_actions_succeed_with_realistic_tenant_clamp_constraint() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let svc = TypeService::new(
        db,
        PolicyEnforcer::new(Arc::new(TenantClampAuthZ)),
        Arc::new(TypeRepository),
    );
    let ctx = common::make_ctx(tenant_id);

    let code = unique_code("authzclamp");
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
        .expect("create_type should succeed under a realistic PDP permit");
    assert_eq!(created.code, code);

    svc.get_type(&ctx, &code)
        .await
        .expect("get_type should succeed under a realistic PDP permit");

    svc.list_types(&ctx, &toolkit_odata::ODataQuery::default())
        .await
        .expect("list_types should succeed under a realistic PDP permit");

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
    .expect("update_type should succeed under a realistic PDP permit");

    svc.delete_type(&ctx, &code)
        .await
        .expect("delete_type should succeed under a realistic PDP permit");
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

// ═══════════════════════════════════════════════════════════════════════
// 5. ResourceGroupLocalClient (the ClientHub `dyn ResourceGroupClient` adapter) is gated
//    -- no in-process bypass exists for its five type methods.
// ═══════════════════════════════════════════════════════════════════════

/// `ResourceGroupLocalClient`'s five type-lifecycle methods must be denied when the
/// `TypeService` they delegate to is wired to a deny-all enforcer -- even
/// for a nil-tenant, `am.system`-shaped `SecurityContext`, the shape
/// account-management's platform-scoped system actor produces
/// (`account-management/src/domain/system_actor.rs::for_gear_init`,
/// `subject_type = "am.system"`, `subject_tenant_id = Uuid::nil()`).
///
/// `484d0582` briefly routed these five methods around `TypeService`'s gate
/// (calling the `*_unscoped` variants directly) specifically so this
/// nil-tenant actor would succeed. The owner reverted that: it handed every
/// in-process `ClientHub` caller -- not just AM's bootstrap path -- the same
/// unscoped access to the whole type registry, without ever inspecting
/// `ctx`. See `docs/DESIGN.md`'s expected-permissions notes and the revert
/// commit for the full rationale.
///
/// AM's side of that story has since been fixed **on the caller**, not
/// here: the user-group type registration moved out of `Gear::init` into
/// `AccountManagementGear::serve` (an `AuthZ`-gated call is impossible
/// during init at all -- the PDP plugin only becomes resolvable after the
/// post-init barrier) and now runs under the tenant-bound
/// `system_actor::for_bootstrap(root_id)` subject, which a tenant-clamping
/// PDP can authorize. This test is unaffected and stays as-is: it asserts
/// the *adapter* is gated, and the nil-tenant `am.system` shape it drives
/// is exactly the caller shape that must keep being denied. It must keep
/// observing denial for as long as the revert stands -- a caller that needs
/// to succeed against a real `PolicyEnforcer` fixes its own phase and
/// subject, not RG's gate.
#[tokio::test]
async fn local_client_type_lifecycle_denied_under_deny_all_enforcer_and_nil_tenant() {
    let db = common::test_db().await;
    let local_client = ResourceGroupLocalClient::new(
        Arc::new(common::make_type_service_deny(db.clone())),
        Arc::new(common::make_group_service_deny(db.clone())),
        Arc::new(common::make_membership_service_deny(db)),
    );

    // Mirrors `system_actor::for_gear_init()`'s output shape exactly:
    // stable subject, "am.system" subject_type, nil subject_tenant_id.
    let ctx = SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_type("am.system")
        .subject_tenant_id(Uuid::nil())
        .build()
        .expect("valid SecurityContext");

    let code = unique_code("rggated");

    let err = local_client
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
        .expect_err(
            "ResourceGroupLocalClient::create_type must be denied by the gate, not bypass it",
        );
    assert_eq!(
        err.status_code(),
        403,
        "expected PermissionDenied (403): {err:?}"
    );

    let err = local_client
        .get_type(&ctx, &code)
        .await
        .expect_err("ResourceGroupLocalClient::get_type must be denied by the gate, not bypass it");
    assert_eq!(
        err.status_code(),
        403,
        "expected PermissionDenied (403): {err:?}"
    );

    let err = local_client
        .list_types(&ctx, &toolkit_odata::ODataQuery::default())
        .await
        .expect_err(
            "ResourceGroupLocalClient::list_types must be denied by the gate, not bypass it",
        );
    assert_eq!(
        err.status_code(),
        403,
        "expected PermissionDenied (403): {err:?}"
    );

    let err = local_client
        .update_type(
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
        .expect_err(
            "ResourceGroupLocalClient::update_type must be denied by the gate, not bypass it",
        );
    assert_eq!(
        err.status_code(),
        403,
        "expected PermissionDenied (403): {err:?}"
    );

    let err = local_client.delete_type(&ctx, &code).await.expect_err(
        "ResourceGroupLocalClient::delete_type must be denied by the gate, not bypass it",
    );
    assert_eq!(
        err.status_code(),
        403,
        "expected PermissionDenied (403): {err:?}"
    );
}
