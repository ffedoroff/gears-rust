// Created: 2026-04-16 by Constructor Tech
// @cpt-dod:cpt-cf-resource-group-dod-testing-rest-api:p2
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]
//! API-level tests using `Router::oneshot` pattern.
//!
//! Verifies HTTP-level behavior: status codes, response shapes,
//! `OData` query parsing, and RFC 9457 error format.

mod common;

use std::sync::Arc;
use toolkit_gts::gts_id;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use uuid::Uuid;

use authz_resolver_sdk::{
    AuthZResolverClient, AuthZResolverError, EvaluationRequest, EvaluationResponse,
    EvaluationResponseContext, PolicyEnforcer,
    constraints::{Constraint, InPredicate, Predicate},
};
use sea_orm_migration::MigratorTrait;
use toolkit::api::OpenApiRegistry;
use toolkit::api::operation_builder::OperationSpec;
use toolkit_db::{
    ConnectOpts, DBProvider, DbError, connect_db, migration_runner::run_migrations_for_testing,
};
use toolkit_odata::{CursorV1, SortDir};
use toolkit_security::{SecurityContext, pep_properties};

use resource_group::domain::group_service::{GroupService, QueryProfile};
use resource_group::domain::membership_service::MembershipService;
use resource_group::domain::type_service::TypeService;
use resource_group::infra::storage::group_repo::GroupRepository;
use resource_group::infra::storage::membership_repo::MembershipRepository;
use resource_group::infra::storage::migrations::Migrator;
use resource_group::infra::storage::type_repo::TypeRepository;

macro_rules! rg_type_id {
    ($($arg:tt)*) => {
        format!("{}{}", gts_id!("cf.core.rg.type.v1~"), format_args!($($arg)*))
    };
}

// ── Noop OpenAPI Registry for tests ─────────────────────────────────────

struct NoopOpenApiRegistry;

impl OpenApiRegistry for NoopOpenApiRegistry {
    fn register_operation(&self, _spec: &OperationSpec) {}

    fn ensure_schema_raw(
        &self,
        name: &str,
        _schemas: Vec<(
            String,
            utoipa::openapi::RefOr<utoipa::openapi::schema::Schema>,
        )>,
    ) -> String {
        name.to_owned()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ── Mock AuthZ: allow-all with tenant scoping ───────────────────────────

struct AllowAllAuthZ;

#[async_trait]
impl AuthZResolverClient for AllowAllAuthZ {
    async fn evaluate(
        &self,
        request: EvaluationRequest,
    ) -> Result<EvaluationResponse, AuthZResolverError> {
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

// ── Test setup ──────────────────────────────────────────────────────────

async fn test_db() -> Arc<DBProvider<DbError>> {
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db("sqlite::memory:", opts)
        .await
        .expect("connect to in-memory SQLite");

    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .expect("run migrations");

    Arc::new(DBProvider::new(db))
}

fn make_ctx(tenant_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_tenant_id(tenant_id)
        .build()
        .expect("valid SecurityContext")
}

fn make_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(AllowAllAuthZ);
    PolicyEnforcer::new(authz)
}

// ── Mock AuthZ: allow-all, no constraints (for `TypeService`) ──────────
//
// `gts_type` is a platform-global table (no `tenant_id` column), and
// `TypeService`'s gate discards the `AccessScope` it computes regardless of
// shape, so every gate call uses `require_constraints(false)` (VHP-2342) to
// also accept this permit-with-zero-constraints PDP shape (`decision: true,
// constraints: []`). This is *a* valid PDP response, not the only one --
// real PDP plugins instead attach a baseline `In(OWNER_TENANT_ID)`
// constraint on every allow decision, and since `RG_TYPE_RESOURCE` declares
// `OWNER_TENANT_ID` as a supported property, the tenant-scoping
// `AllowAllAuthZ` mock above works fine wired to the type routes too --
// see `list_types_with_realistic_tenant_clamp_authz_succeeds` below, which
// exercises exactly that.
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

fn make_type_enforcer() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(AllowAllNoConstraintsAuthZ);
    PolicyEnforcer::new(authz)
}

// ── Mock AuthZ: deny-all (for the type-registry gate rejection tests) ──

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
                deny_reason: Some(authz_resolver_sdk::models::DenyReason {
                    error_code: "deny_all".to_owned(),
                    details: Some("deny-all test enforcer".to_owned()),
                }),
            },
        })
    }
}

fn make_type_enforcer_deny() -> PolicyEnforcer {
    let authz: Arc<dyn AuthZResolverClient> = Arc::new(DenyAllAuthZ);
    PolicyEnforcer::new(authz)
}

/// Build a fully-wired router. `type_enforcer` lets callers swap in a
/// deny-all `PolicyEnforcer` for the type-registry routes while group/
/// membership routes keep the normal allow-all-with-tenant-scoping mock.
async fn build_test_router_with_type_enforcer(
    type_enforcer: PolicyEnforcer,
) -> (Router, Arc<TypeService<TypeRepository>>) {
    let db = test_db().await;
    let enforcer = make_enforcer();

    let type_svc = Arc::new(TypeService::new(
        db.clone(),
        type_enforcer,
        Arc::new(TypeRepository),
    ));
    let group_svc = Arc::new(GroupService::new(
        db.clone(),
        QueryProfile::default(),
        enforcer.clone(),
        Arc::new(GroupRepository),
        Arc::new(TypeRepository),
        common::make_types_registry(),
    ));
    let membership_svc = Arc::new(MembershipService::new(
        db,
        enforcer,
        Arc::new(GroupRepository),
        Arc::new(TypeRepository),
        Arc::new(MembershipRepository),
    ));

    let openapi = NoopOpenApiRegistry;
    let router = resource_group::api::rest::routes::register_routes(
        Router::new(),
        &openapi,
        type_svc.clone(),
        group_svc,
        membership_svc,
    );

    (router, type_svc)
}

async fn build_test_router() -> (Router, Arc<TypeService<TypeRepository>>) {
    build_test_router_with_type_enforcer(make_type_enforcer()).await
}

/// Router wired with a deny-all enforcer for the type-registry routes only
/// -- used by the VHP-2342 rejection tests below.
async fn build_test_router_type_denied() -> (Router, Arc<TypeService<TypeRepository>>) {
    build_test_router_with_type_enforcer(make_type_enforcer_deny()).await
}

fn json_request(
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
    tenant_id: Uuid,
) -> Request<Body> {
    let ctx = make_ctx(tenant_id);
    let mut builder = Request::builder().method(method).uri(uri);

    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }

    let body = match body {
        Some(json) => Body::from(serde_json::to_vec(&json).unwrap()),
        None => Body::empty(),
    };

    let mut req = builder.body(body).unwrap();
    req.extensions_mut().insert(ctx);
    req
}

async fn response_body(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_default()
}

// ── Type CRUD Tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_type_returns_201() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.api.{}.v1~", Uuid::now_v7().as_simple());

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert_eq!(body["code"], code);
    assert_eq!(body["can_be_root"], true);
}

#[tokio::test]
async fn create_type_duplicate_returns_409() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.dup.{}.v1~", Uuid::now_v7().as_simple());

    // Pre-create via service
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_type_invalid_code_returns_400() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": "wrong.prefix",
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn list_types_returns_200_with_page() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.list.{}.v1~", Uuid::now_v7().as_simple());

    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request("GET", "/types-registry/v1/types", None, tenant_id);
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = response_body(resp).await;
    assert_eq!(status, StatusCode::OK, "list_types failed: {body}");

    assert!(body["items"].is_array());
    assert!(!body["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn get_type_returns_200() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.get.{}.v1~", Uuid::now_v7().as_simple());

    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let encoded = code.replace('~', "%7E");
    let req = json_request(
        "GET",
        &format!("/types-registry/v1/types/{encoded}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    assert_eq!(body["code"], code);
}

#[tokio::test]
async fn get_type_not_found_returns_404() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = gts_id!("cf.core.rg.type.v1~test.rg.nonexistent.type.v1~");
    let encoded = code.replace('~', "%7E");

    let req = json_request(
        "GET",
        &format!("/types-registry/v1/types/{encoded}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_type_returns_204() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.del.{}.v1~", Uuid::now_v7().as_simple());

    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let encoded = code.replace('~', "%7E");
    let req = json_request(
        "DELETE",
        &format!("/types-registry/v1/types/{encoded}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ── Type CRUD AuthZ Tests (VHP-2342) ────────────────────────────────────
//
// Before this fix, all five `/types-registry/v1/types` routes were
// `.authenticated()`-only: any caller with a valid JWT -- from any tenant --
// could create/read/update/delete GTS type definitions. These five tests
// wire the router with a deny-all `PolicyEnforcer` for the type routes
// (`build_test_router_type_denied`) and assert the exact HTTP status the
// `DomainError::AccessDenied` -> `CanonicalError` mapping produces
// (`RgError::permission_denied()`, see `src/api/rest/error.rs`) --
// `StatusCode::FORBIDDEN`. The companion `*_returns_2xx` tests above already
// cover the allow path (the router's default enforcer is allow-all).

#[tokio::test]
async fn list_types_denied_returns_403() {
    let (router, _) = build_test_router_type_denied().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request("GET", "/types-registry/v1/types", None, tenant_id);
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::FORBIDDEN).await;
}

#[tokio::test]
async fn create_type_denied_returns_403() {
    let (router, _) = build_test_router_type_denied().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.authz.create.{}.v1~", Uuid::now_v7().as_simple());

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::FORBIDDEN).await;
}

#[tokio::test]
async fn get_type_denied_returns_403() {
    let (router, _) = build_test_router_type_denied().await;
    let tenant_id = Uuid::now_v7();
    // No type needs to exist: the AuthZ gate runs before the lookup, so a
    // deny must short-circuit before a NotFound could ever surface.
    let code = rg_type_id!("test.authz.get.{}.v1~", Uuid::now_v7().as_simple());
    let encoded = code.replace('~', "%7E");

    let req = json_request(
        "GET",
        &format!("/types-registry/v1/types/{encoded}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::FORBIDDEN).await;
}

#[tokio::test]
async fn update_type_denied_returns_403() {
    let (router, _) = build_test_router_type_denied().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.authz.update.{}.v1~", Uuid::now_v7().as_simple());
    let encoded = code.replace('~', "%7E");

    let req = json_request(
        "PUT",
        &format!("/types-registry/v1/types/{encoded}"),
        Some(serde_json::json!({
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::FORBIDDEN).await;
}

#[tokio::test]
async fn delete_type_denied_returns_403() {
    let (router, _) = build_test_router_type_denied().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.authz.delete.{}.v1~", Uuid::now_v7().as_simple());
    let encoded = code.replace('~', "%7E");

    let req = json_request(
        "DELETE",
        &format!("/types-registry/v1/types/{encoded}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::FORBIDDEN).await;
}

/// HTTP-level regression proof for VHP-2342's actual defect (not just the
/// artificial no-constraints mock the rest of this file's type routes are
/// wired with by default). Wires the type-registry routes with
/// `AllowAllAuthZ` -- the tenant-scoping mock that attaches a baseline
/// `In(OWNER_TENANT_ID)` constraint on every allow decision, the same shape
/// `static-authz-plugin`/`tr-authz-plugin` actually return -- and asserts a
/// gated route still succeeds end to end at the wire level. Before
/// `RG_TYPE_RESOURCE` declared `OWNER_TENANT_ID` as a supported property,
/// this exact request failed with `DomainError::InternalError`
/// (`AllConstraintsFailed`), which the `DomainError` -> `CanonicalError`
/// mapping turns into `StatusCode::INTERNAL_SERVER_ERROR` -- a 500 for an
/// allowed caller, not the 200 asserted here.
#[tokio::test]
async fn list_types_with_realistic_tenant_clamp_authz_succeeds() {
    let (router, _) = build_test_router_with_type_enforcer(make_enforcer()).await;
    let tenant_id = Uuid::now_v7();

    let req = json_request("GET", "/types-registry/v1/types", None, tenant_id);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    assert_no_surrogate_ids(&body);
}

// ── Group CRUD Tests ────────────────────────────────────────────────────

#[tokio::test]
async fn create_group_returns_201() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let type_code = rg_type_id!("test.grp.{}.v1~", Uuid::now_v7().as_simple());

    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: type_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": type_code,
            "name": "Test Group"
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert_eq!(body["name"], "Test Group");
    assert!(body["id"].is_string());
    assert_eq!(body["hierarchy"]["tenant_id"], tenant_id.to_string());
}

/// VHP-2345: creating a group with an `id` that collides with an existing
/// group's primary key must come back as a typed 409 `already_exists`, not
/// a raw 500. VHP-2343's owner decision keeps client-supplied `id` accepted
/// as-is on create — capture is not blocked by this fix.
#[tokio::test]
async fn create_group_duplicate_id_returns_409() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let type_code = rg_type_id!("test.grpdup.{}.v1~", Uuid::now_v7().as_simple());

    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: type_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let dup_id = Uuid::now_v7();
    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "id": dup_id,
            "type": type_code,
            "name": "First"
        })),
        tenant_id,
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = response_body(resp).await;
    assert_eq!(body["id"], dup_id.to_string());
    assert_no_surrogate_ids(&body);

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "id": dup_id,
            "type": type_code,
            "name": "Second"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let body = assert_problem_shape(resp, StatusCode::CONFLICT).await;
    assert_eq!(body["context"]["resource_name"], dup_id.to_string());
}

#[tokio::test]
async fn list_groups_returns_200() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request("GET", "/resource-group/v1/groups", None, tenant_id);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    assert!(body["items"].is_array());
}

#[tokio::test]
async fn get_group_not_found_returns_404() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let fake_id = Uuid::now_v7();

    let req = json_request(
        "GET",
        &format!("/resource-group/v1/groups/{fake_id}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Error format tests (RFC 9457 Problem Details) ───────────────────────

#[tokio::test]
async fn error_response_has_problem_fields() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    // Trigger a validation error
    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": "invalid",
            "can_be_root": true
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = response_body(resp).await;
    // RFC 9457 requires these fields
    assert!(
        body["title"].is_string(),
        "Problem must have 'title': {body}"
    );
    assert!(
        body["status"].is_number(),
        "Problem must have 'status': {body}"
    );
    assert!(
        body["detail"].is_string(),
        "Problem must have 'detail': {body}"
    );
}

// ── Helper: assert no surrogate IDs in JSON ──────────────────────────────

fn assert_no_surrogate_ids(json: &serde_json::Value) {
    let text = json.to_string();
    assert!(
        !text.contains("\"gts_type_id\""),
        "Response should not contain gts_type_id: {text}"
    );
    assert!(
        !text.contains("\"type_id\""),
        "Response should not contain type_id: {text}"
    );
    assert!(
        !text.contains("\"parent_type_id\""),
        "Response should not contain parent_type_id: {text}"
    );
    assert!(
        !text.contains("\"schema_id\""),
        "Response should not contain schema_id: {text}"
    );
}

// ── Helper: assert RFC 9457 Problem Details shape ───────────────────────
//
// Per `docs/toolkit_unified_system/12_unit_testing.md` ("Error Response
// Shape (REST tests)"): every REST test that exercises an error response
// MUST check the status code, that Content-Type contains
// `application/problem+json`, that the body carries `status`/`title`/
// `detail`, and that no `stack`/`trace`/`backtrace` leaks into the wire
// body. Consumes the response (mirrors `response_body`) and hands back the
// parsed JSON so callers can layer on endpoint-specific assertions (e.g.
// `context.violations`).
async fn assert_problem_shape(
    resp: axum::http::Response<Body>,
    expected_status: StatusCode,
) -> serde_json::Value {
    let status = resp.status();
    let ct = resp
        .headers()
        .get("content-type")
        .expect("Content-Type header must be present")
        .to_str()
        .unwrap()
        .to_owned();
    let body = response_body(resp).await;
    assert_eq!(
        status, expected_status,
        "unexpected status, got {status}: {body}"
    );
    assert!(
        ct.contains("application/problem+json"),
        "expected application/problem+json for {expected_status}, got: {ct}"
    );
    assert_eq!(
        body["status"],
        expected_status.as_u16(),
        "Problem 'status' must match the HTTP status: {body}"
    );
    assert!(
        body["title"].is_string(),
        "Problem must have 'title': {body}"
    );
    assert!(
        body["detail"].is_string(),
        "Problem must have 'detail': {body}"
    );
    assert!(
        body.get("stack").is_none(),
        "no stack trace must leak into the response: {body}"
    );
    assert!(
        body.get("trace").is_none(),
        "no trace must leak into the response: {body}"
    );
    assert!(
        body.get("backtrace").is_none(),
        "no backtrace must leak into the response: {body}"
    );
    body
}

// =========================================================================
// Section A: REST API endpoint tests (TC-REST-01..08)
// =========================================================================

/// TC-REST-01: PUT type returns 200 with updated body.
#[tokio::test]
async fn rest_put_type_returns_200() {
    let (router, type_svc) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.put.{}.v1~", Uuid::now_v7().as_simple());

    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let encoded = code.replace('~', "%7E");
    let req = json_request(
        "PUT",
        &format!("/types-registry/v1/types/{encoded}"),
        Some(serde_json::json!({
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = response_body(resp).await;
    assert_eq!(status, StatusCode::OK, "PUT type failed: {body}");
    assert_eq!(body["code"], code);
    assert_eq!(body["can_be_root"], true);
    assert_no_surrogate_ids(&body);
}

/// TC-REST-02: PUT type not found returns 404.
#[tokio::test]
async fn rest_put_type_not_found_returns_404() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = gts_id!("cf.core.rg.type.v1~test.rg.nonexistent.put.v1~");
    let encoded = code.replace('~', "%7E");

    let req = json_request(
        "PUT",
        &format!("/types-registry/v1/types/{encoded}"),
        Some(serde_json::json!({
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// TC-REST-03: POST membership returns 201.
#[tokio::test]
async fn rest_post_membership_returns_201() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mt_code = rg_type_id!("test.mt2._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt_code = rg_type_id!("test.gt2.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt_code.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt_code,
                name: "G1".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let mt_encoded = mt_code.replace('~', "%7E");
    let req = json_request(
        "POST",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-001",
            group.id, mt_encoded
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = response_body(resp).await;
    assert_eq!(body["resource_type"], mt_code);
    assert!(
        body.get("tenant_id").is_none(),
        "No tenant_id in membership response"
    );
    assert_no_surrogate_ids(&body);
}

/// VHP-2345 regression: a second `POST` of the same membership composite
/// key must still come back as a typed 409 conflict, now that
/// `MembershipRepository::insert` classifies the duplicate via
/// `toolkit_db::secure::is_unique_violation` instead of a substring match
/// on the driver's error text.
#[tokio::test]
async fn rest_post_membership_duplicate_returns_409() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mt_code = rg_type_id!("test.mtdup._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt_code = rg_type_id!("test.gtdup.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt_code.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt_code,
                name: "G1".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let mt_encoded = mt_code.replace('~', "%7E");
    let path = format!(
        "/resource-group/v1/memberships/{}/{}/res-dup",
        group.id, mt_encoded
    );

    let first = json_request("POST", &path, None, tenant_id);
    let resp = router.clone().oneshot(first).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = response_body(resp).await;
    assert_no_surrogate_ids(&body);

    let second = json_request("POST", &path, None, tenant_id);
    let resp = router.oneshot(second).await.unwrap();
    assert_problem_shape(resp, StatusCode::CONFLICT).await;
}

/// Helper: create a self-referencing root type (create, then update to allow self as parent).
async fn create_self_ref_type(type_svc: &TypeService<TypeRepository>, suffix: &str) -> String {
    let code = rg_type_id!("test.{}.{}.v1~", suffix, Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();
    type_svc
        .update_type_unscoped(
            &code,
            resource_group_sdk::UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![code.clone()],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .unwrap();
    code
}

/// Helper: build a fully-wired router with shared services for multi-request tests.
async fn build_shared_router() -> (
    Router,
    Arc<TypeService<TypeRepository>>,
    Arc<GroupService<GroupRepository, TypeRepository>>,
    Arc<MembershipService<GroupRepository, TypeRepository, MembershipRepository>>,
) {
    let db = test_db().await;
    let enforcer = make_enforcer();
    let type_svc = Arc::new(TypeService::new(
        db.clone(),
        make_type_enforcer(),
        Arc::new(TypeRepository),
    ));
    let group_svc = Arc::new(GroupService::new(
        db.clone(),
        QueryProfile::default(),
        enforcer.clone(),
        Arc::new(GroupRepository),
        Arc::new(TypeRepository),
        common::make_types_registry(),
    ));
    let membership_svc = Arc::new(MembershipService::new(
        db,
        enforcer,
        Arc::new(GroupRepository),
        Arc::new(TypeRepository),
        Arc::new(MembershipRepository),
    ));
    let router = resource_group::api::rest::routes::register_routes(
        Router::new(),
        &NoopOpenApiRegistry,
        type_svc.clone(),
        group_svc.clone(),
        membership_svc.clone(),
    );
    (router, type_svc, group_svc, membership_svc)
}

/// TC-REST-04: DELETE membership returns 204.
#[tokio::test]
async fn rest_delete_membership_returns_204() {
    let (router, type_svc, group_svc, membership_svc) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mt = rg_type_id!("test.mtr._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt = rg_type_id!("test.gtr.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt,
                name: "GDel".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    membership_svc
        .add_membership(&ctx, group.id, &mt, "res-del")
        .await
        .unwrap();

    let mt_encoded = mt.replace('~', "%7E");
    let req = json_request(
        "DELETE",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-del",
            group.id, mt_encoded
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// TC-REST-05: GET memberships returns 200 with list.
#[tokio::test]
async fn rest_get_memberships_returns_200() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request("GET", "/resource-group/v1/memberships", None, tenant_id);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    assert!(body["items"].is_array());
}

// =========================================================================
// VHP-2341: membership operations must respect the caller's tenant scope
// =========================================================================

/// VHP-2341: POST membership into a cross-tenant group returns 404 (looks
/// not-found, not a distinguishable "forbidden").
#[tokio::test]
async fn rest_post_membership_cross_tenant_returns_404() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let ctx_a = make_ctx(tenant_a);

    let mt_code = rg_type_id!("test.xmt._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt_code = rg_type_id!("test.xgt._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt_code.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    // Tenant A creates the group.
    let group = group_svc
        .create_group(
            &ctx_a,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt_code,
                name: "GA".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_a,
        )
        .await
        .unwrap();

    // Tenant B tries to add a member into tenant A's group.
    let mt_encoded = mt_code.replace('~', "%7E");
    let req = json_request(
        "POST",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-xtenant",
            group.id, mt_encoded
        ),
        None,
        tenant_b,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::NOT_FOUND).await;
}

/// VHP-2341: DELETE membership from a cross-tenant group returns 404, and
/// the membership survives.
#[tokio::test]
async fn rest_delete_membership_cross_tenant_returns_404() {
    let (router, type_svc, group_svc, membership_svc) = build_shared_router().await;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let ctx_a = make_ctx(tenant_a);

    let mt_code = rg_type_id!("test.xmtr._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt_code = rg_type_id!("test.xgtr._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt_code.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx_a,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt_code,
                name: "GAR".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_a,
        )
        .await
        .unwrap();

    membership_svc
        .add_membership(&ctx_a, group.id, &mt_code, "res-xtenant-del")
        .await
        .unwrap();

    // Tenant B tries to delete a member from tenant A's group.
    let mt_encoded = mt_code.replace('~', "%7E");
    let req = json_request(
        "DELETE",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-xtenant-del",
            group.id, mt_encoded
        ),
        None,
        tenant_b,
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::NOT_FOUND).await;

    // Tenant A must still see the membership -- the rejected cross-tenant
    // delete must not have removed it.
    let list_req = json_request("GET", "/resource-group/v1/memberships", None, tenant_a);
    let list_resp = router.oneshot(list_req).await.unwrap();
    let body = response_body(list_resp).await;
    let items = body["items"].as_array().expect("items array");
    assert!(
        items.iter().any(|m| m["resource_id"] == "res-xtenant-del"),
        "membership must survive a rejected cross-tenant delete, got: {items:?}"
    );
    assert_no_surrogate_ids(&body);
}

/// VHP-2341: GET memberships is tenant-scoped -- tenant A must not see
/// tenant B's membership rows in the list response.
#[tokio::test]
async fn rest_get_memberships_is_tenant_scoped() {
    let (router, type_svc, group_svc, membership_svc) = build_shared_router().await;
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let ctx_a = make_ctx(tenant_a);
    let ctx_b = make_ctx(tenant_b);

    let mt_code = rg_type_id!("test.xlst._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt_code = rg_type_id!("test.xglst._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt_code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt_code.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group_a = group_svc
        .create_group(
            &ctx_a,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt_code.clone(),
                name: "GAList".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_a,
        )
        .await
        .unwrap();
    let group_b = group_svc
        .create_group(
            &ctx_b,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt_code,
                name: "GBList".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_b,
        )
        .await
        .unwrap();

    membership_svc
        .add_membership(&ctx_a, group_a.id, &mt_code, "res-list-a")
        .await
        .unwrap();
    membership_svc
        .add_membership(&ctx_b, group_b.id, &mt_code, "res-list-b")
        .await
        .unwrap();

    let req = json_request("GET", "/resource-group/v1/memberships", None, tenant_a);
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = response_body(resp).await;
    let items = body["items"].as_array().expect("items array");
    assert!(
        items.iter().any(|m| m["resource_id"] == "res-list-a"),
        "tenant A must see its own membership, got: {items:?}"
    );
    assert!(
        !items.iter().any(|m| m["resource_id"] == "res-list-b"),
        "tenant A must NOT see tenant B's membership, got: {items:?}"
    );
    assert_no_surrogate_ids(&body);
}

/// TC-REST-06: POST group with parent_id returns 201 with hierarchy.
#[tokio::test]
async fn rest_post_group_with_parent_returns_201() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let root_type = rg_type_id!("test.rtp.{}.v1~", Uuid::now_v7().as_simple());
    // Create type first without self-reference, then update to allow self as parent
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: root_type.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();
    type_svc
        .update_type_unscoped(
            &root_type,
            resource_group_sdk::UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![root_type.clone()],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .unwrap();

    let parent = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: root_type.clone(),
                name: "Parent".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": root_type,
            "name": "Child",
            "parent_id": parent.id.to_string()
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert_eq!(body["hierarchy"]["parent_id"], parent.id.to_string());
    assert_no_surrogate_ids(&body);
}

/// TC-REST-07: DELETE group with force=true returns 204.
#[tokio::test]
async fn rest_delete_group_force_returns_204() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let rt = create_self_ref_type(&type_svc, "fdel").await;

    let parent = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt.clone(),
                name: "FParent".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    // Create child so normal delete would fail
    group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt,
                name: "FChild".to_owned(),
                parent_id: Some(parent.id),
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let req = json_request(
        "DELETE",
        &format!("/resource-group/v1/groups/{}?force=true", parent.id),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// TC-REST-08: GET group hierarchy returns 200 with depth fields.
#[tokio::test]
async fn rest_get_group_hierarchy_returns_200() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let rt = create_self_ref_type(&type_svc, "hier").await;

    let root = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt.clone(),
                name: "HRoot".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let child = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt,
                name: "HChild".to_owned(),
                parent_id: Some(root.id),
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let req = json_request(
        "GET",
        &format!("/resource-group/v1/groups/{}/descendants", child.id),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    assert!(body["items"].is_array());
    let items = body["items"].as_array().unwrap();
    assert!(!items.is_empty());
    // Each item should have hierarchy.depth
    for item in items {
        assert!(
            item["hierarchy"]["depth"].is_number(),
            "hierarchy item should have depth: {item}"
        );
        assert!(
            item["type"].is_string(),
            "hierarchy item type should be string: {item}"
        );
        assert_no_surrogate_ids(item);
    }
}

// =========================================================================
// VHP-1977: PUT re-parent cycle detection (REST-level regression coverage)
// =========================================================================
//
// `move_group_internal_impl` (src/domain/group_service.rs) already detects
// cycles via `is_descendant` and `update_group_inner` delegates to it when
// `parent_id` changes on a PUT; the resulting `DomainError::CycleDetected`
// is mapped to `RgError::failed_precondition()` with the `hierarchy`
// precondition subject (src/api/rest/error.rs). Service-level coverage
// already exists in `group_service_test.rs` (TC-GRP-06/07, via
// `move_group`) and error-mapping coverage exists in `domain_unit_test.rs`
// (`domain_to_problem_cycle_detected_is_400`), but neither one drives the
// actual `PUT /resource-group/v1/groups/{id}` HTTP path. These two tests
// close that gap.

/// VHP-1977: PUT re-parent under own descendant returns 400 with a
/// `hierarchy` precondition violation.
#[tokio::test]
async fn rest_update_group_reparent_under_descendant_returns_400_cycle() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let rt = create_self_ref_type(&type_svc, "cyc1").await;

    let root = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt.clone(),
                name: "CycRoot".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .expect("create root group");

    let child = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt,
                name: "CycChild".to_owned(),
                parent_id: Some(root.id),
                metadata: None,
            },
            tenant_id,
        )
        .await
        .expect("create child group");

    // PUT root with parent_id = its own child -- would create a cycle.
    let req = json_request(
        "PUT",
        &format!("/resource-group/v1/groups/{}", root.id),
        Some(serde_json::json!({
            "name": "CycRoot",
            "parent_id": child.id,
            "metadata": null
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let body = assert_problem_shape(resp, StatusCode::BAD_REQUEST).await;

    let violations = body["context"]["violations"]
        .as_array()
        .expect("context.violations must be present");
    assert!(
        !violations.is_empty(),
        "expected at least one precondition violation: {body}"
    );
    assert_eq!(violations[0]["subject"], "hierarchy");
    assert_eq!(violations[0]["type"], "STATE");
    assert!(
        violations[0]["description"]
            .as_str()
            .is_some_and(|d| !d.is_empty()),
        "expected non-empty violation description: {body}"
    );
}

/// VHP-1977: PUT self-parent returns 400 with a `hierarchy` precondition
/// violation.
#[tokio::test]
async fn rest_update_group_self_parent_returns_400_cycle() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let rt = create_self_ref_type(&type_svc, "cyc2").await;

    let root = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt,
                name: "SelfRoot".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .expect("create root group");

    // PUT root with parent_id = itself.
    let req = json_request(
        "PUT",
        &format!("/resource-group/v1/groups/{}", root.id),
        Some(serde_json::json!({
            "name": "SelfRoot",
            "parent_id": root.id,
            "metadata": null
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let body = assert_problem_shape(resp, StatusCode::BAD_REQUEST).await;

    let violations = body["context"]["violations"]
        .as_array()
        .expect("context.violations must be present");
    assert!(
        !violations.is_empty(),
        "expected at least one precondition violation: {body}"
    );
    assert_eq!(violations[0]["subject"], "hierarchy");
    assert_eq!(violations[0]["type"], "STATE");
    assert!(
        violations[0]["description"]
            .as_str()
            .is_some_and(|d| !d.is_empty()),
        "expected non-empty violation description: {body}"
    );
}

// =========================================================================
// Section B: REST Metadata Tests (TC-META-19..22)
// =========================================================================

/// TC-META-19: POST type with metadataSchema (camelCase) returns 201 with schema.
#[tokio::test]
async fn rest_create_type_with_metadata_schema() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.ms.{}.v1~", Uuid::now_v7().as_simple());

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": [],
            "metadata_schema": {"type": "object", "properties": {"self_managed": {"type": "boolean"}}}
        })),
        tenant_id,
    );

    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = response_body(resp).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "Create type with metadata_schema failed: {body}"
    );

    assert!(
        body.get("metadataSchema").is_some() || body.get("metadata_schema").is_some(),
        "Response should contain metadata_schema: {body}"
    );
    assert_no_surrogate_ids(&body);
}

/// TC-META-20: POST group with metadata returns 201 with metadata.
#[tokio::test]
async fn rest_create_group_with_metadata() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let code = rg_type_id!("test.gm.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": code,
            "name": "MetaGroup",
            "metadata": {"self_managed": true}
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert_eq!(body["metadata"]["self_managed"], true);
    assert_no_surrogate_ids(&body);
}

/// TC-META-21: Response omits metadata when null.
#[tokio::test]
async fn rest_group_response_omits_null_metadata() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let code = rg_type_id!("test.nm.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": code,
            "name": "NoMeta"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert!(
        body.get("metadata").is_none(),
        "Response should omit metadata when null: {body}"
    );
}

/// TC-META-22: Response omits metadataSchema when null.
#[tokio::test]
async fn rest_type_response_omits_null_metadata_schema() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.nms.{}.v1~", Uuid::now_v7().as_simple());

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert!(
        body.get("metadataSchema").is_none() && body.get("metadata_schema").is_none(),
        "Response should omit metadataSchema when null: {body}"
    );
}

// =========================================================================
// Section C: Invalid/Non-GTS Input (TC-NOGTS + TC-DESER)
// =========================================================================

/// TC-NOGTS-01: Create type with valid GTS but not RG prefix returns 400.
#[tokio::test]
async fn input_create_type_non_rg_prefix_returns_400() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": gts_id!("cf.other.prefix.type.v1~test.rg.other.type.v1~"),
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-NOGTS-02: Create type with empty code returns 400.
#[tokio::test]
async fn input_create_type_empty_code_returns_400() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": "",
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-NOGTS-03: Create type with SQL injection code returns 400.
#[tokio::test]
async fn input_create_type_sql_injection_returns_400() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": "'; DROP TABLE gts_type; --",
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-NOGTS-04: Create group with non-RG type_path returns 400.
#[tokio::test]
async fn input_create_group_non_rg_type_returns_400() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": gts_id!("cf.other.prefix.type.v1~test.rg.other.type.v1~"),
            "name": "BadGroup"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    // Should be 400 (validation) or 404 (type not found)
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Expected 400 or 404, got {status}"
    );
}

/// TC-NOGTS-05: Create group with empty type_path returns 400.
#[tokio::test]
async fn input_create_group_empty_type_returns_400() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": "",
            "name": "EmptyType"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Expected 400 or 404, got {status}"
    );
}

/// TC-NOGTS-06: Membership with non-GTS resource_type returns 400 or 404.
#[tokio::test]
async fn input_membership_non_gts_resource_type() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let rt = rg_type_id!("test.ngts.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: rt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt,
                name: "NGGroup".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let req = json_request(
        "POST",
        &format!(
            "/resource-group/v1/memberships/{}/not-a-gts-path/res-001",
            group.id
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Expected 400 or 404 for non-GTS resource_type, got {status}"
    );
}

/// TC-NOGTS-07: Membership with empty resource_type returns 404 or 400.
#[tokio::test]
async fn input_membership_empty_resource_type() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let fake_id = Uuid::now_v7();

    // Empty resource_type in the URL path -- axum routing may not match
    let req = json_request(
        "POST",
        &format!("/resource-group/v1/memberships/{fake_id}//res-001"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    // Empty path segment may cause 404 (no route match) or 400
    assert!(
        status == StatusCode::BAD_REQUEST
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::METHOD_NOT_ALLOWED,
        "Expected 400/404/405 for empty resource_type, got {status}"
    );
}

/// TC-DESER-01: Create type with `code: 123` (number not string) returns 400/422.
#[tokio::test]
async fn input_deser_type_code_number_returns_error() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": 123,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for number code, got {status}"
    );
}

/// TC-DESER-02: Create type with `can_be_root: "yes"` (string not bool) returns 400/422.
#[tokio::test]
async fn input_deser_type_can_be_root_string_returns_error() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": gts_id!("cf.core.rg.type.v1~test.rg.deser.type.v1~"),
            "can_be_root": "yes",
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for string can_be_root, got {status}"
    );
}

/// TC-DESER-03: Create type missing `can_be_root` returns 400/422.
#[tokio::test]
async fn input_deser_type_missing_can_be_root_returns_error() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": gts_id!("cf.core.rg.type.v1~test.rg.missing.type.v1~")
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for missing can_be_root, got {status}"
    );
}

/// TC-DESER-04: Create group missing `type` field returns 400/422.
#[tokio::test]
async fn input_deser_group_missing_type_returns_error() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "name": "NoType"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for missing type, got {status}"
    );
}

/// TC-DESER-05: Create group with `parent_id: "not-a-uuid"` returns 400/422.
#[tokio::test]
async fn input_deser_group_invalid_parent_uuid_returns_error() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": gts_id!("cf.core.rg.type.v1~test.rg.simple.type.v1~"),
            "name": "BadParent",
            "parent_id": "not-a-uuid"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for invalid parent_id, got {status}"
    );
}

/// TC-DESER-06: Malformed JSON body returns 400.
#[tokio::test]
async fn input_deser_malformed_json_returns_400() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mut req = Request::builder()
        .method("POST")
        .uri("/types-registry/v1/types")
        .header("content-type", "application/json")
        .body(Body::from("{not valid json"))
        .unwrap();
    req.extensions_mut().insert(ctx);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-DESER-07: Empty body when expected returns 400/422.
#[tokio::test]
async fn input_deser_empty_body_returns_error() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mut req = Request::builder()
        .method("POST")
        .uri("/types-registry/v1/types")
        .header("content-type", "application/json")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ctx);

    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 400 or 422 for empty body, got {status}"
    );
}

/// TC-DESER-08: Create group with empty name returns 400.
#[tokio::test]
async fn input_deser_group_empty_name_returns_400() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let code = rg_type_id!("test.en.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": code,
            "name": ""
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-DESER-09: Group path with non-UUID group_id returns 400.
#[tokio::test]
async fn input_deser_group_path_non_uuid_returns_400() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "GET",
        "/resource-group/v1/groups/not-a-uuid",
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-DESER-10: Membership path with non-UUID group_id returns 400.
#[tokio::test]
async fn input_deser_membership_path_non_uuid_returns_400() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "POST",
        &format!(
            "/resource-group/v1/memberships/not-a-uuid/{}/res-001",
            gts_id!("cf.core.rg.type.v1~test.rg.simple.type.v1~")
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// TC-DESER-11: Extra unknown fields in body are tolerated (verify behavior).
#[tokio::test]
async fn input_deser_extra_fields_behavior() {
    let (router, _) = build_test_router().await;
    let tenant_id = Uuid::now_v7();
    let code = rg_type_id!("test.extra.{}.v1~", Uuid::now_v7().as_simple());

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": [],
            "unknown_field": "should be ignored"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    // Most Rust frameworks ignore extra fields by default (deny_unknown_fields not set)
    // or reject them. Either is valid.
    assert!(
        status == StatusCode::CREATED
            || status == StatusCode::BAD_REQUEST
            || status == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 201 (ignored) or 400/422 (denied), got {status}"
    );
}

// =========================================================================
// Section D: GTS URL Tilde + SMALLINT (TC-GTS-16..20, TC-ADR-17..20)
// =========================================================================

/// TC-GTS-16: Membership POST with %7E tilde encoding succeeds.
#[tokio::test]
async fn gts_membership_post_tilde_encoded() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mt = rg_type_id!("test.tmt._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt = rg_type_id!("test.tgt.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt,
                name: "TildeGroup".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let mt_encoded = mt.replace('~', "%7E");
    let req = json_request(
        "POST",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-tilde",
            group.id, mt_encoded
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// TC-GTS-17: Membership DELETE with %7E tilde encoding succeeds.
#[tokio::test]
async fn gts_membership_delete_tilde_encoded() {
    let (router, type_svc, group_svc, membership_svc) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mt = rg_type_id!("test.tmd._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt = rg_type_id!("test.tgd.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt,
                name: "TildeDelGrp".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    membership_svc
        .add_membership(&ctx, group.id, &mt, "res-tdel")
        .await
        .unwrap();

    let mt_encoded = mt.replace('~', "%7E");
    let req = json_request(
        "DELETE",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-tdel",
            group.id, mt_encoded
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

/// TC-GTS-18: PUT /types/{code} with tilde encoding returns 200.
#[tokio::test]
async fn gts_put_type_tilde_encoded() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let code = rg_type_id!("test.tput.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let encoded = code.replace('~', "%7E");
    let req = json_request(
        "PUT",
        &format!("/types-registry/v1/types/{encoded}"),
        Some(serde_json::json!({
            "can_be_root": true,
            "allowed_parent_types": [],
            "allowed_membership_types": []
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// TC-ADR-17: Type response has no SMALLINT IDs -- all string fields.
#[tokio::test]
async fn smallint_type_response_has_no_surrogate_ids() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let code = rg_type_id!("test.sid.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let encoded = code.replace('~', "%7E");
    let req = json_request(
        "GET",
        &format!("/types-registry/v1/types/{encoded}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    assert_no_surrogate_ids(&body);
    assert!(body["code"].is_string());
    assert!(body["can_be_root"].is_boolean());
}

/// TC-ADR-18: Group response has no SMALLINT IDs -- `type` is string.
#[tokio::test]
async fn smallint_group_response_has_no_surrogate_ids() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let code = rg_type_id!("test.gsid.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": code,
            "name": "SIDGroup"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert_no_surrogate_ids(&body);
    assert!(body["type"].is_string());
    assert!(body["id"].is_string());
}

/// TC-ADR-19: Membership response has no SMALLINT IDs -- `resource_type` is string.
#[tokio::test]
async fn smallint_membership_response_has_no_surrogate_ids() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let mt = rg_type_id!("test.msid._.i{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: mt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let gt = rg_type_id!("test.gsidm.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: gt.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![mt.clone()],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: gt,
                name: "MSIDGrp".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let mt_encoded = mt.replace('~', "%7E");
    let req = json_request(
        "POST",
        &format!(
            "/resource-group/v1/memberships/{}/{}/res-sid",
            group.id, mt_encoded
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body = response_body(resp).await;
    assert_no_surrogate_ids(&body);
    assert!(body["resource_type"].is_string());
    assert!(body.get("tenant_id").is_none());
}

/// TC-ADR-20: Hierarchy response has no SMALLINT IDs -- each `type` is string.
#[tokio::test]
async fn smallint_hierarchy_response_has_no_surrogate_ids() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let rt = create_self_ref_type(&type_svc, "hsid").await;

    let root = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt.clone(),
                name: "HSIDRoot".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let child = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: rt,
                name: "HSIDChild".to_owned(),
                parent_id: Some(root.id),
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let req = json_request(
        "GET",
        &format!("/resource-group/v1/groups/{}/descendants", child.id),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = response_body(resp).await;
    for item in body["items"].as_array().unwrap() {
        assert!(item["type"].is_string());
        assert_no_surrogate_ids(item);
    }
}

// =========================================================================
// Section G: Error response HTTP mapping (TC-REST-10)
// =========================================================================

/// TC-REST-10: Error responses have correct HTTP status and Content-Type.
#[tokio::test]
async fn rest_error_responses_have_problem_content_type_and_status() {
    let (router, type_svc, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    // --- 404 Not Found: GET nonexistent group ---
    let fake_id = Uuid::now_v7();
    let req = json_request(
        "GET",
        &format!("/resource-group/v1/groups/{fake_id}"),
        None,
        tenant_id,
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "expected 404");
    let ct = resp
        .headers()
        .get("content-type")
        .expect("Content-Type header must be present");
    assert!(
        ct.to_str().unwrap().contains("application/problem+json"),
        "expected application/problem+json, got: {ct:?}"
    );
    let body = response_body(resp).await;
    assert_eq!(body["status"], 404);
    assert!(body["title"].is_string());
    assert!(body["detail"].is_string());
    assert!(body.get("stack").is_none(), "no stack trace leaked");
    assert!(body.get("trace").is_none(), "no trace leaked");
    assert!(body.get("backtrace").is_none(), "no backtrace leaked");

    // --- 409 Conflict: duplicate type ---
    let code = rg_type_id!("test.errdup.{}.v1~", Uuid::now_v7().as_simple());
    type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": code,
            "can_be_root": true
        })),
        tenant_id,
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT, "expected 409");
    let ct = resp
        .headers()
        .get("content-type")
        .expect("Content-Type header must be present");
    assert!(
        ct.to_str().unwrap().contains("application/problem+json"),
        "expected application/problem+json for 409, got: {ct:?}"
    );
    let body = response_body(resp).await;
    assert_eq!(body["status"], 409);

    // --- 400 Bad Request: invalid type code ---
    let req = json_request(
        "POST",
        "/types-registry/v1/types",
        Some(serde_json::json!({
            "code": "invalid",
            "can_be_root": true
        })),
        tenant_id,
    );
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "expected 400");
    let ct = resp
        .headers()
        .get("content-type")
        .expect("Content-Type header must be present");
    assert!(
        ct.to_str().unwrap().contains("application/problem+json"),
        "expected application/problem+json for 400, got: {ct:?}"
    );
    let body = response_body(resp).await;
    assert_eq!(body["status"], 400);

    // --- 404: TypeNotFound when creating group with nonexistent type ---
    let req = json_request(
        "POST",
        "/resource-group/v1/groups",
        Some(serde_json::json!({
            "type": gts_id!("cf.core.rg.type.v1~test.rg.nonexistent.type.v1~"),
            "name": "Ghost"
        })),
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "expected 404 for TypeNotFound"
    );
    let ct = resp
        .headers()
        .get("content-type")
        .expect("Content-Type header must be present");
    assert!(
        ct.to_str().unwrap().contains("application/problem+json"),
        "expected application/problem+json for TypeNotFound, got: {ct:?}"
    );
    let body = response_body(resp).await;
    assert_eq!(body["status"], 404);
}

// =========================================================================
// Section H: Route registration smoke test (RG7)
// =========================================================================

/// RG7: All endpoints are registered and respond with non-405.
/// Uses HEAD/POST/DELETE with minimal bodies to exercise route matching
/// without needing valid data setup.
#[tokio::test]
async fn rest_route_smoke_all_endpoints_registered() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let fake_id = Uuid::now_v7();
    let fake_code = rg_type_id!("smoke.v1%7E");

    // (method, path, has_body?, description)
    let endpoints: Vec<(&str, String, bool, &str)> = vec![
        // Types: 5 endpoints
        (
            "GET",
            "/types-registry/v1/types".to_owned(),
            false,
            "list types",
        ),
        (
            "POST",
            "/types-registry/v1/types".to_owned(),
            true,
            "create type",
        ),
        (
            "GET",
            format!("/types-registry/v1/types/{fake_code}"),
            false,
            "get type",
        ),
        (
            "PUT",
            format!("/types-registry/v1/types/{fake_code}"),
            true,
            "update type",
        ),
        (
            "DELETE",
            format!("/types-registry/v1/types/{fake_code}"),
            false,
            "delete type",
        ),
        // Groups: 7 endpoints
        (
            "GET",
            "/resource-group/v1/groups".to_owned(),
            false,
            "list groups",
        ),
        (
            "POST",
            "/resource-group/v1/groups".to_owned(),
            true,
            "create group",
        ),
        (
            "GET",
            format!("/resource-group/v1/groups/{fake_id}"),
            false,
            "get group",
        ),
        (
            "PUT",
            format!("/resource-group/v1/groups/{fake_id}"),
            true,
            "update group",
        ),
        (
            "DELETE",
            format!("/resource-group/v1/groups/{fake_id}"),
            false,
            "delete group",
        ),
        (
            "GET",
            format!("/resource-group/v1/groups/{fake_id}/descendants"),
            false,
            "hierarchy",
        ),
        (
            "GET",
            format!("/resource-group/v1/groups/{fake_id}/ancestors"),
            false,
            "ancestors",
        ),
        // Memberships: 3 endpoints
        (
            "GET",
            "/resource-group/v1/memberships".to_owned(),
            false,
            "list memberships",
        ),
        (
            "POST",
            format!("/resource-group/v1/memberships/{fake_id}/{fake_code}/res-1"),
            false,
            "add membership",
        ),
        (
            "DELETE",
            format!("/resource-group/v1/memberships/{fake_id}/{fake_code}/res-1"),
            false,
            "remove membership",
        ),
    ];

    for (method, path, has_body, desc) in &endpoints {
        let body = if *has_body {
            Some(serde_json::json!({}))
        } else {
            None
        };
        let req = json_request(method, path, body, tenant_id);
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} ({desc}) returned 405 -- route not registered"
        );
    }
}

// =========================================================================
// VHP-1954: membership `$filter` client errors must be 400, not 500
// =========================================================================
//
// `list_memberships` (`membership_repo.rs`) used to fold every failure out
// of `paginate_odata` -- including caller-caused `$filter` rejections --
// into `DomainError::database(..)`, a 500. The OData grammar only parses a
// *bare* hex8-4-4-4-12 UUID literal (no surrounding quotes) as
// `Value::Uuid`; the same literal wrapped in single quotes parses as
// `Value::String`, which `convert_expr_to_filter_node::<MembershipFilterField>`
// rejects with `FilterError::TypeMismatch` because `group_id`'s `FieldKind`
// is `Uuid` -- exactly the shape the ticket's reporter hit (they quoted the
// UUID; the e2e smoke test S10 does not, which is why it stayed green).

/// VHP-1954: `$filter=group_id eq '<uuid>'` (quoted) must return 400, not
/// 500 -- a caller mistake, not a backend fault.
#[tokio::test]
async fn rest_get_memberships_quoted_uuid_filter_returns_400_not_500() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let some_uuid = Uuid::now_v7();

    let req = json_request(
        "GET",
        &format!(
            "/resource-group/v1/memberships\
             ?%24filter=group_id%20eq%20%27{some_uuid}%27"
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::BAD_REQUEST).await;
}

/// VHP-1954 regression guard: the wire-correct *bare* UUID
/// `$filter=group_id eq <uuid>` (no quotes) must keep returning 200 --
/// pinning that the 400 fix above doesn't also start rejecting the shape
/// e2e smoke test S10 (and every well-formed client) actually sends.
#[tokio::test]
async fn rest_get_memberships_bare_uuid_filter_returns_200() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let some_uuid = Uuid::now_v7();

    let req = json_request(
        "GET",
        &format!("/resource-group/v1/memberships?%24filter=group_id%20eq%20{some_uuid}"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = response_body(resp).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "bare-UUID $filter regressed: {body}"
    );
    assert!(body["items"].is_array());
    assert_no_surrogate_ids(&body);
}

// =========================================================================
// Classifier coverage: `From<toolkit_odata::Error> for DomainError`
// (`src/domain/error.rs`) must be exercised by an error that actually
// originates *inside* `paginate_odata`, not by the `$filter` pre-validation
// (`convert_expr_to_filter_node` / `resolve_type_filter_node`) that runs
// before it in `list_memberships`. The quoted-UUID test above never reaches
// the classifier: `MembershipFilterField::GroupId`'s `FieldKind::Uuid`
// rejects the quoted literal at `convert_expr_to_filter_node`, well before
// `paginate_odata` is ever called -- reverting the classifier's application
// site (the `.map_err(DomainError::from)?` on `paginate_odata`'s result) to
// the old blanket `.map_err(|e| DomainError::database(e.to_string()))`
// leaves that test green. These two tests instead drive failures that
// originate *inside* `paginate_odata_collect`: an unknown `$orderby` field,
// and a cursor whose embedded filter hash disagrees with the request's
// current `$filter`. Confirmed by mutation: reverting the classifier's
// application site to the blanket `Database` mapping turns both red (500
// instead of 400).
// =========================================================================

/// VHP-1954 classifier proof (1/2): `$orderby` on a field
/// `MembershipFilterField` doesn't declare passes the extractor
/// (`parse_orderby` only validates syntax, not field names -- see
/// `libs/toolkit/src/api/odata.rs`) and fails *inside*
/// `paginate_odata_collect`'s field-resolution loop with
/// `ODataError::InvalidOrderByField` (`libs/toolkit-db/src/odata/sea_orm_filter.rs`).
/// Must classify as a caller error (400), not a backend fault (500).
#[tokio::test]
async fn rest_get_memberships_unknown_orderby_field_returns_400_not_500() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let req = json_request(
        "GET",
        "/resource-group/v1/memberships?%24orderby=not_a_real_field%20asc",
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::BAD_REQUEST).await;
}

/// VHP-1954 classifier proof (2/2): a cursor whose embedded filter hash
/// (`cursor.f`) doesn't match the current request's `$filter` hash fails
/// *inside* `paginate_odata_collect` with `ODataError::FilterMismatch` -- a
/// client replaying a cursor minted under a different filter, not a
/// backend fault. The cursor is hand-built (rather than round-tripped
/// through a real `next_cursor`) so the mismatch is deterministic: `s`
/// (`"-group_id"`) matches `list_memberships`' real tiebreaker, so it
/// clears the orderby-field check first and the mismatch check is what
/// actually fires; `f` is a value no real `$filter` string will ever hash
/// to. The filter itself (`resource_id eq 'res-1'`) targets a field
/// `TypeRepository::resolve_type_filter_node` passes through untouched, so
/// nothing upstream of `paginate_odata` can reject it first.
#[tokio::test]
async fn rest_get_memberships_cursor_filter_mismatch_returns_400_not_500() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();

    let cursor = CursorV1 {
        k: vec!["group_id".to_owned()],
        o: SortDir::Desc,
        s: "-group_id".to_owned(),
        f: Some("mismatched-filter-hash".to_owned()),
        d: "fwd".to_owned(),
    };
    let token = cursor.encode().expect("encode hand-built cursor");

    let req = json_request(
        "GET",
        &format!(
            "/resource-group/v1/memberships\
             ?%24filter=resource_id%20eq%20%27res-1%27&cursor={token}"
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::BAD_REQUEST).await;
}

// =========================================================================
// list_groups `$filter=type` coverage (fe2d609e generalization follow-up)
// =========================================================================
//
// `resolve_type_filter_node` moved from `GroupRepository` into
// `TypeRepository` (generic over the filter-field enum) so `list_groups`
// and `list_memberships` share one implementation. Independent review
// found `list_groups`' own `type` `$filter` had no REST-level coverage at
// all -- these mirror the membership `$filter` REST tests directly above
// for the groups path.

/// End-to-end HTTP coverage: `GET .../groups?$filter=type eq '<gts-path>'`
/// must return exactly the groups of that type, not another type's groups
/// also present for the same tenant -- proves the whole pipeline (URL/query
/// decoding, `OData` parsing, JSON response), not just the repository call.
#[tokio::test]
async fn rest_list_groups_filters_by_type() {
    let (router, type_svc, group_svc, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let type_a = type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: rg_type_id!("test.restgta.i{}.v1~", Uuid::now_v7().as_simple()),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();
    let type_b = type_svc
        .create_type_unscoped(resource_group_sdk::CreateTypeRequest {
            code: rg_type_id!("test.restgtb.i{}.v1~", Uuid::now_v7().as_simple()),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .unwrap();

    let group_a = group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: type_a.code.clone(),
                name: "RestTypeA".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();
    group_svc
        .create_group(
            &ctx,
            resource_group_sdk::CreateGroupRequest {
                id: None,
                code: type_b.code.clone(),
                name: "RestTypeB".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_id,
        )
        .await
        .unwrap();

    let req = json_request(
        "GET",
        &format!(
            "/resource-group/v1/groups?%24filter=type%20eq%20%27{}%27",
            type_a.code
        ),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status();
    let body = response_body(resp).await;
    assert_eq!(status, StatusCode::OK, "type filter request failed: {body}");

    let items = body["items"].as_array().expect("items array");
    assert_eq!(
        items.len(),
        1,
        "type filter must return exactly the one group of type A, not type B's: {body}"
    );
    assert_eq!(items[0]["id"], group_a.id.to_string());
    assert_eq!(items[0]["type"], type_a.code);
    assert_no_surrogate_ids(&body);
}

/// Mirrors the membership `$filter` 400-not-500 guard above
/// (`rest_get_memberships_quoted_uuid_filter_returns_400_not_500`) for
/// groups: an unregistered GTS type path in `$filter=type eq '<path>'`
/// must classify as a caller error (400), never a raw 500 -- and must not
/// silently degrade to an empty 200 page either
/// (`resolve_type_filter_node` raises "Unknown type in filter" before the
/// value ever reaches the DB).
#[tokio::test]
async fn rest_list_groups_unknown_type_filter_returns_400_not_500() {
    let (router, _, _, _) = build_shared_router().await;
    let tenant_id = Uuid::now_v7();
    let bogus_type = rg_type_id!("test.restgtunknown.i{}.v1~", Uuid::now_v7().as_simple());

    let req = json_request(
        "GET",
        &format!("/resource-group/v1/groups?%24filter=type%20eq%20%27{bogus_type}%27"),
        None,
        tenant_id,
    );
    let resp = router.oneshot(req).await.unwrap();
    assert_problem_shape(resp, StatusCode::BAD_REQUEST).await;
}
