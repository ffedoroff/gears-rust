//! Handler-level tests for `complete_multipart`'s 200/202 branches and `finalize_version`'s
//! auto-bind header mapping. Calls the handlers directly, without an `axum::Router`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;

use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use bytes::Bytes;
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use file_storage::api::rest::handlers::{self, FinalizeAuth, FinalizeUploadReq};
use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::etag::etag_for;
use file_storage::domain::multipart::DEFAULT_MIN_PART_SIZE;
use file_storage::domain::multipart_service::MultipartService;
use file_storage::domain::ports::MultipartStore;
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{BackendRegistry, InMemoryBackend, StorageBackend};
use file_storage::infra::content::hash;
use file_storage::infra::signed_url::{Claims, Issuer, MultipartClaims, Op, UploadConstraints};
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::{NewFile, OwnerKind};

mod common;
use common::write_all;

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn build_db() -> Arc<DBProvider<DbError>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-complete-bind-test-{}.db",
        Uuid::now_v7().simple()
    ));
    let dsn = format!("sqlite://{}?mode=rwc", path.display());
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db(&dsn, opts).await.expect("connect sqlite");
    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .expect("migrations");
    Arc::new(DBProvider::new(db))
}

fn ctx(tenant: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_tenant_id(tenant)
        .build()
        .expect("ctx")
}

fn new_file() -> NewFile {
    NewFile {
        owner_kind: OwnerKind::User,
        owner_id: Uuid::now_v7(),
        name: "complete-bind.bin".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "application/octet-stream".to_owned(),
        custom_metadata: vec![],
    }
}

fn backend_path(file_id: Uuid, version_id: Uuid) -> String {
    format!("/{file_id}/{version_id}")
}

/// `FileService` + `MultipartService` sharing one store/backend, on a caller-supplied `Issuer`
/// so `finalize_version` tests can mint tokens that `svc.verifier()` accepts.
async fn build_env(
    issuer: Arc<Issuer>,
) -> (
    Arc<FileService>,
    Arc<MultipartService>,
    Arc<dyn MultipartStore>,
    Arc<dyn StorageBackend>,
    Store,
) {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    let cfg = ServiceConfig {
        default_url_ttl_secs: 3600,
        sidecar_base_url: "http://sidecar.test".to_owned(),
        default_page_size: 50,
        max_page_size: 1000,
        idempotency_ttl_secs: 86400,
    };
    let store = Store::new(Arc::clone(&db));
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = Arc::new(FileService::new(
        store.clone(),
        backends.clone(),
        Arc::clone(&issuer),
        Arc::clone(&authorizer),
        cfg,
        None,
        None,
    ));
    let msvc = Arc::new(MultipartService::new(
        Arc::clone(&multipart_store),
        backends,
        authorizer,
        None,
        issuer,
        "http://sidecar.test".to_owned(),
        3600,
    ));
    (svc, msvc, multipart_store, backend, store)
}

async fn simulate_sidecar_put_part(
    store: &Arc<dyn MultipartStore>,
    backend: &Arc<dyn StorageBackend>,
    plan: &file_storage::domain::multipart::MultipartPlan,
    backend_path: &str,
    backend_handle: &str,
    part_number: u32,
    data: Bytes,
) {
    let part = plan
        .parts
        .iter()
        .find(|p| p.part_number == part_number)
        .unwrap_or_else(|| panic!("part {part_number} not in plan"));
    assert_eq!(
        data.len() as u64,
        part.size,
        "part {part_number}: size mismatch"
    );

    let len = data.len() as u64;
    let stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
        Box::pin(futures::stream::once(async move { Ok(data) }));
    let (backend_etag, part_hash) = backend
        .upload_part_stream(
            backend_path,
            backend_handle,
            part_number,
            part.offset,
            stream,
            len,
        )
        .await
        .expect("backend upload_part_stream");

    let size = i64::try_from(part.size).unwrap();
    let now = time::OffsetDateTime::now_utc();
    let part_number_i32 = i32::try_from(part_number).unwrap();
    store
        .upsert_multipart_part(
            plan.upload_id,
            part_number_i32,
            &backend_etag,
            part_hash,
            size,
            now,
        )
        .await
        .unwrap();
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("valid JSON body")
}

/// A 2-part auto-bind upload completed through the handler; each `MultipartCompleteDto` field is
/// cross-checked against the persisted rows rather than hardcoded hash bytes.
#[tokio::test]
async fn complete_multipart_completed_returns_200_with_full_dto() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, msvc, multipart_store, backend, store) = build_env(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    // 5 MiB + 5 bytes at a 5 MiB part size -> exactly 2 parts, so composite hash mode/manifest are
    // set.
    let part_size = DEFAULT_MIN_PART_SIZE;
    let declared_size = part_size + 5;
    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            declared_size,
            Some(part_size),
            true, // auto_bind
        )
        .await
        .unwrap();
    assert_eq!(plan.parts.len(), 2, "plan must have exactly 2 parts");

    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let path = backend_path(file_id, plan.version_id);

    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &path,
        &session.backend_upload_handle,
        1,
        Bytes::from(vec![0u8; usize::try_from(part_size).unwrap()]),
    )
    .await;
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &path,
        &session.backend_upload_handle,
        2,
        Bytes::from_static(b"AAAAA"),
    )
    .await;

    let resp = handlers::complete_multipart(
        Extension(ctx.clone()),
        Extension(Arc::clone(&msvc)),
        Path((file_id, plan.upload_id)),
        HeaderMap::new(),
    )
    .await
    .expect("complete_multipart must succeed");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = body_json(resp).await;

    let version = store
        .get_version(file_id, plan.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    let file = store
        .get_file(&AccessScope::allow_all(), file_id)
        .await
        .unwrap()
        .expect("file row must exist");
    let manifest = store
        .get_version_manifest(plan.version_id)
        .await
        .unwrap()
        .expect("a 2-part completion must persist a manifest row");

    assert_eq!(body["version_id"], plan.version_id.to_string());
    assert_eq!(body["size"], i64::try_from(declared_size).unwrap());
    assert_eq!(body["hash_algorithm"], "SHA-256");
    assert_eq!(
        hex::decode(
            body["content_hash"]
                .as_str()
                .expect("content_hash is a string")
        )
        .unwrap(),
        version.hash_value,
        "content_hash must be the hex encoding of the persisted hash_value"
    );
    assert_eq!(body["hash_mode"], "multipart-composite-sha256");
    assert_eq!(body["part_count"], 2);
    assert_eq!(body["manifest"], manifest);
    assert_eq!(body["bind_state"], "bound");
    assert_eq!(
        body["etag"],
        etag_for(&file).expect("bound file must have a content etag")
    );
    assert!(
        body.get("current_etag").is_none(),
        "current_etag must be omitted (null) on a successful bind, got {body:?}"
    );

    assert_eq!(file.content_id, Some(plan.version_id));
}

/// `complete` racing a LIVE completion lease answers 202 with `retry_after_secs` and a matching
/// `Retry-After` header. The lease is taken directly via the store, so there is no race or sleep.
#[tokio::test]
async fn complete_multipart_while_lease_held_returns_202_with_matching_retry_after() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, msvc, multipart_store, _backend, _store) = build_env(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();

    let now = time::OffsetDateTime::now_utc();
    let acquired = multipart_store
        .acquire_multipart_complete_lease(
            plan.upload_id,
            "other-completer",
            now + time::Duration::seconds(120),
            now,
        )
        .await
        .unwrap();
    assert!(
        acquired,
        "test setup: the other completer must win the lease"
    );

    let resp = handlers::complete_multipart(
        Extension(ctx.clone()),
        Extension(Arc::clone(&msvc)),
        Path((file_id, plan.upload_id)),
        HeaderMap::new(),
    )
    .await
    .expect("a live competing lease must answer Completing, not an error");
    assert_eq!(resp.status(), StatusCode::ACCEPTED);

    let retry_after_header = resp
        .headers()
        .get(header::RETRY_AFTER)
        .expect("Retry-After header must be set on a 202")
        .to_str()
        .expect("Retry-After is ASCII")
        .to_owned();

    let body = body_json(resp).await;
    assert_eq!(body["state"], "completing");
    let retry_after_secs = body["retry_after_secs"]
        .as_u64()
        .expect("retry_after_secs is a number");
    assert!(retry_after_secs > 0);
    assert_eq!(
        retry_after_header,
        retry_after_secs.to_string(),
        "Retry-After header must mirror the body's retry_after_secs"
    );
}

/// A `bind_on_finalize` finalize through the real handler sets `x-fs-bound: true` and the new
/// `ETag`.
#[tokio::test]
async fn finalize_version_bind_claim_won_sets_bound_header_and_etag() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, _msvc, _multipart_store, backend, store) = build_env(Arc::clone(&issuer)).await;
    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        "test-internal-secret".to_owned(),
        time::Duration::ZERO,
    ));
    let ctx = ctx(Uuid::now_v7());

    let ticket = svc.create_file(&ctx, new_file(), None, true).await.unwrap();
    let bytes = Bytes::from_static(b"auto-bind me");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, bytes.clone()).await;

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: path,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: true,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let mut headers = HeaderMap::new();
    headers.insert("x-fs-token", token.parse().expect("valid header value"));
    headers.insert(
        "x-fs-internal-token",
        "test-internal-secret".parse().expect("valid header value"),
    );
    let req = FinalizeUploadReq {
        size: i64::try_from(bytes.len()).unwrap(),
        hash_hex: hex::encode(hash::sha256(&bytes)),
    };

    let resp = handlers::finalize_version(
        Extension(svc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await
    .expect("finalize with a winning bind claim must succeed")
    .into_response();

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers().get("x-fs-bound").expect("x-fs-bound header"),
        "true"
    );

    let file = store
        .get_file(&AccessScope::allow_all(), ticket.file_id)
        .await
        .unwrap()
        .expect("file");
    assert_eq!(
        file.content_id,
        Some(ticket.version_id),
        "the bind claim must have actually bound the version"
    );
    let expected_etag = etag_for(&file).expect("bound file must have a content etag");
    assert_eq!(
        resp.headers()
            .get(header::ETAG)
            .expect("ETag header")
            .to_str()
            .unwrap(),
        expected_etag,
        "ETag header must be the file's new content etag"
    );
}

/// Loser of the `content_id IS NULL` CAS between two `bind_on_finalize` completions still
/// finalizes,
/// but the handler answers `x-fs-bound: conflict` + `x-fs-current-etag` of the winner.
#[tokio::test]
async fn finalize_version_bind_claim_lost_cas_reports_conflict_header() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, _msvc, _multipart_store, backend, store) = build_env(Arc::clone(&issuer)).await;
    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        "test-internal-secret".to_owned(),
        time::Duration::ZERO,
    ));
    let ctx = ctx(Uuid::now_v7());

    let ticket = svc.create_file(&ctx, new_file(), None, true).await.unwrap();

    let winner_bytes = Bytes::from_static(b"winner");
    let winner_path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &winner_path, winner_bytes.clone()).await;
    svc.finalize_upload(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        i64::try_from(winner_bytes.len()).unwrap(),
        hash::sha256(&winner_bytes),
    )
    .await
    .unwrap();
    svc.bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .unwrap();

    // Loser: a second pending version on the SAME file whose `content_id IS NULL` CAS can no longer
    // win.
    let ticket2 = svc.presign_version(&ctx, ticket.file_id).await.unwrap();
    let loser_bytes = Bytes::from_static(b"loser!");
    let loser_path = backend_path(ticket.file_id, ticket2.version_id);
    write_all(&backend, &loser_path, loser_bytes.clone()).await;

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket2.version_id,
        backend_id: "mem".to_owned(),
        backend_path: loser_path,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: true,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let mut headers = HeaderMap::new();
    headers.insert("x-fs-token", token.parse().expect("valid header value"));
    headers.insert(
        "x-fs-internal-token",
        "test-internal-secret".parse().expect("valid header value"),
    );
    let req = FinalizeUploadReq {
        size: i64::try_from(loser_bytes.len()).unwrap(),
        hash_hex: hex::encode(hash::sha256(&loser_bytes)),
    };

    let file_before = store
        .get_file(&AccessScope::allow_all(), ticket.file_id)
        .await
        .unwrap()
        .expect("file");
    let winner_etag = etag_for(&file_before).expect("winner bind must have set a content etag");

    let resp = handlers::finalize_version(
        Extension(svc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket2.version_id)),
        headers,
        Json(req),
    )
    .await
    .expect("finalize itself succeeds -- only the embedded bind CAS is lost")
    .into_response();

    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "the upload/finalize is not rejected merely because the bind lost"
    );
    assert_eq!(
        resp.headers().get("x-fs-bound").expect("x-fs-bound header"),
        "conflict"
    );
    assert_eq!(
        resp.headers()
            .get("x-fs-current-etag")
            .expect("x-fs-current-etag header")
            .to_str()
            .unwrap(),
        winner_etag,
        "x-fs-current-etag must carry the CURRENT (winner's) etag for a manual rebind's If-Match"
    );
    assert!(
        resp.headers().get(header::ETAG).is_none(),
        "a conflict response must not also carry an ETag header"
    );
}
