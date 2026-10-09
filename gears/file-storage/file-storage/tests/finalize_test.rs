//! Finalize-time checks: the claimed size is checked against the stored object; a rejected
//! finalize leaves the version `pending`.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::Path;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use bytes::Bytes;
use futures::stream::BoxStream;
use sea_orm_migration::MigratorTrait;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use file_storage::api::rest::handlers::{
    FinalizeAuth, FinalizeUploadReq, ReportPartReq, finalize_version, report_multipart_part,
};
use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::error::DomainError;
use file_storage::domain::multipart_service::MultipartService;
use file_storage::domain::ports::MultipartStore;
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{
    BackendCapabilities, BackendRegistry, InMemoryBackend, PublishOutcome, StorageBackend,
};
use file_storage::infra::content::hash;
use file_storage::infra::signed_url::{Claims, Issuer, MultipartClaims, Op, UploadConstraints};
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage::infra::storage::repo::VersionRepo;
use file_storage_sdk::{ByteRange, FileVersion, NewFile, OwnerKind, VersionStatus};

mod common;
use common::write_all;

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn build_db() -> Arc<DBProvider<DbError>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-finalize-test-{}.db",
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

/// Returns the raw backend and `Store` so tests control the object and inspect the version row.
async fn build_service() -> (Arc<FileService>, Arc<dyn StorageBackend>, Store) {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
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
    let svc = Arc::new(FileService::new(
        store.clone(),
        backends,
        issuer,
        authorizer,
        cfg,
        None,
        None,
    ));
    (svc, backend, store)
}

/// Shares one `Issuer` so handler-level tests can mint tokens the service's verifier accepts.
async fn build_full_service_with_issuer(
    issuer: Arc<Issuer>,
) -> (
    Arc<FileService>,
    Arc<MultipartService>,
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
        Arc::new(store.clone()) as Arc<dyn MultipartStore>,
        backends,
        authorizer,
        None,
        issuer,
        "http://sidecar.test".to_owned(),
        3600,
    ));
    (svc, msvc, backend, store)
}

/// `FileService` over a caller-supplied store/registry/issuer, for the two-instance key-rotation
/// tests.
fn service_over(
    store: Store,
    backends: BackendRegistry,
    authorizer: Arc<dyn file_storage::domain::authz::Authorizer>,
    issuer: Arc<Issuer>,
) -> Arc<FileService> {
    let cfg = ServiceConfig {
        default_url_ttl_secs: 3600,
        sidecar_base_url: "http://sidecar.test".to_owned(),
        default_page_size: 50,
        max_page_size: 1000,
        idempotency_ttl_secs: 86400,
    };
    Arc::new(FileService::new(
        store, backends, issuer, authorizer, cfg, None, None,
    ))
}

fn headers_with_token(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-fs-token",
        token.parse().expect("token is a valid header value"),
    );
    headers
}

/// Secret the `FinalizeAuth` of tests not about the internal credential is built with.
const TEST_INTERNAL_SECRET: &str = "test-internal-secret";

fn headers_with_internal_token(token: &str) -> HeaderMap {
    let mut headers = headers_with_token(token);
    headers.insert(
        "x-fs-internal-token",
        TEST_INTERNAL_SECRET
            .parse()
            .expect("secret is a valid header value"),
    );
    headers
}

fn ctx(tenant: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_tenant_id(tenant)
        .build()
        .expect("ctx")
}

fn new_file() -> NewFile {
    new_file_with_mime("application/octet-stream")
}

fn new_file_with_mime(mime_type: &str) -> NewFile {
    NewFile {
        owner_kind: OwnerKind::User,
        owner_id: Uuid::now_v7(),
        name: "finalize.bin".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: mime_type.to_owned(),
        custom_metadata: vec![],
    }
}

const PNG_MAGIC: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
const PDF_MAGIC: &[u8] = b"%PDF-1.4\n";

fn backend_path(file_id: Uuid, version_id: Uuid) -> String {
    format!("/{file_id}/{version_id}")
}

#[tokio::test]
async fn finalize_without_prior_put_is_rejected() {
    let (svc, _backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let err = svc
        .finalize_upload(&ctx, ticket.file_id, ticket.version_id, 100, vec![0u8; 32])
        .await
        .unwrap_err();
    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must still exist");
    assert_eq!(version.status, VersionStatus::Pending);
    assert_eq!(version.size, 0);
}

#[tokio::test]
async fn finalize_size_mismatch_is_rejected() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, Bytes::from_static(b"hello")).await;

    let err = svc
        .finalize_upload(
            &ctx,
            ticket.file_id,
            ticket.version_id,
            999,
            hash::sha256(b"hello"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must still exist");
    assert_eq!(version.status, VersionStatus::Pending);
}

#[tokio::test]
async fn finalize_persists_reported_hash() {
    // Finalize trusts the sidecar-reported hash; it does not re-read the object.
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, Bytes::from_static(b"hello")).await;

    let reported_hash = vec![0xabu8; 32];
    svc.finalize_upload(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        5,
        reported_hash.clone(),
    )
    .await
    .unwrap();

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(version.status, VersionStatus::Available);
    assert_eq!(version.size, 5);
    assert_eq!(version.hash_value, reported_hash);
}

#[tokio::test]
async fn finalize_matching_size_and_hash_succeeds() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let known_bytes = Bytes::from_static(b"hello, world!");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, known_bytes.clone()).await;

    let true_size = i64::try_from(known_bytes.len()).unwrap();
    let true_hash = hash::sha256(&known_bytes);

    svc.finalize_upload(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        true_size,
        true_hash,
    )
    .await
    .unwrap();

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(version.status, VersionStatus::Available);
    let independently_recomputed = hash::sha256(&known_bytes);
    assert_eq!(version.size, true_size);
    assert_eq!(version.hash_value, independently_recomputed);
}

#[tokio::test]
async fn finalize_by_token_without_prior_put_is_rejected() {
    let (svc, _backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };

    let err = svc
        .finalize_upload_by_token(&claims, 100, vec![0u8; 32])
        .await
        .unwrap_err();
    assert!(
        matches!(err, DomainError::Validation { .. }),
        "expected Validation, got {err:?}"
    );

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must still exist");
    assert_eq!(version.status, VersionStatus::Pending);
}

#[tokio::test]
async fn version_repo_finalize_twice_second_call_returns_false() {
    // `file_versions.file_id` has an FK to `files`, so a real parent file is created first.
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![backend], "mem").expect("registry");
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
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
    let svc = FileService::new(store, backends, issuer, authorizer, cfg, None, None);

    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = VersionRepo::new();

    let version_id = Uuid::now_v7();
    let pending = FileVersion {
        file_id,
        version_id,
        mime_type: "application/octet-stream".to_owned(),
        size: 0,
        hash_algorithm: "SHA-256".to_owned(),
        hash_value: vec![0u8; 32],
        hash_mode: "whole-sha256".to_owned(),
        part_count: None,
        status: VersionStatus::Pending,
        is_current: false,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(file_id, version_id),
        created_at: time::OffsetDateTime::now_utc(),
        bound_on_finalize: false,
    };
    repo.insert(&conn, &scope, &pending)
        .await
        .expect("insert pending version");

    let hash_a = hash::sha256(b"first-call-bytes");
    let hash_b = hash::sha256(b"second-call-bytes");

    let first = repo
        .finalize(
            &conn,
            &scope,
            file_id,
            version_id,
            100,
            hash_a.clone(),
            "whole-sha256",
            None,
            None,
        )
        .await
        .expect("first finalize call");
    assert!(first, "first finalize call on a pending row must succeed");

    let second = repo
        .finalize(
            &conn,
            &scope,
            file_id,
            version_id,
            200,
            hash_b,
            "whole-sha256",
            None,
            None,
        )
        .await
        .expect("second finalize call");
    assert!(
        !second,
        "second finalize call on an already-Available row must be a no-op"
    );

    let row = repo
        .get(&conn, &scope, file_id, version_id)
        .await
        .expect("query version row")
        .expect("version row must still exist");
    assert_eq!(row.size, 100, "size must retain the FIRST call's value");
    assert_eq!(
        row.hash_value, hash_a,
        "hash must retain the FIRST call's value"
    );
    assert_eq!(row.status, VersionStatus::Available);
}

#[tokio::test]
async fn finalize_upload_after_already_available_returns_conflict() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let known_bytes = Bytes::from_static(b"hello, world!");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, known_bytes.clone()).await;

    let true_size = i64::try_from(known_bytes.len()).unwrap();
    let true_hash = hash::sha256(&known_bytes);

    svc.finalize_upload(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        true_size,
        true_hash.clone(),
    )
    .await
    .unwrap();

    // Same size/hash replayed so the call reaches the repo-level CAS, which must conflict.
    let err = svc
        .finalize_upload(
            &ctx,
            ticket.file_id,
            ticket.version_id,
            true_size,
            true_hash.clone(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, DomainError::Conflict { .. }),
        "expected Conflict, got {err:?}"
    );

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must still exist");
    assert_eq!(version.status, VersionStatus::Available);
    assert_eq!(version.size, true_size);
    assert_eq!(version.hash_value, true_hash);
}

#[tokio::test]
async fn finalize_rejects_content_not_matching_declared_mime() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file_with_mime("image/png"), None, false)
        .await
        .unwrap();

    // Declared `image/png` but PDF bytes uploaded (policy bypass attempt).
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, Bytes::from_static(PDF_MAGIC)).await;

    let true_size = i64::try_from(PDF_MAGIC.len()).unwrap();
    let true_hash = hash::sha256(PDF_MAGIC);

    let err = svc
        .finalize_upload(
            &ctx,
            ticket.file_id,
            ticket.version_id,
            true_size,
            true_hash,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, DomainError::MimeMismatch { .. }),
        "expected MimeMismatch, got {err:?}"
    );

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must still exist");
    assert_eq!(version.status, VersionStatus::Pending);
    assert_eq!(
        version.mime_type, "image/png",
        "declared mime is untouched by a rejected finalize"
    );
}

#[tokio::test]
async fn finalize_persists_validated_mime() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    // A `charset` parameter on the declared type: the stored value proves the sniffed type was
    // persisted.
    let ticket = svc
        .create_file(
            &ctx,
            new_file_with_mime("image/png; charset=binary"),
            None,
            false,
        )
        .await
        .unwrap();

    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, Bytes::from_static(PNG_MAGIC)).await;

    let true_size = i64::try_from(PNG_MAGIC.len()).unwrap();
    let true_hash = hash::sha256(PNG_MAGIC);

    svc.finalize_upload(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        true_size,
        true_hash,
    )
    .await
    .unwrap();

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(version.status, VersionStatus::Available);
    assert_eq!(
        version.mime_type, "image/png",
        "stored mime_type must be the sniffed canonical type, not the declared string verbatim"
    );
}

/// Fails `get_stream`/`get_range_stream` (finalize must never read back) and can fail `stat`
/// with a chosen error.
struct NoReadBackBackend {
    inner: Arc<dyn StorageBackend>,
    stat_fault: Option<fn(&str) -> DomainError>,
}

#[async_trait]
impl StorageBackend for NoReadBackBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }
    async fn put_stream(
        &self,
        path: &str,
        stream: BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        self.inner.put_stream(path, stream, max_size).await
    }
    async fn publish_exclusive(
        &self,
        path: &str,
        stream: BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<PublishOutcome, DomainError> {
        self.inner.publish_exclusive(path, stream, max_size).await
    }
    async fn get_stream(
        &self,
        _path: &str,
        _expected_len: u64,
    ) -> Result<BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        Err(DomainError::backend(
            self.id(),
            "finalize must not stream the object back",
        ))
    }
    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        self.inner.read_prefix(path, max_bytes).await
    }
    async fn get_range_stream(
        &self,
        _path: &str,
        _range: ByteRange,
        _expected_len: u64,
    ) -> Result<BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        Err(DomainError::backend(
            self.id(),
            "finalize must not range-read the object",
        ))
    }
    async fn size(&self, path: &str) -> Result<u64, DomainError> {
        self.inner.size(path).await
    }
    async fn delete(&self, path: &str) -> Result<(), DomainError> {
        self.inner.delete(path).await
    }
    async fn exists(&self, path: &str) -> Result<bool, DomainError> {
        self.inner.exists(path).await
    }
    async fn stat(&self, path: &str) -> Result<Option<u64>, DomainError> {
        if let Some(fault) = self.stat_fault {
            return Err(fault(self.id()));
        }
        self.inner.stat(path).await
    }
}

async fn no_read_back_service(
    stat_fault: Option<fn(&str) -> DomainError>,
) -> (
    Arc<FileService>,
    Arc<FileService>,
    Store,
    Arc<dyn StorageBackend>,
) {
    let db = build_db().await;
    let store = Store::new(Arc::clone(&db));
    let inner: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);

    let plain_backends = BackendRegistry::new(vec![Arc::clone(&inner)], "mem").expect("registry");
    let plain_svc = service_over(
        store.clone(),
        plain_backends,
        Arc::clone(&authorizer),
        Arc::clone(&issuer),
    );
    let guarded: Arc<dyn StorageBackend> = Arc::new(NoReadBackBackend {
        inner: Arc::clone(&inner),
        stat_fault,
    });
    let guarded_backends = BackendRegistry::new(vec![guarded], "mem").expect("registry");
    let guarded_svc = service_over(store.clone(), guarded_backends, authorizer, issuer);
    (plain_svc, guarded_svc, store, inner)
}

#[tokio::test]
async fn finalize_large_object_is_not_read_back() {
    let (plain_svc, guarded_svc, store, inner) = no_read_back_service(None).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = plain_svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    // 4 MiB of content: the guarded backend errors on any read-back.
    let large_bytes: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    let large_bytes = Bytes::from(large_bytes);
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&inner, &path, large_bytes.clone()).await;

    let true_size = i64::try_from(large_bytes.len()).unwrap();
    let reported_hash = hash::sha256(&large_bytes);

    guarded_svc
        .finalize_upload(
            &ctx,
            ticket.file_id,
            ticket.version_id,
            true_size,
            reported_hash.clone(),
        )
        .await
        .unwrap();

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(version.status, VersionStatus::Available);
    assert_eq!(version.size, true_size);
    assert_eq!(version.hash_value, reported_hash);
}

/// A transient `stat` fault must surface as a retryable `BackendUnavailable`, not "never uploaded".
#[tokio::test]
async fn finalize_size_check_backend_fault_is_propagated() {
    let (plain_svc, guarded_svc, store, inner) = no_read_back_service(Some(|id: &str| {
        DomainError::backend_unavailable(id, "simulated stat fault (test)")
    }))
    .await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = plain_svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();
    let path = backend_path(ticket.file_id, ticket.version_id);
    let content = Bytes::from_static(b"content whose length check faults during finalize");
    write_all(&inner, &path, content.clone()).await;

    let err = guarded_svc
        .finalize_upload(
            &ctx,
            ticket.file_id,
            ticket.version_id,
            i64::try_from(content.len()).unwrap(),
            hash::sha256(&content),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, DomainError::BackendUnavailable { .. }),
        "a transient backend fault during the size check must stay retryable, got {err:?}"
    );

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must still exist");
    assert_eq!(
        version.status,
        VersionStatus::Pending,
        "finalize must not persist on a failed size check"
    );
}

#[tokio::test]
async fn finalize_with_internal_secret_required_rejects_missing_header() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, _msvc, _backend, _store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        "interim-shared-secret".to_owned(),
        time::Duration::ZERO,
    ));
    // Deliberately no `x-fs-internal-token` header.
    let headers = headers_with_token(&token);

    let req = FinalizeUploadReq {
        size: 5,
        hash_hex: hex::encode(hash::sha256(b"hello")),
    };

    let result = finalize_version(
        Extension(svc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    // `impl IntoResponse` isn't `Debug`, so `expect_err` can't be used.
    let Err(err) = result else {
        panic!("missing internal-token header must be rejected");
    };
    assert_eq!(
        err.status_code(),
        403,
        "missing internal credential must map to 403"
    );
}

#[tokio::test]
async fn finalize_with_internal_secret_required_accepts_matching_header() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, _msvc, backend, store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let known_bytes = Bytes::from_static(b"hello, world!");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, known_bytes.clone()).await;

    let true_size = i64::try_from(known_bytes.len()).unwrap();
    let true_hash = hash::sha256(&known_bytes);

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
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    let secret = "interim-shared-secret";
    let finalize_auth = Arc::new(FinalizeAuth::new(secret.to_owned(), time::Duration::ZERO));

    let mut headers = headers_with_token(&token);
    headers.insert(
        "x-fs-internal-token",
        secret.parse().expect("secret is a valid header value"),
    );

    let req = FinalizeUploadReq {
        size: true_size,
        hash_hex: hex::encode(&true_hash),
    };

    let result = finalize_version(
        Extension(Arc::clone(&svc)),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    let response = result
        .expect("matching internal-token header must be accepted")
        .into_response();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(
        version.status,
        VersionStatus::Available,
        "finalize must have actually gone through once the internal credential matched"
    );
}

// `finalize_token_grace_secs`: the sidecar checks the PUT token once at start, so a slow-but-live
// upload can reach finalize after the token's `exp`.

#[tokio::test]
async fn finalize_with_expired_token_accepted_within_grace() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, _msvc, backend, store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let known_bytes = Bytes::from_static(b"hello, world!");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, known_bytes.clone()).await;

    let true_size = i64::try_from(known_bytes.len()).unwrap();
    let true_hash = hash::sha256(&known_bytes);

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: path,
        // Expired 2 minutes ago: a slow-but-live PUT that outlasted the token TTL.
        exp: time::OffsetDateTime::now_utc().unix_timestamp() - 120,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    // 1-hour grace covers the 2-minute-past-exp token.
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::seconds(3600),
    ));
    let headers = headers_with_internal_token(&token);

    let req = FinalizeUploadReq {
        size: true_size,
        hash_hex: hex::encode(&true_hash),
    };

    let result = finalize_version(
        Extension(Arc::clone(&svc)),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    let response = result
        .expect("an expired-but-within-grace token must still be accepted by finalize")
        .into_response();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(
        version.status,
        VersionStatus::Available,
        "finalize must have actually gone through for the within-grace expired token"
    );
}

#[tokio::test]
async fn finalize_with_expired_token_rejected_beyond_grace() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, _msvc, _backend, _store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        // Expired 2 hours ago, beyond the 1-minute grace configured below.
        exp: time::OffsetDateTime::now_utc().unix_timestamp() - 7200,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::seconds(60),
    ));
    let headers = headers_with_internal_token(&token);

    let req = FinalizeUploadReq {
        size: 5,
        hash_hex: hex::encode(hash::sha256(b"hello")),
    };

    let result = finalize_version(
        Extension(svc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    let Err(err) = result else {
        panic!("a token expired well beyond the configured grace must be rejected");
    };
    assert_eq!(
        err.status_code(),
        403,
        "an expired-beyond-grace token must map to 403, same as any other invalid token"
    );
}

// `signing_key_seed` rotation: `verifier()` must still accept tokens signed under a previous seed
// named in `previous_signing_public_keys`.

#[tokio::test]
async fn finalize_accepts_token_signed_by_previous_key_after_rotation() {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    let store = Store::new(Arc::clone(&db));

    let old_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_before = service_over(
        store.clone(),
        backends.clone(),
        Arc::clone(&authorizer),
        Arc::clone(&old_issuer),
    );
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc_before
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let known_bytes = Bytes::from_static(b"hello, world!");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, known_bytes.clone()).await;

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
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = old_issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    // After rotation: new seed, old public key retained via `previous_signing_public_keys`.
    let new_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_after = Arc::new(
        FileService::new(
            store.clone(),
            backends.clone(),
            Arc::clone(&new_issuer),
            authorizer,
            ServiceConfig {
                default_url_ttl_secs: 3600,
                sidecar_base_url: "http://sidecar.test".to_owned(),
                default_page_size: 50,
                max_page_size: 1000,
                idempotency_ttl_secs: 86400,
            },
            None,
            None,
        )
        .with_previous_signing_public_keys(vec![old_issuer.public_key()])
        .expect("a valid-length previous key must be accepted"),
    );

    let verifier = Arc::new(svc_after.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::ZERO,
    ));
    let headers = headers_with_internal_token(&token);
    let req = FinalizeUploadReq {
        size: i64::try_from(known_bytes.len()).unwrap(),
        hash_hex: hex::encode(hash::sha256(&known_bytes)),
    };

    let result = finalize_version(
        Extension(Arc::clone(&svc_after)),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    let response = result
        .expect(
            "a finalize callback signed under a retained previous signing key must still verify",
        )
        .into_response();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(
        version.status,
        VersionStatus::Available,
        "finalize must have actually gone through for the previous-key-signed token"
    );
}

/// Without `previous_signing_public_keys` the old-seed token is rejected after rotation.
#[tokio::test]
async fn finalize_rejects_token_signed_by_previous_key_without_rotation_config() {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    let store = Store::new(Arc::clone(&db));

    let old_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_before = service_over(
        store.clone(),
        backends.clone(),
        Arc::clone(&authorizer),
        Arc::clone(&old_issuer),
    );
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc_before
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = old_issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let new_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_after = service_over(store, backends, authorizer, new_issuer);

    let verifier = Arc::new(svc_after.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::ZERO,
    ));
    let headers = headers_with_internal_token(&token);
    let req = FinalizeUploadReq {
        size: 5,
        hash_hex: hex::encode(hash::sha256(b"hello")),
    };

    let result = finalize_version(
        Extension(svc_after),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    let Err(err) = result else {
        panic!(
            "an old-seed-signed token must be rejected once the control plane has rotated \
             without retaining that key in previous_signing_public_keys"
        );
    };
    assert_eq!(err.status_code(), 403);
}

/// The grace window also applies on top of previous-key acceptance.
#[tokio::test]
async fn finalize_accepts_expired_previous_key_token_within_grace_after_rotation() {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    let store = Store::new(Arc::clone(&db));

    let old_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_before = service_over(
        store.clone(),
        backends.clone(),
        Arc::clone(&authorizer),
        Arc::clone(&old_issuer),
    );
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc_before
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let known_bytes = Bytes::from_static(b"hello, world!");
    let path = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path, known_bytes.clone()).await;

    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: path,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() - 120,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = old_issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let new_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_after = Arc::new(
        FileService::new(
            store.clone(),
            backends,
            Arc::clone(&new_issuer),
            authorizer,
            ServiceConfig {
                default_url_ttl_secs: 3600,
                sidecar_base_url: "http://sidecar.test".to_owned(),
                default_page_size: 50,
                max_page_size: 1000,
                idempotency_ttl_secs: 86400,
            },
            None,
            None,
        )
        .with_previous_signing_public_keys(vec![old_issuer.public_key()])
        .expect("a valid-length previous key must be accepted"),
    );

    let verifier = Arc::new(svc_after.verifier());
    // 1-hour grace covers the 2-minute-past-exp token.
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::seconds(3600),
    ));
    let headers = headers_with_internal_token(&token);
    let req = FinalizeUploadReq {
        size: i64::try_from(known_bytes.len()).unwrap(),
        hash_hex: hex::encode(hash::sha256(&known_bytes)),
    };

    let result = finalize_version(
        Extension(Arc::clone(&svc_after)),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id)),
        headers,
        Json(req),
    )
    .await;

    let response = result
        .expect("an expired-but-within-grace previous-key token must still be accepted")
        .into_response();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let version = store
        .get_version(ticket.file_id, ticket.version_id)
        .await
        .unwrap()
        .expect("version row must exist");
    assert_eq!(version.status, VersionStatus::Available);
}

/// Minting after rotation signs with the current key only.
#[tokio::test]
async fn signing_after_rotation_uses_current_key_only() {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    let store = Store::new(Arc::clone(&db));

    let old_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let new_issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let svc_after = Arc::new(
        FileService::new(
            store,
            backends,
            Arc::clone(&new_issuer),
            authorizer,
            ServiceConfig {
                default_url_ttl_secs: 3600,
                sidecar_base_url: "http://sidecar.test".to_owned(),
                default_page_size: 50,
                max_page_size: 1000,
                idempotency_ttl_secs: 86400,
            },
            None,
            None,
        )
        .with_previous_signing_public_keys(vec![old_issuer.public_key()])
        .expect("a valid-length previous key must be accepted"),
    );

    let ctx = ctx(Uuid::now_v7());
    let ticket = svc_after
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();
    // Extract the PUT token from the upload URL's `fs-token` query parameter.
    let token = ticket
        .upload_url
        .split("fs-token=")
        .nth(1)
        .expect("upload_url must carry an fs-token query parameter")
        .to_owned();

    let now = time::OffsetDateTime::now_utc();
    assert!(
        new_issuer.verifier().verify(&token, now).is_ok(),
        "a token minted after rotation must verify against the NEW issuer's own key"
    );
    assert!(
        old_issuer.verifier().verify(&token, now).is_err(),
        "a token minted after rotation must NOT verify against the OLD issuer's key -- \
         minting always uses the current key only, regardless of previous_signing_public_keys"
    );
}

#[tokio::test]
async fn report_part_with_expired_token_passes_verification_within_grace() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, msvc, _backend, _store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let upload_id = Uuid::now_v7();
    let part_number = 1u32;
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        exp: time::OffsetDateTime::now_utc().unix_timestamp() - 120,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id,
            part_number,
            offset: 0,
            size: 5,
            backend_handle: String::new(),
        },
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::seconds(3600),
    ));
    let headers = headers_with_internal_token(&token);

    let req = ReportPartReq {
        backend_etag: "etag-1".to_owned(),
        hash_hex: hex::encode(hash::sha256(b"hello")),
        size: 5,
    };

    let result = report_multipart_part(
        Extension(msvc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id, upload_id, part_number)),
        headers,
        Json(req),
    )
    .await;

    // Must fail because no multipart session exists, not with 403 (token rejection).
    if let Err(err) = result {
        assert_ne!(
            err.status_code(),
            403,
            "an expired-but-within-grace token must pass verification, not be rejected as expired"
        );
    }
}

#[tokio::test]
async fn report_part_with_expired_token_rejected_beyond_grace() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, msvc, _backend, _store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let upload_id = Uuid::now_v7();
    let part_number = 1u32;
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        // Expired 2 hours ago, beyond the 1-minute grace configured below.
        exp: time::OffsetDateTime::now_utc().unix_timestamp() - 7200,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id,
            part_number,
            offset: 0,
            size: 5,
            backend_handle: String::new(),
        },
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        TEST_INTERNAL_SECRET.to_owned(),
        time::Duration::seconds(60),
    ));
    let headers = headers_with_internal_token(&token);

    let req = ReportPartReq {
        backend_etag: "etag-1".to_owned(),
        hash_hex: hex::encode(hash::sha256(b"hello")),
        size: 5,
    };

    let result = report_multipart_part(
        Extension(msvc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id, upload_id, part_number)),
        headers,
        Json(req),
    )
    .await;

    let Err(err) = result else {
        panic!("a token expired well beyond the configured grace must be rejected");
    };
    assert_eq!(
        err.status_code(),
        403,
        "an expired-beyond-grace token must map to 403, same as any other invalid token"
    );
}

#[tokio::test]
async fn report_part_with_internal_secret_required_rejects_missing_header() {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let (svc, msvc, _backend, _store) = build_full_service_with_issuer(Arc::clone(&issuer)).await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let upload_id = Uuid::now_v7();
    let part_number = 1u32;
    let claims = Claims {
        op: Op::MultipartPart,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: backend_path(ticket.file_id, ticket.version_id),
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims {
            upload_id,
            part_number,
            offset: 0,
            size: 5,
            backend_handle: String::new(),
        },
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: false,
        content_sha256: String::new(),
    };
    let token = issuer
        .issue(claims, time::OffsetDateTime::now_utc())
        .expect("issue token");

    let verifier = Arc::new(svc.verifier());
    let finalize_auth = Arc::new(FinalizeAuth::new(
        "interim-shared-secret".to_owned(),
        time::Duration::ZERO,
    ));
    // Deliberately no `x-fs-internal-token` header.
    let headers = headers_with_token(&token);

    let req = ReportPartReq {
        backend_etag: "etag-1".to_owned(),
        hash_hex: hex::encode(hash::sha256(b"hello")),
        size: 5,
    };

    let result = report_multipart_part(
        Extension(msvc),
        Extension(verifier),
        Extension(finalize_auth),
        Path((ticket.file_id, ticket.version_id, upload_id, part_number)),
        headers,
        Json(req),
    )
    .await;

    // `impl IntoResponse` isn't `Debug`, so `expect_err` can't be used.
    let Err(err) = result else {
        panic!("missing internal-token header must be rejected");
    };
    assert_eq!(
        err.status_code(),
        403,
        "missing internal credential must map to 403"
    );
}

use file_storage::domain::multipart::BindState;

/// A `bind_on_finalize` token makes finalize itself bind the first content (`content_id IS NULL`
/// CAS).
#[tokio::test]
async fn finalize_with_bind_claim_binds_first_content() {
    let (svc, backend, store) = build_service().await;
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
    let outcome = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(bytes.len()).unwrap(),
            hash::sha256(&bytes),
        )
        .await
        .unwrap();
    assert_eq!(outcome.bind_state, Some(BindState::Bound));
    assert!(
        outcome.etag.is_some(),
        "bound finalize must return the new ETag"
    );

    let file = store
        .get_file(&toolkit_security::AccessScope::allow_all(), ticket.file_id)
        .await
        .unwrap()
        .expect("file");
    assert_eq!(
        file.content_id,
        Some(ticket.version_id),
        "finalize with the bind claim must have bound the first content"
    );

    // Idempotent retry (response lost) converges to the same success, never a 409.
    let retry = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(bytes.len()).unwrap(),
            hash::sha256(&bytes),
        )
        .await
        .expect("honest PUT retry must converge to success");
    assert_eq!(retry.bind_state, Some(BindState::Bound));
    assert_eq!(retry.etag, outcome.etag);
}

/// A retry replays the ORIGINAL `Bound` decision even if an unrelated rebind has since moved
/// the file's content.
#[tokio::test]
async fn finalize_by_token_retry_replays_bound_decision_despite_later_rebind() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc.create_file(&ctx, new_file(), None, true).await.unwrap();

    let bytes_a = Bytes::from_static(b"version A content");
    let path_a = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path_a, bytes_a.clone()).await;

    let claims_a = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket.version_id,
        backend_id: "mem".to_owned(),
        backend_path: path_a,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: true,
        content_sha256: String::new(),
    };
    let original = svc
        .finalize_upload_by_token(
            &claims_a,
            i64::try_from(bytes_a.len()).unwrap(),
            hash::sha256(&bytes_a),
        )
        .await
        .unwrap();
    assert_eq!(original.bind_state, Some(BindState::Bound));
    assert!(original.etag.is_some());

    let ticket_b = svc.presign_version(&ctx, ticket.file_id).await.unwrap();
    let bytes_b = Bytes::from_static(b"version B content");
    let path_b = backend_path(ticket.file_id, ticket_b.version_id);
    write_all(&backend, &path_b, bytes_b.clone()).await;
    svc.finalize_upload(
        &ctx,
        ticket.file_id,
        ticket_b.version_id,
        i64::try_from(bytes_b.len()).unwrap(),
        hash::sha256(&bytes_b),
    )
    .await
    .unwrap();
    // File is bound to A, so rebinding to B needs A's ETag as `If-Match`.
    svc.bind(
        &ctx,
        ticket.file_id,
        ticket_b.version_id,
        original.etag.as_deref(),
    )
    .await
    .unwrap();

    let file = store
        .get_file(&toolkit_security::AccessScope::allow_all(), ticket.file_id)
        .await
        .unwrap()
        .expect("file");
    assert_eq!(
        file.content_id,
        Some(ticket_b.version_id),
        "the file must now legitimately point at version B"
    );

    // Retry of A's token must still see `Bound` + A's ETag, not `Conflict` against B.
    let retry = svc
        .finalize_upload_by_token(
            &claims_a,
            i64::try_from(bytes_a.len()).unwrap(),
            hash::sha256(&bytes_a),
        )
        .await
        .expect("retry of an already-decided Bound finalize must not fail");
    assert_eq!(
        retry.bind_state,
        Some(BindState::Bound),
        "must replay the ORIGINAL Bound decision, not the file's current pointer"
    );
    assert_eq!(
        retry.etag, original.etag,
        "must report version A's own ETag, not a Conflict against version B"
    );
    assert_eq!(retry.current_etag, None);
}

/// Two create-tokens racing for one new file: the loser reports `conflict` + the current ETag;
/// its upload still succeeds.
#[tokio::test]
async fn finalize_bind_claim_lost_cas_reports_conflict() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc.create_file(&ctx, new_file(), None, true).await.unwrap();

    let winner_bytes = Bytes::from_static(b"winner");
    let path_a = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path_a, winner_bytes.clone()).await;
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

    // Loser: a second pending version whose `content_id IS NULL` CAS can no longer win.
    let ticket2 = svc.presign_version(&ctx, ticket.file_id).await.unwrap();
    let loser_bytes = Bytes::from_static(b"loser!");
    let path_b = backend_path(ticket.file_id, ticket2.version_id);
    write_all(&backend, &path_b, loser_bytes.clone()).await;
    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket2.version_id,
        backend_id: "mem".to_owned(),
        backend_path: path_b,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: true,
        content_sha256: String::new(),
    };
    let outcome = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(loser_bytes.len()).unwrap(),
            hash::sha256(&loser_bytes),
        )
        .await
        .expect("finalize itself succeeds \u{2014} only the bind CAS is lost");
    assert_eq!(outcome.bind_state, Some(BindState::Conflict));
    assert!(
        outcome.current_etag.is_some(),
        "conflict must carry the CURRENT ETag for a manual rebind's If-Match"
    );
    assert_eq!(outcome.etag, None);

    let version = store
        .get_version(ticket.file_id, ticket2.version_id)
        .await
        .unwrap()
        .expect("version");
    assert_eq!(version.status, VersionStatus::Available);
    svc.bind(
        &ctx,
        ticket.file_id,
        ticket2.version_id,
        outcome.current_etag.as_deref(),
    )
    .await
    .expect("manual rebind with the conflict-reported ETag");
}

/// A lost auto-bind CAS leaves `bound_on_finalize` unset, so a retry re-derives `Conflict` with the
/// same ETag.
#[tokio::test]
async fn finalize_by_token_retry_after_lost_cas_still_reports_conflict() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc.create_file(&ctx, new_file(), None, true).await.unwrap();

    let winner_bytes = Bytes::from_static(b"winner");
    let path_a = backend_path(ticket.file_id, ticket.version_id);
    write_all(&backend, &path_a, winner_bytes.clone()).await;
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

    let ticket2 = svc.presign_version(&ctx, ticket.file_id).await.unwrap();
    let loser_bytes = Bytes::from_static(b"loser!");
    let path_b = backend_path(ticket.file_id, ticket2.version_id);
    write_all(&backend, &path_b, loser_bytes.clone()).await;
    let claims = Claims {
        op: Op::Put,
        file_id: ticket.file_id,
        version_id: ticket2.version_id,
        backend_id: "mem".to_owned(),
        backend_path: path_b,
        exp: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        upload: UploadConstraints::default(),
        multipart: MultipartClaims::default(),
        request_id: "test-request-id".to_owned(),
        content_type: String::new(),
        etag: String::new(),
        bind_on_finalize: true,
        content_sha256: String::new(),
    };
    let original = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(loser_bytes.len()).unwrap(),
            hash::sha256(&loser_bytes),
        )
        .await
        .unwrap();
    assert_eq!(original.bind_state, Some(BindState::Conflict));

    let retry = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(loser_bytes.len()).unwrap(),
            hash::sha256(&loser_bytes),
        )
        .await
        .expect("honest retry of a lost-CAS finalize must still converge");
    assert_eq!(retry.bind_state, Some(BindState::Conflict));
    assert_eq!(
        retry.current_etag, original.current_etag,
        "must report the SAME live current ETag as the original lost-CAS response"
    );
    assert_eq!(retry.etag, None);

    let version = store
        .get_version(ticket.file_id, ticket2.version_id)
        .await
        .unwrap()
        .expect("version");
    assert!(
        !version.bound_on_finalize,
        "a lost CAS must never set the persisted bind flag"
    );
}

// Manual-mode retry convergence: every single-part upload goes through the replay-safe
// `publish_exclusive`.

/// A manual-token finalize replayed after the version is `Available` converges to the same success,
/// not 409.
#[tokio::test]
async fn finalize_manual_token_converges_on_retry() {
    let (svc, backend, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let bytes = Bytes::from_static(b"manual retry");
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
        bind_on_finalize: false,
        content_sha256: String::new(),
    };

    let outcome = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(bytes.len()).unwrap(),
            hash::sha256(&bytes),
        )
        .await
        .unwrap();
    assert_eq!(outcome.bind_state, None, "manual mode requests no bind");

    let retry = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(bytes.len()).unwrap(),
            hash::sha256(&bytes),
        )
        .await
        .expect("honest manual-mode PUT retry must converge to success, not 409");
    assert_eq!(retry.bind_state, Some(BindState::Manual));
    assert_eq!(retry.etag, None);
    assert_eq!(retry.current_etag, None);

    let versions = store.list_versions(ticket.file_id).await.unwrap();
    assert_eq!(
        versions.len(),
        1,
        "the retry must not create or touch a second version row"
    );
    let file = store
        .get_file(&toolkit_security::AccessScope::allow_all(), ticket.file_id)
        .await
        .unwrap()
        .expect("file");
    assert_eq!(
        file.content_id, None,
        "manual mode must never auto-bind, even on retry"
    );
}

/// A manual token explicitly bound after the first finalize, then retried: the retry reports
/// `Bound`.
#[tokio::test]
async fn finalize_manual_token_converges_to_bound_after_manual_bind() {
    let (svc, backend, _store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let bytes = Bytes::from_static(b"manual then bound");
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
        bind_on_finalize: false,
        content_sha256: String::new(),
    };

    svc.finalize_upload_by_token(
        &claims,
        i64::try_from(bytes.len()).unwrap(),
        hash::sha256(&bytes),
    )
    .await
    .unwrap();

    svc.bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("manual bind after finalize");

    let retry = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(bytes.len()).unwrap(),
            hash::sha256(&bytes),
        )
        .await
        .expect("retry after manual bind must converge to success");
    assert_eq!(retry.bind_state, Some(BindState::Bound));
    assert!(
        retry.etag.is_some(),
        "bound retry must report the content ETag"
    );
    assert_eq!(retry.current_etag, None);
}

/// A manual retry with mismatched size/hash (forged replay) stays rejected.
#[tokio::test]
async fn finalize_manual_token_retry_with_mismatched_hash_is_rejected() {
    let (svc, backend, _store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .unwrap();

    let bytes = Bytes::from_static(b"manual original");
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
        bind_on_finalize: false,
        content_sha256: String::new(),
    };

    svc.finalize_upload_by_token(
        &claims,
        i64::try_from(bytes.len()).unwrap(),
        hash::sha256(&bytes),
    )
    .await
    .unwrap();

    let mismatched = Bytes::from_static(b"forged replay!!!");
    let err = svc
        .finalize_upload_by_token(
            &claims,
            i64::try_from(mismatched.len()).unwrap(),
            hash::sha256(&mismatched),
        )
        .await
        .expect_err("a mismatched replay must not converge to success");
    assert!(
        matches!(err, DomainError::HashMismatch { .. }),
        "expected a hash-mismatch rejection, got {err:?}"
    );
}
