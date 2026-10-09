#![cfg(feature = "integration")]
// Created: 2026-07-27 by Constructor Tech
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
//! PostgreSQL concurrency harness for file-storage's CAS-based safety (real Postgres via Docker).
//! Gated behind the `integration` feature (`make test-fs-pg`); tests skip without Docker unless
//! `FS_PG_REQUIRE_DOCKER` is set.
//!
//! - `f1_*`: version-less orphan `files` row after a multipart-initiate failure.
//! - `f2_*`: two completers racing one session's lease, forced with `Notify` gates.
//! - `f9_*`: auto-bind must not clobber a rebind made before `complete` (no `If-Match`).
//! - `f10_*`/`f11_*`: sweep vs expired or `completing` sessions.
//! - `delete_*`/`orphan_reclaim_*`: parent-row-lock races against a concurrent version insert.
//! - `migration_lease_*`: concurrent `migrate_backend` calls.
//! - `invariant_checker_*`: `content_id` must point at an `available` version.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use file_storage::domain::audit::{AuditEntry, AuditOperation};
use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::cleanup::{CleanupConfig, CleanupEngine};
use file_storage::domain::error::DomainError;
use file_storage::domain::multipart::{BindState, MultipartPart, MultipartUploadState};
use file_storage::domain::multipart_service::MultipartService;
use file_storage::domain::policy::{PolicyScope, StoredPolicy};
use file_storage::domain::ports::{
    AutoBindOnFinalize, CleanupStore, DeleteVersionOutcome, FinalizeMultipartOutcome,
    FinalizeVersionOutcome, MultipartFinishSnapshot, MultipartStore,
};
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{
    BackendRegistry, InMemoryBackend, LocalFsBackend, StorageBackend,
};
use file_storage::infra::content::hash_mode::HashMode;
use file_storage::infra::content::{hash, mime};
use file_storage::infra::signed_url::Issuer;
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::VersionStatus;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sea_orm_migration::MigratorTrait;
use testcontainers::{ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use time::OffsetDateTime;
use tokio::sync::{Mutex, Notify, OnceCell};
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::secure::{SecureEntityExt, SecureUpdateExt};
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

/// Serializes tests sharing one PostgreSQL database: `f2_*`/`f10_*` rely on real lease/session
/// expiry.
static PG_TEST_LOCK: Mutex<()> = Mutex::const_new(());

struct PgFixture {
    dsn: String,
    _container: testcontainers::ContainerAsync<Postgres>,
}

static PG: OnceCell<Option<Arc<PgFixture>>> = OnceCell::const_new();
static MIGRATIONS_DONE: OnceCell<()> = OnceCell::const_new();

/// When set (`1`/`true`), a missing Docker is a hard panic instead of a per-test skip (CI sets it).
fn require_docker() -> bool {
    std::env::var("FS_PG_REQUIRE_DOCKER").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

/// Starts (once per process) a `testcontainers` PostgreSQL; `None` (skip) if Docker is unreachable.
async fn shared_pg() -> Option<Arc<PgFixture>> {
    PG.get_or_init(|| async {
        // Image and tag come from `libs/test-containers`, the single place database images are
        // pinned.
        let request = test_containers::postgres()
            .with_env_var("POSTGRES_PASSWORD", "pass")
            .with_env_var("POSTGRES_USER", "user")
            .with_env_var("POSTGRES_DB", "app");
        match request.start().await {
            Ok(container) => match container.get_host_port_ipv4(5432).await {
                Ok(port) => Some(Arc::new(PgFixture {
                    dsn: format!("postgres://user:pass@127.0.0.1:{port}/app"),
                    _container: container,
                })),
                Err(e) => {
                    assert!(
                        !require_docker(),
                        "Docker required (FS_PG_REQUIRE_DOCKER=1) but the PostgreSQL \
                         container's port could not be resolved: {e}"
                    );
                    eprintln!(
                        "skipping PostgreSQL concurrency tests: container started but its \
                         port could not be resolved ({e}). Is Docker healthy?"
                    );
                    None
                }
            },
            Err(e) => {
                assert!(
                    !require_docker(),
                    "Docker required (FS_PG_REQUIRE_DOCKER=1) but the PostgreSQL container \
                     failed to start: {e}"
                );
                eprintln!(
                    "skipping PostgreSQL concurrency tests: could not start a PostgreSQL \
                     container via testcontainers ({e}). Install/start Docker to run these \
                     for real -- see this file's module docs."
                );
                None
            }
        }
    })
    .await
    .clone()
}

async fn pg_db() -> Option<Arc<DBProvider<DbError>>> {
    let fixture = shared_pg().await?;
    let opts = ConnectOpts {
        max_conns: Some(10),
        min_conns: Some(2),
        ..Default::default()
    };
    let db = connect_db(&fixture.dsn, opts)
        .await
        .expect("connect to the testcontainers PostgreSQL");
    MIGRATIONS_DONE
        .get_or_init(|| async {
            run_migrations_for_testing(&db, Migrator::migrations())
                .await
                .expect("run file-storage migrations against PostgreSQL");
        })
        .await;
    Some(Arc::new(DBProvider::new(db)))
}

macro_rules! pg_db_or_skip {
    () => {{
        let _guard = PG_TEST_LOCK.lock().await;
        match pg_db().await {
            Some(db) => (db, _guard),
            None => return,
        }
    }};
}

/// `Display`-based summary of an outcome for `eprintln!` (avoids `clippy::use_debug`).
fn describe_result<T>(r: &Result<T, DomainError>) -> String {
    match r {
        Ok(_) => "Ok".to_owned(),
        Err(e) => format!("Err({e})"),
    }
}

fn describe_sweep(r: &file_storage::domain::cleanup::SweepResult) -> String {
    format!(
        "pending_deleted={} files_deleted={} multipart_aborted={} retention_deleted={} idempotency_deleted={}",
        r.abandoned_pending_deleted,
        r.abandoned_files_deleted,
        r.expired_multipart_aborted,
        r.retention_expired_deleted,
        r.idempotency_keys_deleted,
    )
}

fn make_ctx(tenant_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_tenant_id(tenant_id)
        .build()
        .expect("valid SecurityContext")
}

fn new_file() -> file_storage_sdk::NewFile {
    file_storage_sdk::NewFile {
        owner_kind: file_storage_sdk::OwnerKind::User,
        owner_id: Uuid::now_v7(),
        name: "pg-audit.bin".to_owned(),
        gts_file_type: toolkit_gts::gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~")
            .to_owned(),
        mime_type: "application/octet-stream".to_owned(),
        custom_metadata: vec![],
    }
}

fn service_config() -> ServiceConfig {
    ServiceConfig {
        default_url_ttl_secs: 3600,
        sidecar_base_url: "http://sidecar.test".to_owned(),
        default_page_size: 50,
        max_page_size: 1000,
        idempotency_ttl_secs: 86400,
    }
}

/// Direct byte-path test double: writes content through `put_stream`.
struct TestDataPlane {
    svc: Arc<FileService>,
    store: Store,
    backends: BackendRegistry,
}

impl TestDataPlane {
    fn new(svc: Arc<FileService>, store: Store, backends: BackendRegistry) -> Self {
        Self {
            svc,
            store,
            backends,
        }
    }

    async fn put_content(
        &self,
        ctx: &SecurityContext,
        file_id: Uuid,
        version_id: Uuid,
        declared_mime: &str,
        bytes: Bytes,
    ) -> Result<(), DomainError> {
        mime::validate(declared_mime, &bytes)?;
        self.svc.authorize_write(ctx, file_id).await?;
        let version = self
            .store
            .get_version(file_id, version_id)
            .await?
            .ok_or_else(|| DomainError::version_not_found(file_id, version_id))?;
        let backend = self.backends.get(&version.backend_id)?;
        let len = bytes.len() as u64;
        let digest = hash::sha256(&bytes);
        let stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
            Box::pin(futures::stream::once(async move { Ok(bytes) }));
        backend
            .put_stream(&version.backend_path, stream, Some(len))
            .await?;
        self.svc
            .finalize_upload(
                ctx,
                file_id,
                version_id,
                i64::try_from(len).unwrap_or(i64::MAX),
                digest,
            )
            .await
    }
}

fn make_file_service(store: Store, backends: BackendRegistry) -> Arc<FileService> {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    Arc::new(FileService::new(
        store,
        backends,
        issuer,
        authorizer,
        service_config(),
        None,
        None,
    ))
}

fn make_multipart_service(
    store: Arc<dyn MultipartStore>,
    backends: BackendRegistry,
    complete_lease_secs: i64,
) -> Arc<MultipartService> {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    Arc::new(
        MultipartService::new(
            store,
            backends,
            authorizer,
            None,
            issuer,
            "http://sidecar.test".to_owned(),
            3600,
        )
        .with_complete_lease_secs(complete_lease_secs),
    )
}

fn make_engine(store: Store, backends: BackendRegistry, orphan_grace_secs: u64) -> CleanupEngine {
    let cleanup_store: Arc<dyn CleanupStore> = Arc::new(store);
    CleanupEngine::new(cleanup_store, backends, CleanupConfig { orphan_grace_secs })
}

/// Drive every part in `plan` through the backend + `MultipartStore` with zero filler bytes.
async fn simulate_all_parts(
    multipart_store: &Arc<dyn MultipartStore>,
    backend: &Arc<dyn StorageBackend>,
    plan: &file_storage::domain::multipart::MultipartPlan,
    file_id: Uuid,
) {
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .expect("get_multipart_upload")
        .expect("session must exist");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    for part in &plan.parts {
        let data = Bytes::from(vec![
            0u8;
            usize::try_from(part.size).expect("part size fits")
        ]);
        let len = data.len() as u64;
        let stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
            Box::pin(futures::stream::once(async move { Ok(data) }));
        let (backend_etag, part_hash) = backend
            .upload_part_stream(
                &backend_path,
                &session.backend_upload_handle,
                part.part_number,
                part.offset,
                stream,
                len,
            )
            .await
            .expect("backend upload_part_stream");
        let size = i64::try_from(part.size).expect("part size fits in i64");
        let part_number_i32 = i32::try_from(part.part_number).expect("part_number fits in i32");
        multipart_store
            .upsert_multipart_part(
                plan.upload_id,
                part_number_i32,
                &backend_etag,
                part_hash,
                size,
                OffsetDateTime::now_utc(),
            )
            .await
            .expect("upsert_multipart_part");
    }
}

/// Capability-reject half: `LocalFsBackend` is not `multipart_native`, so initiate is rejected
/// before
/// any pending version exists, leaving a version-less `files` row. The raw sequence is called
/// directly
/// (no compensation), so the sweep's versionless-files phase must reclaim it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f1_capability_reject_orphan_reclaimed_by_versionless_sweep() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let tmp = tempfile::tempdir().expect("tempdir");
    let backend: Arc<dyn StorageBackend> = Arc::new(LocalFsBackend::new("fs", tmp.keep()));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "fs").expect("registry");
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());
    let msvc = make_multipart_service(multipart_store, backends.clone(), 120);
    let engine = make_engine(store.clone(), backends, 0); // grace=0: everything eligible immediately

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);
    let file_id = svc
        .create_file_bare(&ctx, new_file())
        .await
        .expect("create_file_bare commits the bare file row");

    let err = msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            20,
            Some(10),
            false,
        )
        .await
        .expect_err("local-fs backend does not advertise multipart_native");
    assert!(matches!(err, DomainError::MultipartNotSupported { .. }));

    let result = engine.run_sweep().await;
    eprintln!(
        "f1_capability_reject_orphan_reclaimed_by_versionless_sweep: sweep result = {}",
        describe_sweep(&result)
    );
    assert_eq!(
        result.abandoned_files_deleted, 1,
        "the versionless-files phase must reclaim the bare file in this same pass -- no pending \
         version was ever created, so step 1's abandoned-pending phase cannot reach it and this \
         is the phase that has to"
    );

    let file_after = svc.get_file(&ctx, file_id).await;
    assert!(
        matches!(file_after, Err(DomainError::FileNotFound { .. })),
        "the orphaned bare file must be gone after a real sweep pass, even with no compensation \
         invoked -- got: {file_after:?}"
    );
}

/// Decorator whose `initiate_multipart` always fails while `capabilities()` still advertises
/// `multipart_native`.
struct FailingInitiateBackend {
    inner: Arc<dyn StorageBackend>,
}

#[async_trait]
impl StorageBackend for FailingInitiateBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn capabilities(&self) -> file_storage::infra::backend::BackendCapabilities {
        self.inner.capabilities()
    }
    async fn put_stream(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        self.inner.put_stream(path, stream, max_size).await
    }
    async fn publish_exclusive(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<file_storage::infra::backend::PublishOutcome, DomainError> {
        self.inner.publish_exclusive(path, stream, max_size).await
    }
    async fn get_stream(
        &self,
        path: &str,
        expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        self.inner.get_stream(path, expected_len).await
    }
    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        self.inner.read_prefix(path, max_bytes).await
    }
    async fn get_range_stream(
        &self,
        path: &str,
        range: file_storage_sdk::ByteRange,
        expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        self.inner.get_range_stream(path, range, expected_len).await
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
    async fn initiate_multipart(&self, _path: &str) -> Result<String, DomainError> {
        Err(DomainError::database(
            "simulated backend-initiation failure (e.g. an S3 CreateMultipartUpload error)",
        ))
    }
    async fn upload_part_stream(
        &self,
        path: &str,
        upload_handle: &str,
        part_number: u32,
        part_offset: u64,
        stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>>,
        len: u64,
    ) -> Result<(String, Vec<u8>), DomainError> {
        self.inner
            .upload_part_stream(path, upload_handle, part_number, part_offset, stream, len)
            .await
    }
    async fn complete_multipart(
        &self,
        path: &str,
        upload_handle: &str,
        parts: &[file_storage::infra::backend::MultipartCompletionPart],
    ) -> Result<(file_storage::infra::content::hash_mode::Manifest, [u8; 32]), DomainError> {
        self.inner
            .complete_multipart(path, upload_handle, parts)
            .await
    }
    async fn abort_multipart(&self, path: &str, upload_handle: &str) -> Result<(), DomainError> {
        self.inner.abort_multipart(path, upload_handle).await
    }
    async fn list_paths(&self) -> Result<Vec<String>, DomainError> {
        self.inner.list_paths().await
    }
}

/// Backend-initiation-failure half: same version-less orphan shape, reclaimed the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f1_backend_initiation_failure_orphan_reclaimed_by_versionless_sweep() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let inner: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backend: Arc<dyn StorageBackend> = Arc::new(FailingInitiateBackend { inner });
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());
    let msvc = make_multipart_service(multipart_store, backends.clone(), 120);
    let engine = make_engine(store.clone(), backends, 0);

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);
    let file_id = svc
        .create_file_bare(&ctx, new_file())
        .await
        .expect("create_file_bare");

    let err = msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            20,
            // `None` part size: a tiny literal would fail the part-size range check before reaching
            // the failing backend.
            None,
            false,
        )
        .await
        .expect_err("the backend's initiate_multipart is rigged to fail");
    eprintln!("f1_backend_initiation_failure: initiate error = {err}");

    let result = engine.run_sweep().await;
    eprintln!(
        "f1_backend_initiation_failure_orphan_reclaimed_by_versionless_sweep: sweep result = {}",
        describe_sweep(&result)
    );
    assert_eq!(
        result.abandoned_files_deleted, 1,
        "the versionless-files phase must reclaim this half's orphan too -- the row is identical \
         to the capability-reject half's, whatever made initiate fail"
    );

    let file_after = svc.get_file(&ctx, file_id).await;
    assert!(
        matches!(file_after, Err(DomainError::FileNotFound { .. })),
        "FS-01/F1: the orphaned bare file must be reclaimed by a real sweep pass, got: \
         {file_after:?}"
    );
}

/// Which of the two concurrent completers a `GatedMultipartStore` handle plays.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    A,
    B,
}

/// `MultipartStore` decorator that forces the `f2_*` interleaving with `Notify` gates, not sleeps:
/// - role B's first `get_version` (the takeover fast-path check) notifies `b_checked_pending`;
/// - role A's `finalize_multipart_version` waits on it, then notifies `a_finalized` after its
///   commit;
/// - role B's `finalize_multipart_version` waits on `a_finalized`, so A deterministically wins the
///   CAS.
///
/// `Notify::notify_one` buffers a permit, so there is no lost-wakeup risk.
struct GatedMultipartStore {
    inner: Arc<dyn MultipartStore>,
    role: Role,
    b_checked_pending: Arc<Notify>,
    /// Notified by role A right after its finalize commit returns; role B waits on it before
    /// starting.
    a_finalized: Arc<Notify>,
    b_first_get_version_seen: Arc<AtomicBool>,
}

#[async_trait]
impl MultipartStore for GatedMultipartStore {
    async fn require_file(
        &self,
        scope: &AccessScope,
        file_id: Uuid,
    ) -> Result<file_storage_sdk::File, DomainError> {
        self.inner.require_file(scope, file_id).await
    }

    async fn get_policy(
        &self,
        scope: &AccessScope,
        tenant_id: Uuid,
        policy_scope: &PolicyScope,
        scope_owner_id: Option<Uuid>,
    ) -> Result<Option<StoredPolicy>, DomainError> {
        self.inner
            .get_policy(scope, tenant_id, policy_scope, scope_owner_id)
            .await
    }

    async fn insert_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        mime_type: &str,
        backend_id: &str,
        backend_path: &str,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.inner
            .insert_pending_version(
                file_id,
                version_id,
                mime_type,
                backend_id,
                backend_path,
                now,
            )
            .await
    }

    async fn create_multipart_upload(
        &self,
        upload_id: Uuid,
        file_id: Uuid,
        version_id: Uuid,
        backend_upload_handle: &str,
        backend_id: Option<&str>,
        backend_path: Option<&str>,
        declared_mime: &str,
        declared_size: u64,
        part_size: u64,
        auto_bind: bool,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.inner
            .create_multipart_upload(
                upload_id,
                file_id,
                version_id,
                backend_upload_handle,
                backend_id,
                backend_path,
                declared_mime,
                declared_size,
                part_size,
                auto_bind,
                expires_at,
                now,
            )
            .await
    }

    async fn get_multipart_upload(
        &self,
        upload_id: Uuid,
    ) -> Result<Option<file_storage::domain::multipart::MultipartUploadSession>, DomainError> {
        self.inner.get_multipart_upload(upload_id).await
    }

    async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<file_storage_sdk::FileVersion>, DomainError> {
        let result = self.inner.get_version(file_id, version_id).await;
        if self.role == Role::B && !self.b_first_get_version_seen.swap(true, Ordering::SeqCst) {
            // Releases A's gated finalize only after this pre-finalize read has completed.
            self.b_checked_pending.notify_one();
        }
        result
    }

    async fn get_version_manifest(&self, version_id: Uuid) -> Result<Option<String>, DomainError> {
        self.inner.get_version_manifest(version_id).await
    }

    async fn upsert_multipart_part(
        &self,
        upload_id: Uuid,
        part_number: i32,
        backend_etag: &str,
        part_hash: Vec<u8>,
        size: i64,
        now: OffsetDateTime,
    ) -> Result<(), DomainError> {
        self.inner
            .upsert_multipart_part(upload_id, part_number, backend_etag, part_hash, size, now)
            .await
    }

    async fn list_multipart_parts(
        &self,
        upload_id: Uuid,
    ) -> Result<Vec<MultipartPart>, DomainError> {
        self.inner.list_multipart_parts(upload_id).await
    }

    async fn finalize_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
        hash_mode: file_storage::infra::content::hash_mode::HashMode,
        part_count: Option<i32>,
        manifest: Option<String>,
        validated_mime: Option<String>,
        audit: file_storage::domain::audit::AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
    ) -> Result<FinalizeVersionOutcome, DomainError> {
        // Ungated passthrough, required by the trait.
        self.inner
            .finalize_version(
                file_id,
                version_id,
                size,
                hash_value,
                hash_mode,
                part_count,
                manifest,
                validated_mime,
                audit,
                auto_bind,
            )
            .await
    }

    async fn finalize_multipart_version(
        &self,
        file_id: Uuid,
        manifest: Option<String>,
        validated_mime: Option<String>,
        finalize_audit: file_storage::domain::audit::AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
        finish: MultipartFinishSnapshot,
    ) -> Result<FinalizeMultipartOutcome, DomainError> {
        if self.role == Role::A {
            self.b_checked_pending.notified().await;
        } else {
            // B's redundant finalize must not start before A's finishes, else the scheduler decides
            // who wins the CAS.
            self.a_finalized.notified().await;
        }
        let result = self
            .inner
            .finalize_multipart_version(
                file_id,
                manifest,
                validated_mime,
                finalize_audit,
                auto_bind,
                finish,
            )
            .await;
        if self.role == Role::A {
            self.a_finalized.notify_one();
        }
        result
    }

    async fn complete_multipart_upload(
        &self,
        upload_id: Uuid,
        lease_owner: &str,
        result_json: &str,
        audit: file_storage::domain::audit::AuditEntry,
    ) -> Result<bool, DomainError> {
        self.inner
            .complete_multipart_upload(upload_id, lease_owner, result_json, audit)
            .await
    }

    async fn acquire_multipart_complete_lease(
        &self,
        upload_id: Uuid,
        owner: &str,
        lease_until: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<bool, DomainError> {
        self.inner
            .acquire_multipart_complete_lease(upload_id, owner, lease_until, now)
            .await
    }

    async fn release_multipart_complete_lease(
        &self,
        upload_id: Uuid,
        owner: &str,
    ) -> Result<bool, DomainError> {
        self.inner
            .release_multipart_complete_lease(upload_id, owner)
            .await
    }

    async fn abort_multipart_upload(
        &self,
        upload_id: Uuid,
        audit: file_storage::domain::audit::AuditEntry,
    ) -> Result<bool, DomainError> {
        self.inner.abort_multipart_upload(upload_id, audit).await
    }

    async fn delete_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: file_storage::domain::audit::AuditEntry,
    ) -> Result<bool, DomainError> {
        self.inner.delete_version(file_id, version_id, audit).await
    }
}

/// Two completers race one session: A's lease really expires (1s), B takes it over and starts a
/// redundant reassembly, A's gated finalize wins the CAS, and B's lost finalize must converge via
/// `replay_completed` + `finish_session` instead of erroring and stranding the session. Both
/// callers
/// must get `Ok(Completed(..))`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f2_stale_completer_converges_instead_of_stranding_after_owner_fencing_fix() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let real_multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);
    let file_id = svc
        .create_file_bare(&ctx, new_file())
        .await
        .expect("create_file_bare");
    let plan = {
        let msvc_setup =
            make_multipart_service(Arc::clone(&real_multipart_store), backends.clone(), 120);
        msvc_setup
            .initiate_multipart_upload(
                &ctx,
                file_id,
                "application/octet-stream",
                10 * 1024 * 1024,
                Some(5 * 1024 * 1024),
                true, // auto_bind
            )
            .await
            .expect("initiate_multipart_upload (in-memory backend supports multipart_native)")
    };
    simulate_all_parts(&real_multipart_store, &backend, &plan, file_id).await;

    let b_checked_pending = Arc::new(Notify::new());
    let a_finalized = Arc::new(Notify::new());
    let b_first_get_version_seen = Arc::new(AtomicBool::new(false));

    let store_a: Arc<dyn MultipartStore> = Arc::new(GatedMultipartStore {
        inner: Arc::clone(&real_multipart_store),
        role: Role::A,
        b_checked_pending: Arc::clone(&b_checked_pending),
        a_finalized: Arc::clone(&a_finalized),
        b_first_get_version_seen: Arc::clone(&b_first_get_version_seen),
    });
    let store_b: Arc<dyn MultipartStore> = Arc::new(GatedMultipartStore {
        inner: Arc::clone(&real_multipart_store),
        role: Role::B,
        b_checked_pending: Arc::clone(&b_checked_pending),
        a_finalized: Arc::clone(&a_finalized),
        b_first_get_version_seen: Arc::clone(&b_first_get_version_seen),
    });

    // Shortest lease the code allows (`.max(1)`), so a just-over-a-second wait expires it.
    let msvc_a = make_multipart_service(store_a, backends.clone(), 1);
    let msvc_b = make_multipart_service(store_b, backends.clone(), 120);

    let ctx_a = ctx.clone();
    let upload_id = plan.upload_id;
    let task_a = tokio::spawn(async move {
        msvc_a
            .complete_multipart_upload(&ctx_a, file_id, upload_id, None)
            .await
    });

    // Real wait: the lease CAS compares against `now_utc()`, so `tokio::time::pause` cannot fake
    // it.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let ctx_b = ctx.clone();
    let task_b = tokio::spawn(async move {
        msvc_b
            .complete_multipart_upload(&ctx_b, file_id, upload_id, None)
            .await
    });

    let (result_a, result_b) = tokio::join!(task_a, task_b);
    let result_a = result_a.expect("task A join");
    let result_b = result_b.expect("task B join");

    eprintln!(
        "f2_stale_completer_converges: A={} B={}",
        describe_result(&result_a),
        describe_result(&result_b),
    );
    if let Err(e) = &result_a {
        eprintln!("f2: A's error = {e}");
    }
    if let Err(e) = &result_b {
        eprintln!("f2: B's error = {e}");
    }

    assert!(
        result_a.is_ok() && result_b.is_ok(),
        "FS-02/F2 fix: both completers must now converge to Ok(Completed(...)) instead of \
         stranding the session -- A={result_a:?} B={result_b:?}"
    );
    let completed_a = result_a.expect("checked above").unwrap_completed();
    let completed_b = result_b.expect("checked above").unwrap_completed();
    assert_eq!(
        completed_a.version_id, completed_b.version_id,
        "both completers must agree on the same finalized version"
    );
    assert_eq!(
        completed_a.bind_state,
        BindState::Bound,
        "the auto-bind CAS must have won for the winner's caller"
    );

    let version = store
        .get_version(file_id, plan.version_id)
        .await
        .expect("get_version")
        .expect("version row must still exist");
    assert_eq!(
        version.status,
        VersionStatus::Available,
        "the version must be correctly finalized exactly once"
    );
    let file = svc.get_file(&ctx, file_id).await.expect("get_file");
    assert_eq!(
        file.content_id,
        Some(plan.version_id),
        "the auto-bind CAS won for real -- the file's content_id must point at this version"
    );
    let session = real_multipart_store
        .get_multipart_upload(upload_id)
        .await
        .expect("get_multipart_upload")
        .expect("session row must still exist");
    assert_eq!(
        session.state,
        file_storage::domain::multipart::MultipartUploadState::Completed,
        "FS-02/F2 fix: the session must reach Completed, not be stranded at in_progress"
    );
    assert!(
        session.lease_until.is_none(),
        "a completed session has no live lease -- got {}",
        session
            .lease_until
            .as_ref()
            .map_or_else(|| "none".to_owned(), ToString::to_string)
    );

    // A third retry must replay the persisted result: the session is left in a replayable terminal
    // state.
    let msvc_c = make_multipart_service(Arc::clone(&real_multipart_store), backends.clone(), 120);
    let result_c = msvc_c
        .complete_multipart_upload(&ctx, file_id, upload_id, None)
        .await;
    eprintln!("f2: third retry result = {}", describe_result(&result_c));
    let completed_c = result_c
        .expect(
            "FS-02/F2 fix: a third retry against an already-Completed session must replay, \
                 not error",
        )
        .unwrap_completed();
    assert_eq!(
        completed_c.version_id, completed_a.version_id,
        "the replayed result must match the original completion"
    );
}

/// A stale completer's finalize must not commit after cleanup aborted its session: the finalize CAS
/// locks the session row and requires it to still be `completing`.
#[tokio::test]
async fn f11_finalize_multipart_version_rejects_after_cleanup_aborts_completing_session() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);
    let file_id = svc
        .create_file_bare(&ctx, new_file())
        .await
        .expect("create_file_bare");

    let msvc = make_multipart_service(Arc::clone(&multipart_store), backends.clone(), 120);
    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            10 * 1024 * 1024,
            Some(5 * 1024 * 1024),
            false, // auto_bind -- not exercised here, keep the scenario minimal
        )
        .await
        .expect("initiate_multipart_upload (in-memory backend supports multipart_native)");
    simulate_all_parts(&multipart_store, &backend, &plan, file_id).await;

    let now = OffsetDateTime::now_utc();
    // Already-expired `lease_until`: yields the `completing`-with-lapsed-lease shape without a real
    // sleep.
    let acquired = store
        .acquire_multipart_complete_lease(
            plan.upload_id,
            "stale-completer",
            now - time::Duration::seconds(1),
            now,
        )
        .await
        .expect("acquire_multipart_complete_lease");
    assert!(
        acquired,
        "a fresh in_progress session must accept the lease"
    );

    // Also backdate `expires_at`: the sweep selects a `completing` session only once both it and
    // `lease_until` have passed.
    backdate_multipart_expires_at(&db, plan.upload_id, now - time::Duration::seconds(1)).await;

    // Cleanup's abort: the `in_progress` CAS misses, so `abort_expired_completing` matches on the
    // lapsed lease.
    let abort_audit = AuditEntry::success(
        tenant_id,
        "system",
        Uuid::nil(),
        Some(file_id),
        AuditOperation::MultipartAbort,
        serde_json::json!({"reason": "expired_multipart_session_cleanup"}),
    );
    let aborted = store
        .abort_multipart_upload(plan.upload_id, abort_audit)
        .await
        .expect("abort_multipart_upload");
    assert!(
        aborted,
        "cleanup's abort must win the CAS while the lease is expired"
    );
    let session_before = store
        .get_multipart_upload(plan.upload_id)
        .await
        .expect("get_multipart_upload")
        .expect("session row must still exist");
    assert_eq!(session_before.state, MultipartUploadState::Aborted);

    // The stale completer's finalize arriving after cleanup won.
    let finalize_audit = AuditEntry::success(
        tenant_id,
        "user",
        ctx.subject_id(),
        Some(file_id),
        AuditOperation::FinalizeVersion,
        serde_json::json!({"version_id": plan.version_id, "upload_id": plan.upload_id}),
    );
    let session_audit = AuditEntry::success(
        tenant_id,
        "user",
        ctx.subject_id(),
        Some(file_id),
        AuditOperation::MultipartComplete,
        serde_json::json!({"upload_id": plan.upload_id}),
    );
    let err = store
        .finalize_multipart_version(
            file_id,
            None,
            Some("application/octet-stream".to_owned()),
            finalize_audit,
            None,
            MultipartFinishSnapshot {
                upload_id: plan.upload_id,
                version_id: plan.version_id,
                size: 10 * 1024 * 1024,
                content_hash: vec![0u8; 32],
                hash_mode: HashMode::WholeSha256,
                part_count: None,
                session_audit,
            },
        )
        .await
        .expect_err("finalize must be rejected once cleanup has aborted the session");
    assert!(
        matches!(err, DomainError::Conflict { .. }),
        "expected Conflict once the session is aborted, got {err:?}"
    );

    let version = store
        .get_version(file_id, plan.version_id)
        .await
        .expect("get_version")
        .expect("version row must still exist");
    assert_eq!(
        version.status,
        VersionStatus::Pending,
        "the version must stay pending -- the finalize must have rolled back entirely"
    );

    let file = store
        .require_file(&AccessScope::allow_all(), file_id)
        .await
        .expect("require_file");
    assert!(
        file.content_id.is_none(),
        "content_id must remain unbound -- the rejected finalize must not have auto-bound"
    );

    let session_after = store
        .get_multipart_upload(plan.upload_id)
        .await
        .expect("get_multipart_upload")
        .expect("session row must still exist");
    assert_eq!(
        session_after.state,
        MultipartUploadState::Aborted,
        "the session must remain aborted -- the rejected finalize must not have resurrected it"
    );

    // Delete the file (cascades to version and session) so sibling sweep-based tests sharing this
    // DB
    // don't count the leftover pending version.
    store
        .delete_file_collecting_versions(
            &AccessScope::allow_all(),
            file_id,
            None,
            AuditEntry::success(
                tenant_id,
                "system",
                Uuid::nil(),
                Some(file_id),
                AuditOperation::DeleteFile,
                serde_json::json!({"reason": "test cleanup"}),
            ),
            None,
        )
        .await
        .expect("test cleanup: delete_file_collecting_versions");
}

/// Flip `multipart_uploads.expires_at` directly: no public API backdates a session.
async fn backdate_multipart_expires_at(
    db: &Arc<DBProvider<DbError>>,
    upload_id: Uuid,
    expires_at: OffsetDateTime,
) {
    use file_storage::infra::storage::entity::multipart_upload::{
        Column as UploadColumn, Entity as UploadEntity,
    };
    let conn = db.conn().expect("conn");
    UploadEntity::update_many()
        .col_expr(UploadColumn::ExpiresAt, Expr::value(expires_at))
        .filter(UploadColumn::UploadId.eq(upload_id))
        .secure()
        .scope_with(&AccessScope::allow_all())
        .exec(&conn)
        .await
        .expect("backdate expires_at");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f9_autobind_no_if_match_no_longer_clobbers_prior_rebind() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());
    let msvc = make_multipart_service(multipart_store.clone(), backends.clone(), 120);
    let dp = TestDataPlane::new(Arc::clone(&svc), store.clone(), backends.clone());

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .expect("create_file");
    dp.put_content(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"first content"),
    )
    .await
    .expect("put_content");
    svc.bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind first content");

    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            ticket.file_id,
            "application/octet-stream",
            5,
            None,
            true,
        )
        .await
        .expect("initiate_multipart_upload with auto_bind");
    simulate_all_parts(&multipart_store, &backend, &plan, ticket.file_id).await;

    // Someone legitimately rebinds the file while the multipart upload is in flight.
    let rebind_ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .expect("create_file (rebind source)");
    let _ = rebind_ticket; // (kept for clarity of narration; unused directly)
    let second_ticket_version = svc
        .presign_version(&ctx, ticket.file_id)
        .await
        .expect("presign_version for the legitimate rebind");
    dp.put_content(
        &ctx,
        ticket.file_id,
        second_ticket_version.version_id,
        "text/plain",
        Bytes::from_static(b"legitimately rebound content"),
    )
    .await
    .expect("put_content (legitimate rebind)");
    svc.bind(
        &ctx,
        ticket.file_id,
        second_ticket_version.version_id,
        Some("*"),
    )
    .await
    .expect("legitimate rebind, unconditional CAS wildcard");

    let completed = msvc
        .complete_multipart_upload(&ctx, ticket.file_id, plan.upload_id, None)
        .await
        .expect("complete_multipart_upload (no If-Match) must still succeed -- only the bind is conditional")
        .unwrap_completed();

    // Without `If-Match` the auto-bind CAS requires `content_id IS NULL`: it loses, leaving the
    // rebind intact.
    assert_eq!(
        completed.bind_state,
        BindState::Conflict,
        "FS-04/F9 fix: the auto-bind CAS must lose (content_id IS NULL no longer matches) \
         instead of clobbering the legitimate rebind"
    );
    let file_after = svc.get_file(&ctx, ticket.file_id).await.expect("get_file");
    assert_eq!(
        file_after.content_id,
        Some(second_ticket_version.version_id),
        "FS-04/F9 fix: the legitimate rebind must survive -- content_id must still point at it, \
         not at the multipart upload's version"
    );
}

/// Negative control: with the `If-Match` observed at initiate, the stale ETag is rejected up front
/// by
/// the precondition check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_control_f9_autobind_with_correct_if_match_rejects_stale_rebind() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());
    let msvc = make_multipart_service(multipart_store.clone(), backends.clone(), 120);
    let dp = TestDataPlane::new(Arc::clone(&svc), store.clone(), backends.clone());

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .expect("create_file");
    dp.put_content(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"first content"),
    )
    .await
    .expect("put_content");
    let bound_file = svc
        .bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind first content");
    let etag_at_initiate_time = file_storage::domain::etag::etag_for(&bound_file);

    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            ticket.file_id,
            "application/octet-stream",
            5,
            None,
            true,
        )
        .await
        .expect("initiate_multipart_upload with auto_bind");
    simulate_all_parts(&multipart_store, &backend, &plan, ticket.file_id).await;

    let second_ticket_version = svc
        .presign_version(&ctx, ticket.file_id)
        .await
        .expect("presign_version for the legitimate rebind");
    dp.put_content(
        &ctx,
        ticket.file_id,
        second_ticket_version.version_id,
        "text/plain",
        Bytes::from_static(b"legitimately rebound content"),
    )
    .await
    .expect("put_content (legitimate rebind)");
    svc.bind(
        &ctx,
        ticket.file_id,
        second_ticket_version.version_id,
        Some("*"),
    )
    .await
    .expect("legitimate rebind");

    let err = msvc
        .complete_multipart_upload(
            &ctx,
            ticket.file_id,
            plan.upload_id,
            etag_at_initiate_time.as_deref(),
        )
        .await
        .expect_err("a stale If-Match must be rejected, not silently overwritten");
    assert!(
        matches!(err, DomainError::PreconditionFailed { .. }),
        "negative control: supplying the correct (now-stale) If-Match must turn F9's silent \
         clobber into a clean PreconditionFailed, got: {err}"
    );

    let file_after = svc.get_file(&ctx, ticket.file_id).await.expect("get_file");
    assert_eq!(
        file_after.content_id,
        Some(second_ticket_version.version_id),
        "the legitimate rebind must survive when If-Match correctly protects it"
    );
}

async fn backdate_version_created_at(
    db: &Arc<DBProvider<DbError>>,
    version_id: Uuid,
    created_at: OffsetDateTime,
) {
    use file_storage::infra::storage::entity::file_version::{
        Column as FileVersionColumn, Entity as FileVersionEntity,
    };
    let conn = db.conn().expect("conn");
    FileVersionEntity::update_many()
        .col_expr(FileVersionColumn::CreatedAt, Expr::value(created_at))
        .filter(FileVersionColumn::VersionId.eq(version_id))
        .secure()
        .scope_with(&AccessScope::allow_all())
        .exec(&conn)
        .await
        .expect("backdate version created_at");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn f10_expired_session_orphan_reclaimed_by_step2_in_same_sweep_pass() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = make_file_service(store.clone(), backends.clone());
    let msvc = make_multipart_service(multipart_store.clone(), backends.clone(), 120);
    // 1-hour grace so only the deliberately backdated version is sweep-eligible.
    let engine = make_engine(store.clone(), backends, 3600);

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);
    let file_id = svc
        .create_file_bare(&ctx, new_file())
        .await
        .expect("create_file_bare");
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 1024, None, false)
        .await
        .expect("initiate_multipart_upload");

    let now = OffsetDateTime::now_utc();
    backdate_version_created_at(&db, plan.version_id, now - time::Duration::hours(2)).await;
    backdate_multipart_expires_at(&db, plan.upload_id, now - time::Duration::seconds(10)).await;

    let result = engine.run_sweep().await;
    eprintln!("f10: sweep result = {}", describe_sweep(&result));
    assert_eq!(
        result.abandoned_pending_deleted, 1,
        "the abandoned pending version must be reclaimed in this same pass"
    );
    assert_eq!(
        result.expired_multipart_aborted, 1,
        "the expired session must also be aborted in this same pass"
    );
    assert_eq!(
        result.abandoned_files_deleted, 1,
        "FS-05/F10 fix: the parent file must now ALSO be reclaimed in this same pass -- step 2's \
         own cleanup_expired_session_version runs its own orphan-file check after the session \
         is already aborted, so has_active_for_file no longer blocks it"
    );

    let version_after = store
        .get_version(file_id, plan.version_id)
        .await
        .expect("get_version");
    assert!(
        version_after.is_none(),
        "the pending version row must be gone -- step 1 deletes it regardless of the \
         now-stale has_active_for_file snapshot"
    );
    let file_after = svc.get_file(&ctx, file_id).await;
    assert!(
        matches!(file_after, Err(DomainError::FileNotFound { .. })),
        "FS-05/F10 fix: the file must be reclaimed within this same sweep pass, not left as a \
         version-less orphan -- got: {file_after:?}"
    );
}

/// Every non-`NULL` `files.content_id` must point at an existing `Available` version; returns the
/// violations (empty is healthy).
async fn find_content_id_violations(db: &Arc<DBProvider<DbError>>, file_id: Uuid) -> Vec<String> {
    use file_storage::infra::storage::entity::file::{Column as FileColumn, Entity as FileEntity};
    use file_storage::infra::storage::entity::file_version::{
        Column as FileVersionColumn, Entity as FileVersionEntity,
    };
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let mut violations = Vec::new();
    let Some(file) = FileEntity::find()
        .filter(FileColumn::FileId.eq(file_id))
        .secure()
        .scope_with(&scope)
        .one(&conn)
        .await
        .expect("query files")
    else {
        return violations;
    };
    if let Some(content_id) = file.content_id {
        let version = FileVersionEntity::find()
            .filter(FileVersionColumn::VersionId.eq(content_id))
            .secure()
            .scope_with(&scope)
            .one(&conn)
            .await
            .expect("query file_versions");
        match version {
            None => violations.push(format!(
                "file {file_id} content_id={content_id} points at a version row that does not exist"
            )),
            Some(v) if v.status != "available" => violations.push(format!(
                "file {file_id} content_id={content_id} points at a version whose status is \
                 {}, not available",
                v.status
            )),
            Some(_) => {}
        }
    }
    violations
}

/// Whether `file_id` is a version-less orphan (no `file_versions` rows and `content_id IS NULL`).
async fn is_versionless_orphan(db: &Arc<DBProvider<DbError>>, file_id: Uuid) -> bool {
    use file_storage::infra::storage::entity::file::{Column as FileColumn, Entity as FileEntity};
    use file_storage::infra::storage::entity::file_version::{
        Column as FileVersionColumn, Entity as FileVersionEntity,
    };
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let Some(file) = FileEntity::find()
        .filter(FileColumn::FileId.eq(file_id))
        .secure()
        .scope_with(&scope)
        .one(&conn)
        .await
        .expect("query files")
    else {
        return false;
    };
    if file.content_id.is_some() {
        return false;
    }
    let version_count = FileVersionEntity::find()
        .filter(FileVersionColumn::FileId.eq(file_id))
        .secure()
        .scope_with(&scope)
        .count(&conn)
        .await
        .expect("count file_versions");
    version_count == 0
}

/// The checker must tell a healthy file from a known orphan, not always report clean or violation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invariant_checker_distinguishes_healthy_file_from_known_orphan() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let svc = make_file_service(store.clone(), backends.clone());
    let dp = TestDataPlane::new(Arc::clone(&svc), store.clone(), backends.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);

    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .expect("create_file");
    dp.put_content(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"healthy"),
    )
    .await
    .expect("put_content");
    svc.bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind");

    let violations = find_content_id_violations(&db, ticket.file_id).await;
    assert!(
        violations.is_empty(),
        "a healthy, correctly-bound file must have zero content_id invariant violations, got: \
         {violations:?}"
    );
    assert!(
        !is_versionless_orphan(&db, ticket.file_id).await,
        "a healthy, bound file must not be flagged as a version-less orphan"
    );

    // Orphan reproduction: bare file, failed initiate, no cleanup.
    let tmp = tempfile::tempdir().expect("tempdir");
    let local_backend: Arc<dyn StorageBackend> = Arc::new(LocalFsBackend::new("fs", tmp.keep()));
    let local_backends =
        BackendRegistry::new(vec![Arc::clone(&local_backend)], "fs").expect("registry");
    let svc_local = make_file_service(store.clone(), local_backends.clone());
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let msvc_local = make_multipart_service(multipart_store, local_backends, 120);
    let orphan_file_id = svc_local
        .create_file_bare(&ctx, new_file())
        .await
        .expect("create_file_bare");
    msvc_local
        .initiate_multipart_upload(
            &ctx,
            orphan_file_id,
            "application/octet-stream",
            20,
            Some(10),
            false,
        )
        .await
        .expect_err("capability reject");

    assert!(
        is_versionless_orphan(&db, orphan_file_id).await,
        "known defect FS-01/F1: the invariant checker must flag this file as a version-less \
         orphan -- if this starts failing, either F1 was fixed (update the report) or the \
         checker itself regressed"
    );
    // A version-less orphan has no `content_id`, so it is not a `content_id` violation by
    // definition.
    let orphan_violations = find_content_id_violations(&db, orphan_file_id).await;
    assert!(
        orphan_violations.is_empty(),
        "a version-less orphan has no content_id to be invalid -- the orphan-ness itself is \
         is_versionless_orphan's finding, not find_content_id_violations'; got unexpected \
         content_id violations: {orphan_violations:?}"
    );
}

// Parent-row-lock races: `FileRepo::lock_for_update` (first statement of the delete transactions)
// vs a
// concurrent `insert_pending_version` on the same file, via real `tokio::spawn` + `join!`.
// Whichever
// side wins, the lock leaves exactly two clean outcomes; the tests reject only the dangerous third
// (insert `Ok` while its row is silently cascade-removed). Each loops `RACE_ITERATIONS` times with
// a
// small real-clock head start for the insert: it raises the odds of hitting the narrow window but
// is
// not the correctness mechanism.
const RACE_ITERATIONS: usize = 24;

fn race_audit(
    tenant_id: Uuid,
    file_id: Uuid,
    op: file_storage::domain::audit::AuditOperation,
    detail: serde_json::Value,
) -> file_storage::domain::audit::AuditEntry {
    file_storage::domain::audit::AuditEntry {
        tenant_id,
        actor_kind: "user".to_owned(),
        actor_id: Uuid::now_v7(),
        file_id: Some(file_id),
        operation: op,
        outcome: file_storage::domain::audit::AuditOutcome::Success,
        detail,
        occurred_at: OffsetDateTime::now_utc(),
    }
}

fn race_event(
    tenant_id: Uuid,
    owner_id: Uuid,
    file_id: Uuid,
) -> file_storage::domain::audit::FileEvent {
    file_storage::domain::audit::FileEvent {
        tenant_id,
        owner_id,
        file_id,
        event_type: "file.deleted".to_owned(),
        payload: serde_json::json!({ "version_count": 0 }),
    }
}

/// (a) `delete_file_collecting_versions` vs a concurrent `insert_pending_version`: either the
/// delete
/// collects `v2` too, or the insert fails `FileNotFound` and leaves no row. Rejected: insert `Ok`
/// but
/// `v2` not collected (a silent backend-blob leak).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_file_vs_concurrent_insert_version_has_no_silent_loss() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));

    for iteration in 0..RACE_ITERATIONS {
        let tenant_id = Uuid::now_v7();
        let owner_id = Uuid::now_v7();
        let file_id = Uuid::now_v7();
        let v1 = Uuid::now_v7();
        let now = OffsetDateTime::now_utc();

        store
            .create_file_with_pending_version(
                &new_file(),
                file_id,
                v1,
                tenant_id,
                "mem",
                &format!("/{file_id}/{v1}"),
                now,
                race_audit(
                    tenant_id,
                    file_id,
                    file_storage::domain::audit::AuditOperation::Create,
                    serde_json::json!({}),
                ),
            )
            .await
            .expect("create file + v1");
        common::write_all(
            &backend,
            &format!("/{file_id}/{v1}"),
            Bytes::from_static(b"v1"),
        )
        .await;

        let v2 = Uuid::now_v7();
        let store_del = store.clone();
        let store_ins = store.clone();
        let del_task = tokio::spawn(async move {
            store_del
                .delete_file_collecting_versions(
                    &AccessScope::allow_all(),
                    file_id,
                    None,
                    race_audit(
                        tenant_id,
                        file_id,
                        file_storage::domain::audit::AuditOperation::DeleteFile,
                        serde_json::json!({ "version_count": 0 }),
                    ),
                    Some(race_event(tenant_id, owner_id, file_id)),
                )
                .await
        });
        let ins_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_micros(150)).await;
            store_ins
                .insert_pending_version(
                    file_id,
                    v2,
                    "application/octet-stream",
                    "mem",
                    &format!("/{file_id}/{v2}"),
                    now,
                )
                .await
        });
        let del_res = del_task.await.expect("delete task panicked");
        let ins_res = ins_task.await.expect("insert task panicked");

        eprintln!(
            "delete_file_vs_concurrent_insert_version[{iteration}]: delete={} insert={}",
            describe_result(&del_res),
            describe_result(&ins_res)
        );

        match (del_res, ins_res) {
            (Ok(deleted), Ok(())) => {
                // Insert won: the delete's post-lock version list must include v2.
                assert!(deleted.removed, "the file row must have been removed");
                let mut ids: Vec<Uuid> = deleted.versions.iter().map(|v| v.version_id).collect();
                ids.sort_unstable();
                let mut expected = vec![v1, v2];
                expected.sort_unstable();
                assert_eq!(
                    ids, expected,
                    "insert succeeded (v2 committed) but the delete's collected list does \
                 not contain it -- SILENT BLOB LEAK: v2's row was cascade-removed \
                 without ever being seen by the caller's cleanup"
                );
            }
            (Ok(deleted), Err(e)) => {
                // Delete won: the insert must have failed on the deleted parent; only v1 is
                // collected.
                assert!(deleted.removed, "the file row must have been removed");
                let ids: Vec<Uuid> = deleted.versions.iter().map(|v| v.version_id).collect();
                assert_eq!(
                    ids,
                    vec![v1],
                    "delete won the race -- must have collected exactly v1 (v2 never \
                 committed)"
                );
                assert!(
                    matches!(&e, DomainError::FileNotFound { id } if *id == file_id),
                    "insert lost the race -- expected FileNotFound, got: {e}"
                );
            }
            (Err(e), ins_res) => panic!(
                "delete_file_collecting_versions must not error in this scenario -- got \
             {e}; insert result was {ins_res:?}",
                ins_res = ins_res.map_err(|e| e.to_string())
            ),
        }

        // Either way: no file, no v1, no v2, and nothing left uncollected.
        assert!(
            store
                .get_file(&AccessScope::allow_all(), file_id)
                .await
                .expect("get_file")
                .is_none(),
            "the file must be gone"
        );
        assert!(
            store
                .get_version(file_id, v1)
                .await
                .expect("get_version v1")
                .is_none(),
            "v1 must be gone"
        );
        assert!(
            store
                .get_version(file_id, v2)
                .await
                .expect("get_version v2")
                .is_none(),
            "v2 must be gone (either never committed, or cascade-removed and collected)"
        );
        backend
            .delete(&format!("/{file_id}/{v1}"))
            .await
            .expect("best-effort delete of v1's blob must succeed (no dangling row to block it)");
        assert!(
            !backend
                .exists(&format!("/{file_id}/{v1}"))
                .await
                .expect("exists"),
            "v1's blob must be gone -- no leaked backend storage"
        );
    }
}

/// (b) `delete_version_or_whole_file` on the only version vs a concurrent insert of a second:
/// either
/// `VersionRemoved` (file and `v2` survive) or `FileRemoved` plus an insert `FileNotFound`.
/// Rejected:
/// `FileRemoved` while the insert reports `Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_last_version_vs_concurrent_insert_second_version_has_no_silent_loss() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));

    for iteration in 0..RACE_ITERATIONS {
        let tenant_id = Uuid::now_v7();
        let owner_id = Uuid::now_v7();
        let file_id = Uuid::now_v7();
        let v1 = Uuid::now_v7();
        let now = OffsetDateTime::now_utc();

        store
            .create_file_with_pending_version(
                &new_file(),
                file_id,
                v1,
                tenant_id,
                "mem",
                &format!("/{file_id}/{v1}"),
                now,
                race_audit(
                    tenant_id,
                    file_id,
                    file_storage::domain::audit::AuditOperation::Create,
                    serde_json::json!({}),
                ),
            )
            .await
            .expect("create file + v1");

        let v2 = Uuid::now_v7();
        let store_del = store.clone();
        let store_ins = store.clone();
        let del_task = tokio::spawn(async move {
            store_del
                .delete_version_or_whole_file(
                    file_id,
                    v1,
                    race_audit(
                        tenant_id,
                        file_id,
                        file_storage::domain::audit::AuditOperation::DeleteVersion,
                        serde_json::json!({ "version_id": v1 }),
                    ),
                    race_audit(
                        tenant_id,
                        file_id,
                        file_storage::domain::audit::AuditOperation::DeleteFile,
                        serde_json::json!({ "version_count": 1 }),
                    ),
                    Some(race_event(tenant_id, owner_id, file_id)),
                )
                .await
        });
        let ins_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_micros(150)).await;
            store_ins
                .insert_pending_version(
                    file_id,
                    v2,
                    "application/octet-stream",
                    "mem",
                    &format!("/{file_id}/{v2}"),
                    now,
                )
                .await
        });
        let del_res = del_task.await.expect("delete task panicked");
        let ins_res = ins_task.await.expect("insert task panicked");

        eprintln!(
            "delete_last_version_vs_concurrent_insert_second_version[{iteration}]: delete={} insert={}",
            describe_result(&del_res),
            describe_result(&ins_res)
        );

        match (del_res, ins_res) {
            (Ok(DeleteVersionOutcome::VersionRemoved(removed)), Ok(())) => {
                assert_eq!(removed.version_id, v1, "the removed version must be v1");
                let file = store
                    .get_file(&AccessScope::allow_all(), file_id)
                    .await
                    .expect("get_file");
                assert!(
                    file.is_some(),
                    "insert won the race -- the file must survive (v1 was not its only \
                 version by delete time)"
                );
                assert!(
                    store
                        .get_version(file_id, v2)
                        .await
                        .expect("get_version v2")
                        .is_some(),
                    "v2 (the race version, never asked to be deleted) must still exist"
                );
                assert!(
                    store
                        .get_version(file_id, v1)
                        .await
                        .expect("get_version v1")
                        .is_none(),
                    "v1 (the requested version) must be gone"
                );
            }
            (Ok(DeleteVersionOutcome::FileRemoved(removed)), Err(e)) => {
                assert_eq!(removed.version_id, v1, "the removed version must be v1");
                assert!(
                    store
                        .get_file(&AccessScope::allow_all(), file_id)
                        .await
                        .expect("get_file")
                        .is_none(),
                    "delete won the race -- the whole file must be gone"
                );
                assert!(
                    store
                        .get_version(file_id, v2)
                        .await
                        .expect("get_version v2")
                        .is_none(),
                    "the losing insert must not have left a v2 row behind"
                );
                assert!(
                    matches!(&e, DomainError::FileNotFound { id } if *id == file_id),
                    "insert lost the race -- expected FileNotFound, got: {e}"
                );
            }
            (Ok(DeleteVersionOutcome::FileRemoved(_)), Ok(())) => panic!(
                "SILENT DATA LOSS: the whole file (and v1) was deleted while the \
             concurrent insert of v2 reported success -- v2 must have been \
             cascade-removed without its own caller ever being told"
            ),
            (del_res, ins_res) => panic!(
                "unexpected outcome combination: delete={del_res:?} insert={}",
                describe_result(&ins_res)
            ),
        }

        // Best-effort cleanup: a surviving pending `v2` must not leak into other tests' sweep
        // counts in the
        // shared DB.
        store
            .delete_file_collecting_versions(
                &AccessScope::allow_all(),
                file_id,
                None,
                race_audit(
                    tenant_id,
                    file_id,
                    file_storage::domain::audit::AuditOperation::DeleteFile,
                    serde_json::json!({ "reason": "test_cleanup" }),
                ),
                None,
            )
            .await
            .ok();
    }
}

/// (c) `delete_orphan_file_with_event` vs a concurrent insert of a first version: either the
/// reclaim
/// declines (`Ok(false)`) or removes the file (`Ok(true)`) and the insert fails `FileNotFound`.
/// Rejected: `Ok(true)` while the insert reports `Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn orphan_reclaim_vs_concurrent_insert_version_has_no_silent_loss() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let store = Store::new(Arc::clone(&db));
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let svc = make_file_service(store.clone(), backends);

    for iteration in 0..RACE_ITERATIONS {
        let tenant_id = Uuid::now_v7();
        let ctx = make_ctx(tenant_id);
        let file_id = svc
            .create_file_bare(&ctx, new_file())
            .await
            .expect("create_file_bare (version-less orphan)");
        assert!(
            is_versionless_orphan(&db, file_id).await,
            "the freshly-created bare file must start out as a version-less orphan"
        );

        let now = OffsetDateTime::now_utc();
        let v1 = Uuid::now_v7();
        let store_del = store.clone();
        let store_ins = store.clone();
        let del_task = tokio::spawn(async move {
            store_del
                .delete_orphan_file_with_event(
                    file_id,
                    race_audit(
                        tenant_id,
                        file_id,
                        file_storage::domain::audit::AuditOperation::OrphanReconcile,
                        serde_json::json!({ "reason": "test" }),
                    ),
                    None,
                )
                .await
        });
        let ins_task = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_micros(150)).await;
            store_ins
                .insert_pending_version(
                    file_id,
                    v1,
                    "application/octet-stream",
                    "mem",
                    &format!("/{file_id}/{v1}"),
                    now,
                )
                .await
        });
        let del_res = del_task.await.expect("delete task panicked");
        let ins_res = ins_task.await.expect("insert task panicked");

        eprintln!(
            "orphan_reclaim_vs_concurrent_insert_version[{iteration}]: reclaim={} insert={}",
            describe_result(&del_res),
            describe_result(&ins_res)
        );

        match (del_res, ins_res) {
            (Ok(false), Ok(())) => {
                // Insert won: the reclaim's post-lock check saw the new version and declined.
                let file = store
                    .get_file(&AccessScope::allow_all(), file_id)
                    .await
                    .expect("get_file");
                assert!(file.is_some(), "the file must survive");
                assert!(
                    store
                        .get_version(file_id, v1)
                        .await
                        .expect("get_version v1")
                        .is_some(),
                    "v1 (the race version) must still exist"
                );
            }
            (Ok(true), Err(e)) => {
                // Reclaim won: the insert must have failed on the deleted parent.
                assert!(
                    store
                        .get_file(&AccessScope::allow_all(), file_id)
                        .await
                        .expect("get_file")
                        .is_none(),
                    "the file must be gone"
                );
                assert!(
                    store
                        .get_version(file_id, v1)
                        .await
                        .expect("get_version v1")
                        .is_none(),
                    "the losing insert must not have left a v1 row behind"
                );
                assert!(
                    matches!(&e, DomainError::FileNotFound { id } if *id == file_id),
                    "insert lost the race -- expected FileNotFound, got: {e}"
                );
            }
            (Ok(true), Ok(())) => panic!(
                "SILENT DATA LOSS: the orphan file was reclaimed while the concurrent \
             insert of v1 reported success -- v1 must have been cascade-removed \
             without its own caller ever being told"
            ),
            (del_res, ins_res) => panic!(
                "unexpected outcome combination: reclaim={del_res:?} insert={}",
                describe_result(&ins_res)
            ),
        }

        // Best-effort cleanup, as in test (b).
        store
            .delete_file_collecting_versions(
                &AccessScope::allow_all(),
                file_id,
                None,
                race_audit(
                    tenant_id,
                    file_id,
                    file_storage::domain::audit::AuditOperation::DeleteFile,
                    serde_json::json!({ "reason": "test_cleanup" }),
                ),
                None,
            )
            .await
            .ok();
    }
}

// Migration lease: two concurrent `migrate_backend` calls for one version, to different backends,
// must never both succeed. A deterministic hook, not a timer: A's target backend gates
// `publish_exclusive` (the destination write, after the lease is acquired and committed); the test
// then calls B and expects `Conflict` before releasing A. A sleep-staggered B could run after A
// released its lease and legitimately succeed.
struct GatedPublishBackend {
    inner: Arc<dyn StorageBackend>,
    /// Notified once the migration lease is held and the call is inside its destination write.
    entered: Arc<Notify>,
    /// Waited on before delegating; lets the test hold this call open.
    resume: Arc<Notify>,
}

#[async_trait]
impl StorageBackend for GatedPublishBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn capabilities(&self) -> file_storage::infra::backend::BackendCapabilities {
        self.inner.capabilities()
    }
    async fn put_stream(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        self.inner.put_stream(path, stream, max_size).await
    }
    async fn publish_exclusive(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<file_storage::infra::backend::PublishOutcome, DomainError> {
        self.entered.notify_one();
        self.resume.notified().await;
        self.inner.publish_exclusive(path, stream, max_size).await
    }
    async fn get_stream(
        &self,
        path: &str,
        expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        self.inner.get_stream(path, expected_len).await
    }
    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        self.inner.read_prefix(path, max_bytes).await
    }
    async fn get_range_stream(
        &self,
        path: &str,
        range: file_storage_sdk::ByteRange,
        expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        self.inner.get_range_stream(path, range, expected_len).await
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
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migration_lease_two_concurrent_migrate_backend_calls_exactly_one_wins() {
    let (db, _pg_guard) = pg_db_or_skip!();

    let store = Store::new(Arc::clone(&db));
    let mem: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let alt1_inner: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("alt1"));
    let alt2: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("alt2"));

    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let alt1: Arc<dyn StorageBackend> = Arc::new(GatedPublishBackend {
        inner: Arc::clone(&alt1_inner),
        entered: Arc::clone(&entered),
        resume: Arc::clone(&resume),
    });

    let backends = BackendRegistry::new(
        vec![Arc::clone(&mem), Arc::clone(&alt1), Arc::clone(&alt2)],
        "mem",
    )
    .expect("registry");
    let svc = make_file_service(store.clone(), backends.clone());
    let dp = TestDataPlane::new(Arc::clone(&svc), store.clone(), backends.clone());

    let tenant_id = Uuid::now_v7();
    let ctx = make_ctx(tenant_id);
    let content = Bytes::from_static(b"migration lease race content");

    let ticket = svc
        .create_file(&ctx, new_file(), None, false)
        .await
        .expect("create_file");
    dp.put_content(
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        content.clone(),
    )
    .await
    .expect("put_content");
    svc.bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind");

    let file_id = ticket.file_id;
    let version_id = ticket.version_id;

    let svc_a = Arc::clone(&svc);
    let ctx_a = ctx.clone();
    let a_task = tokio::spawn(async move { svc_a.migrate_backend(&ctx_a, file_id, "alt1").await });

    // A is inside its gated destination write, so its migration lease is already committed.
    entered.notified().await;

    // B must be rejected: A holds the lease and is blocked on `resume`.
    let b_res = svc.migrate_backend(&ctx, file_id, "alt2").await;
    eprintln!(
        "migration_lease_race: b(alt2)={} (while a(alt1) is gated mid-transfer)",
        describe_result(&b_res)
    );
    let b_err = b_res.expect_err(
        "B must be rejected while A's migration lease is held -- no sleep-based stagger, this \
         interleaving is now structurally guaranteed",
    );
    assert!(
        matches!(b_err, DomainError::Conflict { .. }),
        "the losing attempt must be rejected by the migration lease with Conflict, got {b_err}"
    );

    let dest_path = format!("/{file_id}/{version_id}");
    assert!(
        !alt2.exists(&dest_path).await.expect("exists"),
        "B must never have touched its own target backend at all -- it must be rejected by the \
         migration lease before any backend I/O"
    );

    resume.notify_one();
    let a_res = a_task.await.expect("task A panicked");
    eprintln!("migration_lease_race: a(alt1)={}", describe_result(&a_res));
    a_res.expect("A must win the migration lease (nothing else holds it) and complete cleanly");

    let after = store
        .get_version(file_id, version_id)
        .await
        .expect("get_version")
        .expect("version must still exist");
    assert_eq!(
        after.backend_id, "alt1",
        "the version must end up on alt1 -- the only attempt that ever actually ran"
    );
    assert_eq!(after.backend_path, dest_path);

    let stored = alt1_inner
        .read_prefix(&dest_path, 1024)
        .await
        .expect("read_prefix alt1")
        .expect("the migrated object must exist on alt1");
    assert_eq!(
        stored, content,
        "the migrated object's content must match what was originally uploaded"
    );

    assert!(
        !alt2.exists(&dest_path).await.expect("exists"),
        "alt2 must still have no object after A's migration completes"
    );

    // The lease was released when A finished: a fresh attempt to alt2 must succeed.
    let c_res = svc.migrate_backend(&ctx, file_id, "alt2").await;
    eprintln!(
        "migration_lease_race: post-release attempt c(alt2)={}",
        describe_result(&c_res)
    );
    c_res.expect(
        "the migration lease must have been released once A finished -- a subsequent attempt \
         must succeed, not stay rejected",
    );
    let after_c = store
        .get_version(file_id, version_id)
        .await
        .expect("get_version")
        .expect("version must still exist");
    assert_eq!(
        after_c.backend_id, "alt2",
        "the post-release attempt must have actually migrated the version onward to alt2"
    );
}
