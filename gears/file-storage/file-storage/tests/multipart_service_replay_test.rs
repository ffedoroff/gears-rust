#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use sea_orm::{ConnectionTrait, Database, Statement, TransactionTrait};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use file_storage::domain::audit::{AuditEntry, AuditOperation};
use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::error::DomainError;
use file_storage::domain::etag;
use file_storage::domain::multipart::{BindState, MultipartPart, MultipartUploadSession};
use file_storage::domain::multipart_service::MultipartService;
use file_storage::domain::policy::{PolicyScope, StoredPolicy};
use file_storage::domain::ports::{
    AutoBindOnFinalize, FinalizeMultipartOutcome, FinalizeVersionOutcome, MultipartFinishSnapshot,
    MultipartStore,
};
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{BackendRegistry, InMemoryBackend, StorageBackend};
use file_storage::infra::content::hash_mode::HashMode;
use file_storage::infra::signed_url::Issuer;
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::{File, FileVersion, NewFile, OwnerKind, VersionStatus};

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn build_db_with_dsn() -> (Arc<DBProvider<DbError>>, String) {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-mp-replay-test-{}.db",
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
    (Arc::new(DBProvider::new(db)), dsn)
}

async fn build_env() -> (
    Arc<FileService>,
    Arc<MultipartService>,
    Arc<dyn MultipartStore>,
    Arc<dyn StorageBackend>,
    Store,
    SecurityContext,
    String,
) {
    let (db, dsn) = build_db_with_dsn().await;
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
    let msvc = Arc::new(
        MultipartService::new(
            Arc::clone(&multipart_store),
            backends,
            Arc::clone(&authorizer),
            None,
            issuer,
            "http://sidecar.test".to_owned(),
            3600,
        )
        .with_complete_lease_secs(90),
    );
    (
        svc,
        msvc,
        multipart_store,
        backend,
        store,
        ctx(Uuid::now_v7()),
        dsn,
    )
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
        name: "upload.bin".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "application/octet-stream".to_owned(),
        custom_metadata: vec![],
    }
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
        "test data must match the plan"
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
        .expect("upsert part");
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut acc, b| {
        write!(acc, "{b:02x}").expect("writing to a String cannot fail");
        acc
    })
}

fn uuid_blob(id: Uuid) -> String {
    format!("X'{}'", hex_encode(id.as_bytes()))
}

/// Run one raw-SQL statement against an independent connection to `dsn` and assert it hit exactly
/// the row the test set up — a silent no-op tamper would make the rest of the test meaningless.
async fn exec_expect_one_row(dsn: &str, sql: &str) {
    let conn = Database::connect(dsn).await.expect("raw connect");
    let res = conn
        .execute_raw(Statement::from_string(
            conn.get_database_backend(),
            sql.to_owned(),
        ))
        .await
        .unwrap_or_else(|e| panic!("tamper SQL failed: {sql}: {e}"));
    assert_eq!(
        res.rows_affected(),
        1,
        "tamper SQL must hit exactly the one row the test prepared: {sql}"
    );
}

/// Force `replay_completed` to fall through the persisted-snapshot fast path to its version-row
/// fallback, by wiping the snapshot the real `complete` just persisted.
async fn null_complete_result(dsn: &str, upload_id: Uuid) {
    exec_expect_one_row(
        dsn,
        &format!(
            "UPDATE multipart_uploads SET complete_result = NULL WHERE upload_id = {}",
            uuid_blob(upload_id)
        ),
    )
    .await;
}

async fn reset_session_to_in_progress(dsn: &str, upload_id: Uuid) {
    exec_expect_one_row(
        dsn,
        &format!(
            "UPDATE multipart_uploads SET state = 'in_progress', lease_owner = NULL, \
             lease_until = NULL WHERE upload_id = {}",
            uuid_blob(upload_id)
        ),
    )
    .await;
}

async fn set_hash_mode_bypassing_check(dsn: &str, version_id: Uuid, value: &str) {
    let conn = Database::connect(dsn).await.expect("raw connect");
    let backend = conn.get_database_backend();
    let txn = conn.begin().await.expect("begin txn");
    txn.execute_raw(Statement::from_string(
        backend,
        "PRAGMA ignore_check_constraints = ON;".to_owned(),
    ))
    .await
    .expect("disable CHECK enforcement for this connection");
    let res = txn
        .execute_raw(Statement::from_string(
            backend,
            format!(
                "UPDATE file_versions SET hash_mode = '{value}' WHERE version_id = {}",
                uuid_blob(version_id)
            ),
        ))
        .await
        .expect("tamper hash_mode");
    assert_eq!(
        res.rows_affected(),
        1,
        "tamper UPDATE must hit exactly the one row the test prepared"
    );
    txn.commit().await.expect("commit tamper txn");
}

async fn tamper_session_to_completed_out_from_under(dsn: &str, upload_id: Uuid) {
    exec_expect_one_row(
        dsn,
        &format!(
            "UPDATE multipart_uploads SET state = 'completed', complete_result = NULL, \
             lease_owner = NULL, lease_until = NULL WHERE upload_id = {} AND state = 'completing'",
            uuid_blob(upload_id)
        ),
    )
    .await;
}

async fn tamper_rebind_content(dsn: &str, file_id: Uuid, new_content_id: Uuid) {
    exec_expect_one_row(
        dsn,
        &format!(
            "UPDATE files SET content_id = {} WHERE file_id = {}",
            uuid_blob(new_content_id),
            uuid_blob(file_id)
        ),
    )
    .await;
}

struct SessionCasRaceStore {
    inner: Arc<dyn MultipartStore>,
    dsn: String,
    rebind_content_id: Uuid,
    armed: AtomicBool,
}

#[async_trait]
impl MultipartStore for SessionCasRaceStore {
    async fn require_file(&self, scope: &AccessScope, file_id: Uuid) -> Result<File, DomainError> {
        if self.armed.swap(false, Ordering::SeqCst) {
            tamper_rebind_content(&self.dsn, file_id, self.rebind_content_id).await;
        }
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

    #[allow(clippy::too_many_arguments)]
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
    ) -> Result<Option<MultipartUploadSession>, DomainError> {
        self.inner.get_multipart_upload(upload_id).await
    }

    async fn get_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
    ) -> Result<Option<FileVersion>, DomainError> {
        self.inner.get_version(file_id, version_id).await
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

    #[allow(clippy::too_many_arguments)]
    async fn finalize_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        hash_value: Vec<u8>,
        hash_mode: HashMode,
        part_count: Option<i32>,
        manifest: Option<String>,
        validated_mime: Option<String>,
        audit: AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
    ) -> Result<FinalizeVersionOutcome, DomainError> {
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
        finalize_audit: AuditEntry,
        auto_bind: Option<AutoBindOnFinalize>,
        finish: MultipartFinishSnapshot,
    ) -> Result<FinalizeMultipartOutcome, DomainError> {
        tamper_session_to_completed_out_from_under(&self.dsn, finish.upload_id).await;
        self.armed.store(true, Ordering::SeqCst);
        self.inner
            .finalize_multipart_version(
                file_id,
                manifest,
                validated_mime,
                finalize_audit,
                auto_bind,
                finish,
            )
            .await
    }

    async fn complete_multipart_upload(
        &self,
        upload_id: Uuid,
        lease_owner: &str,
        result_json: &str,
        audit: AuditEntry,
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
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        self.inner.abort_multipart_upload(upload_id, audit).await
    }

    async fn delete_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        audit: AuditEntry,
    ) -> Result<bool, DomainError> {
        self.inner.delete_version(file_id, version_id, audit).await
    }
}

#[tokio::test]
async fn complete_multipart_upload_unknown_upload_id_is_not_found() {
    let (svc, msvc, _store, _backend, _s, ctx, _dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    let bogus_upload_id = Uuid::now_v7();
    let err = msvc
        .complete_multipart_upload(&ctx, file_id, bogus_upload_id, None)
        .await
        .expect_err("an unknown upload_id must never succeed");
    match err {
        DomainError::MultipartUploadNotFound { upload_id } => {
            assert_eq!(upload_id, bogus_upload_id);
        }
        other => panic!("expected MultipartUploadNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn replay_completed_fallback_rebuilds_result_from_version_row() {
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 13, None, false)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"Hello, World!"),
    )
    .await;

    let first = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();

    null_complete_result(&dsn, plan.upload_id).await;

    let replay = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("fallback replay of a snapshot-less completed session must succeed")
        .unwrap_completed();

    assert_eq!(replay.version_id, first.version_id);
    assert_eq!(replay.size, first.size);
    assert_eq!(replay.hash_algorithm, first.hash_algorithm);
    assert_eq!(replay.content_hash, first.content_hash);
    assert_eq!(replay.hash_mode, first.hash_mode);
    assert_eq!(
        replay.hash_mode,
        HashMode::WholeSha256,
        "single part degenerates to whole-sha256"
    );
    assert_eq!(replay.part_count, first.part_count);
    assert_eq!(replay.manifest, first.manifest);
    assert_eq!(
        replay.bind_state,
        BindState::Manual,
        "auto_bind: false session was never bound"
    );
    assert_eq!(replay.etag, None);
    assert_eq!(replay.current_etag, None);
}

#[tokio::test]
async fn replay_completed_fallback_errors_when_version_row_is_gone() {
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let first_complete = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    // A replay only means anything once the original complete really finished.
    assert!(
        first_complete.size > 0,
        "the first complete must assemble a non-empty version"
    );

    null_complete_result(&dsn, plan.upload_id).await;
    exec_expect_one_row(
        &dsn,
        &format!(
            "DELETE FROM file_versions WHERE version_id = {}",
            uuid_blob(plan.version_id)
        ),
    )
    .await;

    let err = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect_err("replay against a deleted version row must fail");
    match err {
        DomainError::VersionNotFound {
            file_id: f,
            version_id: v,
        } => {
            assert_eq!(f, file_id);
            assert_eq!(v, plan.version_id);
        }
        other => panic!("expected VersionNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn replay_completed_fallback_errors_when_version_not_available() {
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let first_complete = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    // A replay only means anything once the original complete really finished.
    assert!(
        first_complete.size > 0,
        "the first complete must assemble a non-empty version"
    );

    null_complete_result(&dsn, plan.upload_id).await;
    exec_expect_one_row(
        &dsn,
        &format!(
            "UPDATE file_versions SET status = 'pending' WHERE version_id = {}",
            uuid_blob(plan.version_id)
        ),
    )
    .await;

    let err = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect_err("replay against a non-available version must fail");
    match err {
        DomainError::MultipartUploadNotInProgress { upload_id, state } => {
            assert_eq!(upload_id, plan.upload_id);
            assert_eq!(
                state, "completed",
                "reported state is the SESSION's own state"
            );
        }
        other => panic!("expected MultipartUploadNotInProgress, got {other:?}"),
    }
}

#[tokio::test]
async fn replay_completed_fallback_errors_on_unrecognized_hash_mode() {
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let first_complete = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    // A replay only means anything once the original complete really finished.
    assert!(
        first_complete.size > 0,
        "the first complete must assemble a non-empty version"
    );

    null_complete_result(&dsn, plan.upload_id).await;
    set_hash_mode_bypassing_check(&dsn, plan.version_id, "bogus-mode").await;

    let err = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect_err("an unrecognized hash_mode must fail, not panic or silently pick one");
    assert!(
        matches!(err, DomainError::Database { .. }),
        "expected Database, got {err:?}"
    );
}

#[tokio::test]
async fn replay_completed_fallback_reports_bound_state_when_still_bound() {
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, true)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let first = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    assert_eq!(
        first.bind_state,
        BindState::Bound,
        "auto_bind session must self-bind"
    );

    null_complete_result(&dsn, plan.upload_id).await;

    let replay = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("fallback replay of a still-bound version must succeed")
        .unwrap_completed();
    assert_eq!(replay.bind_state, BindState::Bound);
    assert_eq!(
        replay.etag,
        Some(etag::content_etag(file_id, plan.version_id)),
        "Bound branch must derive the content ETag from (file_id, version_id)"
    );
    assert_eq!(replay.current_etag, None);
}

#[tokio::test]
async fn replay_completed_fallback_reports_conflict_when_content_rebound_elsewhere() {
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    let plan_a = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, true)
        .await
        .unwrap();
    let session_a = multipart_store
        .get_multipart_upload(plan_a.upload_id)
        .await
        .unwrap()
        .expect("session a");
    let path_a = format!("/{file_id}/{}", plan_a.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan_a,
        &path_a,
        &session_a.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let completed_a = msvc
        .complete_multipart_upload(&ctx, file_id, plan_a.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    assert_eq!(completed_a.bind_state, BindState::Bound);

    let plan_b = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session_b = multipart_store
        .get_multipart_upload(plan_b.upload_id)
        .await
        .unwrap()
        .expect("session b");
    let path_b = format!("/{file_id}/{}", plan_b.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan_b,
        &path_b,
        &session_b.backend_upload_handle,
        1,
        Bytes::from_static(b"BBBBB"),
    )
    .await;
    let completed_b = msvc
        .complete_multipart_upload(&ctx, file_id, plan_b.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    assert_eq!(completed_b.bind_state, BindState::Manual);
    svc.bind(&ctx, file_id, plan_b.version_id, Some("*"))
        .await
        .expect("rebind to version B");

    null_complete_result(&dsn, plan_a.upload_id).await;
    let replay_a = msvc
        .complete_multipart_upload(&ctx, file_id, plan_a.upload_id, None)
        .await
        .expect("fallback replay after an external rebind must still succeed")
        .unwrap_completed();
    assert_eq!(replay_a.bind_state, BindState::Conflict);
    assert_eq!(replay_a.etag, None);
    let file = svc.get_file(&ctx, file_id).await.expect("file");
    assert_eq!(
        replay_a.current_etag,
        Some(etag::content_etag(
            file_id,
            file.content_id.expect("bound to B")
        )),
        "Conflict branch must report the file's CURRENT etag, pointing at B"
    );
}

#[tokio::test]
async fn replay_completed_snapshot_survives_a_later_rebind_without_tampering() {
    let (svc, msvc, multipart_store, backend, _store, ctx, _dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    let plan_a = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, true)
        .await
        .unwrap();
    let session_a = multipart_store
        .get_multipart_upload(plan_a.upload_id)
        .await
        .unwrap()
        .expect("session a");
    let path_a = format!("/{file_id}/{}", plan_a.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan_a,
        &path_a,
        &session_a.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let completed_a = msvc
        .complete_multipart_upload(&ctx, file_id, plan_a.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    assert_eq!(completed_a.bind_state, BindState::Bound);
    let original_etag = completed_a
        .etag
        .clone()
        .expect("a Bound completion must carry an etag");

    // A second, independent (manual) upload on the same file, then an explicit rebind moves
    // `files.content_id` to version B -- a completely legitimate, unrelated operation, not a crash
    // or tamper.
    let plan_b = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session_b = multipart_store
        .get_multipart_upload(plan_b.upload_id)
        .await
        .unwrap()
        .expect("session b");
    let path_b = format!("/{file_id}/{}", plan_b.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan_b,
        &path_b,
        &session_b.backend_upload_handle,
        1,
        Bytes::from_static(b"BBBBB"),
    )
    .await;
    msvc.complete_multipart_upload(&ctx, file_id, plan_b.upload_id, None)
        .await
        .unwrap();
    svc.bind(&ctx, file_id, plan_b.version_id, Some("*"))
        .await
        .expect("rebind to version B");

    let replay_a = msvc
        .complete_multipart_upload(&ctx, file_id, plan_a.upload_id, None)
        .await
        .expect("idempotent re-complete after an unrelated later rebind must still succeed")
        .unwrap_completed();
    assert_eq!(
        replay_a.bind_state,
        BindState::Bound,
        "the snapshot must report the historical Bound outcome, not today's Conflict"
    );
    assert_eq!(
        replay_a.etag.as_deref(),
        Some(original_etag.as_str()),
        "the snapshot must report the ORIGINAL etag, not one derived from B's current bind"
    );
    assert_eq!(replay_a.version_id, plan_a.version_id);

    // Sanity: the file itself really did move on to B -- this is a genuine divergence between
    // "current state" and "this session's historical outcome", not a no-op rebind.
    let file = svc.get_file(&ctx, file_id).await.expect("file");
    assert_eq!(file.content_id, Some(plan_b.version_id));
}

#[tokio::test]
async fn complete_reports_transaction_bind_outcome_when_own_session_cas_is_lost() {
    let (db, dsn) = build_db_with_dsn().await;
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
    let real_multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = Arc::new(FileService::new(
        store.clone(),
        backends.clone(),
        Arc::clone(&issuer),
        Arc::clone(&authorizer),
        cfg,
        None,
        None,
    ));
    let raced_store: Arc<dyn MultipartStore> = Arc::new(SessionCasRaceStore {
        inner: Arc::clone(&real_multipart_store),
        dsn: dsn.clone(),
        // Stands in for "some other, unrelated version" -- never dereferenced as a real row, only
        // ever compared against by `bind_state_for` on the (buggy) fallback path.
        rebind_content_id: Uuid::now_v7(),
        armed: AtomicBool::new(false),
    });
    let msvc = Arc::new(
        MultipartService::new(
            Arc::clone(&raced_store),
            backends,
            Arc::clone(&authorizer),
            None,
            issuer,
            "http://sidecar.test".to_owned(),
            3600,
        )
        .with_complete_lease_secs(90),
    );
    let ctx = ctx(Uuid::now_v7());
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    // auto_bind: the finalize's own auto-bind CAS is what must win authoritatively.
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 13, None, true)
        .await
        .unwrap();
    let session = real_multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &real_multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"Hello, World!"),
    )
    .await;

    let completed = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("finalize won its own CAS -- session_completed==false must still succeed")
        .unwrap_completed();

    assert_eq!(
        completed.bind_state,
        BindState::Bound,
        "must report THIS transaction's own auto-bind decision, not a live recompute"
    );
    assert_eq!(
        completed.etag.as_deref(),
        Some(etag::content_etag(file_id, plan.version_id).as_str()),
        "must carry this version's own content etag"
    );
    assert_eq!(completed.current_etag, None);

    let file = svc.get_file(&ctx, file_id).await.expect("file");
    assert_eq!(
        file.content_id,
        Some(plan.version_id),
        "the file must really be bound to this version -- the rebind tamper never fired"
    );
}

#[tokio::test]
async fn replay_completed_snapshot_404s_when_its_composite_version_is_deleted() {
    let (svc, msvc, multipart_store, backend, _store, ctx, _dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();

    let part_size = 5 * 1024 * 1024usize;
    let part1 = vec![b'a'; part_size];
    let part2 = vec![b'b'; 4096];
    let declared_size = (part1.len() + part2.len()) as u64;
    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            declared_size,
            None,
            false,
        )
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from(part1),
    )
    .await;
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        2,
        Bytes::from(part2),
    )
    .await;

    let first = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    assert_eq!(
        first.hash_mode,
        HashMode::MultipartCompositeSha256,
        "sanity: 2 parts must produce a composite version with a real manifest"
    );
    assert!(
        first.manifest.is_some(),
        "sanity: a composite version must have a manifest"
    );

    svc.bind(&ctx, file_id, plan.version_id, None)
        .await
        .expect("first bind");
    let plan2 = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session2 = multipart_store
        .get_multipart_upload(plan2.upload_id)
        .await
        .unwrap()
        .expect("session2");
    let backend_path2 = format!("/{file_id}/{}", plan2.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan2,
        &backend_path2,
        &session2.backend_upload_handle,
        1,
        Bytes::from_static(b"BBBBB"),
    )
    .await;
    msvc.complete_multipart_upload(&ctx, file_id, plan2.upload_id, None)
        .await
        .unwrap();
    svc.bind(
        &ctx,
        file_id,
        plan2.version_id,
        Some(&etag::content_etag(file_id, plan.version_id)),
    )
    .await
    .expect("rebind to V2");

    svc.delete_version(&ctx, file_id, plan.version_id)
        .await
        .expect("delete the now-unbound V1");

    // Replay the ORIGINAL complete for V1's upload_id: the persisted snapshot is still there, but
    // its version is gone -- must 404, never a response with `manifest: null`.
    let err = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect_err("replay of a completed session whose version was since deleted must fail");
    match err {
        DomainError::VersionNotFound {
            file_id: f,
            version_id: v,
        } => {
            assert_eq!(f, file_id);
            assert_eq!(v, plan.version_id);
        }
        other => panic!("expected VersionNotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn complete_takeover_finishes_without_reassembly_when_version_already_available() {
    let (svc, msvc, multipart_store, backend, store, ctx, _dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;
    let part = store
        .list_multipart_parts(plan.upload_id)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("one part");

    let finalize_audit = AuditEntry::success(
        ctx.subject_tenant_id(),
        "user",
        ctx.subject_id(),
        Some(file_id),
        AuditOperation::FinalizeVersion,
        serde_json::json!({ "version_id": plan.version_id }),
    );
    let outcome = multipart_store
        .finalize_version(
            file_id,
            plan.version_id,
            part.size,
            part.part_hash.clone(),
            HashMode::WholeSha256,
            None,
            None,
            Some("application/octet-stream".to_owned()),
            finalize_audit,
            None,
        )
        .await
        .expect("finalize_version");
    assert!(
        outcome.updated,
        "the pending version row must have been finalized"
    );

    let now = time::OffsetDateTime::now_utc();
    let acquired = multipart_store
        .acquire_multipart_complete_lease(
            plan.upload_id,
            "dead-completer",
            now - time::Duration::seconds(5),
            now,
        )
        .await
        .unwrap();
    assert!(
        acquired,
        "the dead-completer lease must attach to the still in_progress session"
    );

    let completed = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("takeover onto an already-finalized version must succeed")
        .unwrap_completed();
    assert_eq!(completed.version_id, plan.version_id);
    assert_eq!(completed.size, part.size);

    let finished_session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session still exists");
    assert_eq!(
        finished_session.state,
        file_storage::domain::multipart::MultipartUploadState::Completed,
        "finish_session must flip completing -> completed"
    );
    assert!(
        finished_session.complete_result.is_some(),
        "finish_session must persist the response snapshot"
    );

    let version = store
        .get_version(file_id, plan.version_id)
        .await
        .unwrap()
        .expect("version");
    assert_eq!(version.status, VersionStatus::Available);
}

#[tokio::test]
async fn complete_converges_after_in_progress_reset_instead_of_reinvoking_consumed_backend_handle()
{
    let (svc, msvc, multipart_store, backend, _store, ctx, dsn) = build_env().await;
    let file_id = svc.create_file_bare(&ctx, new_file()).await.unwrap();
    let plan = msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 5, None, false)
        .await
        .unwrap();
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);
    simulate_sidecar_put_part(
        &multipart_store,
        &backend,
        &plan,
        &backend_path,
        &session.backend_upload_handle,
        1,
        Bytes::from_static(b"AAAAA"),
    )
    .await;

    let first = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();

    // Model the bug's end state: the session looks like a never-attempted, fresh session, even
    // though the work already happened for real.
    reset_session_to_in_progress(&dsn, plan.upload_id).await;

    let retried = msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect(
            "a retry after an in_progress reset must converge to the already-finalized \
             version instead of re-invoking the consumed backend handle",
        )
        .unwrap_completed();

    assert_eq!(retried.version_id, first.version_id);
    assert_eq!(retried.size, first.size);
    assert_eq!(retried.content_hash, first.content_hash);

    let finished_session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session still exists");
    assert_eq!(
        finished_session.state,
        file_storage::domain::multipart::MultipartUploadState::Completed,
        "the retry must converge the session back to completed"
    );
}
