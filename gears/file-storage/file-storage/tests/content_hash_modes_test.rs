//! ADR-0006 content-hash-modes acceptance criteria (§6).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use sea_orm::{ConnectionTrait, Database, Statement};
use sea_orm_migration::MigratorTrait;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::error::DomainError;
use file_storage::domain::multipart::MultipartPlan;
use file_storage::domain::multipart_service::MultipartService;
use file_storage::domain::ports::MultipartStore;
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{
    BackendCapabilities, BackendRegistry, InMemoryBackend, MultipartCompletionPart, StorageBackend,
};
use file_storage::infra::content::hash;
use file_storage::infra::content::hash_mode::{HashMode, Manifest, ManifestEntry};
use file_storage::infra::content::stream_verify::verify_stream;
use file_storage::infra::signed_url::Issuer;
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::{ByteRange, NewFile, OwnerKind};

mod common;
use common::read_all;

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn verify_content_hash(
    content: &[u8],
    hash_mode: HashMode,
    hash_value: &[u8],
    manifest: Option<&Manifest>,
) -> Result<(), DomainError> {
    let bytes = Bytes::copy_from_slice(content);
    let len = bytes.len() as u64;
    let inner: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
        Box::pin(futures::stream::once(async move { Ok(bytes) }));
    let (mut stream, slot) = verify_stream(
        inner,
        len,
        hash_mode,
        hash_value.to_vec(),
        manifest.cloned(),
    )?;
    while let Some(chunk) = stream.next().await {
        chunk.map_err(|e| DomainError::backend("test", e.to_string()))?;
    }
    slot.lock()
        .unwrap()
        .take()
        .expect("verify_stream must publish a verdict once fully drained")
}

/// A `StorageBackend` decorator that counts whole-object reads (`get_stream`) so a test can assert
/// the ADR-0006 "no re-read at complete" invariant.
struct CountingBackend {
    inner: Arc<dyn StorageBackend>,
    reads: Arc<AtomicUsize>,
}

impl CountingBackend {
    fn new(inner: Arc<dyn StorageBackend>) -> (Arc<Self>, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let backend = Arc::new(Self {
            inner,
            reads: Arc::clone(&reads),
        });
        (backend, reads)
    }
}

#[async_trait]
impl StorageBackend for CountingBackend {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn capabilities(&self) -> BackendCapabilities {
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
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.get_stream(path, expected_len).await
    }
    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        self.inner.read_prefix(path, max_bytes).await
    }
    async fn get_range_stream(
        &self,
        path: &str,
        range: ByteRange,
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
    async fn stat(&self, path: &str) -> Result<Option<u64>, DomainError> {
        self.inner.stat(path).await
    }
    async fn initiate_multipart(&self, path: &str) -> Result<String, DomainError> {
        self.inner.initiate_multipart(path).await
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
        parts: &[MultipartCompletionPart],
    ) -> Result<(Manifest, [u8; 32]), DomainError> {
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

async fn build_db_with_dsn() -> (Arc<DBProvider<DbError>>, String) {
    let mut path = std::env::temp_dir();
    path.push(format!("cf-fs-chm-test-{}.db", Uuid::now_v7().simple()));
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

fn cfg() -> ServiceConfig {
    ServiceConfig {
        default_url_ttl_secs: 3600,
        sidecar_base_url: "http://sidecar.test".to_owned(),
        default_page_size: 50,
        max_page_size: 1000,
        idempotency_ttl_secs: 86400,
    }
}

fn services(
    db: &Arc<DBProvider<DbError>>,
    backends: BackendRegistry,
) -> (Arc<FileService>, Arc<MultipartService>, Store) {
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authorizer: Arc<dyn file_storage::domain::authz::Authorizer> =
        Arc::new(TenantOnlyAuthorizer);
    let store = Store::new(Arc::clone(db));
    let svc = Arc::new(FileService::new(
        store.clone(),
        backends.clone(),
        Arc::clone(&issuer),
        Arc::clone(&authorizer),
        cfg(),
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
    (svc, msvc, store)
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

#[allow(clippy::type_complexity)]
async fn drive_multipart(
    svc: &FileService,
    msvc: &Arc<MultipartService>,
    store: &Store,
    backend: &Arc<dyn StorageBackend>,
    ctx: &SecurityContext,
) -> (Uuid, Uuid, Uuid, MultipartPlan, Vec<u8>) {
    let ticket = svc.create_file(ctx, new_file(), None, false).await.unwrap();
    let file_id = ticket.file_id;

    let part_size = 5 * 1024 * 1024usize;
    let part1 = vec![b'a'; part_size];
    let part2 = vec![b'b'; part_size];
    let part3 = vec![b'c'; 4096];
    let mut full = Vec::new();
    full.extend_from_slice(&part1);
    full.extend_from_slice(&part2);
    full.extend_from_slice(&part3);
    let declared_size = full.len() as u64;

    let plan = msvc
        .initiate_multipart_upload(
            ctx,
            file_id,
            "application/octet-stream",
            declared_size,
            None,
            false,
        )
        .await
        .unwrap();

    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .unwrap()
        .expect("session");
    let backend_path = format!("/{file_id}/{}", plan.version_id);

    for part in &plan.parts {
        let data = match part.part_number {
            1 => Bytes::from(part1.clone()),
            2 => Bytes::from(part2.clone()),
            _ => Bytes::from(part3.clone()),
        };
        let len = data.len() as u64;
        let stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
            Box::pin(futures::stream::once(async move { Ok(data) }));
        let (etag, part_hash) = backend
            .upload_part_stream(
                &backend_path,
                &session.backend_upload_handle,
                part.part_number,
                part.offset,
                stream,
                len,
            )
            .await
            .unwrap();
        multipart_store
            .upsert_multipart_part(
                plan.upload_id,
                i32::try_from(part.part_number).unwrap(),
                &etag,
                part_hash,
                i64::try_from(part.size).unwrap(),
                time::OffsetDateTime::now_utc(),
            )
            .await
            .unwrap();
    }

    (file_id, plan.version_id, plan.upload_id, plan, full)
}

#[tokio::test]
async fn complete_multipart_issues_no_object_reread() {
    let db = build_db_with_dsn().await.0;
    let inner: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let (counting, reads) = CountingBackend::new(inner);
    let backend: Arc<dyn StorageBackend> = counting;
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let (svc, msvc, store) = services(&db, backends);
    let ctx = ctx(Uuid::now_v7());

    let (file_id, version_id, upload_id, _plan, _full) =
        drive_multipart(&svc, &msvc, &store, &backend, &ctx).await;

    let before = reads.load(Ordering::SeqCst);
    let _completed = msvc
        .complete_multipart_upload(&ctx, file_id, upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    let during_complete = reads.load(Ordering::SeqCst) - before;
    assert_eq!(
        during_complete, 0,
        "complete_multipart must not GetObject/re-read the assembled object (ADR-0006)"
    );

    // Sanity: the version really did land as multipart-composite.
    let version = store
        .get_version(file_id, version_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.hash_mode, "multipart-composite-sha256");
    assert_eq!(version.part_count, Some(3));
    assert!(
        store
            .get_version_manifest(version_id)
            .await
            .unwrap()
            .is_some(),
        "a multipart-composite version must have a manifest row"
    );
}

#[tokio::test]
async fn client_reverification_succeeds_and_detects_tampering() {
    let db = build_db_with_dsn().await.0;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let (svc, msvc, store) = services(&db, backends);
    let ctx = ctx(Uuid::now_v7());

    let (file_id, version_id, upload_id, _plan, full) =
        drive_multipart(&svc, &msvc, &store, &backend, &ctx).await;
    let _completed = msvc
        .complete_multipart_upload(&ctx, file_id, upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();

    let version = store
        .get_version(file_id, version_id)
        .await
        .unwrap()
        .unwrap();
    let manifest = store
        .get_version_manifest(version_id)
        .await
        .unwrap()
        .unwrap();

    let parsed_manifest = Manifest::from_wire_string(&manifest).unwrap();

    verify_content_hash(
        &full,
        HashMode::MultipartCompositeSha256,
        &version.hash_value,
        Some(&parsed_manifest),
    )
    .await
    .expect("re-verification must succeed on untampered content");

    let mut tampered = full.clone();
    tampered[10] ^= 0xff;
    let err = verify_content_hash(
        &tampered,
        HashMode::MultipartCompositeSha256,
        &version.hash_value,
        Some(&parsed_manifest),
    )
    .await
    .expect_err("a tampered first part must fail re-verification");
    assert!(matches!(err, DomainError::HashMismatch { .. }));

    let mut tampered_tail = full.clone();
    let last = tampered_tail.len() - 1;
    tampered_tail[last] ^= 0xff;
    assert!(
        verify_content_hash(
            &tampered_tail,
            HashMode::MultipartCompositeSha256,
            &version.hash_value,
            Some(&parsed_manifest),
        )
        .await
        .is_err(),
        "a tampered tail part must fail re-verification"
    );

    assert_eq!(
        parsed_manifest.root().as_slice(),
        version.hash_value.as_slice()
    );
    assert_eq!(hash::sha256(manifest.as_bytes()), version.hash_value);
}

#[tokio::test]
async fn client_reverification_succeeds_for_zero_byte_composite_object() {
    let digest = hash::digest_to_array(hash::sha256(b""));
    let manifest = Manifest::new(vec![ManifestEntry { offset: 0, digest }]).unwrap();
    let root = manifest.root().to_vec();

    verify_content_hash(
        &[],
        HashMode::MultipartCompositeSha256,
        &root,
        Some(&manifest),
    )
    .await
    .expect("a zero-byte composite object must re-verify against sha256(\"\")");
}

#[tokio::test]
async fn migrate_backend_verifies_multipart_composite_without_parts_rows() {
    let (db, dsn) = build_db_with_dsn().await;
    let src: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let dst: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem2"));
    let backends =
        BackendRegistry::new(vec![Arc::clone(&src), Arc::clone(&dst)], "mem").expect("registry");
    let (svc, msvc, store) = services(&db, backends);
    let ctx = ctx(Uuid::now_v7());

    let (file_id, version_id, upload_id, _plan, _full) =
        drive_multipart(&svc, &msvc, &store, &src, &ctx).await;
    let _completed = msvc
        .complete_multipart_upload(&ctx, file_id, upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();

    // Delete the multipart-session part rows: migrate_backend's verification must NOT depend on
    // them (ADR-0006 §4 — the manifest is the durable, self-contained record).
    let conn = Database::connect(&dsn).await.expect("raw connect");
    let deleted = conn
        .execute_raw(Statement::from_string(
            conn.get_database_backend(),
            "DELETE FROM multipart_upload_parts".to_owned(),
        ))
        .await
        .expect("delete parts");
    assert!(
        deleted.rows_affected() >= 1,
        "the test must actually delete the part rows it is proving are unnecessary"
    );

    conn.execute_raw(Statement::from_string(
        conn.get_database_backend(),
        "DELETE FROM file_versions WHERE status = 'pending'".to_owned(),
    ))
    .await
    .expect("delete leftover pending version");

    svc.migrate_backend(&ctx, file_id, "mem2")
        .await
        .expect("migrate must verify from object bytes + manifest row alone");

    let version = store
        .get_version(file_id, version_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(version.backend_id, "mem2");
    let manifest = store
        .get_version_manifest(version_id)
        .await
        .unwrap()
        .unwrap();
    let moved_len = dst.stat(&version.backend_path).await.unwrap().unwrap();
    let moved = read_all(&dst, &version.backend_path, moved_len).await;
    let parsed_manifest = Manifest::from_wire_string(&manifest).unwrap();
    verify_content_hash(
        &moved,
        HashMode::MultipartCompositeSha256,
        &version.hash_value,
        Some(&parsed_manifest),
    )
    .await
    .expect("destination copy must still verify against the manifest");
}

#[tokio::test]
async fn complete_result_snapshot_omits_manifest_but_replay_still_returns_it() {
    let (db, dsn) = build_db_with_dsn().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![Arc::clone(&backend)], "mem").expect("registry");
    let (svc, msvc, store) = services(&db, backends);
    let ctx = ctx(Uuid::now_v7());

    let (file_id, version_id, upload_id, _plan, _full) =
        drive_multipart(&svc, &msvc, &store, &backend, &ctx).await;

    let first = msvc
        .complete_multipart_upload(&ctx, file_id, upload_id, None)
        .await
        .unwrap()
        .unwrap_completed();
    assert!(
        first.manifest.is_some(),
        "a multipart-composite completion must return a manifest"
    );
    let canonical_manifest = store
        .get_version_manifest(version_id)
        .await
        .unwrap()
        .expect("version_hash_manifest row must exist for a composite version");
    assert_eq!(
        first.manifest.as_deref(),
        Some(canonical_manifest.as_str()),
        "the completion response's manifest must match the canonical version_hash_manifest row"
    );

    // Raw-SQL check of the persisted snapshot -- bypasses the domain layer, which never
    // deserializes an unknown `manifest` key back out, so this is the only way to see it really is
    // not written.
    let conn = Database::connect(&dsn).await.expect("raw connect");
    let row = conn
        .query_one_raw(Statement::from_string(
            conn.get_database_backend(),
            "SELECT complete_result FROM multipart_uploads".to_owned(),
        ))
        .await
        .expect("query complete_result")
        .expect("exactly one multipart_uploads row");
    let complete_result_json: String = row
        .try_get("", "complete_result")
        .expect("complete_result column must be non-NULL after a successful complete");
    assert!(
        !complete_result_json.contains("manifest"),
        "persisted complete_result JSON must not contain a manifest field: {complete_result_json}"
    );

    // Idempotent re-complete: must still return the correct manifest, even though the persisted
    // snapshot it replays from carries none.
    let replay = msvc
        .complete_multipart_upload(&ctx, file_id, upload_id, None)
        .await
        .expect("re-complete of a completed session must be idempotent")
        .unwrap_completed();
    assert_eq!(
        replay.manifest, first.manifest,
        "replay must return the same manifest as the original completion"
    );
}
