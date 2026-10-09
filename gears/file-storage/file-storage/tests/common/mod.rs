// Created: 2026-07-27 by Constructor Tech
// `dead_code` allowed: clippy checks each test binary separately and not all use every helper.
#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;

use bytes::Bytes;
use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::multipart::MultipartPlan;
use file_storage::domain::multipart_service::MultipartService;
use file_storage::domain::ports::MultipartStore;
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{BackendRegistry, InMemoryBackend, StorageBackend};
use file_storage::infra::signed_url::Issuer;
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::{NewFile, OwnerKind};
use futures::stream::{self, BoxStream};
use sea_orm_migration::MigratorTrait;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::SecurityContext;
use uuid::Uuid;

pub mod query_recorder;
use query_recorder::QueryRecorder;

pub const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

/// Plain migrated in-memory `DBProvider`, no recorder attached.
pub async fn test_db() -> Arc<DBProvider<DbError>> {
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

pub async fn test_db_with_recorder() -> (Arc<DBProvider<DbError>>, QueryRecorder) {
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let (recorder, callback) = QueryRecorder::attach();
    let db = toolkit_db::connect_db_with_metric_callback("sqlite::memory:", opts, callback)
        .await
        .expect("connect to in-memory SQLite with recorder");
    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .expect("run migrations");
    recorder.clear();
    (Arc::new(DBProvider::new(db)), recorder)
}

#[must_use]
pub fn make_ctx(tenant_id: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_tenant_id(tenant_id)
        .build()
        .expect("valid SecurityContext")
}

#[must_use]
pub fn new_file() -> NewFile {
    NewFile {
        owner_kind: OwnerKind::User,
        owner_id: Uuid::now_v7(),
        name: "audit.bin".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "application/octet-stream".to_owned(),
        custom_metadata: vec![],
    }
}

pub struct Services {
    pub svc: Arc<FileService>,
    pub msvc: Arc<MultipartService>,
    pub backend: Arc<dyn StorageBackend>,
    pub multipart_store: Arc<dyn MultipartStore>,
}

pub fn make_services(db: &Arc<DBProvider<DbError>>) -> (Arc<FileService>, Arc<MultipartService>) {
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let s = make_services_with_backends(db, vec![backend], "mem");
    (s.svc, s.msvc)
}

pub fn make_services_full(db: &Arc<DBProvider<DbError>>) -> Services {
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    make_services_with_backends(db, vec![backend], "mem")
}

pub fn make_services_with_backends(
    db: &Arc<DBProvider<DbError>>,
    backends: Vec<Arc<dyn StorageBackend>>,
    default_id: &str,
) -> Services {
    let backend = backends
        .iter()
        .find(|b| b.id() == default_id)
        .cloned()
        .unwrap_or_else(|| backends.first().cloned().expect("at least one backend"));
    let backends_reg = BackendRegistry::new(backends, default_id).expect("registry");
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
    let store = Store::new(Arc::clone(db));
    let multipart_store: Arc<dyn MultipartStore> = Arc::new(store.clone());
    let svc = Arc::new(FileService::new(
        store,
        backends_reg.clone(),
        Arc::clone(&issuer),
        Arc::clone(&authorizer),
        cfg,
        None,
        None,
    ));
    let msvc = Arc::new(MultipartService::new(
        Arc::clone(&multipart_store),
        backends_reg,
        Arc::clone(&authorizer),
        None,
        issuer,
        "http://sidecar.test".to_owned(),
        3600,
    ));
    Services {
        svc,
        msvc,
        backend,
        multipart_store,
    }
}

pub async fn read_all(backend: &Arc<dyn StorageBackend>, path: &str, expected_len: u64) -> Bytes {
    use futures::StreamExt;

    let mut stream = backend
        .get_stream(path, expected_len)
        .await
        .expect("get_stream");
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk.expect("chunk"));
    }
    Bytes::from(buf)
}

pub async fn write_all(backend: &Arc<dyn StorageBackend>, path: &str, bytes: Bytes) {
    let len = bytes.len() as u64;
    let stream: BoxStream<'static, std::io::Result<Bytes>> =
        Box::pin(stream::once(async move { Ok(bytes) }));
    backend
        .put_stream(path, stream, Some(len))
        .await
        .expect("put_stream");
}

fn one_shot_part_stream(data: Bytes) -> (BoxStream<'static, std::io::Result<Bytes>>, u64) {
    let len = data.len() as u64;
    (Box::pin(stream::once(async move { Ok(data) })), len)
}

pub async fn simulate_sidecar_put_part(
    multipart_store: &Arc<dyn MultipartStore>,
    backend: &Arc<dyn StorageBackend>,
    plan: &MultipartPlan,
    file_id: Uuid,
    part_number: u32,
    data: Bytes,
) {
    let part = plan
        .parts
        .iter()
        .find(|p| p.part_number == part_number)
        .unwrap_or_else(|| panic!("part {part_number} not in plan"));
    let session = multipart_store
        .get_multipart_upload(plan.upload_id)
        .await
        .expect("get_multipart_upload")
        .expect("session must exist");
    let backend_path = format!("/{file_id}/{}", plan.version_id);

    let (stream, len) = one_shot_part_stream(data);
    let (backend_etag, part_hash) = backend
        .upload_part_stream(
            &backend_path,
            &session.backend_upload_handle,
            part_number,
            part.offset,
            stream,
            len,
        )
        .await
        .expect("backend upload_part_stream");

    let size = i64::try_from(part.size).expect("part size fits in i64");
    let now = time::OffsetDateTime::now_utc();
    let part_number_i32 = i32::try_from(part_number).expect("part_number fits in i32");
    multipart_store
        .upsert_multipart_part(
            plan.upload_id,
            part_number_i32,
            &backend_etag,
            part_hash,
            size,
            now,
        )
        .await
        .expect("upsert_multipart_part");
}

pub async fn simulate_all_parts(
    multipart_store: &Arc<dyn MultipartStore>,
    backend: &Arc<dyn StorageBackend>,
    plan: &MultipartPlan,
    file_id: Uuid,
) {
    for part in plan.parts.clone() {
        let size = usize::try_from(part.size).expect("part size fits in usize");
        let data = Bytes::from(vec![0u8; size]);
        simulate_sidecar_put_part(
            multipart_store,
            backend,
            plan,
            file_id,
            part.part_number,
            data,
        )
        .await;
    }
}
