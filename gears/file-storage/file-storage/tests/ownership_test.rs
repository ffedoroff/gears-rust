//! Ownership transfer: row update, audit row and file-events outbox, in one transaction.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;

use bytes::Bytes;
use sea_orm::{ConnectionTrait, Database};
use sea_orm_migration::MigratorTrait;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use file_storage::domain::authz::TenantOnlyAuthorizer;
use file_storage::domain::error::DomainError;
use file_storage::domain::service::{FileService, ServiceConfig};
use file_storage::infra::backend::{BackendRegistry, InMemoryBackend, StorageBackend};
use file_storage::infra::content::{hash, mime};
use file_storage::infra::signed_url::Issuer;
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::{NewFile, OwnerKind};

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

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn build_db() -> Arc<DBProvider<DbError>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-ownership-test-{}.db",
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

async fn build_service() -> (Arc<FileService>, TestDataPlane, Store) {
    let db = build_db().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![backend], "mem").expect("registry");
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authorizer = Arc::new(TenantOnlyAuthorizer);
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
        issuer,
        authorizer,
        cfg,
        None,
        None,
    ));
    let dp = TestDataPlane::new(Arc::clone(&svc), store.clone(), backends);
    (svc, dp, store)
}

fn ctx(tenant: Uuid) -> SecurityContext {
    SecurityContext::builder()
        .subject_id(Uuid::now_v7())
        .subject_tenant_id(tenant)
        .build()
        .expect("ctx")
}

fn new_file_for(owner_id: Uuid) -> NewFile {
    NewFile {
        owner_kind: OwnerKind::User,
        owner_id,
        name: "transfer-test.txt".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "text/plain".to_owned(),
        custom_metadata: vec![],
    }
}

#[tokio::test]
async fn transfer_ownership_updates_owner_fields() {
    let (svc, _dp, _store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    let (updated, _meta) = svc
        .transfer_ownership(&ctx, file_id, OwnerKind::App, new_owner)
        .await
        .unwrap();

    assert_eq!(
        updated.owner_kind.as_str(),
        "app",
        "owner_kind must be updated to 'app'"
    );
    assert_eq!(updated.owner_id, new_owner, "owner_id must be updated");
    assert_eq!(updated.file_id, file_id, "file_id must remain unchanged");
    assert_eq!(updated.tenant_id, tenant, "tenant_id must remain unchanged");
}

#[tokio::test]
async fn transfer_ownership_leaves_audit_row() {
    let (svc, _dp, store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    svc.transfer_ownership(&ctx, file_id, OwnerKind::App, new_owner)
        .await
        .unwrap();

    let audit_rows = store.list_audit(file_id).await.unwrap();
    let transfer_rows: Vec<_> = audit_rows
        .iter()
        .filter(|r| r.operation == "transfer_ownership")
        .collect();
    assert_eq!(
        transfer_rows.len(),
        1,
        "expected exactly 1 transfer_ownership audit row"
    );
    let row = transfer_rows[0];
    assert_eq!(row.outcome, "success");
    assert_eq!(row.file_id, Some(file_id));
}

#[tokio::test]
async fn transfer_ownership_enqueues_file_event() {
    let (svc, _dp, store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    svc.transfer_ownership(&ctx, file_id, OwnerKind::App, new_owner)
        .await
        .unwrap();

    let events = store.list_file_events(file_id).await.unwrap();
    let transfer_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "file.owner_transferred")
        .collect();
    assert_eq!(
        transfer_events.len(),
        1,
        "expected exactly 1 file.owner_transferred event"
    );
    let ev = transfer_events[0];
    assert_eq!(ev.file_id, file_id);
    assert_eq!(
        ev.owner_id, new_owner,
        "event owner_id must be the new owner"
    );
    assert_eq!(ev.tenant_id, tenant);
    assert!(ev.published_at.is_none(), "event must not be published yet");
}

#[tokio::test]
async fn create_file_enqueues_created_event() {
    let (svc, _dp, store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    let events = store.list_file_events(file_id).await.unwrap();
    let created_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "file.created")
        .collect();
    assert_eq!(
        created_events.len(),
        1,
        "expected exactly 1 file.created event"
    );
    assert_eq!(created_events[0].file_id, file_id);
    assert_eq!(created_events[0].owner_id, owner);
    assert!(created_events[0].published_at.is_none());
}

#[tokio::test]
async fn delete_file_enqueues_deleted_event() {
    let (svc, dp, store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    // Finalize so the ETag exists for the If-Match delete.
    dp.put_content(
        &ctx,
        file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"hello"),
    )
    .await
    .unwrap();
    svc.bind(&ctx, file_id, ticket.version_id, None)
        .await
        .unwrap();

    let file = svc.get_file(&ctx, file_id).await.unwrap();
    let etag = file_storage::domain::etag::etag_for(&file);

    svc.delete_file(&ctx, file_id, etag.as_deref())
        .await
        .unwrap();

    // Outbox rows survive file deletion (no FK cascade).
    let events = store.list_file_events(file_id).await.unwrap();
    let deleted_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "file.deleted")
        .collect();
    assert_eq!(
        deleted_events.len(),
        1,
        "expected exactly 1 file.deleted event"
    );
    assert_eq!(deleted_events[0].file_id, file_id);
}

#[tokio::test]
async fn bind_enqueues_content_updated_event() {
    let (svc, dp, store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    dp.put_content(
        &ctx,
        file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"hello"),
    )
    .await
    .unwrap();

    svc.bind(&ctx, file_id, ticket.version_id, None)
        .await
        .unwrap();

    let events = store.list_file_events(file_id).await.unwrap();
    let content_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "file.content_updated")
        .collect();
    assert_eq!(
        content_events.len(),
        1,
        "expected exactly 1 file.content_updated event"
    );
    assert_eq!(content_events[0].file_id, file_id);
    assert_eq!(content_events[0].owner_id, owner);
}

#[tokio::test]
async fn transfer_ownership_non_existent_file_returns_not_found() {
    let (svc, _dp, _store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let phantom_id = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let err = svc
        .transfer_ownership(&ctx, phantom_id, OwnerKind::User, new_owner)
        .await
        .unwrap_err();

    assert!(
        matches!(err, DomainError::FileNotFound { id } if id == phantom_id),
        "expected FileNotFound, got: {err:?}"
    );
}

/// If the update finds no row, neither an audit row nor an event row is written.
#[tokio::test]
async fn transfer_ownership_no_row_means_no_audit_and_no_event() {
    let (svc, _dp, store) = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let phantom_id = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    drop(
        svc.transfer_ownership(&ctx, phantom_id, OwnerKind::User, new_owner)
            .await,
    );

    let audit_rows = store.list_audit(phantom_id).await.unwrap();
    let event_rows = store.list_file_events(phantom_id).await.unwrap();

    assert!(
        audit_rows.is_empty(),
        "no audit rows must be written for a phantom file"
    );
    assert!(
        event_rows.is_empty(),
        "no event rows must be written for a phantom file"
    );
}

/// No principal directory is wired in, so only the nil UUID is rejected as a malformed owner.
#[tokio::test]
async fn transfer_to_malformed_owner_is_rejected() {
    let (svc, _dp, _store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    let err = svc
        .transfer_ownership(&ctx, file_id, OwnerKind::App, Uuid::nil())
        .await
        .unwrap_err();

    assert!(
        matches!(err, DomainError::Validation { ref field, .. } if field == "new_owner_id"),
        "expected a new_owner_id validation error, got: {err:?}"
    );

    let file = svc.get_file(&ctx, file_id).await.unwrap();
    assert_eq!(file.owner_id, original_owner);
    assert_eq!(file.owner_kind.as_str(), "user");
}

#[tokio::test]
async fn transfer_to_same_tenant_member_succeeds() {
    let (svc, _dp, _store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    let (updated, _meta) = svc
        .transfer_ownership(&ctx, file_id, OwnerKind::User, new_owner)
        .await
        .unwrap();

    assert_eq!(updated.owner_id, new_owner);
    assert_eq!(
        updated.tenant_id, tenant,
        "the transferred file stays in the caller's tenant"
    );
}

/// The transfer response must reflect the committed state (re-read after the transaction), not the
/// pre-transfer snapshot patched in memory.
#[tokio::test]
async fn transfer_ownership_response_reflects_committed_swap() {
    let (svc, _dp, store) = build_service().await;
    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;
    let before = svc.get_file(&ctx, file_id).await.unwrap();

    // Bump `meta_version` and attach metadata first, so a stale-snapshot response is
    // distinguishable.
    svc.update_metadata(
        &ctx,
        file_id,
        file_storage_sdk::CustomMetadataPatch {
            entries: vec![("k1".to_owned(), Some("v1".to_owned()))],
        },
        None,
    )
    .await
    .unwrap();

    let (updated, updated_meta) = svc
        .transfer_ownership(&ctx, file_id, OwnerKind::App, new_owner)
        .await
        .unwrap();

    assert_eq!(updated.owner_kind.as_str(), "app");
    assert_eq!(updated.owner_id, new_owner);
    assert!(
        updated.last_modified_at >= before.last_modified_at,
        "last_modified_at must be bumped (or at least not regress) by the transfer"
    );
    assert!(
        updated.meta_version > before.meta_version,
        "meta_version must reflect the pre-transfer metadata update, not the original snapshot"
    );

    let tenant_scope = toolkit_security::AccessScope::for_tenant(tenant);
    let reread = store.require_file(&tenant_scope, file_id).await.unwrap();
    assert_eq!(reread.owner_id, updated.owner_id);
    assert_eq!(reread.owner_kind, updated.owner_kind);
    assert_eq!(reread.last_modified_at, updated.last_modified_at);
    assert_eq!(reread.meta_version, updated.meta_version);
    assert_eq!(reread.content_id, updated.content_id);

    let stored_meta = store.list_metadata(file_id).await.unwrap();
    assert!(
        !stored_meta.is_empty(),
        "test setup must have written metadata"
    );
    assert_eq!(updated_meta, stored_meta);
}

/// If a concurrent `DELETE` removes the file between the transfer's commit and its re-read, the
/// call
/// must surface `FileNotFound`, not a stale patched snapshot.
/// The race is simulated deterministically with a `SQLite` trigger that deletes the row inside the
/// ownership `UPDATE` itself (`AFTER UPDATE OF owner_id` does not fire on the initial insert).
#[tokio::test]
async fn transfer_ownership_returns_not_found_when_file_deleted_mid_transfer() {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-ownership-race-test-{}.db",
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
    let db = Arc::new(DBProvider::new(db));

    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));
    let backends = BackendRegistry::new(vec![backend], "mem").expect("registry");
    let issuer = Arc::new(Issuer::generate(3600).expect("issuer"));
    let authorizer = Arc::new(TenantOnlyAuthorizer);
    let cfg = ServiceConfig {
        default_url_ttl_secs: 3600,
        sidecar_base_url: "http://sidecar.test".to_owned(),
        default_page_size: 50,
        max_page_size: 1000,
        idempotency_ttl_secs: 86400,
    };
    let store = Store::new(Arc::clone(&db));
    let svc = Arc::new(FileService::new(
        store, backends, issuer, authorizer, cfg, None, None,
    ));

    let tenant = Uuid::now_v7();
    let ctx = ctx(tenant);
    let original_owner = Uuid::now_v7();
    let new_owner = Uuid::now_v7();

    let ticket = svc
        .create_file(&ctx, new_file_for(original_owner), None, false)
        .await
        .unwrap();
    let file_id = ticket.file_id;

    // A separate raw connection, used only to install the race-simulating trigger.
    let conn = Database::connect(&dsn).await.expect("raw connect");
    conn.execute_unprepared(
        "CREATE TRIGGER trg_delete_after_owner_transfer \
         AFTER UPDATE OF owner_id ON files \
         FOR EACH ROW \
         BEGIN DELETE FROM files WHERE file_id = NEW.file_id; END;",
    )
    .await
    .expect("install race-simulating trigger");

    let result = svc
        .transfer_ownership(&ctx, file_id, OwnerKind::App, new_owner)
        .await;

    assert!(
        matches!(result, Err(DomainError::FileNotFound { .. })),
        "a file deleted between the transfer's commit and its post-commit re-read must \
         surface FileNotFound, not a patched stale success: {result:?}"
    );
}
