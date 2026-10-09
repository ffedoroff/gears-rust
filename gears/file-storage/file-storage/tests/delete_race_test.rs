//! Delete vs a concurrently added version, built deterministically at the `Store` level:
//! the racing version is committed first, then the delete runs. The delete must re-read the
//! version list inside its own transaction, not trust an earlier snapshot.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;

use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use uuid::Uuid;

use file_storage::domain::audit::{AuditEntry, AuditOperation, AuditOutcome, FileEvent};
use file_storage::domain::ports::DeleteVersionOutcome;
use file_storage::infra::backend::{InMemoryBackend, StorageBackend};
use file_storage::infra::storage::Store;
use file_storage::infra::storage::migrations::Migrator;
use file_storage_sdk::NewFile;

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn write_all(backend: &Arc<dyn StorageBackend>, path: &str, bytes: bytes::Bytes) {
    let len = bytes.len() as u64;
    let stream: futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>> =
        Box::pin(futures::stream::once(async move { Ok(bytes) }));
    backend
        .put_stream(path, stream, Some(len))
        .await
        .expect("put_stream");
}

async fn build_store() -> (Store, Arc<DBProvider<DbError>>) {
    let mut path = std::env::temp_dir();
    path.push(format!("cf-fs-delete-race-{}.db", Uuid::now_v7().simple()));
    let dsn = format!("sqlite://{}?mode=rwc", path.display());
    let opts = ConnectOpts {
        max_conns: Some(2),
        min_conns: Some(1),
        ..Default::default()
    };
    let conn = connect_db(&dsn, opts).await.expect("connect sqlite");
    run_migrations_for_testing(&conn, Migrator::migrations())
        .await
        .expect("migrations");
    let db: Arc<DBProvider<DbError>> = Arc::new(DBProvider::new(conn));
    (Store::new(Arc::clone(&db)), db)
}

fn new_file_req(owner_id: Uuid) -> NewFile {
    NewFile {
        owner_kind: file_storage_sdk::OwnerKind::User,
        owner_id,
        name: "doc.bin".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "application/octet-stream".to_owned(),
        custom_metadata: Vec::new(),
    }
}

fn audit(
    tenant_id: Uuid,
    file_id: Uuid,
    op: AuditOperation,
    detail: serde_json::Value,
) -> AuditEntry {
    AuditEntry {
        tenant_id,
        actor_kind: "user".to_owned(),
        actor_id: Uuid::now_v7(),
        file_id: Some(file_id),
        operation: op,
        outcome: AuditOutcome::Success,
        detail,
        occurred_at: OffsetDateTime::now_utc(),
    }
}

fn event(tenant_id: Uuid, owner_id: Uuid, file_id: Uuid) -> FileEvent {
    FileEvent {
        tenant_id,
        owner_id,
        file_id,
        event_type: "file.deleted".to_owned(),
        payload: serde_json::json!({ "version_count": 0 }),
    }
}

// The stale snapshot is taken before the racing version exists; the delete must not rely on it.
#[tokio::test]
async fn delete_file_collecting_versions_does_not_leak_a_concurrently_added_version_blob() {
    let (store, _db) = build_store().await;
    let backend: Arc<dyn StorageBackend> = Arc::new(InMemoryBackend::new("mem"));

    let tenant_id = Uuid::now_v7();
    let owner_id = Uuid::now_v7();
    let file_id = Uuid::now_v7();
    let v1 = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();

    store
        .create_file_with_pending_version(
            &new_file_req(owner_id),
            file_id,
            v1,
            tenant_id,
            "mem",
            &format!("/{file_id}/{v1}"),
            now,
            audit(
                tenant_id,
                file_id,
                AuditOperation::Create,
                serde_json::json!({}),
            ),
        )
        .await
        .expect("create file + v1");
    write_all(
        &backend,
        &format!("/{file_id}/{v1}"),
        bytes::Bytes::from_static(b"v1"),
    )
    .await;

    let stale_snapshot = store.list_versions(file_id).await.expect("stale snapshot");
    assert_eq!(
        stale_snapshot.len(),
        1,
        "the stale snapshot must not see the version inserted below -- this \
         is exactly what made the pre-fix code lose track of it"
    );

    // The race: a concurrent `presign_version` commits a second version for
    // the same file, after the stale snapshot above, before the delete runs.
    let v2 = Uuid::now_v7();
    store
        .insert_pending_version(
            file_id,
            v2,
            "application/octet-stream",
            "mem",
            &format!("/{file_id}/{v2}"),
            now,
        )
        .await
        .expect("insert v2 (the race)");
    write_all(
        &backend,
        &format!("/{file_id}/{v2}"),
        bytes::Bytes::from_static(b"v2"),
    )
    .await;

    let deleted = store
        .delete_file_collecting_versions(
            &toolkit_security::AccessScope::allow_all(),
            file_id,
            None,
            audit(
                tenant_id,
                file_id,
                AuditOperation::DeleteFile,
                serde_json::json!({ "version_count": 0 }),
            ),
            Some(event(tenant_id, owner_id, file_id)),
        )
        .await
        .expect("delete_file_collecting_versions must not error");

    assert!(deleted.removed, "the file row must be found and removed");
    let mut collected_ids: Vec<Uuid> = deleted.versions.iter().map(|v| v.version_id).collect();
    collected_ids.sort_unstable();
    let mut expected_ids = vec![v1, v2];
    expected_ids.sort_unstable();
    assert_eq!(
        collected_ids, expected_ids,
        "the collected version list must include the race version (v2), not \
         just the versions visible at the stale pre-transaction snapshot"
    );

    for v in &deleted.versions {
        backend
            .delete(&v.backend_path)
            .await
            .expect("best-effort delete");
    }
    for v in &deleted.versions {
        assert!(
            !backend.exists(&v.backend_path).await.unwrap(),
            "blob for {} must be gone -- no leaked backend storage",
            v.version_id
        );
    }
}

// A second version appears after the stale "only one version" count; only the requested one may go.
#[tokio::test]
async fn delete_version_or_whole_file_does_not_delete_the_file_when_a_second_version_races_in() {
    let (store, _db) = build_store().await;

    let tenant_id = Uuid::now_v7();
    let owner_id = Uuid::now_v7();
    let file_id = Uuid::now_v7();
    let v1 = Uuid::now_v7();
    let now = OffsetDateTime::now_utc();

    store
        .create_file_with_pending_version(
            &new_file_req(owner_id),
            file_id,
            v1,
            tenant_id,
            "mem",
            &format!("/{file_id}/{v1}"),
            now,
            audit(
                tenant_id,
                file_id,
                AuditOperation::Create,
                serde_json::json!({}),
            ),
        )
        .await
        .expect("create file + v1");

    let stale_snapshot = store.list_versions(file_id).await.expect("stale snapshot");
    assert_eq!(stale_snapshot.len(), 1, "only v1 exists at this point");

    let v2 = Uuid::now_v7();
    store
        .insert_pending_version(
            file_id,
            v2,
            "application/octet-stream",
            "mem",
            &format!("/{file_id}/{v2}"),
            now,
        )
        .await
        .expect("insert v2 (the race)");

    let scope = toolkit_security::AccessScope::allow_all();
    let outcome = store
        .delete_version_or_whole_file(
            file_id,
            v1,
            audit(
                tenant_id,
                file_id,
                AuditOperation::DeleteVersion,
                serde_json::json!({ "version_id": v1 }),
            ),
            audit(
                tenant_id,
                file_id,
                AuditOperation::DeleteFile,
                serde_json::json!({ "version_count": 1 }),
            ),
            Some(event(tenant_id, owner_id, file_id)),
        )
        .await
        .expect("delete_version_or_whole_file must not error");

    assert!(
        matches!(outcome, DeleteVersionOutcome::VersionRemoved(ref removed) if removed.version_id == v1),
        "expected VersionRemoved(v1) since a second version exists by the \
         time the transaction actually runs -- got {outcome:?}"
    );

    let file = store
        .get_file(&scope, file_id)
        .await
        .expect("get_file must not error");
    assert!(
        file.is_some(),
        "the file must survive -- v1 was NOT its only version by delete time"
    );
    let remaining_v2 = store
        .get_version(file_id, v2)
        .await
        .expect("get_version must not error");
    assert!(
        remaining_v2.is_some(),
        "v2 (the race version, never asked to be deleted) must still exist"
    );
    let removed_v1 = store
        .get_version(file_id, v1)
        .await
        .expect("get_version must not error");
    assert!(
        removed_v1.is_none(),
        "v1 (the requested version) must be gone"
    );
}
