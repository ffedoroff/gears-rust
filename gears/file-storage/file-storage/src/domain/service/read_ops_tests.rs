use std::sync::Arc;

use sea_orm_migration::MigratorTrait;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::SecurityContext;
use uuid::Uuid;

use crate::domain::authz::TenantOnlyAuthorizer;
use crate::domain::service::{FileService, ServiceConfig};
use crate::infra::backend::{BackendRegistry, InMemoryBackend, StorageBackend};
use crate::infra::signed_url::Issuer;
use crate::infra::storage::Store;
use crate::infra::storage::migrations::Migrator;
use file_storage_sdk::{CustomMetadataEntry, CustomMetadataPatch, NewFile, OwnerFilter, OwnerKind};

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn build_service() -> Arc<FileService> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-read-ops-test-{}.db",
        Uuid::now_v7().simple()
    ));
    let mut file = path.to_string_lossy().replace('\\', "/");
    if !file.starts_with('/') {
        file.insert(0, '/');
    }
    let dsn = format!("sqlite://{file}?mode=rwc");
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db(&dsn, opts).await.expect("connect sqlite");
    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .expect("migrations");
    let db: Arc<DBProvider<DbError>> = Arc::new(DBProvider::new(db));

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
    Arc::new(FileService::new(
        store, backends, issuer, authorizer, cfg, None, None,
    ))
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
        name: "doc.txt".to_owned(),
        gts_file_type: GTS.to_owned(),
        mime_type: "text/plain".to_owned(),
        custom_metadata: vec![CustomMetadataEntry {
            key: "tag".to_owned(),
            value: "a".to_owned(),
        }],
    }
}

#[tokio::test]
async fn list_files_returns_each_files_custom_metadata() {
    let svc = build_service().await;
    let ctx = ctx(Uuid::now_v7());
    let owner = Uuid::now_v7();

    let mut nf_a = new_file();
    nf_a.owner_id = owner;
    let file_a = svc.create_file(&ctx, nf_a, None, false).await.unwrap();
    svc.update_metadata(
        &ctx,
        file_a.file_id,
        CustomMetadataPatch {
            entries: vec![("tag".to_owned(), Some("a-value".to_owned()))],
        },
        None,
    )
    .await
    .unwrap();

    let mut nf_b = new_file();
    nf_b.owner_id = owner;
    let file_b = svc.create_file(&ctx, nf_b, None, false).await.unwrap();
    svc.update_metadata(
        &ctx,
        file_b.file_id,
        CustomMetadataPatch {
            entries: vec![("tag".to_owned(), Some("b-value".to_owned()))],
        },
        None,
    )
    .await
    .unwrap();

    let mut nf_c = new_file();
    nf_c.owner_id = owner;
    nf_c.custom_metadata = vec![];
    let file_c = svc.create_file(&ctx, nf_c, None, false).await.unwrap();

    let owner_filter = OwnerFilter {
        owner_kind: OwnerKind::User,
        owner_id: owner,
    };
    let files = svc
        .list_files(&ctx, owner_filter, Some(10), None)
        .await
        .unwrap()
        .items;
    assert_eq!(files.len(), 3, "sanity: all three files listed");

    let file_ids: Vec<Uuid> = files.iter().map(|f| f.file_id).collect();
    let mut batched = svc.list_metadata_for_files(&file_ids).await.unwrap();
    assert!(
        !batched.contains_key(&file_c.file_id),
        "a file with no custom metadata must have no entry in the batched map"
    );

    for file in &files {
        let (_f, expected) = svc
            .get_file_with_metadata(&ctx, file.file_id)
            .await
            .unwrap();
        let expected_map: std::collections::BTreeMap<_, _> =
            expected.into_iter().map(|e| (e.key, e.value)).collect();
        let got_map: std::collections::BTreeMap<_, _> = batched
            .remove(&file.file_id)
            .unwrap_or_default()
            .into_iter()
            .map(|e| (e.key, e.value))
            .collect();
        assert_eq!(
            got_map, expected_map,
            "batched metadata for {} must match get_file_with_metadata's",
            file.file_id
        );
    }
}
