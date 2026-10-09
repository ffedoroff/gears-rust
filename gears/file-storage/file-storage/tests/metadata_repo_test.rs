//! Repo-level test for `MetadataRepo::list_for_files`'s bind-parameter chunking (t25).

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;

use sea_orm::Set;
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::secure::secure_insert_many;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage::infra::storage::entity::custom_metadata::{
    ActiveModel as MetadataActiveModel, Entity as MetadataEntity,
};
use file_storage::infra::storage::entity::file::{
    ActiveModel as FileActiveModel, Entity as FileEntity,
};
use file_storage::infra::storage::migrations::Migrator;
use file_storage::infra::storage::repo::MetadataRepo;

async fn db() -> Arc<DBProvider<DbError>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-metadata-repo-test-{}.db",
        Uuid::now_v7().simple()
    ));
    let dsn = format!("sqlite://{}?mode=rwc", path.display());
    let opts = ConnectOpts {
        max_conns: Some(1),
        min_conns: Some(1),
        ..Default::default()
    };
    let conn = connect_db(&dsn, opts).await.expect("connect sqlite");
    run_migrations_for_testing(&conn, Migrator::migrations())
        .await
        .expect("migrations");
    Arc::new(DBProvider::new(conn))
}

#[tokio::test]
async fn list_for_files_returns_all_results_across_multiple_chunks() {
    const N: usize = 35_000;

    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let metadata = MetadataRepo::new();
    let now = OffsetDateTime::now_utc();
    let tenant_id = Uuid::now_v7();

    let file_ids: Vec<Uuid> = (0..N).map(|_| Uuid::now_v7()).collect();

    let file_models: Vec<FileActiveModel> = file_ids
        .iter()
        .map(|&file_id| FileActiveModel {
            file_id: Set(file_id),
            tenant_id: Set(tenant_id),
            owner_kind: Set("user".to_owned()),
            owner_id: Set(Uuid::now_v7()),
            name: Set("f.bin".to_owned()),
            gts_file_type: Set("cf.fstorage.file.type.v1~x.test.file.type.v1~".to_owned()),
            content_id: Set(None),
            meta_version: Set(0),
            created_at: Set(now),
            last_modified_at: Set(now),
        })
        .collect();
    secure_insert_many::<FileEntity>(file_models, &scope, &conn)
        .await
        .expect("seed parent files rows");

    let models: Vec<MetadataActiveModel> = file_ids
        .iter()
        .map(|&file_id| MetadataActiveModel {
            file_id: Set(file_id),
            key: Set("k".to_owned()),
            value: Set(format!("v-{file_id}")),
            set_at: Set(now),
        })
        .collect();
    secure_insert_many::<MetadataEntity>(models, &scope, &conn)
        .await
        .expect("seed custom_metadata rows");

    let grouped = metadata
        .list_for_files(&conn, &scope, &file_ids)
        .await
        .expect("list_for_files must not error across chunk boundaries");

    assert_eq!(
        grouped.len(),
        N,
        "every seeded file_id must have a metadata entry back, regardless \
         of how many chunks the id list was split into"
    );
    for &file_id in &file_ids {
        let entries = grouped
            .get(&file_id)
            .unwrap_or_else(|| panic!("missing metadata entry for {file_id}"));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "k");
        assert_eq!(entries[0].value, format!("v-{file_id}"));
    }
}
