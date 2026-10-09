#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use std::sync::Arc;

use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::{ConnectOpts, DBProvider, DbError, connect_db};
use toolkit_gts::gts_id;
use toolkit_security::AccessScope;
use uuid::Uuid;

use file_storage::infra::storage::migrations::Migrator;
use file_storage::infra::storage::repo::{FileRepo, VersionRepo};
use file_storage_sdk::{File, FileVersion, OwnerKind, VersionStatus};

const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");

async fn db() -> Arc<DBProvider<DbError>> {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "cf-fs-version-repo-test-{}.db",
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

fn new_file(file_id: Uuid, tenant_id: Uuid) -> File {
    let now = OffsetDateTime::now_utc();
    File {
        file_id,
        tenant_id,
        owner_kind: OwnerKind::User,
        owner_id: Uuid::now_v7(),
        name: "doc.txt".to_owned(),
        gts_file_type: GTS.to_owned(),
        content_id: None,
        meta_version: 0,
        created_at: now,
        last_modified_at: now,
    }
}

fn new_version(file_id: Uuid, version_id: Uuid, size: i64) -> FileVersion {
    let now = OffsetDateTime::now_utc();
    FileVersion {
        file_id,
        version_id,
        mime_type: "text/plain".to_owned(),
        size,
        hash_algorithm: "SHA-256".to_owned(),
        hash_value: vec![0u8; 32],
        hash_mode: "whole-sha256".to_owned(),
        part_count: None,
        status: VersionStatus::Available,
        is_current: false,
        backend_id: "mem".to_owned(),
        backend_path: format!("/{file_id}/{version_id}"),
        created_at: now,
        bound_on_finalize: false,
    }
}

/// A `pending` version row with explicit `created_at`, for the `list_pending_older_than` test.
fn new_pending_version(file_id: Uuid, version_id: Uuid, created_at: OffsetDateTime) -> FileVersion {
    FileVersion {
        file_id,
        version_id,
        mime_type: "text/plain".to_owned(),
        size: 0,
        hash_algorithm: "SHA-256".to_owned(),
        hash_value: vec![0u8; 32],
        hash_mode: "whole-sha256".to_owned(),
        part_count: None,
        status: VersionStatus::Pending,
        is_current: false,
        backend_id: "mem".to_owned(),
        backend_path: format!("/{file_id}/{version_id}"),
        created_at,
        bound_on_finalize: false,
    }
}

#[tokio::test]
async fn version_repo_get_returns_correct_row_among_many() {
    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let files = FileRepo::new();
    let versions = VersionRepo::new();

    let file_a = Uuid::now_v7();
    let file_b = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    files
        .create(&conn, &scope, &new_file(file_a, tenant))
        .await
        .expect("create file_a");
    files
        .create(&conn, &scope, &new_file(file_b, tenant))
        .await
        .expect("create file_b");

    let mut target: Option<Uuid> = None;
    for i in 0..5u8 {
        let vid = Uuid::now_v7();
        versions
            .insert(&conn, &scope, &new_version(file_a, vid, i64::from(i) * 10))
            .await
            .expect("insert file_a version");
        if i == 2 {
            target = Some(vid);
        }
    }
    for _ in 0..5u8 {
        let vid = Uuid::now_v7();
        versions
            .insert(&conn, &scope, &new_version(file_b, vid, 999))
            .await
            .expect("insert file_b version");
    }
    let target = target.expect("target version seeded");

    let found = versions
        .get(&conn, &scope, file_a, target)
        .await
        .expect("get must not error")
        .expect("target version must be found");
    assert_eq!(found.file_id, file_a);
    assert_eq!(found.version_id, target);
    assert_eq!(found.size, 20, "must be the i==2 row, not any other");

    let cross = versions
        .get(&conn, &scope, file_b, target)
        .await
        .expect("get must not error");
    assert!(
        cross.is_none(),
        "a version_id belonging to file_a must not resolve under file_b"
    );
}

/// `VersionRepo::get_manifests` must return every requested version's
/// manifest even when the id list spans more than one `max_bind_params_for`
/// chunk (30 000 on `SQLite`, minus `GET_MANIFESTS_RESERVED_PARAMS`).
#[tokio::test]
async fn get_manifests_returns_all_results_across_multiple_chunks() {
    use file_storage::infra::storage::entity::file::{
        ActiveModel as FileActiveModel, Entity as FileEntity,
    };
    use file_storage::infra::storage::entity::file_version::{
        ActiveModel as FileVersionActiveModel, Entity as FileVersionEntity,
    };
    use file_storage::infra::storage::entity::version_hash_manifest::{
        ActiveModel as ManifestActiveModel, Entity as ManifestEntity,
    };
    use sea_orm::Set;
    use toolkit_db::secure::secure_insert_many;

    const N: usize = 35_000;

    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let versions = VersionRepo::new();
    let now = OffsetDateTime::now_utc();
    let tenant_id = Uuid::now_v7();

    let version_ids: Vec<Uuid> = (0..N).map(|_| Uuid::now_v7()).collect();
    let file_ids: Vec<Uuid> = (0..N).map(|_| Uuid::now_v7()).collect();

    let file_models: Vec<FileActiveModel> = file_ids
        .iter()
        .map(|&file_id| FileActiveModel {
            file_id: Set(file_id),
            tenant_id: Set(tenant_id),
            owner_kind: Set("user".to_owned()),
            owner_id: Set(Uuid::now_v7()),
            name: Set("f.bin".to_owned()),
            gts_file_type: Set(GTS.to_owned()),
            content_id: Set(None),
            meta_version: Set(0),
            created_at: Set(now),
            last_modified_at: Set(now),
        })
        .collect();
    secure_insert_many::<FileEntity>(file_models, &scope, &conn)
        .await
        .expect("seed parent files rows");

    let version_models: Vec<FileVersionActiveModel> = file_ids
        .iter()
        .zip(version_ids.iter())
        .map(|(&file_id, &version_id)| FileVersionActiveModel {
            file_id: Set(file_id),
            version_id: Set(version_id),
            mime_type: Set("application/octet-stream".to_owned()),
            size: Set(1024),
            hash_algorithm: Set("SHA-256".to_owned()),
            hash_value: Set(vec![0u8; 32]),
            hash_mode: Set("multipart-composite-sha256".to_owned()),
            part_count: Set(Some(2)),
            status: Set("available".to_owned()),
            is_current: Set(false),
            backend_id: Set("mem".to_owned()),
            backend_path: Set(format!("/{file_id}/{version_id}")),
            created_at: Set(now),
            bound_on_finalize: Set(false),
            migration_lease_owner: Set(None),
            migration_lease_until: Set(None),
        })
        .collect();
    secure_insert_many::<FileVersionEntity>(version_models, &scope, &conn)
        .await
        .expect("seed parent file_versions rows");

    let models: Vec<ManifestActiveModel> = version_ids
        .iter()
        .map(|&version_id| ManifestActiveModel {
            version_id: Set(version_id),
            manifest: Set(format!("{{\"version_id\":\"{version_id}\"}}")),
            created_at: Set(now),
        })
        .collect();
    secure_insert_many::<ManifestEntity>(models, &scope, &conn)
        .await
        .expect("seed manifest rows");

    let manifests = versions
        .get_manifests(&conn, &scope, &version_ids)
        .await
        .expect("get_manifests must not error across chunk boundaries");

    assert_eq!(
        manifests.len(),
        N,
        "every seeded version_id must have a manifest entry back, regardless \
         of how many chunks the id list was split into"
    );
    for &version_id in &version_ids {
        assert_eq!(
            manifests.get(&version_id),
            Some(&format!("{{\"version_id\":\"{version_id}\"}}")),
            "manifest content must round-trip for {version_id}"
        );
    }
}

#[tokio::test]
async fn list_by_file_orders_by_created_at_then_version_id_so_paged_offsets_do_not_skip_or_repeat()
{
    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let files = FileRepo::new();
    let versions = VersionRepo::new();

    let file_id = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    files
        .create(&conn, &scope, &new_file(file_id, tenant))
        .await
        .expect("create file");

    let same_instant = OffsetDateTime::now_utc();
    let ids = [
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        Uuid::from_u128(3),
        Uuid::from_u128(4),
    ];
    for &version_id in &ids {
        versions
            .insert(
                &conn,
                &scope,
                &new_pending_version(file_id, version_id, same_instant),
            )
            .await
            .expect("insert version");
    }

    let page1 = versions
        .list_by_file(&conn, &scope, file_id, 2, 0)
        .await
        .expect("page 1");
    let page2 = versions
        .list_by_file(&conn, &scope, file_id, 2, 2)
        .await
        .expect("page 2");

    let mut seen: Vec<Uuid> = page1
        .iter()
        .chain(page2.iter())
        .map(|v| v.version_id)
        .collect();
    let mut expected = ids.to_vec();
    expected.sort_unstable_by(|a, b| b.cmp(a)); // version_id descending
    assert_eq!(
        seen, expected,
        "two OFFSET pages over four equal-created_at rows must together cover \
         every version_id exactly once, in version_id-descending order"
    );
    seen.dedup();
    assert_eq!(
        seen.len(),
        4,
        "no version_id may be repeated across the two pages"
    );
}

#[tokio::test]
async fn list_by_file_page_keyset_orders_by_created_at_then_version_id_with_no_skip_or_repeat() {
    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let files = FileRepo::new();
    let versions = VersionRepo::new();

    let file_id = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    files
        .create(&conn, &scope, &new_file(file_id, tenant))
        .await
        .expect("create file");

    let same_instant = OffsetDateTime::now_utc();
    let ids = [
        Uuid::from_u128(1),
        Uuid::from_u128(2),
        Uuid::from_u128(3),
        Uuid::from_u128(4),
    ];
    for &version_id in &ids {
        versions
            .insert(
                &conn,
                &scope,
                &new_pending_version(file_id, version_id, same_instant),
            )
            .await
            .expect("insert version");
    }

    let page1 = versions
        .list_by_file_page(&conn, &scope, file_id, 2, None)
        .await
        .expect("page 1");
    assert_eq!(page1.len(), 2);
    let last = page1.last().expect("page 1 non-empty");
    let after_pos = file_storage::domain::pagination::Seek {
        created_at: last.created_at,
        id: last.version_id,
        direction: file_storage::domain::pagination::Direction::Forward,
    };
    let page2 = versions
        .list_by_file_page(&conn, &scope, file_id, 2, Some(after_pos))
        .await
        .expect("page 2");
    let page3 = versions
        .list_by_file_page(&conn, &scope, file_id, 2, {
            let last = page2.last().expect("page 2 non-empty");
            Some(file_storage::domain::pagination::Seek {
                created_at: last.created_at,
                id: last.version_id,
                direction: file_storage::domain::pagination::Direction::Forward,
            })
        })
        .await
        .expect("page 3 (past the end)");

    let mut seen: Vec<Uuid> = page1
        .iter()
        .chain(page2.iter())
        .map(|v| v.version_id)
        .collect();
    let mut expected = ids.to_vec();
    expected.sort_unstable_by(|a, b| b.cmp(a)); // version_id descending
    assert_eq!(
        seen, expected,
        "two keyset pages over four equal-created_at rows must together cover \
         every version_id exactly once, in version_id-descending order"
    );
    seen.dedup();
    assert_eq!(seen.len(), 4, "no version_id may be repeated across pages");
    assert!(
        page3.is_empty(),
        "a keyset page starting past the last row must be empty, got {page3:?}"
    );
}

#[tokio::test]
async fn list_pending_older_than_caps_at_limit_and_orders_deterministically() {
    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let files = FileRepo::new();
    let versions = VersionRepo::new();

    let file_id = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    files
        .create(&conn, &scope, &new_file(file_id, tenant))
        .await
        .expect("create file");

    let base = OffsetDateTime::now_utc() - time::Duration::hours(10);
    let id_a = Uuid::from_u128(1);
    let id_b = Uuid::from_u128(11);
    let id_c = Uuid::from_u128(12);
    let id_d = Uuid::from_u128(99);

    versions
        .insert(&conn, &scope, &new_pending_version(file_id, id_a, base))
        .await
        .expect("insert a");
    versions
        .insert(
            &conn,
            &scope,
            &new_pending_version(file_id, id_c, base + time::Duration::seconds(1)),
        )
        .await
        .expect("insert c");
    versions
        .insert(
            &conn,
            &scope,
            &new_pending_version(file_id, id_b, base + time::Duration::seconds(1)),
        )
        .await
        .expect("insert b");
    versions
        .insert(
            &conn,
            &scope,
            &new_pending_version(file_id, id_d, base + time::Duration::seconds(2)),
        )
        .await
        .expect("insert d (newest, must be excluded by the limit)");

    let now = OffsetDateTime::now_utc();
    let older_than = now;
    let rows = versions
        .list_pending_older_than(&conn, &scope, older_than, now, 3, None)
        .await
        .expect("list_pending_older_than must not error");

    assert_eq!(
        rows.len(),
        3,
        "limit = 3 over 4 eligible candidates must return exactly 3 rows"
    );
    assert_eq!(
        rows.iter().map(|r| r.version_id).collect::<Vec<_>>(),
        vec![id_a, id_b, id_c],
        "rows must be ordered (created_at, version_id) ascending -- a first \
         (oldest), then b before c (same created_at, b's version_id is \
         smaller), and d (strictly newest) excluded by the limit"
    );
}

#[tokio::test]
async fn list_pending_older_than_after_cursor_excludes_seen_rows_including_created_at_tie() {
    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let files = FileRepo::new();
    let versions = VersionRepo::new();

    let file_id = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    files
        .create(&conn, &scope, &new_file(file_id, tenant))
        .await
        .expect("create file");

    let base = OffsetDateTime::now_utc() - time::Duration::hours(10);
    let id_a = Uuid::from_u128(1);
    let id_b = Uuid::from_u128(11);
    let id_c = Uuid::from_u128(12);
    let id_d = Uuid::from_u128(99);

    versions
        .insert(&conn, &scope, &new_pending_version(file_id, id_a, base))
        .await
        .expect("insert a");
    versions
        .insert(
            &conn,
            &scope,
            &new_pending_version(file_id, id_b, base + time::Duration::seconds(1)),
        )
        .await
        .expect("insert b");
    versions
        .insert(
            &conn,
            &scope,
            &new_pending_version(file_id, id_c, base + time::Duration::seconds(1)),
        )
        .await
        .expect("insert c (same created_at as b, larger version_id)");
    versions
        .insert(
            &conn,
            &scope,
            &new_pending_version(file_id, id_d, base + time::Duration::seconds(2)),
        )
        .await
        .expect("insert d (strictly newest)");

    let now = OffsetDateTime::now_utc();
    let older_than = now;

    let after = (base + time::Duration::seconds(1), id_b);
    let rows = versions
        .list_pending_older_than(&conn, &scope, older_than, now, 10, Some(after))
        .await
        .expect("list_pending_older_than with after must not error");

    assert_eq!(
        rows.iter().map(|r| r.version_id).collect::<Vec<_>>(),
        vec![id_c, id_d],
        "after = (b's created_at, b's version_id) must return only rows \
         strictly past that key: c (same created_at, larger version_id) and \
         d (strictly newer), never a, never b itself"
    );
}

#[tokio::test]
async fn insert_against_a_deleted_file_maps_foreign_key_violation_to_file_not_found() {
    let db = db().await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let files = FileRepo::new();
    let versions = VersionRepo::new();

    let file_id = Uuid::now_v7();
    let tenant = Uuid::now_v7();
    files
        .create(&conn, &scope, &new_file(file_id, tenant))
        .await
        .expect("create file");

    let removed = files
        .delete(&conn, &scope, file_id)
        .await
        .expect("delete must not error");
    assert!(removed, "the file row must have been removed");

    let version_id = Uuid::now_v7();
    let err = versions
        .insert(&conn, &scope, &new_version(file_id, version_id, 0))
        .await
        .expect_err("insert against a deleted file's file_id must fail");

    match err {
        file_storage::domain::error::DomainError::FileNotFound { id } => {
            assert_eq!(
                id, file_id,
                "the FileNotFound error must name the file_id the FK check failed against"
            );
        }
        other => panic!(
            "expected DomainError::FileNotFound (mapped from the foreign-key \
             violation), got: {other}"
        ),
    }
}
