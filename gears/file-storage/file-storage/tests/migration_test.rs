#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Statement};
use sea_orm_migration::MigratorTrait;
use toolkit_gts::gts_id;

use file_storage::Migrator;

const TENANT: &str = "00000000-0000-0000-0000-0000000000a1";
const OWNER: &str = "00000000-0000-0000-0000-0000000000b1";
const FILE: &str = "00000000-0000-0000-0000-0000000000c1";
const VERSION: &str = "00000000-0000-0000-0000-0000000000d1";
const GTS: &str = gts_id!("cf.fstorage.file.type.v1~x.test.file.type.v1~");
/// 32 zero bytes — the only hash length the `SHA-256` CHECK accepts.
const HASH32: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn stmt(db: &DatabaseConnection, sql: impl Into<String>) -> Statement {
    Statement::from_string(db.get_database_backend(), sql.into())
}

/// Fresh in-memory SQLite with the initial migration applied and FK enforcement on
/// (SQLite leaves foreign keys off by default, so cascade would silently no-op).
async fn migrated_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    db.execute_raw(stmt(&db, "PRAGMA foreign_keys = ON;"))
        .await
        .expect("enable foreign keys");
    Migrator::up(&db, None).await.expect("apply P1 migration");
    db
}

async fn insert_file(db: &DatabaseConnection, file_id: &str) {
    db.execute_raw(stmt(
        db,
        format!(
            "INSERT INTO files (file_id, tenant_id, owner_kind, owner_id, name, gts_file_type) \
             VALUES ('{file_id}', '{TENANT}', 'user', '{OWNER}', 'doc.txt', '{GTS}')"
        ),
    ))
    .await
    .expect("insert file");
}

async fn insert_version(db: &DatabaseConnection, file_id: &str, version_id: &str, is_current: u8) {
    db.execute_raw(stmt(
        db,
        format!(
            "INSERT INTO file_versions \
             (file_id, version_id, mime_type, size, hash_value, status, is_current, backend_id, backend_path) \
             VALUES ('{file_id}', '{version_id}', 'text/plain', 0, X'{HASH32}', 'available', {is_current}, 'local', '/{file_id}/{version_id}')"
        ),
    ))
    .await
    .expect("insert version");
}

async fn count(db: &DatabaseConnection, sql: &str) -> i64 {
    db.query_one_raw(stmt(db, sql))
        .await
        .expect("count query")
        .expect("one row")
        .try_get::<i64>("", "c")
        .expect("i64 column c")
}

#[tokio::test]
async fn migration_creates_all_three_tables() {
    let db = migrated_db().await;
    for table in ["files", "file_versions", "files_custom_metadata"] {
        let probe = db
            .execute_raw(stmt(&db, format!("SELECT * FROM {table} LIMIT 0")))
            .await;
        assert!(
            probe.is_ok(),
            "table {table} must exist after up: {probe:?}"
        );
    }
}

#[tokio::test]
async fn migration_up_down_up_roundtrip() {
    let db = migrated_db().await;

    let auto_bind_before_down = db
        .execute_raw(stmt(&db, "SELECT auto_bind FROM multipart_uploads LIMIT 0"))
        .await;
    assert!(
        auto_bind_before_down.is_ok(),
        "sanity: auto_bind must exist on the fully-migrated schema: {auto_bind_before_down:?}"
    );

    Migrator::down(&db, None).await.expect("roll back");
    let gone = db
        .execute_raw(stmt(&db, "SELECT * FROM files LIMIT 0"))
        .await;
    assert!(gone.is_err(), "files must be dropped by down(): {gone:?}");

    Migrator::up(&db, None).await.expect("re-apply");
    let back = db
        .execute_raw(stmt(&db, "SELECT * FROM files LIMIT 0"))
        .await;
    assert!(back.is_ok(), "files must exist again after re-up: {back:?}");
}

#[tokio::test]
async fn upload_flow_redesign_down_actually_drops_the_new_columns_and_indexes() {
    let db = migrated_db().await;

    let before = db
        .execute_raw(stmt(&db, "SELECT auto_bind FROM multipart_uploads LIMIT 0"))
        .await;
    assert!(
        before.is_ok(),
        "auto_bind must exist after the full up(): {before:?}"
    );
    let backend_cols_before = db
        .execute_raw(stmt(
            &db,
            "SELECT backend_id, backend_path FROM multipart_uploads LIMIT 0",
        ))
        .await;
    assert!(
        backend_cols_before.is_ok(),
        "backend_id/backend_path must exist after the full up(): {backend_cols_before:?}"
    );
    let bound_on_finalize_before = db
        .execute_raw(stmt(
            &db,
            "SELECT bound_on_finalize FROM file_versions LIMIT 0",
        ))
        .await;
    assert!(
        bound_on_finalize_before.is_ok(),
        "bound_on_finalize must exist after the full up(): {bound_on_finalize_before:?}"
    );
    let migration_lease_cols_before = db
        .execute_raw(stmt(
            &db,
            "SELECT migration_lease_owner, migration_lease_until FROM file_versions LIMIT 0",
        ))
        .await;
    assert!(
        migration_lease_cols_before.is_ok(),
        "migration_lease_owner/migration_lease_until must exist after the full up(): \
         {migration_lease_cols_before:?}"
    );
    assert!(index_exists(&db, "files_owner_listing_v2_idx").await);
    assert!(!index_exists(&db, "files_owner_listing_idx").await);
    assert!(index_exists(&db, "retention_rules_tenant_listing_idx").await);
    assert!(!index_exists(&db, "file_versions_backend_idx").await);

    // The last two migrations: listing_indexes (the listing indexes), then upload_flow_redesign.
    Migrator::down(&db, Some(2))
        .await
        .expect("roll back listing_indexes and upload_flow_redesign");

    let after_down = db
        .execute_raw(stmt(&db, "SELECT auto_bind FROM multipart_uploads LIMIT 0"))
        .await;
    assert!(
        after_down.is_err(),
        "auto_bind must be gone after a real (non-no-op) down(): {after_down:?}"
    );
    let backend_cols_after_down = db
        .execute_raw(stmt(
            &db,
            "SELECT backend_id, backend_path FROM multipart_uploads LIMIT 0",
        ))
        .await;
    assert!(
        backend_cols_after_down.is_err(),
        "backend_id/backend_path must be gone after a real (non-no-op) down(): \
         {backend_cols_after_down:?}"
    );
    let bound_on_finalize_after_down = db
        .execute_raw(stmt(
            &db,
            "SELECT bound_on_finalize FROM file_versions LIMIT 0",
        ))
        .await;
    assert!(
        bound_on_finalize_after_down.is_err(),
        "bound_on_finalize must be gone after a real (non-no-op) down(): \
         {bound_on_finalize_after_down:?}"
    );
    let migration_lease_cols_after_down = db
        .execute_raw(stmt(
            &db,
            "SELECT migration_lease_owner, migration_lease_until FROM file_versions LIMIT 0",
        ))
        .await;
    assert!(
        migration_lease_cols_after_down.is_err(),
        "migration_lease_owner/migration_lease_until must be gone after a real (non-no-op) \
         down(): {migration_lease_cols_after_down:?}"
    );
    assert!(
        !index_exists(&db, "files_owner_listing_v2_idx").await,
        "files_owner_listing_v2_idx must be dropped by down()"
    );
    assert!(
        index_exists(&db, "files_owner_listing_idx").await,
        "files_owner_listing_idx must be recreated by down()"
    );
    assert!(!index_exists(&db, "idempotency_keys_file_idx").await);
    assert!(!index_exists(&db, "multipart_uploads_sweep_idx").await);
    assert!(!index_exists(&db, "files_versionless_sweep_idx").await);
    assert!(!index_exists(&db, "file_versions_file_created_idx").await);
    assert!(
        !index_exists(&db, "retention_rules_tenant_listing_idx").await,
        "retention_rules_tenant_listing_idx must be dropped by down()"
    );
    assert!(
        index_exists(&db, "file_versions_backend_idx").await,
        "file_versions_backend_idx must be recreated by down()"
    );

    Migrator::up(&db, Some(2))
        .await
        .expect("re-apply upload_flow_redesign and listing_indexes");
    let after_up = db
        .execute_raw(stmt(&db, "SELECT auto_bind FROM multipart_uploads LIMIT 0"))
        .await;
    assert!(
        after_up.is_ok(),
        "auto_bind must exist again after re-up(): {after_up:?}"
    );
    let backend_cols_after_up = db
        .execute_raw(stmt(
            &db,
            "SELECT backend_id, backend_path FROM multipart_uploads LIMIT 0",
        ))
        .await;
    assert!(
        backend_cols_after_up.is_ok(),
        "backend_id/backend_path must exist again after re-up(): {backend_cols_after_up:?}"
    );
    let bound_on_finalize_after_up = db
        .execute_raw(stmt(
            &db,
            "SELECT bound_on_finalize FROM file_versions LIMIT 0",
        ))
        .await;
    assert!(
        bound_on_finalize_after_up.is_ok(),
        "bound_on_finalize must exist again after re-up(): {bound_on_finalize_after_up:?}"
    );
    let migration_lease_cols_after_up = db
        .execute_raw(stmt(
            &db,
            "SELECT migration_lease_owner, migration_lease_until FROM file_versions LIMIT 0",
        ))
        .await;
    assert!(
        migration_lease_cols_after_up.is_ok(),
        "migration_lease_owner/migration_lease_until must exist again after re-up(): \
         {migration_lease_cols_after_up:?}"
    );
    assert!(index_exists(&db, "files_owner_listing_v2_idx").await);
    assert!(!index_exists(&db, "files_owner_listing_idx").await);
    assert!(index_exists(&db, "retention_rules_tenant_listing_idx").await);
    assert!(!index_exists(&db, "file_versions_backend_idx").await);
}

const UPLOAD_NO_VERSION: &str = "00000000-0000-0000-0000-0000000000f3";
const ORPHAN_VERSION: &str = "00000000-0000-0000-0000-0000000000f4";

#[tokio::test]
async fn upload_flow_redesign_backfills_backend_id_and_path_from_matching_version() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    db.execute_raw(stmt(&db, "PRAGMA foreign_keys = ON;"))
        .await
        .expect("enable foreign keys");

    // Every migration up to (not including) upload_flow_redesign -- the "old"
    // schema, before backend_id/backend_path existed on multipart_uploads.
    Migrator::up(&db, Some(7))
        .await
        .expect("apply every migration up to (not including) upload_flow_redesign");

    insert_file(&db, FILE).await;
    insert_version(&db, FILE, VERSION, 1).await;

    // A session whose version_id matches the file_versions row just
    // inserted -- must be backfilled from it.
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO multipart_uploads \
             (upload_id, file_id, version_id, backend_upload_handle, declared_mime, expires_at) \
             VALUES ('{UPLOAD}', '{FILE}', '{VERSION}', 'handle-1', 'text/plain', '2999-01-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert multipart session with a matching version, before the backfill migration");

    // A second session whose version_id has NO matching file_versions row --
    // must stay NULL after the backfill.
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO multipart_uploads \
             (upload_id, file_id, version_id, backend_upload_handle, declared_mime, expires_at) \
             VALUES ('{UPLOAD_NO_VERSION}', '{FILE}', '{ORPHAN_VERSION}', 'handle-2', \
             'text/plain', '2999-01-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert multipart session with no matching version, before the backfill migration");

    Migrator::up(&db, None)
        .await
        .expect("apply the remaining migration (upload_flow_redesign)");

    let row = db
        .query_one_raw(stmt(
            &db,
            format!(
                "SELECT backend_id AS bid, backend_path AS bpath FROM multipart_uploads \
                 WHERE upload_id = '{UPLOAD}'"
            ),
        ))
        .await
        .expect("query")
        .expect("one row");
    assert_eq!(
        row.try_get::<String>("", "bid").expect("backend_id"),
        "local",
        "backend_id must be backfilled from the matching file_versions row"
    );
    assert_eq!(
        row.try_get::<String>("", "bpath").expect("backend_path"),
        format!("/{FILE}/{VERSION}"),
        "backend_path must be backfilled from the matching file_versions row"
    );

    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM multipart_uploads WHERE upload_id = '{UPLOAD_NO_VERSION}' \
                 AND backend_id IS NULL AND backend_path IS NULL"
            )
        )
        .await,
        1,
        "a session with no matching version must be left NULL, not backfilled"
    );
}

#[tokio::test]
async fn upload_flow_redesign_backfills_bound_on_finalize_false_for_existing_version() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    db.execute_raw(stmt(&db, "PRAGMA foreign_keys = ON;"))
        .await
        .expect("enable foreign keys");

    // Every migration up to (not including) upload_flow_redesign -- the "old"
    // schema, before bound_on_finalize existed on file_versions.
    Migrator::up(&db, Some(7))
        .await
        .expect("apply every migration up to (not including) upload_flow_redesign");

    insert_file(&db, FILE).await;
    insert_version(&db, FILE, VERSION, 1).await;

    Migrator::up(&db, None)
        .await
        .expect("apply the remaining migration (upload_flow_redesign)");

    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM file_versions WHERE version_id = '{VERSION}' \
                 AND bound_on_finalize = 0"
            )
        )
        .await,
        1,
        "a version that existed before this migration must default bound_on_finalize to false"
    );
}

const FILE2: &str = "00000000-0000-0000-0000-0000000000c2";
const DELETED_FILE: &str = "00000000-0000-0000-0000-0000000000c3";
const RULE_FILE_LIVE: &str = "00000000-0000-0000-0000-0000000000e1";
const RULE_FILE_DANGLING: &str = "00000000-0000-0000-0000-0000000000e2";
const RULE_TENANT: &str = "00000000-0000-0000-0000-0000000000e3";
const RULE_USER: &str = "00000000-0000-0000-0000-0000000000e4";
const USER_OWNER: &str = "00000000-0000-0000-0000-0000000000b2";

async fn insert_retention_rule(
    db: &DatabaseConnection,
    rule_id: &str,
    scope: &str,
    scope_target_id: Option<&str>,
) {
    let target_sql = scope_target_id.map_or("NULL".to_owned(), |id| format!("'{id}'"));
    db.execute_raw(stmt(
        db,
        format!(
            "INSERT INTO retention_rules (rule_id, tenant_id, scope, scope_target_id, body) \
             VALUES ('{rule_id}', '{TENANT}', '{scope}', {target_sql}, '{{}}')"
        ),
    ))
    .await
    .expect("insert retention rule");
}

#[tokio::test]
async fn upload_flow_redesign_deletes_only_dangling_file_scope_retention_rules() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    db.execute_raw(stmt(&db, "PRAGMA foreign_keys = ON;"))
        .await
        .expect("enable foreign keys");

    Migrator::up(&db, Some(7))
        .await
        .expect("apply every migration up to (not including) upload_flow_redesign");

    insert_file(&db, FILE2).await;

    insert_retention_rule(&db, RULE_FILE_LIVE, "file", Some(FILE2)).await;
    insert_retention_rule(&db, RULE_FILE_DANGLING, "file", Some(DELETED_FILE)).await;
    insert_retention_rule(&db, RULE_TENANT, "tenant", None).await;
    insert_retention_rule(&db, RULE_USER, "user", Some(USER_OWNER)).await;

    Migrator::up(&db, None)
        .await
        .expect("apply the remaining migration (upload_flow_redesign)");

    let remaining_ids: Vec<String> = {
        let rows = db
            .query_all_raw(stmt(
                &db,
                "SELECT rule_id AS id FROM retention_rules ORDER BY rule_id",
            ))
            .await
            .expect("query remaining rules");
        rows.iter()
            .map(|r| r.try_get::<String>("", "id").expect("rule_id"))
            .collect()
    };

    assert!(
        remaining_ids.contains(&RULE_FILE_LIVE.to_owned()),
        "a File-scope rule on a file that still exists must survive: {remaining_ids:?}"
    );
    assert!(
        !remaining_ids.contains(&RULE_FILE_DANGLING.to_owned()),
        "a File-scope rule on an already-deleted file must be removed: {remaining_ids:?}"
    );
    assert!(
        remaining_ids.contains(&RULE_TENANT.to_owned()),
        "a Tenant-scope rule must never be touched by this cleanup: {remaining_ids:?}"
    );
    assert!(
        remaining_ids.contains(&RULE_USER.to_owned()),
        "a User-scope rule must never be touched by this cleanup: {remaining_ids:?}"
    );
    assert_eq!(
        remaining_ids.len(),
        3,
        "exactly the one dangling File-scope rule must have been deleted: {remaining_ids:?}"
    );
}

/// Upload id used only by the `upload_flow_redesign` rebuild-survival test
/// below.
const UPLOAD: &str = "00000000-0000-0000-0000-0000000000f1";

async fn index_exists(db: &DatabaseConnection, name: &str) -> bool {
    count(
        db,
        &format!(
            "SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'index' AND name = '{name}'"
        ),
    )
    .await
        == 1
}

#[tokio::test]
async fn upload_flow_redesign_data_and_indexes_survive_rebuild() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    db.execute_raw(stmt(&db, "PRAGMA foreign_keys = ON;"))
        .await
        .expect("enable foreign keys");

    Migrator::up(&db, Some(7))
        .await
        .expect("apply every migration up to (not including) upload_flow_redesign");

    insert_file(&db, FILE).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO multipart_uploads \
             (upload_id, file_id, version_id, backend_upload_handle, declared_mime, expires_at) \
             VALUES ('{UPLOAD}', '{FILE}', '{VERSION}', 'handle-1', 'text/plain', '2999-01-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert multipart session before the rebuild migration");
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO multipart_upload_parts \
             (upload_id, part_number, backend_etag, part_hash, size) VALUES \
             ('{UPLOAD}', 1, 'etag-1', X'{HASH32}', 100), \
             ('{UPLOAD}', 2, 'etag-2', X'{HASH32}', 200)"
        ),
    ))
    .await
    .expect("insert two parts before the rebuild migration");

    Migrator::up(&db, None)
        .await
        .expect("apply the remaining migration (upload_flow_redesign)");

    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM multipart_upload_parts WHERE upload_id = '{UPLOAD}'"
            )
        )
        .await,
        2,
        "both parts must survive the multipart_uploads rebuild"
    );
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS c FROM multipart_uploads WHERE upload_id = '{UPLOAD}'")
        )
        .await,
        1,
        "the session row must survive the rebuild"
    );
    assert!(
        index_exists(&db, "multipart_uploads_file_idx").await,
        "multipart_uploads_file_idx must be recreated by the rebuild"
    );
    assert!(
        index_exists(&db, "multipart_uploads_expired_idx").await,
        "multipart_uploads_expired_idx must be recreated by the rebuild"
    );
}

#[tokio::test]
async fn upload_flow_redesign_indexes_exist_after_up() {
    let db = migrated_db().await;
    assert!(
        index_exists(&db, "idempotency_keys_file_idx").await,
        "idempotency_keys_file_idx must exist after up()"
    );
    assert!(
        index_exists(&db, "multipart_uploads_sweep_idx").await,
        "multipart_uploads_sweep_idx must exist after up()"
    );
    assert!(
        index_exists(&db, "files_versionless_sweep_idx").await,
        "files_versionless_sweep_idx must exist after up()"
    );
    assert!(
        index_exists(&db, "file_versions_file_created_idx").await,
        "file_versions_file_created_idx must exist after up()"
    );
    assert!(
        index_exists(&db, "files_owner_listing_v2_idx").await,
        "files_owner_listing_v2_idx must exist after up()"
    );
    assert!(
        !index_exists(&db, "files_owner_listing_idx").await,
        "files_owner_listing_idx must be dropped after up() -- superseded by \
         files_owner_listing_v2_idx"
    );
    assert!(
        index_exists(&db, "retention_rules_tenant_listing_idx").await,
        "retention_rules_tenant_listing_idx must exist after up()"
    );
    assert!(
        !index_exists(&db, "file_versions_backend_idx").await,
        "file_versions_backend_idx must be dropped after up() -- unused (no query \
         filters file_versions by backend_id)"
    );
}

#[tokio::test]
async fn files_accepts_user_and_app_owner_kinds() {
    let db = migrated_db().await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO files (file_id, tenant_id, owner_kind, owner_id, name, gts_file_type) \
             VALUES ('{FILE}', '{TENANT}', 'user', '{OWNER}', 'a', '{GTS}'), \
                    ('00000000-0000-0000-0000-0000000000c2', '{TENANT}', 'app', '{OWNER}', 'b', '{GTS}')"
        ),
    ))
    .await
    .expect("both owner kinds are valid");
    assert_eq!(count(&db, "SELECT COUNT(*) AS c FROM files").await, 2);
}

#[tokio::test]
async fn files_rejects_invalid_owner_kind() {
    let db = migrated_db().await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO files (file_id, tenant_id, owner_kind, owner_id, name, gts_file_type) \
                 VALUES ('{FILE}', '{TENANT}', 'robot', '{OWNER}', 'a', '{GTS}')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "owner_kind CHECK must reject 'robot': {res:?}"
    );
}

#[tokio::test]
async fn files_rejects_negative_meta_version() {
    let db = migrated_db().await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO files (file_id, tenant_id, owner_kind, owner_id, name, gts_file_type, meta_version) \
                 VALUES ('{FILE}', '{TENANT}', 'user', '{OWNER}', 'a', '{GTS}', -1)"
            ),
        ))
        .await;
    assert!(res.is_err(), "meta_version CHECK must reject -1: {res:?}");
}

#[tokio::test]
async fn files_content_id_is_nullable_until_first_bind() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await; // no content_id supplied
    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM files WHERE file_id = '{FILE}' AND content_id IS NULL"
            )
        )
        .await,
        1,
        "content_id must default to NULL"
    );
}

#[tokio::test]
async fn file_versions_accepts_valid_row() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    insert_version(&db, FILE, "00000000-0000-0000-0000-0000000000d1", 1).await;
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS c FROM file_versions").await,
        1
    );
}

#[tokio::test]
async fn file_versions_rejects_negative_size() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions (file_id, version_id, mime_type, size, hash_value, backend_id, backend_path) \
                 VALUES ('{FILE}', '00000000-0000-0000-0000-0000000000d1', 'text/plain', -1, X'{HASH32}', 'local', '/p')"
            ),
        ))
        .await;
    assert!(res.is_err(), "size CHECK must reject -1: {res:?}");
}

#[tokio::test]
async fn file_versions_rejects_unknown_status() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions (file_id, version_id, mime_type, size, hash_value, status, backend_id, backend_path) \
                 VALUES ('{FILE}', '00000000-0000-0000-0000-0000000000d1', 'text/plain', 0, X'{HASH32}', 'frozen', 'local', '/p')"
            ),
        ))
        .await;
    assert!(res.is_err(), "status CHECK must reject 'frozen': {res:?}");
}

#[tokio::test]
async fn file_versions_rejects_wrong_hash_length() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions (file_id, version_id, mime_type, size, hash_value, backend_id, backend_path) \
                 VALUES ('{FILE}', '00000000-0000-0000-0000-0000000000d1', 'text/plain', 0, X'00112233', 'local', '/p')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "hash_value length CHECK must reject 4 bytes: {res:?}"
    );
}

#[tokio::test]
async fn file_versions_allows_only_one_current_per_file() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    insert_version(&db, FILE, "00000000-0000-0000-0000-0000000000d1", 1).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions (file_id, version_id, mime_type, size, hash_value, is_current, backend_id, backend_path) \
                 VALUES ('{FILE}', '00000000-0000-0000-0000-0000000000d2', 'text/plain', 0, X'{HASH32}', 1, 'local', '/p')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "two current versions for one file must violate the unique index: {res:?}"
    );
}

#[tokio::test]
async fn file_versions_allows_many_non_current_per_file() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    insert_version(&db, FILE, "00000000-0000-0000-0000-0000000000d1", 0).await;
    insert_version(&db, FILE, "00000000-0000-0000-0000-0000000000d2", 0).await;
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS c FROM file_versions").await,
        2,
        "multiple non-current versions are allowed"
    );
}

#[tokio::test]
async fn file_versions_allows_current_per_distinct_file() {
    let db = migrated_db().await;
    let file2 = "00000000-0000-0000-0000-0000000000c2";
    insert_file(&db, FILE).await;
    insert_file(&db, file2).await;
    insert_version(&db, FILE, "00000000-0000-0000-0000-0000000000d1", 1).await;
    insert_version(&db, file2, "00000000-0000-0000-0000-0000000000d2", 1).await;
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS c FROM file_versions WHERE is_current = 1"
        )
        .await,
        2
    );
}

#[tokio::test]
async fn custom_metadata_rejects_duplicate_key_per_file() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO files_custom_metadata (file_id, key, value) VALUES ('{FILE}', 'tag', 'a')"
        ),
    ))
    .await
    .expect("first key insert");
    let res = db
        .execute_raw(stmt(
            &db,
            format!("INSERT INTO files_custom_metadata (file_id, key, value) VALUES ('{FILE}', 'tag', 'b')"),
        ))
        .await;
    assert!(
        res.is_err(),
        "(file_id, key) PK must reject duplicate key: {res:?}"
    );
}

#[tokio::test]
async fn idempotency_keys_request_hash_column_exists_with_default() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO idempotency_keys \
             (tenant_id, owner_kind, owner_id, idempotency_key, file_id, \
              response_status, response_body, response_etag, expires_at) \
             VALUES ('{TENANT}', 'user', '{OWNER}', 'k1', '{FILE}', \
                     201, '{{}}', 'etag', '2999-01-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert idempotency row omitting request_hash must succeed");

    let hash_len = db
        .query_one_raw(stmt(
            &db,
            format!(
                "SELECT LENGTH(request_hash) AS c FROM idempotency_keys \
                 WHERE tenant_id = '{TENANT}' AND idempotency_key = 'k1'"
            ),
        ))
        .await
        .expect("select request_hash length")
        .expect("one row")
        .try_get::<i64>("", "c")
        .expect("i64 column c");
    assert_eq!(
        hash_len, 0,
        "request_hash must default to an empty blob, not a populated/garbage value"
    );
}

#[tokio::test]
async fn policies_unique_index_rejects_duplicate_scope_tuple() {
    let db = migrated_db().await;
    let owner2 = "00000000-0000-0000-0000-0000000000b2";
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body) \
             VALUES ('00000000-0000-0000-0000-0000000000e1', '{TENANT}', 'user', '{owner2}', '{{}}')"
        ),
    ))
    .await
    .expect("first user-scope policy insert");

    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body) \
                 VALUES ('00000000-0000-0000-0000-0000000000e2', '{TENANT}', 'user', '{owner2}', '{{}}')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "duplicate (tenant_id, 'user', scope_owner_id) must violate \
         policies_user_scope_unique_idx: {res:?}"
    );
}

#[tokio::test]
async fn policies_unique_index_rejects_duplicate_tenant_scope() {
    let db = migrated_db().await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body) \
             VALUES ('00000000-0000-0000-0000-0000000000e3', '{TENANT}', 'tenant', NULL, '{{}}')"
        ),
    ))
    .await
    .expect("first tenant-scope policy insert");

    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body) \
                 VALUES ('00000000-0000-0000-0000-0000000000e4', '{TENANT}', 'tenant', NULL, '{{}}')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "duplicate (tenant_id, 'tenant') with NULL scope_owner_id must \
         violate policies_tenant_scope_unique_idx: {res:?}"
    );
}

#[tokio::test]
async fn policies_unique_index_allows_distinct_scopes() {
    let db = migrated_db().await;
    let tenant2 = "00000000-0000-0000-0000-0000000000a2";
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body) VALUES \
             ('00000000-0000-0000-0000-0000000000e5', '{TENANT}', 'tenant', NULL, '{{}}'), \
             ('00000000-0000-0000-0000-0000000000e6', '{TENANT}', 'user', '{OWNER}', '{{}}'), \
             ('00000000-0000-0000-0000-0000000000e7', '{tenant2}', 'user', '{OWNER}', '{{}}')"
        ),
    ))
    .await
    .expect("distinct scopes must not collide across the partial indexes");
    assert_eq!(count(&db, "SELECT COUNT(*) AS c FROM policies").await, 3);
}

#[tokio::test]
async fn policies_unique_migration_dedups_preexisting_duplicates() {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");

    Migrator::up(&db, Some(5))
        .await
        .expect("apply migrations up to (not including) policies_unique_scope");

    let owner = "00000000-0000-0000-0000-0000000000b2";
    let older = "00000000-0000-0000-0000-0000000000e1";
    let newer = "00000000-0000-0000-0000-0000000000e2";

    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body, updated_at) \
             VALUES ('{older}', '{TENANT}', 'user', '{owner}', '{{\"v\":1}}', '2026-01-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert older duplicate user-scope policy");
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body, updated_at) \
             VALUES ('{newer}', '{TENANT}', 'user', '{owner}', '{{\"v\":2}}', '2026-06-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert newer duplicate user-scope policy");

    let tenant_older = "00000000-0000-0000-0000-0000000000e3";
    let tenant_newer = "00000000-0000-0000-0000-0000000000e4";
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body, updated_at) \
             VALUES ('{tenant_older}', '{TENANT}', 'tenant', NULL, '{{\"v\":1}}', '2026-01-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert older duplicate tenant-scope policy");
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body, updated_at) \
             VALUES ('{tenant_newer}', '{TENANT}', 'tenant', NULL, '{{\"v\":2}}', '2026-06-01T00:00:00Z')"
        ),
    ))
    .await
    .expect("insert newer duplicate tenant-scope policy");

    assert_eq!(
        count(&db, "SELECT COUNT(*) AS c FROM policies").await,
        4,
        "all four duplicate rows must be present before the dedup migration runs"
    );

    // Apply the remaining migration (policies_unique_scope). This must not
    // fail even though duplicates exist.
    Migrator::up(&db, Some(1))
        .await
        .expect("policies_unique_scope migration must dedup before creating the unique indexes");

    // Exactly one row per group must survive, and it must be the
    // most-recently-updated one.
    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM policies WHERE tenant_id = '{TENANT}' AND scope = 'user' AND scope_owner_id = '{owner}'"
            )
        )
        .await,
        1,
        "duplicate user-scope rows must be deduped to exactly one"
    );
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS c FROM policies WHERE policy_id = '{newer}'")
        )
        .await,
        1,
        "the surviving user-scope row must be the most-recently-updated one"
    );
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS c FROM policies WHERE policy_id = '{older}'")
        )
        .await,
        0,
        "the stale user-scope duplicate must have been deleted"
    );

    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM policies WHERE tenant_id = '{TENANT}' AND scope = 'tenant' AND scope_owner_id IS NULL"
            )
        )
        .await,
        1,
        "duplicate tenant-scope rows must be deduped to exactly one"
    );
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS c FROM policies WHERE policy_id = '{tenant_newer}'")
        )
        .await,
        1,
        "the surviving tenant-scope row must be the most-recently-updated one"
    );
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS c FROM policies WHERE policy_id = '{tenant_older}'")
        )
        .await,
        0,
        "the stale tenant-scope duplicate must have been deleted"
    );

    // The partial unique indexes must now be live: a fresh duplicate insert
    // is rejected.
    let dup_res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO policies (policy_id, tenant_id, scope, scope_owner_id, body) \
                 VALUES ('00000000-0000-0000-0000-0000000000e9', '{TENANT}', 'user', '{owner}', '{{}}')"
            ),
        ))
        .await;
    assert!(
        dup_res.is_err(),
        "policies_user_scope_unique_idx must reject a fresh duplicate after the dedup migration: {dup_res:?}"
    );
}

#[tokio::test]
async fn deleting_file_cascades_to_versions_and_metadata() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    insert_version(&db, FILE, "00000000-0000-0000-0000-0000000000d1", 1).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO files_custom_metadata (file_id, key, value) VALUES ('{FILE}', 'tag', 'a')"
        ),
    ))
    .await
    .expect("insert metadata");

    db.execute_raw(stmt(
        &db,
        format!("DELETE FROM files WHERE file_id = '{FILE}'"),
    ))
    .await
    .expect("delete file");

    assert_eq!(
        count(&db, "SELECT COUNT(*) AS c FROM file_versions").await,
        0,
        "versions must be cascade-deleted with the file"
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS c FROM files_custom_metadata").await,
        0,
        "custom metadata must be cascade-deleted with the file"
    );
}

#[tokio::test]
async fn content_hash_modes_backfill_existing_rows_to_whole_sha256() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    // `insert_version` deliberately does NOT mention hash_mode/part_count.
    insert_version(&db, FILE, VERSION, 1).await;

    let row = db
        .query_one_raw(stmt(
            &db,
            format!(
                "SELECT hash_mode AS m, \
                 (SELECT COUNT(*) FROM file_versions WHERE part_count IS NULL) AS c \
                 FROM file_versions WHERE version_id = '{VERSION}'"
            ),
        ))
        .await
        .expect("query")
        .expect("one row");
    assert_eq!(
        row.try_get::<String>("", "m").expect("hash_mode"),
        "whole-sha256",
        "existing rows must backfill to whole-sha256"
    );
    assert_eq!(
        row.try_get::<i64>("", "c").expect("null part_count count"),
        1,
        "existing rows must have part_count NULL"
    );
    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM version_hash_manifest WHERE version_id = '{VERSION}'"
            )
        )
        .await,
        0,
        "whole-sha256 versions must have no manifest row"
    );
}

#[tokio::test]
async fn content_hash_modes_rejects_multipart_without_part_count() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions \
                 (file_id, version_id, mime_type, size, hash_value, hash_mode, part_count, \
                  status, is_current, backend_id, backend_path) \
                 VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, X'{HASH32}', \
                 'multipart-composite-sha256', NULL, 'available', 0, 'local', '/x')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "multipart-composite-sha256 with a NULL part_count must violate the presence CHECK"
    );
}

#[tokio::test]
async fn content_hash_modes_rejects_whole_with_part_count() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions \
                 (file_id, version_id, mime_type, size, hash_value, hash_mode, part_count, \
                  status, is_current, backend_id, backend_path) \
                 VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, X'{HASH32}', \
                 'whole-sha256', 3, 'available', 0, 'local', '/x')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "whole-sha256 with a non-NULL part_count must violate the presence CHECK"
    );
}

/// The presence CHECK alone does not pin a `>= 2` floor on `part_count`: a
/// `multipart-composite-sha256` row with `part_count = 1` satisfies it.
#[tokio::test]
async fn content_hash_modes_accepts_legacy_single_part_composite() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO file_versions \
             (file_id, version_id, mime_type, size, hash_value, hash_mode, part_count, \
              status, is_current, backend_id, backend_path) \
             VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, X'{HASH32}', \
             'multipart-composite-sha256', 1, 'available', 0, 'local', '/x')"
        ),
    ))
    .await
    .expect(
        "multipart-composite-sha256 with part_count = 1 must satisfy the CHECK \
         (legacy pre-amendment rows, ADR-0006)",
    );
}

#[tokio::test]
async fn content_hash_modes_accepts_multipart_with_two_parts() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO file_versions \
             (file_id, version_id, mime_type, size, hash_value, hash_mode, part_count, \
              status, is_current, backend_id, backend_path) \
             VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, X'{HASH32}', \
             'multipart-composite-sha256', 2, 'available', 0, 'local', '/x')"
        ),
    ))
    .await
    .expect("multipart-composite-sha256 with part_count = 2 must satisfy the CHECK");

    assert_eq!(
        count(
            &db,
            &format!(
                "SELECT COUNT(*) AS c FROM file_versions \
                 WHERE version_id = '{VERSION}' AND part_count = 2"
            )
        )
        .await,
        1
    );
}

#[tokio::test]
async fn content_hash_modes_accepts_whole_with_null_part_count() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    db.execute_raw(stmt(
        &db,
        format!(
            "INSERT INTO file_versions \
             (file_id, version_id, mime_type, size, hash_value, hash_mode, part_count, \
              status, is_current, backend_id, backend_path) \
             VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, X'{HASH32}', \
             'whole-sha256', NULL, 'available', 0, 'local', '/x')"
        ),
    ))
    .await
    .expect("whole-sha256 with a NULL part_count must satisfy the CHECK");
}

#[tokio::test]
async fn content_hash_modes_rejects_unknown_hash_mode() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions \
                 (file_id, version_id, mime_type, size, hash_value, hash_mode, \
                  status, is_current, backend_id, backend_path) \
                 VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, X'{HASH32}', \
                 'blake3-tree', 'available', 0, 'local', '/x')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "an unknown hash_mode must be rejected by the CHECK"
    );
}

#[tokio::test]
async fn content_hash_modes_leaves_hash_algorithm_check_intact() {
    let db = migrated_db().await;
    insert_file(&db, FILE).await;
    let res = db
        .execute_raw(stmt(
            &db,
            format!(
                "INSERT INTO file_versions \
                 (file_id, version_id, mime_type, size, hash_algorithm, hash_value, \
                  status, is_current, backend_id, backend_path) \
                 VALUES ('{FILE}', '{VERSION}', 'text/plain', 0, 'BLAKE3', X'{HASH32}', \
                 'available', 0, 'local', '/x')"
            ),
        ))
        .await;
    assert!(
        res.is_err(),
        "hash_algorithm CHECK must still reject any non-SHA-256 value"
    );
}
