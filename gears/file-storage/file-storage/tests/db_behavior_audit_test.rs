// Created: 2026-07-27 by Constructor Tech
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::too_many_lines
)]
//! DB-behavior audit for file-storage, mirroring resource-group's own
//! methodology (see `docs/toolkit_unified_system/14_db_behavior_testing.md`).

mod common;

use std::sync::Arc;

use bytes::Bytes;
use common::query_recorder::QueryKind;
use file_storage::domain::error::DomainError;
use file_storage::domain::service::FileService;
use file_storage::infra::backend::{LocalFsBackend, StorageBackend};
use file_storage_sdk::CustomMetadataPatch;
use uuid::Uuid;

async fn put_content(
    svc: &FileService,
    backend: &Arc<dyn StorageBackend>,
    ctx: &toolkit_security::SecurityContext,
    file_id: Uuid,
    version_id: Uuid,
    declared_mime: &str,
    bytes: Bytes,
) -> Result<(), DomainError> {
    file_storage::infra::content::mime::validate(declared_mime, &bytes)?;
    svc.authorize_write(ctx, file_id).await?;
    let backend_path = format!("/{file_id}/{version_id}");
    let len = bytes.len() as u64;
    let digest = file_storage::infra::content::hash::sha256(&bytes);
    let stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>> =
        Box::pin(futures::stream::once(async move { Ok(bytes) }));
    backend.put_stream(&backend_path, stream, Some(len)).await?;
    svc.finalize_upload(
        ctx,
        file_id,
        version_id,
        i64::try_from(len).unwrap_or(i64::MAX),
        digest,
    )
    .await
}

#[tokio::test]
async fn trace_create_file() {
    let (db, rec) = common::test_db_with_recorder().await;
    let (svc, _msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    rec.clear();
    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file should succeed");
    assert!(!ticket.upload_url.is_empty());

    assert!(
        rec.writes_outside_tx().is_empty(),
        "create_file must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_full_upload_finalize_and_bind() {
    let (db, rec) = common::test_db_with_recorder().await;
    let s = common::make_services_full(&db);
    let svc = &s.svc;
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");

    rec.clear();
    put_content(
        svc,
        &s.backend,
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"hello world"),
    )
    .await
    .expect("put_content (upload + finalize)");
    assert!(
        rec.writes_outside_tx().is_empty(),
        "finalize_upload must run its writes inside a transaction:\n{}",
        rec.dump()
    );

    rec.clear();
    let bound = svc
        .bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind (first bind, no If-Match)");
    assert_eq!(bound.content_id, Some(ticket.version_id));
    assert!(
        rec.writes_outside_tx().is_empty(),
        "bind must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_update_metadata() {
    let (db, rec) = common::test_db_with_recorder().await;
    let (svc, _msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");

    rec.clear();
    let patch = CustomMetadataPatch {
        entries: vec![("k1".to_owned(), Some("v1".to_owned()))],
    };
    let updated = svc
        .update_metadata(&ctx, ticket.file_id, patch, None)
        .await
        .expect("update_metadata should succeed");
    assert!(updated.meta_version >= 1);

    assert!(
        rec.writes_outside_tx().is_empty(),
        "update_metadata must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_delete_file() {
    let (db, rec) = common::test_db_with_recorder().await;
    let (svc, _msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");

    rec.clear();
    svc.delete_file(&ctx, ticket.file_id, Some("*"))
        .await
        .expect("delete_file should succeed");

    assert!(
        rec.writes_outside_tx().is_empty(),
        "delete_file must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_multipart_complete() {
    let (db, rec) = common::test_db_with_recorder().await;
    let s = common::make_services_full(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let file_id = s
        .svc
        .create_file_bare(&ctx, common::new_file())
        .await
        .expect("create_file_bare");
    let plan = s
        .msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            10 * 1024 * 1024,
            Some(5 * 1024 * 1024),
            false,
        )
        .await
        .expect("initiate_multipart_upload (in-memory backend supports multipart_native)");
    assert_eq!(plan.parts.len(), 2, "10 MiB at part_size=5 MiB -> 2 parts");

    common::simulate_all_parts(&s.multipart_store, &s.backend, &plan, file_id).await;

    rec.clear();
    let completed = s
        .msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("complete_multipart_upload")
        .unwrap_completed();
    assert_eq!(completed.size, 10 * 1024 * 1024);

    let outside = rec.writes_outside_tx();
    assert_eq!(
        outside.len(),
        1,
        "expected exactly one write outside a transaction \
         (acquire_complete_lease's CAS) -- got {}:\n{}",
        outside.len(),
        rec.dump()
    );
    assert_eq!(
        outside[0].table.as_deref(),
        Some("multipart_uploads"),
        "the one untransacted write must be acquire_complete_lease's UPDATE \
         on multipart_uploads, got: {:?}",
        outside[0]
    );
    assert!(
        outside[0].sql.contains("\"lease_until\"")
            && !outside[0].sql.contains("\"complete_result\""),
        "expected acquire_complete_lease's shape (sets lease_until, not \
         complete_result -- that's finish_complete's column), got: {}",
        outside[0].sql
    );
}

async fn make_services_local_fs_only() -> common::Services {
    let db = common::test_db().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let backend: Arc<dyn StorageBackend> = Arc::new(LocalFsBackend::new("fs", tmp.keep()));
    common::make_services_with_backends(&db, vec![backend], "fs")
}

#[tokio::test]
async fn multipart_initiate_capability_reject_leaves_orphan_bare_file() {
    // Only the `POST /files` handler calls `compensate_failed_multipart_initiate`; this test
    // drives the two domain calls directly, so the orphan bare file is expected here.
    let s = make_services_local_fs_only().await;
    let (svc, msvc) = (s.svc, s.msvc);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let file_id = svc
        .create_file_bare(&ctx, common::new_file())
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
    assert!(
        matches!(err, DomainError::MultipartNotSupported { .. }),
        "expected a clean MultipartNotSupported, got: {err}"
    );

    let still_there = svc.get_file(&ctx, file_id).await;
    assert!(
        still_there.is_ok(),
        "the orphaned bare file must still exist after JUST the two raw domain calls, with no \
         compensation invoked -- got: {still_there:?}"
    );
}

#[tokio::test]
async fn multipart_initiate_capability_reject_with_compensation_reclaims_orphan() {
    let s = make_services_local_fs_only().await;
    let (svc, msvc) = (s.svc, s.msvc);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let file_id = svc
        .create_file_bare(&ctx, common::new_file())
        .await
        .expect("create_file_bare commits the bare file row");
    msvc.initiate_multipart_upload(
        &ctx,
        file_id,
        "application/octet-stream",
        20,
        Some(10),
        false,
    )
    .await
    .expect_err("local-fs backend does not advertise multipart_native");

    svc.compensate_failed_multipart_initiate(&ctx, file_id)
        .await;

    let gone = svc.get_file(&ctx, file_id).await;
    assert!(
        matches!(gone, Err(DomainError::FileNotFound { .. })),
        "FS-01/F1 fix: the compensating delete must reclaim the orphan file, got: {gone:?}"
    );
}

#[tokio::test]
async fn multipart_finish_complete_cas_omits_lease_owner_for_embedded_call() {
    let (db, rec) = common::test_db_with_recorder().await;
    let s = common::make_services_full(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let file_id = s
        .svc
        .create_file_bare(&ctx, common::new_file())
        .await
        .expect("create_file_bare");
    let plan = s
        .msvc
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 10, None, false)
        .await
        .expect("initiate_multipart_upload");
    common::simulate_all_parts(&s.multipart_store, &s.backend, &plan, file_id).await;

    rec.clear();
    let _ = s
        .msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("complete_multipart_upload");

    let finish_complete_updates: Vec<_> = rec
        .events()
        .into_iter()
        .filter(|e| {
            e.kind == QueryKind::Update
                && e.table.as_deref() == Some("multipart_uploads")
                && e.sql.contains("\"complete_result\"")
        })
        .collect();
    assert_eq!(
        finish_complete_updates.len(),
        1,
        "expected exactly one UPDATE multipart_uploads (finish_complete, \
         identified by its complete_result column) statement:\n{}",
        rec.dump()
    );
    // `lease_owner` legitimately appears in the SET list (finish_complete
    // clears the lease on success) -- check only the clause after WHERE.
    let sql = &finish_complete_updates[0].sql;
    let where_clause = sql
        .split_once(" WHERE ")
        .map_or("", |(_, rhs)| rhs)
        .to_ascii_lowercase();
    assert!(
        !where_clause.contains("lease_owner"),
        "the embedded finish_complete call (ordinary, uncontested completion) \
         must keep passing `None` for its owner predicate -- if this now \
         filters on lease_owner, re-check the f2 stranding-race reasoning in \
         this test's doc comment before treating that as a fix. Full SQL: {sql}"
    );
}

#[tokio::test]
async fn multipart_complete_auto_bind_no_if_match_cas_now_requires_content_id_is_null() {
    let (db, rec) = common::test_db_with_recorder().await;
    let s = common::make_services_full(&db);
    let (svc, msvc) = (s.svc.clone(), s.msvc.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");
    put_content(
        &svc,
        &s.backend,
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"first content"),
    )
    .await
    .expect("put_content");
    let bound_first = svc
        .bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind first content");

    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            ticket.file_id,
            "application/octet-stream",
            10,
            None,
            true,
        )
        .await
        .expect("initiate_multipart_upload with auto_bind");
    common::simulate_all_parts(&s.multipart_store, &s.backend, &plan, ticket.file_id).await;

    rec.clear();
    let completed = msvc
        .complete_multipart_upload(&ctx, ticket.file_id, plan.upload_id, None)
        .await
        .expect("complete_multipart_upload (no If-Match) must still succeed -- only the bind is conditional")
        .unwrap_completed();
    assert_eq!(
        completed.bind_state,
        file_storage::domain::multipart::BindState::Conflict,
        "FS-04/F9 fix: expected the auto-bind CAS to lose (content_id IS NULL no longer \
         matches) rather than unconditionally clobbering the previously bound content"
    );
    let file_after = svc.get_file(&ctx, ticket.file_id).await.expect("get_file");
    assert_eq!(
        file_after.content_id,
        Some(ticket.version_id),
        "the previously bound content must survive -- the multipart version stays available \
         and manually rebindable, exactly like any other lost bind CAS"
    );
    let _ = bound_first; // (kept for narration; superseded by file_after above)

    let bind_updates: Vec<_> = rec
        .events()
        .into_iter()
        .filter(|e| e.kind == QueryKind::Update && e.table.as_deref() == Some("files"))
        .collect();
    assert_eq!(
        bind_updates.len(),
        1,
        "expected exactly one UPDATE files (bind_content_cas):\n{}",
        rec.dump()
    );
    let sql = &bind_updates[0].sql;
    assert!(
        sql.to_ascii_lowercase().contains("is null"),
        "FS-04/F9 fix regression: multipart complete's auto-bind CAS (no If-Match supplied) \
         must target content_id IS NULL, got: {sql}"
    );
}

#[tokio::test]
async fn negative_control_multipart_complete_auto_bind_with_if_match_still_binds() {
    let (db, rec) = common::test_db_with_recorder().await;
    let s = common::make_services_full(&db);
    let (svc, msvc) = (s.svc.clone(), s.msvc.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");
    put_content(
        &svc,
        &s.backend,
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        Bytes::from_static(b"first content"),
    )
    .await
    .expect("put_content");
    let bound_first = svc
        .bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind first content");
    let etag_first =
        file_storage::domain::etag::etag_for(&bound_first).expect("bound file must have an etag");

    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            ticket.file_id,
            "application/octet-stream",
            10,
            None,
            true,
        )
        .await
        .expect("initiate_multipart_upload with auto_bind");
    common::simulate_all_parts(&s.multipart_store, &s.backend, &plan, ticket.file_id).await;

    rec.clear();
    let completed = msvc
        .complete_multipart_upload(&ctx, ticket.file_id, plan.upload_id, Some(&etag_first))
        .await
        .expect("complete_multipart_upload with a correct If-Match")
        .unwrap_completed();
    assert_eq!(
        completed.bind_state,
        file_storage::domain::multipart::BindState::Bound,
        "supplying the correct If-Match must still let the auto-bind win"
    );

    let bind_updates: Vec<_> = rec
        .events()
        .into_iter()
        .filter(|e| e.kind == QueryKind::Update && e.table.as_deref() == Some("files"))
        .collect();
    assert_eq!(bind_updates.len(), 1);
    let sql = &bind_updates[0].sql;
    assert!(
        !sql.to_ascii_lowercase().contains("is null"),
        "with a confirmed If-Match, the CAS must target the observed (non-NULL) content_id, \
         not IS NULL, got: {sql}"
    );
}

async fn metadata_upsert_statements_for_patch_size(n: usize) -> usize {
    let (db, rec) = common::test_db_with_recorder().await;
    let (svc, _msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");

    rec.clear();
    let patch = CustomMetadataPatch {
        entries: (0..n)
            .map(|i| (format!("k{i}"), Some(format!("v{i}"))))
            .collect(),
    };
    svc.update_metadata(&ctx, ticket.file_id, patch, None)
        .await
        .expect("update_metadata should succeed");

    rec.stats()
        .into_iter()
        .filter(|((kind, table), _)| {
            *kind == common::query_recorder::QueryKind::Insert && table == "custom_metadata"
        })
        .map(|(_, count)| count)
        .sum()
}

#[tokio::test]
async fn scale_metadata_patch_inserts_do_not_grow_with_entry_count() {
    let small = metadata_upsert_statements_for_patch_size(2).await;
    let large = metadata_upsert_statements_for_patch_size(15).await;
    assert_eq!(
        small, large,
        "custom_metadata INSERT count must not scale with patch entry count \
         (small={small} at N=2, large={large} at N=15)"
    );
}

#[test]
fn structural_rule_infra_storage_never_imports_infra_backend() {
    let storage_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/infra/storage");
    let mut offenders = Vec::new();
    visit_rs_files(&storage_dir, &mut |path, src| {
        if src.contains("infra::backend") || src.contains("StorageBackend") {
            offenders.push(path.display().to_string());
        }
    });
    assert!(
        offenders.is_empty(),
        "expected zero infra::backend/StorageBackend references anywhere under \
         src/infra/storage/ (this would mean a DB transaction closure could \
         reach a backend call) -- found in: {offenders:?}"
    );
}

fn visit_rs_files(dir: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &str)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            visit_rs_files(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(src) = std::fs::read_to_string(&path)
        {
            f(&path, &src);
        }
    }
}

#[tokio::test]
async fn negative_control_read_paths_produce_no_write_statements() {
    let (db, rec) = common::test_db_with_recorder().await;
    let (svc, msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let ticket = svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");

    rec.clear();
    svc.get_file(&ctx, ticket.file_id)
        .await
        .expect("get_file should succeed");
    svc.list_versions(&ctx, ticket.file_id, None, None)
        .await
        .expect("list_versions should succeed");
    let _ = msvc; // silence unused in case future reads move here

    let stats = rec.stats();
    for (kind, _table) in stats.keys() {
        assert!(
            !matches!(
                kind,
                QueryKind::Insert | QueryKind::Update | QueryKind::Delete
            ),
            "read-only calls must not produce write statements:\n{}",
            rec.dump()
        );
    }
}

#[tokio::test]
async fn negative_control_multipart_native_backend_initiate_succeeds() {
    let (db, _rec) = common::test_db_with_recorder().await;
    let (svc, msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let file_id = svc
        .create_file_bare(&ctx, common::new_file())
        .await
        .expect("create_file_bare");
    let plan = msvc
        .initiate_multipart_upload(
            &ctx,
            file_id,
            "application/octet-stream",
            10 * 1024 * 1024,
            Some(5 * 1024 * 1024),
            false,
        )
        .await
        .expect("in-memory backend advertises multipart_native, initiate must succeed");
    assert_eq!(plan.parts.len(), 2);
}

async fn create_file_metadata_insert_statements_for_entry_count(n: usize) -> usize {
    let (db, rec) = common::test_db_with_recorder().await;
    let (svc, _msvc) = common::make_services(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let mut new = common::new_file();
    new.custom_metadata = (0..n)
        .map(|i| file_storage_sdk::CustomMetadataEntry {
            key: format!("k{i}"),
            value: format!("v{i}"),
        })
        .collect();

    rec.clear();
    svc.create_file(&ctx, new, None, false)
        .await
        .expect("create_file with initial custom_metadata should succeed");

    rec.stats()
        .into_iter()
        .filter(|((kind, table), _)| {
            *kind == common::query_recorder::QueryKind::Insert && table == "custom_metadata"
        })
        .map(|(_, count)| count)
        .sum()
}

#[tokio::test]
async fn scale_create_file_metadata_inserts_do_not_grow_with_entry_count() {
    let small = create_file_metadata_insert_statements_for_entry_count(2).await;
    let large = create_file_metadata_insert_statements_for_entry_count(15).await;
    assert_eq!(
        small, large,
        "custom_metadata INSERT count at create_file time must not scale with the initial \
         entry count (small={small} at N=2, large={large} at N=15)"
    );
}
