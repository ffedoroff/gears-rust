// Created: 2026-07-27 by Constructor Tech
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]
//! Contract-drift tests for the file-storage DB-behavior audit (see
//! `docs/toolkit_unified_system/14_db_behavior_testing.md`).

mod common;

use file_storage::domain::multipart::BindState;
use uuid::Uuid;

async fn put_content(
    svc: &file_storage::domain::service::FileService,
    backend: &std::sync::Arc<dyn file_storage::infra::backend::StorageBackend>,
    ctx: &toolkit_security::SecurityContext,
    file_id: Uuid,
    version_id: Uuid,
    declared_mime: &str,
    bytes: bytes::Bytes,
) -> Result<(), file_storage::domain::error::DomainError> {
    file_storage::infra::content::mime::validate(declared_mime, &bytes)?;
    svc.authorize_write(ctx, file_id).await?;
    let backend_path = format!("/{file_id}/{version_id}");
    let len = bytes.len() as u64;
    let digest = file_storage::infra::content::hash::sha256(&bytes);
    let stream: futures::stream::BoxStream<'static, std::io::Result<bytes::Bytes>> =
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
async fn fs06_f4_completed_retry_with_stale_if_match_now_replays_instead_of_failing_precondition() {
    let (db, _rec) = common::test_db_with_recorder().await;
    let s = common::make_services_full(&db);
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let ticket = s
        .svc
        .create_file(&ctx, common::new_file(), None, false)
        .await
        .expect("create_file");
    put_content(
        &s.svc,
        &s.backend,
        &ctx,
        ticket.file_id,
        ticket.version_id,
        "text/plain",
        bytes::Bytes::from_static(b"initial content"),
    )
    .await
    .expect("put_content");
    let bound = s
        .svc
        .bind(&ctx, ticket.file_id, ticket.version_id, None)
        .await
        .expect("bind initial content");
    let etag_of_initial_content =
        file_storage::domain::etag::etag_for(&bound).expect("bound file must have an etag");

    let plan = s
        .msvc
        .initiate_multipart_upload(
            &ctx,
            ticket.file_id,
            "application/octet-stream",
            10,
            None,
            true, // auto_bind
        )
        .await
        .expect("initiate_multipart_upload with auto_bind");
    common::simulate_all_parts(&s.multipart_store, &s.backend, &plan, ticket.file_id).await;

    let completed_first = s
        .msvc
        .complete_multipart_upload(
            &ctx,
            ticket.file_id,
            plan.upload_id,
            Some(&etag_of_initial_content),
        )
        .await
        .expect("first complete: If-Match matches the initial content pointer")
        .unwrap_completed();
    assert_eq!(completed_first.bind_state, BindState::Bound);

    let retry = s
        .msvc
        .complete_multipart_upload(
            &ctx,
            ticket.file_id,
            plan.upload_id,
            Some(&etag_of_initial_content),
        )
        .await
        .expect(
            "FS-06/F4 fix: a retry against an already-Completed session must replay, not \
                 fail a stale precondition check",
        )
        .unwrap_completed();
    assert_eq!(
        retry.version_id, completed_first.version_id,
        "the replayed result must match the original completion"
    );
}

#[tokio::test]
async fn negative_control_fs06_completed_retry_without_if_match_replays_correctly() {
    let (db, _rec) = common::test_db_with_recorder().await;
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
        .initiate_multipart_upload(&ctx, file_id, "application/octet-stream", 10, None, true)
        .await
        .expect("initiate_multipart_upload with auto_bind");
    common::simulate_all_parts(&s.multipart_store, &s.backend, &plan, file_id).await;

    let completed_first = s
        .msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("first complete")
        .unwrap_completed();
    assert_eq!(completed_first.bind_state, BindState::Bound);

    let retry = s
        .msvc
        .complete_multipart_upload(&ctx, file_id, plan.upload_id, None)
        .await
        .expect("retry with no If-Match must replay, not error")
        .unwrap_completed();
    assert_eq!(
        retry.version_id, completed_first.version_id,
        "the replayed result must match the original completion"
    );
}

#[test]
fn fs12_concurrency_doc_race_catalog_item_2_claim_holds_after_fs02_fix() {
    let doc = include_str!("../../docs/concurrency-and-failure-model.md");
    let claim = "converges by replaying the persisted result";
    assert!(
        doc.contains(claim),
        "FS-12: expected concurrency-and-failure-model.md's Race Catalog item 2 to still \
         contain the claim ({claim:?}) -- if this doc text changed, re-check whether this pin \
         needs updating instead of just fixing this assertion"
    );
}
