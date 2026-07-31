// Created: 2026-07-31 by Constructor Tech
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]
//! SQLite `:memory:` tests for the hierarchy offset-cursor validation
//! (ML-4182/ML-8813, Part B): `GroupRepository::decode_offset_cursor`
//! (private, exercised only through `get_descendants`/`get_ancestors`) and
//! `encode_offset_cursor`'s minted `f` (`query.filter_hash`).
//!
//! Same repository-direct pattern and rationale as
//! `hierarchy_traversal_bounds_db_test.rs` (same file family, split out
//! because this is a distinct concern -- cursor codec validation, not
//! traversal-bound derivation).
//!
//! Positive tests matter here as much as the rejections: a validator that
//! rejects everything trivially "passes" every negative test.
//!
//! What the filtered-pagination test does *not* do is pin a defect of the
//! old code. Before this change the hierarchy cursor was not validated at
//! all -- `f` was ignored and minted as `None` -- so a filtered second page
//! worked. That test guards the *intermediate* state this change could have
//! passed through: strict `f` checking added without minting `f` from
//! `query.filter_hash` would fail every filtered continuation. It is why the
//! two halves ship together, and it is an acceptance test, not a regression
//! pin.

mod common;

use std::sync::Arc;

use resource_group::domain::error::DomainError;
use resource_group::domain::repo::GroupRepositoryTrait;
use resource_group::infra::storage::group_repo::GroupRepository;
use resource_group_sdk::ResourceGroup;
use toolkit_odata::{CursorV1, ODataQuery, SortDir};
use toolkit_security::AccessScope;
use uuid::Uuid;

struct Fixture {
    root: ResourceGroup,
    // Kept for fixture symmetry with `hierarchy_traversal_bounds_db_test.rs`;
    // no scenario below needs individual child identities, only the count
    // and `child_type_code`.
    #[allow(dead_code)]
    children: Vec<ResourceGroup>,
    child_type_code: String,
}

/// `root` (depth 0) with five children (depth 1), all of the same type, so
/// a `type eq` filter can narrow to exactly the five children.
async fn build_fixture(
    db: &Arc<toolkit_db::DBProvider<toolkit_db::DbError>>,
    tenant_id: Uuid,
) -> Fixture {
    let type_svc = common::make_type_service(db.clone());
    let group_svc = common::make_group_service(db.clone());
    let ctx = common::make_ctx(tenant_id);

    let root_type = common::create_root_type(&type_svc, "hcur0").await;
    let child_type = common::create_child_type(&type_svc, "hcur1", &[&root_type.code], &[]).await;

    let root =
        common::create_root_group(&group_svc, &ctx, &root_type.code, "root", tenant_id).await;

    let mut children = Vec::new();
    for i in 0..5 {
        children.push(
            common::create_child_group(
                &group_svc,
                &ctx,
                &child_type.code,
                root.id,
                &format!("child-{i}"),
                tenant_id,
            )
            .await,
        );
    }

    Fixture {
        root,
        children,
        child_type_code: child_type.code,
    }
}

fn filter_query(raw: &str) -> ODataQuery {
    let parsed = toolkit_odata::parse_filter_string(raw)
        .unwrap_or_else(|e| panic!("fixture filter {raw:?} must parse: {e}"));
    ODataQuery::new().with_filter(parsed.into_expr())
}

// -- Positive: pagination actually walks the full result set --

#[tokio::test]
async fn hierarchy_cursor_unfiltered_pagination_has_no_gaps_or_dupes() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let canonical = repo
        .get_descendants(
            &conn,
            &scope,
            fixture.root.id,
            &ODataQuery::new().with_limit(100),
        )
        .await
        .expect("canonical fetch")
        .items
        .into_iter()
        .map(|i| i.id)
        .collect::<Vec<_>>();
    assert_eq!(canonical.len(), 6, "root plus five children");

    let mut collected = Vec::new();
    let mut query = ODataQuery::new().with_limit(2);
    loop {
        let page = repo
            .get_descendants(&conn, &scope, fixture.root.id, &query)
            .await
            .expect("paginated fetch");
        collected.extend(page.items.iter().map(|i| i.id));
        match page.page_info.next_cursor {
            Some(token) => {
                let cursor = CursorV1::decode(&token).expect("valid cursor");
                query = ODataQuery::new().with_limit(2).with_cursor(cursor);
            }
            None => break,
        }
    }

    assert_eq!(
        collected, canonical,
        "walking the cursor two at a time must reproduce the canonical order with no gaps or dupes"
    );
}

#[tokio::test]
async fn hierarchy_cursor_filtered_pagination_has_no_gaps_or_dupes() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;
    let raw = format!("type eq '{}'", fixture.child_type_code);

    let canonical = repo
        .get_descendants(
            &conn,
            &scope,
            fixture.root.id,
            &filter_query(&raw).with_limit(100),
        )
        .await
        .expect("canonical filtered fetch")
        .items
        .into_iter()
        .map(|i| i.id)
        .collect::<Vec<_>>();
    assert_eq!(canonical.len(), 5, "exactly the five children, not root");

    let mut collected = Vec::new();
    let mut query = filter_query(&raw).with_limit(2);
    loop {
        let page = repo
            .get_descendants(&conn, &scope, fixture.root.id, &query)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "paginated filtered fetch must not fail (ML-8813: cursor `f` must be minted \
                     from query.filter_hash, or the second page of any filtered /descendants \
                     request fails FilterMismatch): {e}"
                )
            });
        collected.extend(page.items.iter().map(|i| i.id));
        match page.page_info.next_cursor {
            // A REST client resends the same `$filter` on every page
            // request; simulate that by rebuilding the same filter (and
            // therefore the same filter_hash) rather than reusing `query`.
            Some(token) => {
                let cursor = CursorV1::decode(&token).expect("valid cursor");
                query = filter_query(&raw).with_limit(2).with_cursor(cursor);
            }
            None => break,
        }
    }

    assert_eq!(
        collected, canonical,
        "walking the filtered cursor two at a time must reproduce the canonical filtered order"
    );
}

#[tokio::test]
async fn hierarchy_cursor_prev_roundtrips_to_the_same_page() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let page1 = repo
        .get_descendants(
            &conn,
            &scope,
            fixture.root.id,
            &ODataQuery::new().with_limit(2),
        )
        .await
        .expect("page 1");
    let page1_ids: Vec<Uuid> = page1.items.iter().map(|i| i.id).collect();

    let next = page1.page_info.next_cursor.expect("page 1 has a next page");
    let page2 = repo
        .get_descendants(
            &conn,
            &scope,
            fixture.root.id,
            &ODataQuery::new()
                .with_limit(2)
                .with_cursor(CursorV1::decode(&next).expect("valid cursor")),
        )
        .await
        .expect("page 2");

    let prev = page2.page_info.prev_cursor.expect("page 2 has a prev page");
    let page1_again = repo
        .get_descendants(
            &conn,
            &scope,
            fixture.root.id,
            &ODataQuery::new()
                .with_limit(2)
                .with_cursor(CursorV1::decode(&prev).expect("valid cursor")),
        )
        .await
        .expect("page 1 via prev");
    let page1_again_ids: Vec<Uuid> = page1_again.items.iter().map(|i| i.id).collect();

    assert_eq!(
        page1_ids, page1_again_ids,
        "prev must round-trip to the same page"
    );
}

// -- Negative: reject, never degrade to offset 0 --

/// Fetch a real, well-formed cursor to mutate for the negative tests below,
/// rather than hardcoding the signature constant (private to
/// `group_repo.rs`) in this external-crate test file.
async fn sample_cursor(
    repo: &GroupRepository,
    conn: &impl toolkit_db::secure::DBRunner,
    scope: &AccessScope,
    group_id: Uuid,
) -> CursorV1 {
    let page = repo
        .get_descendants(conn, scope, group_id, &ODataQuery::new().with_limit(1))
        .await
        .expect("seed fetch");
    let token = page
        .page_info
        .next_cursor
        .expect("seed fetch must have a next page to sample a cursor from");
    CursorV1::decode(&token).expect("valid cursor")
}

fn assert_rejected(
    result: Result<
        toolkit_odata::Page<resource_group_sdk::models::ResourceGroupWithDepth>,
        DomainError,
    >,
) {
    match result {
        Err(DomainError::Validation { .. }) => {}
        Err(other) => panic!("expected DomainError::Validation, got {other:?}"),
        Ok(page) => panic!(
            "expected the malformed cursor to be rejected, got a successful page: {:?}",
            page.items.iter().map(|i| i.id).collect::<Vec<_>>()
        ),
    }
}

#[tokio::test]
async fn hierarchy_cursor_stale_pre_epoch_signature_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.s = "depth".to_owned(); // the pre-ML-4182/8813 signature value
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &query)
            .await,
    );
}

#[tokio::test]
async fn hierarchy_cursor_wrong_sort_direction_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.o = SortDir::Desc;
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &query)
            .await,
    );
}

#[tokio::test]
async fn hierarchy_cursor_multi_key_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.k = vec!["1".to_owned(), "2".to_owned()];
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &query)
            .await,
    );
}

#[tokio::test]
async fn hierarchy_cursor_negative_offset_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.k = vec!["-1".to_owned()];
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &query)
            .await,
    );
}

#[tokio::test]
async fn hierarchy_cursor_non_numeric_offset_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.k = vec!["not-a-number".to_owned()];
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &query)
            .await,
    );
}

#[tokio::test]
async fn hierarchy_cursor_filter_hash_mismatch_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    // Mint a cursor under one filter, then replay it against a request with
    // no filter at all -- the minted `f` (Some(hash)) must not match the
    // second request's `filter_hash` (None).
    let filtered = filter_query(&format!("type eq '{}'", fixture.child_type_code)).with_limit(1);
    let page = repo
        .get_descendants(&conn, &scope, fixture.root.id, &filtered)
        .await
        .expect("filtered seed fetch");
    let token = page
        .page_info
        .next_cursor
        .expect("filtered seed fetch must have a next page");
    let cursor = CursorV1::decode(&token).expect("valid cursor");

    let unfiltered_query = ODataQuery::new().with_limit(1).with_cursor(cursor);
    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &unfiltered_query)
            .await,
    );
}

#[tokio::test]
async fn hierarchy_cursor_huge_offset_does_not_panic() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.k = vec![usize::MAX.to_string()];
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    let page = repo
        .get_descendants(&conn, &scope, fixture.root.id, &query)
        .await
        .expect("a huge but well-formed offset must not panic and must not be rejected");
    assert!(
        page.items.is_empty(),
        "an offset past the end returns an empty page"
    );
    assert!(
        page.page_info.next_cursor.is_none(),
        "checked_add overflow must not produce a next_cursor"
    );
}

/// A cursor whose direction field is neither `fwd` nor `bwd` is rejected.
///
/// The REST path never produces one — `CursorV1::decode` rejects it first —
/// but `ODataQuery::with_cursor` takes a `CursorV1` by value, so an
/// in-process caller (this gear has them by design, via `RgReadService` over
/// `ClientHub`) can hand the repository a struct that never saw the decoder.
/// The repository therefore checks `d` itself rather than trusting it was
/// already checked upstream.
#[tokio::test]
async fn hierarchy_cursor_unknown_direction_rejected() {
    let db = common::test_db().await;
    let tenant_id = Uuid::now_v7();
    let fixture = build_fixture(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    let mut cursor = sample_cursor(&repo, &conn, &scope, fixture.root.id).await;
    cursor.d = "sideways".to_owned();
    let query = ODataQuery::new().with_limit(2).with_cursor(cursor);

    assert_rejected(
        repo.get_descendants(&conn, &scope, fixture.root.id, &query)
            .await,
    );
}
