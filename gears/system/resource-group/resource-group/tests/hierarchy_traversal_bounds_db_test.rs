// Created: 2026-07-31 by Constructor Tech
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]
//! SQLite `:memory:` tests proving `HierarchyFilter::traversal_bounds`
//! narrows the closure-table query without ever excluding a row that
//! `HierarchyFilter::matches` would have accepted (ML-4182/ML-8813).
//!
//! This is the stated stack of `docs/toolkit_unified_system/12_unit_testing.md`
//! (`:26-28` allows this ярус directly), and it is the *only* ярус that can
//! prove the narrowing actually reached SQL rather than merely computing
//! the right answer in memory: the pure unit tests in
//! `src/domain/hierarchy_filter_tests.rs` pin `traversal_bounds`'s return
//! value in isolation, but say nothing about whether `GroupRepository`
//! actually threads that value into the closure-table query. A
//! [`toolkit_db::test_support::QueryRecorder`] closes that gap by recording
//! the real SQL SeaORM issues; assertions below check the *normalized*
//! `RecordedQuery.sql` (literals redacted), never `raw_sql`, per the
//! recorder's own guidance -- normalized SQL is what proves the query
//! *shape* changed, and matching against a literal bound value would be
//! testing an implementation detail the unit tests already pin.
//!
//! New file rather than an addition to `tests/group_service_test.rs` or
//! `tests/tenant_filtering_db_test.rs`: traversal bounds are a
//! repository-level concern (`GroupRepositoryTrait::get_descendants` /
//! `get_ancestors` directly, no `GroupService` preflight or `AuthZ` scope in
//! the way), and `db_behavior_audit_test.rs` is a different subject
//! (write-path transaction hygiene). Direct-trait-from-`tests/` precedent:
//! `tests/pg_group_filter_test.rs:59-60,179`.
//!
//! Fixture: a single chain `root -> g1 -> g2 -> g3 -> g4 -> g5`, one type
//! per level, so a depth-based filter and a type-based filter can be
//! composed against known, distinct types and known depths.

mod common;

use std::sync::Arc;

use resource_group::domain::repo::GroupRepositoryTrait;
use resource_group::infra::storage::group_repo::GroupRepository;
use resource_group_sdk::ResourceGroup;
use toolkit_odata::ODataQuery;
use toolkit_security::AccessScope;
use uuid::Uuid;

/// Six-level chain fixture: `root` (depth 0) through `g5` (depth 5), one
/// distinct GTS type per level.
struct Chain {
    root: ResourceGroup,
    g1: ResourceGroup,
    // Depth 2; not asserted on directly by any scenario below, but kept
    // (not `_g2`) since it is real fixture data every scenario's exclusion
    // assertions rely on being present in the chain.
    #[allow(dead_code)]
    g2: ResourceGroup,
    g3: ResourceGroup,
    g4: ResourceGroup,
    g5: ResourceGroup,
}

async fn build_chain(
    db: &Arc<toolkit_db::DBProvider<toolkit_db::DbError>>,
    tenant_id: Uuid,
) -> Chain {
    let type_svc = common::make_type_service(db.clone());
    let group_svc = common::make_group_service(db.clone());
    let ctx = common::make_ctx(tenant_id);

    let t0 = common::create_root_type(&type_svc, "htb0").await;
    let t1 = common::create_child_type(&type_svc, "htb1", &[&t0.code], &[]).await;
    let t2 = common::create_child_type(&type_svc, "htb2", &[&t1.code], &[]).await;
    let t3 = common::create_child_type(&type_svc, "htb3", &[&t2.code], &[]).await;
    let t4 = common::create_child_type(&type_svc, "htb4", &[&t3.code], &[]).await;
    let t5 = common::create_child_type(&type_svc, "htb5", &[&t4.code], &[]).await;

    let root = common::create_root_group(&group_svc, &ctx, &t0.code, "root", tenant_id).await;
    let g1 = common::create_child_group(&group_svc, &ctx, &t1.code, root.id, "g1", tenant_id).await;
    let g2 = common::create_child_group(&group_svc, &ctx, &t2.code, g1.id, "g2", tenant_id).await;
    let g3 = common::create_child_group(&group_svc, &ctx, &t3.code, g2.id, "g3", tenant_id).await;
    let g4 = common::create_child_group(&group_svc, &ctx, &t4.code, g3.id, "g4", tenant_id).await;
    let g5 = common::create_child_group(&group_svc, &ctx, &t5.code, g4.id, "g5", tenant_id).await;

    Chain {
        root,
        g1,
        g2,
        g3,
        g4,
        g5,
    }
}

fn filter_query(raw: &str) -> ODataQuery {
    let parsed = toolkit_odata::parse_filter_string(raw)
        .unwrap_or_else(|e| panic!("fixture filter {raw:?} must parse: {e}"));
    ODataQuery::new().with_filter(parsed.into_expr())
}

/// Every recorded `SELECT` against `resource_group_closure`, most recent
/// last.
fn closure_selects(recorder: &toolkit_db::test_support::QueryRecorder) -> Vec<String> {
    recorder
        .events()
        .into_iter()
        .filter(|e| {
            e.kind == toolkit_db::test_support::QueryKind::Select
                && e.table.as_deref() == Some("resource_group_closure")
        })
        .map(|e| e.sql)
        .collect()
}

/// Whether any recorded closure `SELECT` narrows by an upper bound on
/// `depth` (`"depth" <= ?`, however SeaORM/sqlite happens to quote it).
fn any_select_bounds_depth(selects: &[String]) -> bool {
    selects
        .iter()
        .any(|sql| sql.to_ascii_lowercase().contains("depth\" <= ?"))
}

/// `hierarchy/depth eq 1 or hierarchy/depth eq 3`: both `or` branches are
/// bounded, so the union bound `Max(3)` must reach the closure query (proof
/// the SQL was narrowed), while the final result is still exactly `{g1, g3}`
/// -- not the wider `{root, g1, g2, g3}` a naive "just apply the bound and
/// stop" implementation would return, and not empty either.
#[tokio::test]
async fn hierarchy_traversal_bounds_or_returns_exact_union() {
    let (db, recorder) = common::test_db_with_recorder().await;
    let tenant_id = Uuid::now_v7();
    let chain = build_chain(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    recorder.clear();
    let query = filter_query("hierarchy/depth eq 1 or hierarchy/depth eq 3");
    let page = repo
        .get_descendants(&conn, &scope, chain.root.id, &query)
        .await
        .expect("get_descendants");

    let mut ids: Vec<Uuid> = page.items.iter().map(|i| i.id).collect();
    ids.sort();
    let mut expected = vec![chain.g1.id, chain.g3.id];
    expected.sort();
    assert_eq!(
        ids, expected,
        "expected exactly the depth=1 and depth=3 rows"
    );

    let selects = closure_selects(&recorder);
    assert!(
        any_select_bounds_depth(&selects),
        "expected the closure query to be narrowed by depth <= 3; recorded selects: {selects:?}"
    );
}

/// `hierarchy/depth eq 1 or type eq '<g5's type>'`: one `or` branch (`type`)
/// has no derivable bound, so the union must be `Unbounded` -- narrowing the
/// SQL query here would silently drop `g5`, which only matches through the
/// unbounded branch and sits far past where a (wrongly derived) depth bound
/// would cut off.
#[tokio::test]
async fn hierarchy_traversal_bounds_or_unbounded_branch_reaches_deep_match() {
    let (db, recorder) = common::test_db_with_recorder().await;
    let tenant_id = Uuid::now_v7();
    let chain = build_chain(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    recorder.clear();
    let query = filter_query(&format!(
        "hierarchy/depth eq 1 or type eq '{}'",
        chain.g5.code
    ));
    let page = repo
        .get_descendants(&conn, &scope, chain.root.id, &query)
        .await
        .expect("get_descendants");

    let mut ids: Vec<Uuid> = page.items.iter().map(|i| i.id).collect();
    ids.sort();
    let mut expected = vec![chain.g1.id, chain.g5.id];
    expected.sort();
    assert_eq!(
        ids, expected,
        "expected the depth=1 row and the deep type-matched row, and nothing else"
    );

    let selects = closure_selects(&recorder);
    assert!(
        !any_select_bounds_depth(&selects),
        "an unbounded `or` branch must not narrow the closure query; recorded selects: {selects:?}"
    );
}

/// `not (hierarchy/depth le 3)`: `not` never derives a bound, so the deep
/// match (`depth > 3`, i.e. `g4`/`g5`) must survive an unnarrowed fetch.
#[tokio::test]
async fn hierarchy_traversal_bounds_not_reaches_deep_match() {
    let (db, recorder) = common::test_db_with_recorder().await;
    let tenant_id = Uuid::now_v7();
    let chain = build_chain(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    recorder.clear();
    let query = filter_query("not (hierarchy/depth le 3)");
    let page = repo
        .get_descendants(&conn, &scope, chain.root.id, &query)
        .await
        .expect("get_descendants");

    let mut ids: Vec<Uuid> = page.items.iter().map(|i| i.id).collect();
    ids.sort();
    let mut expected = vec![chain.g4.id, chain.g5.id];
    expected.sort();
    assert_eq!(ids, expected, "expected exactly depth=4 and depth=5");

    let selects = closure_selects(&recorder);
    assert!(
        !any_select_bounds_depth(&selects),
        "`not` must never derive a narrowing bound; recorded selects: {selects:?}"
    );
}

/// `hierarchy/depth gt -3` on `/ancestors`: the composition returns exactly
/// `g5`'s ancestors at closure depth 1 and 2 (`g4`, `g3`), and the closure
/// query is narrowed rather than scanning the whole chain.
///
/// What this test does **not** prove is that the bound is the *tight* `2`
/// rather than the old, loose `4`: the recorded SQL only shows that a
/// `"depth" <= ?` predicate is present, and the recorder redacts literals,
/// so both bounds look identical here. Tightness is pinned one tier down, by
/// `hierarchy_filter_ancestor_bound_gt_negative_literal_is_tight`, which
/// asserts `Max(2)` directly. That split is deliberate — a value assertion
/// belongs where the value is computed, not where SQL is observed.
#[tokio::test]
async fn hierarchy_traversal_bounds_ancestor_gt_negative_narrows_to_physical_bound() {
    let (db, recorder) = common::test_db_with_recorder().await;
    let tenant_id = Uuid::now_v7();
    let chain = build_chain(&db, tenant_id).await;
    let conn = db.conn().expect("conn");
    let scope = AccessScope::allow_all();
    let repo = GroupRepository;

    recorder.clear();
    let query = filter_query("hierarchy/depth gt -3");
    let page = repo
        .get_ancestors(&conn, &scope, chain.g5.id, &query)
        .await
        .expect("get_ancestors");

    let mut ids: Vec<Uuid> = page.items.iter().map(|i| i.id).collect();
    ids.sort();
    let mut expected = vec![chain.g5.id, chain.g4.id, chain.g3.id];
    expected.sort();
    assert_eq!(
        ids, expected,
        "expected self plus two levels up, not the deeper ancestors"
    );

    let selects = closure_selects(&recorder);
    assert!(
        any_select_bounds_depth(&selects),
        "expected the ancestor-rows query to be narrowed to depth <= 2; recorded selects: {selects:?}"
    );
}
