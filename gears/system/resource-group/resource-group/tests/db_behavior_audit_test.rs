// Created: 2026-07-26 by Constructor Tech
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::too_many_lines
)]
//! DB-behavior audit for resource-group (Step 1 of the audit program).
//!
//! Two complementary detection mechanisms, both driven by *class*-level
//! rules (not hardcoded to specific line numbers):
//!
//! 1. **Dynamic trace analysis** (this file's majority): every write
//!    operation runs against a real SQLite connection with
//!    [`toolkit_db::test_support::QueryRecorder`] attached, then:
//!    - `writes_outside_tx()` must be empty -- every INSERT/UPDATE/DELETE
//!      must run inside a `Db::transaction*` closure (`no-tx-write` class).
//!    - **Scale-invariance**: statement counts for a given (kind, table)
//!      shape must not grow with N (subtree size / junction list length /
//!      ancestor depth) -- growth is the `n-plus-one` class.
//!    - `redundant_reads_after_write()` flags the `redundant-io` class
//!      (write ignores the model it just wrote, re-reads by id).
//!
//! 2. **Static source-scan rules** (bottom of this file): two defect
//!    classes the SQL trace cannot see at all, because they aren't SQL --
//!    `no-retry-serializable` (a SERIALIZABLE tx not wrapped in the retry
//!    helper) and `external-call-in-tx` (an external-dependency call
//!    textually inside a transaction closure). Both are plain `#[test]`s
//!    over the checked-in source text, no DB involved.
//!
//! Known defects are asserted for real and marked `#[ignore = "known defect
//! RG-XX: ..."]` so the suite stays green while the defect stays
//! executable-and-documented. Operations that are *not* known-defective
//! assert the healthy invariant directly (non-ignored) -- these double as
//! negative controls proving the rules don't fire indiscriminately.
//!
//! Each operation's SQL trace can be dumped for reading by eye by setting
//! `DB_AUDIT_TRACE_DIR` (see [`snapshot_trace`]); an ordinary run writes
//! nothing.
//!
//! Findings inventory and how to repeat this audit on another module:
//! `docs/db-behavior-audit.md`.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use resource_group::domain::group_service::{GroupService, QueryProfile};
use resource_group::domain::seeding::{self, GroupSeedDef};
use resource_group::domain::type_service::TypeService;
use resource_group::infra::storage::group_repo::GroupRepository;
use resource_group::infra::storage::type_repo::TypeRepository;
use resource_group_sdk::{CreateTypeRequest, UpdateGroupRequest, UpdateTypeRequest};
use toolkit_db::test_support::{QueryKind, snapshot_trace};
use toolkit_gts::gts_id;
use toolkit_security::SecurityContext;
use uuid::Uuid;

// =========================================================================
// Fixture helpers
// =========================================================================

fn make_group_service_with_profile(
    db: Arc<toolkit_db::DBProvider<toolkit_db::DbError>>,
    profile: QueryProfile,
) -> GroupService<GroupRepository, TypeRepository> {
    GroupService::new(
        db,
        profile,
        common::make_enforcer(),
        Arc::new(GroupRepository),
        Arc::new(TypeRepository),
        common::make_types_registry(),
    )
}

/// A type that can root itself and allows itself as a parent -- lets a
/// single type build chains/trees of arbitrary depth and width.
async fn create_self_referencing_type(
    type_svc: &TypeService<TypeRepository>,
    suffix: &str,
) -> resource_group_sdk::ResourceGroupType {
    // `resolve_ids` rejects a parent path that doesn't exist yet, so a type
    // can't reference itself as an allowed parent at create time (mirrors
    // group_service_test.rs's `create_tenant_type` helper comment). Create
    // it plain, then update it to add the self-reference now that the row
    // exists.
    let code = format!(
        "{}x.test.{}.i{}.v1~",
        gts_id!("cf.core.rg.type.v1~"),
        suffix.to_ascii_lowercase(),
        Uuid::now_v7().as_simple()
    );
    type_svc
        .create_type(CreateTypeRequest {
            code: code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .expect("create self-referencing type (initial)");
    type_svc
        .update_type(
            &code,
            UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![code.clone()],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .expect("update type to add self-reference")
}

/// Mirrors `membership_service_test.rs`'s local helper: a root type whose
/// `allowed_membership_types` includes the given resource-type paths.
async fn create_type_with_memberships(
    type_svc: &TypeService<TypeRepository>,
    suffix: &str,
    memberships: &[&str],
) -> resource_group_sdk::ResourceGroupType {
    let code = format!(
        "{}x.test.{}.i{}.v1~",
        gts_id!("cf.core.rg.type.v1~"),
        suffix.to_ascii_lowercase(),
        Uuid::now_v7().as_simple()
    );
    type_svc
        .create_type(CreateTypeRequest {
            code,
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: memberships.iter().map(|s| (*s).to_owned()).collect(),
            metadata_schema: None,
        })
        .await
        .expect("create type with memberships")
}

/// Build a chain of `depth` nodes (root + `depth - 1` single children),
/// returning the id of the last (deepest) node.
async fn build_chain(
    group_svc: &GroupService<GroupRepository, TypeRepository>,
    ctx: &SecurityContext,
    type_code: &str,
    tenant_id: Uuid,
    depth: usize,
) -> Uuid {
    assert!(depth >= 1, "chain must have at least one node");
    let root = common::create_root_group(group_svc, ctx, type_code, "n0", tenant_id).await;
    let mut current = root.id;
    for i in 1..depth {
        let child = common::create_child_group(
            group_svc,
            ctx,
            type_code,
            current,
            &format!("n{i}"),
            tenant_id,
        )
        .await;
        current = child.id;
    }
    current
}

/// Build a flat subtree under `parent_id`: one "subtree root" child plus
/// `child_count` leaves directly under it. Returns the subtree root's id.
/// Total subtree size (including the subtree root) is `child_count + 1`.
async fn build_flat_subtree(
    group_svc: &GroupService<GroupRepository, TypeRepository>,
    ctx: &SecurityContext,
    type_code: &str,
    parent_id: Uuid,
    tenant_id: Uuid,
    child_count: usize,
) -> Uuid {
    let subtree_root = common::create_child_group(
        group_svc,
        ctx,
        type_code,
        parent_id,
        "subtree-root",
        tenant_id,
    )
    .await;
    for i in 0..child_count {
        common::create_child_group(
            group_svc,
            ctx,
            type_code,
            subtree_root.id,
            &format!("leaf{i}"),
            tenant_id,
        )
        .await;
    }
    subtree_root.id
}

fn count_in(stats: &BTreeMap<(QueryKind, String), usize>, kind: QueryKind, table: &str) -> usize {
    stats.get(&(kind, table.to_owned())).copied().unwrap_or(0)
}

// =========================================================================
// Section 1 -- per-operation trace snapshots + writes-in-tx assertions
// =========================================================================

#[tokio::test]
async fn trace_create_root_group() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let root_type = common::create_root_type(&type_svc, "org").await;

    rec.clear();
    let root =
        common::create_root_group(&group_svc, &ctx, &root_type.code, "Root", tenant_id).await;
    assert_eq!(root.hierarchy.parent_id, None);

    snapshot_trace("create_root_group", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "create_group must run its writes inside a transaction:\n{}",
        rec.dump()
    );
    // RG-08 fixed: group_repo::insert used to discard secure_insert's
    // returned model and issue its own explicit re-read. Exactly 2
    // resource_group SELECTs remain: SeaORM's own non-RETURNING-fallback
    // re-select (`ActiveModelTrait::insert` on SQLite, since this
    // workspace doesn't enable `sqlite-use-returning-for-3_35` --
    // unavoidable at the app level, absent entirely on PostgreSQL) plus
    // create_group_inner's final find_by_id to build the returned SDK
    // model. Was 3 before the fix (the extra explicit find_model_by_id).
    let rg_selects = count_in(&rec.stats(), QueryKind::Select, "resource_group");
    assert_eq!(
        rg_selects,
        2,
        "RG-08 regression: expected exactly 2 resource_group SELECTs (SeaORM's \
         non-RETURNING fallback + the final find_by_id), got {rg_selects}:\n{}",
        rec.dump()
    );
    // RG-11 fixed: create_group_inner used to call resolve_id then
    // find_by_code for the same req.code (two "SELECT gts_type WHERE
    // schema_id = ?" statements). find_by_code_with_id now resolves both
    // the surrogate id and the full type in one query. Exactly 2 gts_type
    // SELECTs remain: that combined lookup, plus create_group_inner's
    // final resolve-by-id for the returned SDK model. Was 3 before the fix.
    let type_selects = count_in(&rec.stats(), QueryKind::Select, "gts_type");
    assert_eq!(
        type_selects,
        2,
        "RG-11 regression: expected exactly 2 gts_type SELECTs (the combined \
         find_by_code_with_id lookup + the final resolve-by-id), got \
         {type_selects}:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_create_child_group_depth3() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = make_group_service_with_profile(
        db.clone(),
        QueryProfile {
            max_depth: None,
            max_width: None,
        },
    );
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = create_self_referencing_type(&type_svc, "chain").await;

    let n0 = common::create_root_group(&group_svc, &ctx, &t.code, "n0", tenant_id).await;
    let n1 = common::create_child_group(&group_svc, &ctx, &t.code, n0.id, "n1", tenant_id).await;

    rec.clear();
    let n2 = common::create_child_group(&group_svc, &ctx, &t.code, n1.id, "n2", tenant_id).await;
    assert_eq!(n2.hierarchy.parent_id, Some(n1.id));

    snapshot_trace("create_child_group_depth3", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "create_group must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_update_group() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = common::create_root_type(&type_svc, "org").await;
    let root = common::create_root_group(&group_svc, &ctx, &t.code, "Root", tenant_id).await;

    rec.clear();
    let updated = group_svc
        .update_group(
            &ctx,
            root.id,
            UpdateGroupRequest {
                name: "Root Renamed".to_owned(),
                parent_id: None,
                metadata: None,
            },
        )
        .await
        .expect("update_group should succeed");
    assert_eq!(updated.name, "Root Renamed");

    snapshot_trace("update_group", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "update_group must run its writes inside a transaction:\n{}",
        rec.dump()
    );
    // Known defect RG-08 (redundant-io): the repo write ignores the model it
    // just wrote and re-reads it by id immediately after.
    assert!(
        !rec.redundant_reads_after_write().is_empty(),
        "expected a redundant read-after-write on resource_group (known defect RG-08):\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_move_group() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = create_self_referencing_type(&type_svc, "mv").await;

    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;
    let target_parent =
        common::create_child_group(&group_svc, &ctx, &t.code, root.id, "target", tenant_id).await;
    // Small subtree (3 nodes) so the canonical trace isn't dominated by noise.
    let moved = build_flat_subtree(&group_svc, &ctx, &t.code, root.id, tenant_id, 2).await;

    rec.clear();
    let result = group_svc
        .move_group(moved, Some(target_parent.id))
        .await
        .expect("move_group should succeed");
    assert_eq!(result.hierarchy.parent_id, Some(target_parent.id));

    snapshot_trace("move_group", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "move_group must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_force_delete_subtree() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = create_self_referencing_type(&type_svc, "del").await;
    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;
    let subtree_root = build_flat_subtree(&group_svc, &ctx, &t.code, root.id, tenant_id, 2).await;

    rec.clear();
    group_svc
        .delete_group(&ctx, subtree_root, true)
        .await
        .expect("force delete should succeed");

    snapshot_trace("force_delete_subtree", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "delete_group(force=true) must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_create_type() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));

    rec.clear();
    let t = common::create_root_type(&type_svc, "newtype").await;
    assert!(t.can_be_root);

    snapshot_trace("create_type", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "create_type's writes run inside a transaction (RG-03's missing retry \
         wrapper -- not trace-observable -- is fixed too, see the static rule \
         tests at the bottom of this file):\n{}",
        rec.dump()
    );
    // RG-08 fixed: type_repo::insert used to discard secure_insert's
    // returned model and issue its own explicit find_model_by_code
    // re-read. Exactly 2 gts_type SELECTs remain: the "does this code
    // already exist" pre-check plus SeaORM's own non-RETURNING-fallback
    // re-select (unavoidable at the app level on SQLite, absent on
    // PostgreSQL). Was 3 before the fix.
    let type_selects = count_in(&rec.stats(), QueryKind::Select, "gts_type");
    assert_eq!(
        type_selects,
        2,
        "RG-08 regression: expected exactly 2 gts_type SELECTs (the exists-check + \
         SeaORM's non-RETURNING fallback), got {type_selects}:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_update_type() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let t = common::create_root_type(&type_svc, "upd").await;

    rec.clear();
    let updated = type_svc
        .update_type(
            &t.code,
            UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![],
                allowed_membership_types: vec![],
                metadata_schema: Some(serde_json::json!({"type": "object"})),
            },
        )
        .await
        .expect("update_type should succeed");
    assert_eq!(
        updated.metadata_schema,
        Some(serde_json::json!({"type": "object"}))
    );

    snapshot_trace("update_type", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "update_type's writes run inside a transaction (RG-03's retry wrapper, \
         not trace-observable, is fixed too):\n{}",
        rec.dump()
    );
    // RG-11 fixed: update_type_in_tx used to call find_by_code then,
    // further down, resolve_id for the same code (two "SELECT gts_type
    // WHERE schema_id = ?" statements). find_by_code_with_id now resolves
    // both together in one query. Exactly 2 gts_type SELECTs remain: that
    // combined lookup, plus the necessary post-update_many re-read (update_type
    // goes through SecureUpdateMany, which -- unlike secure_insert -- only
    // reports rows-affected, not the model; see RG-08's commit message for
    // why that one is not fixable the same way). Was 3 before the fix.
    let type_selects = count_in(&rec.stats(), QueryKind::Select, "gts_type");
    assert_eq!(
        type_selects,
        2,
        "RG-11 regression: expected exactly 2 gts_type SELECTs (the combined \
         find_by_code_with_id lookup + the necessary post-update re-read), got \
         {type_selects}:\n{}",
        rec.dump()
    );
}

/// Known defect RG-02 fixed: delete_type's resolve/count/delete sequence now
/// runs inside a SERIALIZABLE transaction with retry (see
/// `TypeService::delete_type`). This is now a permanent guard, not a
/// documented-but-ignored finding.
#[tokio::test]
async fn trace_delete_type() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let t = common::create_root_type(&type_svc, "del").await;

    rec.clear();
    type_svc
        .delete_type(&t.code)
        .await
        .expect("delete_type should succeed (no groups reference it)");

    snapshot_trace("delete_type", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "delete_type must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

/// Known defect RG-01 fixed: add_membership's check-then-insert sequence now
/// runs inside a SERIALIZABLE transaction with retry (see
/// `MembershipService::add_membership_inner`). This is now a permanent
/// guard, not a documented-but-ignored finding.
#[tokio::test]
async fn trace_add_membership() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let membership_svc = common::make_membership_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let member_type = common::create_root_type(&type_svc, "mbr").await;
    let grp_type = create_type_with_memberships(&type_svc, "grp", &[&member_type.code]).await;
    let group = common::create_root_group(&group_svc, &ctx, &grp_type.code, "G1", tenant_id).await;

    rec.clear();
    membership_svc
        .add_membership(&ctx, group.id, &member_type.code, "res-001")
        .await
        .expect("add_membership should succeed");

    snapshot_trace("add_membership", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "add_membership must run its writes inside a transaction:\n{}",
        rec.dump()
    );
    // RG-08 fixed: membership_repo::insert used to discard secure_insert's
    // returned model and issue its own explicit find_by_composite_key
    // re-read. Exactly 2 resource_group_membership SELECTs remain: the
    // tenant-compatibility pre-check plus SeaORM's own non-RETURNING-
    // fallback re-select (unavoidable at the app level on SQLite, absent
    // on PostgreSQL). Was 3 before the fix.
    let membership_selects = count_in(&rec.stats(), QueryKind::Select, "resource_group_membership");
    assert_eq!(
        membership_selects,
        2,
        "RG-08 regression: expected exactly 2 resource_group_membership SELECTs \
         (the tenant-compatibility check + SeaORM's non-RETURNING fallback), got \
         {membership_selects}:\n{}",
        rec.dump()
    );
}

/// RG-14 fixed: `remove_membership` had the *same* check-then-write shape as
/// `add_membership` (resolve type, verify existence, delete) on a bare
/// connection -- the general `no-tx-write` rule caught it too, even though
/// only `add_membership` was in the original ground-truth list. Now runs
/// inside a SERIALIZABLE transaction with retry (see
/// `MembershipService::remove_membership`).
#[tokio::test]
async fn trace_remove_membership() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let membership_svc = common::make_membership_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let member_type = common::create_root_type(&type_svc, "mbr").await;
    let grp_type = create_type_with_memberships(&type_svc, "grp", &[&member_type.code]).await;
    let group = common::create_root_group(&group_svc, &ctx, &grp_type.code, "G1", tenant_id).await;
    membership_svc
        .add_membership(&ctx, group.id, &member_type.code, "res-001")
        .await
        .expect("add_membership should succeed");

    rec.clear();
    membership_svc
        .remove_membership(&ctx, group.id, &member_type.code, "res-001")
        .await
        .expect("remove_membership should succeed");

    snapshot_trace("remove_membership", &rec);
    assert!(
        rec.writes_outside_tx().is_empty(),
        "remove_membership must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn trace_seeding() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();

    let type_code = format!(
        "{}x.test.seed.i{}.v1~",
        gts_id!("cf.core.rg.type.v1~"),
        Uuid::now_v7().as_simple()
    );

    rec.clear();
    let type_seeds = vec![CreateTypeRequest {
        code: type_code.clone(),
        can_be_root: true,
        allowed_parent_types: vec![],
        allowed_membership_types: vec![],
        metadata_schema: None,
    }];
    let type_result = seeding::seed_types(&type_svc, &type_seeds)
        .await
        .expect("seed_types should succeed");
    assert_eq!(type_result.created, 1);

    let root_id = Uuid::now_v7();
    let group_seeds = vec![GroupSeedDef {
        id: root_id,
        code: type_code,
        name: "Seeded Root".to_owned(),
        parent_id: None,
        metadata: None,
        tenant_id,
    }];
    let group_result = seeding::seed_groups(&group_svc, &group_seeds)
        .await
        .expect("seed_groups should succeed");
    assert_eq!(group_result.created, 1);

    // NOTE: membership seeding shares add_membership_inner's transaction
    // behavior (RG-01, fixed); trace_add_membership asserts it directly, not
    // repeated here.
    snapshot_trace("seeding", &rec);
}

// =========================================================================
// Section 2 -- scale-invariance: statement count must not grow with N
// =========================================================================

#[tokio::test]
async fn scale_create_child_closure_inserts_do_not_grow_with_ancestor_depth() {
    // RG-06 fixed: group_repo::insert_ancestor_closure_rows now sends the
    // whole ancestor batch as a single secure_insert_many call instead of
    // one secure_insert per ancestor.
    async fn closure_inserts_for_new_child_at_depth(depth: usize) -> usize {
        let (db, rec) = common::test_db_with_recorder().await;
        let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
        let group_svc = make_group_service_with_profile(
            db.clone(),
            QueryProfile {
                max_depth: None,
                max_width: None,
            },
        );
        let tenant_id = Uuid::now_v7();
        let ctx = common::make_ctx(tenant_id);
        let t = create_self_referencing_type(&type_svc, "anc").await;
        let last = build_chain(&group_svc, &ctx, &t.code, tenant_id, depth).await;

        rec.clear();
        common::create_child_group(&group_svc, &ctx, &t.code, last, "extra", tenant_id).await;
        count_in(&rec.stats(), QueryKind::Insert, "resource_group_closure")
    }

    let small = closure_inserts_for_new_child_at_depth(3).await;
    let large = closure_inserts_for_new_child_at_depth(15).await;
    assert_eq!(
        small, large,
        "closure INSERT count must not scale with ancestor depth \
         (small={small} at depth 3, large={large} at depth 15)"
    );
}

async fn move_stats_for_subtree_size(n: usize) -> BTreeMap<(QueryKind, String), usize> {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = create_self_referencing_type(&type_svc, "mvscale").await;

    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;
    let target_parent =
        common::create_child_group(&group_svc, &ctx, &t.code, root.id, "target", tenant_id).await;
    assert!(n >= 1);
    let moved = build_flat_subtree(&group_svc, &ctx, &t.code, root.id, tenant_id, n - 1).await;

    rec.clear();
    group_svc
        .move_group(moved, Some(target_parent.id))
        .await
        .expect("move_group should succeed");
    rec.stats()
}

#[tokio::test]
async fn scale_move_closure_inserts_do_not_grow_with_subtree_size() {
    // RG-04 fixed: group_repo::rebuild_subtree_closure now sends the whole
    // A x N batch as a single secure_insert_many call.
    let small = count_in(
        &move_stats_for_subtree_size(3).await,
        QueryKind::Insert,
        "resource_group_closure",
    );
    let large = count_in(
        &move_stats_for_subtree_size(15).await,
        QueryKind::Insert,
        "resource_group_closure",
    );
    assert_eq!(
        small, large,
        "closure INSERT count during move must not scale with subtree size \
         (small={small} at N=3, large={large} at N=15)"
    );
}

#[tokio::test]
async fn scale_move_descendant_depth_selects_do_not_grow_with_subtree_size() {
    // RG-05 fixed: move's depth validation now calls
    // get_descendant_ids_with_depth once and takes the max in memory,
    // instead of is_descendant + get_relative_depth once per descendant.
    let small = count_in(
        &move_stats_for_subtree_size(3).await,
        QueryKind::Select,
        "resource_group_closure",
    );
    let large = count_in(
        &move_stats_for_subtree_size(15).await,
        QueryKind::Select,
        "resource_group_closure",
    );
    assert_eq!(
        small, large,
        "closure SELECT count during move must not scale with subtree size \
         (small={small} at N=3, large={large} at N=15)"
    );
}

async fn junction_inserts_for_parent_count(n: usize) -> usize {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let mut parent_codes = Vec::with_capacity(n);
    for i in 0..n {
        let t = common::create_root_type(&type_svc, &format!("par{i}")).await;
        parent_codes.push(t.code);
    }

    rec.clear();
    type_svc
        .create_type(CreateTypeRequest {
            code: format!(
                "{}x.test.child.i{}.v1~",
                gts_id!("cf.core.rg.type.v1~"),
                Uuid::now_v7().as_simple()
            ),
            can_be_root: false,
            allowed_parent_types: parent_codes,
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .expect("create_type with N allowed parents should succeed");

    count_in(&rec.stats(), QueryKind::Insert, "gts_type_allowed_parent")
}

#[tokio::test]
async fn scale_create_type_junction_inserts_do_not_grow_with_parent_count() {
    // RG-07 fixed: allowed-parent/membership junction rows are now inserted
    // via a single secure_insert_many call.
    let small = junction_inserts_for_parent_count(2).await;
    let large = junction_inserts_for_parent_count(8).await;
    assert_eq!(
        small, large,
        "gts_type_allowed_parent INSERT count must not scale with \
         allowed_parent_types length (small={small} at N=2, large={large} at N=8)"
    );
}

async fn list_types_total_statements_for_page_size(n: usize) -> usize {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    // Self-referencing types (non-empty allowed_parent_types) so the batch
    // loader's junction-row and id->code resolution queries are actually
    // exercised for every row in the page, not skipped as trivially empty.
    for i in 0..n {
        create_self_referencing_type(&type_svc, &format!("listscale{i}")).await;
    }

    rec.clear();
    let query = toolkit_odata::ODataQuery {
        limit: Some(n as u64 + 5),
        ..Default::default()
    };
    let page = type_svc
        .list_types(&query)
        .await
        .expect("list_types should succeed");
    assert_eq!(page.items.len(), n, "page must contain all N created types");
    rec.total()
}

#[tokio::test]
async fn scale_list_types_statements_do_not_grow_with_page_size() {
    // RG-12 fixed (n-plus-one, read path): list_types used to call
    // load_full_type once per row -- each issuing its own junction-table
    // queries (plus a further id->code resolution query when non-empty) --
    // so statement count grew with page size. load_full_types_batch now
    // issues a constant number of queries for the whole page.
    let small = list_types_total_statements_for_page_size(3).await;
    let large = list_types_total_statements_for_page_size(15).await;
    assert_eq!(
        small, large,
        "list_types total statement count must not scale with page size \
         (small={small} at N=3, large={large} at N=15)"
    );
}

#[tokio::test]
async fn create_type_conflict_check_does_not_overfetch_junctions() {
    // RG-13 fixed (redundant-io): create_type's duplicate-check used to
    // call find_by_code, which loads full junction data (allowed parents +
    // memberships) just to test existence -- visible specifically on the
    // *conflict* path (creating an already-existing code); the happy path
    // never hit it, since it short-circuits before load_full_type. resolve_id
    // now does the same existence check with a single, plain id lookup --
    // no junction reads at all, on either path.
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let t = common::create_root_type(&type_svc, "conflict").await;

    rec.clear();
    let result = type_svc
        .create_type(CreateTypeRequest {
            code: t.code.clone(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await;
    assert!(
        matches!(
            result,
            Err(resource_group::domain::error::DomainError::TypeAlreadyExists { .. })
        ),
        "expected a clean TypeAlreadyExists for the conflicting create, got: {result:?}"
    );

    let parent_junction_selects =
        count_in(&rec.stats(), QueryKind::Select, "gts_type_allowed_parent");
    let membership_junction_selects = count_in(
        &rec.stats(),
        QueryKind::Select,
        "gts_type_allowed_membership",
    );
    assert_eq!(
        parent_junction_selects,
        0,
        "RG-13 regression: the duplicate-code conflict check must not read \
         gts_type_allowed_parent at all, got {parent_junction_selects} SELECTs:\n{}",
        rec.dump()
    );
    assert_eq!(
        membership_junction_selects,
        0,
        "RG-13 regression: the duplicate-code conflict check must not read \
         gts_type_allowed_membership at all, got {membership_junction_selects} SELECTs:\n{}",
        rec.dump()
    );
}

async fn total_statements_for_force_delete(n: usize) -> usize {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = create_self_referencing_type(&type_svc, "fd").await;
    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;
    assert!(n >= 1);
    for i in 0..(n - 1) {
        common::create_child_group(
            &group_svc,
            &ctx,
            &t.code,
            root.id,
            &format!("leaf{i}"),
            tenant_id,
        )
        .await;
    }

    rec.clear();
    group_svc
        .delete_group(&ctx, root.id, true)
        .await
        .expect("force delete should succeed");
    rec.total()
}

#[tokio::test]
async fn scale_force_delete_statements_do_not_grow_with_subtree_size() {
    // RG-10 fixed: force delete now batches memberships/closure deletes
    // across the whole subtree (2 + 1 statements total) and deletes groups
    // depth-level by depth-level (one batched statement per distinct depth,
    // deepest first) instead of ~4 statements per node in a loop.
    let small = total_statements_for_force_delete(3).await;
    let large = total_statements_for_force_delete(15).await;
    assert_eq!(
        small, large,
        "force-delete total statement count must not scale with subtree size \
         (small={small} at N=3, large={large} at N=15)"
    );
}

// =========================================================================
// Section 3 -- negative controls
// =========================================================================
//
// These prove the detector distinguishes protected invariants from broken
// ones: both scenarios below rely on SERIALIZABLE + retry and must show
// writes_outside_tx() == empty, just like the healthy operations in
// Section 1 -- the SQLite trace can't exercise the actual SSI conflict
// (that needs real concurrency; see tests/pg_concurrency_test.rs), but it
// does prove these paths aren't flagged by the same rule that catches RG-01/02.

fn unique_tenant_type_code() -> String {
    format!(
        "{}test{}.v1~",
        resource_group_sdk::TENANT_RG_TYPE_PATH,
        Uuid::now_v7().as_simple()
    )
}

#[tokio::test]
async fn negative_control_tenant_root_create_runs_in_tx() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_type = type_svc
        .create_type(CreateTypeRequest {
            code: unique_tenant_type_code(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .expect("create tenant type");
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    rec.clear();
    let root =
        common::create_root_group(&group_svc, &ctx, &tenant_type.code, "Tenant", tenant_id).await;
    assert_eq!(root.hierarchy.tenant_id, root.id);

    assert!(
        rec.writes_outside_tx().is_empty(),
        "tenant-root create (an invariant protected by SSI) must run inside a transaction:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn negative_control_width_limited_create_runs_in_tx() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = make_group_service_with_profile(
        db.clone(),
        QueryProfile {
            max_depth: None,
            max_width: Some(1),
        },
    );
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = create_self_referencing_type(&type_svc, "width").await;
    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;

    rec.clear();
    common::create_child_group(&group_svc, &ctx, &t.code, root.id, "only-child", tenant_id).await;

    assert!(
        rec.writes_outside_tx().is_empty(),
        "width-limited create (an invariant protected by SSI) must run inside a transaction:\n{}",
        rec.dump()
    );
}

/// Read paths must not be flagged by the write-oriented rules
/// (`writes_outside_tx`) -- there simply are no writes to flag. Documents
/// the negative-control result for the report; see the report's "noise"
/// section for the (separate, and legitimate) N+1 finding on `list_types`.
#[tokio::test]
async fn negative_control_read_paths_produce_no_write_statements() {
    let (db, rec) = common::test_db_with_recorder().await;
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let t = common::create_root_type(&type_svc, "read").await;
    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;

    rec.clear();
    group_svc
        .get_group(&ctx, root.id)
        .await
        .expect("get_group should succeed");
    group_svc
        .list_groups(&ctx, &toolkit_odata::ODataQuery::default())
        .await
        .expect("list_groups should succeed");
    type_svc
        .list_types(&toolkit_odata::ODataQuery::default())
        .await
        .expect("list_types should succeed");

    assert!(
        rec.total() > 0,
        "reads should still produce SELECT statements"
    );
    let stats = rec.stats();
    for kind in [QueryKind::Insert, QueryKind::Update, QueryKind::Delete] {
        for ((k, table), count) in &stats {
            assert!(
                *k != kind,
                "read-only calls must not produce {kind} statements (table {table}, count {count}):\n{}",
                rec.dump()
            );
        }
    }
    assert!(
        rec.writes_outside_tx().is_empty(),
        "trivially true for read paths, asserted for completeness"
    );
}

// =========================================================================
// Section 4 -- static source-scan rules
// =========================================================================
//
// Two defect classes the dynamic SQL trace cannot see at all, because
// they're not observable as SQL: RG-03 (a SERIALIZABLE transaction not
// wrapped in the retry helper) and RG-09 (an external-dependency call
// textually inside a transaction closure). Both rules match on API call
// *shape* (method names, argument identifiers), not on line numbers, so
// they generalize the same way the dynamic rules do. Plain #[test] -- no
// DB, no recorder, just the checked-in source text.

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

#[test]
fn static_rule_passes_type_service_uses_retry() {
    // Was static_rule_flags_type_service_missing_retry: RG-02 (delete_type)
    // and RG-03 (create_type/update_type) are both fixed now, so this is a
    // negative control (matches static_rule_passes_group_service_uses_retry)
    // instead of a known-defect pin.
    let src = include_str!("../src/domain/type_service.rs");
    let unretried = count_occurrences(
        src,
        ".transaction_ref_mapped_with_config(TxConfig::serializable()",
    );
    let retried = count_occurrences(src, ".transaction_with_retry(TxConfig::serializable()");
    assert_eq!(
        unretried, 0,
        "negative control violated: type_service.rs should not bypass \
         transaction_with_retry for its SERIALIZABLE writes (RG-03 regressed?)"
    );
    assert_eq!(
        retried, 3,
        "expected create_type/update_type/delete_type to all use \
         transaction_with_retry, found {retried}"
    );
}

#[test]
fn static_rule_passes_group_service_uses_retry() {
    let src = include_str!("../src/domain/group_service.rs");
    let unretried = count_occurrences(
        src,
        ".transaction_ref_mapped_with_config(TxConfig::serializable()",
    );
    let retried = count_occurrences(src, ".transaction_with_retry(TxConfig::serializable()");
    assert_eq!(
        unretried, 0,
        "negative control violated: group_service.rs should not bypass \
         transaction_with_retry for its SERIALIZABLE writes"
    );
    assert!(
        retried >= 3,
        "expected create/update/move/delete_group to all use \
         transaction_with_retry, found {retried}"
    );
}

/// Extract the parenthesized argument list starting at the `(` at or after
/// `from`, honoring nested parens. Best-effort lexical scan (not a real
/// parser) -- adequate for this repo's formatting; documented as a
/// limitation in the audit report.
fn extract_call_args(src: &str, from: usize) -> Option<&str> {
    let bytes = src.as_bytes();
    let open = src[from..].find('(')? + from;
    let mut depth = 0i32;
    let mut idx = open;
    loop {
        match bytes.get(idx)? {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&src[open..=idx]);
                }
            }
            _ => {}
        }
        idx += 1;
    }
}

/// Find every `db.transaction_with_retry(...)` call site in `src` and return
/// each one's full argument text (closure body included).
fn transaction_with_retry_call_bodies(src: &str) -> Vec<&str> {
    const MARKER: &str = "db.transaction_with_retry(";
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = src[cursor..].find(MARKER) {
        let abs = cursor + rel;
        let call_start = abs + MARKER.len() - 1; // at the '('
        match extract_call_args(src, call_start) {
            Some(body) => {
                cursor = call_start + body.len();
                out.push(body);
            }
            None => break,
        }
    }
    out
}

/// Find parameter names declared with an external SDK "client" trait-object
/// type -- `&dyn some_sdk::FooClient` or `Arc<dyn some_sdk::FooClient>` --
/// anywhere in `src`. This keys off the *type shape* (a `dyn ...Client`
/// trait object, the idiomatic signature for an injected external
/// dependency in this codebase: `AuthZResolverClient`, `TypesRegistryClient`,
/// `MembershipAdder`-style adapters, etc.), not a specific field name, so
/// renaming `types_registry` to anything else wouldn't defeat the rule.
///
/// Deliberately a class-level signal, not a proof: it does not confirm an
/// `.await` call happens on the identifier, only that a value of an
/// external-client type is reachable by name inside the closure text (it may
/// flow into a further function call, as `create_group_inner`'s does). A
/// real implementation of this check belongs in a dylint late lint with type
/// information; this is the interim, source-text version -- see the
/// "what this method does not cover" section of
/// docs/db-behavior-audit.md.
fn external_client_param_names(src: &str) -> Vec<&str> {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"\b([a-z_][a-zA-Z0-9_]*)\s*:\s*&?\s*(?:Arc<\s*)?dyn\s+[\w:]*Client\b")
            .expect("valid regex")
    });
    let mut names: Vec<&str> = RE
        .captures_iter(src)
        .map(|c| c.get(1).expect("group 1 always present").as_str())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// Whether `body` references `name` as a whole word (not as a substring of a
/// longer identifier).
fn references_identifier(body: &str, name: &str) -> bool {
    let pattern = format!(r"\b{}\b", regex::escape(name));
    regex::Regex::new(&pattern)
        .expect("valid regex")
        .is_match(body)
}

#[test]
fn static_rule_passes_no_external_call_inside_group_service_tx() {
    // Was static_rule_flags_external_call_inside_create_group_tx: RG-09 is
    // fixed now (validate_metadata_via_gts moved before the transaction in
    // both create_group/create_group_unscoped and update_group), so this is
    // a negative control instead of a known-defect pin.
    let src = include_str!("../src/domain/group_service.rs");
    let client_params = external_client_param_names(src);
    assert!(
        client_params.contains(&"types_registry"),
        "expected to discover an external-client parameter by its `&dyn ...Client` / \
         `Arc<dyn ...Client>` type shape (found: {client_params:?}) -- this asserts the \
         *discovery* mechanism still works (the struct field / constructor parameter still \
         has this shape) even though no transaction closure captures it anymore"
    );

    let bodies = transaction_with_retry_call_bodies(src);
    assert!(
        bodies.len() >= 4,
        "expected create/update/move/delete_group's transaction_with_retry \
         call sites, found {}",
        bodies.len()
    );

    // RG-09 fixed: no SERIALIZABLE tx closure in this file should reference
    // a discovered external-client identifier anymore -- both
    // create_group_inner and update_group_inner had `validate_metadata_via_gts`
    // moved out to run before the transaction opens. If this starts
    // failing, RG-09 has regressed (an external call slipped back inside a
    // tx closure).
    let flagged: Vec<&str> = bodies
        .iter()
        .filter(|b| {
            client_params
                .iter()
                .any(|name| references_identifier(b, name))
        })
        .copied()
        .collect();
    assert!(
        flagged.is_empty(),
        "RG-09 regression: {} of {} transaction_with_retry closures reference a discovered \
         external-client identifier ({client_params:?})",
        flagged.len(),
        bodies.len()
    );
}

// =========================================================================
// Section 5 -- contract-drift rules
// =========================================================================
//
// A "contract" here is a documented, specific promise (DESIGN.md) about
// observable behavior. Where the checked-in code doesn't (yet) keep that
// promise, the drift is turned into an executable, #[ignore]d assertion
// instead of a comment -- the same "known defect" convention used
// throughout this file, applied to a doc-vs-code mismatch rather than a
// DB-behavior class.
//
// A third DESIGN.md promise was checked and deliberately did *not* get a
// test here: the "Database-level query timeout (statement_timeout) is
// configured at the connection pool level per platform defaults" line
// (~DESIGN.md:1248) is explicitly scoped, in its own wording, as a
// deployment/platform concern -- not application code. Confirmed there is
// no toolkit_db::ConnectOpts field or connection-setup code path for it
// either (checked libs/toolkit-db/src/lib.rs in full), so there is no
// code-level behavior to assert against; it would be an infra/ops
// config-management gap, not a resource-group or toolkit-db defect.

#[test]
#[ignore = "contract drift: DESIGN.md (S4.x, concurrency testing) promises an \
            exhausted SERIALIZABLE retry maps to ServiceUnavailable (503) with a \
            retry-after hint; DomainError::Database has no dedicated variant for \
            'retry exhausted' (vs. any other DB error) and always maps to \
            Internal (500) via CanonicalError::internal(...) in api/rest/error.rs, \
            whose own comment already acknowledges the gap. Deferred -- see \
            docs/db-behavior-audit.md."]
fn contract_drift_exhausted_retry_should_map_to_service_unavailable() {
    // Representative shape of what transaction_with_retry returns after
    // exhausting its attempt budget against a real SERIALIZABLE conflict --
    // see RG-15's regression tests in libs/toolkit-db/src/contention.rs for
    // the exact message shape this is modeled on.
    let exhausted = resource_group::domain::error::DomainError::Database(sea_orm::DbErr::Custom(
        "Query Error: error returned from database: could not serialize access due to \
         read/write dependencies among transactions"
            .to_owned(),
    ));
    let canonical: toolkit_canonical_errors::CanonicalError = exhausted.into();
    assert_eq!(
        canonical.status_code(),
        503,
        "DESIGN.md promises an exhausted SERIALIZABLE retry maps to ServiceUnavailable \
         (503); got {} instead (DomainError::Database always maps to Internal) -- if this \
         starts passing, the contract drift was fixed, remove the #[ignore] and update the \
         report",
        canonical.status_code()
    );
}

#[test]
#[ignore = "contract drift: DESIGN.md's 'Concurrency Testing' section (~line 1599) promises \
            hierarchy-mutating SERIALIZABLE transactions carry a 5s (configurable) transaction \
            timeout, but toolkit_db::secure::TxConfig (the type transaction_with_retry takes) \
            has no timeout field or enforcement mechanism at all -- confirmed by reading \
            libs/toolkit-db/src/secure/tx_config.rs in full (isolation + access_mode only). \
            Deferred -- see docs/db-behavior-audit.md."]
fn contract_drift_tx_config_has_no_timeout_mechanism() {
    let cfg = toolkit_db::secure::TxConfig::serializable();
    let debug_repr = format!("{cfg:?}");
    assert!(
        debug_repr.to_lowercase().contains("timeout"),
        "DESIGN.md promises a 5s (configurable) transaction timeout for SERIALIZABLE \
         hierarchy mutations; TxConfig::serializable()'s Debug representation is \
         `{debug_repr}` -- no timeout field at all. If this starts passing, the contract \
         drift may have been fixed -- remove the #[ignore] and update the report."
    );
}
