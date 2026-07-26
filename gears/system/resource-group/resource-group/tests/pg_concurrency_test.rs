// Created: 2026-07-26 by Constructor Tech
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::doc_markdown,
    clippy::too_many_lines
)]
//! PostgreSQL concurrency harness for the resource-group DB-behavior audit.
//!
//! These tests need a real PostgreSQL to exercise actual SSI predicate
//! conflicts and FK enforcement that SQLite cannot reproduce faithfully
//! (SQLite's own "SERIALIZABLE" is a whole-database writer lock, not
//! row/predicate-level SSI, and it has no FK-driven RESTRICT semantics under
//! concurrent writers the way Postgres does). They run for real, automatically,
//! as part of a normal `cargo test -p cf-gears-resource-group` -- no
//! `#[ignore]`, no environment variable to remember to set. [`shared_pg`]
//! brings up a `testcontainers` PostgreSQL once per process (shared by every
//! test in this file, mirroring account-management's
//! `tests/common/mod.rs::pg::bring_up_postgres()`) and every test skips
//! itself gracefully -- passes, with an explanatory message on stderr -- if
//! Docker isn't reachable, rather than failing the suite. Where Docker *is*
//! available (checked into this audit's report), they exercise the real race.
//!
//! ## Running locally
//!
//! No setup needed if Docker is running -- just:
//!
//! ```sh
//! cargo test -p cf-gears-resource-group --test pg_concurrency_test
//! ```
//!
//! To watch it not run (and see the skip message) with Docker stopped:
//!
//! ```sh
//! cargo test -p cf-gears-resource-group --test pg_concurrency_test -- --nocapture
//! ```
//!
//! All tests in this file share one PostgreSQL database (started once,
//! lazily, by whichever test asks first) and serialize against it via
//! [`PG_TEST_LOCK`], because a couple of scenarios (tenant-root uniqueness)
//! exercise a *global* invariant (scoped by a type-code prefix, not by any
//! per-test tenant id) that would spuriously conflict if two test functions
//! in this file ran concurrently against it (cargo test's default
//! parallel-by-function scheduling would otherwise do exactly that). Each
//! test cleans up the rows it created so the harness stays re-runnable.
//!
//! ## Scenarios
//!
//! The first five scenarios below now assert *fixed* behavior (remediation
//! step) -- they were originally written to reproduce the bug (see git
//! history / the audit report for the pre-fix shape of each assertion).
//!
//! - `membership_first_write_race_exactly_one_tenant_wins` -- RG-01 fixed:
//!   two concurrent "first membership" adds for the same resource in two
//!   different tenants now resolve to exactly one winner, the other getting
//!   a clean `TenantIncompatibility` (`add_membership_inner` runs inside
//!   `transaction_with_retry(TxConfig::serializable())`).
//! - `delete_type_races_create_group_resolves_cleanly` -- RG-02 fixed:
//!   `delete_type` now runs its count-then-delete inside the same
//!   transaction pattern, so the FK-violation / raw-error window is closed
//!   (asserts zero corruption and zero raw/unexpected outcomes, reporting
//!   the delete-won/create-won split, which remains nondeterministic by
//!   nature -- see the test body).
//! - `create_type_conflict_retried_yields_clean_already_exists_for_loser` --
//!   RG-03 fixed: `create_type` now uses `transaction_with_retry`, so the
//!   loser of a same-code race gets the clean `TypeAlreadyExists`, not a
//!   raw serialization failure.
//! - `negative_control_*` -- tenant-root create and width=1 create both use
//!   `transaction_with_retry` + SERIALIZABLE: the *invariant* always holds
//!   (exactly one of two concurrent attempts succeeds -- proves the
//!   detector distinguishes protected invariants from broken ones using the
//!   same kind of concurrent-race harness, not just by "reads vs writes").
//!   The loser's *error shape* is now also asserted as the clean domain
//!   error (`TenantRootAlreadyExists` / `LimitViolation`) rather than just
//!   logged: RG-15 (`is_retryable_contention` not recognizing
//!   `DbErr::Custom`) used to let a raw serialization failure leak through
//!   here even though the invariant itself always held; that's fixed too.
//!
//! Five more scenarios specifically target `move_group` and its
//! `rebuild_subtree_closure`/`insert_ancestor_closure_rows` machinery --
//! `SERIALIZABLE` was introduced *for* moves, but nothing above ever calls
//! `move_group`, and none races a hierarchy write against another hierarchy
//! write that touches *overlapping* closure rows (as opposed to two
//! independent inserts):
//!
//! - `move_a_to_b_races_move_b_to_a` -- a genuine write-skew "dangerous
//!   structure" (each side's cycle check reads exactly the row the other
//!   side's closure rebuild writes); exactly one side must win, the loser
//!   must get a clean `CycleDetected`, never an actual cycle in the data.
//! - `move_ancestor_races_move_descendant` -- an ancestor and one of its own
//!   descendants move to unrelated new parents at the same time; both are
//!   logically independent and both must succeed.
//! - `create_child_races_move_parent` -- a new child is created under `P`
//!   while `P` itself moves elsewhere; both must succeed and the child must
//!   end up with the same final ancestor chain as `P`.
//! - `force_delete_races_create_child` / `force_delete_races_add_membership`
//!   -- a force-delete (cascading) races a concurrent create-child /
//!   add-membership on the group being deleted; `resource_group.parent_id`
//!   is `ON DELETE RESTRICT`, so the interesting question is whether the
//!   retry machinery resolves this to a clean outcome (rejected with
//!   `GroupNotFound`, or the delete's retry cascades the new row too) or a
//!   raw constraint-violation error leaks through.
//!
//! Every scenario also runs [`assert_hierarchy_invariants`] (and, for the
//! membership scenarios, [`assert_membership_tenant_invariant`]) after the
//! race to confirm the *data*, not just the call outcome, is consistent --
//! a concurrent pair of `200`s could in principle still leave the closure
//! table or `parent_id` graph corrupt even when the primary invariant
//! (exactly one logical winner, or two independent winners) holds. Each
//! race is also timed against a coarse [`MAX_WINNING_TX_DURATION`] budget
//! via the [`timed`] helper -- not fine-grained APM, just a ceiling that
//! would catch a transaction pathologically slowed down by an N+1
//! regression.

mod common;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use resource_group::domain::error::DomainError;
use resource_group::domain::group_service::QueryProfile;
use resource_group::domain::type_service::TypeService;
use resource_group::infra::storage::entity::resource_group::{
    Column as RgColumn, Entity as RgEntity,
};
use resource_group::infra::storage::entity::resource_group_closure::Entity as ClosureEntity;
use resource_group::infra::storage::entity::resource_group_membership::Entity as MbrEntity;
use resource_group::infra::storage::migrations::Migrator;
use resource_group::infra::storage::type_repo::TypeRepository;
use resource_group_sdk::CreateGroupRequest;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sea_orm_migration::MigratorTrait;
use testcontainers::{ContainerRequest, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::{Barrier, Mutex, OnceCell};
use toolkit_db::secure::SecureEntityExt;
use toolkit_db::{
    ConnectOpts, DBProvider, DbError, connect_db, migration_runner::run_migrations_for_testing,
};
use toolkit_security::AccessScope;
use uuid::Uuid;

/// Ceiling for a single winning transaction's wall-clock duration in a race
/// scenario -- a coarse axis (transaction-window budget), not a
/// microbenchmark. Generous on purpose: this only needs to catch a
/// transaction that is pathologically long (e.g. an N+1 regression turning
/// a handful of statements into thousands), not to characterize p95 latency.
const MAX_WINNING_TX_DURATION: Duration = Duration::from_secs(5);

/// Recomputes the transitive closure implied by `resource_group.parent_id`
/// across the *entire* table (all tests in this file share one database, so
/// this is a global check, not scoped to one test's fixtures) and compares
/// it against the actual `resource_group_closure` rows. Also asserts there
/// are no cycles in the `parent_id` graph. This is the "did the *data* stay
/// consistent" check a bare `ok_count == 1` cannot make: a concurrent move
/// racing against another write can leave the closure table diverged from
/// `parent_id` even when every individual call's return value looks correct
/// (both `200`, or one `200` and one clean domain error) -- exactly the
/// class of bug `SERIALIZABLE` is supposed to prevent, and exactly the kind
/// of divergence RG-04/RG-05/RG-06's closure-rebuild code touches.
async fn assert_hierarchy_invariants(db: &Arc<DBProvider<DbError>>) {
    let conn = db.conn().expect("db conn");
    let scope = AccessScope::allow_all();

    let groups = RgEntity::find()
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await
        .expect("query resource_group table");
    let parent_of: HashMap<Uuid, Option<Uuid>> =
        groups.iter().map(|g| (g.id, g.parent_id)).collect();

    // Cycle check: walking up from any node must terminate within
    // parent_of.len() hops.
    for &id in parent_of.keys() {
        let mut current = id;
        let mut hops = 0usize;
        while let Some(parent) = parent_of.get(&current).copied().flatten() {
            hops += 1;
            assert!(
                hops <= parent_of.len(),
                "cycle detected in resource_group.parent_id starting at {id}"
            );
            current = parent;
        }
    }

    // Expected closure: self-row (depth 0) plus one row per ancestor at the
    // correct depth, derived purely from parent_id.
    let mut expected: HashSet<(Uuid, Uuid, i32)> = HashSet::new();
    for &id in parent_of.keys() {
        expected.insert((id, id, 0));
        let mut current = id;
        let mut depth = 0i32;
        while let Some(parent) = parent_of.get(&current).copied().flatten() {
            depth += 1;
            expected.insert((parent, id, depth));
            current = parent;
        }
    }

    let closure_rows = ClosureEntity::find()
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await
        .expect("query resource_group_closure table");
    let actual: HashSet<(Uuid, Uuid, i32)> = closure_rows
        .iter()
        .map(|r| (r.ancestor_id, r.descendant_id, r.depth))
        .collect();

    let missing: Vec<_> = expected.difference(&actual).collect();
    let extra: Vec<_> = actual.difference(&expected).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "closure table diverged from the transitive closure of parent_id: \
         missing={missing:?} extra={extra:?}"
    );
}

/// Companion invariant checker for the membership races: no
/// `(resource_type, resource_id)` is linked from groups in more than one
/// distinct tenant, checked across every membership row in the database
/// (not just the one resource a given test created).
async fn assert_membership_tenant_invariant(db: &Arc<DBProvider<DbError>>) {
    let conn = db.conn().expect("db conn");
    let scope = AccessScope::allow_all();

    let memberships = MbrEntity::find()
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await
        .expect("query resource_group_membership table");
    let groups = RgEntity::find()
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await
        .expect("query resource_group table");
    let tenant_of: HashMap<Uuid, Uuid> = groups.iter().map(|g| (g.id, g.tenant_id)).collect();

    let mut by_resource: HashMap<(i16, String), HashSet<Uuid>> = HashMap::new();
    for m in &memberships {
        if let Some(&tenant) = tenant_of.get(&m.group_id) {
            by_resource
                .entry((m.gts_type_id, m.resource_id.clone()))
                .or_default()
                .insert(tenant);
        }
    }
    let violations: Vec<_> = by_resource
        .iter()
        .filter(|(_, tenants)| tenants.len() > 1)
        .collect();
    assert!(
        violations.is_empty(),
        "resource(s) linked from groups in more than one tenant: {violations:?}"
    );
}

/// Times `f`, asserting the result stays under [`MAX_WINNING_TX_DURATION`] --
/// a coarse transaction-window budget, not a precision benchmark.
async fn timed<T>(label: &str, f: impl std::future::Future<Output = T>) -> T {
    let start = Instant::now();
    let result = f.await;
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64();
    let budget_secs = MAX_WINNING_TX_DURATION.as_secs_f64();
    assert!(
        elapsed <= MAX_WINNING_TX_DURATION,
        "{label} took {elapsed_secs:.3}s, exceeding the {budget_secs:.3}s transaction-window \
         budget -- likely an N+1 regression, not normal variance"
    );
    eprintln!("{label}: {elapsed_secs:.3}s");
    result
}

/// Serializes the five test functions in this file against each other: they
/// share one PostgreSQL database, and a couple of scenarios exercise a
/// *global* invariant that would spuriously conflict if two of these test
/// functions raced against each other (cargo test's default parallel-by-
/// function scheduling would otherwise do exactly that -- unlike the
/// deliberate races each test creates *within* itself via `Barrier`).
static PG_TEST_LOCK: Mutex<()> = Mutex::const_new(());

/// Holds the `testcontainers` PostgreSQL alive for the process lifetime.
/// `_container`'s only job is to not be dropped -- letting the container
/// stop -- before the test binary exits.
struct PgFixture {
    dsn: String,
    _container: testcontainers::ContainerAsync<Postgres>,
}

static PG: OnceCell<Option<Arc<PgFixture>>> = OnceCell::const_new();
static MIGRATIONS_DONE: OnceCell<()> = OnceCell::const_new();

/// Bring up (once per process) a `testcontainers` PostgreSQL, mirroring
/// account-management's `tests/common/mod.rs::pg::bring_up_postgres()`.
/// Returns `None` if Docker isn't reachable -- callers treat that as a
/// graceful skip, not a failure.
async fn shared_pg() -> Option<Arc<PgFixture>> {
    PG.get_or_init(|| async {
        // testcontainers-modules' Postgres image defaults to "11-alpine",
        // which predates gen_random_uuid() becoming a built-in (PG13+) --
        // RG's migrations use it, so pin a modern tag (matches the
        // postgres:16 used for this audit's manual docker-based dry run).
        let request = ContainerRequest::from(Postgres::default())
            .with_tag("16-alpine")
            .with_env_var("POSTGRES_PASSWORD", "pass")
            .with_env_var("POSTGRES_USER", "user")
            .with_env_var("POSTGRES_DB", "app");
        match request.start().await {
            Ok(container) => match container.get_host_port_ipv4(5432).await {
                Ok(port) => Some(Arc::new(PgFixture {
                    dsn: format!("postgres://user:pass@127.0.0.1:{port}/app"),
                    _container: container,
                })),
                Err(e) => {
                    eprintln!(
                        "skipping PostgreSQL concurrency tests: container started but its \
                         port could not be resolved ({e}). Is Docker healthy?"
                    );
                    None
                }
            },
            Err(e) => {
                eprintln!(
                    "skipping PostgreSQL concurrency tests: could not start a PostgreSQL \
                     container via testcontainers ({e}). Install/start Docker to run these \
                     for real -- see this file's module docs."
                );
                None
            }
        }
    })
    .await
    .clone()
}

/// Connect to the shared PostgreSQL fixture and ensure RG's migrations have
/// run against it. Returns `None` (propagated from [`shared_pg`]) when
/// Docker isn't available -- callers should skip, not fail, in that case.
async fn pg_db() -> Option<Arc<DBProvider<DbError>>> {
    let fixture = shared_pg().await?;
    let opts = ConnectOpts {
        max_conns: Some(10),
        min_conns: Some(2),
        ..Default::default()
    };
    let db = connect_db(&fixture.dsn, opts)
        .await
        .expect("connect to the testcontainers PostgreSQL");
    MIGRATIONS_DONE
        .get_or_init(|| async {
            run_migrations_for_testing(&db, Migrator::migrations())
                .await
                .expect("run resource-group migrations against PostgreSQL");
        })
        .await;
    Some(Arc::new(DBProvider::new(db)))
}

/// Shorthand for the common test-entry sequence: acquire the cross-test
/// lock, then get a connected `DBProvider`, returning early (soft-skip) if
/// PostgreSQL isn't available. `_guard` must be held for the whole test.
macro_rules! pg_db_or_skip {
    () => {{
        let _guard = PG_TEST_LOCK.lock().await;
        match pg_db().await {
            Some(db) => (db, _guard),
            None => return,
        }
    }};
}

/// Distinct `tenant_id`s of the groups that *actually hold a membership row*
/// for `(resource_type, resource_id)` -- not the tenants of any particular
/// candidate groups. Resolves `resource_type` to its surrogate id, finds
/// every `resource_group_membership` row for that `(gts_type_id,
/// resource_id)`, then looks up those specific groups' tenants.
async fn distinct_tenant_ids_for_resource(
    db: &Arc<DBProvider<DbError>>,
    resource_type: &str,
    resource_id: &str,
) -> Vec<Uuid> {
    use resource_group::infra::storage::entity::resource_group_membership::{
        Column as MbrColumn, Entity as MbrEntity,
    };

    let conn = db.conn().expect("db conn");
    let scope = AccessScope::allow_all();

    let gts_type_id = TypeRepository::resolve_id(&conn, resource_type)
        .await
        .expect("resolve resource_type")
        .expect("resource_type must be a registered GTS type");

    let membership_rows = MbrEntity::find()
        .filter(MbrColumn::GtsTypeId.eq(gts_type_id))
        .filter(MbrColumn::ResourceId.eq(resource_id))
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await
        .expect("query resource_group_membership table");
    let holder_group_ids: Vec<Uuid> = membership_rows.iter().map(|m| m.group_id).collect();
    if holder_group_ids.is_empty() {
        return Vec::new();
    }

    let rows = RgEntity::find()
        .filter(RgColumn::Id.is_in(holder_group_ids))
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await
        .expect("query resource_group table");
    let mut ids: Vec<Uuid> = rows.into_iter().map(|r| r.tenant_id).collect();
    ids.sort();
    ids.dedup();
    ids
}

/// `Display`-based diagnostic summary of an `add_membership` outcome, for
/// `eprintln!` (avoids `clippy::use_debug`).
fn describe_membership_result(
    r: &Result<resource_group_sdk::models::ResourceGroupMembership, DomainError>,
) -> String {
    describe_result(r)
}

/// `Display`-based diagnostic summary of any `Result<_, DomainError>`, for
/// `eprintln!` (avoids `clippy::use_debug` -- `DomainError` has a `Display`
/// impl via `thiserror`, but the `Ok` payload types here don't all implement
/// `Debug`/`Display` uniformly, so this only ever names the `Ok` case).
fn describe_result<T>(r: &Result<T, DomainError>) -> String {
    match r {
        Ok(_) => "Ok".to_owned(),
        Err(e) => format!("Err({e})"),
    }
}

// =========================================================================
// RG-01: membership first-write race (fixed)
// =========================================================================

/// Two concurrent `add_membership` calls for the same `(resource_type,
/// resource_id)` in two *different* tenants. The "a resource belongs to
/// groups of a single tenant" invariant requires exactly one of them to
/// succeed. `add_membership_inner` now runs inside a `SERIALIZABLE`
/// transaction with retry (fixes RG-01): the two transactions' predicate
/// reads over `get_existing_membership_tenant_ids` conflict with each
/// other's insert (textbook write-skew), so PostgreSQL aborts one with
/// `40001` and `transaction_with_retry` retries it -- the retried attempt
/// then sees the other's committed membership and returns the clean
/// `TenantIncompatibility` domain error (also exercises the RG-15 fix:
/// without it, retry detection would not recognize this repo-mapped error
/// as retryable and the loser would get a raw serialization failure
/// instead).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_first_write_race_exactly_one_tenant_wins() {
    // Run several trials for the same reason
    // delete_type_races_create_group_reproduces_check_window does: the
    // invariant must hold under real concurrent load, not just in a single
    // sample.
    const TRIALS: usize = 8;

    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());

    let member_type = common::create_root_type(&type_svc, "pgmbrres").await;
    let grp_type = {
        // Local copy of membership_service_test.rs's helper -- creates a
        // root type whose allowed_membership_types includes member_type.
        let code = format!(
            "{}x.test.pgmbrgrp.i{}.v1~",
            toolkit_gts::gts_id!("cf.core.rg.type.v1~"),
            Uuid::now_v7().as_simple()
        );
        type_svc
            .create_type(resource_group_sdk::CreateTypeRequest {
                code,
                can_be_root: true,
                allowed_parent_types: vec![],
                allowed_membership_types: vec![member_type.code.clone()],
                metadata_schema: None,
            })
            .await
            .expect("create membership-holding type")
    };

    let mut both_succeeded = 0usize;
    let mut correctly_rejected = 0usize; // one Ok + one Err(TenantIncompatibility)
    let mut unexpected = 0usize;

    for _ in 0..TRIALS {
        let tenant_a = Uuid::now_v7();
        let tenant_b = Uuid::now_v7();
        let ctx_a = common::make_ctx(tenant_a);
        let ctx_b = common::make_ctx(tenant_b);
        let group_a =
            common::create_root_group(&group_svc, &ctx_a, &grp_type.code, "A", tenant_a).await;
        let group_b =
            common::create_root_group(&group_svc, &ctx_b, &grp_type.code, "B", tenant_b).await;

        let resource_id = format!("shared-{}", Uuid::now_v7().as_simple());
        let barrier = Arc::new(Barrier::new(2));

        // MembershipService/TypeService/GroupService can't derive Clone
        // (their repo type params -- unit structs like TypeRepository --
        // aren't Clone, even though the services only ever hold them behind
        // an Arc), so build a fresh instance per task instead of cloning a
        // shared one.
        let (svc1, svc2) = (
            common::make_membership_service(db.clone()),
            common::make_membership_service(db.clone()),
        );
        let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
        let (rt1, rt2) = (member_type.code.clone(), member_type.code.clone());
        let (rid1, rid2) = (resource_id.clone(), resource_id.clone());

        let t1 = tokio::spawn(async move {
            b1.wait().await;
            svc1.add_membership(&ctx_a, group_a.id, &rt1, &rid1).await
        });
        let t2 = tokio::spawn(async move {
            b2.wait().await;
            svc2.add_membership(&ctx_b, group_b.id, &rt2, &rid2).await
        });

        let (r1, r2) = timed("membership_first_write_race trial", async {
            tokio::join!(t1, t2)
        })
        .await;
        let r1 = r1.expect("task 1 join");
        let r2 = r2.expect("task 2 join");

        let tenant_ids =
            distinct_tenant_ids_for_resource(&db, &member_type.code, &resource_id).await;
        match (&r1, &r2, tenant_ids.len()) {
            (Ok(_), Ok(_), _) => both_succeeded += 1,
            (Ok(_), Err(e), 1) | (Err(e), Ok(_), 1) => {
                correctly_rejected += 1;
                assert!(
                    matches!(e, DomainError::TenantIncompatibility { .. }),
                    "the losing add_membership must get a clean TenantIncompatibility \
                     (proving transaction_with_retry + the RG-15 fix absorbed the SSI \
                     conflict), got: {e}"
                );
            }
            _ => {
                unexpected += 1;
                let tenants = tenant_ids
                    .iter()
                    .map(Uuid::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                eprintln!(
                    "membership_first_write_race: unexpected outcome r1={} r2={} \
                     distinct_tenants=[{tenants}]",
                    describe_membership_result(&r1),
                    describe_membership_result(&r2),
                );
            }
        }
    }

    eprintln!(
        "membership_first_write_race: both_succeeded={both_succeeded} \
         correctly_rejected={correctly_rejected} unexpected={unexpected} (out of {TRIALS} trials)"
    );
    assert_eq!(
        unexpected, 0,
        "every trial must be either both-succeed (RG-01 regression) or the correct outcome \
         (one rejected with a clean TenantIncompatibility) -- got {unexpected} trials with a \
         genuinely unexpected shape"
    );
    // RG-01 fixed: both tenants' "first membership" succeeding for the same
    // resource must never happen now. If this starts failing, RG-01 has
    // regressed.
    assert_eq!(
        both_succeeded, 0,
        "RG-01 regression: {both_succeeded}/{TRIALS} trials let both tenants' first-membership \
         add succeed for the same resource"
    );
    assert_eq!(
        correctly_rejected, TRIALS,
        "expected every trial to resolve to exactly one tenant winning, got {correctly_rejected}/{TRIALS}"
    );

    // Confirm the *data*, not just the call outcomes, stayed consistent:
    // every resource must still be linked from exactly one tenant, and the
    // closure table (untouched by memberships, but shared infrastructure)
    // must still match the parent_id graph.
    assert_membership_tenant_invariant(&db).await;
    assert_hierarchy_invariants(&db).await;
}

// =========================================================================
// RG-02: delete_type races create_group of that type (fixed)
// =========================================================================

/// `delete_type` now runs its "no groups reference this type" check and the
/// delete itself inside the same `transaction_with_retry(TxConfig::
/// serializable())` pattern as `create_group_unscoped` (both open a
/// `SERIALIZABLE` transaction). The two transactions' predicate reads
/// conflict under real concurrency (textbook write-skew: each reads "no
/// referencing groups" / "type exists", then acts on it), so PostgreSQL
/// aborts one with `40001` and it transparently retries -- the retried
/// attempt then sees the other side's committed effect and returns a clean
/// domain error instead of raw error. FK (`resource_group.gts_type_id ...
/// ON DELETE RESTRICT`) still backstops *data corruption* regardless (the
/// type row can never actually vanish while a referencing group exists),
/// but before the fix the race was still visible as a raw, non-domain error
/// surfacing to callers; that's what this test now asserts is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_type_races_create_group_resolves_cleanly() {
    const TRIALS: usize = 15;

    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let tenant_id = Uuid::now_v7();

    let mut corruption = 0usize; // both succeeded -- would be a real invariant violation
    let mut delete_won = 0usize; // delete succeeded, create cleanly rejected (type gone)
    let mut create_won = 0usize; // create succeeded, delete cleanly rejected (conflict)
    let mut unexpected = 0usize; // anything else -- a raw error or an unrecognized shape

    for i in 0..TRIALS {
        let t = common::create_root_type(&type_svc, &format!("pgdelrace{i}")).await;
        let barrier = Arc::new(Barrier::new(2));
        let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
        // Fresh instances per task -- see the comment in
        // membership_first_write_race_exactly_one_tenant_wins about why
        // these services can't just be `.clone()`d.
        let type_svc1 = TypeService::new(db.clone(), Arc::new(TypeRepository));
        let group_svc1 = common::make_group_service(db.clone());
        let (code1, code2) = (t.code.clone(), t.code.clone());

        let delete_task = tokio::spawn(async move {
            b1.wait().await;
            type_svc1.delete_type(&code1).await
        });
        let create_task = tokio::spawn(async move {
            b2.wait().await;
            group_svc1
                .create_group_unscoped(
                    CreateGroupRequest {
                        id: None,
                        code: code2,
                        name: "race".to_owned(),
                        parent_id: None,
                        metadata: None,
                    },
                    tenant_id,
                )
                .await
        });

        let (delete_res, create_res) = timed("delete_type_races_create_group trial", async {
            tokio::join!(delete_task, create_task)
        })
        .await;
        let delete_res = delete_res.expect("delete task join");
        let create_res = create_res.expect("create task join");

        // Each trial uses a fresh, uniquely-coded type (no global invariant
        // like tenant-root is at stake), so there's nothing to clean up
        // between trials regardless of outcome.
        match (&delete_res, &create_res) {
            (Ok(()), Ok(_)) => corruption += 1,
            (Ok(()), Err(DomainError::TypeNotFound { .. })) => delete_won += 1,
            (Err(DomainError::ConflictActiveReferences { .. }), Ok(_)) => create_won += 1,
            _ => {
                unexpected += 1;
                eprintln!(
                    "delete_type_races_create_group: unexpected outcome delete={} create={}",
                    describe_result(&delete_res),
                    describe_result(&create_res),
                );
            }
        }

        // Whichever side won, the data must stay consistent (FK RESTRICT
        // backstops corruption regardless, but confirm the closure table
        // agrees with parent_id too, since create_group_unscoped writes it).
        assert_hierarchy_invariants(&db).await;
    }

    assert_eq!(
        corruption, 0,
        "invariant violation: delete_type and create_group_unscoped both succeeded for the \
         same type in {corruption}/{TRIALS} trials -- FK RESTRICT should make this impossible"
    );
    // RG-02 fixed: the race window that used to let a raw, non-domain error
    // leak through is closed now that delete_type is transaction_with_retry
    // + SERIALIZABLE, same as create_group_unscoped. Every trial must
    // resolve to a clean domain error on the losing side -- if this starts
    // failing (unexpected > 0), RG-02 has regressed.
    assert_eq!(
        unexpected, 0,
        "RG-02 regression: {unexpected}/{TRIALS} trials produced a raw error or unrecognized \
         outcome shape instead of a clean domain error on the losing side"
    );
    assert_eq!(
        delete_won + create_won,
        TRIALS,
        "accounting mismatch: delete_won={delete_won} create_won={create_won} \
         unexpected={unexpected}"
    );
    eprintln!(
        "delete_type_races_create_group: delete_won={delete_won} create_won={create_won} \
         (out of {TRIALS} trials)"
    );
}

// =========================================================================
// RG-03: create_type conflict (fixed -- now retried)
// =========================================================================

/// Two concurrent `create_type` calls for the *same* code. Both check
/// "does this code exist" inside their own `SERIALIZABLE` transaction, both
/// see "no", both attempt the INSERT -- one must fail under SSI.
/// `create_type` now uses `transaction_with_retry` (same pattern as
/// `create_group`, see the negative controls below), so the loser's retried
/// attempt sees the winner's committed row and returns the clean
/// `TypeAlreadyExists`, not a raw serialization failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_type_conflict_retried_yields_clean_already_exists_for_loser() {
    let (db, _pg_guard) = pg_db_or_skip!();

    let code = format!(
        "{}x.test.pgtyperace.i{}.v1~",
        toolkit_gts::gts_id!("cf.core.rg.type.v1~"),
        Uuid::now_v7().as_simple()
    );
    let barrier = Arc::new(Barrier::new(2));
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let svc1 = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let svc2 = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let (code1, code2) = (code.clone(), code.clone());

    let req = |code: String| resource_group_sdk::CreateTypeRequest {
        code,
        can_be_root: true,
        allowed_parent_types: vec![],
        allowed_membership_types: vec![],
        metadata_schema: None,
    };

    let t1 = tokio::spawn(async move {
        b1.wait().await;
        svc1.create_type(req(code1)).await
    });
    let t2 = tokio::spawn(async move {
        b2.wait().await;
        svc2.create_type(req(code2)).await
    });

    let (r1, r2) = timed("create_type_conflict race", async { tokio::join!(t1, t2) }).await;
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent create_type for the same code must succeed: r1={r1:?} r2={r2:?}"
    );

    let loser = if r1.is_err() { &r1 } else { &r2 };
    let loser_err = loser.as_ref().unwrap_err();
    // RG-03 fixed: create_type now uses transaction_with_retry, so the SSI
    // conflict transparently retries and the loser sees the clean
    // TypeAlreadyExists a retried attempt produces, not a raw serialization
    // failure. Also exercises the RG-15 fix (is_retryable_contention
    // recognizing DbErr::Custom): without it, retry would never fire here
    // either.
    eprintln!("create_type_conflict_retried: loser error = {loser_err}");
    assert!(
        matches!(loser_err, DomainError::TypeAlreadyExists { .. }),
        "the losing create_type must get a clean TypeAlreadyExists (proving \
         transaction_with_retry absorbed the SSI conflict), got: {loser_err:?}"
    );

    // Types don't touch resource_group/closure directly, but this is a
    // cheap regression net against anything else in the shared database.
    assert_hierarchy_invariants(&db).await;
}

// =========================================================================
// Negative controls: SSI + retry works for hierarchy mutations
// =========================================================================

fn unique_tenant_type_code() -> String {
    format!(
        "{}pgrace{}.v1~",
        resource_group_sdk::TENANT_RG_TYPE_PATH,
        Uuid::now_v7().as_simple()
    )
}

/// Two concurrent tenant-root creates: exactly one must succeed, the other
/// must fail with the clean `TenantRootAlreadyExists` domain error -- never
/// both, and never a raw serialization failure. Proves `transaction_with_retry`
/// + SERIALIZABLE genuinely protects this invariant under real concurrency,
/// matching the SQLite audit's negative control but under an actual SSI
/// conflict this time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_control_tenant_root_race_exactly_one_succeeds() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());

    let tenant_type = type_svc
        .create_type(resource_group_sdk::CreateTypeRequest {
            code: unique_tenant_type_code(),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![],
            metadata_schema: None,
        })
        .await
        .expect("create tenant type");

    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let ctx_a = common::make_ctx(tenant_a);
    let ctx_b = common::make_ctx(tenant_b);
    let barrier = Arc::new(Barrier::new(2));

    let svc1 = common::make_group_service(db.clone());
    let svc2 = common::make_group_service(db.clone());
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let (code1, code2) = (tenant_type.code.clone(), tenant_type.code.clone());

    let t1 = tokio::spawn(async move {
        b1.wait().await;
        svc1.create_group(
            &ctx_a,
            CreateGroupRequest {
                id: None,
                code: code1,
                name: "Tenant A".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_a,
        )
        .await
    });
    let t2 = tokio::spawn(async move {
        b2.wait().await;
        svc2.create_group(
            &ctx_b,
            CreateGroupRequest {
                id: None,
                code: code2,
                name: "Tenant B".to_owned(),
                parent_id: None,
                metadata: None,
            },
            tenant_b,
        )
        .await
    });

    let (r1, r2) = timed("negative_control_tenant_root_race", async {
        tokio::join!(t1, t2)
    })
    .await;
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent tenant-root create must succeed: r1={r1:?} r2={r2:?}"
    );
    let loser = if r1.is_err() { &r1 } else { &r2 };
    let loser_err = loser.as_ref().unwrap_err();
    // RG-15 fixed: is_retryable_contention now recognizes DbErr::Custom, so
    // transaction_with_retry's retry actually fires even when the SSI abort
    // surfaces from an interior repo call (not just at COMMIT). The loser
    // must now always get the clean TenantRootAlreadyExists, never a raw
    // serialization failure.
    assert!(
        matches!(loser_err, DomainError::TenantRootAlreadyExists { .. }),
        "the losing create must get a clean TenantRootAlreadyExists (proving \
         transaction_with_retry + the RG-15 fix absorbed the SSI conflict), got: {loser_err:?}"
    );

    // Confirm the closure table agrees with parent_id before tearing the
    // winner back down.
    assert_hierarchy_invariants(&db).await;

    // Clean up so the harness can be re-run without a stale tenant-root
    // (the uniqueness check is scoped by TENANT_RG_TYPE_PATH prefix, global
    // across all tenants -- not by our per-test tenant ids).
    let winner_group = if let Ok(g) = &r1 {
        g
    } else {
        r2.as_ref().unwrap()
    };
    // A tenant-type root's effective tenant_id is its own group id (see
    // create_group_inner's is_tenant_type branch), not tenant_a/tenant_b --
    // scope the cleanup ctx accordingly or delete_group's AuthZ scope won't
    // see the row.
    let cleanup_ctx = common::make_ctx(winner_group.id);
    group_svc
        .delete_group(&cleanup_ctx, winner_group.id, true)
        .await
        .expect("cleanup: force delete tenant root");
}

/// Two concurrent creates under `max_width = 1`: exactly one must succeed,
/// the other must fail with the clean `LimitViolation` error -- never both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_control_width_limited_race_exactly_one_succeeds() {
    fn width_limited_group_service(
        db: Arc<DBProvider<DbError>>,
    ) -> resource_group::domain::group_service::GroupService<
        resource_group::infra::storage::group_repo::GroupRepository,
        TypeRepository,
    > {
        resource_group::domain::group_service::GroupService::new(
            db,
            QueryProfile {
                max_depth: None,
                max_width: Some(1),
            },
            common::make_enforcer(),
            Arc::new(resource_group::infra::storage::group_repo::GroupRepository),
            Arc::new(TypeRepository),
            common::make_types_registry(),
        )
    }

    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = width_limited_group_service(db.clone());

    let t = {
        // `resolve_ids` rejects a parent path that doesn't exist yet, so the
        // type can't reference itself as an allowed parent at create time
        // (see create_self_referencing_type's equivalent comment in
        // db_behavior_audit_test.rs). Create it plain, then update to add
        // the self-reference below.
        let code = format!(
            "{}x.test.pgwidth.i{}.v1~",
            toolkit_gts::gts_id!("cf.core.rg.type.v1~"),
            Uuid::now_v7().as_simple()
        );
        type_svc
            .create_type(resource_group_sdk::CreateTypeRequest {
                code,
                can_be_root: true,
                allowed_parent_types: vec![],
                allowed_membership_types: vec![],
                metadata_schema: None,
            })
            .await
            .expect("create type (initial)")
    };
    let t = type_svc
        .update_type(
            &t.code,
            resource_group_sdk::UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![t.code.clone()],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .expect("update type to self-reference");

    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let root = common::create_root_group(&group_svc, &ctx, &t.code, "root", tenant_id).await;

    let barrier = Arc::new(Barrier::new(2));
    let svc1 = width_limited_group_service(db.clone());
    let svc2 = width_limited_group_service(db.clone());
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let (ctx1, ctx2) = (ctx.clone(), ctx.clone());
    let (code1, code2) = (t.code.clone(), t.code.clone());

    let t1 = tokio::spawn(async move {
        b1.wait().await;
        svc1.create_group(
            &ctx1,
            CreateGroupRequest {
                id: None,
                code: code1,
                name: "child-1".to_owned(),
                parent_id: Some(root.id),
                metadata: None,
            },
            tenant_id,
        )
        .await
    });
    let t2 = tokio::spawn(async move {
        b2.wait().await;
        svc2.create_group(
            &ctx2,
            CreateGroupRequest {
                id: None,
                code: code2,
                name: "child-2".to_owned(),
                parent_id: Some(root.id),
                metadata: None,
            },
            tenant_id,
        )
        .await
    });

    let (r1, r2) = timed("negative_control_width_limited_race", async {
        tokio::join!(t1, t2)
    })
    .await;
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent create under max_width=1 must succeed: r1={r1:?} r2={r2:?}"
    );
    let loser = if r1.is_err() { &r1 } else { &r2 };
    let loser_err = loser.as_ref().unwrap_err();
    // RG-15 fixed (same as negative_control_tenant_root_race_exactly_one_succeeds):
    // the loser must now always get the clean LimitViolation.
    assert!(
        matches!(loser_err, DomainError::LimitViolation { .. }),
        "the losing create must get a clean LimitViolation (proving transaction_with_retry \
         + the RG-15 fix absorbed the SSI conflict), got: {loser_err:?}"
    );

    assert_hierarchy_invariants(&db).await;

    group_svc
        .delete_group(&ctx, root.id, true)
        .await
        .expect("cleanup: force delete root + surviving child");
}

// =========================================================================
// Move-scenario races: does SERIALIZABLE really protect the closure table
// under concurrent hierarchy *mutations*, not just concurrent inserts?
// =========================================================================
//
// SERIALIZABLE + transaction_with_retry was introduced specifically to make
// moves safe (DESIGN.md's "Concurrency Testing" section), but none of the
// five scenarios above ever exercises `move_group`, and none races a
// hierarchy write against another hierarchy write that touches *overlapping*
// closure rows (as opposed to two independent inserts). These four
// scenarios close that gap, each followed by [`assert_hierarchy_invariants`]
// (and the membership-tenant equivalent where relevant) to check the actual
// data, not just the call outcomes.

/// Create a type that can be root AND lists itself as an allowed parent, so
/// its groups can be freely reparented under one another. Mirrors
/// `negative_control_width_limited_race_exactly_one_succeeds`'s inline setup
/// (a type can't reference itself as an allowed parent at create time --
/// `resolve_ids` rejects a parent path that doesn't exist yet).
async fn self_referencing_root_type(
    type_svc: &TypeService<TypeRepository>,
    suffix: &str,
) -> resource_group_sdk::ResourceGroupType {
    let t = common::create_root_type(type_svc, suffix).await;
    type_svc
        .update_type(
            &t.code,
            resource_group_sdk::UpdateTypeRequest {
                can_be_root: true,
                allowed_parent_types: vec![t.code.clone()],
                allowed_membership_types: vec![],
                metadata_schema: None,
            },
        )
        .await
        .expect("update type to self-reference")
}

/// `A` moves under `B` while, at the same instant, `B` moves under `A`.
/// Neither transaction's own cycle check (`is_descendant`) sees the other's
/// pending write in isolation -- both read "not currently a cycle" -- so
/// this is a textbook write-skew / SSI "dangerous structure": transaction 1
/// reads exactly the closure row transaction 2's rebuild writes, and vice
/// versa. If `SERIALIZABLE` really protects moves the way `DESIGN.md`
/// promises, PostgreSQL must abort (and `transaction_with_retry` retry) one
/// side; the retried side must then see the winner's committed move and
/// correctly report `CycleDetected` -- never an actual cycle written to the
/// database.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn move_a_to_b_races_move_b_to_a() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let t = self_referencing_root_type(&type_svc, "pgmoveaabba").await;

    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let a = common::create_root_group(&group_svc, &ctx, &t.code, "A", tenant_id).await;
    let b = common::create_root_group(&group_svc, &ctx, &t.code, "B", tenant_id).await;

    let barrier = Arc::new(Barrier::new(2));
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let svc1 = common::make_group_service(db.clone());
    let svc2 = common::make_group_service(db.clone());
    let (a_id, b_id) = (a.id, b.id);

    let t1 = tokio::spawn(async move {
        b1.wait().await;
        svc1.move_group(a_id, Some(b_id)).await
    });
    let t2 = tokio::spawn(async move {
        b2.wait().await;
        svc2.move_group(b_id, Some(a_id)).await
    });

    let (r1, r2) = timed("move_a_to_b_races_move_b_to_a", async {
        tokio::join!(t1, t2)
    })
    .await;
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    eprintln!(
        "move_a_to_b_races_move_b_to_a: move_A_under_B={} move_B_under_A={}",
        describe_result(&r1),
        describe_result(&r2),
    );

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one of A->B / B->A must succeed (the other must be rejected as a cycle) -- \
         both succeeding would mean an actual cycle was written; both failing would mean neither \
         side ever got a clean shot: move_A_under_B={r1:?} move_B_under_A={r2:?}"
    );
    let loser_err = if let Err(e) = &r1 {
        e
    } else {
        r2.as_ref().unwrap_err()
    };
    assert!(
        matches!(loser_err, DomainError::CycleDetected { .. }),
        "the losing move must get a clean CycleDetected (the retried attempt should see the \
         winner's already-committed move and correctly detect the would-be cycle), got: \
         {loser_err:?}"
    );

    // The interesting part: does the *data* actually stay a tree? Recompute
    // the whole-table transitive closure and check for cycles independently
    // of which side "won" the call.
    assert_hierarchy_invariants(&db).await;

    // Force-deleting A cascades into B too if B ended up under A; either
    // way, clean up both roots (ignore NotFound on whichever one the first
    // delete already swept up).
    group_svc.delete_group(&ctx, a.id, true).await.ok();
    group_svc.delete_group(&ctx, b.id, true).await.ok();
}

/// `M` is `R0`'s child and is itself the parent of `L`. Concurrently, `M`
/// moves out from under `R0` to `R2`, while `L` (M's own child) moves out to
/// `R3` at the same time. Both writes touch overlapping closure rows for
/// `L` (M's subtree-rebuild walks through L; L's own move rewrites those
/// same rows directly) -- exactly the overlapping-write concurrency
/// `rebuild_subtree_closure` has to get right under real load, not just
/// under a single caller. Unlike the A/B cycle race above, these two moves
/// are logically independent (no domain invariant should reject either), so
/// the healthy outcome is both succeeding once `transaction_with_retry`
/// absorbs any transient SSI conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn move_ancestor_races_move_descendant() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let t = self_referencing_root_type(&type_svc, "pgmoveanc").await;

    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let r0 = common::create_root_group(&group_svc, &ctx, &t.code, "R0", tenant_id).await;
    let m = common::create_child_group(&group_svc, &ctx, &t.code, r0.id, "M", tenant_id).await;
    let l = common::create_child_group(&group_svc, &ctx, &t.code, m.id, "L", tenant_id).await;
    let r2 = common::create_root_group(&group_svc, &ctx, &t.code, "R2", tenant_id).await;
    let r3 = common::create_root_group(&group_svc, &ctx, &t.code, "R3", tenant_id).await;

    let barrier = Arc::new(Barrier::new(2));
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let svc1 = common::make_group_service(db.clone());
    let svc2 = common::make_group_service(db.clone());
    let (m_id, l_id, r2_id, r3_id) = (m.id, l.id, r2.id, r3.id);

    let move_m_task = tokio::spawn(async move {
        b1.wait().await;
        svc1.move_group(m_id, Some(r2_id)).await
    });
    let move_leaf_task = tokio::spawn(async move {
        b2.wait().await;
        svc2.move_group(l_id, Some(r3_id)).await
    });

    let (move_m_res, move_leaf_res) = timed("move_ancestor_races_move_descendant", async {
        tokio::join!(move_m_task, move_leaf_task)
    })
    .await;
    let move_m_res = move_m_res.expect("move M task join");
    let move_leaf_res = move_leaf_res.expect("move L task join");

    eprintln!(
        "move_ancestor_races_move_descendant: move_M={} move_L={}",
        describe_result(&move_m_res),
        describe_result(&move_leaf_res),
    );

    assert!(
        move_m_res.is_ok() && move_leaf_res.is_ok(),
        "moving an ancestor and one of its own descendants to unrelated new parents at the same \
         time are independent operations that should both succeed once transaction_with_retry \
         absorbs any transient SSI conflict over the shared closure rows: move_M={move_m_res:?} \
         move_L={move_leaf_res:?}"
    );

    assert_hierarchy_invariants(&db).await;

    // M is now under R2 (without L); L is now under R3. Force-deleting the
    // three original roots (R0 is now empty, R2 carries M, R3 carries L)
    // resets the harness.
    for root_id in [r0.id, r2.id, r3.id] {
        group_svc.delete_group(&ctx, root_id, true).await.ok();
    }
}

/// A brand-new child `C` is created under `P` at the same instant `P`
/// itself is moved from `R0` to `Q`. Proves `insert_ancestor_closure_rows`
/// (reads `P`'s current ancestor chain to seed `C`'s closure rows) and
/// `rebuild_subtree_closure` (rewrites that same ancestor chain when `P`
/// moves) can't observe each other's stale/half-applied state: `C` must end
/// up with the *same* final ancestor chain as `P` ends up with, whichever
/// order the two transactions actually committed in. Like the
/// ancestor/descendant race above, these are logically independent
/// operations -- the healthy outcome is both succeeding.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_child_races_move_parent() {
    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let t = self_referencing_root_type(&type_svc, "pgcreatemove").await;

    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let r0 = common::create_root_group(&group_svc, &ctx, &t.code, "R0", tenant_id).await;
    let p = common::create_child_group(&group_svc, &ctx, &t.code, r0.id, "P", tenant_id).await;
    let q = common::create_root_group(&group_svc, &ctx, &t.code, "Q", tenant_id).await;

    let barrier = Arc::new(Barrier::new(2));
    let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let svc1 = common::make_group_service(db.clone());
    let svc2 = common::make_group_service(db.clone());
    let ctx1 = ctx.clone();
    let (code1, p_id, q_id) = (t.code.clone(), p.id, q.id);

    let create_task = tokio::spawn(async move {
        b1.wait().await;
        svc1.create_group(
            &ctx1,
            CreateGroupRequest {
                id: None,
                code: code1,
                name: "C".to_owned(),
                parent_id: Some(p_id),
                metadata: None,
            },
            tenant_id,
        )
        .await
    });
    let move_task = tokio::spawn(async move {
        b2.wait().await;
        svc2.move_group(p_id, Some(q_id)).await
    });

    let (create_res, move_res) = timed("create_child_races_move_parent", async {
        tokio::join!(create_task, move_task)
    })
    .await;
    let create_res = create_res.expect("create task join");
    let move_res = move_res.expect("move task join");

    eprintln!(
        "create_child_races_move_parent: create_C={} move_P={}",
        describe_result(&create_res),
        describe_result(&move_res),
    );

    assert!(
        create_res.is_ok() && move_res.is_ok(),
        "creating a child under P and moving P itself to a new parent at the same time are \
         independent operations that should both succeed once transaction_with_retry absorbs \
         any transient SSI conflict over P's ancestor closure rows: create_C={create_res:?} \
         move_P={move_res:?}"
    );

    assert_hierarchy_invariants(&db).await;

    // P (now under Q, with C under it) plus the now-empty R0 and Q.
    for root_id in [r0.id, q.id] {
        group_svc.delete_group(&ctx, root_id, true).await.ok();
    }
}

/// `G` is force-deleted (cascading) at the same instant a caller tries to
/// attach a brand-new child to it. `resource_group.parent_id` is `ON DELETE
/// RESTRICT`, so if the new child's row is visible to the delete's own
/// referential-integrity check before the delete's cascade has swept it up,
/// PostgreSQL itself refuses to let `G` disappear while the child still
/// references it. The question this test answers empirically is whether
/// `transaction_with_retry` turns that moment into a clean outcome (create
/// rejected with `GroupNotFound`, or delete's retry re-reads the descendant
/// set and cascades the child too) or whether a raw constraint-violation
/// error can still leak through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn force_delete_races_create_child() {
    const TRIALS: usize = 10;

    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let t = self_referencing_root_type(&type_svc, "pgfdelcreate").await;
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let mut clean_rejection = 0usize; // create failed cleanly (GroupNotFound)
    let mut cascaded_child = 0usize; // create succeeded, but child is gone afterwards (delete's cascade caught it)
    let mut orphan_survivor = 0usize; // create succeeded AND child still exists post-delete -- would violate FK RESTRICT, should be unreachable
    let mut unexpected = 0usize;

    for i in 0..TRIALS {
        let g =
            common::create_root_group(&group_svc, &ctx, &t.code, &format!("G{i}"), tenant_id).await;
        let barrier = Arc::new(Barrier::new(2));
        let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
        let group_svc1 = common::make_group_service(db.clone());
        let group_svc2 = common::make_group_service(db.clone());
        let ctx1 = ctx.clone();
        let ctx2 = ctx.clone();
        let (code1, g_id) = (t.code.clone(), g.id);

        let delete_task = tokio::spawn(async move {
            b1.wait().await;
            group_svc1.delete_group(&ctx1, g_id, true).await
        });
        let create_task = tokio::spawn(async move {
            b2.wait().await;
            group_svc2
                .create_group(
                    &ctx2,
                    CreateGroupRequest {
                        id: None,
                        code: code1,
                        name: "C".to_owned(),
                        parent_id: Some(g_id),
                        metadata: None,
                    },
                    tenant_id,
                )
                .await
        });

        let (delete_res, create_res) = timed("force_delete_races_create_child trial", async {
            tokio::join!(delete_task, create_task)
        })
        .await;
        let delete_res = delete_res.expect("delete task join");
        let create_res = create_res.expect("create task join");

        assert!(
            delete_res.is_ok(),
            "force_delete_group on an existing group must never itself fail: {delete_res:?}"
        );

        match &create_res {
            Err(DomainError::GroupNotFound { .. }) => clean_rejection += 1,
            Ok(child) => {
                let still_exists = group_svc.get_group_unscoped(child.id).await.is_ok();
                if still_exists {
                    orphan_survivor += 1;
                } else {
                    cascaded_child += 1;
                }
            }
            Err(_) => {
                unexpected += 1;
                eprintln!(
                    "force_delete_races_create_child: unexpected create outcome: {}",
                    describe_result(&create_res)
                );
            }
        }

        assert_hierarchy_invariants(&db).await;
    }

    eprintln!(
        "force_delete_races_create_child: clean_rejection={clean_rejection} \
         cascaded_child={cascaded_child} orphan_survivor={orphan_survivor} \
         unexpected={unexpected} (out of {TRIALS} trials)"
    );
    assert_eq!(
        orphan_survivor, 0,
        "RG-16 candidate: {orphan_survivor}/{TRIALS} trials left a child alive whose parent was \
         concurrently force-deleted -- this would mean the FK RESTRICT was somehow bypassed"
    );
    assert_eq!(
        unexpected, 0,
        "{unexpected}/{TRIALS} trials produced a raw/unexpected error instead of a clean \
         GroupNotFound or a successful (later cascaded) create -- possible RG-16 candidate"
    );
}

/// Same question as `force_delete_races_create_child`, but for a
/// membership row instead of a child group: `G` is force-deleted while a
/// caller concurrently tries to `add_membership` to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn force_delete_races_add_membership() {
    const TRIALS: usize = 10;

    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);

    let member_type = common::create_root_type(&type_svc, "pgfdelmbrres").await;
    let grp_type = type_svc
        .create_type(resource_group_sdk::CreateTypeRequest {
            code: format!(
                "{}x.test.pgfdelmbrgrp.i{}.v1~",
                toolkit_gts::gts_id!("cf.core.rg.type.v1~"),
                Uuid::now_v7().as_simple()
            ),
            can_be_root: true,
            allowed_parent_types: vec![],
            allowed_membership_types: vec![member_type.code.clone()],
            metadata_schema: None,
        })
        .await
        .expect("create membership-holding type");

    let mut clean_rejection = 0usize; // add_membership failed cleanly (GroupNotFound)
    let mut cascaded_membership = 0usize; // add succeeded, but membership is gone afterwards
    let mut orphan_survivor = 0usize; // add succeeded AND membership still exists post-delete -- should be unreachable
    let mut unexpected = 0usize;

    for i in 0..TRIALS {
        let g = common::create_root_group(
            &group_svc,
            &ctx,
            &grp_type.code,
            &format!("G{i}"),
            tenant_id,
        )
        .await;
        let resource_id = format!("res-{}", Uuid::now_v7().as_simple());
        let barrier = Arc::new(Barrier::new(2));
        let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
        let group_svc1 = common::make_group_service(db.clone());
        let membership_svc = common::make_membership_service(db.clone());
        let ctx1 = ctx.clone();
        let ctx2 = ctx.clone();
        let g_id = g.id;
        let (rt, rid) = (member_type.code.clone(), resource_id.clone());

        let delete_task = tokio::spawn(async move {
            b1.wait().await;
            group_svc1.delete_group(&ctx1, g_id, true).await
        });
        let add_task = tokio::spawn(async move {
            b2.wait().await;
            membership_svc.add_membership(&ctx2, g_id, &rt, &rid).await
        });

        let (delete_res, add_res) = timed("force_delete_races_add_membership trial", async {
            tokio::join!(delete_task, add_task)
        })
        .await;
        let delete_res = delete_res.expect("delete task join");
        let add_res = add_res.expect("add task join");

        assert!(
            delete_res.is_ok(),
            "force_delete_group on an existing group must never itself fail: {delete_res:?}"
        );

        match &add_res {
            Err(DomainError::GroupNotFound { .. }) => clean_rejection += 1,
            Ok(_) => {
                let survivors =
                    distinct_tenant_ids_for_resource(&db, &member_type.code, &resource_id).await;
                if survivors.is_empty() {
                    cascaded_membership += 1;
                } else {
                    orphan_survivor += 1;
                }
            }
            Err(_) => {
                unexpected += 1;
                eprintln!(
                    "force_delete_races_add_membership: unexpected add outcome: {}",
                    describe_result(&add_res)
                );
            }
        }

        assert_membership_tenant_invariant(&db).await;
        assert_hierarchy_invariants(&db).await;
    }

    eprintln!(
        "force_delete_races_add_membership: clean_rejection={clean_rejection} \
         cascaded_membership={cascaded_membership} orphan_survivor={orphan_survivor} \
         unexpected={unexpected} (out of {TRIALS} trials)"
    );
    assert_eq!(
        orphan_survivor, 0,
        "RG-16 candidate: {orphan_survivor}/{TRIALS} trials left a membership alive whose group \
         was concurrently force-deleted"
    );
    assert_eq!(
        unexpected, 0,
        "{unexpected}/{TRIALS} trials produced a raw/unexpected error instead of a clean \
         GroupNotFound or a successful (later cascaded) add_membership -- possible RG-16 \
         candidate"
    );
}
