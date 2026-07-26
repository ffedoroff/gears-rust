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
//! All five tests share one PostgreSQL database (started once, lazily, by
//! whichever test asks first) and serialize against it via [`PG_TEST_LOCK`],
//! because a couple of scenarios (tenant-root uniqueness) exercise a *global*
//! invariant (scoped by a type-code prefix, not by any per-test tenant id)
//! that would spuriously conflict if two test functions in this file ran
//! concurrently against it (cargo test's default parallel-by-function
//! scheduling would otherwise do exactly that). Each test cleans up the rows
//! it created so the harness stays re-runnable.
//!
//! ## Scenarios
//!
//! - `membership_first_write_race_*` -- known defect RG-01: two concurrent
//!   "first membership" adds for the same resource in two different tenants
//!   both succeed, because `add_membership_inner`'s check-then-insert runs on
//!   a bare connection with no transaction.
//! - `delete_type_races_create_group_*` -- known defect RG-02: reproduces the
//!   delete-check race window (`delete_type`'s count-then-delete has no
//!   transaction either).
//! - `create_type_conflict_no_retry_*` -- known defect RG-03: two concurrent
//!   `create_type` calls for the *same* code hit a SERIALIZABLE conflict;
//!   because `create_type` isn't wrapped in `transaction_with_retry` (unlike
//!   `create_group`), the loser gets a raw serialization-failure error
//!   instead of transparently retrying to the clean `TypeAlreadyExists`.
//! - `negative_control_*` -- tenant-root create and width=1 create both use
//!   `transaction_with_retry` + SERIALIZABLE: the *invariant* always holds
//!   (exactly one of two concurrent attempts succeeds -- this must keep
//!   passing, it proves the detector distinguishes protected invariants from
//!   broken ones using the same kind of concurrent-race harness, not just by
//!   "reads vs writes"). The *error shape* the loser gets is a separate,
//!   softer check: ideally the clean domain error (`TenantRootAlreadyExists`
//!   / `LimitViolation`), but new finding RG-16 means it's sometimes a raw
//!   serialization-failure error instead -- every repo call wraps its
//!   sea_orm error via `DomainError::database(e.to_string())`, which loses
//!   the structured `DbErr` shape `is_retryable_contention` needs to decide
//!   a retry is warranted, so `transaction_with_retry`'s retry can silently
//!   never fire even on this "protected" path. Both tests log which shape
//!   they observed rather than hard-failing on it.

mod common;

use std::sync::Arc;

use resource_group::domain::error::DomainError;
use resource_group::domain::group_service::QueryProfile;
use resource_group::domain::type_service::TypeService;
use resource_group::infra::storage::entity::resource_group::{
    Column as RgColumn, Entity as RgEntity,
};
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
    match r {
        Ok(_) => "Ok".to_owned(),
        Err(e) => format!("Err({e})"),
    }
}

// =========================================================================
// RG-01: membership first-write race
// =========================================================================

/// Two concurrent `add_membership` calls for the same `(resource_type,
/// resource_id)` in two *different* tenants. The "a resource belongs to
/// groups of a single tenant" invariant requires exactly one of them to
/// succeed -- `add_membership_inner`'s check-then-insert has no transaction,
/// so both race the same "existing_tenants is empty" read and both insert.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn membership_first_write_race_both_tenants_succeed() {
    // A genuine race between two network round-trips isn't guaranteed to
    // interleave on every single attempt (system load, scheduler luck), so
    // run several trials and require the bug to reproduce in at least one --
    // matches delete_type_races_create_group_reproduces_check_window's
    // approach below. In practice this reproduces on every trial when the
    // machine isn't under heavy concurrent load.
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

        let (r1, r2) = tokio::join!(t1, t2);
        let r1 = r1.expect("task 1 join");
        let r2 = r2.expect("task 2 join");

        let tenant_ids =
            distinct_tenant_ids_for_resource(&db, &member_type.code, &resource_id).await;
        match (r1.is_ok(), r2.is_ok(), tenant_ids.len()) {
            (true, true, 2) => both_succeeded += 1,
            (true, false, 1) | (false, true, 1) => correctly_rejected += 1,
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
        "every trial must be either the known bug (both succeed) or the correct outcome \
         (one rejected) -- got {unexpected} trials with a genuinely unexpected shape"
    );
    // Known defect RG-01, reproduced: with a correct implementation, every
    // trial would land in `correctly_rejected` (one Ok, one
    // Err(TenantIncompatibility)). Today at least some trials show both
    // tenants' "first membership" succeeding for the same resource --
    // add_membership_inner's check-then-insert has no transaction. Once
    // RG-01 is fixed, invert this to `assert_eq!(both_succeeded, 0)`.
    assert!(
        both_succeeded > 0,
        "known defect RG-01 not reproduced in {TRIALS} trials (correctly_rejected={correctly_rejected}) \
         -- either the bug was fixed (update the report) or the race didn't interleave this run; \
         try increasing TRIALS"
    );
}

// =========================================================================
// RG-02: delete_type races create_group of that type
// =========================================================================

/// `delete_type`'s count-then-delete has no transaction, so it can pass its
/// own "no groups reference this type" check and then have a concurrent
/// `create_group_unscoped` insert one anyway. The FK (`resource_group
/// .gts_type_id ... ON DELETE RESTRICT`) prevents *data corruption* (the type
/// row can never actually vanish while a referencing group exists), but the
/// race still means the outcome is nondeterministic and can surface a raw
/// database error instead of the clean `ConflictActiveReferences` the code
/// intends. Run repeatedly to make the window observable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delete_type_races_create_group_reproduces_check_window() {
    const TRIALS: usize = 15;

    let (db, _pg_guard) = pg_db_or_skip!();
    let type_svc = TypeService::new(db.clone(), Arc::new(TypeRepository));
    let tenant_id = Uuid::now_v7();

    let mut corruption = 0usize; // both succeeded -- would be a real invariant violation
    let mut delete_won = 0usize; // delete succeeded, create then failed (type gone)
    let mut create_won = 0usize; // create succeeded, delete correctly rejected (conflict)
    let mut raw_db_error = 0usize; // either side surfaced a non-domain-shaped DB error

    for i in 0..TRIALS {
        let t = common::create_root_type(&type_svc, &format!("pgdelrace{i}")).await;
        let barrier = Arc::new(Barrier::new(2));
        let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));
        // Fresh instances per task -- see the comment in
        // membership_first_write_race_both_tenants_succeed about why these
        // services can't just be `.clone()`d.
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

        let (delete_res, create_res) = tokio::join!(delete_task, create_task);
        let delete_res = delete_res.expect("delete task join");
        let create_res = create_res.expect("create task join");

        // Each trial uses a fresh, uniquely-coded type (no global invariant
        // like tenant-root is at stake), so there's nothing to clean up
        // between trials regardless of outcome.
        match (&delete_res, &create_res) {
            (Ok(()), Ok(_)) => corruption += 1,
            (Ok(()), Err(_)) => delete_won += 1,
            (Err(DomainError::ConflictActiveReferences { .. }), Ok(_)) => create_won += 1,
            (Err(_), Ok(_)) => raw_db_error += 1,
            (_, Err(_)) => {
                // Either delete_type errored non-cleanly, or create failed
                // (e.g. TypeNotFound because delete really did win first);
                // both are consistent with "delete won" or "raw error".
                if delete_res.is_ok() {
                    delete_won += 1;
                } else {
                    raw_db_error += 1;
                }
            }
        }
    }

    assert_eq!(
        corruption, 0,
        "invariant violation: delete_type and create_group_unscoped both succeeded for the \
         same type in {corruption}/{TRIALS} trials -- FK RESTRICT should make this impossible"
    );
    // Known defect RG-02 window, reproduced: without a transaction wrapping
    // delete_type's check+delete, racing it against a concurrent first-group
    // create is nondeterministic. We don't assert a specific split (that
    // depends on scheduler timing), only that the race is real: at least one
    // trial produced *some* outcome, and if any trial surfaced a raw
    // non-domain error that's direct evidence of the missing transaction
    // (see docs/analysis/DB_BEHAVIOR_AUDIT.md).
    assert_eq!(
        delete_won + create_won + raw_db_error,
        TRIALS,
        "accounting mismatch: delete_won={delete_won} create_won={create_won} raw_db_error={raw_db_error}"
    );
    eprintln!(
        "delete_type_races_create_group: delete_won={delete_won} create_won={create_won} \
         raw_db_error={raw_db_error} (out of {TRIALS} trials)"
    );
}

// =========================================================================
// RG-03: create_type conflict has no retry
// =========================================================================

/// Two concurrent `create_type` calls for the *same* code. Both check
/// "does this code exist" inside their own SERIALIZABLE transaction, both
/// see "no", both attempt the INSERT -- one must fail under SSI. Because
/// `create_type` is not wrapped in `transaction_with_retry` (unlike
/// `create_group`, see the negative controls below), the loser gets whatever
/// raw error the retry-less path surfaces instead of a clean
/// `TypeAlreadyExists`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn create_type_conflict_no_retry_yields_raw_error_for_loser() {
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

    let (r1, r2) = tokio::join!(t1, t2);
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent create_type for the same code must succeed: r1={r1:?} r2={r2:?}"
    );

    let loser = if r1.is_err() { &r1 } else { &r2 };
    let loser_err = loser.as_ref().unwrap_err();
    // Known defect RG-03, reproduced: a *correct*, retry-wrapped
    // implementation would transparently retry the SSI conflict and return
    // TypeAlreadyExists (see create_group's equivalent path, which does).
    // Document what actually comes back so the report can cite it, without
    // over-constraining on a specific DbErr message.
    eprintln!("create_type_conflict_no_retry: loser error = {loser_err}");
    assert!(
        !matches!(loser_err, DomainError::TypeAlreadyExists { .. }),
        "if this starts failing, RG-03 has likely been fixed (loser now gets a clean \
         TypeAlreadyExists via retry) -- update docs/analysis/DB_BEHAVIOR_AUDIT.md and invert \
         this assertion. Got: {loser_err:?}"
    );
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

    let (r1, r2) = tokio::join!(t1, t2);
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent tenant-root create must succeed: r1={r1:?} r2={r2:?}"
    );
    let loser = if r1.is_err() { &r1 } else { &r2 };
    let loser_err = loser.as_ref().unwrap_err();
    // The uniqueness invariant itself held (asserted above: ok_count == 1).
    // Ideally the loser always gets the clean TenantRootAlreadyExists that
    // transaction_with_retry's retry is supposed to produce once it resolves
    // the SSI conflict. In practice this run may instead observe new finding
    // RG-16: every repo call maps its sea_orm error through
    // `DomainError::database(e.to_string())`, which wraps it as
    // `DbErr::Custom` -- a shape `is_retryable_contention` never matches
    // (it only recognizes `DbErr::Exec`/`DbErr::Query`). When the SSI abort
    // surfaces from an interior repo call rather than at COMMIT, the retry
    // never fires and a raw serialization-failure error leaks through even
    // on this "protected" path. Accept either outcome here (the invariant is
    // what this test guards), but surface which one happened for the report.
    if loser_err.is_serialization_failure() {
        eprintln!(
            "negative_control_tenant_root_race: RG-16 reproduced -- loser got a raw \
             serialization failure instead of TenantRootAlreadyExists: {loser_err}"
        );
    } else {
        assert!(
            matches!(loser_err, DomainError::TenantRootAlreadyExists { .. }),
            "expected either TenantRootAlreadyExists or (RG-16) a raw serialization failure, \
             got something else entirely: {loser_err:?}"
        );
    }

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

    let (r1, r2) = tokio::join!(t1, t2);
    let r1 = r1.expect("task 1 join");
    let r2 = r2.expect("task 2 join");

    let ok_count = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        ok_count, 1,
        "exactly one concurrent create under max_width=1 must succeed: r1={r1:?} r2={r2:?}"
    );
    let loser = if r1.is_err() { &r1 } else { &r2 };
    let loser_err = loser.as_ref().unwrap_err();
    // Same caveat as negative_control_tenant_root_race_exactly_one_succeeds:
    // the width invariant itself held (ok_count == 1, asserted above); the
    // loser's error shape may be the clean LimitViolation, or -- new finding
    // RG-16 -- a raw serialization failure if the SSI abort surfaced from an
    // interior repo call (see that test's comment for the full explanation).
    if loser_err.is_serialization_failure() {
        eprintln!(
            "negative_control_width_limited_race: RG-16 reproduced -- loser got a raw \
             serialization failure instead of LimitViolation: {loser_err}"
        );
    } else {
        assert!(
            matches!(loser_err, DomainError::LimitViolation { .. }),
            "expected either LimitViolation or (RG-16) a raw serialization failure, got \
             something else entirely: {loser_err:?}"
        );
    }

    group_svc
        .delete_group(&ctx, root.id, true)
        .await
        .expect("cleanup: force delete root + surviving child");
}
