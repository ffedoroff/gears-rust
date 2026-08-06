#![cfg(feature = "integration")]
// Created: 2026-07-29 by Constructor Tech
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]
//! PostgreSQL-backed reproduction of the failure mode, for
//! `list_groups`' own `type` `$filter` -- mirrors
//! `pg_membership_filter_test.rs`, which covers the same concern for
//! `list_memberships`.
//!
//! `fe2d609e` lifted `resolve_type_filter_node` out of `GroupRepository`
//! (where it was originally written, specific to `GroupFilterField`) and
//! into `TypeRepository`, generic over the caller's filter-field enum, so
//! `GroupRepository::list_groups` and `MembershipRepository::list_memberships`
//! now share one implementation instead of two. Independent review found
//! that after that generalization, `list_groups`' own `type` `$filter` had
//! no dedicated test: a regression in the shared resolve that broke only
//! the `GroupFilterField::Type` guard (but not `MembershipFilterField`)
//! would pass CI, since every other test that exercises the shared code
//! goes through memberships.
//!
//! The specific defect shape the SQLite-level test
//! (`group_service_test.rs::group_list_filters_by_type_returns_only_matching_type`)
//! cannot reach: `type` is a GTS type-path string on the wire but stored
//! as the SMALLINT `gts_type_id` column. If `list_groups` ever went back
//! to comparing the raw string against that column (i.e. skipped the
//! resolve), SQLite's lenient type affinity would tolerate the mismatch
//! and silently return an empty page; real PostgreSQL rejects the
//! comparison outright ("operator does not exist: smallint = text"),
//! exactly like the membership half of the fix already covers.
//!
//! **Why a Rust `testcontainers` test, not pytest E2E:** this is a
//! deliberate, written-down deviation from
//! `docs/toolkit_unified_system/12_unit_testing.md` (which routes
//! PostgreSQL-specific behavior to E2E) and `13_e2e_testing.md` (which
//! defines E2E as pytest against a running `cf-gears-server`). Precedent:
//! PR #4269 established this pattern first, with `pg_concurrency_test.rs`
//! plus the `test-rg-pg` `Makefile` target and its dedicated CI step -- this
//! suite and `pg_membership_filter_test.rs` follow the same shape. It stays
//! out of the default suite (gated behind
//! `#![cfg(feature = "integration")]`, run only via `make test-rg-pg` / CI's
//! `integration` job), so it does not violate the unit-testing guide's speed
//! requirement. And it gives a diagnosis pytest cannot: if this filter ever
//! regresses, the failure carries PostgreSQL's actual rejected-SQL text
//! ("operator does not exist: smallint = text", via
//! `DomainError::Database`), not just an HTTP status code -- a pytest
//! client hitting the same regression through the REST layer would only
//! ever see a 500 with no indication of the actual type mismatch. See
//! `docs/db-behavior-audit.md` for the fuller writeup of this decision.
//!
//! Run via:
//! ```sh
//! cargo nextest run -p cf-gears-resource-group --features integration --test pg_group_filter_test
//! ```

mod common;

use std::sync::Arc;

use resource_group::domain::error::DomainError;
use resource_group::domain::repo::GroupRepositoryTrait;
use resource_group::infra::storage::group_repo::GroupRepository;
use resource_group::infra::storage::migrations::Migrator;
use sea_orm_migration::MigratorTrait;
use testcontainers::{ContainerRequest, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;
use toolkit_db::{
    ConnectOpts, DBProvider, DbError, connect_db, migration_runner::run_migrations_for_testing,
};
use uuid::Uuid;

/// A PostgreSQL container plus a `DBProvider` connected to it, owned by the
/// test. Deliberately a standalone copy of `pg_concurrency_test.rs`'s
/// `PgFixture` (that type and its helpers are private to that module) --
/// same container-lifetime and CI-gating rationale, see that file's docs.
struct PgFixture {
    _container: testcontainers::ContainerAsync<Postgres>,
    db: Arc<DBProvider<DbError>>,
}

/// Whether a missing or broken Docker must fail the run rather than skip it.
/// CI sets `RG_PG_REQUIRE_DOCKER=1`; locally it is unset and skipping is fine.
fn require_docker() -> bool {
    std::env::var_os("RG_PG_REQUIRE_DOCKER").is_some_and(|v| v != "0" && !v.is_empty())
}

/// Bring up a `testcontainers` PostgreSQL and run RG's migrations against it.
/// Returns `None` if Docker isn't reachable; callers treat that as a
/// graceful skip (except in CI, where `RG_PG_REQUIRE_DOCKER=1` panics instead).
async fn pg_fixture() -> Option<PgFixture> {
    // Pin a modern tag: the default "11-alpine" predates gen_random_uuid()
    // becoming a built-in (PG13+), which RG's migrations use.
    let request = ContainerRequest::from(Postgres::default())
        .with_tag("16-alpine")
        .with_env_var("POSTGRES_PASSWORD", "pass")
        .with_env_var("POSTGRES_USER", "user")
        .with_env_var("POSTGRES_DB", "app");

    let container = match request.start().await {
        Ok(container) => container,
        Err(e) => {
            let msg = format!(
                "group filter tests: could not start a PostgreSQL container via \
                 testcontainers ({e}). Install/start Docker to run these for real."
            );
            assert!(!require_docker(), "{msg}");
            eprintln!("skipping -- {msg}");
            return None;
        }
    };
    let port = match container.get_host_port_ipv4(5432).await {
        Ok(port) => port,
        Err(e) => {
            let msg = format!(
                "group filter tests: container started but its port could not be \
                 resolved ({e}). Is Docker healthy?"
            );
            assert!(!require_docker(), "{msg}");
            eprintln!("skipping -- {msg}");
            return None;
        }
    };

    let opts = ConnectOpts {
        max_conns: Some(5),
        min_conns: Some(1),
        ..Default::default()
    };
    let db = connect_db(&format!("postgres://user:pass@127.0.0.1:{port}/app"), opts)
        .await
        .expect("connect to the testcontainers PostgreSQL");
    run_migrations_for_testing(&db, Migrator::migrations())
        .await
        .expect("run resource-group migrations against PostgreSQL");

    Some(PgFixture {
        _container: container,
        db: Arc::new(DBProvider::new(db)),
    })
}

/// Bring up the fixture, or return from the test if Docker isn't available.
macro_rules! pg_fixture_or_skip {
    () => {
        match pg_fixture().await {
            Some(fixture) => fixture,
            None => return,
        }
    };
}

/// (groups side): filtering `list_groups` by `type` against real
/// PostgreSQL. Before `resolve_type_filter_node` existed (and if a future
/// change to the now-shared implementation ever dropped the
/// `GroupFilterField::Type` guard), the repository would compare the raw
/// GTS type-path string against the SMALLINT `gts_type_id` column --
/// PostgreSQL rejects that comparison outright as a genuine DB error
/// (surfaced through `DomainError::Database`, i.e. HTTP 500), rather than
/// SQLite's silent empty-page behavior.
#[tokio::test(flavor = "multi_thread")]
async fn list_groups_resolves_type_filter_on_postgres() {
    let fixture = pg_fixture_or_skip!();
    let db = fixture.db.clone();
    let conn = db.conn().expect("db conn");

    let type_svc = common::make_type_service(db.clone());
    let type_a = common::create_root_type(&type_svc, "pggrpfa").await;
    let type_b = common::create_root_type(&type_svc, "pggrpfb").await;

    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let group_a = common::create_root_group(&group_svc, &ctx, &type_a.code, "PGA", tenant_id).await;
    common::create_root_group(&group_svc, &ctx, &type_b.code, "PGB", tenant_id).await;

    let parsed = toolkit_odata::parse_filter_string(&format!("type eq '{}'", type_a.code))
        .expect("parse type filter");
    let query = toolkit_odata::ODataQuery::new().with_filter(parsed.into_expr());

    let scope = toolkit_security::AccessScope::for_tenant(tenant_id);
    let repo = GroupRepository;
    let result = repo.list_groups(&conn, &scope, &query).await;

    match &result {
        Ok(page) => {
            assert_eq!(
                page.items.len(),
                1,
                "type filter must resolve the GTS path to its surrogate id and return \
                 exactly the seeded group of that type, excluding the other type's group: \
                 {:?}",
                page.items
            );
            assert_eq!(page.items[0].id, group_a.id);
            assert_eq!(page.items[0].code, type_a.code);
        }
        Err(DomainError::Database(db_err)) => {
            panic!(
                "list_groups returned a raw DB error for the type filter -- the \
                 SMALLINT/string type mismatch regressed on the groups path: \
                 {db_err}"
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}
