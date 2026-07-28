#![cfg(feature = "integration")]
// Created: 2026-07-29 by Constructor Tech
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]
//! PostgreSQL-backed reproduction of VHP-1731's actual reported symptom.
//!
//! `list_memberships`' `resource_type` `$filter` used to compare a GTS
//! type-path string directly against the SMALLINT `gts_type_id` column
//! (`membership_repo.rs` never resolved the string to its surrogate id, the
//! way `list_groups` already does for its `type` filter). SQLite tolerates
//! the mismatch via its lenient type affinity and silently returns an empty
//! page -- pinned at the service level in
//! `membership_service_test.rs::membership_list_filters_by_resource_type`.
//! Real PostgreSQL does not: comparing a SMALLINT column against a
//! non-numeric text value is a genuine backend error there, which is the
//! actual 500 the ticket reports. Only real Postgres can prove that half of
//! the defect, hence this separate `--features integration` suite --
//! mirrors `pg_concurrency_test.rs`'s Docker-gated harness (see that file's
//! module docs for the full rationale behind the container-lifetime /
//! `RG_PG_REQUIRE_DOCKER` pattern duplicated below).
//!
//! Run via:
//! ```sh
//! cargo nextest run -p cf-gears-resource-group --features integration --test pg_membership_filter_test
//! ```

mod common;

use std::sync::Arc;

use resource_group::domain::error::DomainError;
use resource_group::domain::repo::MembershipRepositoryTrait;
use resource_group::infra::storage::membership_repo::MembershipRepository;
use resource_group::infra::storage::migrations::Migrator;
use resource_group::infra::storage::type_repo::TypeRepository;
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
                "membership filter tests: could not start a PostgreSQL container via \
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
                "membership filter tests: container started but its port could not be \
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

/// VHP-1731: filtering `list_memberships` by `resource_type` against real
/// PostgreSQL. Before the fix, the repository compared the raw GTS
/// type-path string against the SMALLINT `gts_type_id` column --
/// PostgreSQL rejects that comparison outright as a genuine DB error
/// (surfaced through `DomainError::Database`, i.e. HTTP 500), rather than
/// SQLite's silent empty-page behavior.
#[tokio::test(flavor = "multi_thread")]
async fn list_memberships_resolves_resource_type_filter_on_postgres() {
    let fixture = pg_fixture_or_skip!();
    let db = fixture.db.clone();
    let conn = db.conn().expect("db conn");

    let type_svc = common::make_type_service(db.clone());
    let member_type = common::create_root_type(&type_svc, "pgmbrfilter").await;

    let group_svc = common::make_group_service(db.clone());
    let tenant_id = Uuid::now_v7();
    let ctx = common::make_ctx(tenant_id);
    let group =
        common::create_root_group(&group_svc, &ctx, &member_type.code, "PGF", tenant_id).await;

    let gts_type_id = TypeRepository::resolve_id(&conn, &member_type.code)
        .await
        .expect("resolve member type")
        .expect("member type must be registered");

    let mbr_repo = MembershipRepository;
    mbr_repo
        .insert(&conn, group.id, gts_type_id, "res-pg-1")
        .await
        .expect("seed membership");

    let parsed =
        toolkit_odata::parse_filter_string(&format!("resource_type eq '{}'", member_type.code))
            .expect("parse resource_type filter");
    let query = toolkit_odata::ODataQuery::new().with_filter(parsed.into_expr());

    let scope = toolkit_security::AccessScope::allow_all();
    let result = mbr_repo.list_memberships(&conn, &scope, &query).await;

    match &result {
        Ok(page) => {
            assert_eq!(
                page.items.len(),
                1,
                "resource_type filter must resolve the GTS path to its \
                 surrogate id and return exactly the seeded membership: {:?}",
                page.items
            );
            assert_eq!(page.items[0].resource_id, "res-pg-1");
            assert_eq!(page.items[0].resource_type, member_type.code);
        }
        Err(DomainError::Database(db_err)) => {
            panic!(
                "list_memberships returned a raw DB error for the resource_type \
                 filter -- the SMALLINT/string type mismatch (VHP-1731) is unfixed: {db_err}"
            );
        }
        Err(other) => panic!("unexpected error: {other}"),
    }
}

/// VHP-2341: `list_memberships`' tenant scoping (a correlated EXISTS
/// subquery against `resource_group`, since the membership entity itself
/// declares `no_tenant`) must actually filter rows on a real database, not
/// just SQLite. Two tenants each get a group with one membership; a scope
/// constrained to tenant A must return only A's row, and vice versa for B.
///
/// This is the one piece of VHP-2341 that specifically needs Postgres:
/// SQLite's lenient typing/planner can mask a query that would be rejected
/// or silently mis-plan on a real engine (see VHP-1731's `resource_type`
/// filter for a concrete precedent of exactly that gap in this same repo).
#[tokio::test(flavor = "multi_thread")]
async fn list_memberships_is_tenant_scoped_on_postgres() {
    let fixture = pg_fixture_or_skip!();
    let db = fixture.db.clone();
    let conn = db.conn().expect("db conn");

    let type_svc = common::make_type_service(db.clone());
    let member_type = common::create_root_type(&type_svc, "pgtenscope").await;

    let group_svc = common::make_group_service(db.clone());
    let tenant_a = Uuid::now_v7();
    let tenant_b = Uuid::now_v7();
    let ctx_a = common::make_ctx(tenant_a);
    let ctx_b = common::make_ctx(tenant_b);
    let group_a =
        common::create_root_group(&group_svc, &ctx_a, &member_type.code, "PGA", tenant_a).await;
    let group_b =
        common::create_root_group(&group_svc, &ctx_b, &member_type.code, "PGB", tenant_b).await;

    let gts_type_id = TypeRepository::resolve_id(&conn, &member_type.code)
        .await
        .expect("resolve member type")
        .expect("member type must be registered");

    let mbr_repo = MembershipRepository;
    mbr_repo
        .insert(&conn, group_a.id, gts_type_id, "res-pg-tenant-a")
        .await
        .expect("seed tenant A membership");
    mbr_repo
        .insert(&conn, group_b.id, gts_type_id, "res-pg-tenant-b")
        .await
        .expect("seed tenant B membership");

    let query = toolkit_odata::ODataQuery::default();

    let scope_a = toolkit_security::AccessScope::for_tenant(tenant_a);
    let page_a = mbr_repo
        .list_memberships(&conn, &scope_a, &query)
        .await
        .expect("list_memberships scoped to tenant A");
    let ids_a: Vec<&str> = page_a
        .items
        .iter()
        .map(|m| m.resource_id.as_str())
        .collect();
    assert!(
        ids_a.contains(&"res-pg-tenant-a"),
        "tenant A scope must see tenant A's membership, got: {ids_a:?}"
    );
    assert!(
        !ids_a.contains(&"res-pg-tenant-b"),
        "tenant A scope must NOT see tenant B's membership, got: {ids_a:?}"
    );

    let scope_b = toolkit_security::AccessScope::for_tenant(tenant_b);
    let page_b = mbr_repo
        .list_memberships(&conn, &scope_b, &query)
        .await
        .expect("list_memberships scoped to tenant B");
    let ids_b: Vec<&str> = page_b
        .items
        .iter()
        .map(|m| m.resource_id.as_str())
        .collect();
    assert!(
        ids_b.contains(&"res-pg-tenant-b"),
        "tenant B scope must see tenant B's membership, got: {ids_b:?}"
    );
    assert!(
        !ids_b.contains(&"res-pg-tenant-a"),
        "tenant B scope must NOT see tenant A's membership, got: {ids_b:?}"
    );
}
