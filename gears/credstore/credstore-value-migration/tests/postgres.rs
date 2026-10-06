// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! `migrate` and `cleanup` on a real `PostgreSQL` in a container: the happy path,
//! a resume case, the `m0002` guard, and the advisory lock that keeps a second
//! run out. The `SQLite` suites cover every phase; this one checks what only the
//! real engine can: the statements, transactional DDL and the session lock.
//!
//! All tests are `#[ignore]`d (they need Docker and never run in CI):
//!
//! ```text
//! CREDSTORE_MIGRATION_REQUIRE_DOCKER=1 cargo test -p cf-gears-credstore-value-migration \
//!     --test postgres -- --ignored
//! ```
//!
//! Without a reachable Docker a test prints a notice and returns, unless
//! `CREDSTORE_MIGRATION_REQUIRE_DOCKER` is set.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::use_debug,
    reason = "tests"
)]

mod common;

use common::{Fixture, Row, Standard, expect_exit, tenant};
use credstore::CredStoreGear;
use credstore::infra::storage::migrations::Migrator;
use credstore_sdk::{StoreKey, TenantId};
use credstore_value_migration::Exit;
use toolkit_db::migration_runner::run_migrations_for_gear;
use toolkit_db::sea_orm_migration::MigratorTrait;
use uuid::Uuid;

macro_rules! docker_test {
    ($(#[$meta:meta])* async fn $name:ident($f:ident) $body:block) => {
        #[tokio::test]
        #[ignore = "requires Docker (starts a PostgreSQL container); run manually with `-- --ignored`"]
        $(#[$meta])*
        async fn $name() {
            let Some($f) = Fixture::postgres().await else {
                return;
            };
            $body
        }
    };
}

async fn assert_activated(f: &Fixture, row: &Row) {
    let (status, version, fallback, row_version) = f.secret(row.id).await.unwrap();
    assert_eq!(
        (status, fallback, row_version),
        (2, 1, 2),
        "{}",
        row.reference
    );
    let key = StoreKey::new(TenantId(row.tenant), row.id);
    assert_eq!(
        f.new.bytes(&key, &version.unwrap()).unwrap(),
        row.value(),
        "{}",
        row.reference
    );
}

fn ids(s: &Standard) -> Vec<Uuid> {
    [
        &s.shared,
        &s.private,
        &s.seeded,
        &s.tenant_shared,
        &s.provisioning,
        &s.deprovisioning,
    ]
    .iter()
    .map(|r| r.id)
    .collect()
}

docker_test! {
    async fn migrate_then_cleanup_on_postgres(f) {
        let s = f.seed_standard().await;
        let lost = Row::valued(10, tenant(5), "gone");
        f.insert(&lost).await;

        // Losses need a decision first.
        expect_exit(&f.run(&["migrate"]).await, Exit::Decision);
        assert_eq!(f.phase().await, "verifying");

        let run = f.run(&["migrate", "--accept-losses"]).await;
        expect_exit(&run, Exit::Success);
        assert_eq!(f.header().await, Some(("done".to_owned(), true, false)));
        for row in s.active() {
            assert_activated(&f, row).await;
        }
        assert_eq!(f.secret(lost.id).await.map(|(s, v, fb, _)| (s, v, fb)), Some((4, None, 2)));
        assert!(!f.row_exists(s.provisioning.id).await);
        assert_eq!(f.history().await, ["m0001_initial_schema", "m0002_value_versions"]);
        assert!(f.new.live().values().all(|v| v.len() == 1));

        // Finished: a second run only reports.
        let again = f.run(&["migrate"]).await;
        expect_exit(&again, Exit::Success);
        assert!(again.out.contains("already done"), "{}", again.out);

        // Cleanup, with the bookkeeping dropped at the end.
        expect_exit(&f.run(&["cleanup", "--include-fence-key", "--drop-state"]).await, Exit::Success);
        assert!(f.old.snapshot().is_empty());
        assert!(!f.table_exists("credstore_value_migration_rows").await);
        assert!(!f.table_exists("credstore_value_migration").await);
        for row in s.active() {
            assert_activated(&f, row).await;
        }
    }
}

docker_test! {
    async fn a_crash_in_the_middle_of_activating_resumes_on_postgres(f) {
        let s = f.seed_standard().await;
        credstore_value_migration::state::create_tables(&f.db, f.backend()).await.unwrap();
        f.exec("CREATE FUNCTION credstore_inject() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql").await;
        f.exec(
            "CREATE TRIGGER inject BEFORE UPDATE OF activated ON credstore_value_migration_rows \
             FOR EACH ROW WHEN (NEW.activated AND NEW.reference = 'shared-by-3') \
             EXECUTE FUNCTION credstore_inject()",
        )
        .await;

        let first = f.run(&["migrate"]).await;
        expect_exit(&first, Exit::Failure);
        assert_eq!(f.phase().await, "activating");
        // The failing row is untouched (one transaction); the ones before it are done.
        let (status, version, _, _) = f.secret(s.tenant_shared.id).await.unwrap();
        assert_eq!((status, version), (4, None));
        assert_activated(&f, &s.shared).await;

        f.exec("DROP TRIGGER inject ON credstore_value_migration_rows").await;
        expect_exit(&f.run(&["migrate"]).await, Exit::Success);
        for row in s.active() {
            assert_activated(&f, row).await;
        }
        assert_eq!(f.phase().await, "done");
        assert!(f.new.live().values().all(|v| v.len() == 1));
    }
}

docker_test! {
    async fn m0002_applied_but_not_recorded_by_the_tool_resumes_on_postgres(f) {
        let s = f.seed_standard().await;
        credstore_value_migration::state::create_tables(&f.db, f.backend()).await.unwrap();
        f.exec("CREATE FUNCTION credstore_inject() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected'; END $$ LANGUAGE plpgsql").await;
        f.exec(
            "CREATE TRIGGER inject BEFORE UPDATE OF phase ON credstore_value_migration \
             FOR EACH ROW WHEN (NEW.phase = 'activating') EXECUTE FUNCTION credstore_inject()",
        )
        .await;

        expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
        // m0002 is applied (the platform history says so), the tool is still in `schema`.
        assert_eq!(f.phase().await, "schema");
        assert_eq!(f.history().await, ["m0001_initial_schema", "m0002_value_versions"]);

        f.exec("DROP TRIGGER inject ON credstore_value_migration").await;
        expect_exit(&f.run(&["migrate"]).await, Exit::Success);
        for row in s.active() {
            assert_activated(&f, row).await;
        }
        assert_eq!(ids(&s).len(), 6);
    }
}

docker_test! {
    async fn the_gear_cannot_migrate_over_unmigrated_values_on_postgres(f) {
        let s = f.seed_standard().await;

        let err = run_migrations_for_gear(&f.platform, CredStoreGear::MODULE_NAME, Migrator::migrations())
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("credstore-value-migration migrate"), "{text}");
        // The transaction rolled back: the shipped schema and rows are intact.
        assert_eq!(f.history().await, ["m0001_initial_schema"]);
        assert!(f.row_exists(s.shared.id).await);

        // With the tool's marker (what it records when copying is done) it passes.
        expect_exit(&f.run(&["migrate"]).await, Exit::Success);
        assert_eq!(f.history().await.len(), 2);
    }
}

docker_test! {
    async fn a_fresh_postgres_installation_passes_the_guard_without_the_tool(f) {
        run_migrations_for_gear(&f.platform, CredStoreGear::MODULE_NAME, Migrator::migrations())
            .await
            .unwrap();
        assert_eq!(f.history().await.len(), 2);
    }
}

docker_test! {
    async fn the_advisory_lock_keeps_a_second_run_out(f) {
        f.seed_standard().await;
        // The first run parks inside its first read of the old store, holding the lock.
        let gate = f.old.park_first_get();
        let first = f.run(&["migrate"]);
        let second = async {
            gate.entered.notified().await;
            let second = f.run(&["migrate"]).await;
            let cleanup = f.run(&["cleanup"]).await;
            gate.release.notify_one();
            (second, cleanup)
        };
        let (first, (second, cleanup)) = tokio::join!(first, second);

        for refused in [&second, &cleanup] {
            expect_exit(refused, Exit::Failure);
            assert!(refused.err.contains("holds the migration lock"), "{}", refused.err);
        }
        // The one that held the lock finished normally.
        expect_exit(&first, Exit::Success);
        assert_eq!(f.phase().await, "done");

        // Once it is released, the next run gets the lock.
        let after = f.run(&["migrate"]).await;
        expect_exit(&after, Exit::Success);
    }
}
