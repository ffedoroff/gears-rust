// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! `migrate` end to end over `SQLite`: the real `m0001` / `m0002` migrations applied
//! through the platform runner, a fake old store (the published V1 contract) and a
//! fake new store (V2), with failures injected at every phase boundary and in the
//! middle of every phase. No Docker.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::use_debug,
    reason = "tests"
)]

mod common;

use std::sync::atomic::Ordering;

use common::{Fixture, Row, STANDARD_ACTIVE, Standard, TYPE_B, expect_exit, rid, tenant};
use credstore::CredStoreGear;
use credstore::infra::storage::migrations::Migrator;
use credstore_sdk::{StoreKey, TenantId};
use credstore_value_migration::state::{create_tables, mark_copied, take_snapshot};
use credstore_value_migration::{Exit, MigrationError, RowState};
use toolkit_db::migration_runner::run_migrations_for_gear;
use toolkit_db::sea_orm_migration::MigratorTrait;
use uuid::Uuid;

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

fn key(row: &Row) -> StoreKey {
    StoreKey::new(TenantId(row.tenant), row.id)
}

/// The migrated row points at exactly the bytes the old store held.
async fn assert_activated(f: &Fixture, row: &Row) {
    let (status, version, fallback, row_version) = f.secret(row.id).await.unwrap();
    assert_eq!(
        (status, fallback, row_version),
        (2, 1, 2),
        "{}",
        row.reference
    );
    assert_eq!(
        f.new.bytes(&key(row), &version.unwrap()).unwrap(),
        row.value(),
        "{}",
        row.reference
    );
}

// -- the happy path -------------------------------------------------------------------

#[tokio::test]
async fn migrate_runs_every_phase_and_ends_with_the_values_in_place() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    let old_before = f.old.snapshot();

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);

    // Phases, in the order of the report.
    for phase in [
        "verify:",
        "copy:",
        "schema:",
        "activate:",
        "tidy:",
        "migrate: done",
    ] {
        assert!(run.out.contains(phase), "{phase} missing in:\n{}", run.out);
    }
    assert_eq!(f.header().await, Some(("done".to_owned(), false, false)));
    // Every active row points at the bytes of its OLD address: the private row at
    // the owner's value, the shared row at the tenant's.
    for row in s.active() {
        assert_activated(&f, row).await;
    }
    assert_ne!(s.shared.value(), s.private.value());
    // The retired statuses are gone with m0002; their progress rows say why.
    assert!(f.secret(s.provisioning.id).await.is_none());
    assert!(f.secret(s.deprovisioning.id).await.is_none());
    for (row, state) in [
        (&s.shared, "copied"),
        (&s.private, "copied"),
        (&s.seeded, "unverified_copied"),
        (&s.tenant_shared, "copied"),
        (&s.provisioning, "unfinished"),
        (&s.deprovisioning, "unfinished"),
    ] {
        let (st, version, _, _, error) = f.progress(row.id).await.unwrap();
        assert_eq!(st, state, "{}", row.reference);
        assert_eq!(
            version.is_some(),
            state.contains("copied"),
            "{}",
            row.reference
        );
        assert_eq!(error, None);
    }
    // One live version per key in the new store, the old store untouched.
    assert_eq!(f.new.live().len(), STANDARD_ACTIVE);
    assert!(f.new.live().values().all(|v| v.len() == 1));
    assert_eq!(f.old.snapshot(), old_before);
    // The platform's own history knows both migrations: the new gear starts clean.
    assert_eq!(
        f.history().await,
        ["m0001_initial_schema", "m0002_value_versions"]
    );
    // The report names counts, never values.
    assert!(run.out.contains("copied: 3") && run.out.contains("unverified_copied: 1"));
    assert!(!run.out.contains("value-of-"), "{}", run.out);
    assert!(!run.err.contains("value-of-"), "{}", run.err);
}

#[tokio::test]
async fn a_finished_migration_is_a_no_op_that_only_reports() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    let (gets, puts, destroys) = (
        f.old.gets.load(Ordering::SeqCst),
        f.new.puts.load(Ordering::SeqCst),
        f.new.destroys.load(Ordering::SeqCst),
    );

    let again = f.run(&["migrate"]).await;
    expect_exit(&again, Exit::Success);
    assert!(again.out.contains("already done"), "{}", again.out);
    assert_eq!(
        (
            f.old.gets.load(Ordering::SeqCst),
            f.new.puts.load(Ordering::SeqCst),
            f.new.destroys.load(Ordering::SeqCst)
        ),
        (gets, puts, destroys)
    );
}

#[tokio::test]
async fn the_gear_finds_its_migrations_recorded_after_the_tool() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);

    // What the platform runtime does when the new gear starts: the gear's whole list
    // (its schema migrations) through the same runner. The tool
    // applied the schema ones under the same history table, so they are skipped.
    let migrations = <CredStoreGear as toolkit::contracts::DatabaseCapability>::migrations(
        &CredStoreGear::default(),
    );
    let total = migrations.len();
    let result = run_migrations_for_gear(&f.platform, CredStoreGear::MODULE_NAME, migrations)
        .await
        .unwrap();
    assert_eq!(result.skipped, Migrator::migrations().len());
    assert!(
        !result.applied_names.iter().any(|n| n.starts_with("m000")),
        "{:?}",
        result.applied_names
    );
    assert_eq!(result.applied + result.skipped, total);
}

#[tokio::test]
async fn a_fresh_installation_has_nothing_to_migrate() {
    let f = Fixture::sqlite().await;
    // Applied by the platform at the gear's first start: no rows, no tool state.
    run_migrations_for_gear(
        &f.platform,
        CredStoreGear::MODULE_NAME,
        Migrator::migrations(),
    )
    .await
    .unwrap();

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);
    assert!(run.out.contains("nothing to do"), "{}", run.out);
    assert!(!f.table_exists("credstore_value_migration").await);
    assert_eq!(f.old.calls(), 0);
}

#[tokio::test]
async fn an_installation_without_rows_still_migrates_and_finishes() {
    let f = Fixture::sqlite().await;
    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);
    assert_eq!(f.phase().await, "done");
    assert_eq!(f.history().await.len(), 2);
}

#[tokio::test]
async fn retries_ride_out_a_transient_failure_of_either_store() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    // Two failures in a row are within the three attempts of the test tuning.
    f.old.transient_gets.store(2, Ordering::SeqCst);

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);
    for row in s.active() {
        assert_activated(&f, row).await;
    }
}

// -- the verification and its decisions -----------------------------------------------

#[tokio::test]
async fn losses_need_a_decision_and_change_nothing_until_accepted() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    // A value gone from the old store, a value that fails its fingerprint, and a
    // fingerprint of another fence key.
    let missing = Row::valued(10, tenant(5), "gone");
    f.insert(&missing).await;
    let mismatch = Row::valued(11, tenant(5), "tampered");
    f.seed(&mismatch, b"tampered-value").await;
    let mut other_key = Row::valued(12, tenant(5), "other-key");
    other_key.fp_key_id = Some(2);
    f.seed(&other_key, &other_key.value()).await;

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Decision);
    for (title, row) in [
        ("MISSING", &missing),
        ("FP_MISMATCH", &mismatch),
        ("UNKNOWN_FENCE_KEY", &other_key),
    ] {
        assert!(
            run.out.contains(&format!("{title} (")),
            "{title}:\n{}",
            run.out
        );
        assert!(
            run.out.contains(&format!(
                "id={} tenant={} reference={}",
                row.id, row.tenant, row.reference
            )),
            "{}",
            run.out
        );
    }
    assert!(run.out.contains("--accept-losses"));
    assert!(!run.out.contains("tampered-value"), "{}", run.out);
    // Nothing was written: no copy, no schema change, header still verifying.
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);
    assert_eq!(f.phase().await, "verifying");
    assert_eq!(f.history().await, ["m0001_initial_schema"]);

    // The decision, once given, is persisted and the run completes.
    let accepted = f.run(&["migrate", "--accept-losses"]).await;
    expect_exit(&accepted, Exit::Success);
    assert_eq!(f.header().await, Some(("done".to_owned(), true, false)));
    for row in s.active() {
        assert_activated(&f, row).await;
    }
    // The lost rows stay declared and are suppressed (`fallback = none`), so the
    // reference cannot fall through to an ancestor's value.
    for row in [&missing, &mismatch, &other_key] {
        assert_eq!(
            f.secret(row.id)
                .await
                .map(|(status, version, fallback, _)| (status, version, fallback)),
            Some((4, None, 2)),
            "{}",
            row.reference
        );
    }
    for (row, state) in [
        (&missing, "missing"),
        (&mismatch, "fp_mismatch"),
        (&other_key, "unknown_fence_key"),
    ] {
        assert_eq!(f.progress(row.id).await.unwrap().0, state);
    }
    // Their old entries are untouched.
    assert!(f.old.has(mismatch.tenant, &mismatch.reference, None));
}

#[tokio::test]
async fn the_decision_survives_a_later_failure() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.insert(&Row::valued(10, tenant(5), "gone")).await;
    f.new.fail_put_from(Some(1));

    // Accepted, then the new store fails mid-copy.
    expect_exit(&f.run(&["migrate", "--accept-losses"]).await, Exit::Failure);
    f.new.fail_put_from(None);

    // The flag is not repeated: the persisted decision stands.
    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);
    assert_eq!(f.header().await, Some(("done".to_owned(), true, false)));
}

#[tokio::test]
async fn an_absent_fence_key_with_fingerprinted_rows_aborts() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.old.remove(Uuid::nil(), "cfs-internal-fence-key", None);

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("fence key"), "{}", run.err);
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);
    assert_eq!(f.phase().await, "verifying");
}

#[tokio::test]
async fn an_absent_fence_key_is_fine_when_no_row_has_a_fingerprint() {
    let f = Fixture::sqlite().await;
    let row = Row::valued(1, tenant(1), "k").without_fp();
    f.seed(&row, &row.value()).await;
    f.old.remove(Uuid::nil(), "cfs-internal-fence-key", None);

    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    assert_activated(&f, &row).await;
    assert_eq!(f.progress(row.id).await.unwrap().0, "unverified_copied");
}

#[tokio::test]
async fn a_reference_the_old_store_could_not_have_held_aborts() {
    let f = Fixture::sqlite().await;
    let row = Row::valued(1, tenant(1), "has.a.dot");
    f.insert(&row).await;

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains(&row.id.to_string()), "{}", run.err);
}

#[tokio::test]
async fn verification_reports_type_divergent_pairs() {
    let f = Fixture::sqlite().await;
    let shared = Row::valued(1, tenant(1), "k");
    let mut private = Row::valued(2, tenant(1), "k").private(Uuid::from_u128(0x77));
    private.ty = TYPE_B;
    let same = Row::valued(3, tenant(2), "same");
    let same_private = Row::valued(4, tenant(2), "same").private(Uuid::from_u128(0x78));
    for row in [&shared, &private, &same, &same_private] {
        f.seed(row, &row.value()).await;
    }

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);
    assert!(run.out.contains("type-divergent pairs: 1"), "{}", run.out);
    assert!(
        run.out.contains(&format!("private={}", private.id))
            && run.out.contains(&format!("non-private={}", shared.id)),
        "{}",
        run.out
    );
}

// -- failures of the stores ------------------------------------------------------------

#[tokio::test]
async fn a_read_back_of_other_bytes_aborts_and_leaves_the_row_pending() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    f.new.corrupt.store(true, Ordering::SeqCst);

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("different bytes"), "{}", run.err);
    assert_eq!(f.phase().await, "copying");
    let first = ids(&s).into_iter().min().unwrap();
    let (state, version, _, _, error) = f.progress(first).await.unwrap();
    assert_eq!((state.as_str(), version), ("pending", None));
    assert!(error.unwrap().contains("different bytes"));
}

#[tokio::test]
async fn a_version_the_store_cannot_read_back_aborts_after_the_retries() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.new.none_gets_left.store(100, Ordering::SeqCst);

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(
        run.err.contains("no value at the returned version"),
        "{}",
        run.err
    );
    // The three attempts of the test tuning, for the one row it stopped at.
    assert_eq!(f.new.gets.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_persistently_failing_old_store_aborts_the_verification_without_marking_anything() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.old.fail_get_from(Some(0));

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("old store"), "{}", run.err);
    // The three attempts, then the abort: no row marked, nothing written.
    assert_eq!(f.old.gets.load(Ordering::SeqCst), 3);
    assert_eq!(f.phase().await, "verifying");
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_store_without_destroy_skips_the_tidy_phase() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    f.new.destroy_supported.store(false, Ordering::SeqCst);

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Success);
    assert!(run.out.contains("tidy: skipped"), "{}", run.out);
    assert_eq!(f.new.destroys.load(Ordering::SeqCst), 0);
    for row in s.active() {
        assert_activated(&f, row).await;
    }
}

// -- discarding values ------------------------------------------------------------------

#[tokio::test]
async fn discard_values_touches_neither_store_and_leaves_the_rows_declared() {
    let f = Fixture::sqlite().await;
    // The in-memory plugin's installation: rows, no values, no fence key.
    f.old.remove(Uuid::nil(), "cfs-internal-fence-key", None);
    let rows = [
        Row::valued(1, tenant(1), "a"),
        Row::valued(2, tenant(1), "a").private(Uuid::from_u128(0x77)),
        Row::valued(3, tenant(2), "b").with_status(1),
    ];
    for row in &rows {
        f.insert(row).await;
    }

    let run = f.run(&["migrate", "--discard-values"]).await;
    expect_exit(&run, Exit::Success);
    assert_eq!(f.old.calls(), 0);
    assert_eq!(
        f.new.puts.load(Ordering::SeqCst) + f.new.gets.load(Ordering::SeqCst),
        0
    );
    assert_eq!(f.header().await, Some(("done".to_owned(), false, true)));
    // `declared` with the default fallback, as m0002 leaves them.
    for row in &rows[..2] {
        assert_eq!(
            f.secret(row.id)
                .await
                .map(|(status, version, fallback, _)| (status, version, fallback)),
            Some((4, None, 1))
        );
        assert_eq!(f.progress(row.id).await.unwrap().0, "discarded");
    }
    assert!(f.secret(rows[2].id).await.is_none());
    assert_eq!(f.progress(rows[2].id).await.unwrap().0, "unfinished");
    assert_eq!(f.history().await.len(), 2);
}

#[tokio::test]
async fn discard_values_cannot_be_chosen_after_values_were_copied() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.new.fail_put_from(Some(1));
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    assert_eq!(f.phase().await, "copying");
    f.new.fail_put_from(None);

    let run = f.run(&["migrate", "--discard-values"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("--discard-values"), "{}", run.err);
    // The honest run still completes.
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
}

// -- the guard in m0002 -----------------------------------------------------------------

#[tokio::test]
async fn the_gear_cannot_migrate_the_schema_over_unmigrated_values_without_the_tool() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;

    // The platform starting the new gear over the shipped database.
    let err = run_migrations_for_gear(
        &f.platform,
        CredStoreGear::MODULE_NAME,
        Migrator::migrations(),
    )
    .await
    .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("credstore-value-migration migrate") && text.contains("--discard-values"),
        "{text}"
    );
    // Nothing changed.
    assert_eq!(f.history().await, ["m0001_initial_schema"]);
    assert!(f.row_exists(rid(1)).await);

    // The tool then does the job.
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
}

// -- the persisted snapshot -------------------------------------------------------------

#[tokio::test]
async fn while_verifying_the_snapshot_is_taken_again_on_every_run() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.insert(&Row::valued(10, tenant(5), "gone")).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Decision);

    // The operator looks: the old credstore ran again and a row changed.
    f.exec("DELETE FROM credstore_secrets WHERE reference = 'gone'")
        .await;
    let late = Row::valued(11, tenant(6), "late");
    f.seed(&late, &late.value()).await;

    // Without the lost row there is nothing to decide, and the late row is migrated.
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    assert_activated(&f, &late).await;
}

#[tokio::test]
async fn a_row_that_appears_after_copying_started_stops_before_the_schema_change() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    // Stop right before the phase moves on to the schema.
    create_tables(&f.db, f.backend()).await.unwrap();
    f.exec(
        "CREATE TRIGGER inject BEFORE UPDATE OF phase ON credstore_value_migration \
         WHEN NEW.phase = 'schema' BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    assert_eq!(f.phase().await, "copying");
    f.exec("DROP TRIGGER inject").await;

    // The old credstore ran in between.
    let late = Row::valued(11, tenant(6), "late");
    f.seed(&late, &late.value()).await;

    let run = f.run(&["migrate"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("snapshot"), "{}", run.err);
    // m0002 is irreversible; it must not have run.
    assert_eq!(f.history().await, ["m0001_initial_schema"]);
    assert!(f.row_exists(late.id).await);
}

#[tokio::test]
async fn rows_changed_or_deleted_after_the_schema_change_are_superseded_not_overwritten() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    // Stop after m0002, before the rows are activated.
    create_tables(&f.db, f.backend()).await.unwrap();
    f.exec(
        "CREATE TRIGGER inject BEFORE UPDATE OF phase ON credstore_value_migration \
         WHEN NEW.phase = 'activating' BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    assert_eq!(f.phase().await, "schema");
    f.exec("DROP TRIGGER inject").await;

    // Someone (the gear, an operator) rewrote one row and deleted another.
    f.exec(&format!(
        "UPDATE credstore_secrets SET status = 2, value_version = 'other', version = version + 1 \
         WHERE id = {}",
        blob(s.shared.id)
    ))
    .await;
    f.exec(&format!(
        "DELETE FROM credstore_secrets WHERE id = {}",
        blob(s.private.id)
    ))
    .await;

    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    // The rewritten row keeps what it has; its copy is superseded.
    let (status, version, _, _) = f.secret(s.shared.id).await.unwrap();
    assert_eq!((status, version.as_deref()), (2, Some("other")));
    assert_eq!(f.progress(s.shared.id).await.unwrap().0, "superseded");
    assert!(f.secret(s.private.id).await.is_none());
    assert_eq!(f.progress(s.private.id).await.unwrap().0, "superseded");
    // The others are activated as usual.
    assert_activated(&f, &s.seeded).await;
    assert_activated(&f, &s.tenant_shared).await;
}

fn blob(id: Uuid) -> String {
    format!("x'{}'", id.simple())
}

// -- usage ------------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_database_url_is_an_error() {
    let f = Fixture::sqlite().await;
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = credstore_value_migration::run_with(
        ["credstore-value-migration", "migrate"],
        &f.old,
        &f.new,
        &credstore_value_migration::Tuning::immediate(),
        &mut out,
        &mut err,
    )
    .await;
    assert_eq!(exit, Exit::Failure);
    assert!(String::from_utf8(err).unwrap().contains("--database-url"));
}

// -- a loss that appears after the verification ----------------------------------------------

#[tokio::test]
async fn migrate_new_loss_between_verify_and_copy_asks_for_decision() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    // The verification passes and the header moves on to `copying`, but the old store
    // is unreachable when the copy starts: nothing has been decided per row yet.
    inject(&f, Fault::CopyStart).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    assert_eq!(f.phase().await, "copying");
    heal(&f, Fault::CopyStart).await;
    // Meanwhile one value disappears from the old store: the second row in id order,
    // so one row is copied before the loss and two are left after it.
    let lost = &s.private;
    f.old.remove(lost.tenant, &lost.reference, lost.old_owner());
    let old_before = f.old.snapshot();
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);

    let run = f.run(&["migrate"]).await;

    // The outcome and what it reports.
    expect_exit(&run, Exit::Decision);
    let report = format!(
        "NEW LOSS since the verification: id={} tenant={} reference={} outcome=missing",
        lost.id, lost.tenant, lost.reference
    );
    assert!(
        run.out.contains(&report),
        "{report} missing in:\n{}",
        run.out
    );
    assert!(run.out.contains("--accept-losses"), "{}", run.out);
    assert!(!run.out.contains("migrate: done"), "{}", run.out);
    // Persisted: the phase did not move and the decision was not taken for the operator.
    assert_eq!(f.header().await, Some(("copying".to_owned(), false, false)));
    // Per row: the one before the loss is copied; the lost one and the rest are still
    // `pending` with nothing in the new store; the unfinished ones are untouched.
    let expected = vec![
        (&s.shared, "copied"),
        (&s.private, "pending"),
        (&s.seeded, "pending"),
        (&s.tenant_shared, "pending"),
        (&s.provisioning, "unfinished"),
        (&s.deprovisioning, "unfinished"),
    ];
    for (row, state) in expected {
        let (st, version, activated, tidied, error) = f.progress(row.id).await.unwrap();
        let copied = state == "copied";
        assert_eq!(st, state, "{}", row.reference);
        assert_eq!(version.is_some(), copied, "{}", row.reference);
        assert_eq!(
            (activated, tidied, error),
            (false, false, None),
            "{}",
            row.reference
        );
        assert_eq!(
            f.new.version_count(&key(row)),
            usize::from(copied),
            "{}",
            row.reference
        );
    }
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 1);
    assert_eq!(f.new.live().len(), 1);
    // The old store and the gear's schema are as they were.
    assert_eq!(f.old.snapshot(), old_before);
    assert_eq!(f.old.deletes.load(Ordering::SeqCst), 0);
    assert_eq!(f.history().await, ["m0001_initial_schema"]);
}

// -- a header that contradicts the schema ----------------------------------------------------

#[tokio::test]
async fn migrate_phase_contradicting_schema_refuses_with_restore_hint() {
    const SHIPPED: &str = "shipped (m0001 only)";
    const MIGRATED: &str = "migrated (m0002 applied)";
    // (the phase set by hand, whether the schema is migrated, the schema it names)
    let cases: Vec<(&str, bool, &str)> = vec![
        ("activating", false, SHIPPED),
        ("tidying", false, SHIPPED),
        ("verifying", true, MIGRATED),
        ("copying", true, MIGRATED),
    ];
    for (phase, migrated, schema) in cases {
        let f = Fixture::sqlite().await;
        f.seed_standard().await;
        if migrated {
            expect_exit(&f.run(&["migrate"]).await, Exit::Success);
        } else {
            // Stop in `copying` with the shipped schema.
            inject(&f, Fault::Boundary("schema")).await;
            expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
            heal(&f, Fault::Boundary("schema")).await;
        }
        f.exec(&format!(
            "UPDATE credstore_value_migration SET phase = '{phase}'"
        ))
        .await;
        let before = f.tables_digest().await;
        let history = f.history().await;
        let (gets, puts, destroys) = (
            f.old.gets.load(Ordering::SeqCst),
            f.new.puts.load(Ordering::SeqCst),
            f.new.destroys.load(Ordering::SeqCst),
        );

        let run = f.run(&["migrate"]).await;

        expect_exit(&run, Exit::Failure);
        let says = format!(
            "the progress table says phase {phase}, but credstore_secrets has the {schema} schema"
        );
        assert!(run.err.contains(&says), "{phase}/{schema}: {}", run.err);
        assert!(
            run.err
                .contains("restore the database snapshot taken before the migration"),
            "{phase}/{schema}: {}",
            run.err
        );
        // No row, no store, no history entry was touched.
        assert_eq!(f.tables_digest().await, before, "{phase}/{schema}");
        assert_eq!(f.history().await, history, "{phase}/{schema}");
        assert_eq!(
            (
                f.old.gets.load(Ordering::SeqCst),
                f.new.puts.load(Ordering::SeqCst),
                f.new.destroys.load(Ordering::SeqCst)
            ),
            (gets, puts, destroys),
            "{phase}/{schema}"
        );
    }
}

#[tokio::test]
async fn migrate_half_applied_schema_is_refused() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    // `m0002` died half way: the new column is there, the old one is not gone.
    f.exec("ALTER TABLE credstore_secrets ADD COLUMN value_version TEXT")
        .await;
    let before = f.tables_digest().await;

    let run = f.run(&["migrate"]).await;

    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("wrong schema state"), "{}", run.err);
    assert!(
        run.err
            .contains("has both value_fp and value_version: m0002 did not complete"),
        "{}",
        run.err
    );
    // Nothing was started: no tool table, no store call, no row changed.
    assert!(!f.table_exists("credstore_value_migration").await);
    assert!(!f.table_exists("credstore_value_migration_rows").await);
    assert_eq!(f.tables_digest().await, before);
    assert_eq!(f.history().await, ["m0001_initial_schema"]);
    assert_eq!(f.old.calls(), 0);
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn migrate_missing_secrets_table_is_refused() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.exec("DROP TABLE credstore_secrets").await;
    let before = f.tables_digest().await;

    let run = f.run(&["migrate"]).await;

    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("wrong schema state"), "{}", run.err);
    assert!(
        run.err
            .contains("credstore_secrets is missing or has neither value_fp nor value_version"),
        "{}",
        run.err
    );
    // Nothing was started, and nothing was created in place of the table.
    assert!(!f.table_exists("credstore_secrets").await);
    assert!(!f.table_exists("credstore_value_migration").await);
    assert!(!f.table_exists("credstore_value_migration_rows").await);
    assert_eq!(f.tables_digest().await, before);
    assert_eq!(f.history().await, ["m0001_initial_schema"]);
    assert_eq!(f.old.calls(), 0);
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);
}

// -- two runs on one database ------------------------------------------------------------------

#[tokio::test]
async fn migrate_phase_cas_rejects_a_concurrent_run() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    // The first run parks inside its first read of the old store, in the verification;
    // another run moves the header on in the meantime.
    let gate = f.old.park_first_get();
    let first = f.run(&["migrate"]);
    let other = async {
        gate.entered.notified().await;
        f.exec("UPDATE credstore_value_migration SET phase = 'copying'")
            .await;
        gate.release.notify_one();
    };
    let (run, ()) = tokio::join!(first, other);

    // The first run's own move out of `verifying` finds another phase and stops.
    expect_exit(&run, Exit::Failure);
    assert!(
        run.err.contains("inconsistent migration state"),
        "{}",
        run.err
    );
    assert!(
        run.err
            .contains("not in phase verifying when moving to copying: another run changed it"),
        "{}",
        run.err
    );
    // The header is what the other run left; the first run did not touch it or go on.
    assert_eq!(f.header().await, Some(("copying".to_owned(), false, false)));
    assert!(!run.out.contains("phase verifying finished"), "{}", run.out);
    assert_eq!(f.new.puts.load(Ordering::SeqCst), 0);
    for row in s.active() {
        assert_eq!(
            f.progress(row.id).await,
            Some(("pending".to_owned(), None, false, false, None)),
            "{}",
            row.reference
        );
    }
    assert_eq!(f.history().await, ["m0001_initial_schema"]);
}

#[tokio::test]
async fn state_mark_copied_twice_is_an_error() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    take_snapshot(&f.db, f.backend(), false, false)
        .await
        .unwrap();
    let row = &s.shared;

    let first = mark_copied(&f.db, f.backend(), row.id, RowState::Copied, "1").await;
    assert!(first.is_ok(), "the first mark must succeed: {first:?}");
    let second = mark_copied(&f.db, f.backend(), row.id, RowState::UnverifiedCopied, "2").await;

    let err = second.unwrap_err();
    assert!(
        matches!(err, MigrationError::State(_)),
        "expected State, got: {err:?}"
    );
    assert!(
        err.to_string().contains(&format!(
            "progress row {} was not in the expected state",
            row.id
        )),
        "{err}"
    );
    // The row keeps what the first call recorded; the other rows are still pending.
    assert_eq!(
        f.progress(row.id).await,
        Some((
            "copied".to_owned(),
            Some("1".to_owned()),
            false,
            false,
            None
        ))
    );
    for other in [&s.private, &s.seeded, &s.tenant_shared] {
        assert_eq!(
            f.progress(other.id).await,
            Some(("pending".to_owned(), None, false, false, None)),
            "{}",
            other.reference
        );
    }
}

// -- resuming after a failure anywhere --------------------------------------------------

/// A failure to inject: at every phase boundary, and mid-phase for every phase.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// The snapshot cannot be written.
    Snapshot,
    /// The old store keeps failing during the verification.
    VerifyOldStore,
    /// The header cannot move on to the next phase (`verifying -> copying`, ...).
    Boundary(&'static str),
    /// The old store keeps failing during the copy.
    CopyOldStore,
    /// The old store is unreachable when the copy starts (its first read, the
    /// fence key): the verification passed and the header is `copying`, but no row
    /// has been touched.
    CopyStart,
    /// The new store refuses a `put` mid-copy.
    CopyPut,
    /// The `put` and the read-back succeeded, recording the version failed: the
    /// process died between the two.
    CrashAfterPutBeforeRecord,
    /// The new store does not return a version it just stored.
    CopyReadBackNone,
    /// The read-back call fails.
    CopyReadBackError,
    /// `m0002` fails.
    SchemaFails,
    /// The activation of one row fails mid-phase (its transaction rolls back).
    ActivateMid,
    /// The new store fails `destroy` mid-tidy.
    TidyMid,
}

async fn inject(f: &Fixture, fault: Fault) {
    create_tables(&f.db, f.backend()).await.unwrap();
    let trigger = |sql: &str| {
        format!("CREATE TRIGGER inject {sql} BEGIN SELECT RAISE(ABORT, 'injected'); END")
    };
    match fault {
        Fault::Snapshot => {
            f.exec(&trigger("BEFORE INSERT ON credstore_value_migration_rows"))
                .await;
        }
        Fault::VerifyOldStore => f.old.fail_get_from(Some(3)),
        Fault::Boundary(to) => {
            f.exec(&trigger(&format!(
                "BEFORE UPDATE OF phase ON credstore_value_migration WHEN NEW.phase = '{to}'"
            )))
            .await;
        }
        // Verify reads the fence key and every active row (5 calls); the copy reads
        // the fence key and rows again: fail from the third row of the copy on.
        Fault::CopyOldStore => f.old.fail_get_from(Some(1 + STANDARD_ACTIVE + 1 + 2)),
        // Verify reads the fence key and every active row: the copy's first read is next.
        Fault::CopyStart => f.old.fail_get_from(Some(1 + STANDARD_ACTIVE)),
        Fault::CopyPut => f.new.fail_put_from(Some(2)),
        Fault::CrashAfterPutBeforeRecord => {
            f.exec(&trigger(
                "BEFORE UPDATE OF state ON credstore_value_migration_rows \
                 WHEN NEW.state = 'copied' AND NEW.reference = 'shared-by-3'",
            ))
            .await;
        }
        Fault::CopyReadBackNone => f.new.none_gets_left.store(1000, Ordering::SeqCst),
        Fault::CopyReadBackError => f.new.fail_get_from(Some(1)),
        Fault::SchemaFails => {
            f.exec("CREATE TABLE credstore_secrets_new (x INTEGER)")
                .await;
        }
        Fault::ActivateMid => {
            f.exec(&trigger(
                "BEFORE UPDATE OF activated ON credstore_value_migration_rows \
                 WHEN NEW.activated = 1 AND NEW.reference = 'shared-by-3'",
            ))
            .await;
        }
        Fault::TidyMid => f.new.fail_destroy_from(Some(1)),
    }
}

async fn heal(f: &Fixture, fault: Fault) {
    match fault {
        Fault::Snapshot
        | Fault::Boundary(_)
        | Fault::CrashAfterPutBeforeRecord
        | Fault::ActivateMid => {
            f.exec("DROP TRIGGER inject").await;
        }
        Fault::VerifyOldStore | Fault::CopyOldStore | Fault::CopyStart => {
            f.old.fail_get_from(None);
        }
        Fault::CopyPut => f.new.fail_put_from(None),
        Fault::CopyReadBackNone => f.new.none_gets_left.store(0, Ordering::SeqCst),
        Fault::CopyReadBackError => f.new.fail_get_from(None),
        Fault::SchemaFails => f.exec("DROP TABLE credstore_secrets_new").await,
        Fault::TidyMid => f.new.fail_destroy_from(None),
    }
}

/// The end state of an undisturbed migration of the standard dataset.
async fn reference_end_state() -> common::EndState {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    f.end_state(&ids(&s)).await
}

/// Interrupts the migration with `fault`, checks where it stopped, heals the fault
/// and runs the same command again: it completes, and the end state is that of an
/// undisturbed run.
async fn resumes_after(fault: Fault, stopped_in: Option<&str>) {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    inject(&f, fault).await;

    let first = f.run(&["migrate"]).await;
    expect_exit(&first, Exit::Failure);
    assert!(first.err.contains("ABORTED"), "{fault:?}: {}", first.err);
    match stopped_in {
        Some(phase) => assert_eq!(f.phase().await, phase, "{fault:?}"),
        None => assert_eq!(f.header().await, None, "{fault:?}"),
    }

    heal(&f, fault).await;
    let second = f.run(&["migrate"]).await;
    expect_exit(&second, Exit::Success);
    assert_eq!(
        f.end_state(&ids(&s)).await,
        reference_end_state().await,
        "{fault:?}: the resumed run must end exactly where an undisturbed one does"
    );
}

macro_rules! resume_tests {
    ($($name:ident: $fault:expr => $phase:expr;)+) => {
        $(
            #[tokio::test]
            async fn $name() {
                resumes_after($fault, $phase).await;
            }
        )+
    };
}

resume_tests! {
    resumes_after_the_snapshot_failed: Fault::Snapshot => None;
    resumes_after_the_old_store_failed_during_verification: Fault::VerifyOldStore => Some("verifying");
    resumes_after_failing_to_leave_verifying: Fault::Boundary("copying") => Some("verifying");
    resumes_after_the_old_store_failed_during_the_copy: Fault::CopyOldStore => Some("copying");
    resumes_after_the_new_store_refused_a_put: Fault::CopyPut => Some("copying");
    resumes_after_a_crash_between_put_and_record: Fault::CrashAfterPutBeforeRecord => Some("copying");
    resumes_after_the_new_store_lost_a_version: Fault::CopyReadBackNone => Some("copying");
    resumes_after_the_read_back_failed: Fault::CopyReadBackError => Some("copying");
    resumes_after_failing_to_leave_copying: Fault::Boundary("schema") => Some("copying");
    resumes_after_m0002_failed: Fault::SchemaFails => Some("schema");
    resumes_after_failing_to_leave_schema_with_m0002_applied: Fault::Boundary("activating") => Some("schema");
    resumes_after_a_crash_in_the_middle_of_activating: Fault::ActivateMid => Some("activating");
    resumes_after_failing_to_leave_activating: Fault::Boundary("tidying") => Some("activating");
    resumes_after_a_crash_in_the_middle_of_tidying: Fault::TidyMid => Some("tidying");
    resumes_after_failing_to_leave_tidying: Fault::Boundary("done") => Some("tidying");
}

#[tokio::test]
async fn a_crash_between_put_and_record_leaves_a_version_that_tidying_destroys() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    inject(&f, Fault::CrashAfterPutBeforeRecord).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    // The put happened, nobody points at it.
    assert_eq!(f.new.version_count(&key(&s.tenant_shared)), 1);
    assert_eq!(f.progress(s.tenant_shared.id).await.unwrap().0, "pending");

    heal(&f, Fault::CrashAfterPutBeforeRecord).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    // The second put got version 2; version 1 was destroyed.
    assert_eq!(f.new.version_count(&key(&s.tenant_shared)), 1);
    let (_, version, _, _) = f.secret(s.tenant_shared.id).await.unwrap();
    assert_eq!(version.as_deref(), Some("2"));
}

#[tokio::test]
async fn a_crash_in_the_middle_of_activating_rolls_the_row_back_with_its_progress() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    inject(&f, Fault::ActivateMid).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);

    // The failing row: neither pointed nor marked (one transaction).
    let (status, version, _, _) = f.secret(s.tenant_shared.id).await.unwrap();
    assert_eq!((status, version), (4, None));
    let (state, _, activated, _, error) = f.progress(s.tenant_shared.id).await.unwrap();
    assert_eq!((state.as_str(), activated), ("copied", false));
    assert!(error.unwrap().contains("injected"));
    // A row before it in id order was completed, and stays so.
    assert_activated(&f, &s.shared).await;
    assert!(f.progress(s.shared.id).await.unwrap().2);
    let _ = rid(0);
}
