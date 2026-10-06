// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! `cleanup` over `SQLite`: driven by the progress table, resumable, evidence kept,
//! the UUID guard, the fence key last. No Docker.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::use_debug,
    reason = "tests"
)]

mod common;

use common::{Fixture, Row, Standard, expect_exit, tenant};
use credstore_value_migration::Exit;
use credstore_value_migration::state::take_snapshot;
use uuid::Uuid;

const FENCE: &str = "cfs-internal-fence-key";

/// Rows that end up without a value, next to the standard dataset.
struct Lost {
    missing: Row,
    mismatch: Row,
    other_key: Row,
}

/// The standard dataset plus one lost row of every kind, migrated.
async fn migrated_with_losses() -> (Fixture, Standard, Lost) {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    let missing = Row::valued(10, tenant(5), "gone");
    f.insert(&missing).await;
    let mismatch = Row::valued(11, tenant(5), "tampered");
    f.seed(&mismatch, b"tampered-value").await;
    let mut other_key = Row::valued(12, tenant(5), "other-key");
    other_key.fp_key_id = Some(2);
    f.seed(&other_key, &other_key.value()).await;
    expect_exit(&f.run(&["migrate", "--accept-losses"]).await, Exit::Success);
    (
        f,
        s,
        Lost {
            missing,
            mismatch,
            other_key,
        },
    )
}

fn all_ids(s: &Standard, l: &Lost) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = [
        &s.shared,
        &s.private,
        &s.seeded,
        &s.tenant_shared,
        &s.provisioning,
        &s.deprovisioning,
        &l.missing,
        &l.mismatch,
        &l.other_key,
    ]
    .iter()
    .map(|r| r.id)
    .collect();
    ids.sort();
    ids
}

fn has_old(f: &Fixture, row: &Row) -> bool {
    f.old.has(row.tenant, &row.reference, row.old_owner())
}

#[tokio::test]
async fn cleanup_deletes_the_superseded_entries_keeps_evidence_and_the_fence_key() {
    let (f, s, l) = migrated_with_losses().await;
    let live_before = f.new.live();

    let run = f.run(&["cleanup"]).await;
    expect_exit(&run, Exit::Success);

    // Deleted by their recorded old addresses, the private one by its owner.
    for row in s.active() {
        assert!(!has_old(&f, row), "{}", row.reference);
    }
    for row in [&s.provisioning, &s.deprovisioning] {
        assert!(!has_old(&f, row), "{}", row.reference);
    }
    // Kept: the evidence, and the fence key (no flag).
    assert!(has_old(&f, &l.mismatch));
    assert!(has_old(&f, &l.other_key));
    assert!(f.old.has(Uuid::nil(), FENCE, None));
    assert!(run.out.contains("kept as evidence"), "{}", run.out);
    assert!(run.out.contains(&l.mismatch.id.to_string()), "{}", run.out);

    // The progress table keeps exactly the evidence; the rest is resolved.
    for row in s.active() {
        assert!(f.progress(row.id).await.is_none(), "{}", row.reference);
    }
    assert!(f.progress(l.missing.id).await.is_none());
    assert_eq!(f.progress(l.mismatch.id).await.unwrap().0, "fp_mismatch");
    assert_eq!(
        f.progress(l.other_key.id).await.unwrap().0,
        "unknown_fence_key"
    );
    assert_eq!(f.phase().await, "done");

    // Neither the new store nor the gear table is touched.
    assert_eq!(f.new.live(), live_before);
    assert_eq!(f.secret(s.shared.id).await.unwrap().0, 2);

    // Running it again is safe and changes nothing.
    let old_after = f.old.snapshot();
    expect_exit(&f.run(&["cleanup"]).await, Exit::Success);
    assert_eq!(f.old.snapshot(), old_after);
}

#[tokio::test]
async fn a_dry_run_changes_nothing() {
    let (f, s, l) = migrated_with_losses().await;
    let old_before = f.old.snapshot();
    let deletes = f.old.deletes.load(std::sync::atomic::Ordering::SeqCst);

    let run = f
        .run(&[
            "cleanup",
            "--dry-run",
            "--include-fence-key",
            "--drop-state",
        ])
        .await;
    // Evidence rows block dropping the state: the decision is reported even in a dry run.
    expect_exit(&run, Exit::Decision);
    assert!(run.out.contains("DRY RUN"), "{}", run.out);
    assert!(
        run.out.contains("old entries deleted (would be): 6"),
        "{}",
        run.out
    );
    assert_eq!(f.old.snapshot(), old_before);
    assert_eq!(
        f.old.deletes.load(std::sync::atomic::Ordering::SeqCst),
        deletes
    );
    for row in all_ids(&s, &l) {
        assert!(f.progress(row).await.is_some());
    }
}

#[tokio::test]
async fn the_fence_key_goes_last_and_only_with_the_flag() {
    let (f, _s, l) = migrated_with_losses().await;
    // The old store fails after two deletes: the fence key must not have been touched.
    f.old.fail_delete_from(Some(
        f.old.deletes.load(std::sync::atomic::Ordering::SeqCst) + 2,
    ));
    let run = f.run(&["cleanup", "--include-fence-key"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(f.old.has(Uuid::nil(), FENCE, None));

    // Healed, the same command finishes: the fence key last, the evidence kept.
    f.old.fail_delete_from(None);
    expect_exit(
        &f.run(&["cleanup", "--include-fence-key"]).await,
        Exit::Success,
    );
    assert!(!f.old.has(Uuid::nil(), FENCE, None));
    assert!(has_old(&f, &l.mismatch));
    assert!(has_old(&f, &l.other_key));
}

#[tokio::test]
async fn cleanup_resumes_after_a_failed_delete_and_ends_where_an_undisturbed_run_does() {
    async fn end(f: &Fixture, s: &Standard, l: &Lost) -> common::EndState {
        f.end_state(&all_ids(s, l)).await
    }
    let (clean, cs, cl) = migrated_with_losses().await;
    expect_exit(&clean.run(&["cleanup"]).await, Exit::Success);
    let expected = end(&clean, &cs, &cl).await;

    let (f, s, l) = migrated_with_losses().await;
    f.old.fail_delete_from(Some(
        f.old.deletes.load(std::sync::atomic::Ordering::SeqCst) + 3,
    ));
    let first = f.run(&["cleanup"]).await;
    expect_exit(&first, Exit::Failure);
    // Some rows are resolved, the others are still in the table.
    let left = {
        let mut n = 0;
        for id in all_ids(&s, &l) {
            if f.progress(id).await.is_some() {
                n += 1;
            }
        }
        n
    };
    assert!(
        left > 2,
        "the failed run resolved only part of the rows ({left} left)"
    );

    f.old.fail_delete_from(None);
    expect_exit(&f.run(&["cleanup"]).await, Exit::Success);
    assert_eq!(end(&f, &s, &l).await, expected);
}

#[tokio::test]
async fn drop_state_with_evidence_left_asks_for_a_decision_and_keeps_the_tables() {
    let (f, _s, l) = migrated_with_losses().await;

    let run = f.run(&["cleanup", "--drop-state"]).await;
    expect_exit(&run, Exit::Decision);
    assert!(run.out.contains("NOT dropped"), "{}", run.out);
    assert!(f.table_exists("credstore_value_migration").await);
    assert!(f.table_exists("credstore_value_migration_rows").await);
    assert!(f.progress(l.mismatch.id).await.is_some());
}

#[tokio::test]
async fn drop_state_without_evidence_removes_the_progress_tables() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);

    expect_exit(
        &f.run(&["cleanup", "--include-fence-key", "--drop-state"])
            .await,
        Exit::Success,
    );
    assert!(!f.table_exists("credstore_value_migration").await);
    assert!(!f.table_exists("credstore_value_migration_rows").await);
    assert!(f.old.snapshot().is_empty(), "{:?}", f.old.snapshot().keys());
    // The gear's own table is untouched.
    assert_eq!(f.secret(s.shared.id).await.unwrap().0, 2);

    // Nothing is left to do, and it says so.
    let again = f.run(&["cleanup"]).await;
    expect_exit(&again, Exit::Success);
    assert!(again.out.contains("nothing to do"), "{}", again.out);
}

#[tokio::test]
async fn a_reference_shaped_like_a_new_key_stops_cleanup_before_it_deletes_anything() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    // An old reference that is a UUID equal to the id of a credential record: on a
    // shared mount that address IS the new key of that record.
    let shaped = Row::valued(7, tenant(1), &s.shared.id.to_string());
    f.seed(&shaped, &shaped.value()).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    let old_before = f.old.snapshot();

    let run = f.run(&["cleanup"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("look like new store keys"), "{}", run.err);
    assert!(run.err.contains(&s.shared.id.to_string()), "{}", run.err);
    assert_eq!(
        f.old.snapshot(),
        old_before,
        "nothing may have been deleted"
    );
    assert!(f.progress(s.shared.id).await.is_some());
}

#[tokio::test]
async fn a_uuid_shaped_reference_that_is_no_record_id_is_cleaned_up_normally() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    let unrelated = Row::valued(7, tenant(1), &Uuid::from_u128(0xdead).to_string());
    f.seed(&unrelated, &unrelated.value()).await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);

    expect_exit(&f.run(&["cleanup"]).await, Exit::Success);
    assert!(!has_old(&f, &unrelated));
}

#[tokio::test]
async fn cleanup_before_the_migration_is_done_is_refused() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    f.new.fail_put_from(Some(1));
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    let old_before = f.old.snapshot();

    let run = f.run(&["cleanup"]).await;
    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("not done"), "{}", run.err);
    assert_eq!(f.old.snapshot(), old_before);
}

#[tokio::test]
async fn cleanup_without_any_migration_state_is_a_no_op() {
    let f = Fixture::sqlite().await;
    let run = f.run(&["cleanup"]).await;
    // The shipped schema and no tool state: nothing was ever migrated, nothing to clean.
    expect_exit(&run, Exit::Success);
    assert!(run.out.contains("nothing to do"), "{}", run.out);
    assert_eq!(f.old.calls(), 0);
}

#[tokio::test]
async fn superseded_rows_old_entries_are_cleaned_up_too() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    credstore_value_migration::state::create_tables(&f.db, f.backend())
        .await
        .unwrap();
    f.exec(
        "CREATE TRIGGER inject BEFORE UPDATE OF phase ON credstore_value_migration \
         WHEN NEW.phase = 'activating' BEGIN SELECT RAISE(ABORT, 'injected'); END",
    )
    .await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Failure);
    f.exec("DROP TRIGGER inject").await;
    f.exec(&format!(
        "DELETE FROM credstore_secrets WHERE id = x'{}'",
        s.shared.id.simple()
    ))
    .await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    assert_eq!(f.progress(s.shared.id).await.unwrap().0, "superseded");

    expect_exit(&f.run(&["cleanup"]).await, Exit::Success);
    assert!(!has_old(&f, &s.shared));
    assert!(f.progress(s.shared.id).await.is_none());
}

#[tokio::test]
async fn after_discarding_values_cleanup_only_removes_the_bookkeeping() {
    let f = Fixture::sqlite().await;
    let row = Row::valued(1, tenant(1), "a");
    f.insert(&row).await;
    expect_exit(
        &f.run(&["migrate", "--discard-values"]).await,
        Exit::Success,
    );
    assert_eq!(f.progress(row.id).await.unwrap().0, "discarded");

    expect_exit(&f.run(&["cleanup", "--drop-state"]).await, Exit::Success);
    assert!(!f.table_exists("credstore_value_migration_rows").await);
}

#[tokio::test]
async fn cleanup_refuses_done_header_with_shipped_schema() {
    let f = Fixture::sqlite().await;
    f.seed_standard().await;
    // A header that says `done` over the SHIPPED schema (a restored gear table, a hand
    // edit). The rows are in a state `cleanup` deletes by: without the check it would
    // delete their old entries.
    take_snapshot(&f.db, f.backend(), false, false)
        .await
        .unwrap();
    f.exec("UPDATE credstore_value_migration SET phase = 'done'")
        .await;
    f.exec(
        "UPDATE credstore_value_migration_rows SET state = 'copied', value_version = '1' \
         WHERE state = 'pending'",
    )
    .await;
    let old_before = f.old.snapshot();
    let tables_before = f.tables_digest().await;

    let run = f.run(&["cleanup"]).await;

    expect_exit(&run, Exit::Failure);
    assert!(run.err.contains("wrong schema state"), "{}", run.err);
    assert!(
        run.err.contains("cleanup runs after the gear's migrations"),
        "{}",
        run.err
    );
    assert!(!run.out.contains("old entries deleted"), "{}", run.out);
    // Nothing was deleted, in either store or in the tables.
    assert_eq!(f.old.snapshot(), old_before);
    assert_eq!(f.old.deletes.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(f.tables_digest().await, tables_before);
    assert_eq!(f.phase().await, "done");
}

#[tokio::test]
async fn cleanup_dry_run_with_drop_state_keeps_the_tables() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    let old_before = f.old.snapshot();
    let live_before = f.new.live();
    let deletes = f.old.deletes.load(std::sync::atomic::Ordering::SeqCst);
    let tables_before = f.tables_digest().await;

    let run = f.run(&["cleanup", "--dry-run", "--drop-state"]).await;

    // No evidence is left, so dropping would be possible: the dry run says so, and
    // exits `0`, not `2`.
    expect_exit(&run, Exit::Success);
    assert!(run.out.contains("DRY RUN"), "{}", run.out);
    assert!(
        run.out.contains("old entries deleted (would be): 6"),
        "{}",
        run.out
    );
    assert!(
        run.out.contains("progress tables dropped (would be): true"),
        "{}",
        run.out
    );
    assert!(!run.out.contains("NOT dropped"), "{}", run.out);
    // Both tables are still there with every row, and the header still says `done`.
    assert!(f.table_exists("credstore_value_migration").await);
    assert!(f.table_exists("credstore_value_migration_rows").await);
    assert_eq!(f.tables_digest().await, tables_before);
    assert_eq!(f.phase().await, "done");
    let states = vec![
        (&s.shared, "copied"),
        (&s.private, "copied"),
        (&s.seeded, "unverified_copied"),
        (&s.tenant_shared, "copied"),
        (&s.provisioning, "unfinished"),
        (&s.deprovisioning, "unfinished"),
    ];
    for (row, state) in states {
        assert_eq!(
            f.progress(row.id).await.unwrap().0,
            state,
            "{}",
            row.reference
        );
    }
    // Neither store was touched.
    assert_eq!(f.old.snapshot(), old_before);
    assert_eq!(
        f.old.deletes.load(std::sync::atomic::Ordering::SeqCst),
        deletes
    );
    assert_eq!(f.new.live(), live_before);
}

#[tokio::test]
async fn cleanup_fence_key_refused_while_rows_remain() {
    let f = Fixture::sqlite().await;
    let s = f.seed_standard().await;
    expect_exit(&f.run(&["migrate"]).await, Exit::Success);
    // A progress row nothing resolves: not evidence, not deletable, not "nothing was
    // there". A finished migration never leaves a `pending` one; a hand edit can, and the
    // fence key is the last thing that could still verify an old entry.
    let stray = Row::valued(20, tenant(7), "stray");
    f.insert_progress(&stray, "pending").await;
    f.old
        .put(stray.tenant, &stray.reference, None, b"stray-value");

    let run = f.run(&["cleanup", "--include-fence-key"]).await;

    expect_exit(&run, Exit::Failure);
    assert!(
        run.err
            .contains("rows other than evidence are still in credstore_value_migration_rows"),
        "{}",
        run.err
    );
    assert!(
        run.err
            .contains("the fence key is deleted last, after every old entry"),
        "{}",
        run.err
    );
    // The fence key is still there, and so are the stray row and its old entry.
    assert!(f.old.has(Uuid::nil(), FENCE, None));
    assert_eq!(f.progress(stray.id).await.unwrap().0, "pending");
    assert!(f.old.has(stray.tenant, &stray.reference, None));
    // The entries that could be resolved were resolved before the check: the fence key
    // is last, never first.
    for row in s.active() {
        assert!(!has_old(&f, row), "{}", row.reference);
        assert!(f.progress(row.id).await.is_none(), "{}", row.reference);
    }
}
