// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The command line entry points: `--help` and a usage error, which never reach a
//! database. Kept in a binary of their own because `run_from` installs a global
//! `tracing` subscriber (writing to the real stderr) for the whole process, which
//! must not leak into the migration suites. No Docker.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::use_debug,
    reason = "tests"
)]

mod common;

use std::process::ExitCode;
use std::sync::atomic::Ordering;

use common::{FakeNew, FakeOld, expect_exit, run_cli, run_entry_point, shared_stores};
use credstore_value_migration::Exit;

/// Neither store was called.
fn assert_stores_untouched(old: &FakeOld, new: &FakeNew) {
    assert_eq!(old.calls(), 0, "the old store was called");
    assert_eq!(
        (
            new.puts.load(Ordering::SeqCst),
            new.gets.load(Ordering::SeqCst),
            new.destroys.load(Ordering::SeqCst)
        ),
        (0, 0, 0),
        "the new store was called"
    );
}

// `run_from` writes to the real stdout and stderr: for it only the exit code can be
// checked (the text is covered through `run_with`, which captures it).

#[tokio::test]
async fn cli_help_exits_zero() {
    let (old, new) = shared_stores();
    let cases: Vec<&[&str]> = vec![&["--help"], &["-h"], &["migrate", "--help"]];
    for args in cases {
        let code = run_entry_point(&old, &new, args).await;
        assert_eq!(code, ExitCode::from(0), "{args:?}");
    }
    assert_stores_untouched(&old, &new);
}

#[tokio::test]
async fn cli_unknown_subcommand_prints_usage_and_exits_one() {
    let (old, new) = shared_stores();
    let code = run_entry_point(&old, &new, &["frobnicate"]).await;
    assert_eq!(code, ExitCode::from(1));
    assert_stores_untouched(&old, &new);
}

#[tokio::test]
async fn cli_help_text_goes_to_stdout() {
    let (old, new) = shared_stores();

    let run = run_cli(old.as_ref(), new.as_ref(), &["--help"]).await;

    expect_exit(&run, Exit::Success);
    for expected in [
        "Usage:",
        "migrate",
        "cleanup",
        "Exit codes: 0 done, 1 error",
    ] {
        assert!(
            run.out.contains(expected),
            "{expected} missing in:\n{}",
            run.out
        );
    }
    assert!(run.err.is_empty(), "{}", run.err);
    assert_stores_untouched(&old, &new);
}

#[tokio::test]
async fn cli_unknown_subcommand_text_goes_to_stderr() {
    let (old, new) = shared_stores();

    let run = run_cli(old.as_ref(), new.as_ref(), &["frobnicate"]).await;

    expect_exit(&run, Exit::Failure);
    assert!(
        run.err.contains("unrecognized subcommand 'frobnicate'"),
        "{}",
        run.err
    );
    assert!(run.err.contains("Usage:"), "{}", run.err);
    assert!(run.out.is_empty(), "{}", run.out);
    assert_stores_untouched(&old, &new);
}
