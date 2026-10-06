// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Command-line entry point an operator's binary calls.
//!
//! ```text
//! credstore-value-migration --database-url postgres://... migrate [--accept-losses] [--discard-values]
//! credstore-value-migration --database-url postgres://... cleanup [--dry-run] [--include-fence-key] [--drop-state]
//! ```
//!
//! `--database-url` can also come from `CREDSTORE_MIGRATION_DATABASE_URL`.
//!
//! Exit codes: `0` done; `1` aborted by an error (the reason is on stderr; fix
//! the cause and run the same command again, it resumes); `2` the operator has
//! to decide something (`migrate`: some rows end up without a value, run it
//! again with `--accept-losses` once you have read the list; `cleanup
//! --drop-state`: evidence rows are still in the progress table).

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use credstore_sdk::CredStorePluginClientV2;
use sea_orm::{ConnectOptions, Database, DatabaseBackend};
use toolkit_db::{ConnectOpts, Db, DbError, DbLockError, DbLockGuard};

use crate::env::Env;
use crate::error::MigrationError;
use crate::legacy::LegacyStore;
use crate::migrate;
use crate::report::{Exit, Out, say};
use crate::stores::{NewStore, OldStore, Tuning, tool_context};
use crate::{cleanup, db};

/// Namespace and key of the `PostgreSQL` advisory lock that keeps two runs off
/// the same database (derived from the tool's name).
const LOCK_NAMESPACE: &str = "credstore-value-migration";
const LOCK_KEY: &str = "run";

#[derive(Debug, Parser)]
#[command(
    name = "credstore-value-migration",
    about = "Moves CredStore values into the immutable-versions store (one-off, stop-the-world)",
    after_help = "Exit codes: 0 done, 1 error (fix the cause and run the same command again), \
                  2 a decision is needed (see the report)."
)]
struct Cli {
    /// Database of the credstore gear (postgres:// or sqlite://).
    #[arg(
        long,
        env = "CREDSTORE_MIGRATION_DATABASE_URL",
        global = true,
        hide_env_values = true
    )]
    database_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Move every value into the new store and apply the gear's schema
    /// migrations. Stop the old credstore first. Run it until it exits 0: it
    /// resumes after any failure.
    Migrate {
        /// Accept that some rows end up without a value (missing in the old
        /// store, or failing the fingerprint check). Persisted.
        #[arg(long)]
        accept_losses: bool,
        /// The old backend was the in-memory plugin (no value survived):
        /// copy nothing, leave every credential row `declared`.
        #[arg(long)]
        discard_values: bool,
    },
    /// After the migration is verified: delete the superseded entries of the
    /// old store. Resumable; the point of no return for the old store.
    Cleanup {
        /// Report what would be done; change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Also delete the old fence key (last).
        #[arg(long)]
        include_fence_key: bool,
        /// Drop the tool's progress tables when nothing is left in them.
        #[arg(long)]
        drop_state: bool,
    },
}

/// Runs the tool with `std::env::args`: parses the command line, runs the
/// command and returns the process exit code.
///
/// `old` is the pre-ADR-0006 store through [`LegacyStore`] (only `get` and
/// `delete` are called; for a plugin of the published V1 contract use the
/// sibling crate `credstore-value-migration-v1`, which bridges it), `new` the
/// plugin of the immutable-versions store. Build both directly, with the
/// deployment's own configuration, as the plugins' `init` would, but without a
/// `ClientHub`.
///
/// # Errors
///
/// Only when the output cannot be written; every other failure is reported on
/// stderr and returned as exit code `1`.
pub async fn run(
    old: Arc<dyn LegacyStore>,
    new: Arc<dyn CredStorePluginClientV2>,
) -> anyhow::Result<ExitCode> {
    run_from(std::env::args_os(), old, new).await
}

/// Like [`run`] with explicit arguments (the first is the program name).
///
/// # Errors
///
/// Only when the output cannot be written.
pub async fn run_from<I, T>(
    args: I,
    old: Arc<dyn LegacyStore>,
    new: Arc<dyn CredStorePluginClientV2>,
) -> anyhow::Result<ExitCode>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init()
        .ok();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let exit = run_with(
        args,
        old.as_ref(),
        new.as_ref(),
        &Tuning::default(),
        &mut stdout,
        &mut stderr,
    )
    .await;
    stdout.flush()?;
    Ok(exit.into())
}

/// The whole tool with everything explicit: arguments, stores, tuning and the
/// two output streams. Installs no logger. Used by [`run_from`] and by tests.
pub async fn run_with<I, T>(
    args: I,
    old: &dyn LegacyStore,
    new: &dyn CredStorePluginClientV2,
    tuning: &Tuning,
    out: Out<'_>,
    err: Out<'_>,
) -> Exit
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let usage = e.render().to_string();
            return if e.use_stderr() {
                say!(err, "{}", usage.trim_end());
                Exit::Failure
            } else {
                say!(out, "{}", usage.trim_end());
                Exit::Success
            };
        }
    };
    match execute(&cli, old, new, tuning, out).await {
        Ok(exit) => exit,
        Err(e) => {
            say!(err, "ABORTED: {e}");
            Exit::Failure
        }
    }
}

async fn execute(
    cli: &Cli,
    old: &dyn LegacyStore,
    new: &dyn CredStorePluginClientV2,
    tuning: &Tuning,
    out: Out<'_>,
) -> Result<Exit, MigrationError> {
    let url = cli.database_url.as_deref().ok_or_else(|| {
        MigrationError::Usage(
            "--database-url (or CREDSTORE_MIGRATION_DATABASE_URL) is required".to_owned(),
        )
    })?;
    reject_memory_database(url)?;
    say!(
        out,
        "database: {}",
        toolkit_db::redact_credentials_in_dsn(Some(url))
    );
    let platform = toolkit_db::connect_db(
        url,
        ConnectOpts {
            max_conns: Some(2),
            ..ConnectOpts::default()
        },
    )
    .await?;
    let mut options = ConnectOptions::new(url.to_owned());
    options.max_connections(4);
    let raw = Database::connect(options).await?;
    let backend = db::backend(&raw)?;
    let lock = acquire_lock(&platform, backend).await?;

    let env = Env {
        db: &raw,
        backend,
        platform: &platform,
        old: OldStore::new(old, tuning.clone()),
        new: NewStore::new(new, tool_context()?, tuning.clone()),
        tuning,
    };
    let result = match &cli.command {
        Command::Migrate {
            accept_losses,
            discard_values,
        } => {
            let opts = migrate::Options {
                accept_losses: *accept_losses,
                discard_values: *discard_values,
            };
            migrate::run(&env, &opts, out).await
        }
        Command::Cleanup {
            dry_run,
            include_fence_key,
            drop_state,
        } => {
            let opts = cleanup::Options {
                mode: if *dry_run {
                    cleanup::Mode::DryRun
                } else {
                    cleanup::Mode::Apply
                },
                fence_key: if *include_fence_key {
                    cleanup::FenceKey::Delete
                } else {
                    cleanup::FenceKey::Keep
                },
                progress_tables: if *drop_state {
                    cleanup::ProgressTables::Drop
                } else {
                    cleanup::ProgressTables::Keep
                },
            };
            cleanup::run(&env, opts, out).await
        }
    };
    if let Some(lock) = lock
        && let Err(e) = lock.release().await
    {
        tracing::warn!(error = %e, "credstore value migration: releasing the migration lock failed");
    }
    result
}

/// The tool opens two connections (the platform handle for the migration runner and
/// its own for raw statements); an in-memory `SQLite` database would be two
/// different databases.
fn reject_memory_database(url: &str) -> Result<(), MigrationError> {
    if url.contains(":memory:") || url.contains("mode=memory") {
        return Err(MigrationError::Usage(
            "an in-memory SQLite database cannot be migrated: give the file of the credstore \
             database (sqlite://path/to/file.db)"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Takes the session-level advisory lock that keeps two runs off one
/// `PostgreSQL` database. `SQLite` has no cross-process lock worth the name
/// here: a `SQLite` database is migrated by one process at a time, which the
/// operator guarantees (documented in the README).
async fn acquire_lock(
    platform: &Db,
    backend: DatabaseBackend,
) -> Result<Option<DbLockGuard>, MigrationError> {
    if backend != DatabaseBackend::Postgres {
        return Ok(None);
    }
    match platform.lock(LOCK_NAMESPACE, LOCK_KEY).await {
        Ok(guard) => Ok(Some(guard)),
        Err(DbError::Lock(DbLockError::AlreadyHeld { .. })) => Err(MigrationError::AlreadyRunning),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn migrate_and_cleanup_flags_parse() {
        let cli = Cli::try_parse_from([
            "m",
            "--database-url",
            "sqlite://x",
            "migrate",
            "--accept-losses",
            "--discard-values",
        ])
        .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Command::Migrate {
                accept_losses: true,
                discard_values: true
            }
        ));
        let cli = Cli::try_parse_from(["m", "cleanup", "--include-fence-key", "--drop-state"])
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(
            cli.command,
            Command::Cleanup {
                dry_run: false,
                include_fence_key: true,
                drop_state: true
            }
        ));
    }

    #[test]
    fn an_in_memory_database_is_refused() {
        for url in [
            "sqlite::memory:",
            "sqlite://:memory:",
            "sqlite://x?mode=memory",
        ] {
            assert!(reject_memory_database(url).is_err(), "{url}");
        }
        assert!(reject_memory_database("sqlite://db.sqlite?mode=rwc").is_ok());
        assert!(reject_memory_database("postgres://u:p@h/db").is_ok());
    }

    #[test]
    fn the_old_stage_commands_are_gone() {
        for stage in ["copy", "activate"] {
            assert!(Cli::try_parse_from(["m", stage]).is_err(), "{stage}");
        }
        assert!(Cli::try_parse_from(["m", "migrate", "--results", "x"]).is_err());
    }
}
