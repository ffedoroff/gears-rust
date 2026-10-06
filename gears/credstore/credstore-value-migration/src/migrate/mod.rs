// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! `migrate`: the resumable move of every credential value into the new store,
//! phase by phase, with its progress in the database.
//!
//! ```text
//! verifying  snapshot the rows, read every value from the old store, check the
//!            fingerprints; writes nothing but the snapshot
//! copying    put each value into the new store, read it back, record the version
//! schema     apply the gear's own migrations (m0001, m0002) with the platform runner
//! activating point each copied row at its version (a short transaction per row)
//! tidying    destroy the versions interrupted writes left behind
//! done
//! ```
//!
//! Every phase is idempotent and the header row names the one a restart resumes
//! in; within a phase the per-row state says what is left. A run that stops for
//! any reason is simply run again.

mod activate;
mod copy;
mod schema;
mod tidy;
mod verify;

use crate::db::{self, Schema};
use crate::env::Env;
use crate::error::MigrationError;
use crate::report::{Exit, Out, print_tally, say};
use crate::state::{self, Header, Phase};

/// The operator's choices for `migrate`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Accept that some rows end up without a value (persisted).
    pub accept_losses: bool,
    /// The old backend held no durable values (the in-memory plugin): copy
    /// nothing, mark every row `discarded`.
    pub discard_values: bool,
}

enum Start {
    /// The migration is done already.
    Finished,
    /// No shipped rows and no tool state: a fresh installation.
    NothingToMigrate,
    /// Continue with this header.
    Resume(Header),
}

async fn reload(env: &Env<'_>) -> Result<Header, MigrationError> {
    state::load_header(env.db, env.backend)
        .await?
        .ok_or_else(|| MigrationError::State("the migration header vanished".to_owned()))
}

/// Decides where a run starts, taking the snapshot when it is time to.
async fn start(
    env: &Env<'_>,
    opts: &Options,
    schema: Schema,
    out: Out<'_>,
) -> Result<Start, MigrationError> {
    let Some(header) = state::load_header(env.db, env.backend).await? else {
        if schema == Schema::ValueVersions {
            return Ok(Start::NothingToMigrate);
        }
        say!(out, "snapshot: recording the credential rows");
        state::take_snapshot(env.db, env.backend, false, opts.discard_values).await?;
        return Ok(Start::Resume(reload(env).await?));
    };
    if header.phase == Phase::Done {
        return Ok(Start::Finished);
    }
    match (header.phase, schema) {
        (Phase::Verifying, Schema::Shipped) => {
            // Nothing is decided per row yet, and the old credstore may have
            // run since the last attempt: record the rows again.
            say!(out, "snapshot: recording the credential rows again");
            state::take_snapshot(env.db, env.backend, true, opts.discard_values).await?;
            Ok(Start::Resume(reload(env).await?))
        }
        (phase, Schema::Shipped) if phase < Phase::Activating => {
            check_discard(header, *opts)?;
            Ok(Start::Resume(header))
        }
        (phase, Schema::ValueVersions) if phase.copy_finished() => {
            check_discard(header, *opts)?;
            Ok(Start::Resume(header))
        }
        (phase, schema) => Err(MigrationError::State(format!(
            "the progress table says phase {phase}, but credstore_secrets has the {} \
             schema; restore the database snapshot taken before the migration",
            schema.name()
        ))),
    }
}

/// `--discard-values` cannot be chosen once the migration went on without it.
fn check_discard(header: Header, opts: Options) -> Result<(), MigrationError> {
    if opts.discard_values && !header.discard_values {
        return Err(MigrationError::State(format!(
            "--discard-values was not chosen when this migration started and it is already in \
             phase {}: values may have been copied; restore the database snapshot to start over",
            header.phase
        )));
    }
    Ok(())
}

/// Runs `migrate` to completion, or to the point where it needs the operator.
///
/// # Errors
///
/// Any [`MigrationError`] aborts the run; the persisted progress stays and the
/// same command resumes from it.
pub async fn run(env: &Env<'_>, opts: &Options, out: Out<'_>) -> Result<Exit, MigrationError> {
    let schema = db::detect_schema(env.db, env.backend).await?;
    let mut header = match start(env, opts, schema, out).await? {
        Start::Finished => {
            say!(out, "migrate: already done");
            print_summary(env, out).await?;
            return Ok(Exit::Success);
        }
        Start::NothingToMigrate => {
            say!(
                out,
                "migrate: nothing to do (the schema is already migrated and the tool holds no \
                 state: a fresh installation)"
            );
            return Ok(Exit::Success);
        }
        Start::Resume(header) => header,
    };
    if opts.accept_losses && !header.accept_losses {
        state::persist_accept_losses(env.db, env.backend).await?;
        header.accept_losses = true;
        say!(out, "decision recorded: rows without a value are accepted");
    }
    if header.discard_values {
        say!(out, "mode: --discard-values (no value is read or copied)");
    }
    say!(out, "migrate: resuming in phase {}", header.phase);

    while header.phase != Phase::Done {
        let phase = header.phase;
        match phase {
            Phase::Verifying => {
                let report = verify::run(env, out).await?;
                report.print(out);
                if report.has_losses() && !header.accept_losses {
                    say!(
                        out,
                        "Some rows end up without a value. Inspect the list above; to proceed \
                         anyway run the same command again with --accept-losses."
                    );
                    return Ok(Exit::Decision);
                }
            }
            Phase::Copying => {
                if copy::run(env, &header, out).await? == copy::Outcome::NeedsDecision {
                    return Ok(Exit::Decision);
                }
            }
            Phase::Schema => schema::run(env, out).await?,
            Phase::Activating => activate::run(env, out).await?,
            Phase::Tidying => tidy::run(env, out).await?,
            Phase::Done => break,
        }
        let next = phase.next();
        state::set_phase(env.db, env.backend, phase, next).await?;
        say!(out, "phase {phase} finished");
        header.phase = next;
    }
    say!(out, "migrate: done");
    print_summary(env, out).await?;
    Ok(Exit::Success)
}

async fn print_summary(env: &Env<'_>, out: Out<'_>) -> Result<(), MigrationError> {
    let tally = state::tally(env.db, env.backend, env.tuning.batch_size).await?;
    say!(out, "credential rows by outcome:");
    print_tally(out, &tally);
    Ok(())
}
