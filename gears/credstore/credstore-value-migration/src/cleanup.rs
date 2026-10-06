// Created: 2026-10-02 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! `cleanup`: retire the superseded entries of the OLD store, driven by the
//! progress table. Run it only after the migrated values have been verified in
//! the running gear: it is the point of no return for the old store.
//!
//! * `copied`, `unverified_copied`, `unfinished` and `superseded` rows: the old
//!   entry is deleted by its recorded address (never by enumerating the store;
//!   an absent entry is success) and the progress row is removed;
//! * `missing` and `discarded` rows: nothing was ever there; the progress row is
//!   removed;
//! * `fp_mismatch` and `unknown_fence_key` rows: KEPT, with their old entries,
//!   as evidence, and reported;
//! * before anything is deleted, every candidate whose reference parses as a UUID
//!   equal to the id of any credential record is refused (the old and the new
//!   store may share a mount, and such an old address is a new key): the run
//!   aborts and deletes nothing;
//! * the old fence key goes LAST, only with `--include-fence-key`, and only when
//!   nothing but evidence rows remain;
//! * `--drop-state` finally drops the tool's progress tables, but only when no
//!   row is left (evidence rows block it: it exits `2` and says so). Without
//!   the flag the tables stay, so cleanup can be run again.
//!
//! Resumable: a row is removed right after its old entry is deleted, so a run
//! that stopped continues with what is left. `--dry-run` changes nothing.

use uuid::Uuid;

use crate::db::{self, Schema};
use crate::env::Env;
use crate::error::MigrationError;
use crate::report::{Exit, Out, RowRef, print_rows, say};
use crate::state::{self, Phase, ProgressRow, ROWS_TABLE, RowState, states_in};
use crate::stores::OldAddress;

/// Whether `cleanup` changes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Delete, and remove the progress rows.
    #[default]
    Apply,
    /// Report what would be done; change nothing.
    DryRun,
}

/// What happens to the old fence key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FenceKey {
    /// Keep it (the evidence rows can still be verified).
    #[default]
    Keep,
    /// Delete it, last.
    Delete,
}

/// What happens to the tool's progress tables at the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProgressTables {
    /// Keep them, so `cleanup` can be run again.
    #[default]
    Keep,
    /// Drop them when nothing is left in them.
    Drop,
}

/// The operator's choices for `cleanup`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Whether anything is changed.
    pub mode: Mode,
    /// What happens to the old fence key.
    pub fence_key: FenceKey,
    /// What happens to the progress tables.
    pub progress_tables: ProgressTables,
}

impl Options {
    fn dry_run(self) -> bool {
        self.mode == Mode::DryRun
    }
}

/// The states whose old entry `cleanup` deletes.
const DELETABLE: [RowState; 4] = [
    RowState::Copied,
    RowState::UnverifiedCopied,
    RowState::Unfinished,
    RowState::Superseded,
];

/// Nothing was ever in the old store for these.
const NOTHING_OLD: [RowState; 2] = [RowState::Missing, RowState::Discarded];

/// Refuses when an old reference has the shape of a new key.
async fn refuse_new_key_shapes(env: &Env<'_>) -> Result<(), MigrationError> {
    let predicate = states_in(&DELETABLE);
    let (mut after, mut offending, mut first): (_, usize, Option<(String, Uuid)>) = (None, 0, None);
    loop {
        let rows = state::fetch_rows(
            env.db,
            env.backend,
            &predicate,
            after,
            env.tuning.batch_size,
        )
        .await?;
        let Some(last) = rows.last() else { break };
        after = Some(last.id);
        for row in &rows {
            if is_new_key_shaped(env, row).await? {
                offending += 1;
                first.get_or_insert_with(|| (row.reference.clone(), row.tenant_id));
            }
        }
    }
    match first {
        None => Ok(()),
        Some((reference, tenant_id)) => Err(MigrationError::NewKeyShaped {
            reference,
            tenant_id,
            count: offending,
        }),
    }
}

async fn is_new_key_shaped(env: &Env<'_>, row: &ProgressRow) -> Result<bool, MigrationError> {
    let Ok(candidate) = Uuid::parse_str(&row.reference) else {
        return Ok(false);
    };
    let sql = format!(
        "SELECT 1 AS present FROM credstore_secrets WHERE id = {} LIMIT 1",
        db::ph(env.backend, 1)
    );
    db::exists(env.db, env.backend, &sql, vec![candidate.into()]).await
}

/// What `cleanup` did (or, with `--dry-run`, would do).
#[derive(Debug, Default)]
struct Report {
    deleted: usize,
    nothing_old: usize,
    evidence: Vec<(RowRef, RowState)>,
    fence_key_deleted: bool,
    state_dropped: bool,
}

/// Runs `cleanup`.
///
/// # Errors
///
/// Any [`MigrationError`]: the migration is not done yet, an old reference has
/// the shape of a new key, or a store or database call failed. What was done
/// stays done; a re-run continues.
pub async fn run(env: &Env<'_>, opts: Options, out: Out<'_>) -> Result<Exit, MigrationError> {
    let backend = env.backend;
    let header = state::load_header(env.db, backend).await?;
    let Some(header) = header else {
        say!(
            out,
            "cleanup: nothing to do (the tool holds no migration state)"
        );
        return Ok(Exit::Success);
    };
    if header.phase != Phase::Done {
        return Err(MigrationError::State(format!(
            "the migration is in phase {}, not done: run `migrate` until it exits 0 before \
             `cleanup`",
            header.phase
        )));
    }
    if db::detect_schema(env.db, backend).await? != Schema::ValueVersions {
        return Err(MigrationError::WrongSchema(
            "cleanup runs after the gear's migrations".to_owned(),
        ));
    }
    if opts.dry_run() {
        say!(out, "cleanup: DRY RUN (nothing is changed)");
    }
    refuse_new_key_shapes(env).await?;

    let mut report = Report::default();
    delete_old_entries(env, opts, &mut report).await?;
    report.nothing_old = drop_rows_without_old_entry(env, opts).await?;
    report.evidence = list_evidence(env).await?;
    if opts.fence_key == FenceKey::Delete {
        delete_fence_key(env, opts, &mut report).await?;
    }
    let decision = if opts.progress_tables == ProgressTables::Drop {
        drop_state(env, opts, &mut report).await?
    } else {
        false
    };
    print(out, &report, opts);
    Ok(if decision {
        Exit::Decision
    } else {
        Exit::Success
    })
}

async fn delete_old_entries(
    env: &Env<'_>,
    opts: Options,
    report: &mut Report,
) -> Result<(), MigrationError> {
    let predicate = states_in(&DELETABLE);
    let mut after = None;
    loop {
        let rows = state::fetch_rows(
            env.db,
            env.backend,
            &predicate,
            after,
            env.tuning.batch_size,
        )
        .await?;
        let Some(last) = rows.last() else {
            return Ok(());
        };
        after = Some(last.id);
        for row in &rows {
            if !opts.dry_run() {
                env.old
                    .delete(&OldAddress::of(row))
                    .await
                    .map_err(|e| e.at_row(row.id))
                    .inspect_err(|e| {
                        tracing::error!(
                            id = %row.id,
                            tenant = %row.tenant_id,
                            reference = %row.reference,
                            error = %e,
                            "credstore value migration: cleanup stopped at this row"
                        );
                    })?;
                state::delete_row(env.db, env.backend, row.id).await?;
            }
            report.deleted += 1;
            tracing::debug!(id = %row.id, state = %row.state, "credstore value migration: old entry deleted");
        }
    }
}

/// `missing` and `discarded` rows had no old entry: their progress rows go.
async fn drop_rows_without_old_entry(
    env: &Env<'_>,
    opts: Options,
) -> Result<usize, MigrationError> {
    if !opts.dry_run() {
        let removed = state::delete_rows_in(env.db, env.backend, &NOTHING_OLD).await?;
        return Ok(usize::try_from(removed).unwrap_or(usize::MAX));
    }
    let tally = state::tally(env.db, env.backend, env.tuning.batch_size).await?;
    Ok(NOTHING_OLD
        .iter()
        .map(|s| tally.get(s).copied().unwrap_or(0))
        .sum())
}

async fn list_evidence(env: &Env<'_>) -> Result<Vec<(RowRef, RowState)>, MigrationError> {
    let predicate = states_in(&[RowState::FpMismatch, RowState::UnknownFenceKey]);
    let (mut after, mut found) = (None, Vec::new());
    loop {
        let rows = state::fetch_rows(
            env.db,
            env.backend,
            &predicate,
            after,
            env.tuning.batch_size,
        )
        .await?;
        let Some(last) = rows.last() else {
            return Ok(found);
        };
        after = Some(last.id);
        found.extend(rows.iter().map(|r| {
            (
                RowRef {
                    id: r.id,
                    tenant_id: r.tenant_id,
                    reference: r.reference.clone(),
                },
                r.state,
            )
        }));
    }
}

/// Deletes the old fence key; last, and only when nothing but evidence is left.
async fn delete_fence_key(
    env: &Env<'_>,
    opts: Options,
    report: &mut Report,
) -> Result<(), MigrationError> {
    let only_evidence = format!(
        "NOT ({})",
        states_in(&[RowState::FpMismatch, RowState::UnknownFenceKey])
    );
    if !opts.dry_run() && state::any_row(env.db, env.backend, &only_evidence).await? {
        return Err(MigrationError::State(format!(
            "rows other than evidence are still in {ROWS_TABLE}: the fence key is deleted last, \
             after every old entry"
        )));
    }
    if !report.evidence.is_empty() {
        tracing::warn!(
            kept = report.evidence.len(),
            "credstore value migration: deleting the fence key; the kept entries can no longer be verified"
        );
    }
    if !opts.dry_run() {
        env.old.delete(&OldAddress::fence_key()).await?;
    }
    report.fence_key_deleted = true;
    Ok(())
}

/// Drops the progress tables when no row is left. Returns whether the operator
/// has to decide (rows remain).
async fn drop_state(
    env: &Env<'_>,
    opts: Options,
    report: &mut Report,
) -> Result<bool, MigrationError> {
    if !report.evidence.is_empty() {
        return Ok(true);
    }
    if !opts.dry_run() {
        state::drop_tables(env.db).await?;
    }
    report.state_dropped = true;
    Ok(false)
}

fn print(out: Out<'_>, r: &Report, opts: Options) {
    let verb = if opts.dry_run() { "would be" } else { "were" };
    say!(out, "old entries deleted ({verb}): {}", r.deleted);
    say!(
        out,
        "rows with no old entry (missing, discarded) removed from the progress table ({verb}): {}",
        r.nothing_old
    );
    print_rows(out, "kept as evidence (old entries untouched)", &r.evidence);
    if opts.fence_key == FenceKey::Delete {
        say!(out, "fence key deleted ({verb}): {}", r.fence_key_deleted);
    }
    if opts.progress_tables == ProgressTables::Drop {
        if r.state_dropped {
            say!(out, "progress tables dropped ({verb}): true");
        } else {
            say!(
                out,
                "progress tables NOT dropped: the evidence rows above are still in them. \
                 Resolve them (and delete their old entries by hand) or drop \
                 {ROWS_TABLE} and {} yourself.",
                state::HEADER_TABLE
            );
        }
    }
}
