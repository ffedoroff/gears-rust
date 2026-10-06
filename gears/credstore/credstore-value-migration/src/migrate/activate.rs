// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Phase `activating`: point every copied row at its new version.
//!
//! Each row is handled in its own short transaction together with its progress
//! update, so a stop at any point leaves every row either fully done or
//! untouched; a re-run does the rest.
//!
//! * copied rows: `status = 2, value_version = <the version>, version =
//!   version + 1`, only where the row is still `declared` without a version
//!   (what `m0002` left). A row that is gone, or that someone rewrote after
//!   `m0002`, is `superseded`; a row that already is active at exactly this
//!   version is done.
//! * rows without a value (`missing`, `fp_mismatch`, `unknown_fence_key`):
//!   `fallback = 2` (`none`), so the reference does not fall through to an
//!   ancestor's value; they stay `declared`.

use sea_orm::{ConnectionTrait, DatabaseBackend, TransactionTrait};
use uuid::Uuid;

use crate::db::{ph, stmt};
use crate::env::Env;
use crate::error::MigrationError;
use crate::report::{Out, say};
use crate::state::{self, ProgressRow, RowState, states_in};

const STATUS_ACTIVE: i16 = 2;
const STATUS_DECLARED: i16 = 4;
const FALLBACK_NONE: i16 = 2;

/// What happened to a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Applied {
    /// The row now points at its version, or is suppressed.
    Done,
    /// The row is no longer the one that was copied.
    Superseded,
}

/// Activates every row that is not yet.
///
/// # Errors
///
/// Any [`MigrationError`]; rows done so far stay and a re-run resumes.
pub async fn run(env: &Env<'_>, out: Out<'_>) -> Result<(), MigrationError> {
    say!(out, "activate: pointing the rows at their new versions");
    let predicate = format!(
        "{} AND activated = FALSE",
        states_in(&[
            RowState::Copied,
            RowState::UnverifiedCopied,
            RowState::Missing,
            RowState::FpMismatch,
            RowState::UnknownFenceKey,
        ])
    );
    let (mut after, mut processed, mut superseded) = (None, 0_usize, 0_usize);
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
            match activate_row(env, row).await {
                Ok(Applied::Done) => {}
                Ok(Applied::Superseded) => superseded += 1,
                Err(e) => {
                    state::record_error(env.db, env.backend, row.id, &e.to_string()).await;
                    tracing::error!(
                        id = %row.id,
                        error = %e,
                        "credstore value migration: activate stopped at this row"
                    );
                    return Err(e);
                }
            }
        }
        processed += rows.len();
        tracing::info!(
            processed,
            superseded,
            "credstore value migration: activate progress"
        );
    }
    say!(
        out,
        "activate: {processed} row(s) processed, {superseded} superseded"
    );
    Ok(())
}

async fn activate_row(env: &Env<'_>, row: &ProgressRow) -> Result<Applied, MigrationError> {
    let backend = env.backend;
    let txn = env.db.begin().await?;
    let applied = if row.state.is_copied() {
        promote(&txn, backend, row).await?
    } else {
        suppress(&txn, backend, row.id).await?;
        Applied::Done
    };
    state::mark_activated(&txn, backend, row.id, applied == Applied::Superseded).await?;
    txn.commit().await?;
    Ok(applied)
}

/// `declared` -> `active` at the copied version, when the row is still the one
/// `m0002` left.
async fn promote(
    txn: &impl ConnectionTrait,
    backend: DatabaseBackend,
    row: &ProgressRow,
) -> Result<Applied, MigrationError> {
    let version = row
        .value_version
        .as_deref()
        .ok_or_else(|| MigrationError::BadRow {
            id: row.id,
            reason: "a copied row has no value_version".to_owned(),
        })?;
    let sql = format!(
        "UPDATE credstore_secrets SET status = {STATUS_ACTIVE}, value_version = {}, \
         version = version + 1 WHERE id = {} AND status = {STATUS_DECLARED} \
         AND value_version IS NULL",
        ph(backend, 1),
        ph(backend, 2)
    );
    let changed = txn
        .execute_raw(stmt(backend, &sql, vec![version.into(), row.id.into()]))
        .await?
        .rows_affected();
    if changed == 1 {
        return Ok(Applied::Done);
    }
    // Not declared any more: gone, rewritten, or already done by a previous run.
    match current(txn, backend, row.id).await? {
        Some((STATUS_ACTIVE, Some(v))) if v == version => Ok(Applied::Done),
        _ => Ok(Applied::Superseded),
    }
}

/// `fallback = none` for a row that ends up without a value.
async fn suppress(
    txn: &impl ConnectionTrait,
    backend: DatabaseBackend,
    id: Uuid,
) -> Result<(), MigrationError> {
    let sql = format!(
        "UPDATE credstore_secrets SET fallback = {FALLBACK_NONE} WHERE id = {} \
         AND status = {STATUS_DECLARED} AND value_version IS NULL",
        ph(backend, 1)
    );
    // No row changed: the row is gone or was rewritten, and there is nothing to suppress.
    txn.execute_raw(stmt(backend, &sql, vec![id.into()]))
        .await?;
    Ok(())
}

/// `(status, value_version)` of the gear row, `None` when it is gone.
async fn current(
    txn: &impl ConnectionTrait,
    backend: DatabaseBackend,
    id: Uuid,
) -> Result<Option<(i16, Option<String>)>, MigrationError> {
    let sql = format!(
        "SELECT status, value_version FROM credstore_secrets WHERE id = {}",
        ph(backend, 1)
    );
    let Some(row) = txn
        .query_one_raw(stmt(backend, &sql, vec![id.into()]))
        .await?
    else {
        return Ok(None);
    };
    Ok(Some((
        row.try_get("", "status")?,
        row.try_get("", "value_version")?,
    )))
}
