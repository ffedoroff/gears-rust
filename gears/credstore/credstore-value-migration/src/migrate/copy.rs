// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Phase `copying`: put every `pending` value into the new store, read it back,
//! and record the version the store returned.
//!
//! Per row: read the value from the old store, judge it (the same rules as the
//! verification), then either `put` it under `(tenant_id, record_id = row id)`,
//! read the version back and compare, and record `copied` /
//! `unverified_copied` with the version; or record the loss. A row is recorded
//! only after its read-back succeeded. A `put` whose result was not recorded
//! (the run died in between) leaves a version nobody points at; the tidy phase
//! destroys it.

use credstore_sdk::{SecretValue, StoreKey, ValueVersion};

use crate::env::{Env, load_fence_key};
use crate::error::MigrationError;
use crate::report::{Out, say};
use crate::state::{self, Header, ProgressRow, RowState};
use crate::stores::{OldAddress, store_key};
use crate::verdict::{Verdict, judge};

/// How the phase ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Every pending row has been recorded.
    Done,
    /// A row ends up without a value although the operator has not accepted
    /// that (it was fine at verification time and changed since).
    NeedsDecision,
}

/// Copies every pending row.
///
/// # Errors
///
/// Any [`MigrationError`]; the rows recorded so far stay and a re-run resumes.
pub async fn run(env: &Env<'_>, header: &Header, out: Out<'_>) -> Result<Outcome, MigrationError> {
    say!(out, "copy: moving the values into the new store");
    let fence_key = load_fence_key(env).await?;
    let mut after = None;
    let mut processed = 0_usize;
    loop {
        let rows = state::fetch_rows(
            env.db,
            env.backend,
            "state = 'pending'",
            after,
            env.tuning.batch_size,
        )
        .await?;
        let Some(last) = rows.last() else {
            return Ok(Outcome::Done);
        };
        after = Some(last.id);
        for row in &rows {
            match copy_row(env, header, fence_key.as_ref(), row, out).await {
                Ok(Outcome::Done) => {}
                Ok(Outcome::NeedsDecision) => return Ok(Outcome::NeedsDecision),
                Err(e) => {
                    state::record_error(env.db, env.backend, row.id, &e.to_string()).await;
                    tracing::error!(
                        id = %row.id,
                        tenant = %row.tenant_id,
                        reference = %row.reference,
                        error = %e,
                        "credstore value migration: copy stopped at this row"
                    );
                    return Err(e);
                }
            }
        }
        processed += rows.len();
        tracing::info!(processed, "credstore value migration: copy progress");
    }
}

async fn copy_row(
    env: &Env<'_>,
    header: &Header,
    fence_key: Option<&SecretValue>,
    row: &ProgressRow,
    out: Out<'_>,
) -> Result<Outcome, MigrationError> {
    let value = env
        .old
        .get(&OldAddress::of(row))
        .await
        .map_err(|e| e.at_row(row.id))?;
    let verdict = judge(row, value, fence_key.map(SecretValue::as_bytes));
    let state = verdict.state();
    let Verdict::Copy { value, .. } = verdict else {
        return record_loss(env, header, row, state, out).await;
    };
    let key = store_key(row);
    let version = env.new.put(&key, value.as_bytes()).await?;
    read_back(env, row, &key, &version, value.as_bytes()).await?;
    state::mark_copied(env.db, env.backend, row.id, state, version.as_str()).await?;
    tracing::debug!(id = %row.id, %state, "credstore value migration: row copied");
    Ok(Outcome::Done)
}

/// A row that ends up without a value: recorded when the operator accepted
/// that, otherwise the phase stops and asks.
async fn record_loss(
    env: &Env<'_>,
    header: &Header,
    row: &ProgressRow,
    loss: RowState,
    out: Out<'_>,
) -> Result<Outcome, MigrationError> {
    if !header.accept_losses {
        say!(
            out,
            "NEW LOSS since the verification: id={} tenant={} reference={} outcome={}; \
             run the same command again with --accept-losses to accept it",
            row.id,
            row.tenant_id,
            row.reference,
            loss
        );
        return Ok(Outcome::NeedsDecision);
    }
    state::mark_loss(env.db, env.backend, row.id, loss).await?;
    tracing::debug!(
        id = %row.id,
        state = %loss,
        "credstore value migration: row without a value"
    );
    Ok(Outcome::Done)
}

/// Reads the stored version back and compares it with what was written. A
/// version that is not there yet is asked for again (the store may need a
/// moment); other bytes are a store failure and abort at once.
async fn read_back(
    env: &Env<'_>,
    row: &ProgressRow,
    key: &StoreKey,
    version: &ValueVersion,
    written: &[u8],
) -> Result<(), MigrationError> {
    let tuning = env.new.tuning();
    let mut attempt = 1;
    loop {
        match env.new.get(key, version).await? {
            Some(back) if back.as_bytes() == written => return Ok(()),
            Some(_) => {
                return Err(MigrationError::ReadBack {
                    id: row.id,
                    reason: "the new store returned different bytes".to_owned(),
                });
            }
            None if attempt < tuning.attempts => {
                attempt += 1;
                tokio::time::sleep(tuning.base_delay).await;
            }
            None => {
                return Err(MigrationError::ReadBack {
                    id: row.id,
                    reason: "the new store holds no value at the returned version".to_owned(),
                });
            }
        }
    }
}
