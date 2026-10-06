// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Phase `tidying`: destroy the versions below each activated version.
//!
//! A `put` whose result the tool did not record (it was interrupted, or its
//! answer was lost) leaves a version nobody points at. Nobody else writes
//! during the downtime and versions of a key are ordered, so everything below
//! the recorded version is such a leftover. Only a store that declares
//! `destroy` is tidied; for any other the leftovers stay (they are inert: the
//! database decides which version is current).

use crate::env::Env;
use crate::error::MigrationError;
use crate::report::{Out, say};
use crate::state::{self, RowState, states_in};
use crate::stores::store_key;
use credstore_sdk::ValueVersion;

/// Destroys the leftover versions of every activated, copied row.
///
/// # Errors
///
/// Any [`MigrationError`]; rows done so far stay and a re-run resumes.
pub async fn run(env: &Env<'_>, out: Out<'_>) -> Result<(), MigrationError> {
    if !env.new.supports_destroy() {
        say!(
            out,
            "tidy: skipped, the new store does not support destroy (versions left behind by \
             interrupted writes, if any, stay; they are inert)"
        );
        return Ok(());
    }
    say!(
        out,
        "tidy: destroying versions left behind by interrupted writes"
    );
    let predicate = format!(
        "{} AND activated = TRUE AND tidied = FALSE",
        states_in(&[RowState::Copied, RowState::UnverifiedCopied])
    );
    let (mut after, mut processed) = (None, 0_usize);
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
            let Some(version) = row.value_version.as_deref() else {
                continue;
            };
            let done = env
                .new
                .destroy_below(&store_key(row), &ValueVersion::new(version))
                .await;
            if let Err(e) = done {
                state::record_error(env.db, env.backend, row.id, &e.to_string()).await;
                tracing::error!(
                    id = %row.id,
                    error = %e,
                    "credstore value migration: tidy stopped at this row"
                );
                return Err(e);
            }
            state::mark_tidied(env.db, env.backend, row.id).await?;
        }
        processed += rows.len();
        tracing::info!(processed, "credstore value migration: tidy progress");
    }
    say!(out, "tidy: {processed} row(s) processed");
    Ok(())
}
