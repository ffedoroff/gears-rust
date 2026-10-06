// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Phase `verifying`: read every `active` value from the old store and check it
//! against the shipped fingerprint. Writes nothing (the outcomes are decided
//! again, row by row, in the copy phase), so re-running it is cheap and safe.

use credstore_sdk::SecretValue;

use crate::env::{Env, load_fence_key};
use crate::error::MigrationError;
use crate::report::{Out, RowRef, print_rows, print_type_divergence, say};
use crate::state::{self, ProgressRow, RowState, TypeDivergence};
use crate::stores::OldAddress;
use crate::verdict::{Verdict, judge};

/// What the verification found.
#[derive(Debug, Default)]
pub struct VerifyReport {
    /// Whether the old store held the fence key.
    pub fence_key_present: bool,
    /// Rows whose fingerprint matched.
    pub verified: usize,
    /// Rows without a fingerprint (copied on trust, as the shipped gear served them).
    pub unverified: usize,
    /// Rows that end up without a value, with the reason.
    pub losses: Vec<(RowRef, RowState)>,
    /// Rows in status `1`/`3`, listed for cleanup only.
    pub unfinished: usize,
    /// Private rows whose type differs from the tenant's non-private row.
    pub type_divergent: Vec<TypeDivergence>,
}

impl VerifyReport {
    /// Whether any row ends up without a value.
    #[must_use]
    pub fn has_losses(&self) -> bool {
        !self.losses.is_empty()
    }

    fn record(&mut self, row: &ProgressRow, verdict: Verdict) {
        match verdict {
            Verdict::Copy { verified: true, .. } => self.verified += 1,
            Verdict::Copy {
                verified: false, ..
            } => self.unverified += 1,
            loss => self.losses.push((
                RowRef {
                    id: row.id,
                    tenant_id: row.tenant_id,
                    reference: row.reference.clone(),
                },
                loss.state(),
            )),
        }
    }

    /// Prints the counts, then one line per row that ends up without a value.
    pub fn print(&self, out: Out<'_>) {
        say!(
            out,
            "fence key in the old store: {}",
            self.fence_key_present
        );
        say!(
            out,
            "will be copied (fingerprint verified): {}",
            self.verified
        );
        say!(
            out,
            "will be copied unverified (no fingerprint, served on trust before): {}",
            self.unverified
        );
        for (state, title) in [
            (RowState::Missing, "MISSING (no value in the old store)"),
            (RowState::FpMismatch, "FP_MISMATCH (will not be copied)"),
            (
                RowState::UnknownFenceKey,
                "UNKNOWN_FENCE_KEY (will not be copied)",
            ),
        ] {
            let rows: Vec<_> = self
                .losses
                .iter()
                .filter(|(_, s)| *s == state)
                .cloned()
                .collect();
            print_rows(out, title, &rows);
        }
        say!(
            out,
            "unfinished rows (status 1/3, nothing to copy, listed for cleanup): {}",
            self.unfinished
        );
        print_type_divergence(out, &self.type_divergent);
    }
}

/// Reads and judges every `pending` row.
///
/// A transient failure of the old store is retried; when it persists the run
/// aborts, with nothing marked.
///
/// # Errors
///
/// Any [`MigrationError`].
pub async fn run(env: &Env<'_>, out: Out<'_>) -> Result<VerifyReport, MigrationError> {
    say!(
        out,
        "verify: reading every active value from the old store (nothing is written)"
    );
    let fence_key = load_fence_key(env).await?;
    let mut report = VerifyReport {
        fence_key_present: fence_key.is_some(),
        ..VerifyReport::default()
    };
    let mut after = None;
    let mut checked = 0_usize;
    loop {
        let rows = state::fetch_rows(
            env.db,
            env.backend,
            "state = 'pending'",
            after,
            env.tuning.batch_size,
        )
        .await?;
        let Some(last) = rows.last() else { break };
        after = Some(last.id);
        for row in &rows {
            let verdict = verdict_of(env, row, fence_key.as_ref())
                .await
                .inspect_err(|e| {
                    tracing::error!(
                        id = %row.id,
                        tenant = %row.tenant_id,
                        reference = %row.reference,
                        error = %e,
                        "credstore value migration: verify stopped at this row"
                    );
                })?;
            report.record(row, verdict);
        }
        checked += rows.len();
        tracing::info!(checked, "credstore value migration: verify progress");
    }
    let tally = state::tally(env.db, env.backend, env.tuning.batch_size).await?;
    report.unfinished = tally.get(&RowState::Unfinished).copied().unwrap_or(0);
    report.type_divergent = state::type_divergence(env.db, env.backend).await?;
    Ok(report)
}

async fn verdict_of(
    env: &Env<'_>,
    row: &ProgressRow,
    fence_key: Option<&SecretValue>,
) -> Result<Verdict, MigrationError> {
    let value = env
        .old
        .get(&OldAddress::of(row))
        .await
        .map_err(|e| e.at_row(row.id))?;
    Ok(judge(row, value, fence_key.map(SecretValue::as_bytes)))
}
