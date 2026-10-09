//! Cleanup engine: orphan reconciliation and retention-policy expiry.
//!
//! `CleanupEngine::run_sweep` runs one best-effort cycle: a failing step is logged at `warn`
//! and does not abort the rest. There is no cross-instance coordination: sweeps may run on
//! every instance and are safe to repeat or overlap, because deletes are no-ops once the row
//! is gone and audit rows are written transactionally only when a row is actually deleted.

#![allow(unknown_lints, de0309_must_have_domain_model)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::audit::{AuditEntry, AuditOperation, AuditOutcome, FileEvent};
use crate::domain::multipart::MultipartUploadSession;
use crate::domain::policy::RetentionScope;
use crate::domain::ports::{CleanupStore, DeletedFile};
use crate::domain::storage_layout;
use crate::infra::backend::BackendRegistry;
use crate::infra::external_clients::{UsageDelta, UsageReporter};

/// Page size for the keyset-paginated retention file scan (bounds memory use).
const RETENTION_SWEEP_BATCH: u64 = 500;

/// Page size for the abandoned-pending-version phase (sweep step 1, first phase). Batches
/// are keyset-paginated by `(created_at, version_id)` until a short page or the per-tick
/// time budget; the rest is left for a later tick.
const ABANDONED_PENDING_SWEEP_BATCH: u64 = 500;

/// Page size for the versionless-files phase (step 1, second phase), keyset-paginated by
/// `(created_at, file_id)`.
const VERSIONLESS_SWEEP_BATCH: u64 = 500;

/// Page size for expired multipart sessions (step 2), keyset-paginated by
/// `(expires_at, upload_id)`.
const EXPIRED_MULTIPART_SWEEP_BATCH: u64 = 500;

/// Page size for expired `idempotency_keys` rows (step 4). No cursor: each batch deletes
/// what it selects, and the bound avoids one unbounded `DELETE` on a large backlog.
const EXPIRED_IDEMPOTENCY_SWEEP_BATCH: u64 = 500;

/// Default per-tick time budget for [`CleanupEngine::run_sweep`] (15 minutes), used unless
/// [`CleanupEngine::with_tick_budget`] is called.
const DEFAULT_SWEEP_TICK_BUDGET: Duration = Duration::from_mins(15);

/// Configuration knobs for the cleanup engine.
#[derive(Debug, Clone)]
pub struct CleanupConfig {
    /// Pending versions older than this many seconds are eligible for orphan reconciliation.
    pub orphan_grace_secs: u64,
}

/// Tally of what a single sweep cycle reconciled.
#[derive(Debug, Default, Clone)]
pub struct SweepResult {
    /// Number of abandoned pending version rows deleted (and their blobs).
    pub abandoned_pending_deleted: usize,
    /// Number of zero-version orphan `files` rows deleted after their last abandoned
    /// pending version was reclaimed.
    pub abandoned_files_deleted: usize,
    /// Number of expired in-progress multipart sessions aborted.
    pub expired_multipart_aborted: usize,
    /// Number of files deleted because a retention rule triggered.
    pub retention_expired_deleted: usize,
    /// Number of expired `idempotency_keys` rows deleted.
    pub idempotency_keys_deleted: u64,
    /// `true` when the time budget ([`CleanupEngine::with_tick_budget`]) ran out while a phase
    /// still had candidates; they resume on a later tick (retention from its saved cursor).
    pub budget_exhausted: bool,
    /// Wall-clock duration of this sweep tick, in milliseconds.
    pub elapsed_ms: u64,
}

/// The cleanup engine: orchestrates one cleanup sweep.
///
/// Call `run_sweep()` to execute one full cycle. The gear runs no background loop: a
/// separate cleanup job is expected to call this. Backend blob-without-row reconciliation
/// (enumerating via `list_paths`) is not done, as it would need cross-instance coordination.
pub struct CleanupEngine {
    store: Arc<dyn CleanupStore>,
    backends: BackendRegistry,
    config: CleanupConfig,
    /// Usage-reporting sink; `None` disables reporting.
    usage_reporter: Option<Arc<dyn UsageReporter>>,
    /// Per-tick time budget for [`Self::run_sweep`] (see [`DEFAULT_SWEEP_TICK_BUDGET`]).
    tick_budget: Duration,
    /// Retention-sweep keyset cursor (`files.file_id`), carried across ticks (other phases
    /// restart every tick). `None` means start from the beginning.
    retention_cursor: Mutex<Option<Uuid>>,
}

impl CleanupEngine {
    #[must_use]
    pub fn new(
        store: Arc<dyn CleanupStore>,
        backends: BackendRegistry,
        config: CleanupConfig,
    ) -> Self {
        Self {
            store,
            backends,
            config,
            usage_reporter: None,
            tick_budget: DEFAULT_SWEEP_TICK_BUDGET,
            retention_cursor: Mutex::new(None),
        }
    }

    /// Install a usage-reporting sink (builder step, so `new()` call sites stay unchanged).
    #[must_use]
    pub fn with_usage_reporter(mut self, usage_reporter: Option<Arc<dyn UsageReporter>>) -> Self {
        self.usage_reporter = usage_reporter;
        self
    }

    /// Override the per-tick time budget (default: [`DEFAULT_SWEEP_TICK_BUDGET`]).
    #[must_use]
    pub fn with_tick_budget(mut self, tick_budget: Duration) -> Self {
        self.tick_budget = tick_budget;
        self
    }

    /// Fire-and-forget usage delta report; a failing reporter never blocks the sweep.
    fn report_usage(&self, delta: UsageDelta) {
        if let Some(reporter) = self.usage_reporter.clone() {
            tokio::spawn(async move {
                reporter.report(delta).await;
            });
        }
    }

    /// Run one sweep cycle (callable directly by a cleanup job, tests and admin use).
    ///
    /// Steps, each best-effort:
    /// 1. Abandoned pending versions older than the orphan grace window, except a version
    ///    backing a live `in_progress` multipart session (`expires_at > now`); then
    ///    permanently versionless `files` rows.
    /// 2. Expired multipart sessions (`expires_at < now`, still `in_progress`).
    /// 3. Retention-policy expiry (age / inactivity / metadata rules, all scopes).
    /// 4. Expired idempotency keys (`expires_at <= now`).
    ///
    /// Phases run batch by batch, round-robin, until all are exhausted or the per-tick
    /// budget is spent (checked only from the second pass, so each phase gets a batch).
    /// Concurrent sweeps are safe: the first writer wins and the rest get `Ok(false)`.
    #[tracing::instrument(skip_all)]
    pub async fn run_sweep(&self) -> SweepResult {
        let tick_start = Instant::now();
        // `None`: the budget overflows `Instant`, so treat it as unbounded.
        let deadline = tick_start.checked_add(self.tick_budget);

        let mut result = SweepResult::default();
        let now = OffsetDateTime::now_utc();
        let grace =
            time::Duration::seconds(i64::try_from(self.config.orphan_grace_secs).unwrap_or(3600));
        let grace_cutoff = now - grace;

        // Per-phase tick-local keyset cursor and an "exhausted" latch.
        let mut pending_after: Option<(OffsetDateTime, Uuid)> = None;
        let mut pending_done = false;
        let mut versionless_after: Option<(OffsetDateTime, Uuid)> = None;
        let mut versionless_done = false;
        let mut multipart_after: Option<(OffsetDateTime, Uuid)> = None;
        let mut multipart_done = false;
        let mut idempotency_done = false;

        // Rules are loaded once per tick. An empty set resets the persisted cursor; a load
        // failure skips the scan but keeps the cursor so the scan resumes after recovery.
        let (all_rules, rules_load_failed) = match self.store.list_all_retention_rules().await {
            Ok(rules) => (rules, false),
            Err(e) => {
                tracing::warn!(error = ?e, "cleanup: failed to list retention rules");
                (Vec::new(), true)
            }
        };
        let mut retention_after = *self
            .retention_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !rules_load_failed && all_rules.is_empty() {
            retention_after = None;
            *self
                .retention_cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        let mut retention_done = all_rules.is_empty();

        // Checked before each phase's batch from the second pass onward.
        let deadline_hit = |first_pass: bool| -> bool {
            !first_pass
                && match deadline {
                    Some(d) => Instant::now() >= d,
                    None => false,
                }
        };

        let mut budget_exhausted = false;
        let mut first_pass = true;
        loop {
            if !pending_done {
                if deadline_hit(first_pass) {
                    budget_exhausted = true;
                    break;
                }
                let (pending_deleted, files_deleted, exhausted, next_after) = self
                    .sweep_abandoned_pending_page(grace_cutoff, now, pending_after)
                    .await;
                result.abandoned_pending_deleted += pending_deleted;
                result.abandoned_files_deleted += files_deleted;
                pending_after = next_after;
                pending_done = exhausted;
            }

            if !versionless_done {
                if deadline_hit(first_pass) {
                    budget_exhausted = true;
                    break;
                }
                let (files_deleted, exhausted, next_after) = self
                    .sweep_versionless_files_page(grace_cutoff, versionless_after)
                    .await;
                result.abandoned_files_deleted += files_deleted;
                versionless_after = next_after;
                versionless_done = exhausted;
            }

            if !multipart_done {
                if deadline_hit(first_pass) {
                    budget_exhausted = true;
                    break;
                }
                let (aborted, files_deleted, exhausted, next_after) = self
                    .sweep_expired_multipart_page(now, multipart_after)
                    .await;
                result.expired_multipart_aborted += aborted;
                result.abandoned_files_deleted += files_deleted;
                multipart_after = next_after;
                multipart_done = exhausted;
            }

            if !retention_done {
                if deadline_hit(first_pass) {
                    budget_exhausted = true;
                    break;
                }
                let (deleted, exhausted, next_after) = self
                    .sweep_retention_expiry_page(now, &all_rules, retention_after)
                    .await;
                result.retention_expired_deleted += deleted;
                retention_after = next_after;
                retention_done = exhausted;
            }

            if !idempotency_done {
                if deadline_hit(first_pass) {
                    budget_exhausted = true;
                    break;
                }
                // Step 4. `audit_outbox`/`events_outbox` are not swept: `published_at` stays `NULL`
                // until the relay exists, so an age-based purge would drop undelivered rows.
                let (deleted, exhausted) = self.sweep_idempotency_page(now).await;
                result.idempotency_keys_deleted += deleted;
                idempotency_done = exhausted;
            }

            if pending_done
                && versionless_done
                && multipart_done
                && retention_done
                && idempotency_done
            {
                break;
            }
            first_pass = false;
        }

        // Persist the retention cursor for the next tick.
        *self
            .retention_cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = retention_after;

        result.budget_exhausted = budget_exhausted;
        result.elapsed_ms = u64::try_from(tick_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        result
    }

    /// Delete one batch of never-finalised pending versions older than `grace_cutoff`; blob
    /// cleanup is best-effort.
    ///
    /// A version backing a live `in_progress` multipart session (`expires_at > now`) is never
    /// selected; `now` is passed in so the guard uses the caller's own "now". `after` is the
    /// tick-local keyset cursor (`(created_at, version_id)`); it always advances to the last
    /// candidate seen, so a candidate that cannot be reclaimed does not starve the rest.
    ///
    /// Returns `(pending_versions_deleted, orphan_files_deleted, exhausted, next_after)`;
    /// `exhausted` once the batch was short or the list query failed (logged).
    async fn sweep_abandoned_pending_page(
        &self,
        grace_cutoff: OffsetDateTime,
        now: OffsetDateTime,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> (usize, usize, bool, Option<(OffsetDateTime, Uuid)>) {
        let versions = match self
            .store
            .list_abandoned_pending_versions(
                grace_cutoff,
                now,
                ABANDONED_PENDING_SWEEP_BATCH,
                after,
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "cleanup: failed to list abandoned pending versions"
                );
                return (0, 0, true, after);
            }
        };
        let exhausted = (versions.len() as u64) < ABANDONED_PENDING_SWEEP_BATCH;
        let next_after = versions
            .last()
            .map(|v| (v.created_at, v.version_id))
            .or(after);

        // Resolve all parent files in one batch (see `load_files_by_ids_for_audit`).
        let file_ids: Vec<Uuid> = {
            let mut seen = std::collections::HashSet::new();
            versions
                .iter()
                .map(|v| v.file_id)
                .filter(|id| seen.insert(*id))
                .collect()
        };
        let files_by_id = self.load_files_by_ids_for_audit(&file_ids).await;

        let mut pending_count = 0_usize;
        let mut files_count = 0_usize;
        for v in versions {
            let prefetched_file = files_by_id.get(&v.file_id).cloned();
            let (pending, files) = self
                .delete_abandoned_pending_version(
                    v.file_id,
                    v.version_id,
                    v.size,
                    &v.backend_id,
                    &v.backend_path,
                    prefetched_file,
                )
                .await;
            pending_count += pending;
            files_count += files;
        }
        (pending_count, files_count, exhausted, next_after)
    }

    /// Best-effort file lookup for audit tenant attribution; a failure is logged and treated as
    /// absent (nil tenant) rather than blocking reclamation.
    async fn load_file_for_audit(&self, file_id: Uuid) -> Option<file_storage_sdk::File> {
        match self.store.get_file(file_id).await {
            Ok(file) => file,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    file_id = %file_id,
                    "cleanup: failed to load file for audit tenant attribution"
                );
                None
            }
        }
    }

    /// Batched [`Self::load_file_for_audit`]: resolves `ids` in one round trip, keyed by
    /// `file_id`. A failed read is logged once and yields an empty map (nil audit tenant);
    /// empty `ids` skips the call.
    async fn load_files_by_ids_for_audit(
        &self,
        ids: &[Uuid],
    ) -> HashMap<Uuid, file_storage_sdk::File> {
        if ids.is_empty() {
            return HashMap::new();
        }
        match self.store.list_files_by_ids(ids).await {
            Ok(files) => files.into_iter().map(|f| (f.file_id, f)).collect(),
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    file_ids = ?ids,
                    "cleanup: failed to load files for audit tenant attribution"
                );
                HashMap::new()
            }
        }
    }

    /// Delete one abandoned pending version row, its backend blob and, if that leaves the
    /// parent with no versions and a `NULL` `content_id`, the orphaned `files` row.
    ///
    /// `size` is read back from `file_versions.size` (structurally `0`) so the usage debit
    /// stays correct if that changes. The delete is status-guarded (only while still
    /// `pending`): a concurrent `finalize_upload` flipping the version to `available` makes
    /// this a no-op returning `Ok(false)`, leaving row, blob and debit untouched.
    ///
    /// `prefetched_file` is the parent `File` if the caller already loaded it (reused for the
    /// audit `tenant_id` and passed to `maybe_delete_orphaned_file`).
    ///
    /// Returns `(pending_versions_deleted, orphan_files_deleted)`, each `0` or `1`. `pub`
    /// only so a unit test can drive the finalize race deterministically.
    pub async fn delete_abandoned_pending_version(
        &self,
        file_id: Uuid,
        version_id: Uuid,
        size: i64,
        backend_id: &str,
        backend_path: &str,
        prefetched_file: Option<file_storage_sdk::File>,
    ) -> (usize, usize) {
        let file = prefetched_file;
        let audit = AuditEntry {
            tenant_id: file.as_ref().map_or_else(Uuid::nil, |file| file.tenant_id),
            actor_kind: "system".to_owned(),
            actor_id: Uuid::nil(),
            file_id: Some(file_id),
            operation: AuditOperation::OrphanReconcile,
            outcome: AuditOutcome::Success,
            detail: serde_json::json!({
                "reason": "abandoned_pending_version",
                "version_id": version_id,
            }),
            occurred_at: OffsetDateTime::now_utc(),
        };
        match self
            .store
            .delete_pending_version(file_id, version_id, audit)
            .await
        {
            Ok(true) => {
                // `file_count_delta` is `0`: only the version row is gone here, the file's own
                // debit (if any) comes from `maybe_delete_orphaned_file`.
                if let Some(file) = file.as_ref() {
                    self.report_usage(UsageDelta {
                        tenant_id: file.tenant_id,
                        owner_id: file.owner_id,
                        bytes_delta: -size,
                        file_count_delta: 0,
                    });
                }

                // Row first, blob after: a failed blob delete only leaves an unreachable blob.
                self.best_effort_delete(backend_id, backend_path).await;
                // Reuse the caller's `prefetched_file` snapshot for the audit row.
                let files_deleted = self
                    .maybe_delete_orphaned_file(
                        file_id,
                        file,
                        "abandoned_pending_version_orphan_file",
                    )
                    .await;
                (1, files_deleted)
            }
            Ok(false) => {
                // Already removed by a concurrent sweep.
                (0, 0)
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    %file_id,
                    %version_id,
                    "cleanup: failed to delete abandoned pending version"
                );
                (0, 0)
            }
        }
    }

    /// Second phase of step 1: reclaim `files` rows that never received any version, which
    /// the pending-version phase cannot see. Such rows come from a crash between
    /// `create_file_bare`'s commit and the multipart plan's `insert_pending_version`, or from
    /// a failed `FileService::compensate_failed_multipart_initiate`.
    ///
    /// `after` is the tick-local keyset cursor (`(created_at, file_id)`), advancing as in
    /// [`Self::sweep_abandoned_pending_page`]. Returns `(orphan_files_deleted, exhausted,
    /// next_after)`.
    async fn sweep_versionless_files_page(
        &self,
        grace_cutoff: OffsetDateTime,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> (usize, bool, Option<(OffsetDateTime, Uuid)>) {
        let candidates = match self
            .store
            .list_versionless_orphan_files(grace_cutoff, VERSIONLESS_SWEEP_BATCH, after)
            .await
        {
            Ok(files) => files,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "cleanup: failed to list versionless orphan files"
                );
                return (0, true, after);
            }
        };
        let exhausted = (candidates.len() as u64) < VERSIONLESS_SWEEP_BATCH;
        let next_after = candidates
            .last()
            .map(|f| (f.created_at, f.file_id))
            .or(after);

        let mut count = 0_usize;
        for file in candidates {
            let file_id = file.file_id;
            // `maybe_delete_orphaned_file` re-verifies zero versions and any blocking multipart
            // session, so one that appears after the list query is not destroyed.
            count += self
                .maybe_delete_orphaned_file(file_id, Some(file), "versionless_orphan_file")
                .await;
        }
        (count, exhausted, next_after)
    }

    /// After deleting a file's last abandoned pending version, delete the parent `files` row
    /// too if it is now a permanent zero-version orphan (no versions, `content_id IS NULL`).
    ///
    /// The checks here are a cheap pre-filter on a pre-transaction snapshot. The
    /// authoritative guard (`CleanupStore::delete_orphan_file_with_event`) locks the `files`
    /// row and re-runs them, plus a no-active-multipart-session check, inside the delete's
    /// transaction. A version or session created in between aborts the delete, so a stale
    /// snapshot never causes data loss.
    ///
    /// `prefetched_file` is an already-read `File` snapshot (`None` if unavailable).
    /// `reason` is recorded in the audit row's `detail.reason` and the `file.deleted` event
    /// payload. Returns `1` if the file row was deleted, `0` otherwise.
    async fn maybe_delete_orphaned_file(
        &self,
        file_id: Uuid,
        prefetched_file: Option<file_storage_sdk::File>,
        reason: &str,
    ) -> usize {
        let Some(file) = self.orphan_candidate_file(file_id, prefetched_file).await else {
            return 0;
        };

        let audit = orphan_reconcile_audit(
            file_id,
            file.tenant_id,
            serde_json::json!({ "reason": reason }),
        );
        let event = Some(FileEvent {
            tenant_id: file.tenant_id,
            owner_id: file.owner_id,
            file_id: file.file_id,
            event_type: "file.deleted".to_owned(),
            payload: serde_json::json!({ "reason": reason }),
        });

        match self
            .store
            .delete_orphan_file_with_event(file_id, audit, event)
            .await
        {
            Ok(true) => {
                // Debit the file count only: a zero-version file never had bytes credited.
                self.report_usage(UsageDelta {
                    tenant_id: file.tenant_id,
                    owner_id: file.owner_id,
                    bytes_delta: 0,
                    file_count_delta: -1,
                });
                1
            }
            Ok(false) => {
                // In-transaction guard failed (a version now exists) or already removed.
                0
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    %file_id,
                    "cleanup: failed to delete orphaned zero-version file"
                );
                0
            }
        }
    }

    /// Pre-check whether `file_id` looks like a permanent zero-version orphan (no versions,
    /// `NULL` `content_id`). Returns the `File` to delete, or `None` if it is not (or no
    /// longer) an orphan or a lookup failed (logged).
    ///
    /// The version list is always re-fetched; `prefetched_file`, when `Some`, only replaces
    /// the `get_file` call. Its staleness is safe per
    /// [`Self::maybe_delete_orphaned_file`].
    async fn orphan_candidate_file(
        &self,
        file_id: Uuid,
        prefetched_file: Option<file_storage_sdk::File>,
    ) -> Option<file_storage_sdk::File> {
        let remaining = match self.store.list_versions(file_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    %file_id,
                    "cleanup: failed to list versions while checking for orphaned file"
                );
                return None;
            }
        };
        if !remaining.is_empty() {
            return None;
        }

        let file = self
            .resolve_orphan_candidate_row(file_id, prefetched_file)
            .await?;
        if file.content_id.is_some() {
            // Bound content means a version exists; the `remaining` snapshot was stale.
            return None;
        }

        if self.has_blocking_multipart_session(file_id).await {
            return None;
        }

        Some(file)
    }

    /// Resolve the `files` row for the orphan check: the caller's snapshot or a fresh lookup.
    /// `None` (row gone or lookup failed) means do not treat it as an orphan.
    async fn resolve_orphan_candidate_row(
        &self,
        file_id: Uuid,
        prefetched_file: Option<file_storage_sdk::File>,
    ) -> Option<file_storage_sdk::File> {
        if let Some(file) = prefetched_file {
            return Some(file);
        }
        match self.store.get_file(file_id).await {
            Ok(Some(file)) => Some(file),
            Ok(None) => None, // Already gone -- fine.
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    %file_id,
                    "cleanup: failed to fetch file while checking for orphaned file"
                );
                None
            }
        }
    }

    /// Whether `file_id` has a not-yet-expired multipart session that blocks orphan-file
    /// deletion.
    ///
    /// Step 1 keys only on a pending version's age, so a live session can have its backing
    /// version reclaimed in the same pass. Deleting the file then would cascade
    /// (`ON DELETE CASCADE`) to the `in_progress` `multipart_uploads` row and silently destroy
    /// the upload. Blocking leaves the file for a later pass, after the session is
    /// aborted or completed. A lookup failure counts as blocking (errs toward not deleting).
    async fn has_blocking_multipart_session(&self, file_id: Uuid) -> bool {
        match self.store.has_active_multipart_for_file(file_id).await {
            Ok(blocking) => blocking,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    %file_id,
                    "cleanup: failed to check active multipart sessions while \
                     checking for orphaned file"
                );
                true
            }
        }
    }

    /// Abort one batch of in-progress multipart sessions whose `expires_at` has passed.
    /// `after` is the tick-local keyset cursor `(expires_at, upload_id)`.
    ///
    /// Returns `(sessions_aborted, orphan_files_reclaimed, exhausted, next_after)`;
    /// `exhausted` as in [`Self::sweep_abandoned_pending_page`].
    async fn sweep_expired_multipart_page(
        &self,
        now: OffsetDateTime,
        after: Option<(OffsetDateTime, Uuid)>,
    ) -> (usize, usize, bool, Option<(OffsetDateTime, Uuid)>) {
        let sessions = match self
            .store
            .list_expired_multipart_uploads(now, EXPIRED_MULTIPART_SWEEP_BATCH, after)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    "cleanup: failed to list expired multipart uploads"
                );
                return (0, 0, true, after);
            }
        };
        let exhausted = (sessions.len() as u64) < EXPIRED_MULTIPART_SWEEP_BATCH;
        let next_after = sessions
            .last()
            .map(|s| (s.expires_at, s.upload_id))
            .or(after);

        // Resolve all parent files in one batch, as in `sweep_abandoned_pending_page`.
        let file_ids: Vec<Uuid> = {
            let mut seen = std::collections::HashSet::new();
            sessions
                .iter()
                .map(|s| s.file_id)
                .filter(|id| seen.insert(*id))
                .collect()
        };
        let files_by_id = self.load_files_by_ids_for_audit(&file_ids).await;

        let mut aborted_count = 0_usize;
        let mut files_count = 0_usize;
        for session in sessions {
            let prefetched_file = files_by_id.get(&session.file_id).cloned();
            let (aborted, files) = self
                .abort_expired_multipart_session(session, prefetched_file)
                .await;
            aborted_count += aborted;
            files_count += files;
        }
        (aborted_count, files_count, exhausted, next_after)
    }

    /// Abort one expired multipart session: win the `in_progress -> aborted` CAS first, then
    /// abort the backend upload handle and delete the pending version row. Returns
    /// `(sessions_aborted, orphan_files_reclaimed)`, each `0` or `1`.
    ///
    /// The CAS must come first (as in the user-driven `abort_multipart_upload`): it races
    /// `complete_multipart_upload`'s `in_progress -> completed`, and if the sweep loses
    /// (`Ok(false)`) the version may already be bound and must be left untouched.
    async fn abort_expired_multipart_session(
        &self,
        session: MultipartUploadSession,
        prefetched_file: Option<file_storage_sdk::File>,
    ) -> (usize, usize) {
        // `prefetched_file` comes from the page's batch load and is threaded down to
        // `orphan_candidate_file`; `None` falls back to `Uuid::nil()` rather than blocking.
        let file = prefetched_file;
        let audit_tenant_id = file.as_ref().map_or_else(Uuid::nil, |file| file.tenant_id);
        let abort_audit = AuditEntry {
            tenant_id: audit_tenant_id,
            actor_kind: "system".to_owned(),
            actor_id: Uuid::nil(),
            file_id: Some(session.file_id),
            operation: AuditOperation::MultipartAbort,
            outcome: AuditOutcome::Success,
            detail: serde_json::json!({
                "reason": "expired_multipart_session_cleanup",
                "upload_id": session.upload_id,
            }),
            occurred_at: OffsetDateTime::now_utc(),
        };
        match self
            .store
            .abort_multipart_upload(session.upload_id, abort_audit)
            .await
        {
            Ok(true) => {
                // CAS won: no concurrent complete can bind this version. Call the `_with_file`
                // variant directly to reuse the `file` read above.
                let files_reclaimed = self
                    .cleanup_expired_session_version_with_file(&session, file)
                    .await;
                (1, files_reclaimed)
            }
            Ok(false) => {
                // A concurrent complete/abort won; after a complete the version is bound.
                tracing::info!(
                    upload_id = %session.upload_id,
                    "cleanup: skipping version cleanup, session no longer in_progress \
                     (concurrent complete/abort won the race)"
                );
                (0, 0)
            }
            Err(e) => {
                tracing::warn!(error = ?e, upload_id = %session.upload_id,
                    "cleanup: failed to mark expired multipart upload as aborted");
                (0, 0)
            }
        }
    }

    /// Abort the backend upload and delete the pending version row for an expired multipart
    /// session, then check whether the parent file is now a permanent zero-version orphan.
    /// Returns `1` if the orphan file was also reclaimed, `0` otherwise.
    ///
    /// The version row may already be gone: step 1 only excludes `in_progress` sessions with
    /// `expires_at > now`, so an expired one can be reclaimed there first. The backend abort
    /// must still run (or an S3 multipart upload leaks), using the session's stored
    /// `backend_id`/`backend_path`, falling back to the default backend and the
    /// deterministic path for legacy sessions without them.
    ///
    /// The session is already `aborted`, so `has_active_for_file` no longer blocks the
    /// orphan reclaim that step 1 declined. Thin wrapper over
    /// [`Self::cleanup_expired_session_version_with_file`] with no prefetched `File`; `pub`
    /// only so a unit test can drive the interleaving deterministically.
    pub async fn cleanup_expired_session_version(&self, session: &MultipartUploadSession) -> usize {
        self.cleanup_expired_session_version_with_file(session, None)
            .await
    }

    /// Implementation behind [`Self::cleanup_expired_session_version`], with an optional
    /// already-read parent `File`.
    ///
    /// `prefetched_file` supplies the delete-audit `tenant_id` and is passed on to
    /// `maybe_delete_orphaned_file`; `None` fetches fresh. A snapshot taken before the abort
    /// is safe: `tenant_id` is stable and the orphan delete re-verifies inside its
    /// transaction.
    async fn cleanup_expired_session_version_with_file(
        &self,
        session: &MultipartUploadSession,
        prefetched_file: Option<file_storage_sdk::File>,
    ) -> usize {
        let ver = self
            .store
            .get_version(session.file_id, session.version_id)
            .await
            .ok()
            .flatten();

        // Best-effort: abort the backend upload. Resolve `(backend_id, backend_path)` from, in
        // order: the version row; the session's stored pair; the default backend with the
        // recomputed path (legacy sessions only; wrong if the upload was on another backend).
        let (backend_id, backend_path) = if let Some(v) = ver.as_ref() {
            (v.backend_id.clone(), v.backend_path.clone())
        } else if let (Some(backend_id), Some(backend_path)) =
            (session.backend_id.as_ref(), session.backend_path.as_ref())
        {
            (backend_id.clone(), backend_path.clone())
        } else {
            (
                self.backends.default_id().to_owned(),
                storage_layout::backend_path(session.file_id, session.version_id),
            )
        };
        self.backend_abort_multipart_best_effort(
            &backend_id,
            &backend_path,
            &session.backend_upload_handle,
            session.upload_id,
        )
        .await;

        // Reuse `prefetched_file` or fetch it: the one file read here, also handed to
        // `maybe_delete_orphaned_file`.
        let file = match prefetched_file {
            Some(file) => Some(file),
            None => self.load_file_for_audit(session.file_id).await,
        };
        // Status-guarded: matches zero rows if step 1 reclaimed the version or a racing complete
        // already flipped it to `available`.
        let del_audit = orphan_reconcile_audit(
            session.file_id,
            file.as_ref().map_or_else(Uuid::nil, |file| file.tenant_id),
            serde_json::json!({
                "reason": "expired_multipart_version_cleanup",
                "upload_id": session.upload_id,
                "version_id": session.version_id,
            }),
        );
        match self
            .store
            .delete_pending_version(session.file_id, session.version_id, del_audit)
            .await
        {
            Ok(true) => {
                // Also delete the object at this path: a completer may have assembled it
                // and crashed before finalizing the row, which `abort_multipart` cannot
                // reclaim. Only reached when the pending row was removed here.
                self.best_effort_delete(&backend_id, &backend_path).await;
            }
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    version_id = %session.version_id,
                    "cleanup: failed to delete pending version for expired multipart"
                );
            }
        }

        // The session is `aborted`, so `has_active_for_file` no longer blocks reclaiming a
        // zero-version parent (which step 1 correctly declined while it looked active).
        self.maybe_delete_orphaned_file(
            session.file_id,
            file,
            "abandoned_pending_version_orphan_file",
        )
        .await
    }

    /// Tell a backend to abort a multipart upload handle; log and ignore errors.
    async fn backend_abort_multipart_best_effort(
        &self,
        backend_id: &str,
        path: &str,
        handle: &str,
        upload_id: Uuid,
    ) {
        if let Ok(backend) = self.backends.get(backend_id)
            && let Err(e) = backend.abort_multipart(path, handle).await
        {
            tracing::warn!(
                error = ?e,
                %upload_id,
                "cleanup: backend abort_multipart failed (continuing)"
            );
        }
    }

    /// Delete files expired by a retention rule, one keyset page (by `file_id`) at a time, so
    /// memory stays bounded and a full-table scan can span several ticks.
    ///
    /// `all_rules` is loaded once per tick. `after` is the persisted cross-tick cursor
    /// ([`CleanupEngine::retention_cursor`]); restarting every tick would starve files late
    /// in keyset order.
    ///
    /// Returns `(files_deleted, exhausted, next_after)`:
    /// - a short page (< [`RETENTION_SWEEP_BATCH`]) means the table is scanned:
    ///   `exhausted = true`, `next_after = None`;
    /// - a full page means more remain: `exhausted = false`, `next_after = Some(..)` (deleting
    ///   rows does not shift the window since the next query filters `file_id > next_after`);
    /// - a query error keeps the cursor (`next_after = after`) and marks the phase
    ///   `exhausted` for this tick, so the same page is retried next tick.
    async fn sweep_retention_expiry_page(
        &self,
        now: OffsetDateTime,
        all_rules: &[crate::domain::policy::StoredRetentionRule],
        after: Option<Uuid>,
    ) -> (usize, bool, Option<Uuid>) {
        let batch = match self
            .store
            .list_all_files_for_sweep(after, RETENTION_SWEEP_BATCH)
            .await
        {
            Ok(batch) => batch,
            Err(e) => {
                tracing::warn!(error = ?e, "cleanup: failed to list files for retention sweep");
                return (0, true, after);
            }
        };
        if batch.is_empty() {
            return (0, true, None);
        }
        let exhausted = (batch.len() as u64) < RETENTION_SWEEP_BATCH;
        let next_after = batch.last().map(|f| f.file_id);
        let deleted = self.expire_batch(&batch, all_rules, now).await;
        (
            deleted,
            exhausted,
            if exhausted { None } else { next_after },
        )
    }

    /// Apply retention rules to one page of files. Returns the number deleted.
    async fn expire_batch(
        &self,
        batch: &[file_storage_sdk::File],
        all_rules: &[crate::domain::policy::StoredRetentionRule],
        now: OffsetDateTime,
    ) -> usize {
        // Fetch metadata in ONE query, only for files whose rules have a metadata criterion
        // (`needs_metadata`). No chunking: the 500-id `IN` list is far below the smallest
        // bind-parameter budget (`max_bind_params_for`).
        let need_metadata: Vec<Uuid> = batch
            .iter()
            .filter(|f| Self::needs_metadata(all_rules, f))
            .map(|f| f.file_id)
            .collect();
        let prefetched = if need_metadata.is_empty() {
            Some(std::collections::HashMap::new())
        } else {
            match self.store.list_metadata_for_files(&need_metadata).await {
                Ok(map) => Some(map),
                Err(e) => {
                    // Metadata unreadable: skip rather than expire on incomplete data.
                    tracing::warn!(
                        error = ?e,
                        page_size = batch.len(),
                        "cleanup: failed to batch-fetch metadata for retention check -- \
                         files with metadata-criterion rules are skipped this pass"
                    );
                    None
                }
            }
        };

        let mut count = 0_usize;
        for file in batch {
            count += self
                .maybe_expire_file(file, all_rules, now, prefetched.as_ref())
                .await;
        }
        count
    }

    /// Whether any retention rule applicable to `file` has a metadata criterion, i.e. whether
    /// [`Self::maybe_expire_file`] needs the file's custom metadata. Shared with
    /// [`Self::expire_batch`]'s prefetch so the two cannot disagree.
    fn needs_metadata(
        all_rules: &[crate::domain::policy::StoredRetentionRule],
        file: &file_storage_sdk::File,
    ) -> bool {
        all_rules
            .iter()
            .any(|r| rule_applies_to_file(r, file) && r.body.metadata.is_some())
    }

    /// Apply retention rules to one file. Returns 1 if deleted, 0 otherwise.
    async fn maybe_expire_file(
        &self,
        file: &file_storage_sdk::File,
        all_rules: &[crate::domain::policy::StoredRetentionRule],
        now: OffsetDateTime,
        prefetched_metadata: Option<
            &std::collections::HashMap<Uuid, Vec<file_storage_sdk::CustomMetadataEntry>>,
        >,
    ) -> usize {
        let applicable: Vec<&crate::domain::policy::StoredRetentionRule> = all_rules
            .iter()
            .filter(|r| rule_applies_to_file(r, file))
            .collect();

        if applicable.is_empty() {
            return 0;
        }

        // Only fetched when a rule has a metadata criterion (see `needs_metadata`).
        let metadata: &[file_storage_sdk::CustomMetadataEntry] =
            if applicable.iter().any(|r| r.body.metadata.is_some()) {
                match prefetched_metadata {
                    // Absent from the map: the file has no custom metadata rows.
                    Some(map) => map.get(&file.file_id).map_or(&[][..], Vec::as_slice),
                    // The page batch fetch failed (logged by `expire_batch`): skip.
                    None => return 0,
                }
            } else {
                &[]
            };

        // OR semantics: if any rule triggers, delete the file.
        let should_expire = applicable
            .iter()
            .any(|r| rule_matches(&r.body, file, metadata, now));

        if !should_expire {
            return 0;
        }

        self.expire_file(file, now).await
    }

    /// Delete one retention-expired file (DB row + backend blobs). Returns 1 if deleted.
    async fn expire_file(&self, file: &file_storage_sdk::File, now: OffsetDateTime) -> usize {
        let audit = AuditEntry {
            tenant_id: file.tenant_id,
            actor_kind: "system".to_owned(),
            actor_id: Uuid::nil(),
            file_id: Some(file.file_id),
            operation: AuditOperation::RetentionDelete,
            outcome: AuditOutcome::Success,
            detail: serde_json::json!({
                "reason": "retention_policy_expired",
                "file_id": file.file_id,
                "expired_at": now,
            }),
            occurred_at: now,
        };

        // Emit `file.deleted` like user-initiated deletes; plain `delete_file` skips the event.
        let event = Some(FileEvent {
            tenant_id: file.tenant_id,
            owner_id: file.owner_id,
            file_id: file.file_id,
            event_type: "file.deleted".to_owned(),
            payload: serde_json::json!({
                "reason": "retention_policy_expired",
                "expired_at": now,
            }),
        });

        let scope = toolkit_security::AccessScope::allow_all();
        match self
            .store
            .delete_file_with_event_collecting_versions(&scope, file.file_id, None, audit, event)
            .await
        {
            Ok(DeletedFile {
                removed: true,
                versions,
            }) => {
                // Debit the whole file, as the user-initiated delete path does.
                let total_bytes: i64 = versions.iter().map(|v| v.size).sum();
                self.report_usage(UsageDelta {
                    tenant_id: file.tenant_id,
                    owner_id: file.owner_id,
                    bytes_delta: -total_bytes,
                    file_count_delta: -1,
                });

                for v in &versions {
                    self.best_effort_delete(&v.backend_id, &v.backend_path)
                        .await;
                }
                1
            }
            Ok(DeletedFile { removed: false, .. }) => {
                // Already deleted by a concurrent sweep.
                0
            }
            Err(e) => {
                tracing::warn!(
                    error = ?e,
                    file_id = %file.file_id,
                    "cleanup: failed to delete retention-expired file"
                );
                0
            }
        }
    }

    /// Delete one batch of expired `idempotency_keys` rows (`expires_at <= now`). No cursor:
    /// each call deletes what it selects. Returns `(rows_deleted, exhausted)`; `exhausted`
    /// once the batch was short or the delete errored (logged).
    async fn sweep_idempotency_page(&self, now: OffsetDateTime) -> (u64, bool) {
        match self
            .store
            .delete_expired_idempotency_keys(now, EXPIRED_IDEMPOTENCY_SWEEP_BATCH)
            .await
        {
            Ok(deleted) => (deleted, deleted < EXPIRED_IDEMPOTENCY_SWEEP_BATCH),
            Err(e) => {
                tracing::warn!(error = ?e, "cleanup: failed to delete expired idempotency keys");
                (0, true)
            }
        }
    }

    /// Delete a blob from a backend; errors are logged, not propagated.
    async fn best_effort_delete(&self, backend_id: &str, path: &str) {
        let Ok(backend) = self.backends.get(backend_id) else {
            tracing::warn!(
                backend_id,
                path,
                "cleanup: backend not found for best-effort delete"
            );
            return;
        };
        if let Err(e) = backend.delete(path).await {
            tracing::warn!(
                error = ?e,
                path,
                "cleanup: best-effort backend delete failed"
            );
        }
    }
}

/// Build a system-actor `OrphanReconcile` audit entry.
fn orphan_reconcile_audit(file_id: Uuid, tenant_id: Uuid, detail: serde_json::Value) -> AuditEntry {
    AuditEntry {
        tenant_id,
        actor_kind: "system".to_owned(),
        actor_id: Uuid::nil(),
        file_id: Some(file_id),
        operation: AuditOperation::OrphanReconcile,
        outcome: AuditOutcome::Success,
        detail,
        occurred_at: OffsetDateTime::now_utc(),
    }
}

/// Return `true` when a retention rule applies to `file` based on its scope.
fn rule_applies_to_file(
    rule: &crate::domain::policy::StoredRetentionRule,
    file: &file_storage_sdk::File,
) -> bool {
    rule.tenant_id == file.tenant_id
        && match rule.scope {
            RetentionScope::Tenant => true,
            RetentionScope::User => rule.scope_target_id == Some(file.owner_id),
            RetentionScope::File => rule.scope_target_id == Some(file.file_id),
        }
}

/// Whether `body` triggers expiry for `file` (OR across criteria).
fn rule_matches(
    body: &crate::domain::policy::RetentionRuleBody,
    file: &file_storage_sdk::File,
    metadata: &[file_storage_sdk::CustomMetadataEntry],
    now: OffsetDateTime,
) -> bool {
    if let Some(age) = &body.age {
        let max_age = time::Duration::days(i64::from(age.max_age_days));
        if now - file.created_at > max_age {
            return true;
        }
    }

    if let Some(inact) = &body.inactivity {
        let inact_dur = time::Duration::days(i64::from(inact.inactivity_days));
        if now - file.last_modified_at > inact_dur {
            return true;
        }
    }

    if let Some(meta_rule) = &body.metadata
        && metadata
            .iter()
            .any(|e| e.key == meta_rule.key && e.value == meta_rule.value)
    {
        return true;
    }

    false
}
