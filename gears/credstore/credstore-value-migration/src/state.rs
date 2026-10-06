// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! The tool's own tables: where the progress of a migration lives.
//!
//! Two tables, created by the tool and never touched by the gear's migrations
//! (the `m0002` guard only reads the header):
//!
//! * `credstore_value_migration` - one header row: the [`Phase`] the migration
//!   is in and the operator's persisted decisions (`accept_losses`,
//!   `discard_values`);
//! * `credstore_value_migration_rows` - one row per credential row of the
//!   shipped `credstore_secrets`, snapshotted at the start: the old address
//!   (tenant, reference, owner), the fingerprint columns that the gear's
//!   `m0002` drops, the [`RowState`] and the `value_version` the new store
//!   returned. Neither table ever holds a secret value or a fence key.
//!
//! The tool never `COUNT`s these tables: progress is a log line per batch and
//! counters in memory; an operator may of course query them.

use std::fmt;

use credstore::infra::storage::migrations::m0002_value_versions::VALUE_MIGRATION_STATE_TABLE;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, TransactionTrait, Value};
use uuid::Uuid;

use crate::db::{self, ph, stmt};
use crate::error::MigrationError;

/// The header table; also the marker the `m0002` guard looks for.
pub const HEADER_TABLE: &str = VALUE_MIGRATION_STATE_TABLE;
/// The per-credential-row table.
pub const ROWS_TABLE: &str = "credstore_value_migration_rows";

const STATUS_ACTIVE: i16 = 2;

/// Where a migration is. Persisted in the header; every phase is idempotent and
/// a restart resumes in the persisted one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    /// Snapshot taken and values being checked; nothing is persisted per row
    /// yet, so a re-run starts over (and re-takes the snapshot).
    Verifying,
    /// Values are being copied into the new store; the snapshot is frozen.
    Copying,
    /// Copying finished; the gear's schema migrations are applied next. From
    /// this phase on the `m0002` guard lets the migration run.
    Schema,
    /// Rows are being pointed at their new versions.
    Activating,
    /// Versions left behind by interrupted writes are being destroyed.
    Tidying,
    /// Finished.
    Done,
}

impl Phase {
    /// Every phase, in order.
    pub const ALL: [Self; 6] = [
        Self::Verifying,
        Self::Copying,
        Self::Schema,
        Self::Activating,
        Self::Tidying,
        Self::Done,
    ];

    /// The name stored in the header (and read by the `m0002` guard).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verifying => "verifying",
            Self::Copying => "copying",
            Self::Schema => "schema",
            Self::Activating => "activating",
            Self::Tidying => "tidying",
            Self::Done => "done",
        }
    }

    /// Parses a stored name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }

    /// Whether copying has finished, so the gear's schema migration may run.
    #[must_use]
    pub fn copy_finished(self) -> bool {
        self >= Self::Schema
    }

    /// The phase after this one ([`Phase::Done`] is its own successor).
    #[must_use]
    pub const fn next(self) -> Self {
        match self {
            Self::Verifying => Self::Copying,
            Self::Copying => Self::Schema,
            Self::Schema => Self::Activating,
            Self::Activating => Self::Tidying,
            Self::Tidying | Self::Done => Self::Done,
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the migration decided about one credential row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RowState {
    /// Snapshotted, an `active` row whose value is still to be copied.
    Pending,
    /// Fingerprint verified, value copied to the new store.
    Copied,
    /// The row carried no fingerprint (seeded out of band; the shipped gear
    /// served such rows on trust): value copied, but never verified.
    UnverifiedCopied,
    /// The old store held no value for an `active` row. Nothing copied.
    Missing,
    /// The value failed the fingerprint check. Not copied; kept as evidence.
    FpMismatch,
    /// `fp_key_id` names a fence key other than the one the shipped gear used,
    /// so the fingerprint cannot be verified. Not copied; kept as evidence.
    UnknownFenceKey,
    /// The row was `provisioning` or `deprovisioning` (status `1`/`3`):
    /// nothing to copy; its old entry, if any, is only listed for cleanup.
    Unfinished,
    /// The row was changed or deleted after the snapshot, so the copied value
    /// is not the one it points at.
    Superseded,
    /// `migrate --discard-values`: the old backend held no durable values.
    Discarded,
}

impl RowState {
    /// Every state, in display order.
    pub const ALL: [Self; 9] = [
        Self::Pending,
        Self::Copied,
        Self::UnverifiedCopied,
        Self::Missing,
        Self::FpMismatch,
        Self::UnknownFenceKey,
        Self::Unfinished,
        Self::Superseded,
        Self::Discarded,
    ];

    /// The name stored in the `state` column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Copied => "copied",
            Self::UnverifiedCopied => "unverified_copied",
            Self::Missing => "missing",
            Self::FpMismatch => "fp_mismatch",
            Self::UnknownFenceKey => "unknown_fence_key",
            Self::Unfinished => "unfinished",
            Self::Superseded => "superseded",
            Self::Discarded => "discarded",
        }
    }

    /// Parses a stored name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }

    /// The value was copied to the new store (the row has a `value_version`).
    #[must_use]
    pub fn is_copied(self) -> bool {
        matches!(self, Self::Copied | Self::UnverifiedCopied)
    }

    /// The row ends up without a value.
    #[must_use]
    pub fn is_loss(self) -> bool {
        matches!(
            self,
            Self::Missing | Self::FpMismatch | Self::UnknownFenceKey
        )
    }

    /// The old entry is kept by `cleanup` as evidence.
    #[must_use]
    pub fn is_evidence(self) -> bool {
        matches!(self, Self::FpMismatch | Self::UnknownFenceKey)
    }
}

impl fmt::Display for RowState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `state IN ('a', 'b')` for the given states. Built from the enum, never from
/// input.
#[must_use]
pub fn states_in(states: &[RowState]) -> String {
    let list: Vec<String> = states.iter().map(|s| format!("'{}'", s.as_str())).collect();
    format!("state IN ({})", list.join(", "))
}

/// The header row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Where the migration is.
    pub phase: Phase,
    /// The operator accepted that some rows end up without a value.
    pub accept_losses: bool,
    /// `migrate --discard-values`: no value is copied, every row is discarded.
    pub discard_values: bool,
}

/// One credential row of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressRow {
    /// `credstore_secrets.id`, also the new store's `record_id`.
    pub id: Uuid,
    /// Tenant of the row.
    pub tenant_id: Uuid,
    /// Reference of the row (part of the old address).
    pub reference: String,
    /// Sharing code: `1` private, `2`/`3` non-private.
    pub sharing: i16,
    /// `owner_id` column (nil for non-private rows).
    pub owner_id: Uuid,
    /// Status of the row before the migration: `1`, `2` or `3`.
    pub status_before: i16,
    /// Secret type of the row (UUID of its GTS type id).
    pub secret_type_uuid: Uuid,
    /// Value fingerprint as shipped (`NULL` for rows seeded out of band).
    pub value_fp: Option<Vec<u8>>,
    /// Fence key id of the fingerprint.
    pub fp_key_id: Option<i16>,
    /// What the migration decided.
    pub state: RowState,
    /// The version the new store returned (copied rows only).
    pub value_version: Option<String>,
    /// The row has been pointed at its new version (or suppressed).
    pub activated: bool,
    /// Versions below `value_version` have been destroyed.
    pub tidied: bool,
}

impl ProgressRow {
    /// The owner of the old address: `Some` only for a private row (the owner's
    /// key class), `None` for the tenant key class - exactly what the shipped
    /// gear passed to the plugin.
    #[must_use]
    pub fn legacy_owner(&self) -> Option<Uuid> {
        (self.sharing == 1).then_some(self.owner_id)
    }
}

const ROW_COLUMNS: &str = "id, tenant_id, reference, sharing, owner_id, status_before, \
     secret_type_uuid, value_fp, fp_key_id, state, value_version, activated, tidied";

fn row_from(r: &sea_orm::QueryResult) -> Result<ProgressRow, MigrationError> {
    let id: Uuid = r.try_get("", "id")?;
    let state: String = r.try_get("", "state")?;
    let state = RowState::parse(&state).ok_or_else(|| MigrationError::BadRow {
        id,
        reason: format!("unknown progress state {state:?}"),
    })?;
    Ok(ProgressRow {
        id,
        tenant_id: r.try_get("", "tenant_id")?,
        reference: r.try_get("", "reference")?,
        sharing: r.try_get("", "sharing")?,
        owner_id: r.try_get("", "owner_id")?,
        status_before: r.try_get("", "status_before")?,
        secret_type_uuid: r.try_get("", "secret_type_uuid")?,
        value_fp: r.try_get("", "value_fp")?,
        fp_key_id: r.try_get("", "fp_key_id")?,
        state,
        value_version: r.try_get("", "value_version")?,
        activated: r.try_get("", "activated")?,
        tidied: r.try_get("", "tidied")?,
    })
}

/// Creates both tables when they are missing. Idempotent.
///
/// # Errors
///
/// A failing statement.
pub async fn create_tables(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
) -> Result<(), MigrationError> {
    let phases = Phase::ALL.map(|p| format!("'{}'", p.as_str())).join(", ");
    let states = RowState::ALL
        .map(|s| format!("'{}'", s.as_str()))
        .join(", ");
    // (uuid, bytes, boolean true literal, timestamp) per backend.
    let (uuid, bytes, ts) = match backend {
        DatabaseBackend::Postgres => ("UUID", "BYTEA", "TIMESTAMPTZ"),
        _ => ("BLOB", "BLOB", "TEXT"),
    };
    let statements = [
        format!(
            "CREATE TABLE IF NOT EXISTS {HEADER_TABLE} (\
             id SMALLINT PRIMARY KEY CHECK (id = 1), \
             phase TEXT NOT NULL CHECK (phase IN ({phases})), \
             accept_losses BOOLEAN NOT NULL DEFAULT FALSE, \
             discard_values BOOLEAN NOT NULL DEFAULT FALSE, \
             started_at {ts} NOT NULL DEFAULT CURRENT_TIMESTAMP, \
             updated_at {ts} NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {ROWS_TABLE} (\
             id {uuid} PRIMARY KEY NOT NULL, \
             tenant_id {uuid} NOT NULL, \
             reference TEXT NOT NULL, \
             sharing SMALLINT NOT NULL, \
             owner_id {uuid} NOT NULL, \
             status_before SMALLINT NOT NULL, \
             secret_type_uuid {uuid} NOT NULL, \
             value_fp {bytes} NULL, \
             fp_key_id SMALLINT NULL, \
             state TEXT NOT NULL CHECK (state IN ({states})), \
             value_version TEXT NULL, \
             activated BOOLEAN NOT NULL DEFAULT FALSE, \
             tidied BOOLEAN NOT NULL DEFAULT FALSE, \
             error TEXT NULL)"
        ),
        format!("CREATE INDEX IF NOT EXISTS idx_{ROWS_TABLE}_state ON {ROWS_TABLE} (state, id)"),
        // The type-divergence report joins rows on the reference.
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{ROWS_TABLE}_ref ON {ROWS_TABLE} (tenant_id, reference)"
        ),
    ];
    for sql in &statements {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

/// Drops both tables. The caller has decided that the progress is no longer
/// needed.
///
/// # Errors
///
/// A failing statement.
pub async fn drop_tables(db: &DatabaseConnection) -> Result<(), MigrationError> {
    db.execute_unprepared(&format!("DROP TABLE IF EXISTS {ROWS_TABLE}"))
        .await?;
    db.execute_unprepared(&format!("DROP TABLE IF EXISTS {HEADER_TABLE}"))
        .await?;
    Ok(())
}

/// Reads the header; `None` when the tables or the row do not exist (no
/// migration has been started).
///
/// # Errors
///
/// A failing statement, or a phase name the tool does not know.
pub async fn load_header(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
) -> Result<Option<Header>, MigrationError> {
    if !db::table_exists(db, backend, HEADER_TABLE).await? {
        return Ok(None);
    }
    let sql =
        format!("SELECT phase, accept_losses, discard_values FROM {HEADER_TABLE} WHERE id = 1");
    let Some(row) = db.query_one_raw(stmt(backend, &sql, vec![])).await? else {
        return Ok(None);
    };
    let phase: String = row.try_get("", "phase")?;
    let phase = Phase::parse(&phase).ok_or_else(|| {
        MigrationError::State(format!("unknown phase {phase:?} in {HEADER_TABLE}"))
    })?;
    Ok(Some(Header {
        phase,
        accept_losses: row.try_get("", "accept_losses")?,
        discard_values: row.try_get("", "discard_values")?,
    }))
}

/// Executes a statement and returns the number of rows it changed.
async fn exec(
    conn: &impl ConnectionTrait,
    backend: DatabaseBackend,
    sql: &str,
    values: Vec<Value>,
) -> Result<u64, MigrationError> {
    Ok(conn
        .execute_raw(stmt(backend, sql, values))
        .await?
        .rows_affected())
}

/// Checks the shipped rows for values the tool cannot snapshot.
async fn validate_shipped_rows(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
) -> Result<(), MigrationError> {
    for (column, what) in [("status", "status"), ("sharing", "sharing code")] {
        let sql = format!(
            "SELECT id, {column} AS bad FROM credstore_secrets \
             WHERE {column} NOT IN (1, 2, 3) LIMIT 1"
        );
        if let Some(row) = db.query_one_raw(stmt(backend, &sql, vec![])).await? {
            let bad: i16 = row.try_get("", "bad")?;
            return Err(MigrationError::BadRow {
                id: row.try_get("", "id")?,
                reason: format!("the shipped schema does not produce {what} {bad}"),
            });
        }
    }
    Ok(())
}

/// Snapshots the shipped `credstore_secrets` into the progress table, in one
/// transaction together with the header.
///
/// With `header_exists` (a re-run while still [`Phase::Verifying`]) the old
/// snapshot is replaced and the persisted decisions are kept: nothing has been
/// decided per row yet, and the old credstore may have run in between.
/// Every `active` row becomes `pending`, or `discarded` with `discard`; every
/// other row `unfinished`. With `discard` the header starts in
/// [`Phase::Schema`] (there is nothing to verify or copy).
///
/// # Errors
///
/// A failing statement, or a row the shipped schema cannot produce.
pub async fn take_snapshot(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    header_exists: bool,
    discard: bool,
) -> Result<(), MigrationError> {
    create_tables(db, backend).await?;
    validate_shipped_rows(db, backend).await?;
    let phase = if discard {
        Phase::Schema
    } else {
        Phase::Verifying
    };
    let active_state = if discard {
        RowState::Discarded
    } else {
        RowState::Pending
    };

    let txn = db.begin().await?;
    exec(&txn, backend, &format!("DELETE FROM {ROWS_TABLE}"), vec![]).await?;
    if header_exists {
        let sql = format!(
            "UPDATE {HEADER_TABLE} SET phase = {}, discard_values = {}, \
             updated_at = CURRENT_TIMESTAMP WHERE id = 1",
            ph(backend, 1),
            ph(backend, 2)
        );
        exec(
            &txn,
            backend,
            &sql,
            vec![phase.as_str().into(), discard.into()],
        )
        .await?;
    } else {
        let sql = format!(
            "INSERT INTO {HEADER_TABLE} (id, phase, accept_losses, discard_values) \
             VALUES (1, {}, FALSE, {})",
            ph(backend, 1),
            ph(backend, 2)
        );
        exec(
            &txn,
            backend,
            &sql,
            vec![phase.as_str().into(), discard.into()],
        )
        .await?;
    }
    // The two state names are constants of the enum, not input: inlined, so the
    // statement needs no parameter whose type `PostgreSQL` would have to infer.
    let sql = format!(
        "INSERT INTO {ROWS_TABLE} (id, tenant_id, reference, sharing, owner_id, status_before, \
         secret_type_uuid, value_fp, fp_key_id, state) \
         SELECT id, tenant_id, reference, sharing, owner_id, status, secret_type_uuid, value_fp, \
         fp_key_id, CASE WHEN status = {STATUS_ACTIVE} THEN '{}' ELSE '{}' END \
         FROM credstore_secrets",
        active_state.as_str(),
        RowState::Unfinished.as_str()
    );
    exec(&txn, backend, &sql, vec![]).await?;
    txn.commit().await?;
    Ok(())
}

/// Moves the header from phase `from` to `to` (a compare-and-set on the phase).
///
/// # Errors
///
/// A failing statement, or [`MigrationError::State`] when the header was not
/// in `from`.
pub async fn set_phase(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    from: Phase,
    to: Phase,
) -> Result<(), MigrationError> {
    let sql = format!(
        "UPDATE {HEADER_TABLE} SET phase = {}, updated_at = CURRENT_TIMESTAMP \
         WHERE id = 1 AND phase = {}",
        ph(backend, 1),
        ph(backend, 2)
    );
    let changed = exec(
        db,
        backend,
        &sql,
        vec![to.as_str().into(), from.as_str().into()],
    )
    .await?;
    if changed == 1 {
        Ok(())
    } else {
        Err(MigrationError::State(format!(
            "the migration was not in phase {from} when moving to {to}: another run changed it"
        )))
    }
}

/// Persists the operator's decision to accept rows that end up without a value.
///
/// # Errors
///
/// A failing statement.
pub async fn persist_accept_losses(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
) -> Result<(), MigrationError> {
    let sql = format!(
        "UPDATE {HEADER_TABLE} SET accept_losses = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = 1"
    );
    exec(db, backend, &sql, vec![]).await?;
    Ok(())
}

/// A page of rows matching `predicate` (a `WHERE` fragment built from
/// constants), in id order, after the cursor.
///
/// # Errors
///
/// A failing statement or an undecodable row.
pub async fn fetch_rows(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    predicate: &str,
    after: Option<Uuid>,
    limit: u32,
) -> Result<Vec<ProgressRow>, MigrationError> {
    let (cursor, values) = match after {
        Some(id) => (format!(" AND id > {}", ph(backend, 1)), vec![id.into()]),
        None => (String::new(), vec![]),
    };
    let sql = format!(
        "SELECT {ROW_COLUMNS} FROM {ROWS_TABLE} WHERE {predicate}{cursor} ORDER BY id LIMIT {limit}"
    );
    let rows = db.query_all_raw(stmt(backend, &sql, values)).await?;
    rows.iter().map(row_from).collect()
}

/// A page of `(id, state)` pairs after the cursor, for tallies.
///
/// # Errors
///
/// A failing statement or an unknown state.
pub async fn fetch_states(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    after: Option<Uuid>,
    limit: u32,
) -> Result<Vec<(Uuid, RowState)>, MigrationError> {
    let (cursor, values) = match after {
        Some(id) => (format!(" WHERE id > {}", ph(backend, 1)), vec![id.into()]),
        None => (String::new(), vec![]),
    };
    let sql = format!("SELECT id, state FROM {ROWS_TABLE}{cursor} ORDER BY id LIMIT {limit}");
    let rows = db.query_all_raw(stmt(backend, &sql, values)).await?;
    rows.iter()
        .map(|r| {
            let id: Uuid = r.try_get("", "id")?;
            let state: String = r.try_get("", "state")?;
            let state = RowState::parse(&state).ok_or_else(|| MigrationError::BadRow {
                id,
                reason: format!("unknown progress state {state:?}"),
            })?;
            Ok((id, state))
        })
        .collect()
}

/// How many rows are in each state, tallied by scanning the table in id order
/// (the tool never `COUNT`s).
///
/// # Errors
///
/// A failing statement or an unknown state.
pub async fn tally(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    batch_size: u32,
) -> Result<std::collections::BTreeMap<RowState, usize>, MigrationError> {
    let mut tally = std::collections::BTreeMap::new();
    let mut after = None;
    loop {
        let page = fetch_states(db, backend, after, batch_size).await?;
        let Some((last, _)) = page.last() else {
            return Ok(tally);
        };
        after = Some(*last);
        for (_, state) in &page {
            *tally.entry(*state).or_insert(0) += 1;
        }
    }
}

/// Whether any row matches `predicate`.
///
/// # Errors
///
/// A failing statement.
pub async fn any_row(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    predicate: &str,
) -> Result<bool, MigrationError> {
    let sql = format!("SELECT 1 AS present FROM {ROWS_TABLE} WHERE {predicate} LIMIT 1");
    db::exists(db, backend, &sql, vec![]).await
}

/// Records that the row's value was copied.
///
/// # Errors
///
/// A failing statement, or [`MigrationError::State`] when the row was no
/// longer `pending`.
pub async fn mark_copied(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    id: Uuid,
    state: RowState,
    version: &str,
) -> Result<(), MigrationError> {
    let sql = format!(
        "UPDATE {ROWS_TABLE} SET state = {}, value_version = {}, error = NULL \
         WHERE id = {} AND state = 'pending'",
        ph(backend, 1),
        ph(backend, 2),
        ph(backend, 3)
    );
    let changed = exec(
        db,
        backend,
        &sql,
        vec![state.as_str().into(), version.into(), id.into()],
    )
    .await?;
    expect_one(changed, id)
}

/// Records that the row ends up without a value.
///
/// # Errors
///
/// A failing statement, or [`MigrationError::State`] when the row was no
/// longer `pending`.
pub async fn mark_loss(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    id: Uuid,
    state: RowState,
) -> Result<(), MigrationError> {
    let sql = format!(
        "UPDATE {ROWS_TABLE} SET state = {}, error = NULL WHERE id = {} AND state = 'pending'",
        ph(backend, 1),
        ph(backend, 2)
    );
    let changed = exec(db, backend, &sql, vec![state.as_str().into(), id.into()]).await?;
    expect_one(changed, id)
}

fn expect_one(changed: u64, id: Uuid) -> Result<(), MigrationError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(MigrationError::State(format!(
            "progress row {id} was not in the expected state"
        )))
    }
}

/// Marks the row activated, and `superseded` when `superseded` is set. Runs on
/// the activation transaction.
///
/// # Errors
///
/// A failing statement.
pub async fn mark_activated(
    conn: &impl ConnectionTrait,
    backend: DatabaseBackend,
    id: Uuid,
    superseded: bool,
) -> Result<(), MigrationError> {
    let sql = if superseded {
        format!(
            "UPDATE {ROWS_TABLE} SET activated = TRUE, state = 'superseded', error = NULL \
             WHERE id = {}",
            ph(backend, 1)
        )
    } else {
        format!(
            "UPDATE {ROWS_TABLE} SET activated = TRUE, error = NULL WHERE id = {}",
            ph(backend, 1)
        )
    };
    exec(conn, backend, &sql, vec![id.into()]).await?;
    Ok(())
}

/// Marks the row's superseded versions destroyed.
///
/// # Errors
///
/// A failing statement.
pub async fn mark_tidied(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    id: Uuid,
) -> Result<(), MigrationError> {
    let sql = format!(
        "UPDATE {ROWS_TABLE} SET tidied = TRUE, error = NULL WHERE id = {}",
        ph(backend, 1)
    );
    exec(db, backend, &sql, vec![id.into()]).await?;
    Ok(())
}

/// Stores the last error text on a row, best effort, so an operator can see
/// where a run stopped. The text comes from a store error and never carries a
/// value; it is cut to 300 characters.
pub async fn record_error(db: &DatabaseConnection, backend: DatabaseBackend, id: Uuid, text: &str) {
    let text: String = text.chars().take(300).collect();
    let sql = format!(
        "UPDATE {ROWS_TABLE} SET error = {} WHERE id = {}",
        ph(backend, 1),
        ph(backend, 2)
    );
    if let Err(e) = exec(db, backend, &sql, vec![text.into(), id.into()]).await {
        tracing::warn!(%id, error = %e, "could not record the error on the progress row");
    }
}

/// Removes one progress row (its old entry has been cleaned up).
///
/// # Errors
///
/// A failing statement.
pub async fn delete_row(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    id: Uuid,
) -> Result<(), MigrationError> {
    let sql = format!("DELETE FROM {ROWS_TABLE} WHERE id = {}", ph(backend, 1));
    exec(db, backend, &sql, vec![id.into()]).await?;
    Ok(())
}

/// Removes every row in `states`.
///
/// # Errors
///
/// A failing statement.
pub async fn delete_rows_in(
    db: &DatabaseConnection,
    backend: DatabaseBackend,
    states: &[RowState],
) -> Result<u64, MigrationError> {
    exec(
        db,
        backend,
        &format!("DELETE FROM {ROWS_TABLE} WHERE {}", states_in(states)),
        vec![],
    )
    .await
}

#[cfg(test)]
mod tests {
    use credstore::infra::storage::migrations::m0002_value_versions::VALUE_MIGRATION_COPY_DONE_PHASES;

    use super::*;

    #[test]
    fn phase_names_round_trip_and_are_ordered() {
        for phase in Phase::ALL {
            assert_eq!(Phase::parse(phase.as_str()), Some(phase));
        }
        assert!(Phase::ALL.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(Phase::parse("nope"), None);
    }

    #[test]
    fn the_guard_of_m0002_agrees_with_the_phases() {
        let past_copy: Vec<&str> = Phase::ALL
            .into_iter()
            .filter(|p| p.copy_finished())
            .map(Phase::as_str)
            .collect();
        assert_eq!(past_copy, VALUE_MIGRATION_COPY_DONE_PHASES);
        assert_eq!(HEADER_TABLE, "credstore_value_migration");
    }

    #[test]
    fn row_state_names_round_trip_and_classify() {
        for state in RowState::ALL {
            assert_eq!(RowState::parse(state.as_str()), Some(state));
        }
        let losses: Vec<_> = RowState::ALL.into_iter().filter(|s| s.is_loss()).collect();
        assert_eq!(
            losses,
            [
                RowState::Missing,
                RowState::FpMismatch,
                RowState::UnknownFenceKey
            ]
        );
        assert!(RowState::UnverifiedCopied.is_copied());
        assert!(RowState::FpMismatch.is_evidence());
        assert!(!RowState::Missing.is_evidence());
        assert_eq!(
            states_in(&[RowState::Copied, RowState::UnverifiedCopied]),
            "state IN ('copied', 'unverified_copied')"
        );
    }

    #[test]
    fn only_private_rows_carry_an_owner_in_the_old_address() {
        let mut row = ProgressRow {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            reference: "k".to_owned(),
            sharing: 1,
            owner_id: Uuid::from_u128(3),
            status_before: 2,
            secret_type_uuid: Uuid::nil(),
            value_fp: None,
            fp_key_id: None,
            state: RowState::Pending,
            value_version: None,
            activated: false,
            tidied: false,
        };
        assert_eq!(row.legacy_owner(), Some(Uuid::from_u128(3)));
        for sharing in [2, 3] {
            row.sharing = sharing;
            assert_eq!(row.legacy_owner(), None);
        }
    }
}
