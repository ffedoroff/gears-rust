//! Upload-flow redesign, one migration for both dialects:
//!
//! 1. `multipart_uploads`: `auto_bind` (fixed at session creation; `complete` reads it back and
//!    binds in the same transaction as the version finalize), completion-lease columns
//!    (`lease_owner`, `lease_until`, `complete_result`; `state` CHECK widened to admit
//!    `completing`), and `backend_id`/`backend_path` (the backend and path the upload targets,
//!    so expired-session cleanup does not need a `file_versions` row that may already be
//!    reclaimed). Existing rows are backfilled from the matching `file_versions` row, else
//!    left `NULL`. `SQLite` cannot alter a CHECK, so the table is rebuilt; its child
//!    `multipart_upload_parts` rows are evacuated first because `DROP TABLE` would cascade-delete
//!    them (`PRAGMA foreign_keys` cannot be toggled mid-transaction), and the two indexes on the
//!    old table are recreated.
//! 2. Index hardening (applied after 1, as two indexes cover its new columns): FK-cascade index
//!    `idempotency_keys_file_idx`; sweep indexes `multipart_uploads_sweep_idx` (non-partial,
//!    leads with `state` to cover both branches of the sweep's OR) and
//!    `files_versionless_sweep_idx`. `file_versions_backend_idx` is dropped: no query filters by
//!    `backend_id`. The listing indexes for cursor pagination are in
//!    `m20261008_000001_listing_indexes`.
//! 3. `file_versions.bound_on_finalize`: set in the same transaction as the finalize's
//!    `bind_on_finalize` CAS, so an idempotent finalize retry can report the bind outcome
//!    without re-reading `files.content_id`, which may have moved on.
//! 4. `file_versions.migration_lease_owner`/`migration_lease_until`: the lease `migrate_backend`
//!    takes before writing to the destination, so concurrent attempts on one version cannot
//!    race. Expiry is timed by the database clock, not the instance's.
//! 5. One-time delete of `File`-scope `retention_rules` left dangling by earlier `files` deletes
//!    (`scope_target_id` has no FK; deletes now remove such rules in the same transaction).
//!
//! `down()` reverses the schema changes: new indexes dropped, `file_versions_backend_idx`
//! recreated, columns/CHECK restored (`SQLite`: table rebuilt).
//! `completing` rows are folded into `aborted` first (the narrow CHECK cannot hold them);
//! `backend_id`/`backend_path` are dropped without an inverse backfill; part 5 is not undone.

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::ConnectionTrait;

#[derive(DeriveMigrationName)]
pub struct Migration;

const POSTGRES_UP: &str = r"
ALTER TABLE multipart_uploads
    ADD COLUMN IF NOT EXISTS auto_bind BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE multipart_uploads
    ADD COLUMN IF NOT EXISTS lease_until timestamptz NULL;
ALTER TABLE multipart_uploads
    ADD COLUMN IF NOT EXISTS lease_owner text NULL;
ALTER TABLE multipart_uploads
    ADD COLUMN IF NOT EXISTS complete_result text NULL;
-- Widen the state CHECK to admit the new 'completing' lease state. The
-- original inline CHECK gets the auto-generated name below on Postgres.
ALTER TABLE multipart_uploads DROP CONSTRAINT IF EXISTS multipart_uploads_state_check;
ALTER TABLE multipart_uploads
    ADD CONSTRAINT multipart_uploads_state_check
    CHECK (state IN ('in_progress', 'completing', 'completed', 'aborted'));

-- The backend/path a session's upload actually targets (see the module doc
-- for why cleanup needs this persisted rather than always reconstructed).
ALTER TABLE multipart_uploads
    ADD COLUMN IF NOT EXISTS backend_id text NULL;
ALTER TABLE multipart_uploads
    ADD COLUMN IF NOT EXISTS backend_path text NULL;
-- Backfill existing rows (created by a pre-this-migration server) from their
-- matching file_versions row. Only touches rows this migration itself just
-- added the (NULL) columns to -- an already-populated row (a re-run, or a
-- row this migration's own INSERT path already filled) is left untouched.
UPDATE multipart_uploads
SET backend_id = fv.backend_id,
    backend_path = fv.backend_path
FROM file_versions fv
WHERE fv.file_id = multipart_uploads.file_id
  AND fv.version_id = multipart_uploads.version_id
  AND multipart_uploads.backend_id IS NULL;

-- Index hardening (part 2 of this migration -- see the module doc). Placed
-- after the columns above because multipart_uploads_sweep_idx covers
-- lease_until and the widened state domain.
CREATE INDEX IF NOT EXISTS idempotency_keys_file_idx
    ON idempotency_keys (file_id);
CREATE INDEX IF NOT EXISTS multipart_uploads_sweep_idx
    ON multipart_uploads (state, expires_at, lease_until);
CREATE INDEX IF NOT EXISTS files_versionless_sweep_idx
    ON files (created_at, file_id) WHERE content_id IS NULL;
-- `file_versions_backend_idx` (m20260624_000001_p1_initial): no query in this
-- gear filters `file_versions` by `backend_id` -- `migrate_backend`/backend
-- migration reads/writes by `(file_id, version_id)`, never scans by backend --
-- so this index only pays insert/update cost with no read ever using it.
DROP INDEX IF EXISTS file_versions_backend_idx;

-- Part 3: persisted finalize-time bind decision (see the module doc).
ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS bound_on_finalize boolean NOT NULL DEFAULT false;

-- Part 4: migration lease (see the module doc) -- both nullable, so every
-- existing row simply gets an unheld lease (NULL/NULL), same as a version
-- that has never been migrated.
ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS migration_lease_owner uuid NULL;
ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS migration_lease_until timestamptz NULL;

-- Part 5: one-time cleanup of `File`-scope retention rules already left
-- dangling by a `files` row deleted before this migration ran (see the
-- module doc) -- 'file' is `RetentionScope::File`'s wire/DB spelling, same
-- value `m20260701_000001_p2_initial`'s CHECK and `RetentionRuleRepo::
-- list_by_file_scope` use.
DELETE FROM retention_rules
WHERE scope = 'file'
  AND scope_target_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM files f WHERE f.file_id = retention_rules.scope_target_id
  );
";

// SQLite rebuild (create-copy-drop-rename): see the module doc for why the child
// `multipart_upload_parts` rows are evacuated first and the two indexes recreated.
const SQLITE_UP: &str = r"
CREATE TABLE multipart_upload_parts_backup AS SELECT * FROM multipart_upload_parts;

CREATE TABLE multipart_uploads_new (
    upload_id              TEXT  PRIMARY KEY NOT NULL,
    file_id                TEXT  NOT NULL
                                 REFERENCES files (file_id) ON DELETE CASCADE,
    version_id             TEXT  NOT NULL,
    backend_upload_handle  TEXT  NOT NULL,
    state                  TEXT  NOT NULL  DEFAULT 'in_progress'
                                 CHECK (state IN ('in_progress', 'completing', 'completed', 'aborted')),
    declared_mime          TEXT  NOT NULL,
    mime_validated         INTEGER NOT NULL DEFAULT 0,
    declared_size          INTEGER NOT NULL DEFAULT 0,
    part_size              INTEGER NOT NULL DEFAULT 0,
    auto_bind              BOOLEAN NOT NULL DEFAULT FALSE,
    lease_until            TIMESTAMP NULL,
    lease_owner            TEXT NULL,
    complete_result        TEXT NULL,
    backend_id             TEXT NULL,
    backend_path           TEXT NULL,
    created_at             TEXT  NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    expires_at             TEXT  NOT NULL
);
-- Backfill backend_id/backend_path from the matching file_versions row (see
-- the module doc) via a LEFT JOIN in the same copy -- a row with no matching
-- version (already reclaimed, or never given one) simply gets NULLs from the
-- unmatched join side, same as the Postgres backfill's fallback.
INSERT INTO multipart_uploads_new (
    upload_id, file_id, version_id, backend_upload_handle, state,
    declared_mime, mime_validated, declared_size, part_size,
    backend_id, backend_path,
    created_at, expires_at
)
SELECT mu.upload_id, mu.file_id, mu.version_id, mu.backend_upload_handle, mu.state,
       mu.declared_mime, mu.mime_validated, mu.declared_size, mu.part_size,
       fv.backend_id, fv.backend_path,
       mu.created_at, mu.expires_at
FROM multipart_uploads mu
LEFT JOIN file_versions fv
    ON fv.file_id = mu.file_id AND fv.version_id = mu.version_id;
DROP TABLE multipart_uploads;
ALTER TABLE multipart_uploads_new RENAME TO multipart_uploads;

INSERT INTO multipart_upload_parts (
    upload_id, part_number, backend_etag, part_hash, size, uploaded_at
)
SELECT upload_id, part_number, backend_etag, part_hash, size, uploaded_at
FROM multipart_upload_parts_backup;
DROP TABLE multipart_upload_parts_backup;

CREATE INDEX IF NOT EXISTS multipart_uploads_file_idx
    ON multipart_uploads (file_id);
CREATE INDEX IF NOT EXISTS multipart_uploads_expired_idx
    ON multipart_uploads (expires_at, state);

-- Index hardening (part 2 of this migration -- see the module doc). Placed
-- after the rebuild above because multipart_uploads_sweep_idx covers
-- lease_until and the widened state domain.
CREATE INDEX IF NOT EXISTS idempotency_keys_file_idx
    ON idempotency_keys (file_id);
CREATE INDEX IF NOT EXISTS multipart_uploads_sweep_idx
    ON multipart_uploads (state, expires_at, lease_until);
CREATE INDEX IF NOT EXISTS files_versionless_sweep_idx
    ON files (created_at, file_id) WHERE content_id IS NULL;
-- Unused index removal -- see POSTGRES_UP's matching statement.
DROP INDEX IF EXISTS file_versions_backend_idx;

-- Part 3: persisted finalize-time bind decision (see the module doc).
-- SQLite's `ADD COLUMN` has no `IF NOT EXISTS` clause, unlike Postgres above.
ALTER TABLE file_versions ADD COLUMN bound_on_finalize BOOLEAN NOT NULL DEFAULT FALSE;

-- Part 4: migration lease (see the module doc) -- TEXT, matching every other
-- nullable timestamp column on SQLite in this migration.
ALTER TABLE file_versions ADD COLUMN migration_lease_owner TEXT NULL;
ALTER TABLE file_versions ADD COLUMN migration_lease_until TEXT NULL;

-- Part 5: one-time cleanup of `File`-scope retention rules already left
-- dangling by a `files` row deleted before this migration ran -- see
-- POSTGRES_UP's matching statement for the full comment.
DELETE FROM retention_rules
WHERE scope = 'file'
  AND scope_target_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM files f WHERE f.file_id = retention_rules.scope_target_id
  );
";

// Reverse of POSTGRES_UP. Live `completing` rows are folded into `aborted` before the CHECK
// is narrowed, so a rollback does not fail on an active deployment.
const POSTGRES_DOWN: &str = r"
DROP INDEX IF EXISTS files_versionless_sweep_idx;
DROP INDEX IF EXISTS multipart_uploads_sweep_idx;
DROP INDEX IF EXISTS idempotency_keys_file_idx;
-- Reverse of the unused-index removal above.
CREATE INDEX IF NOT EXISTS file_versions_backend_idx
    ON file_versions (backend_id);

-- Part 3 (see the module doc): plain, symmetric drop -- nothing else in
-- this migration depends on the column existing.
ALTER TABLE file_versions DROP COLUMN IF EXISTS bound_on_finalize;

-- Part 4 (see the module doc): plain, symmetric drop.
ALTER TABLE file_versions DROP COLUMN IF EXISTS migration_lease_owner;
ALTER TABLE file_versions DROP COLUMN IF EXISTS migration_lease_until;

UPDATE multipart_uploads SET state = 'aborted' WHERE state = 'completing';
ALTER TABLE multipart_uploads DROP CONSTRAINT IF EXISTS multipart_uploads_state_check;
ALTER TABLE multipart_uploads
    ADD CONSTRAINT multipart_uploads_state_check
    CHECK (state IN ('in_progress', 'completed', 'aborted'));
ALTER TABLE multipart_uploads DROP COLUMN IF EXISTS auto_bind;
ALTER TABLE multipart_uploads DROP COLUMN IF EXISTS lease_until;
ALTER TABLE multipart_uploads DROP COLUMN IF EXISTS lease_owner;
ALTER TABLE multipart_uploads DROP COLUMN IF EXISTS complete_result;
ALTER TABLE multipart_uploads DROP COLUMN IF EXISTS backend_id;
ALTER TABLE multipart_uploads DROP COLUMN IF EXISTS backend_path;
";

// SQLite down: same index revert as POSTGRES_DOWN, then the child-safe rebuild mirrored; the
// `completing` -> `aborted` fold-in happens in the copy's SELECT (CHECK applies on INSERT).
const SQLITE_DOWN: &str = r"
DROP INDEX IF EXISTS files_versionless_sweep_idx;
DROP INDEX IF EXISTS multipart_uploads_sweep_idx;
DROP INDEX IF EXISTS idempotency_keys_file_idx;
-- Reverse of the unused-index removal above -- see POSTGRES_DOWN's matching statement.
CREATE INDEX IF NOT EXISTS file_versions_backend_idx
    ON file_versions (backend_id);

-- Part 3 (see the module doc): plain, symmetric drop. SQLite's `DROP COLUMN`
-- has no `IF EXISTS` clause, unlike Postgres's equivalent statement.
ALTER TABLE file_versions DROP COLUMN bound_on_finalize;

-- Part 4 (see the module doc): plain, symmetric drop.
ALTER TABLE file_versions DROP COLUMN migration_lease_owner;
ALTER TABLE file_versions DROP COLUMN migration_lease_until;

CREATE TABLE multipart_upload_parts_backup AS SELECT * FROM multipart_upload_parts;

CREATE TABLE multipart_uploads_old (
    upload_id              TEXT  PRIMARY KEY NOT NULL,
    file_id                TEXT  NOT NULL
                                 REFERENCES files (file_id) ON DELETE CASCADE,
    version_id             TEXT  NOT NULL,
    backend_upload_handle  TEXT  NOT NULL,
    state                  TEXT  NOT NULL  DEFAULT 'in_progress'
                                 CHECK (state IN ('in_progress', 'completed', 'aborted')),
    declared_mime          TEXT  NOT NULL,
    mime_validated         INTEGER NOT NULL DEFAULT 0,
    declared_size          INTEGER NOT NULL DEFAULT 0,
    part_size              INTEGER NOT NULL DEFAULT 0,
    created_at             TEXT  NOT NULL  DEFAULT CURRENT_TIMESTAMP,
    expires_at             TEXT  NOT NULL
);
INSERT INTO multipart_uploads_old (
    upload_id, file_id, version_id, backend_upload_handle, state,
    declared_mime, mime_validated, declared_size, part_size,
    created_at, expires_at
)
SELECT upload_id, file_id, version_id, backend_upload_handle,
       CASE WHEN state = 'completing' THEN 'aborted' ELSE state END,
       declared_mime, mime_validated, declared_size, part_size,
       created_at, expires_at
FROM multipart_uploads;
-- backend_id/backend_path are dropped along with the other four columns this
-- migration added -- up()'s copy is not mirrored in reverse (no rebuild reads
-- them back out of file_versions); the round trip is schema-equivalence
-- only, not data preservation of these two columns.
DROP TABLE multipart_uploads;
ALTER TABLE multipart_uploads_old RENAME TO multipart_uploads;

INSERT INTO multipart_upload_parts (
    upload_id, part_number, backend_etag, part_hash, size, uploaded_at
)
SELECT upload_id, part_number, backend_etag, part_hash, size, uploaded_at
FROM multipart_upload_parts_backup;
DROP TABLE multipart_upload_parts_backup;

CREATE INDEX IF NOT EXISTS multipart_uploads_file_idx
    ON multipart_uploads (file_id);
CREATE INDEX IF NOT EXISTS multipart_uploads_expired_idx
    ON multipart_uploads (expires_at, state);
";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let sql = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => POSTGRES_UP,
            sea_orm::DatabaseBackend::Sqlite => SQLITE_UP,
            // MySQL and any future `#[non_exhaustive]` backend are refused explicitly.
            _ => {
                return Err(DbErr::Custom(
                    "file-storage migrations support Postgres and SQLite only".to_owned(),
                ));
            }
        };
        conn.execute_unprepared(sql).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let sql = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Postgres => POSTGRES_DOWN,
            sea_orm::DatabaseBackend::Sqlite => SQLITE_DOWN,
            // See `up()`'s matching arm.
            _ => {
                return Err(DbErr::Custom(
                    "file-storage migrations support Postgres and SQLite only".to_owned(),
                ));
            }
        };
        conn.execute_unprepared(sql).await?;
        Ok(())
    }
}
