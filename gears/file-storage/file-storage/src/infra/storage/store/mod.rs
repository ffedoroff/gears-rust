//! Unit-of-work persistence facade: the single touch-point for `toolkit_db`.
//!
//! `Store` owns the `DBProvider`, the tenant-scoped repositories (bundled in `Repos`)
//! and all connection/transaction logic, so nothing else opens a connection or a
//! transaction. It decides which `AccessScope` each table is queried with and handles
//! ETag/If-Match semantics; authorization decisions stay in `FileService`.
//!
//! Every mutating method that runs a transaction inserts its audit row in the
//! **same** transaction. `Store` is deliberately kept whole (a flow such as multipart
//! complete touches files, versions, the session and the audit outbox in one
//! transaction); narrow consumers should depend on the domain ports (`CleanupStore`,
//! `MultipartStore`) rather than the concrete `Store`.
//!
//! The impl is split across sibling files (`files`, `versions`, `metadata`, `policy`,
//! `multipart`, `lifecycle`, `traits`) to keep each file small.

// Domain terms (ETag, If-Match) appear in the module docs.
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use time::OffsetDateTime;
use toolkit_db::{DBProvider, DbError};
use uuid::Uuid;

use crate::infra::content::hash;
use crate::infra::content::hash_mode::HashMode;
use crate::infra::storage::repo::Repos;

mod files;
mod lifecycle;
mod metadata;
mod multipart;
mod policy;
mod traits;
mod versions;

pub use crate::infra::storage::repo::{AuditRow, FileEventRow};

/// An idempotency-key row persisted in the **same** transaction as the file creation,
/// so a committed `POST /files` always leaves a replay record.
pub struct IdempotencyInsert {
    pub tenant_id: Uuid,
    pub owner_kind: String,
    pub owner_id: Uuid,
    pub key: String,
    /// Subject creating this record; verified on replay so one caller's key never
    /// surfaces another caller's ticket.
    pub subject_id: Uuid,
    pub response_status: i32,
    pub response_body: String,
    pub response_etag: String,
    /// SHA-256 of the canonicalized request (`domain::idempotency::compute_request_hash`);
    /// compared on replay so a different body never surfaces a stored ticket.
    pub request_hash: Vec<u8>,
    pub expires_at: OffsetDateTime,
}

/// Persistence facade: the only type that holds `DBProvider` and drives
/// transactions. Cheap to clone.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Clone)]
pub struct Store {
    pub(super) db: Arc<DBProvider<DbError>>,
    pub(super) repos: Repos,
}

impl Store {
    /// Construct a `Store` from the shared `DBProvider`.
    #[must_use]
    pub fn new(db: Arc<DBProvider<DbError>>) -> Self {
        Self {
            db,
            repos: Repos::default(),
        }
    }
}

/// Build a `pending` version row with placeholder size/hash (filled at finalize).
pub(super) fn pending_version(
    file_id: Uuid,
    version_id: Uuid,
    mime_type: &str,
    backend_id: &str,
    backend_path: &str,
    now: OffsetDateTime,
) -> file_storage_sdk::FileVersion {
    use file_storage_sdk::VersionStatus;
    file_storage_sdk::FileVersion {
        file_id,
        version_id,
        mime_type: mime_type.to_owned(),
        size: 0,
        hash_algorithm: hash::ALGORITHM.to_owned(),
        // 32 zero bytes — satisfies the NOT NULL + length-32 CHECK until finalize.
        hash_value: vec![0u8; 32],
        // Mode is decided at finalize time, so a pending row defaults to `whole-sha256`.
        hash_mode: HashMode::WholeSha256.as_str().to_owned(),
        part_count: None,
        status: VersionStatus::Pending,
        is_current: false,
        backend_id: backend_id.to_owned(),
        backend_path: backend_path.to_owned(),
        created_at: now,
        bound_on_finalize: false,
    }
}
