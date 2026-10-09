//! `FileService` — control-plane business logic.
//!
//! Owns create/presign, finalize/bind (optimistic CAS), download-URL issuance, metadata,
//! listing, versioning and delete. Content bytes never flow through it; they move via
//! `crate::domain::data_plane::DataPlaneService`.
//!
//! The impl is split across `create.rs`, `write.rs`, `read_ops.rs` and `backend.rs`;
//! shared types and the struct live here.

// Domain terms (ETag, If-Match, FileStorage, GET/PUT) recur throughout the docs.
#![allow(clippy::doc_markdown)]

use std::sync::Arc;

use time::OffsetDateTime;
use toolkit_gts::gts_id;
use toolkit_security::{AccessScope, SecurityContext};
use uuid::Uuid;

use crate::domain::audit::{AuditEntry, AuditOperation, FileEvent};
use crate::domain::authz::Authorizer;
use crate::domain::error::DomainError;
use crate::domain::ports::FileStorageMetricsPort;
use crate::infra::backend::BackendRegistry;
use crate::infra::external_clients::{QuotaClient, UsageDelta, UsageReporter};
use crate::infra::metrics::NoopMetrics;
use crate::infra::signed_url::{Claims, Issuer, MultipartClaims, Op, UploadConstraints};
use crate::infra::storage::Store;

mod backend;
mod create;
mod read_ops;
mod write;

/// Service-level configuration distilled from [`crate::config::FileStorageConfig`].
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    /// Default TTL (seconds) of every signed URL; the issuer caps it at `max_url_ttl`.
    pub default_url_ttl_secs: i64,
    pub sidecar_base_url: String,
    pub default_page_size: u64,
    pub max_page_size: u64,
    /// Seconds an idempotency key is retained; afterwards a retry is a fresh request.
    pub idempotency_ttl_secs: u64,
}

/// Result of creating a file or presigning a new version: identity plus the
/// signed URL the client `PUT`s the bytes to.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct UploadTicket {
    pub file_id: Uuid,
    pub version_id: Uuid,
    pub upload_url: String,
}

/// Outcome of the token-authenticated finalize callback; the sidecar surfaces it to the
/// client as `PUT`-response headers (`X-FS-Bound: true` + `ETag`, or `X-FS-Bound: conflict` +
/// `X-FS-Current-ETag`).
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct FinalizeByTokenOutcome {
    /// `None`: the token did not request a bind (manual mode), first non-retried call.
    /// `Some(Bound)`/`Some(Conflict)`: auto-bind token that won/lost the `content_id IS NULL`
    /// CAS. `Some(Manual)`: idempotent retry of a manual-mode finalize on an already-`Available`,
    /// still-unbound version; handled like `None`.
    pub bind_state: Option<crate::domain::multipart::BindState>,
    /// Content ETag after a successful bind (`Bound` only).
    pub etag: Option<String>,
    /// The file's current content ETag on a lost CAS (`Conflict` only), for a manual rebind.
    pub current_etag: Option<String>,
}

/// Result of `download-url`: the signed URL plus the content ETag.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct DownloadTicket {
    pub download_url: String,
    pub etag: String,
    pub version_id: Uuid,
}

/// Quota metric name used for storage preflight checks.
pub(super) const QUOTA_METRIC_NAME: &str =
    gts_id!("cf.qe.metric.type.v1~cf.qe.metric.file_storage_bytes.v1");

/// The control-plane file service.
#[allow(unknown_lints, de0309_must_have_domain_model)]
pub struct FileService {
    pub(super) store: Store,
    pub(super) backends: BackendRegistry,
    pub(super) issuer: Arc<Issuer>,
    pub(super) authorizer: Arc<dyn Authorizer>,
    pub(super) cfg: ServiceConfig,
    /// `None` disables quota checks; when present, client errors deny the request (fail-closed).
    pub(super) quota_client: Option<Arc<dyn QuotaClient>>,
    /// `None` disables usage reporting; failures are logged and swallowed.
    pub(super) usage_reporter: Option<Arc<dyn UsageReporter>>,
    /// Defaults to a no-op; `with_metrics` installs the real meter.
    pub(super) metrics: Arc<dyn FileStorageMetricsPort>,
    /// Verifier for the finalize/report-part callbacks: the issuer's current key plus any
    /// retained previous keys, so a `signing_key_seed` rotation does not reject in-flight uploads.
    pub(super) callback_verifier: crate::infra::signed_url::Verifier,
    /// Time budget (seconds) of one `migrate_backend` attempt; default mirrors
    /// `FileStorageConfig::migrate_timeout_secs`.
    pub(super) migrate_timeout_secs: u64,
    /// Margin (seconds) added to `migrate_timeout_secs` when sizing the migration lease;
    /// default mirrors `FileStorageConfig::migrate_lease_margin_secs`.
    pub(super) migrate_lease_margin_secs: u64,
}

impl FileService {
    pub fn new(
        store: Store,
        backends: BackendRegistry,
        issuer: Arc<Issuer>,
        authorizer: Arc<dyn Authorizer>,
        cfg: ServiceConfig,
        quota_client: Option<Arc<dyn QuotaClient>>,
        usage_reporter: Option<Arc<dyn UsageReporter>>,
    ) -> Self {
        let callback_verifier = issuer.verifier();
        Self {
            store,
            backends,
            issuer,
            authorizer,
            cfg,
            quota_client,
            usage_reporter,
            metrics: Arc::new(NoopMetrics),
            callback_verifier,
            // Same defaults as the config fields of the same names.
            migrate_timeout_secs: 3600,
            migrate_lease_margin_secs: 300,
        }
    }

    /// Install the migration lease's timeout and margin (builder step, like `with_metrics`).
    #[must_use]
    pub fn with_migrate_lease_config(mut self, timeout_secs: u64, margin_secs: u64) -> Self {
        self.migrate_timeout_secs = timeout_secs;
        self.migrate_lease_margin_secs = margin_secs;
        self
    }

    /// Install a real metrics port (a builder step so `new()` keeps its signature).
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<dyn FileStorageMetricsPort>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Extend the callback verifier to also accept `previous_keys` (raw public keys of earlier
    /// `signing_key_seed`s). A no-op when empty. Only widens what the callback routes accept;
    /// minting always uses the current key.
    ///
    /// Duplicates of the current key (or within `previous_keys`) are deduped with a warning.
    ///
    /// # Errors
    /// Returns an error if any key is not a valid 32-byte Ed25519 public key.
    pub fn with_previous_signing_public_keys(
        mut self,
        previous_keys: Vec<Vec<u8>>,
    ) -> Result<Self, DomainError> {
        if previous_keys.is_empty() {
            return Ok(self);
        }
        let (keys, dropped) =
            crate::infra::signed_url::dedupe_public_keys(self.issuer.public_key(), previous_keys);
        if dropped > 0 {
            tracing::warn!(
                dropped_duplicates = dropped,
                "file-storage: previous_signing_public_keys contains keys already accepted by \
                 the current signing key; dropped \u{2014} a completed signing_key_seed rotation \
                 usually means the list should be cleared"
            );
        }
        self.callback_verifier = crate::infra::signed_url::Verifier::from_public_keys(keys)?;
        Ok(self)
    }

    pub(super) fn tenant_scope(ctx: &SecurityContext) -> AccessScope {
        AccessScope::for_tenant(ctx.subject_tenant_id())
    }

    pub(super) fn validate_gts_type(t: &str) -> Result<(), DomainError> {
        if gts::GtsTypeId::try_new(t).is_ok() {
            Ok(())
        } else {
            Err(DomainError::invalid_gts_type(t))
        }
    }

    /// Token verifier for the finalize/report-part callbacks (see `callback_verifier`).
    #[must_use]
    pub fn verifier(&self) -> crate::infra::signed_url::Verifier {
        self.callback_verifier.clone()
    }

    /// Mint a signed URL for `op` against `v`.
    ///
    /// `download_meta` is `Some((content_type, etag, content_sha256))` for `Op::Get` only (the
    /// version's MIME, content ETag and, in whole-object mode, hex SHA-256), so the sidecar can
    /// emit `Content-Type`/`ETag` and verify the stream without a DB lookup; ignored for other
    /// ops.
    pub(super) fn sign_url(
        &self,
        op: Op,
        v: &VersionRef,
        constraints: UploadConstraints,
        download_meta: Option<(String, String, String)>,
    ) -> Result<String, DomainError> {
        self.sign_url_with_bind(op, v, constraints, download_meta, false)
    }

    /// `sign_url` with an explicit `bind_on_finalize` claim (only `create_file` with auto-bind).
    pub(super) fn sign_url_with_bind(
        &self,
        op: Op,
        v: &VersionRef,
        constraints: UploadConstraints,
        download_meta: Option<(String, String, String)>,
        bind_on_finalize: bool,
    ) -> Result<String, DomainError> {
        // Validate `op` before any signing work.
        let verb = content_verb(op)?;
        let now = OffsetDateTime::now_utc();
        // Only a GET (download) token carries content_type/etag/content_sha256.
        let (content_type, etag, content_sha256) = match op {
            Op::Get => download_meta.unwrap_or_default(),
            Op::Put | Op::MultipartPart => (String::new(), String::new(), String::new()),
        };
        // `checked_add` is defense in depth: `FileStorageConfig::validate()` bounds the TTL.
        let exp = now
            .unix_timestamp()
            .checked_add(self.cfg.default_url_ttl_secs)
            .ok_or_else(|| {
                DomainError::database("default_url_ttl_secs overflowed computing the token expiry")
            })?;
        let claims = Claims {
            op,
            file_id: v.file_id,
            version_id: v.version_id,
            backend_id: v.backend_id.clone(),
            backend_path: v.backend_path.clone(),
            exp,
            upload: constraints,
            multipart: MultipartClaims::default(),
            request_id: Uuid::now_v7().to_string(),
            content_type,
            etag,
            bind_on_finalize,
            content_sha256,
        };
        let token = self.issuer.issue(claims, now)?;
        Ok(format!(
            "{}/api/file-storage-data/v1/{}/{}/{}?fs-token={}",
            self.cfg.sidecar_base_url.trim_end_matches('/'),
            verb,
            v.file_id,
            v.version_id,
            token
        ))
    }

    /// Stable actor kind (`app` or `user`) of the caller.
    pub(super) fn actor_kind(ctx: &SecurityContext) -> &'static str {
        match ctx.subject_type() {
            Some("app") => "app",
            _ => "user",
        }
    }

    pub(super) fn audit_ok(
        ctx: &SecurityContext,
        file_id: Option<Uuid>,
        operation: AuditOperation,
        detail: serde_json::Value,
    ) -> AuditEntry {
        AuditEntry::success(
            ctx.subject_tenant_id(),
            Self::actor_kind(ctx),
            ctx.subject_id(),
            file_id,
            operation,
            detail,
        )
    }

    /// Fire-and-forget: a failing usage reporter must not block file operations.
    pub(super) fn report_usage(&self, delta: UsageDelta) {
        if let Some(reporter) = self.usage_reporter.clone() {
            tokio::spawn(async move {
                reporter.report(delta).await;
            });
        }
    }

    pub(super) fn make_file_event(
        tenant_id: Uuid,
        owner_id: Uuid,
        file_id: Uuid,
        event_type: &str,
        payload: serde_json::Value,
    ) -> FileEvent {
        FileEvent {
            tenant_id,
            owner_id,
            file_id,
            event_type: event_type.to_owned(),
            payload,
        }
    }
}

/// Map an [`Op`] to its sidecar path segment (`/api/file-storage-data/v1/{verb}/{file}/{version}`).
///
/// `Op::MultipartPart` is rejected: part uploads use a distinct sidecar route with part-specific
/// claims, and `MultipartService::initiate` is the single source of truth for those URLs.
fn content_verb(op: Op) -> Result<&'static str, DomainError> {
    match op {
        Op::Get => Ok("download"),
        Op::Put => Ok("upload"),
        Op::MultipartPart => Err(DomainError::InternalError),
    }
}

/// A minimal reference to a version's backend location, for URL signing.
#[allow(unknown_lints, de0309_must_have_domain_model)]
pub(super) struct VersionRef {
    pub(super) file_id: Uuid,
    pub(super) version_id: Uuid,
    pub(super) backend_id: String,
    pub(super) backend_path: String,
}

/// Serializable form of `UploadTicket` stored in the idempotency record.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct IdempotencyTicket {
    pub(super) file_id: Uuid,
    pub(super) version_id: Uuid,
    pub(super) upload_url: String,
    /// The `bind` mode minted into `upload_url`'s token at the original `create_file` call; a
    /// replay re-mints with this value, not the retry's. Defaults to `false` for tickets
    /// stored before auto-bind existed.
    #[serde(default)]
    pub(super) auto_bind: bool,
}

impl From<IdempotencyTicket> for UploadTicket {
    fn from(t: IdempotencyTicket) -> Self {
        Self {
            file_id: t.file_id,
            version_id: t.version_id,
            upload_url: t.upload_url,
        }
    }
}

#[cfg(test)]
mod service_tests;
