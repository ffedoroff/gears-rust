//! Gear configuration for file-storage.
//!
//! Storage backends are loaded from the gear's own platform config section at startup.

use std::fmt;

use serde::{Deserialize, Serialize};
use toolkit_utils::SecretString;

/// Upper bound (seconds) accepted for `finalize_token_grace_secs`: 7 days.
///
/// `gear.rs` converts the field to `i64` with a saturating `unwrap_or(i64::MAX)`; an oversized
/// value would otherwise make the finalize/report-part `exp` check a no-op.
/// A week is ample for a slow upload; default is 1 hour.
pub const MAX_FINALIZE_TOKEN_GRACE_SECS: u64 = 7 * 24 * 3600;

/// Absolute ceiling accepted for `max_page_size`: the platform-wide cursor-pagination cap
/// (`guidelines/DNA/REST/QUERYING.md`). `validate()` rejects anything above it.
pub const MAX_PAGE_SIZE_CEILING: u64 = 200;

/// Upper bound (seconds) accepted for `max_url_ttl_secs`: 30 days.
///
/// The value is added to `now` in `Issuer::issue`; an oversized one would overflow.
/// 30 days: room well past the 7-day recommended default.
pub const MAX_URL_TTL_CEILING: u64 = 30 * 24 * 3600;

/// Upper bound (seconds) accepted for `multipart_session_ttl_secs`: 30 days.
///
/// Added to `now` for `expires_at`; an oversized value would overflow.
/// 30 days covers a very large upload; default is 24h.
pub const MAX_MULTIPART_SESSION_TTL_SECS: u64 = 30 * 24 * 3600;

/// Upper bound (seconds) accepted for `multipart_complete_lease_secs`: 1 day.
///
/// An oversized lease would let a crashed completer block others too long.
/// 1 day covers a very slow backend assembly; default is 120s.
pub const MAX_MULTIPART_COMPLETE_LEASE_SECS: u64 = 24 * 3600;

/// Upper bound (seconds) accepted for `migrate_timeout_secs`: 1 day.
///
/// An oversized value would let a stuck migration hold the version's lease too long.
/// 1 day covers a very large object over a slow backend; default is 1h.
pub const MAX_MIGRATE_TIMEOUT_SECS: u64 = 24 * 3600;

/// Upper bound (seconds) accepted for `migrate_lease_margin_secs`: 1 hour.
///
/// Absorbs clock skew between instance and DB and the tail of an in-flight backend call
/// after the timeout; 1h ceiling, default 5 min.
pub const MAX_MIGRATE_LEASE_MARGIN_SECS: u64 = 3600;

/// Upper bound (seconds) accepted for `idempotency_ttl_secs`: 30 days.
///
/// Well past any realistic retry window; default is 24h.
pub const MAX_IDEMPOTENCY_TTL_SECS: u64 = 30 * 24 * 3600;

/// Configuration for the `file-storage` gear.
///
/// `Debug` is implemented manually so `signing_key_seed` is never printed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct FileStorageConfig {
    /// Default signed-URL TTL in seconds (default 15 minutes), kept short to bound the
    /// stale-permission window. Never exceeds `max_url_ttl_secs`.
    #[serde(default = "default_default_url_ttl_secs")]
    pub default_url_ttl_secs: u64,

    /// Hard ceiling on signed-URL TTL in seconds (default 7 days). `Issuer::issue` clamps
    /// a longer requested TTL down to it.
    #[serde(default = "default_max_url_ttl_secs")]
    pub max_url_ttl_secs: u64,

    /// Grace (seconds) on the signed PUT token's `exp` when it is re-checked on the
    /// finalize/report-part callbacks. The sidecar checks the token only at the start of a
    /// PUT, so a slow upload can reach finalize with an expired token; the grace absorbs
    /// that gap (never applied at the sidecar). `0` disables it. Default 3600; capped at
    /// `MAX_FINALIZE_TOKEN_GRACE_SECS` by `validate()`.
    #[serde(default = "default_finalize_token_grace_secs")]
    pub finalize_token_grace_secs: u64,

    /// Lifetime (seconds) of a multipart upload session. Independent of
    /// `default_url_ttl_secs` so large uploads are not capped by the short per-URL TTL.
    /// Default 86400; capped at `MAX_MULTIPART_SESSION_TTL_SECS`.
    #[serde(default = "default_multipart_session_ttl_secs")]
    pub multipart_session_ttl_secs: u64,

    /// Lease (seconds) one multipart `complete` holds on the `completing` state before
    /// another caller may take it over after a crash. Held without an open DB transaction.
    /// Default 120.
    #[serde(default = "default_multipart_complete_lease_secs")]
    pub multipart_complete_lease_secs: u64,

    /// Time budget (seconds) for one `migrate_backend` attempt (stream, verify hash, commit
    /// the CAS), enforced by `tokio::time::timeout`. On expiry the destination object it
    /// created is deleted best-effort and a retryable 503 is returned. Also the base of the
    /// migration lease, so a concurrent attempt on the same version gets 409. Default 3600;
    /// capped at `MAX_MIGRATE_TIMEOUT_SECS`.
    #[serde(default = "default_migrate_timeout_secs")]
    pub migrate_timeout_secs: u64,

    /// Margin (seconds) added to `migrate_timeout_secs` for the migration lease
    /// (`lease = migrate_timeout_secs + migrate_lease_margin_secs`). Covers clock skew
    /// between the instance and the DB clock, and a backend call still in flight after the
    /// local timeout fired. Default 300; capped at `MAX_MIGRATE_LEASE_MARGIN_SECS`.
    #[serde(default = "default_migrate_lease_margin_secs")]
    pub migrate_lease_margin_secs: u64,

    /// Public base URL of the data-plane sidecar that signed URLs point at.
    #[serde(default = "default_sidecar_base_url")]
    pub sidecar_base_url: String,

    /// Default page size for `GET /files` listing.
    #[serde(default = "default_page_size")]
    pub default_page_size: u64,

    /// Maximum page size a caller may request.
    #[serde(default = "default_max_page_size")]
    pub max_page_size: u64,

    /// Local filesystem root for the default `local-fs` backend.
    #[serde(default = "default_storage_root")]
    pub storage_root: String,

    /// Base64url-encoded 32-byte Ed25519 seed for the URL-signing key, making the key
    /// stable across restarts. When absent an ephemeral key is generated at boot (dev
    /// only: signed URLs do not survive a restart and the sidecar needs reconfiguring).
    #[serde(
        default,
        serialize_with = "toolkit_utils::secret_string::serialize_option_exposed"
    )]
    pub signing_key_seed: Option<SecretString>,

    /// When `true` (default), gear init fails if `signing_key_seed` is absent, since
    /// replicas would otherwise each mint a different key. Set `false` for dev/test.
    #[serde(default = "default_require_signing_key_seed")]
    pub require_signing_key_seed: bool,

    /// Seconds an idempotency key is retained (default 86400); after that a retry with
    /// the same key is a fresh request.
    #[serde(default = "default_idempotency_ttl_secs")]
    pub idempotency_ttl_secs: u64,

    /// Registers an extra non-durable `memory` backend (dev/test only; loses content on
    /// restart). Default `false`.
    #[serde(default)]
    pub enable_in_memory_backend: bool,

    /// S3-compatible backends to register alongside `local-fs`, each keyed by its `id`.
    #[serde(default)]
    pub s3_backends: Vec<S3BackendConfig>,

    /// Backend id that new uploads write to (`BackendRegistry::default_backend`).
    /// `None` keeps `local-fs`. Must name a registered backend (`local-fs`, `memory` if
    /// enabled, or an `s3_backends` entry); an unknown id fails gear init.
    #[serde(default)]
    pub default_backend_id: Option<String>,

    /// **Required** (enforced by `validate()`). Shared secret the sidecar sends in the
    /// `x-fs-internal-token` header on the finalize/report-part callbacks, on top of the
    /// signed upload token; set the same value as `FS_SIDECAR_INTERNAL_TOKEN`. The
    /// control plane trusts the size and SHA-256 reported on that callback. Interim until
    /// `toolkit-security::internal_auth` can replace it (ADR-0003). Redacted in `Debug`.
    #[serde(
        default,
        serialize_with = "toolkit_utils::secret_string::serialize_option_exposed"
    )]
    pub finalize_internal_secret: Option<SecretString>,

    /// Public keys of previously-active `signing_key_seed`s that the finalize/report-part
    /// callbacks still accept besides the current key, so a seed rotation does not fail
    /// uploads started before the restart. Each entry is a base64url (no padding) raw
    /// Ed25519 public key. `validate()` rejects malformed entries and more than
    /// `infra::signed_url::MAX_PREVIOUS_SIGNING_PUBLIC_KEYS`; duplicates are deduped with a
    /// startup warning.
    #[serde(default)]
    pub previous_signing_public_keys: Vec<String>,
}

/// One S3-compatible backend entry (`FileStorageConfig::s3_backends`).
///
/// `Debug` is implemented manually so `secret_access_key` is never printed.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3BackendConfig {
    /// Backend id; must be unique across the whole registry (`BackendRegistry::new`).
    pub id: String,

    /// S3-compatible endpoint, e.g. `http://127.0.0.1:9000` for `MinIO`. `None` means real
    /// AWS S3 (`https://s3.{region}.amazonaws.com`).
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Region used for `SigV4` signing (e.g. `us-east-1` for most `MinIO` setups).
    pub region: String,

    /// Target bucket name.
    pub bucket: String,

    /// Access key id. `None` reads `AWS_ACCESS_KEY_ID` from the environment.
    #[serde(default)]
    pub access_key_id: Option<String>,

    /// Secret access key. `None` reads `AWS_SECRET_ACCESS_KEY` from the environment.
    /// Redacted in `Debug`.
    #[serde(
        default,
        serialize_with = "toolkit_utils::secret_string::serialize_option_exposed"
    )]
    pub secret_access_key: Option<SecretString>,

    /// Path-style addressing (default `true`, as most non-AWS endpoints require it).
    /// Currently accepted but not forwarded: `S3Backend::new` always uses
    /// `UrlStyle::Path`, which is also valid on AWS S3.
    #[serde(default = "default_path_style")]
    pub path_style: bool,
}

impl fmt::Debug for S3BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3BackendConfig")
            .field("id", &self.id)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key_id", &self.access_key_id)
            // Never print the secret — only whether one is configured.
            .field(
                "secret_access_key",
                &self.secret_access_key.as_ref().map(|_| "<redacted>"),
            )
            .field("path_style", &self.path_style)
            .finish()
    }
}

fn default_path_style() -> bool {
    true
}

impl FileStorageConfig {
    /// Validates cross-field invariants that `serde` cannot express; called at gear init.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Without a seed each replica would mint a different ephemeral key.
        if self.require_signing_key_seed && self.signing_key_seed.is_none() {
            anyhow::bail!(
                "invalid file-storage config: signing_key_seed is required (set \
                 require_signing_key_seed: false to allow an ephemeral per-boot key in dev)"
            );
        }
        // Finalize trusts the size/hash the sidecar reports, so the secret is mandatory.
        if self
            .finalize_internal_secret
            .as_ref()
            .is_none_or(|s| s.expose().is_empty())
        {
            anyhow::bail!(
                "invalid file-storage config: finalize_internal_secret is required (set the \
                 same value as the sidecar's FS_SIDECAR_INTERNAL_TOKEN)"
            );
        }
        // Bounded: `gear.rs` saturates the `i64` conversion, which would make `exp` a no-op.
        if self.finalize_token_grace_secs > MAX_FINALIZE_TOKEN_GRACE_SECS {
            anyhow::bail!(
                "invalid file-storage config: finalize_token_grace_secs ({}) must not exceed \
                 MAX_FINALIZE_TOKEN_GRACE_SECS ({})",
                self.finalize_token_grace_secs,
                MAX_FINALIZE_TOKEN_GRACE_SECS
            );
        }
        // Bounded: `Issuer::issue` adds the TTL to `now`; a saturated value would overflow.
        if self.max_url_ttl_secs > MAX_URL_TTL_CEILING {
            anyhow::bail!(
                "invalid file-storage config: max_url_ttl_secs ({}) must not exceed \
                 MAX_URL_TTL_CEILING ({})",
                self.max_url_ttl_secs,
                MAX_URL_TTL_CEILING
            );
        }
        // Zero would silently mint every URL with a 1-second TTL (`.max(1)` downstream).
        if self.default_url_ttl_secs == 0 {
            anyhow::bail!(
                "invalid file-storage config: default_url_ttl_secs must be > 0 (a zero-second \
                 signed URL TTL would expire before any client could plausibly use it)"
            );
        }
        // Every mint without an override uses the default, so it must respect the ceiling.
        if self.default_url_ttl_secs > self.max_url_ttl_secs {
            anyhow::bail!(
                "invalid file-storage config: default_url_ttl_secs ({}) must not exceed \
                 max_url_ttl_secs ({})",
                self.default_url_ttl_secs,
                self.max_url_ttl_secs
            );
        }
        // Same for listing: the default page size must not exceed the cap.
        if self.default_page_size > self.max_page_size {
            anyhow::bail!(
                "invalid file-storage config: default_page_size ({}) must not exceed \
                 max_page_size ({})",
                self.default_page_size,
                self.max_page_size
            );
        }
        // Bounded: an arbitrary page size inflates row count and latency of every listing.
        if self.max_page_size > MAX_PAGE_SIZE_CEILING {
            anyhow::bail!(
                "invalid file-storage config: max_page_size ({}) must not exceed \
                 MAX_PAGE_SIZE_CEILING ({})",
                self.max_page_size,
                MAX_PAGE_SIZE_CEILING
            );
        }
        // Zero would silently mint a 1-second session (`.max(1)` downstream).
        if self.multipart_session_ttl_secs == 0 {
            anyhow::bail!(
                "invalid file-storage config: multipart_session_ttl_secs must be > 0 (a \
                 zero-second session lifetime would expire before any upload could complete)"
            );
        }
        // The session must outlive the per-part URLs minted at initiate time.
        if self.multipart_session_ttl_secs < self.default_url_ttl_secs {
            anyhow::bail!(
                "invalid file-storage config: multipart_session_ttl_secs ({}) must be >= \
                 default_url_ttl_secs ({}) -- otherwise a signed upload URL minted at initiate \
                 time could remain valid past the multipart session's own expiry",
                self.multipart_session_ttl_secs,
                self.default_url_ttl_secs
            );
        }
        // Bounded: the value is added to `now` for `expires_at`.
        if self.multipart_session_ttl_secs > MAX_MULTIPART_SESSION_TTL_SECS {
            anyhow::bail!(
                "invalid file-storage config: multipart_session_ttl_secs ({}) must not exceed \
                 MAX_MULTIPART_SESSION_TTL_SECS ({})",
                self.multipart_session_ttl_secs,
                MAX_MULTIPART_SESSION_TTL_SECS
            );
        }
        // Zero would grant a 1-second lease, defeating crash recovery.
        if self.multipart_complete_lease_secs == 0 {
            anyhow::bail!(
                "invalid file-storage config: multipart_complete_lease_secs must be > 0 (a \
                 zero-second lease would let another caller take it over almost immediately)"
            );
        }
        // Bounded: an oversized lease lets a crashed completer block others too long.
        if self.multipart_complete_lease_secs > MAX_MULTIPART_COMPLETE_LEASE_SECS {
            anyhow::bail!(
                "invalid file-storage config: multipart_complete_lease_secs ({}) must not exceed \
                 MAX_MULTIPART_COMPLETE_LEASE_SECS ({})",
                self.multipart_complete_lease_secs,
                MAX_MULTIPART_COMPLETE_LEASE_SECS
            );
        }
        self.validate_migrate_lease()?;
        // Bounded: added to `now` for the record's `expires_at`.
        if self.idempotency_ttl_secs > MAX_IDEMPOTENCY_TTL_SECS {
            anyhow::bail!(
                "invalid file-storage config: idempotency_ttl_secs ({}) must not exceed \
                 MAX_IDEMPOTENCY_TTL_SECS ({})",
                self.idempotency_ttl_secs,
                MAX_IDEMPOTENCY_TTL_SECS
            );
        }
        // Reject malformed keys at init rather than at the first callback. Duplicates of the
        // current key are deduped (with a warning) in `FileService`, once the key is derived.
        if !self.previous_signing_public_keys.is_empty() {
            // Checked first: every callback tries each key, so the list length is a per-callback
            // cost.
            if self.previous_signing_public_keys.len()
                > crate::infra::signed_url::MAX_PREVIOUS_SIGNING_PUBLIC_KEYS
            {
                anyhow::bail!(
                    "invalid file-storage config: previous_signing_public_keys has {} entries, \
                     exceeding MAX_PREVIOUS_SIGNING_PUBLIC_KEYS ({})",
                    self.previous_signing_public_keys.len(),
                    crate::infra::signed_url::MAX_PREVIOUS_SIGNING_PUBLIC_KEYS
                );
            }
            let decoded = self
                .previous_signing_public_keys
                .iter()
                .enumerate()
                .map(|(i, k)| crate::infra::signed_url::decode_public_key_entry(k, i))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| {
                    anyhow::anyhow!(
                        "invalid file-storage config: previous_signing_public_keys: {e}"
                    )
                })?;
            crate::infra::signed_url::Verifier::from_public_keys(decoded).map_err(|e| {
                anyhow::anyhow!("invalid file-storage config: previous_signing_public_keys: {e}")
            })?;
        }
        Ok(())
    }

    /// Checks for `migrate_timeout_secs` and `migrate_lease_margin_secs`; split out of
    /// `validate()` for the function-length lint.
    fn validate_migrate_lease(&self) -> anyhow::Result<()> {
        // Zero would abort every migration immediately (`.max(1)` downstream).
        if self.migrate_timeout_secs == 0 {
            anyhow::bail!(
                "invalid file-storage config: migrate_timeout_secs must be > 0 (a zero-second \
                 migration timeout would abort every migration attempt before it could transfer \
                 any bytes)"
            );
        }
        // Bounded: it sizes the migration lease base.
        if self.migrate_timeout_secs > MAX_MIGRATE_TIMEOUT_SECS {
            anyhow::bail!(
                "invalid file-storage config: migrate_timeout_secs ({}) must not exceed \
                 MAX_MIGRATE_TIMEOUT_SECS ({})",
                self.migrate_timeout_secs,
                MAX_MIGRATE_TIMEOUT_SECS
            );
        }
        // A zero margin leaves no slack for clock skew or an in-flight backend request.
        if self.migrate_lease_margin_secs == 0 {
            anyhow::bail!(
                "invalid file-storage config: migrate_lease_margin_secs must be > 0 (a zero \
                 margin leaves no slack for clock skew or an in-flight backend request that \
                 outlives migrate_backend's own timeout)"
            );
        }
        // Bounded: an oversized margin extends how long a stuck migration blocks others.
        if self.migrate_lease_margin_secs > MAX_MIGRATE_LEASE_MARGIN_SECS {
            anyhow::bail!(
                "invalid file-storage config: migrate_lease_margin_secs ({}) must not exceed \
                 MAX_MIGRATE_LEASE_MARGIN_SECS ({})",
                self.migrate_lease_margin_secs,
                MAX_MIGRATE_LEASE_MARGIN_SECS
            );
        }
        Ok(())
    }
}

impl fmt::Debug for FileStorageConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileStorageConfig")
            .field("default_url_ttl_secs", &self.default_url_ttl_secs)
            .field("max_url_ttl_secs", &self.max_url_ttl_secs)
            .field("finalize_token_grace_secs", &self.finalize_token_grace_secs)
            .field(
                "multipart_session_ttl_secs",
                &self.multipart_session_ttl_secs,
            )
            .field(
                "multipart_complete_lease_secs",
                &self.multipart_complete_lease_secs,
            )
            .field("migrate_timeout_secs", &self.migrate_timeout_secs)
            .field("migrate_lease_margin_secs", &self.migrate_lease_margin_secs)
            .field("sidecar_base_url", &self.sidecar_base_url)
            .field("default_page_size", &self.default_page_size)
            .field("max_page_size", &self.max_page_size)
            .field("storage_root", &self.storage_root)
            .field("idempotency_ttl_secs", &self.idempotency_ttl_secs)
            .field("enable_in_memory_backend", &self.enable_in_memory_backend)
            // Never print the signing key — only whether one is configured.
            .field(
                "signing_key_seed",
                &self.signing_key_seed.as_ref().map(|_| "<redacted>"),
            )
            .field("require_signing_key_seed", &self.require_signing_key_seed)
            // `S3BackendConfig` has its own redacting `Debug`.
            .field("s3_backends", &self.s3_backends)
            .field("default_backend_id", &self.default_backend_id)
            // Never print the shared secret — only whether one is configured.
            .field(
                "finalize_internal_secret",
                &self.finalize_internal_secret.as_ref().map(|_| "<redacted>"),
            )
            // A public key is not secret.
            .field(
                "previous_signing_public_keys",
                &self.previous_signing_public_keys,
            )
            .finish()
    }
}

impl Default for FileStorageConfig {
    fn default() -> Self {
        Self {
            default_url_ttl_secs: default_default_url_ttl_secs(),
            max_url_ttl_secs: default_max_url_ttl_secs(),
            finalize_token_grace_secs: default_finalize_token_grace_secs(),
            multipart_session_ttl_secs: default_multipart_session_ttl_secs(),
            multipart_complete_lease_secs: default_multipart_complete_lease_secs(),
            migrate_timeout_secs: default_migrate_timeout_secs(),
            migrate_lease_margin_secs: default_migrate_lease_margin_secs(),
            sidecar_base_url: default_sidecar_base_url(),
            default_page_size: default_page_size(),
            max_page_size: default_max_page_size(),
            storage_root: default_storage_root(),
            signing_key_seed: None,
            require_signing_key_seed: default_require_signing_key_seed(),
            idempotency_ttl_secs: default_idempotency_ttl_secs(),
            enable_in_memory_backend: false,
            s3_backends: Vec::new(),
            default_backend_id: None,
            finalize_internal_secret: None,
            previous_signing_public_keys: Vec::new(),
        }
    }
}

fn default_default_url_ttl_secs() -> u64 {
    // 15 minutes: bounds the stale-permission window.
    15 * 60
}

fn default_max_url_ttl_secs() -> u64 {
    // 7 days.
    7 * 24 * 60 * 60
}

fn default_finalize_token_grace_secs() -> u64 {
    3600 // 1 hour: see FileStorageConfig::finalize_token_grace_secs
}

fn default_multipart_complete_lease_secs() -> u64 {
    120 // backend-assembly budget; see FileStorageConfig::multipart_complete_lease_secs
}

fn default_migrate_timeout_secs() -> u64 {
    3600 // 1 hour: see FileStorageConfig::migrate_timeout_secs
}

fn default_migrate_lease_margin_secs() -> u64 {
    300 // 5 minutes: see FileStorageConfig::migrate_lease_margin_secs
}

fn default_multipart_session_ttl_secs() -> u64 {
    86400 // 24 hours
}

fn default_sidecar_base_url() -> String {
    "http://localhost:8087".to_owned()
}

fn default_page_size() -> u64 {
    25 // platform-wide cursor-pagination default (guidelines/DNA/REST/QUERYING.md)
}

fn default_max_page_size() -> u64 {
    200 // platform-wide cursor-pagination cap; see MAX_PAGE_SIZE_CEILING
}

fn default_storage_root() -> String {
    "./.file-storage-data".to_owned()
}

fn default_idempotency_ttl_secs() -> u64 {
    86400 // 24 hours
}

fn default_require_signing_key_seed() -> bool {
    true // secure-by-default: no seed configured must not silently accept an ephemeral key
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
