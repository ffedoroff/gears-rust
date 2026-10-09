//! Signed content URLs.
//!
//! The control plane is the sole minter: it signs short-lived, opaque tokens
//! (`base64url(payload).base64url(signature)`) that authorize exactly one content operation
//! against the sidecar, which holds only the public key and verifies statelessly. ADR-0004
//! specifies PASETO `v4.public`; this is an equivalent Ed25519-signed compact token, an
//! internal detail of control plane + sidecar.
//!
//! Sign/verify goes through [`SignatureProvider`] / [`SignatureVerifier`] (see [`provider`]),
//! never a crypto crate directly, so the algorithm is replaceable (ADR-0004 FIPS posture).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::domain::error::DomainError;

mod provider;
pub use provider::{Ed25519Provider, SignatureProvider, SignatureVerifier};

/// The content operation a token authorizes (checked against the HTTP method by the sidecar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Download (`GET`).
    Get,
    /// Single-part upload (`PUT`).
    Put,
    /// One part of a multipart upload (`PUT` to the sidecar); carries `MultipartClaims`
    /// that the sidecar enforces before writing any bytes.
    MultipartPart,
}

/// Upload-only content constraints the sidecar enforces while streaming.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadConstraints {
    /// Upper bound on uploaded size (mutually exclusive with `exact_size`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u64>,
    /// Exact required size (mutually exclusive with `max_size`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact_size: Option<u64>,
    /// Required content hash, `"<alg>:<hex>"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
}

/// Multipart-part-specific claims carried in `op = multipart_part` tokens.
///
/// The sidecar enforces the plan (part boundaries, exact size) from these before writing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartClaims {
    /// The multipart session that owns this part.
    pub upload_id: Uuid,
    /// 1-based part number (S3 convention; 0 is invalid).
    pub part_number: u32,
    /// Byte offset of this part within the final assembled object.
    pub offset: u64,
    /// **Exact** byte length the sidecar accepts for this part (`413` if the body differs).
    pub size: u64,
    /// The backend's own multipart handle (e.g. an S3 `UploadId`) from
    /// `StorageBackend::initiate_multipart`. Empty means the sidecar falls back to the
    /// local-fs offset-object model instead of calling `StorageBackend::upload_part`.
    /// `#[serde(default)]` tolerates older tokens.
    #[serde(default)]
    pub backend_handle: String,
}

/// The signed token's claim set (AND-combined; `exp` is mandatory).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub op: Op,
    pub file_id: Uuid,
    /// The specific immutable blob: `content_id` for GET, the pending version
    /// for PUT / `multipart_part`.
    pub version_id: Uuid,
    pub backend_id: String,
    pub backend_path: String,
    /// Expiry, unix seconds.
    pub exp: i64,
    #[serde(default, skip_serializing_if = "is_default_constraints")]
    pub upload: UploadConstraints,
    /// Non-empty only when `op = multipart_part`.
    #[serde(default, skip_serializing_if = "is_default_multipart")]
    pub multipart: MultipartClaims,
    /// Opaque correlation id minted at issuance. The sidecar echoes it as `x-request-id`
    /// on its finalize/report-part callback so both planes' logs correlate.
    /// `#[serde(default)]` tolerates older tokens.
    #[serde(default)]
    pub request_id: String,
    /// Stored MIME of the version (`op = get` only), so the sidecar can emit a real
    /// `Content-Type` without DB access. `#[serde(default)]` tolerates older tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// Opaque content `ETag` of the (file, version) pair (`op = get` only), the same value as
    /// `DownloadTicket::etag` (`domain::etag::content_etag`). `#[serde(default)]` tolerates
    /// older tokens.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// Tells the finalize callback to also bind the finalized version under a
    /// `content_id IS NULL` CAS (`op = put` only). Minted **only** by `POST /files` with
    /// `bind: "auto"` for a brand-new file; replacing content must go through the authorized
    /// `bind`/`complete` paths. The sidecar never reads it. `#[serde(default)]` tolerates
    /// older tokens.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bind_on_finalize: bool,
    /// Whole-object hex SHA-256 (`op = get`, full download only; a `Range` cannot be checked
    /// against it). Set only for `whole-sha256` versions: a `multipart-composite-sha256`
    /// `hash_value` is a root over per-part digests (ADR-0006), not a digest of the bytes.
    /// Empty means the sidecar skips the check (also for older tokens).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_sha256: String,
}

fn is_default_constraints(c: &UploadConstraints) -> bool {
    *c == UploadConstraints::default()
}

fn is_default_multipart(c: &MultipartClaims) -> bool {
    *c == MultipartClaims::default()
}

/// The control-plane signing key (sole minter), backed by a [`SignatureProvider`].
pub struct Issuer {
    provider: Arc<dyn SignatureProvider>,
    /// Maximum lifetime (seconds) any issued token may carry (`max_url_ttl`).
    max_ttl_secs: i64,
}

impl Issuer {
    /// Generate a static signing key with the default [`Ed25519Provider`] (no rotation).
    pub fn generate(max_ttl_secs: i64) -> Result<Self, DomainError> {
        Ok(Self::with_provider(
            Arc::new(Ed25519Provider::generate()?),
            max_ttl_secs,
        ))
    }

    /// Build an issuer from a configured 32-byte Ed25519 seed, so the key is stable across
    /// restarts.
    pub fn from_seed(seed: &[u8], max_ttl_secs: i64) -> Result<Self, DomainError> {
        Ok(Self::with_provider(
            Arc::new(Ed25519Provider::from_seed(seed)?),
            max_ttl_secs,
        ))
    }

    /// Build an issuer over an explicit signature provider (e.g. FIPS-validated, ADR-0004).
    #[must_use]
    pub fn with_provider(provider: Arc<dyn SignatureProvider>, max_ttl_secs: i64) -> Self {
        Self {
            provider,
            max_ttl_secs,
        }
    }

    /// The raw public key the sidecar must be configured with.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.provider.public_key()
    }

    /// A single-key verifier bound to this issuer's current public key: the control plane's
    /// own default verifier for the finalize/report-part callbacks (`FileService::verifier`),
    /// extended by `FileService::with_previous_signing_public_keys` so a `signing_key_seed`
    /// rotation does not reject in-flight uploads.
    #[must_use]
    pub fn verifier(&self) -> Verifier {
        Verifier::with_verifier(self.provider.verifier())
    }

    /// Mint a token for `claims`, clamping its lifetime to `max_ttl`.
    pub fn issue(&self, mut claims: Claims, now: OffsetDateTime) -> Result<String, DomainError> {
        // `checked_add`: `validate()` bounds the TTL, but an unchecked overflow would wrap
        // or panic; defense in depth.
        let max_exp = now
            .unix_timestamp()
            .checked_add(self.max_ttl_secs)
            .ok_or_else(|| {
                DomainError::database(
                    "max_url_ttl_secs overflowed computing the token's max expiry",
                )
            })?;
        if claims.exp > max_exp {
            claims.exp = max_exp;
        }
        let payload = serde_json::to_vec(&claims)
            .map_err(|e| DomainError::token_invalid(format!("serialize claims: {e}")))?;
        let sig = self.provider.sign(&payload);
        Ok(format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(&sig)
        ))
    }
}

/// The sidecar's verifier: a small **ordered** set of public keys, stateless verification.
///
/// Lets a `signing_key_seed` rotation proceed without an outage: the sidecar gets the new
/// key added first, so tokens signed by either key verify throughout the rollout (see
/// `docs/operations.md`). There is deliberately no `kid` claim: the set is small, trying
/// each key is cheap, and a token cannot name which key to check.
///
/// The control plane uses the same type, [`dedupe_public_keys`] and [`parse_public_key_list`]
/// for its own callback verification (`FileService::verifier`), since the sidecar's key set
/// does not widen what the control plane accepts.
#[derive(Clone)]
pub struct Verifier {
    /// Verifiers to try in order; `[0]` is the current primary key, the rest only keep
    /// accepting tokens from an older key during rotation. Never empty.
    verifiers: Vec<Arc<dyn SignatureVerifier>>,
}

impl Verifier {
    /// Construct from a single raw Ed25519 public key.
    pub fn from_public_key(public_key: Vec<u8>) -> Result<Self, DomainError> {
        Self::from_public_keys(vec![public_key])
    }

    /// Construct from an ordered list of raw Ed25519 public keys. Validates every key's
    /// length and rejects an empty list so misconfiguration fails at startup. FIPS deployments
    /// use [`Self::with_verifiers`].
    pub fn from_public_keys(public_keys: Vec<Vec<u8>>) -> Result<Self, DomainError> {
        const ED25519_PUBLIC_KEY_LEN: usize = 32;
        if public_keys.is_empty() {
            return Err(DomainError::token_invalid(
                "at least one public key is required to construct a Verifier",
            ));
        }
        let verifiers = public_keys
            .into_iter()
            .map(|key| {
                if key.len() != ED25519_PUBLIC_KEY_LEN {
                    return Err(DomainError::token_invalid(format!(
                        "invalid Ed25519 public key length: expected {ED25519_PUBLIC_KEY_LEN} bytes, got {}",
                        key.len()
                    )));
                }
                Ok(Arc::new(provider::Ed25519Verifier::new(key)) as Arc<dyn SignatureVerifier>)
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        Ok(Self { verifiers })
    }

    /// Construct over a single explicit verifier (a non-default provider).
    #[must_use]
    pub fn with_verifier(verifier: Arc<dyn SignatureVerifier>) -> Self {
        Self::with_verifiers(vec![verifier])
    }

    /// Construct over an ordered list of explicit verifiers (primary first).
    ///
    /// # Panics
    ///
    /// Panics if `verifiers` is empty.
    #[must_use]
    pub fn with_verifiers(verifiers: Vec<Arc<dyn SignatureVerifier>>) -> Self {
        assert!(
            !verifiers.is_empty(),
            "Verifier::with_verifiers requires at least one SignatureVerifier"
        );
        Self { verifiers }
    }

    /// Verify a token's signature and expiry, returning its claims; the caller still checks
    /// `op` against the HTTP method and enforces upload constraints.
    ///
    /// The token is parsed once, then checked against each verifier in order. A failure is
    /// always the same "signature verification failed", never revealing how many keys exist.
    pub fn verify(&self, token: &str, now: OffsetDateTime) -> Result<Claims, DomainError> {
        self.verify_with_grace(token, now, Duration::ZERO)
    }

    /// Like [`Self::verify`], but an expired token is still accepted while
    /// `now < exp + grace`.
    ///
    /// For the server-to-server finalize/report-part callbacks only: they carry the PUT token
    /// the sidecar checked strictly at the start of the upload, so a slow upload can outlive
    /// the TTL with its bytes already written. Only `exp` gets slack; signature, `op` and the
    /// `(file_id, version_id)` binding are checked as usual. `Duration::ZERO` equals
    /// [`Self::verify`].
    pub fn verify_with_grace(
        &self,
        token: &str,
        now: OffsetDateTime,
        grace: Duration,
    ) -> Result<Claims, DomainError> {
        let (payload_b64, sig_b64) = token
            .split_once('.')
            .ok_or_else(|| DomainError::token_invalid("malformed token"))?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| DomainError::token_invalid("bad payload encoding"))?;
        let sig = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| DomainError::token_invalid("bad signature encoding"))?;

        let signature_ok = self
            .verifiers
            .iter()
            .any(|verifier| verifier.verify(&payload, &sig).is_ok());
        if !signature_ok {
            return Err(DomainError::token_invalid("signature verification failed"));
        }

        let claims: Claims = serde_json::from_slice(&payload)
            .map_err(|_| DomainError::token_invalid("bad claims"))?;

        // Exclusive: unusable at `exp` plus grace. `grace` is clamped to whole seconds and
        // saturates rather than overflowing `i64`.
        let expires_at = claims.exp.saturating_add(grace.whole_seconds());
        if now.unix_timestamp() >= expires_at {
            return Err(DomainError::token_invalid("token expired"));
        }
        Ok(claims)
    }
}

/// Decode one base64url (`URL_SAFE_NO_PAD`) Ed25519 public key; `index` is the entry's
/// position in its list, named in the error. Does no length check (see
/// [`Verifier::from_public_keys`]). Shared by the sidecar's
/// `FS_SIDECAR_PREVIOUS_PUBLIC_KEYS` and `previous_signing_public_keys` parsing.
pub fn decode_public_key_entry(raw: &str, index: usize) -> Result<Vec<u8>, DomainError> {
    URL_SAFE_NO_PAD
        .decode(raw.trim())
        .map_err(|e| DomainError::token_invalid(format!("invalid public key entry #{index}: {e}")))
}

/// Ceiling on entries in either side's "previous keys" list
/// (`FS_SIDECAR_PREVIOUS_PUBLIC_KEYS`, `previous_signing_public_keys`).
///
/// A [`Verifier`] tries every key per verification, so an unbounded list is an unbounded
/// per-request cost. Only keys of an in-progress rotation are needed; 8 leaves headroom.
pub const MAX_PREVIOUS_SIGNING_PUBLIC_KEYS: usize = 8;

/// Parse a comma-separated list of base64url Ed25519 public keys (the
/// `FS_SIDECAR_PREVIOUS_PUBLIC_KEYS` format).
///
/// Elements are trimmed and empty ones skipped; a malformed key fails the whole parse via
/// [`decode_public_key_entry`]. Does **not** enforce [`MAX_PREVIOUS_SIGNING_PUBLIC_KEYS`];
/// callers check the length.
pub fn parse_public_key_list(raw: &str) -> Result<Vec<Vec<u8>>, DomainError> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .enumerate()
        .map(|(i, s)| decode_public_key_entry(s, i))
        .collect()
}

/// De-duplicate an ordered key set: `primary` leads, then `previous` in order, dropping any
/// repeat. Returns `(deduped_keys, dropped_count)`.
///
/// Shared by the sidecar and the control plane (`FileService::with_previous_signing_public_keys`).
/// A duplicate is harmless (at most one wasted comparison), so it is dropped silently and
/// the call site warns instead of rejecting.
#[must_use]
pub fn dedupe_public_keys(primary: Vec<u8>, previous: Vec<Vec<u8>>) -> (Vec<Vec<u8>>, usize) {
    let mut deduped = Vec::with_capacity(previous.len() + 1);
    deduped.push(primary);
    let mut dropped = 0_usize;
    for key in previous {
        if deduped.contains(&key) {
            dropped += 1;
        } else {
            deduped.push(key);
        }
    }
    (deduped, dropped)
}

#[cfg(test)]
#[path = "signed_url_tests.rs"]
mod signed_url_tests;
