//! Pluggable storage-backend abstraction.
//!
//! A backend stores immutable content blobs keyed by an opaque path
//! (`/{file_id}/{version_id}` by convention). Clients never address a backend
//! directly; content moves only through the sidecar. Shipped backends: local
//! filesystem, in-memory and S3 (opt-in, ADR-0005).

mod hashing_length_guard;
mod in_memory;
mod length_guard;
mod local_fs;
mod s3;

pub(crate) use hashing_length_guard::hashing_length_guard;
pub(crate) use length_guard::length_guard;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use file_storage_sdk::ByteRange;

use crate::domain::error::DomainError;
use crate::infra::content::hash_mode::Manifest;

pub use in_memory::InMemoryBackend;
pub use local_fs::LocalFsBackend;
pub use s3::S3Backend;

use crate::infra::content::hash_mode::ManifestEntry;

/// Hard ceiling on [`StorageBackend::read_prefix`]'s `max_bytes`. The largest real caller is
/// the MIME-sniff prefix (`MIME_SNIFF_PREFIX_BYTES`, 8 KiB); exceeding the ceiling is a
/// caller bug, rejected as a validation error rather than clamped, so a whole-object
/// `read_prefix` is impossible by construction.
pub(crate) const MAX_READ_PREFIX_BYTES: u64 = 64 * 1024;

/// Whether a backend I/O error is transient (a retry may succeed) rather than a persistent
/// fault. Shared so all backends classify stalled/interrupted/reset I/O identically; a
/// missing path, permission denied, disk full or corrupt data is never transient.
///
/// `UnexpectedEof` is included: a chunked read raises it when a stream ends short of the
/// committed length, i.e. a concurrent write or a dropped connection, both retry-worthy.
pub(crate) fn is_transient_io_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Shared check every [`StorageBackend::read_prefix`] implementation runs before touching its
/// backend, so the ceiling and error shape are identical across backends.
pub(crate) fn check_read_prefix_budget(max_bytes: u64) -> Result<(), DomainError> {
    if max_bytes > MAX_READ_PREFIX_BYTES {
        return Err(DomainError::validation(
            "max_bytes",
            format!(
                "read_prefix max_bytes {max_bytes} exceeds the {MAX_READ_PREFIX_BYTES}-byte ceiling"
            ),
        ));
    }
    Ok(())
}

/// One part of a multipart completion: `(part_number, offset, part_hash, backend_etag)`.
pub type MultipartCompletionPart = (u32, u64, [u8; 32], String);

/// Build the ADR-0006 offset-manifest and its `root` from the [`MultipartCompletionPart`]
/// tuples of a `complete_multipart` call.
///
/// Shared by all multipart backends so the canonical wire format is produced in one place.
/// Entries are sorted by ascending offset, so out-of-order parts still yield the canonical
/// manifest.
pub(crate) fn build_manifest_and_root(
    parts: &[MultipartCompletionPart],
) -> Result<(Manifest, [u8; 32]), DomainError> {
    let mut entries: Vec<ManifestEntry> = parts
        .iter()
        .map(|(_, offset, digest, _)| ManifestEntry {
            offset: *offset,
            digest: *digest,
        })
        .collect();
    entries.sort_by_key(|e| e.offset);
    let manifest = Manifest::new(entries)?;
    let root = manifest.root();
    Ok((manifest, root))
}

/// Result of [`StorageBackend::publish_exclusive`]: the measured size/digest of the streamed
/// bytes, plus whether the write landed.
///
/// `created: false` means `path` already held a blob and was left untouched. `bytes_written`
/// and `digest` always describe this attempt's bytes, so a caller can run an idempotency
/// check without re-reading the backend.
#[derive(Debug, Clone, Copy)]
pub struct PublishOutcome {
    pub bytes_written: u64,
    pub digest: [u8; 32],
    pub created: bool,
}

/// Optional features a backend may declare. Versioning is not here: it is implemented at
/// the `FileStorage` level on every backend.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackendCapabilities {
    /// Native chunked upload with server-side assembly.
    pub multipart_native: bool,
    /// Server-side encryption at rest.
    pub encryption_native: bool,
    /// Whether the backend serves byte ranges natively (reported to clients).
    pub range_native: bool,
    /// Internal-only presigned URLs (backend-to-backend tooling); never exposed.
    pub presigned_url_internal: bool,
    /// Maximum blob size the backend accepts in bytes. `None` = unbounded.
    pub max_size_bytes: Option<u64>,
    /// Whether content survives process restarts (`false` for the in-memory backend).
    /// `migrate_backend` gates moves onto a non-durable backend behind an elevated scope.
    pub durable: bool,
}

/// A storage backend: moves immutable content blobs. All methods are keyed by an
/// opaque backend path.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Stable backend identifier (matches `file_versions.backend_id`).
    fn id(&self) -> &str;

    /// The capabilities this backend advertises.
    fn capabilities(&self) -> BackendCapabilities;

    /// Stream a blob into `path`, hashing incrementally and enforcing `max_size` as bytes
    /// arrive. Returns `(bytes_written, sha256_digest)`. No default: every backend implements
    /// it natively.
    async fn put_stream(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError>;

    /// Publish a blob at `path` **only if nothing is stored there yet** (create-exclusive),
    /// unlike [`Self::put_stream`], which overwrites. Used only by the sidecar's single-shot
    /// upload to publish a version's final object at `/{file_id}/{version_id}`.
    ///
    /// A `PUT` token's signature covers size/hash constraints, never the body, and stays valid
    /// until `exp`. Overwriting would let a holder of a still-valid token replace
    /// already-served content under the recorded size/hash/`ETag`/MIME (an immutability
    /// break). Create-exclusive means only the first write lands; later attempts observe
    /// `created: false` with the existing bytes untouched.
    ///
    /// A backend-agnostic `exists`-then-write fallback would be non-atomic (TOCTOU), so there
    /// is no default. `LocalFsBackend` uses `hard_link`, `InMemoryBackend` one mutex, and
    /// `S3Backend` an `If-None-Match: *` conditional write (`412` maps to `created: false`),
    /// which needs an endpoint honouring S3 conditional writes; see ADR-0003 ("Known gap")
    /// and ADR-0005.
    async fn publish_exclusive(
        &self,
        path: &str,
        stream: futures::stream::BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<PublishOutcome, DomainError>;

    /// Stream the blob at `path` in chunks, without buffering the whole object. Used by
    /// migration's content verification and the sidecar's whole-object download.
    ///
    /// `expected_len` is the length the caller already committed to (e.g. in `Content-Length`).
    /// Every implementation must verify the object it opens still has this exact length
    /// **before yielding any byte**, and fail rather than stream a disagreeing body (a
    /// concurrent write can invalidate the caller's earlier `stat`).
    ///
    /// Declared `BoxStream<'static, _>` because implementations move owned data into the
    /// stream, which `axum::body::Body::from_stream` requires (the crate forbids `unsafe`).
    ///
    /// No default: a buffering fallback would defeat the point; every backend implements it.
    async fn get_stream(
        &self,
        path: &str,
        expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError>;

    /// Read up to `max_bytes` from the **start** of the blob at `path`, capped at
    /// [`MAX_READ_PREFIX_BYTES`] (every implementation enforces it via
    /// [`check_read_prefix_budget`]). With [`Self::stat`], this is the only way the
    /// control plane sees object bytes; ranges and whole objects stream only through the
    /// sidecar.
    ///
    /// `Ok(None)`: nothing stored at `path`. `Ok(Some(bytes))`: `bytes.len() ==
    /// min(max_bytes, object length)`; a short object is returned whole, not an error.
    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError>;

    /// Stream a byte range of the blob at `path` without buffering the whole range.
    ///
    /// Used for `Range`-qualified downloads: `Range: bytes=0-` resolves to the entire object,
    /// so a whole-range buffer would be unbounded. `'static` as for [`Self::get_stream`].
    ///
    /// `expected_len` is the resolved range's length that the caller already put in
    /// `Content-Length`. Every implementation must verify that re-resolving `range` against
    /// the object it opens still gives exactly this length before yielding any byte, and fail
    /// with [`DomainError::conflict`] rather than stream a disagreeing body.
    async fn get_range_stream(
        &self,
        path: &str,
        range: ByteRange,
        expected_len: u64,
    ) -> Result<futures::stream::BoxStream<'static, std::io::Result<Bytes>>, DomainError>;

    /// Total length in bytes of the blob at `path` (a metadata-only HEAD, no content read).
    /// Used to resolve `Range` requests and build `Content-Range`.
    async fn size(&self, path: &str) -> Result<u64, DomainError>;

    /// Delete the blob at `path`. Missing blobs are treated as success
    /// (idempotent delete).
    async fn delete(&self, path: &str) -> Result<(), DomainError>;

    /// Whether a blob exists at `path`.
    async fn exists(&self, path: &str) -> Result<bool, DomainError>;

    /// Existence check plus size in one round-trip: `Ok(None)` when nothing is stored,
    /// `Ok(Some(len))` when a blob of `len` bytes exists, `Err` for a genuine backend fault.
    /// Saves a second `HeadObject` on S3 for every download `GET`/`HEAD`.
    ///
    /// The default composes `exists` then `size`; all shipped backends override it.
    async fn stat(&self, path: &str) -> Result<Option<u64>, DomainError> {
        if !self.exists(path).await? {
            return Ok(None);
        }
        Ok(Some(self.size(path).await?))
    }

    /// Initiate a multipart upload for `path`, returning an opaque backend handle.
    /// Default is an error; backends opt in and set `multipart_native: true`.
    async fn initiate_multipart(&self, _path: &str) -> Result<String, DomainError> {
        Err(DomainError::multipart_not_supported(self.id()))
    }

    /// Upload one part, streamed rather than buffered. Returns `(backend_etag, part_hash_bytes)`.
    ///
    /// `part_offset` is the part's start offset in the assembled object; the part hash is a
    /// flat `sha256(data)` and the offset is passed through for the offset-manifest (ADR-0006).
    ///
    /// `len` is the part's exact expected size (the server-minted token claim, never a client
    /// header). An implementation MUST verify `stream` yields exactly `len` bytes before
    /// treating the part as stored. `'static` lets the stream go straight into an HTTP
    /// client body without a buffering copy.
    async fn upload_part_stream(
        &self,
        _path: &str,
        _upload_handle: &str,
        _part_number: u32,
        _part_offset: u64,
        _stream: futures::stream::BoxStream<'static, std::io::Result<Bytes>>,
        _len: u64,
    ) -> Result<(String, Vec<u8>), DomainError> {
        Err(DomainError::multipart_not_supported(self.id()))
    }

    /// Complete a multipart upload, assembling all uploaded parts in order.
    ///
    /// The backend MUST build the manifest and `root` from `parts` (ADR-0006) rather than
    /// re-reading the assembled object.
    ///
    /// Returns `(manifest, root)` with `root = sha256(manifest.to_wire_string())`; the
    /// control plane stores `root` as the version's `hash_value`.
    async fn complete_multipart(
        &self,
        _path: &str,
        _upload_handle: &str,
        _parts: &[MultipartCompletionPart],
    ) -> Result<(Manifest, [u8; 32]), DomainError> {
        Err(DomainError::multipart_not_supported(self.id()))
    }

    /// Abort a multipart upload, discarding all uploaded parts.
    async fn abort_multipart(&self, _path: &str, _upload_handle: &str) -> Result<(), DomainError> {
        Err(DomainError::multipart_not_supported(self.id()))
    }

    /// Enumerate all stored paths in the `file_versions.backend_path` format (for orphan
    /// reconciliation). The default is empty: backends that cannot enumerate are skipped.
    async fn list_paths(&self) -> Result<Vec<String>, DomainError> {
        Ok(vec![])
    }

    /// Cheap readiness probe for the sidecar's `/readyz` (e.g. root mounted, S3 reachable),
    /// without moving content. The default is always ready.
    async fn is_ready(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Registry of configured backends, with one designated default for new uploads.
#[derive(Clone)]
pub struct BackendRegistry {
    backends: BTreeMap<String, Arc<dyn StorageBackend>>,
    default_id: String,
}

impl BackendRegistry {
    /// Build a registry from configured backends; `default_id` must be present.
    pub fn new(
        backends: Vec<Arc<dyn StorageBackend>>,
        default_id: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let default_id = default_id.into();
        // Fail fast on a duplicate id instead of silently dropping a backend.
        let mut map: BTreeMap<String, Arc<dyn StorageBackend>> = BTreeMap::new();
        for b in backends {
            let id = b.id().to_owned();
            if map.insert(id.clone(), b).is_some() {
                return Err(DomainError::backend(id, "duplicate backend id"));
            }
        }
        if !map.contains_key(&default_id) {
            return Err(DomainError::backend(
                default_id,
                "default backend id is not among the configured backends",
            ));
        }
        Ok(Self {
            backends: map,
            default_id,
        })
    }

    /// The backend new uploads are written to.
    #[must_use]
    pub fn default_backend(&self) -> Arc<dyn StorageBackend> {
        // Safe: constructor guarantees the default id is present.
        Arc::clone(&self.backends[&self.default_id])
    }

    /// The id of the default backend.
    #[must_use]
    pub fn default_id(&self) -> &str {
        &self.default_id
    }

    /// Look up a backend by id.
    pub fn get(&self, id: &str) -> Result<Arc<dyn StorageBackend>, DomainError> {
        self.backends
            .get(id)
            .cloned()
            .ok_or_else(|| DomainError::unknown_backend(id))
    }

    /// All configured backends with their capabilities (for `GET /storages`).
    #[must_use]
    pub fn list(&self) -> Vec<(String, BackendCapabilities)> {
        self.backends
            .values()
            .map(|b| (b.id().to_owned(), b.capabilities()))
            .collect()
    }

    /// Iterate all configured backends as `(id, backend)` pairs (used by `/readyz`).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<dyn StorageBackend>)> {
        self.backends.iter().map(|(id, b)| (id.as_str(), b))
    }
}

#[cfg(test)]
mod classify_io_error_tests {
    use std::io::ErrorKind;

    use super::is_transient_io_error;

    #[test]
    fn classifies_timed_out_as_transient() {
        assert!(is_transient_io_error(ErrorKind::TimedOut));
    }

    #[test]
    fn classifies_interrupted_and_would_block_as_transient() {
        assert!(is_transient_io_error(ErrorKind::Interrupted));
        assert!(is_transient_io_error(ErrorKind::WouldBlock));
    }

    #[test]
    fn classifies_dropped_connection_kinds_as_transient() {
        assert!(is_transient_io_error(ErrorKind::ConnectionReset));
        assert!(is_transient_io_error(ErrorKind::ConnectionAborted));
        assert!(is_transient_io_error(ErrorKind::BrokenPipe));
    }

    #[test]
    fn classifies_unexpected_eof_as_transient() {
        assert!(is_transient_io_error(ErrorKind::UnexpectedEof));
    }

    #[test]
    fn classifies_not_found_and_permission_denied_as_permanent() {
        assert!(!is_transient_io_error(ErrorKind::NotFound));
        assert!(!is_transient_io_error(ErrorKind::PermissionDenied));
    }

    #[test]
    fn classifies_invalid_data_and_other_as_permanent() {
        assert!(!is_transient_io_error(ErrorKind::InvalidData));
        assert!(!is_transient_io_error(ErrorKind::Other));
    }
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod backend_tests;
