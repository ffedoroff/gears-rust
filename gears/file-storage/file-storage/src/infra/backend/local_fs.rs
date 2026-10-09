//! Local filesystem storage backend.
//!
//! Blobs live at `<root>/<sanitized-path>`; the opaque path is sanitized to prevent traversal
//! outside root.
//!
//! Writes never touch the target directly: bytes go to a sibling temp file
//! (`<target>.tmp.<uuid>`, same filesystem), which is fsynced and then atomically renamed
//! onto the target, so readers never see a partial file. The parent directory is then fsynced
//! best-effort (needed on ext4/xfs for the rename to survive a crash); if that fails, a
//! warning is logged and the write still succeeds. `publish_exclusive` follows the same shape
//! but publishes with `hard_link`, which fails if the target exists (see
//! `StorageBackend::publish_exclusive`).

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use file_storage_sdk::ByteRange;
use futures::StreamExt;
use futures::stream::BoxStream;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::infra::content::hash;

use super::{BackendCapabilities, PublishOutcome, StorageBackend, check_read_prefix_budget};

/// Filesystem-backed blob store rooted at a configured directory.
pub struct LocalFsBackend {
    id: String,
    root: PathBuf,
    fsync_parent_dir: bool,
}

impl LocalFsBackend {
    #[must_use]
    pub fn new(id: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            root: root.into(),
            fsync_parent_dir: true,
        }
    }

    /// Enable/disable the best-effort parent-directory fsync after rename (default `true`).
    #[must_use]
    pub fn with_fsync_parent_dir(mut self, enabled: bool) -> Self {
        self.fsync_parent_dir = enabled;
        self
    }

    /// Map an opaque backend path to a file path under `root`, rejecting components that
    /// could escape it (`..`, `.`, backslashes).
    fn resolve(&self, path: &str) -> Result<PathBuf, DomainError> {
        let mut out = self.root.clone();
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            if comp == ".." || comp == "." || comp.contains('\\') {
                return Err(DomainError::backend(&self.id, "illegal path component"));
            }
            out.push(comp);
        }
        if !out.starts_with(&self.root) {
            return Err(DomainError::backend(&self.id, "path escapes backend root"));
        }
        Ok(out)
    }

    /// Transient I/O errors (see `super::is_transient_io_error`) map to `backend_unavailable`,
    /// everything else (missing path, permission denied, disk full, ...) is permanent.
    fn io_err(&self, e: &std::io::Error) -> DomainError {
        let msg = e.to_string();
        if super::is_transient_io_error(e.kind()) {
            DomainError::backend_unavailable(&self.id, msg)
        } else {
            DomainError::backend(&self.id, msg)
        }
    }

    /// Best-effort directory fsync (flushes directory entries such as a rename).
    async fn fsync_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
        let dir_handle = tokio::fs::File::open(dir).await?;
        dir_handle.sync_all().await
    }

    /// Resolve `path` to its target file and create the parent directory.
    async fn prepare_target(&self, path: &str) -> Result<(PathBuf, Option<PathBuf>), DomainError> {
        let target = self.resolve(path)?;
        let parent = target.parent().map(Path::to_path_buf);
        if let Some(parent) = &parent {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| self.io_err(&e))?;
        }
        Ok((target, parent))
    }

    /// A unique sibling temp-file path for `target`.
    fn tmp_path_for(target: &Path) -> PathBuf {
        PathBuf::from(format!("{}.tmp.{}", target.display(), Uuid::now_v7()))
    }

    /// Rename a written and fsynced temp file onto `target`, then fsync the parent
    /// best-effort (see module docs).
    async fn publish_tmp(
        &self,
        tmp: &Path,
        target: &Path,
        parent: Option<&Path>,
    ) -> Result<(), DomainError> {
        tokio::fs::rename(tmp, target)
            .await
            .map_err(|e| self.io_err(&e))?;

        if self.fsync_parent_dir
            && let Some(parent) = parent
            && let Err(e) = self.fsync_dir(parent).await
        {
            tracing::warn!(
                error = ?e,
                "parent-dir fsync failed or unsupported by this filesystem, continuing"
            );
        }

        Ok(())
    }

    /// Hard-link `tmp` at `target` **iff `target` does not exist**: `link(2)` atomically fails
    /// with `AlreadyExists`, unlike `rename`, which would silently replace it. On success `tmp`'s
    /// own entry is removed and the parent fsynced best-effort.
    ///
    /// Returns `Ok(true)` if this call created `target`, `Ok(false)` if it already existed (the
    /// caller then removes `tmp`; it is untouched on that path).
    async fn publish_tmp_exclusive(
        &self,
        tmp: &Path,
        target: &Path,
        parent: Option<&Path>,
    ) -> Result<bool, DomainError> {
        match tokio::fs::hard_link(tmp, target).await {
            Ok(()) => {
                self.finish_exclusive_publish(tmp, parent).await;
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(self.io_err(&e)),
        }
    }

    /// Best-effort tail of a hard-link publish: remove `tmp`'s own directory entry and fsync
    /// the parent. Failures are only logged.
    async fn finish_exclusive_publish(&self, tmp: &Path, parent: Option<&Path>) {
        // A failure leaves a harmless extra link, cleaned up like any stray `*.tmp.*`.
        if let Err(e) = tokio::fs::remove_file(tmp).await {
            tracing::warn!(
                error = ?e,
                "failed to remove temp file's directory entry after hard-link publish"
            );
        }

        if self.fsync_parent_dir
            && let Some(parent) = parent
            && let Err(e) = self.fsync_dir(parent).await
        {
            tracing::warn!(
                error = ?e,
                "parent-dir fsync failed or unsupported by this filesystem, continuing"
            );
        }
    }

    /// Stream chunks into `tmp`, hashing incrementally and aborting as soon as the byte count
    /// exceeds `max_size`. The caller removes `tmp` on error and publishes it on success.
    async fn write_stream_to_tmp(
        &self,
        tmp: &Path,
        mut stream: BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        let mut file = tokio::fs::File::create(tmp)
            .await
            .map_err(|e| self.io_err(&e))?;
        let mut hasher = hash::Hasher::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| self.io_err(&e))?;
            file.write_all(&chunk).await.map_err(|e| self.io_err(&e))?;
            hasher.update(&chunk);
            if max_size.is_some_and(|m| hasher.len() > m) {
                return Err(DomainError::validation("size", "exceeds max_size"));
            }
        }
        file.sync_all().await.map_err(|e| self.io_err(&e))?;
        let bytes_written = hasher.len();
        let digest = hash::digest_to_array(hasher.finalize());
        Ok((bytes_written, digest))
    }

    /// Read chunk size for `chunked_file_stream`.
    const READ_CHUNK_SIZE: usize = 64 * 1024;

    /// Chunked-read core of `get_stream` and `get_range_stream`: reads up to `READ_CHUNK_SIZE`
    /// at a time from `file` (already seeked by the caller), stopping at EOF
    /// (`remaining: None`) or after exactly `remaining` bytes.
    ///
    /// The stream owns `file` (`'static`), so it can go straight into
    /// `axum::body::Body::from_stream`. A read that hits EOF while `remaining` is still
    /// positive yields `UnexpectedEof` instead of a silently short body; this is the second
    /// line of defense after the length checks at open time.
    fn chunked_file_stream(
        file: tokio::fs::File,
        remaining: Option<u64>,
    ) -> BoxStream<'static, std::io::Result<Bytes>> {
        let stream =
            futures::stream::unfold((Some(file), remaining), |(state, remaining)| async move {
                let mut file = state?;
                if remaining == Some(0) {
                    return None;
                }
                let want = remaining.map_or(Self::READ_CHUNK_SIZE, |r| {
                    usize::try_from(r)
                        .unwrap_or(usize::MAX)
                        .min(Self::READ_CHUNK_SIZE)
                });
                let mut buf = vec![0u8; want];
                match file.read(&mut buf).await {
                    // `Some(0)` returned above, so `Some(r)` here means `r > 0`: short file.
                    Ok(0) => remaining.map(|r| {
                        (
                            Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                format!("file ended {r} byte(s) short of the expected read length"),
                            )),
                            (None, None),
                        )
                    }),
                    Ok(n) => {
                        buf.truncate(n);
                        let next_remaining = remaining.map(|r| r - n as u64);
                        Some((Ok(Bytes::from(buf)), (Some(file), next_remaining)))
                    }
                    Err(e) => Some((Err(e), (None, None))),
                }
            });
        Box::pin(stream)
    }
}

#[async_trait]
impl StorageBackend for LocalFsBackend {
    fn id(&self) -> &str {
        &self.id
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            range_native: true,
            durable: true,
            ..BackendCapabilities::default()
        }
    }

    /// Writes and hashes chunks as they arrive without buffering the body; an oversized
    /// upload is aborted mid-stream. The partial temp file is removed on any failure.
    async fn put_stream(
        &self,
        path: &str,
        stream: BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<(u64, [u8; 32]), DomainError> {
        let (target, parent) = self.prepare_target(path).await?;
        let tmp = Self::tmp_path_for(&target);

        let write_result = self.write_stream_to_tmp(&tmp, stream, max_size).await;

        let (bytes_written, digest) = match write_result {
            Ok(v) => v,
            Err(e) => {
                // Best-effort cleanup of the partial temp file.
                drop(tokio::fs::remove_file(&tmp).await);
                return Err(e);
            }
        };

        self.publish_tmp(&tmp, &target, parent.as_deref()).await?;
        Ok((bytes_written, digest))
    }

    /// Like `put_stream`, but publishes via `publish_tmp_exclusive` (see
    /// `StorageBackend::publish_exclusive` for the contract).
    async fn publish_exclusive(
        &self,
        path: &str,
        stream: BoxStream<'_, std::io::Result<Bytes>>,
        max_size: Option<u64>,
    ) -> Result<PublishOutcome, DomainError> {
        let (target, parent) = self.prepare_target(path).await?;
        let tmp = Self::tmp_path_for(&target);

        let write_result = self.write_stream_to_tmp(&tmp, stream, max_size).await;
        let (bytes_written, digest) = match write_result {
            Ok(v) => v,
            Err(e) => {
                drop(tokio::fs::remove_file(&tmp).await);
                return Err(e);
            }
        };

        match self
            .publish_tmp_exclusive(&tmp, &target, parent.as_deref())
            .await
        {
            Ok(true) => Ok(PublishOutcome {
                bytes_written,
                digest,
                created: true,
            }),
            Ok(false) => {
                // Target already existed and was not touched; drop this attempt's temp file.
                drop(tokio::fs::remove_file(&tmp).await);
                Ok(PublishOutcome {
                    bytes_written,
                    digest,
                    created: false,
                })
            }
            Err(e) => {
                drop(tokio::fs::remove_file(&tmp).await);
                Err(e)
            }
        }
    }

    /// Reads at most `max_bytes` from the start (fewer at EOF); `NotFound` maps to `Ok(None)`.
    async fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<Option<Bytes>, DomainError> {
        check_read_prefix_budget(max_bytes)?;
        let target = self.resolve(path)?;
        let mut file = match tokio::fs::File::open(&target).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.io_err(&e)),
        };
        let want = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        let mut buf = vec![0u8; want];
        let mut filled = 0usize;
        while filled < want {
            let n = file
                .read(&mut buf[filled..])
                .await
                .map_err(|e| self.io_err(&e))?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        buf.truncate(filled);
        Ok(Some(Bytes::from(buf)))
    }

    /// Streams the file in fixed-size chunks via `chunked_file_stream`, so at most one chunk
    /// is in memory.
    ///
    /// `expected_len` is the length the caller already committed to (e.g. the sidecar's
    /// `Content-Length` from an earlier `stat`). It is compared with a fresh `metadata()`
    /// before reading, so a file resized in between is refused; a later change is caught by
    /// the short-read detection.
    async fn get_stream(
        &self,
        path: &str,
        expected_len: u64,
    ) -> Result<BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        let target = self.resolve(path)?;
        let file = tokio::fs::File::open(&target)
            .await
            .map_err(|e| self.io_err(&e))?;
        let len = file.metadata().await.map_err(|e| self.io_err(&e))?.len();
        if len != expected_len {
            return Err(DomainError::conflict(format!(
                "object at '{path}' changed size before it could be read: expected {expected_len} byte(s), found {len}"
            )));
        }
        Ok(Self::chunked_file_stream(file, Some(expected_len)))
    }

    /// Resolves the range against the file's real length, seeks once and streams via
    /// `chunked_file_stream`, so `bytes=0-` never allocates a `len`-sized buffer.
    ///
    /// `expected_len` is the range length the caller already resolved (for
    /// `Content-Length`). The range is re-resolved against a fresh `metadata()`, and a
    /// mismatch is refused before any byte is read.
    async fn get_range_stream(
        &self,
        path: &str,
        range: ByteRange,
        expected_len: u64,
    ) -> Result<BoxStream<'static, std::io::Result<Bytes>>, DomainError> {
        let target = self.resolve(path)?;
        let mut file = tokio::fs::File::open(&target)
            .await
            .map_err(|e| self.io_err(&e))?;
        let total = file.metadata().await.map_err(|e| self.io_err(&e))?.len();
        let Some((start, end)) = range.resolve(total) else {
            return Err(DomainError::validation("range", "unsatisfiable byte range"));
        };
        // `resolve` yields an inclusive end; clamp defensively.
        let end = end.min(total.saturating_sub(1));
        let len = end - start + 1;
        if len != expected_len {
            return Err(DomainError::conflict(format!(
                "object at '{path}' range changed before it could be read: expected {expected_len} byte(s), resolved {len}"
            )));
        }
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| self.io_err(&e))?;
        Ok(Self::chunked_file_stream(file, Some(expected_len)))
    }

    /// Reads only the file's metadata, never its content.
    async fn size(&self, path: &str) -> Result<u64, DomainError> {
        let target = self.resolve(path)?;
        let meta = tokio::fs::metadata(&target)
            .await
            .map_err(|e| self.io_err(&e))?;
        Ok(meta.len())
    }

    async fn delete(&self, path: &str) -> Result<(), DomainError> {
        let target = self.resolve(path)?;
        match tokio::fs::remove_file(&target).await {
            Ok(()) => Ok(()),
            // Idempotent: a missing blob is a successful delete.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(self.io_err(&e)),
        }
    }

    async fn exists(&self, path: &str) -> Result<bool, DomainError> {
        let target = self.resolve(path)?;
        // Only "not found" means absent; other errors must not be reported as a missing blob.
        match tokio::fs::metadata(&target).await {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(self.io_err(&e)),
        }
    }

    /// Single `stat(2)`: `Ok(None)` if not found, `Ok(Some(len))` if present, `Err` on I/O fault.
    async fn stat(&self, path: &str) -> Result<Option<u64>, DomainError> {
        let target = self.resolve(path)?;
        match tokio::fs::metadata(&target).await {
            Ok(meta) => Ok(Some(meta.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(self.io_err(&e)),
        }
    }

    /// Walks `root` recursively and returns backend-relative paths (`"/{component}/..."`);
    /// a missing root yields an empty vec.
    async fn list_paths(&self) -> Result<Vec<String>, DomainError> {
        match tokio::fs::metadata(&self.root).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(self.io_err(&e)),
        }

        let mut paths = Vec::new();
        let mut stack = vec![self.root.clone()];

        while let Some(dir) = stack.pop() {
            let mut entries = tokio::fs::read_dir(&dir)
                .await
                .map_err(|e| self.io_err(&e))?;

            while let Some(entry) = entries.next_entry().await.map_err(|e| self.io_err(&e))? {
                let ft = entry.file_type().await.map_err(|e| self.io_err(&e))?;
                if ft.is_dir() {
                    stack.push(entry.path());
                } else if ft.is_file() {
                    let abs = entry.path();
                    if let Ok(rel) = abs.strip_prefix(&self.root) {
                        let rel_str = rel.to_string_lossy().replace('\\', "/");
                        paths.push(format!("/{rel_str}"));
                    }
                }
            }
        }

        Ok(paths)
    }

    /// Readiness probe: `root` exists and is a directory (catches an unmounted volume).
    async fn is_ready(&self) -> Result<(), DomainError> {
        let meta = tokio::fs::metadata(&self.root)
            .await
            .map_err(|e| self.io_err(&e))?;
        if meta.is_dir() {
            Ok(())
        } else {
            Err(DomainError::backend(&self.id, "root is not a directory"))
        }
    }
}
