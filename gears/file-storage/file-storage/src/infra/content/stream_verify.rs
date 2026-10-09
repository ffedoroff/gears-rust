//! Streaming, mode-aware content-hash verification (ADR-0006) for `migrate_backend`.
//!
//! Wraps a `BoxStream<io::Result<Bytes>>`: every chunk is forwarded unchanged while being
//! hashed incrementally (mode-aware, like `Store::verify_content_hash`) and the byte count is
//! tracked against the declared length. Memory is bounded by the number of parts, not the
//! object size.
//!
//! The verdict is only known once the stream is fully drained ("write first, check second"):
//! the caller must read the [`VerifySlot`] after the consumer finishes and treat an
//! unpopulated slot (early stop or upstream read error) as a verification failure.
//!
//! Both modes share the same mechanics: whole-object mode is the one-span case
//! (`[0, expected_len)`), so one "current span" is hashed at a time and a chunk is split at
//! span boundaries (one chunk may cross several). Composite mode compares per-part digests to
//! the manifest and recomputes `root` via `Manifest::new`/`Manifest::root`, the same functions
//! `complete_multipart` uses, so the wire encoding is not hand-rolled twice.

use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::domain::error::DomainError;
use crate::infra::content::hash::{Hasher, digest_to_array};
use crate::infra::content::hash_mode::{HashMode, Manifest, ManifestEntry};

/// Where [`verify_stream`] publishes its verdict once the stream is fully drained; stays `None`
/// otherwise, which a caller must treat as a verification failure.
pub type VerifySlot = Arc<Mutex<Option<Result<(), DomainError>>>>;

/// [`verify_stream`]'s return value: the forwarding stream and its [`VerifySlot`].
pub type VerifiedStream = (BoxStream<'static, io::Result<Bytes>>, VerifySlot);

enum VerifyState {
    Reading {
        inner: BoxStream<'static, io::Result<Bytes>>,
        total_seen: u64,
        span_idx: usize,
        hasher: Hasher,
        part_digests: Vec<[u8; 32]>,
    },
    Done,
}

/// One byte span of the object hashed as a single unit: the whole object, or one manifest part.
struct Span {
    end: u64,
}

/// What to compare the finished per-span digests against.
enum Spec {
    /// Compare the single digest to `hash_value`.
    Whole,
    /// Compare each digest to its manifest entry, then the rebuilt manifest's `root()` to
    /// `hash_value`.
    Composite { entries: Vec<ManifestEntry> },
}

/// Validate that `hash_mode`/`manifest` agree (as `Store::verify_content_hash` does) and derive
/// the byte spans up front.
fn build_spec(
    expected_len: u64,
    hash_mode: HashMode,
    manifest: Option<Manifest>,
    hash_value: &[u8],
) -> Result<(Vec<Span>, Spec), DomainError> {
    match hash_mode {
        HashMode::WholeSha256 => {
            if manifest.is_some() {
                return Err(DomainError::validation(
                    "manifest",
                    "whole-sha256 versions carry no manifest",
                ));
            }
            Ok((vec![Span { end: expected_len }], Spec::Whole))
        }
        HashMode::MultipartCompositeSha256 => {
            let manifest = manifest.ok_or_else(|| {
                DomainError::validation(
                    "manifest",
                    "multipart-composite-sha256 verification requires the stored manifest",
                )
            })?;
            let entries = manifest.entries().to_vec();
            let mut spans = Vec::with_capacity(entries.len());
            let last_idx = entries.len().saturating_sub(1);
            for (i, entry) in entries.iter().enumerate() {
                let start = entry.offset;
                let end = entries.get(i + 1).map_or(expected_len, |next| next.offset);
                // A zero-length span is legitimate (S3 composite semantics) only as the last
                // entry; `Manifest::new`'s ascending offsets already guarantee it, so the
                // `i != last_idx` check only guards hand-built manifests.
                if start > end || end > expected_len || (start == end && i != last_idx) {
                    return Err(DomainError::hash_mismatch(
                        hex::encode(hash_value),
                        format!(
                            "manifest offset {start} out of range for a {expected_len} byte(s) object"
                        ),
                    ));
                }
                spans.push(Span { end });
            }
            Ok((spans, Spec::Composite { entries }))
        }
    }
}

/// Feed `chunk` into the span(s) it falls into, finalizing a span's digest as soon as
/// `total_seen` reaches its end (possibly several per chunk). Bytes past the last span are
/// counted into `total_seen` (so an oversized stream fails the length check) but never hashed.
/// `Bytes::split_to` slices without copying.
fn process_chunk(
    mut chunk: Bytes,
    spans: &[Span],
    span_idx: &mut usize,
    total_seen: &mut u64,
    hasher: &mut Hasher,
    part_digests: &mut Vec<[u8; 32]>,
) {
    while !chunk.is_empty() {
        let Some(span) = spans.get(*span_idx) else {
            // Overage bytes: counted for the length check, never hashed.
            *total_seen += chunk.len() as u64;
            return;
        };
        let remaining_in_span = span.end.saturating_sub(*total_seen);
        let take = usize::try_from(remaining_in_span)
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        if take > 0 {
            let head = chunk.split_to(take);
            hasher.update(&head);
            *total_seen += take as u64;
        }
        if *total_seen == span.end {
            let digest = digest_to_array(std::mem::take(hasher).finalize());
            part_digests.push(digest);
            *span_idx += 1;
        }
    }
}

/// Compare the finished per-span digests against `spec`.
fn compare(spec: &Spec, hash_value: &[u8], part_digests: Vec<[u8; 32]>) -> Result<(), DomainError> {
    match spec {
        Spec::Whole => {
            let digest = part_digests
                .into_iter()
                .next()
                .unwrap_or_else(|| digest_to_array(Hasher::new().finalize()));
            if digest.as_slice() != hash_value {
                return Err(DomainError::hash_mismatch(
                    hex::encode(hash_value),
                    hex::encode(digest),
                ));
            }
            Ok(())
        }
        Spec::Composite { entries } => {
            // `zip` stops at the shorter side, which would silently skip unfinalized tail
            // entries; check the lengths explicitly first.
            if part_digests.len() != entries.len() {
                return Err(DomainError::hash_mismatch(
                    hex::encode(hash_value),
                    format!(
                        "expected {} composite part(s) per the manifest, got {} finalized \
                         span(s) from the stream",
                        entries.len(),
                        part_digests.len()
                    ),
                ));
            }
            for (entry, digest) in entries.iter().zip(part_digests.iter()) {
                if *digest != entry.digest {
                    return Err(DomainError::hash_mismatch(
                        hex::encode(entry.digest),
                        format!(
                            "recomputed part digest at offset {}: {}",
                            entry.offset,
                            hex::encode(digest)
                        ),
                    ));
                }
            }
            let rebuilt: Vec<ManifestEntry> = entries
                .iter()
                .zip(part_digests.iter())
                .map(|(e, d)| ManifestEntry {
                    offset: e.offset,
                    digest: *d,
                })
                .collect();
            let root = Manifest::new(rebuilt)?.root();
            if root.as_slice() != hash_value {
                return Err(DomainError::hash_mismatch(
                    hex::encode(hash_value),
                    hex::encode(root),
                ));
            }
            Ok(())
        }
    }
}

/// Wrap `inner` so chunks are forwarded unchanged while the content hash and total length
/// (`expected_len`) are verified; see the module doc for the [`VerifySlot`] contract.
/// `manifest` must be `Some` iff `hash_mode` is `MultipartCompositeSha256`.
///
/// # Errors
/// Returns `Err` up front if `hash_mode`/`manifest` disagree or the manifest offsets exceed
/// `expected_len`.
pub fn verify_stream(
    inner: BoxStream<'static, io::Result<Bytes>>,
    expected_len: u64,
    hash_mode: HashMode,
    hash_value: Vec<u8>,
    manifest: Option<Manifest>,
) -> Result<VerifiedStream, DomainError> {
    let (spans, spec) = build_spec(expected_len, hash_mode, manifest, &hash_value)?;
    let spans = Arc::new(spans);
    let spec = Arc::new(spec);
    let hash_value = Arc::new(hash_value);

    let slot: VerifySlot = Arc::new(Mutex::new(None));
    let out_slot = Arc::clone(&slot);

    let initial = VerifyState::Reading {
        inner,
        total_seen: 0,
        span_idx: 0,
        hasher: Hasher::new(),
        part_digests: Vec::with_capacity(spans.len()),
    };

    let stream = futures::stream::unfold(initial, move |state| {
        let slot = Arc::clone(&slot);
        let spans = Arc::clone(&spans);
        let spec = Arc::clone(&spec);
        let hash_value = Arc::clone(&hash_value);
        async move {
            match state {
                VerifyState::Done => None,
                VerifyState::Reading {
                    mut inner,
                    mut total_seen,
                    mut span_idx,
                    mut hasher,
                    mut part_digests,
                } => match inner.next().await {
                    None => {
                        let verdict = if total_seen == expected_len {
                            // A span still open here is zero-length (`process_chunk` only
                            // finalizes spans while consuming bytes); `build_spec` allows
                            // that only for the last entry, so close it with the empty digest.
                            while span_idx < spans.len() {
                                let digest =
                                    digest_to_array(std::mem::take(&mut hasher).finalize());
                                part_digests.push(digest);
                                span_idx += 1;
                            }
                            compare(&spec, &hash_value, part_digests)
                        } else {
                            Err(DomainError::hash_mismatch(
                                format!("{expected_len} byte(s) (declared version size)"),
                                format!(
                                    "{total_seen} byte(s) actually read from the source backend"
                                ),
                            ))
                        };
                        if let Ok(mut s) = slot.lock() {
                            *s = Some(verdict);
                        }
                        None
                    }
                    Some(Err(e)) => Some((Err(e), VerifyState::Done)),
                    Some(Ok(chunk)) => {
                        let forward = chunk.clone();
                        process_chunk(
                            chunk,
                            &spans,
                            &mut span_idx,
                            &mut total_seen,
                            &mut hasher,
                            &mut part_digests,
                        );
                        Some((
                            Ok(forward),
                            VerifyState::Reading {
                                inner,
                                total_seen,
                                span_idx,
                                hasher,
                                part_digests,
                            },
                        ))
                    }
                },
            }
        }
    });

    Ok((Box::pin(stream), out_slot))
}

/// Wrap a **whole-object** download stream (the sidecar's full, non-`Range` `GET` body),
/// forwarding it unchanged while accumulating its SHA-256; on a mismatch with
/// `expected_sha256_hex` the stream's last item is an `Err`.
///
/// Unlike [`verify_stream`] there is no later moment to read a verdict: by the last chunk the
/// headers and earlier bytes have already reached the client, so the only signal left is
/// aborting the connection (`axum::body::Body::from_stream` does so on a stream `Err`).
///
/// Logs the mismatch at `error!` (digests only, never the object's bytes).
#[must_use]
pub fn verify_whole_object_download_stream(
    inner: BoxStream<'static, io::Result<Bytes>>,
    expected_sha256_hex: String,
) -> BoxStream<'static, io::Result<Bytes>> {
    enum State {
        Reading {
            inner: BoxStream<'static, io::Result<Bytes>>,
            hasher: Hasher,
            expected_hex: String,
        },
        Done,
    }

    let stream = futures::stream::unfold(
        State::Reading {
            inner,
            hasher: Hasher::new(),
            expected_hex: expected_sha256_hex,
        },
        move |state| async move {
            match state {
                State::Done => None,
                State::Reading {
                    mut inner,
                    mut hasher,
                    expected_hex,
                } => match inner.next().await {
                    None => {
                        let digest_hex = hex::encode(hasher.finalize());
                        if digest_hex == expected_hex {
                            None
                        } else {
                            tracing::error!(
                                expected = %expected_hex,
                                actual = %digest_hex,
                                "whole-object download content hash mismatch; aborting response"
                            );
                            let e = io::Error::new(
                                io::ErrorKind::InvalidData,
                                "downloaded object's content does not match its recorded hash",
                            );
                            Some((Err(e), State::Done))
                        }
                    }
                    Some(Err(e)) => Some((Err(e), State::Done)),
                    Some(Ok(chunk)) => {
                        hasher.update(&chunk);
                        Some((
                            Ok(chunk),
                            State::Reading {
                                inner,
                                hasher,
                                expected_hex,
                            },
                        ))
                    }
                },
            }
        },
    );
    Box::pin(stream)
}

#[cfg(test)]
#[path = "stream_verify_tests.rs"]
mod stream_verify_tests;
