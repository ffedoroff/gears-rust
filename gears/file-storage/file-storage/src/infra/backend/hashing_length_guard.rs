//! Wraps a byte stream so it enforces `length_guard`'s exact-length
//! contract and accumulates the SHA-256 of the bytes it forwards, in a single pass (used for
//! `S3Backend::upload_part_stream`, where the part must not be buffered just to hash it).
//!
//! The digest is published *speculatively* the moment the running count reaches
//! `expected_len`, not after a trailing `None` poll: an HTTP client sending a fixed
//! `Content-Length` request body may never poll again once it has written that many bytes.
//! If a caller keeps polling and more data turns up, the digest is revoked (slot cleared)
//! and the stream errors like `length_guard` would.

use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;

use crate::infra::content::hash::{Hasher, digest_to_array};

/// Where [`hashing_length_guard`] publishes the digest once exactly `expected_len` bytes
/// were yielded. Stays (or is reset to) `None` on every error path, so a caller must trust
/// a populated digest only after the stream's consumer (e.g. the HTTP client) succeeded.
pub type DigestSlot = Arc<Mutex<Option<[u8; 32]>>>;

/// `inner` must yield exactly `expected_len` bytes, or the returned stream errors like
/// `length_guard` (see the module doc for when the digest is published).
pub fn hashing_length_guard(
    inner: BoxStream<'static, io::Result<Bytes>>,
    expected_len: u64,
) -> (BoxStream<'static, io::Result<Bytes>>, DigestSlot) {
    /// `unfold` state: as in `length_guard`, plus a running hasher below `expected_len`.
    enum State {
        Reading {
            inner: BoxStream<'static, io::Result<Bytes>>,
            hasher: Hasher,
        },
        /// `expected_len` bytes seen and digest already published; still watching `inner`
        /// for oversize data.
        AtBoundary {
            inner: BoxStream<'static, io::Result<Bytes>>,
        },
        Pending(io::Error),
        Done,
    }

    let digest_slot: DigestSlot = Arc::new(Mutex::new(None));
    let out_slot = Arc::clone(&digest_slot);

    let stream = futures::stream::unfold(
        State::Reading {
            inner,
            hasher: Hasher::new(),
        },
        move |state| {
            let digest_slot = Arc::clone(&digest_slot);
            async move {
                match state {
                    State::Done => None,
                    State::Pending(e) => Some((Err(e), State::Done)),
                    State::AtBoundary { mut inner } => match inner.next().await {
                        // Clean end: the published digest stands.
                        None => None,
                        // Misbehaved past the promised length: revoke the digest.
                        Some(Err(e)) => {
                            if let Ok(mut slot) = digest_slot.lock() {
                                *slot = None;
                            }
                            Some((Err(e), State::Done))
                        }
                        Some(Ok(_chunk)) => {
                            if let Ok(mut slot) = digest_slot.lock() {
                                *slot = None;
                            }
                            let over_err = io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "stream exceeded the expected {expected_len} byte(s) after \
                                     already reaching it exactly"
                                ),
                            );
                            Some((Err(over_err), State::Done))
                        }
                    },
                    State::Reading {
                        mut inner,
                        mut hasher,
                    } => match inner.next().await {
                        None => {
                            let seen = hasher.len();
                            if seen == expected_len {
                                let digest = digest_to_array(hasher.finalize());
                                if let Ok(mut slot) = digest_slot.lock() {
                                    *slot = Some(digest);
                                }
                                None
                            } else {
                                let e = io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    format!(
                                        "stream ended {} byte(s) short of the expected {expected_len} byte(s)",
                                        expected_len - seen
                                    ),
                                );
                                Some((Err(e), State::Done))
                            }
                        }
                        Some(Err(e)) => Some((Err(e), State::Done)),
                        Some(Ok(chunk)) => {
                            let seen = hasher.len();
                            let n = chunk.len() as u64;
                            let new_seen = seen + n;
                            match new_seen.cmp(&expected_len) {
                                std::cmp::Ordering::Less => {
                                    hasher.update(&chunk);
                                    Some((Ok(chunk), State::Reading { inner, hasher }))
                                }
                                std::cmp::Ordering::Equal => {
                                    // Publish now; see the module doc.
                                    hasher.update(&chunk);
                                    let digest = digest_to_array(hasher.finalize());
                                    if let Ok(mut slot) = digest_slot.lock() {
                                        *slot = Some(digest);
                                    }
                                    Some((Ok(chunk), State::AtBoundary { inner }))
                                }
                                std::cmp::Ordering::Greater => {
                                    let over_err = io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!(
                                            "stream exceeded the expected {expected_len} byte(s) (at least {new_seen} byte(s) seen)"
                                        ),
                                    );
                                    // Only `allowed` bytes are within the promised length;
                                    // the rest must reach neither the caller nor the hasher.
                                    let allowed = usize::try_from(expected_len - seen).unwrap_or(0);
                                    if allowed == 0 {
                                        Some((Err(over_err), State::Done))
                                    } else {
                                        let truncated = chunk.slice(0..allowed);
                                        hasher.update(&truncated);
                                        Some((Ok(truncated), State::Pending(over_err)))
                                    }
                                }
                            }
                        }
                    },
                }
            }
        },
    );
    (Box::pin(stream), out_slot)
}

#[cfg(test)]
#[path = "hashing_length_guard_tests.rs"]
mod hashing_length_guard_tests;
