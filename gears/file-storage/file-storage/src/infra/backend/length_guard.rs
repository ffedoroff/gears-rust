//! Enforces that a byte stream yields exactly the length its caller already committed to
//! (e.g. an already-sent `Content-Length`) before it ends successfully.
//!
//! The backend's `Content-Length` check is skippable (chunked responses carry none);
//! [`length_guard`] holds for every response shape.

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use std::io;

/// Wraps `inner` so it yields exactly `expected_len` bytes, erroring instead of completing at
/// a different length.
///
/// - Too short: the final item is `Err(UnexpectedEof)` instead of a clean end.
/// - Too long: the chunk crossing the boundary is truncated to it, and the next poll yields
///   `Err(InvalidData)`; a chunk ending exactly on the boundary with more to come yields the
///   error immediately.
/// - A read error from `inner` passes through unchanged and ends the stream.
///
/// `expected_len == 0` with an immediately-ending `inner` yields an empty stream, not an error.
pub fn length_guard(
    inner: BoxStream<'static, io::Result<Bytes>>,
    expected_len: u64,
) -> BoxStream<'static, io::Result<Bytes>> {
    /// `Pending` holds the overflow error to surface on the poll after the truncated chunk.
    enum State {
        Reading {
            inner: BoxStream<'static, io::Result<Bytes>>,
            seen: u64,
        },
        Pending(io::Error),
        Done,
    }

    let stream = futures::stream::unfold(
        State::Reading { inner, seen: 0 },
        move |state| async move {
            match state {
                State::Done => None,
                State::Pending(e) => Some((Err(e), State::Done)),
                State::Reading { mut inner, seen } => match inner.next().await {
                    None => {
                        if seen == expected_len {
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
                        let n = chunk.len() as u64;
                        let new_seen = seen + n;
                        if new_seen <= expected_len {
                            Some((
                                Ok(chunk),
                                State::Reading {
                                    inner,
                                    seen: new_seen,
                                },
                            ))
                        } else {
                            let over_err = io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "stream exceeded the expected {expected_len} byte(s) (at least {new_seen} byte(s) seen)"
                                ),
                            );
                            // Only `allowed` bytes are within the promised length.
                            let allowed = usize::try_from(expected_len - seen).unwrap_or(0);
                            if allowed == 0 {
                                Some((Err(over_err), State::Done))
                            } else {
                                let truncated = chunk.slice(0..allowed);
                                Some((Ok(truncated), State::Pending(over_err)))
                            }
                        }
                    }
                },
            }
        },
    );
    Box::pin(stream)
}

#[cfg(test)]
#[path = "length_guard_tests.rs"]
mod length_guard_tests;
