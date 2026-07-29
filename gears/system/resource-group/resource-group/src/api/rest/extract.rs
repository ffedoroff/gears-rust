// Created: 2026-07-29 by Constructor Tech
//! Request-body extractor that keeps serde rejections on the RFC-9457 path.
//!
//! `toolkit::api::canonical_prelude` re-exports `axum::Json`, whose
//! `JsonRejection` renders as a bare `text/plain` body — 400 for a syntax
//! error, **422** for a schema error (unknown field, missing field, wrong
//! type). `canonical_error_middleware` cannot repair that: it only rewrites
//! responses that already carry `application/problem+json`. So on a route
//! whose DTO relies on serde to enforce the wire envelope, the strictness is
//! invisible to a client that speaks RFC 9457 — contradicting
//! `docs/toolkit_unified_system/04_rest_operation_builder.md`, "Always return
//! RFC 9457 Problem Details for all 4xx/5xx errors".
//!
//! [`StrictJson`] closes that on the routes that need it: it performs the same
//! `serde` deserialization (so `#[serde(deny_unknown_fields)]` and every other
//! serde attribute still do the deciding) and routes a failure through
//! `DomainError::validation` → the gear's single
//! `From<DomainError> for CanonicalError` ladder, landing on the same
//! `problem+json` 400 as every other caller error in this gear.
//!
//! Used on **every** route in this gear that takes a request body, not only the
//! strict full-replacement ones. Uniformity is the point: a client should not
//! have to learn which RG endpoint answers a bad body in RFC 9457 and which
//! answers in `text/plain`. The strict DTOs are simply where it matters most,
//! because there `deny_unknown_fields` and the required-key checks make serde
//! rejections a routine, expected outcome rather than a sign of a broken
//! client.
//!
//! The general fix belongs in the toolkit prelude's own `Json` — every gear in
//! the repository has this gap, which is why their tests accept `400 || 422`.
//! This type is a gear-local stopgap, not a licence to fork that decision per
//! gear; if the prelude gains a canonical `Json`, delete this module and switch
//! back.

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use axum::http::header;
use toolkit_canonical_errors::CanonicalError;

use crate::domain::error::DomainError;

/// `Json`-shaped extractor whose rejection is a canonical `problem+json` 400.
///
/// Drop-in for `axum::Json` in a handler signature:
/// `StrictJson(req_body): StrictJson<UpdateGroupDto>`.
#[derive(Debug, Clone, Copy)]
pub struct StrictJson<T>(pub T);

impl<T, S> FromRequest<S> for StrictJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = CanonicalError;

    #[allow(clippy::manual_async_fn)]
    fn from_request(
        req: Request,
        state: &S,
    ) -> impl core::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            // Reject a non-JSON body up front, mirroring what `axum::Json`
            // checks — but as a 400 on the canonical path rather than a bare
            // 415, since a wrong `Content-Type` on these routes is a client
            // mistake indistinguishable in effect from a malformed body.
            if !is_json_content_type(&req) {
                return Err(DomainError::validation(
                    "request body must be sent as application/json",
                )
                .into());
            }

            let bytes = Bytes::from_request(req, state).await.map_err(|e| {
                CanonicalError::from(DomainError::validation(format!(
                    "could not read the request body: {e}"
                )))
            })?;

            serde_json::from_slice::<T>(&bytes)
                .map(StrictJson)
                .map_err(|e| {
                    // `serde_json`'s message names the offending key and the line
                    // and column, which is precisely what a client needs to fix
                    // the payload; it describes the caller's own request, so it
                    // discloses nothing.
                    CanonicalError::from(DomainError::validation(format!(
                        "invalid request body: {e}"
                    )))
                })
        }
    }
}

/// Whether the request declares a JSON body. Accepts `application/json` and
/// the `+json` structured suffix, with or without parameters — the same family
/// `axum::Json` accepts. Hand-rolled rather than pulling in the `mime` crate
/// for one predicate.
fn is_json_content_type(req: &Request) -> bool {
    let Some(value) = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json"
        || (essence.starts_with("application/") && essence.ends_with("+json"))
}

#[cfg(test)]
#[path = "extract_tests.rs"]
mod tests;
