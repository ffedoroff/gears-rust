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
//! **Known status-classification gap (platform, not gear).** Two of the
//! failures below are owed a status the canonical taxonomy cannot express, so
//! they are canonical 400s instead: an unsupported/missing `Content-Type`
//! (`guidelines/DNA/REST/STATUS_CODES.md` requires 415) and a body over the
//! request-body limit (413). `CanonicalError::status_code` has no 415 or 413
//! category at all, and the whole point of this extractor is that every
//! rejection stays on the RFC-9457 ladder, so neither can be fixed here — the
//! platform's own API Gateway answers the media-type case with a canonical 400
//! for exactly the same reason. See the comments at each site; the fix is a
//! `toolkit-canonical-errors` change.
//!
//! The general fix belongs in the toolkit prelude's own `Json` — every gear in
//! the repository has this gap, which is why their tests accept `400 || 422`.
//! This type is a gear-local stopgap, not a licence to fork that decision per
//! gear; if the prelude gains a canonical `Json`, delete this module and switch
//! back.

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, FailedToBufferBody};
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
            // checks.
            //
            // **This is a 400, and `guidelines/DNA/REST/STATUS_CODES.md`
            // requires 415 — a platform gap, not a gear preference.**
            // `CanonicalError` has no category that maps to 415: its
            // `status_code()` ladder covers 400/401/403/404/409/429/499/5xx and
            // nothing else, and this extractor's `Rejection` is a
            // `CanonicalError` precisely so every failure stays on the RFC-9457
            // ladder (see this module's header). Minting a bare 415 outside
            // that ladder would trade a wrong status for a non-canonical body,
            // which is the worse of the two. The platform's own API Gateway
            // made the same call in the same situation: its
            // `mime_validation_middleware` answers an unsupported or missing
            // `Content-Type` with a canonical `invalid_argument` (400) carrying
            // `field_violations[0].reason = UNSUPPORTED_MEDIA_TYPE` /
            // `MISSING_CONTENT_TYPE`, documenting that there is "no top-level
            // `CanonicalError::*` constructor for this category". Fixing this
            // properly means adding the category to
            // `toolkit-canonical-errors`; until then the deviation is recorded
            // in `docs/DESIGN.md` (§ "Strictness is the other half of the
            // decision") rather than worked around here.
            if !is_json_content_type(&req) {
                return Err(DomainError::validation(
                    "request body must be sent as application/json",
                )
                .into());
            }

            // Every `Bytes` rejection lands on a canonical 400. The one that
            // *should* differ is the body-limit rejection
            // (`FailedToBufferBody::LengthLimitError`), which
            // `STATUS_CODES.md` assigns 413 — and which is reachable here
            // without any extra middleware, because `Bytes::from_request`
            // applies axum's 2 MiB `DefaultBodyLimit` itself (an explicit
            // `DefaultBodyLimit` / `RequestBodyLimitLayer` only changes the
            // threshold). Same platform gap as the media-type case above:
            // `CanonicalError` has no 413 category either (`ResourceExhausted`
            // is 429, `OutOfRange` is 400), so the status cannot be expressed
            // without leaving the canonical ladder.
            //
            // What *is* fixable without leaving it: axum renders both
            // `FailedToBufferBody` variants with the identical string
            // ("Failed to buffer the request body"), so the flattened message
            // used to tell a client nothing about which one it hit. Match the
            // variant and say so.
            let bytes = Bytes::from_request(req, state)
                .await
                .map_err(|e| CanonicalError::from(DomainError::validation(body_read_detail(&e))))?;

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

/// Human-readable detail for a failed body read.
///
/// Names the body-limit case explicitly: axum's `Display` is the same string
/// for every `FailedToBufferBody` variant, and the canonical taxonomy cannot
/// express the 413 this case is owed (see [`StrictJson::from_request`]), so the
/// detail is the only place a client can learn that the body was too large
/// rather than unreadable.
fn body_read_detail(rejection: &BytesRejection) -> String {
    match rejection {
        BytesRejection::FailedToBufferBody(FailedToBufferBody::LengthLimitError(_)) => {
            "request body exceeds the maximum accepted size".to_owned()
        }
        other => format!("could not read the request body: {other}"),
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
