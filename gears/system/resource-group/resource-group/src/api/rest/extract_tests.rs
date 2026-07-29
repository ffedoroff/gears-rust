// Created: 2026-07-29 by Constructor Tech
use super::*;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::IntoResponse;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    name: String,
}

fn request_with(content_type: Option<&str>, body: &str) -> Request {
    let mut builder = Request::builder().method("PUT").uri("/probe");
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    builder.body(Body::from(body.to_owned())).expect("request")
}

async fn extract(req: Request) -> Result<Probe, StatusCode> {
    match StrictJson::<Probe>::from_request(req, &()).await {
        Ok(StrictJson(v)) => Ok(v),
        Err(e) => Err(e.into_response().status()),
    }
}

#[tokio::test]
async fn accepts_a_well_formed_json_body() {
    let got = extract(request_with(Some("application/json"), r#"{"name":"ok"}"#))
        .await
        .expect("well-formed body must deserialize");
    assert_eq!(got.name, "ok");
}

#[tokio::test]
async fn accepts_content_type_parameters_and_json_suffix() {
    for ct in [
        "application/json; charset=utf-8",
        "APPLICATION/JSON",
        "application/merge-patch+json",
    ] {
        extract(request_with(Some(ct), r#"{"name":"ok"}"#))
            .await
            .unwrap_or_else(|s| panic!("content-type {ct} must be accepted, got {s}"));
    }
}

/// The point of the whole extractor: a serde rejection is a **400**, not
/// axum's 422, so it can be rendered as RFC-9457 `problem+json` by the
/// canonical ladder.
#[tokio::test]
async fn serde_failures_are_400_not_422() {
    // Unknown field (`deny_unknown_fields`).
    let status = extract(request_with(
        Some("application/json"),
        r#"{"name":"ok","surprise":1}"#,
    ))
    .await
    .expect_err("unknown field must be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Missing required field.
    let status = extract(request_with(Some("application/json"), "{}"))
        .await
        .expect_err("missing field must be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wrong type.
    let status = extract(request_with(Some("application/json"), r#"{"name":7}"#))
        .await
        .expect_err("wrong type must be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Malformed JSON.
    let status = extract(request_with(Some("application/json"), "{not json"))
        .await
        .expect_err("malformed JSON must be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejects_a_missing_or_non_json_content_type() {
    let status = extract(request_with(None, r#"{"name":"ok"}"#))
        .await
        .expect_err("absent content-type must be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let status = extract(request_with(Some("text/plain"), r#"{"name":"ok"}"#))
        .await
        .expect_err("non-JSON content-type must be rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Render a rejection to `(content_type, parsed problem body)`.
async fn problem_of(err: CanonicalError) -> (String, serde_json::Value) {
    let response = err.into_response();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let problem = serde_json::from_slice(&bytes).expect("parse problem");
    (content_type, problem)
}

/// Assert a rejection carries the full RFC-9457 envelope.
fn assert_problem_shape(content_type: &str, problem: &serde_json::Value, expected_status: u16) {
    assert!(
        content_type.contains("application/problem+json"),
        "rejection must be problem+json, got {content_type}"
    );
    for key in ["type", "title", "status", "detail"] {
        assert!(
            problem.get(key).is_some(),
            "RFC-9457 requires `{key}`: {problem}"
        );
    }
    assert_eq!(problem["status"], expected_status, "{problem}");
}

/// The rejection body is a `problem+json` document, which is the whole reason
/// this extractor exists.
#[tokio::test]
async fn rejection_renders_as_problem_json() {
    let err = StrictJson::<Probe>::from_request(
        request_with(Some("application/json"), r#"{"name":"ok","surprise":1}"#),
        &(),
    )
    .await
    .expect_err("unknown field must be rejected");

    let (content_type, problem) = problem_of(err).await;
    assert_problem_shape(&content_type, &problem, 400);
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains("surprise")),
        "detail should name the offending key: {problem}"
    );
}

/// T1.4: a wrong/absent `Content-Type` keeps the full RFC-9457 envelope.
///
/// **The status is 400 and `guidelines/DNA/REST/STATUS_CODES.md` asks for
/// 415.** That is not fixable in this extractor: `CanonicalError` has no
/// category mapping to 415 (see [`super::StrictJson::from_request`]'s comment,
/// and note that the platform's own API Gateway answers the same condition
/// with a canonical 400 for the same reason). This test pins what *is*
/// guaranteed — the envelope — and pins the deviation so that adding a 415
/// category to `toolkit-canonical-errors` makes it fail loudly here rather
/// than going unnoticed.
#[tokio::test]
async fn wrong_content_type_rejection_is_a_full_problem_document() {
    for ct in [None, Some("text/plain"), Some("application/xml")] {
        let err = StrictJson::<Probe>::from_request(request_with(ct, r#"{"name":"ok"}"#), &())
            .await
            .expect_err("a non-JSON content-type must be rejected");
        let (content_type, problem) = problem_of(err).await;
        assert_problem_shape(&content_type, &problem, 400);
        assert!(
            problem["detail"]
                .as_str()
                .is_some_and(|d| d.contains("application/json")),
            "detail should name the media type the route expects: {problem}"
        );
    }
}

/// T1.4: a body over the request-body limit keeps the full RFC-9457 envelope,
/// and its detail says the body was too large rather than unreadable.
///
/// Reachable with no extra middleware: `Bytes::from_request` applies axum's
/// 2 MiB `DefaultBodyLimit` itself. **The status is 400 and `STATUS_CODES.md`
/// asks for 413** — same platform gap as the media-type case above
/// (`CanonicalError` has no 413 category: `ResourceExhausted` is 429,
/// `OutOfRange` is 400), so only the envelope and the detail are in this
/// gear's hands.
#[tokio::test]
async fn oversize_body_rejection_is_a_full_problem_document() {
    // 2 MiB + 1 of valid JSON: past axum's default limit, so the rejection is
    // a `LengthLimitError` rather than a serde error.
    let padding = "a".repeat(2 * 1024 * 1024 + 1);
    let body = format!(r#"{{"name":"{padding}"}}"#);
    let err = StrictJson::<Probe>::from_request(request_with(Some("application/json"), &body), &())
        .await
        .expect_err("a body over the limit must be rejected");

    let (content_type, problem) = problem_of(err).await;
    assert_problem_shape(&content_type, &problem, 400);
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains("exceeds the maximum accepted size")),
        "detail must distinguish the body-limit case from an unreadable body -- axum renders both \
         `FailedToBufferBody` variants with the same string: {problem}"
    );
}
