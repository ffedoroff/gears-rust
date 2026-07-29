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

    let response = err.into_response();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        content_type.contains("application/problem+json"),
        "rejection must be problem+json, got {content_type}"
    );

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let problem: serde_json::Value = serde_json::from_slice(&bytes).expect("parse problem");
    assert_eq!(problem["status"], 400);
    assert!(
        problem["detail"]
            .as_str()
            .is_some_and(|d| d.contains("surprise")),
        "detail should name the offending key: {problem}"
    );
}
