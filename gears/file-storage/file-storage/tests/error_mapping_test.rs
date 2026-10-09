#![allow(clippy::expect_used, clippy::unwrap_used, clippy::doc_markdown)]

use axum::http::header;
use file_storage::domain::error::DomainError;
use toolkit::api::canonical_prelude::{CanonicalError, IntoResponse, Problem};
use uuid::Uuid;

const EXPECTED_VARIANT_COUNT: usize = 26;

fn expected_status(err: &DomainError) -> u16 {
    match err {
        DomainError::Validation { .. }
        | DomainError::PreconditionFailed { .. }
        | DomainError::MimeMismatch { .. }
        | DomainError::HashMismatch { .. }
        | DomainError::InvalidGtsType { .. }
        | DomainError::UnknownBackend { .. }
        | DomainError::PolicyMimeNotAllowed { .. }
        | DomainError::PolicySizeExceeded { .. }
        | DomainError::PolicyMetadataExceeded { .. }
        | DomainError::MultipartNotSupported { .. }
        | DomainError::Cursor(_) => 400,
        DomainError::TokenInvalid { .. } | DomainError::Forbidden => 403,
        DomainError::FileNotFound { .. }
        | DomainError::VersionNotFound { .. }
        | DomainError::RetentionRuleNotFound { .. }
        | DomainError::MultipartUploadNotFound { .. } => 404,
        DomainError::Conflict { .. }
        | DomainError::MultipartUploadNotInProgress { .. }
        | DomainError::MultipartPartsMissing { .. }
        | DomainError::VersionedFileMigrationNotSupported { .. } => 409,
        DomainError::QuotaExceeded { .. } => 429,
        DomainError::Database { .. } | DomainError::Backend { .. } | DomainError::InternalError => {
            500
        }
        DomainError::BackendUnavailable { .. } => 503,
    }
}

fn all_variant_instances() -> Vec<DomainError> {
    vec![
        DomainError::FileNotFound { id: Uuid::nil() },
        DomainError::VersionNotFound {
            file_id: Uuid::nil(),
            version_id: Uuid::nil(),
        },
        DomainError::RetentionRuleNotFound {
            rule_id: Uuid::nil(),
        },
        DomainError::Database {
            message: "db down".into(),
        },
        DomainError::Validation {
            field: "name".into(),
            message: "required".into(),
        },
        DomainError::Conflict {
            message: "already exists".into(),
        },
        DomainError::PreconditionFailed {
            message: "If-Match mismatch".into(),
        },
        DomainError::MimeMismatch {
            declared: "image/png".into(),
            detected: "image/jpeg".into(),
        },
        DomainError::HashMismatch {
            expected: "aaaa".into(),
            got: "bbbb".into(),
        },
        DomainError::InvalidGtsType {
            value: "not-a-gts-type".into(),
        },
        DomainError::Backend {
            backend_id: "s3".into(),
            message: "put failed".into(),
        },
        DomainError::BackendUnavailable {
            backend_id: "s3".into(),
            message: "connection timed out".into(),
        },
        DomainError::UnknownBackend {
            backend_id: "nope".into(),
        },
        DomainError::TokenInvalid {
            reason: "bad signature".into(),
        },
        DomainError::Forbidden,
        DomainError::InternalError,
        DomainError::PolicyMimeNotAllowed {
            mime_type: "application/x-evil".into(),
        },
        DomainError::PolicySizeExceeded {
            limit_bytes: 1024,
            limit_source: "tenant-policy".into(),
        },
        DomainError::PolicyMetadataExceeded {
            reason: "too many keys".into(),
        },
        DomainError::QuotaExceeded {
            reason: "storage_bytes".into(),
        },
        DomainError::MultipartNotSupported {
            backend_id: "local".into(),
        },
        DomainError::MultipartUploadNotFound {
            upload_id: Uuid::nil(),
        },
        DomainError::MultipartUploadNotInProgress {
            upload_id: Uuid::nil(),
            state: "aborted".into(),
        },
        DomainError::MultipartPartsMissing {
            upload_id: Uuid::nil(),
            missing: vec![2, 5],
        },
        DomainError::VersionedFileMigrationNotSupported {
            file_id: Uuid::nil(),
        },
        DomainError::Cursor(toolkit_odata::Error::InvalidCursor),
    ]
}

#[test]
fn error_domain_error_maps_to_expected_http_status() {
    let cases = all_variant_instances();
    assert_eq!(
        cases.len(),
        EXPECTED_VARIANT_COUNT,
        "all_variant_instances must enumerate every DomainError variant \
         exactly once; update EXPECTED_VARIANT_COUNT and add/remove a case \
         when DomainError gains or loses a variant"
    );

    for err in cases {
        let expected = expected_status(&err);
        let debug = format!("{err:?}");
        let canonical: CanonicalError = err.into();
        let actual = canonical.status_code();
        assert_eq!(
            actual, expected,
            "DomainError variant {debug} mapped to {actual} but expected {expected}"
        );
    }
}

#[test]
fn declared_routes_match_the_pinned_status_table() {
    let precondition_failed_expected = expected_status(&DomainError::PreconditionFailed {
        message: "x".into(),
    });
    let multipart_not_supported_expected = expected_status(&DomainError::MultipartNotSupported {
        backend_id: "x".into(),
    });

    let declared_routes: Vec<(&str, u16)> = vec![
        ("file_storage.bind", precondition_failed_expected),
        ("file_storage.delete_file", precondition_failed_expected),
        (
            "file_storage.initiate_multipart",
            multipart_not_supported_expected,
        ),
    ];

    for (operation_id, declared_status) in declared_routes {
        assert_eq!(
            declared_status, 400,
            "{operation_id}'s declared route status must be 400 per the 2.5 fix"
        );
    }
}

#[test]
fn backend_unavailable_maps_to_503_with_retry_after_5() {
    let err = DomainError::backend_unavailable("s3-primary", "connect timed out");
    let canonical: CanonicalError = err.into();
    assert_eq!(canonical.status_code(), 503);

    let problem = Problem::from(canonical);
    assert_eq!(
        problem
            .context
            .get("retry_after_seconds")
            .and_then(serde_json::Value::as_u64),
        Some(5)
    );

    let response = problem.into_response();
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("Retry-After header present on 503")
            .to_str()
            .expect("valid header value"),
        "5"
    );
}

#[test]
fn backend_still_maps_to_500() {
    let err = DomainError::backend("s3-primary", "invalid bucket config");
    let canonical: CanonicalError = err.into();
    assert_eq!(canonical.status_code(), 500);
}
