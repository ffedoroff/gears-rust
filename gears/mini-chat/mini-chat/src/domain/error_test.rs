use super::DomainError;

/// ML-5130: `toolkit_odata::Error` has 15 variants; only `Db` and
/// `ParsingUnavailable` are genuine infrastructure failures. The other 13
/// originate from a caller-supplied `$filter` / `$orderby` / cursor / `$top`
/// and must classify as `DomainError::Validation` (-> HTTP 400), never
/// `DomainError::Database` (-> HTTP 500). Mirrors the classifier contract
/// documented over `toolkit_odata::Error` (`libs/toolkit-odata/src/lib.rs`)
/// and its `problem_mapping` (`libs/toolkit-odata/src/problem_mapping.rs`).
fn assert_database(e: toolkit_odata::Error) {
    let mapped: DomainError = e.into();
    assert!(
        matches!(mapped, DomainError::Database { .. }),
        "expected Database, got {mapped:?}"
    );
}

fn assert_validation(e: toolkit_odata::Error) {
    let mapped: DomainError = e.into();
    assert!(
        matches!(mapped, DomainError::Validation { .. }),
        "expected Validation, got {mapped:?}"
    );
}

#[test]
fn db_error_classifies_as_database() {
    assert_database(toolkit_odata::Error::Db("connection reset".to_owned()));
}

#[test]
fn parsing_unavailable_classifies_as_database() {
    assert_database(toolkit_odata::Error::ParsingUnavailable(
        "grammar not loaded",
    ));
}

#[test]
fn invalid_filter_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::InvalidFilter("bad filter".to_owned()));
}

#[test]
fn invalid_orderby_field_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::InvalidOrderByField(
        "not_a_real_field".to_owned(),
    ));
}

#[test]
fn order_mismatch_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::OrderMismatch);
}

#[test]
fn filter_mismatch_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::FilterMismatch);
}

#[test]
fn invalid_cursor_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::InvalidCursor);
}

#[test]
fn invalid_limit_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::InvalidLimit);
}

#[test]
fn order_with_cursor_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::OrderWithCursor);
}

#[test]
fn cursor_invalid_base64_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::CursorInvalidBase64);
}

#[test]
fn cursor_invalid_json_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::CursorInvalidJson);
}

#[test]
fn cursor_invalid_version_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::CursorInvalidVersion);
}

#[test]
fn cursor_invalid_keys_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::CursorInvalidKeys);
}

#[test]
fn cursor_invalid_fields_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::CursorInvalidFields);
}

#[test]
fn cursor_invalid_direction_classifies_as_validation() {
    assert_validation(toolkit_odata::Error::CursorInvalidDirection);
}
