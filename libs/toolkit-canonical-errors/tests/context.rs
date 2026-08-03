extern crate toolkit_canonical_errors;

use toolkit_canonical_errors::{
    Aborted, AlreadyExists, Cancelled, DataLoss, DeadlineExceeded, FailedPrecondition,
    FieldViolation, Internal, InvalidArgument, NotFound, OutOfRange, PermissionDenied,
    PreconditionViolation, QuotaViolation, ResourceExhausted, ServiceUnavailable, Unauthenticated,
    Unimplemented, Unknown,
};

// =========================================================================
// Shared inner types
// =========================================================================

#[test]
fn field_violation_serialization() {
    let v = FieldViolation::new("email", "must be valid", "INVALID_FORMAT");
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json["field"], "email");
    assert_eq!(json["description"], "must be valid");
    assert_eq!(json["reason"], "INVALID_FORMAT");
}

#[test]
fn quota_violation_serialization() {
    let v = QuotaViolation::new("requests_per_minute", "Limit exceeded");
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json["subject"], "requests_per_minute");
    assert_eq!(json["description"], "Limit exceeded");
}

#[test]
fn precondition_violation_serialization() {
    let v = PreconditionViolation::new("STATE", "tenant.users", "Must have zero users");
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json["type"], "STATE");
    assert_eq!(json["subject"], "tenant.users");
    assert_eq!(json["description"], "Must have zero users");
}

/// `blocking_entity_ids` is opt-in: `new()` leaves it empty, and an empty
/// list is omitted from the wire form entirely (`skip_serializing_if`) --
/// there's no "empty array" ever sent, so old consumers that don't know the
/// field see the same shape as before this field existed.
#[test]
fn precondition_violation_blocking_entity_ids_default_is_omitted_from_wire() {
    let v = PreconditionViolation::new("STATE", "tenant.users", "Must have zero users");
    assert!(v.blocking_entity_ids.is_empty());

    let json = serde_json::to_value(&v).unwrap();
    assert!(
        json.get("blocking_entity_ids").is_none(),
        "empty blocking_entity_ids must not appear on the wire: {json}"
    );
}

/// `with_blocking_entity_ids` populates the field, and a populated field
/// round-trips through serialize -> deserialize unchanged.
#[test]
fn precondition_violation_blocking_entity_ids_round_trips_when_set() {
    let v = PreconditionViolation::new("STATE", "active_references", "has blockers")
        .with_blocking_entity_ids(vec!["child-1".to_owned(), "child-2".to_owned()]);

    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(
        json["blocking_entity_ids"],
        serde_json::json!(["child-1", "child-2"])
    );

    let restored: PreconditionViolation = serde_json::from_value(json).unwrap();
    assert_eq!(
        restored.blocking_entity_ids,
        vec!["child-1".to_owned(), "child-2".to_owned()]
    );
}

/// Wire compatibility: a JSON payload produced by an emitter that predates
/// this field (no `blocking_entity_ids` key at all) must still deserialize,
/// with the field defaulting to empty.
#[test]
fn precondition_violation_deserializes_pre_existing_wire_payload_without_the_field() {
    let old_wire = serde_json::json!({
        "type": "STATE",
        "subject": "active_references",
        "description": "has blockers"
    });

    let restored: PreconditionViolation = serde_json::from_value(old_wire).unwrap();
    assert_eq!(restored.type_, "STATE");
    assert_eq!(restored.subject, "active_references");
    assert_eq!(restored.description, "has blockers");
    assert!(restored.blocking_entity_ids.is_empty());
}

// =========================================================================
// Per-category context serialization tests
// =========================================================================

#[test]
fn cancelled_serialization() {
    let ctx = Cancelled::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn unknown_serialization() {
    let ctx = Unknown::new("something went wrong");
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn invalid_argument_field_violations_serialization() {
    let ctx = InvalidArgument::fields(vec![FieldViolation::new(
        "email",
        "must be valid",
        "INVALID_FORMAT",
    )]);
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json["field_violations"].is_array());
    assert_eq!(json["field_violations"][0]["field"], "email");
}

#[test]
fn invalid_argument_format_serialization() {
    let ctx = InvalidArgument::format("bad json");
    let json = serde_json::to_value(&ctx).unwrap();
    assert_eq!(json["format"], "bad json");
}

#[test]
fn invalid_argument_constraint_serialization() {
    let ctx = InvalidArgument::constraint("too many items");
    let json = serde_json::to_value(&ctx).unwrap();
    assert_eq!(json["constraint"], "too many items");
}

#[test]
fn deadline_exceeded_serialization() {
    let ctx = DeadlineExceeded::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn not_found_serialization() {
    let ctx = NotFound::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn already_exists_serialization() {
    let ctx = AlreadyExists::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn permission_denied_serialization() {
    let ctx = PermissionDenied::new("CROSS_TENANT_ACCESS");
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
    assert_eq!(json["reason"], "CROSS_TENANT_ACCESS");
}

#[test]
fn resource_exhausted_serialization() {
    let ctx = ResourceExhausted::new(vec![QuotaViolation::new("rpm", "exceeded")]);
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json["violations"].is_array());
    assert_eq!(json["violations"][0]["subject"], "rpm");
}

#[test]
fn failed_precondition_serialization() {
    let ctx = FailedPrecondition::new(vec![PreconditionViolation::new("STATE", "s", "d")]);
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json["violations"].is_array());
}

#[test]
fn aborted_serialization() {
    let ctx = Aborted::new("OPTIMISTIC_LOCK_FAILURE");
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
    assert_eq!(json["reason"], "OPTIMISTIC_LOCK_FAILURE");
}

#[test]
fn out_of_range_field_violations_serialization() {
    let ctx = OutOfRange::new(vec![FieldViolation::new(
        "page",
        "must be between 1 and 12",
        "OUT_OF_RANGE",
    )]);
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json["field_violations"].is_array());
    assert_eq!(json["field_violations"][0]["field"], "page");
}

#[test]
fn unimplemented_serialization() {
    let ctx = Unimplemented::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn internal_serialization() {
    let ctx = Internal::new("db pool exhausted");
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn service_unavailable_serialization() {
    let ctx = ServiceUnavailable::new(Some(30));
    let json = serde_json::to_value(&ctx).unwrap();
    assert_eq!(json["retry_after_seconds"], 30);
}

#[test]
fn data_loss_serialization() {
    let ctx = DataLoss::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}

#[test]
fn unauthenticated_serialization() {
    let ctx = Unauthenticated::new();
    let json = serde_json::to_value(&ctx).unwrap();
    assert!(json.is_object());
}
