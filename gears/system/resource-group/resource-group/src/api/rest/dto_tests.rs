// Created: 2026-04-16 by Constructor Tech
use super::*;
use toolkit_gts::{GTS_ID_PREFIX, gts_id};
use uuid::Uuid;

// TC-DTO-01: ResourceGroupType -> TypeDto
#[test]
fn dto_type_from_resource_group_type() {
    let rgt = ResourceGroupType {
        code: gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~").to_owned(),
        can_be_root: true,
        allowed_parent_types: vec![format!("{GTS_ID_PREFIX}parent~")],
        allowed_membership_types: vec![format!("{GTS_ID_PREFIX}member~")],
        metadata_schema: Some(serde_json::json!({"type": "object"})),
    };
    let dto: TypeDto = rgt.into();
    assert_eq!(
        dto.code,
        gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~")
    );
    assert!(dto.can_be_root);
    assert_eq!(
        dto.allowed_parent_types,
        vec![format!("{GTS_ID_PREFIX}parent~")]
    );
    assert_eq!(
        dto.allowed_membership_types,
        vec![format!("{GTS_ID_PREFIX}member~")]
    );
    assert!(dto.metadata_schema.is_some());
}

// TC-DTO-02: CreateTypeDto -> CreateTypeRequest
#[test]
fn dto_create_type_to_request() {
    let dto = CreateTypeDto {
        code: gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~").to_owned(),
        can_be_root: false,
        allowed_parent_types: vec![format!("{GTS_ID_PREFIX}parent~")],
        allowed_membership_types: vec![],
        metadata_schema: None,
    };
    let req: CreateTypeRequest = dto.into();
    assert_eq!(
        req.code,
        gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~")
    );
    assert!(!req.can_be_root);
    assert_eq!(
        req.allowed_parent_types,
        vec![format!("{GTS_ID_PREFIX}parent~")]
    );
    assert!(req.allowed_membership_types.is_empty());
    assert!(req.metadata_schema.is_none());
}

// TC-DTO-03: ResourceGroup -> GroupDto
#[test]
fn dto_group_from_resource_group() {
    let parent_id = Uuid::now_v7();
    let tenant_id = Uuid::now_v7();
    let group = ResourceGroup {
        id: Uuid::now_v7(),
        code: gts_id!("cf.system.rg.type.v1~").to_owned(),
        name: "My Group".to_owned(),
        hierarchy: resource_group_sdk::models::GroupHierarchy {
            parent_id: Some(parent_id),
            tenant_id,
        },
        metadata: Some(serde_json::json!({"k": "v"})),
    };
    let dto: GroupDto = group.clone().into();
    assert_eq!(dto.id, group.id);
    assert_eq!(dto.type_path, gts_id!("cf.system.rg.type.v1~"));
    assert_eq!(dto.name, "My Group");
    assert_eq!(dto.hierarchy.parent_id, Some(parent_id));
    assert_eq!(dto.hierarchy.tenant_id, tenant_id);
    assert!(dto.metadata.is_some());
}

// TC-DTO-04: ResourceGroupWithDepth -> GroupWithDepthDto
#[test]
fn dto_group_with_depth_from_resource_group() {
    let tenant_id = Uuid::now_v7();
    let gwd = ResourceGroupWithDepth {
        id: Uuid::now_v7(),
        code: gts_id!("cf.system.rg.type.v1~").to_owned(),
        name: "Depth Group".to_owned(),
        hierarchy: resource_group_sdk::models::GroupHierarchyWithDepth {
            parent_id: None,
            tenant_id,
            depth: 3,
        },
        metadata: None,
    };
    let dto: GroupWithDepthDto = gwd.into();
    assert_eq!(dto.name, "Depth Group");
    assert_eq!(dto.hierarchy.depth, 3);
    assert!(dto.hierarchy.parent_id.is_none());
    assert_eq!(dto.hierarchy.tenant_id, tenant_id);
}

// TC-DTO-05: Deserialize {"type": gts_id!(".."), "name": "X"} into CreateGroupDto
#[test]
fn dto_create_group_deserialize_type_key() {
    let json = serde_json::json!({
        "type": gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~"),
        "name": "X"
    })
    .to_string();
    let dto: CreateGroupDto = serde_json::from_str(&json).unwrap();
    assert_eq!(
        dto.type_path,
        gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~")
    );
    assert_eq!(dto.name, "X");
    assert!(dto.parent_id.is_none());
    assert!(dto.id.is_none());
}

// TC-DTO-05b: Caller-supplied `id` is deserialized and passed through to the SDK request
#[test]
fn dto_create_group_id_passthrough() {
    let id = Uuid::now_v7();
    let json = serde_json::json!({
        "id": id,
        "type": gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~"),
        "name": "X"
    })
    .to_string();
    let dto: CreateGroupDto = serde_json::from_str(&json).unwrap();
    assert_eq!(dto.id, Some(id));

    let req: CreateGroupRequest = dto.into();
    assert_eq!(req.id, Some(id));
}

// TC-DTO-05c: Omitted `id` maps to `None` in the SDK request (server generates it)
#[test]
fn dto_create_group_no_id_maps_to_none() {
    let dto = CreateGroupDto {
        id: None,
        type_path: gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~").to_owned(),
        name: "X".to_owned(),
        parent_id: None,
        tenant_id: None,
        metadata: None,
    };
    let req: CreateGroupRequest = dto.into();
    assert!(req.id.is_none());
}

// TC-DTO-05d: Caller-supplied `tenant_id` is deserialized from
// the snake_case wire key and passed through to the SDK request.
#[test]
fn dto_create_group_tenant_id_passthrough() {
    let tenant_id = Uuid::now_v7();
    let json = serde_json::json!({
        "type": gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~"),
        "name": "X",
        "tenant_id": tenant_id
    })
    .to_string();
    let dto: CreateGroupDto = serde_json::from_str(&json).unwrap();
    assert_eq!(dto.tenant_id, Some(tenant_id));

    let req: CreateGroupRequest = dto.into();
    assert_eq!(req.tenant_id, Some(tenant_id));
}

// TC-DTO-05e: Omitted `tenant_id` maps to `None` in the SDK
// request -- byte-for-byte today's behavior (the service falls back to the
// caller's own `SecurityContext` tenant).
#[test]
fn dto_create_group_no_tenant_id_maps_to_none() {
    let dto = CreateGroupDto {
        id: None,
        type_path: gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~").to_owned(),
        name: "X".to_owned(),
        parent_id: None,
        tenant_id: None,
        metadata: None,
    };
    let req: CreateGroupRequest = dto.into();
    assert!(req.tenant_id.is_none());
}

// TC-DTO-06: Deserialize with no vectors -> defaults to empty
#[test]
fn dto_create_type_deserialize_missing_vectors_default_empty() {
    let json = serde_json::json!({
        "code": gts_id!("cf.system.rg.type.v1~x.test.dto.mytype.v1~"),
        "can_be_root": true
    })
    .to_string();
    let dto: CreateTypeDto = serde_json::from_str(&json).unwrap();
    assert!(dto.allowed_parent_types.is_empty());
    assert!(dto.allowed_membership_types.is_empty());
}

// TC-DTO-07: MembershipDto serialization has no tenant_id key
#[test]
fn dto_membership_serialize_no_tenant_id() {
    let membership = ResourceGroupMembership {
        group_id: Uuid::now_v7(),
        resource_type: gts_id!("cf.system.rg.type.v1~").to_owned(),
        resource_id: "res-001".to_owned(),
    };
    let dto: MembershipDto = membership.into();
    let json = serde_json::to_value(&dto).unwrap();
    assert!(
        json.get("tenant_id").is_none(),
        "MembershipDto should not contain tenant_id, got: {json}"
    );
    assert!(json.get("group_id").is_some());
    assert!(json.get("resource_type").is_some());
    assert!(json.get("resource_id").is_some());
}

// =========================================================================
// Strict full-replacement payloads: omitted key != explicit null
// =========================================================================
//
// `#[schema(required)]` is a utoipa annotation and has no effect on serde --
// an omitted `Option<T>` still deserializes to `None`. These tests pin the
// `double_option` mechanism that makes the distinction observable, and the
// `TryFrom` conversions that turn an omitted key into a `DomainError` (and
// hence an RFC-9457 400) instead of a silent data wipe.

// TC-DTO-08: `UpdateGroupDto` distinguishes an omitted `metadata` key from an
// explicit `null`. The omitted case is the defect this replaced: it used to
// deserialize to `None` and erase the stored metadata with a 200 response.
#[test]
fn dto_update_group_omitted_metadata_is_rejected() {
    let dto: UpdateGroupDto =
        serde_json::from_value(serde_json::json!({ "name": "X" })).expect("body deserializes");
    assert_eq!(dto.metadata, None, "an omitted key must stay observable");

    let err = UpdateGroupRequest::try_from(dto).expect_err("omitted metadata must be rejected");
    let msg = err.to_string();
    assert!(msg.contains("metadata"), "error must name the key: {msg}");
}

// TC-DTO-09: an explicit `"metadata": null` is accepted and means "clear it".
#[test]
fn dto_update_group_explicit_null_metadata_clears() {
    let dto: UpdateGroupDto =
        serde_json::from_value(serde_json::json!({ "name": "X", "metadata": null }))
            .expect("body deserializes");
    assert_eq!(
        dto.metadata,
        Some(None),
        "an explicit null must be distinguishable from an omitted key"
    );

    let req = UpdateGroupRequest::try_from(dto).expect("explicit null is a valid instruction");
    assert_eq!(req.name, "X");
    assert!(req.metadata.is_none(), "null clears the metadata");
}

// TC-DTO-10: a `metadata` value round-trips through the tri-state.
#[test]
fn dto_update_group_metadata_value_round_trips() {
    let dto: UpdateGroupDto =
        serde_json::from_value(serde_json::json!({ "name": "X", "metadata": {"k": "v"} }))
            .expect("body deserializes");
    let req = UpdateGroupRequest::try_from(dto).expect("value is valid");
    assert_eq!(req.metadata, Some(serde_json::json!({"k": "v"})));
}

// TC-DTO-11: `name` is required, and an explicit `null` is rejected too --
// unlike `metadata` it is not a nullable field, so both shapes are errors.
#[test]
fn dto_update_group_requires_name() {
    for body in [
        serde_json::json!({ "metadata": null }),
        serde_json::json!({ "name": null, "metadata": null }),
    ] {
        let dto: UpdateGroupDto = serde_json::from_value(body.clone()).expect("body deserializes");
        let err =
            UpdateGroupRequest::try_from(dto).expect_err("a missing or null name must be rejected");
        assert!(
            err.to_string().contains("name"),
            "error must name the key for {body}: {err}"
        );
    }
}

// TC-DTO-12: `UpdateGroupDto` rejects unknown fields -- in particular
// `parent_id`, the pre-split move-via-PUT shape, and `type`, which is
// immutable and used to be silently discarded.
#[test]
fn dto_update_group_rejects_unknown_fields() {
    for body in [
        serde_json::json!({ "name": "X", "metadata": null, "parent_id": null }),
        serde_json::json!({ "name": "X", "metadata": null, "type": gts_id!("cf.system.rg.type.v1~") }),
        serde_json::json!({ "name": "X", "metadata": null, "surprise": 1 }),
    ] {
        serde_json::from_value::<UpdateGroupDto>(body.clone())
            .expect_err(&format!("deny_unknown_fields must reject {body}"));
    }
}

// TC-DTO-13: `MoveGroupDto` requires the `parent_id` key; an explicit `null`
// is the documented way to say "move to root".
#[test]
fn dto_move_group_requires_parent_id_key() {
    let omitted: MoveGroupDto =
        serde_json::from_value(serde_json::json!({})).expect("empty body deserializes");
    let err = omitted
        .into_new_parent_id()
        .expect_err("an omitted parent_id must be rejected");
    assert!(
        err.to_string().contains("parent_id"),
        "error must name the key: {err}"
    );

    let to_root: MoveGroupDto = serde_json::from_value(serde_json::json!({ "parent_id": null }))
        .expect("explicit null deserializes");
    assert_eq!(
        to_root.into_new_parent_id().expect("null is valid"),
        None,
        "explicit null means move to root"
    );

    let target = Uuid::now_v7();
    let to_parent: MoveGroupDto =
        serde_json::from_value(serde_json::json!({ "parent_id": target }))
            .expect("uuid deserializes");
    assert_eq!(
        to_parent.into_new_parent_id().expect("uuid is valid"),
        Some(target)
    );
}

// TC-DTO-14: `MoveGroupDto` rejects unknown fields, so a caller that sends the
// whole group representation to the move endpoint is told so.
#[test]
fn dto_move_group_rejects_unknown_fields() {
    serde_json::from_value::<MoveGroupDto>(serde_json::json!({ "parent_id": null, "name": "X" }))
        .expect_err("deny_unknown_fields must reject extra members");
}

// TC-DTO-15: `UpdateTypeDto` has the same defect and the same fix -- an
// omitted `metadata_schema` used to erase the stored JSON Schema.
#[test]
fn dto_update_type_omitted_metadata_schema_is_rejected() {
    let dto: UpdateTypeDto = serde_json::from_value(serde_json::json!({
        "can_be_root": true,
        "allowed_parent_types": [],
        "allowed_membership_types": []
    }))
    .expect("body deserializes");
    assert_eq!(dto.metadata_schema, None);

    let err = UpdateTypeRequest::try_from(dto).expect_err("omitted schema must be rejected");
    assert!(
        err.to_string().contains("metadata_schema"),
        "error must name the key: {err}"
    );
}

// TC-DTO-16: an explicit `"metadata_schema": null` clears the schema.
#[test]
fn dto_update_type_explicit_null_metadata_schema_clears() {
    let dto: UpdateTypeDto = serde_json::from_value(serde_json::json!({
        "can_be_root": true,
        "allowed_parent_types": [],
        "allowed_membership_types": [],
        "metadata_schema": null
    }))
    .expect("body deserializes");
    assert_eq!(dto.metadata_schema, Some(None));

    let req = UpdateTypeRequest::try_from(dto).expect("explicit null is valid");
    assert!(req.metadata_schema.is_none());
}

// TC-DTO-17: `UpdateTypeDto` rejects unknown fields -- notably `code`, which
// is the type's identity and comes from the path.
#[test]
fn dto_update_type_rejects_unknown_fields() {
    serde_json::from_value::<UpdateTypeDto>(serde_json::json!({
        "code": gts_id!("cf.system.rg.type.v1~"),
        "can_be_root": true,
        "allowed_parent_types": [],
        "allowed_membership_types": [],
        "metadata_schema": null
    }))
    .expect_err("deny_unknown_fields must reject `code` in the body");
}

// TC-DTO-18: the generated OpenAPI schemas must advertise the strict keys as
// required. `#[schema(required)]` is the only thing that says so -- serde's
// tri-state `Option<Option<T>>` would otherwise be published as optional, and
// the document would tell clients the opposite of what the endpoint enforces.
#[test]
fn dto_openapi_schemas_mark_strict_keys_required() {
    use utoipa::PartialSchema;

    fn required_of<T: PartialSchema>() -> Vec<String> {
        let schema = serde_json::to_value(T::schema()).expect("schema serializes");
        schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    let mut group = required_of::<UpdateGroupDto>();
    group.sort();
    assert_eq!(
        group,
        vec!["metadata".to_owned(), "name".to_owned()],
        "UpdateGroupDto must publish both replaceable keys as required"
    );

    assert_eq!(
        required_of::<MoveGroupDto>(),
        vec!["parent_id".to_owned()],
        "MoveGroupDto must publish parent_id as required"
    );

    let mut ty = required_of::<UpdateTypeDto>();
    ty.sort();
    assert_eq!(
        ty,
        vec![
            "allowed_membership_types".to_owned(),
            "allowed_parent_types".to_owned(),
            "can_be_root".to_owned(),
            "metadata_schema".to_owned(),
        ],
        "UpdateTypeDto must publish every replaceable key as required"
    );
}
