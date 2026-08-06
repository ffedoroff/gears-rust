// Created: 2026-04-16 by Constructor Tech
// Updated: 2026-04-29 by Constructor Tech
//! REST DTOs for resource-group type and group management.

use resource_group_sdk::models::{
    CreateGroupRequest, CreateTypeRequest, ResourceGroup, ResourceGroupMembership,
    ResourceGroupType, ResourceGroupWithDepth, UpdateGroupRequest, UpdateTypeRequest,
};
use uuid::Uuid;

use crate::domain::error::DomainError;

/// Serde helper distinguishing an **omitted** key (`None`) from an explicit
/// JSON `null` (`Some(None)`) and from a value (`Some(Some(v))`). Pair with
/// `#[serde(default, deserialize_with = "double_option")]`.
///
/// Needed because `#[schema(required)]` is a *utoipa* attribute: it makes the
/// generated `OpenAPI` document advertise the field as required, but has no
/// effect on serde, which happily deserializes a missing `Option<T>` into
/// `None`. Without this helper "the client omitted `metadata`" and "the
/// client sent `metadata: null`" are the same value — which is exactly how
/// an omitted key came to silently erase stored metadata (`group_repo.rs`
/// writes the column unconditionally).
///
/// The full-replacement DTOs below use it the other way round from a PATCH:
/// they do not *accept* an omitted key, they **detect** it in order to reject
/// the request with a 400 `problem+json`. Mirrors the same helper in
/// account-management's `api::rest::dto`, which uses it for PATCH semantics.
///
/// `serde_with::rust::double_option` would do the same job, but `serde_with`
/// is not a dependency of this crate.
#[allow(clippy::option_option)]
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(de).map(Some)
}

/// Reject an omitted required key on a full-replacement (`PUT`) payload.
///
/// Deliberately implemented *after* deserialization rather than by making
/// the field non-`Option` in serde: RG handlers extract bodies with
/// `axum::Json` (via `toolkit::api::canonical_prelude`), whose rejection is
/// a bare `text/plain` 400/422 that never passes through
/// `canonical_error_middleware` — it only rewrites responses that already
/// carry `application/problem+json`. Routing the check through
/// `DomainError::validation` instead puts it on the same
/// `From<DomainError> for CanonicalError` ladder as every other 400 in this
/// gear, so the client gets RFC-9457 as
/// `docs/toolkit_unified_system/04_rest_operation_builder.md` requires.
fn require_key<T>(value: Option<T>, field: &str, hint: &str) -> Result<T, DomainError> {
    value.ok_or_else(|| {
        DomainError::validation(format!(
            "'{field}' is required: this endpoint performs a full replacement, so an omitted \
             key cannot be distinguished from a request to keep the stored value. {hint}"
        ))
    })
}

/// REST DTO for GTS type representation.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request, response)]
pub struct TypeDto {
    /// GTS type path
    pub code: String,
    /// Whether groups of this type can be root nodes
    pub can_be_root: bool,
    /// GTS type paths of allowed parent types
    pub allowed_parent_types: Vec<String>,
    /// GTS type paths of allowed membership resource types
    pub allowed_membership_types: Vec<String>,
    /// Optional JSON Schema for instance metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_schema: Option<serde_json::Value>,
}

/// REST DTO for creating a new GTS type.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct CreateTypeDto {
    /// GTS type path. Must have prefix `gts.cf.core.rg.type.v1~`.
    ///
    /// Whether the type creates a new tenant scope is derived from the code:
    /// any path starting with the tenant RG type prefix is a tenant type.
    pub code: String,
    /// Whether groups of this type can be root nodes.
    pub can_be_root: bool,
    /// GTS type paths of allowed parent types.
    #[serde(default)]
    pub allowed_parent_types: Vec<String>,
    /// GTS type paths of allowed membership resource types.
    #[serde(default)]
    pub allowed_membership_types: Vec<String>,
    /// Optional JSON Schema for instance metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_schema: Option<serde_json::Value>,
}

/// REST DTO for updating a GTS type (full replacement via PUT).
///
/// The type registry is a document resource: a type definition is replaced as
/// a whole, so strict full replacement is the correct shape for it (baseline
/// rule B1.1). Every replaceable field is therefore **required** and an
/// omitted key is an error, not "preserve previous value" — `metadata_schema`
/// must be sent explicitly as `null` to clear it.
///
/// `deny_unknown_fields` locks the wire envelope, so a client that sends
/// `code` (the type's identity, taken from the path and immutable) gets an
/// explicit 400 instead of a silently-dropped field.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub struct UpdateTypeDto {
    /// Whether groups of this type can be root nodes.
    pub can_be_root: bool,
    /// GTS type paths of allowed parent types.
    pub allowed_parent_types: Vec<String>,
    /// GTS type paths of allowed membership resource types.
    pub allowed_membership_types: Vec<String>,
    /// JSON Schema for instance metadata. Required: send `null` to clear it.
    /// An omitted key is rejected — it used to silently erase the stored
    /// schema (`type_service.rs` writes the column unconditionally).
    #[serde(default, deserialize_with = "double_option")]
    #[schema(required, value_type = Option<serde_json::Value>)]
    pub metadata_schema: Option<Option<serde_json::Value>>,
}

// -- Conversions --

impl From<ResourceGroupType> for TypeDto {
    fn from(t: ResourceGroupType) -> Self {
        Self {
            code: t.code,
            can_be_root: t.can_be_root,
            allowed_parent_types: t.allowed_parent_types,
            allowed_membership_types: t.allowed_membership_types,
            metadata_schema: t.metadata_schema,
        }
    }
}

impl From<CreateTypeDto> for CreateTypeRequest {
    fn from(dto: CreateTypeDto) -> Self {
        Self {
            code: dto.code,
            can_be_root: dto.can_be_root,
            allowed_parent_types: dto.allowed_parent_types,
            allowed_membership_types: dto.allowed_membership_types,
            metadata_schema: dto.metadata_schema,
        }
    }
}

impl TryFrom<UpdateTypeDto> for UpdateTypeRequest {
    type Error = DomainError;

    fn try_from(dto: UpdateTypeDto) -> Result<Self, Self::Error> {
        Ok(Self {
            can_be_root: dto.can_be_root,
            allowed_parent_types: dto.allowed_parent_types,
            allowed_membership_types: dto.allowed_membership_types,
            metadata_schema: require_key(
                dto.metadata_schema,
                "metadata_schema",
                "Send \"metadata_schema\": null to clear the stored JSON Schema.",
            )?,
        })
    }
}

// -- Group DTOs --

/// REST DTO for hierarchy context in group responses.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request, response)]
pub struct HierarchyDto {
    /// Parent group ID (null for root groups).
    #[schema(required)]
    pub parent_id: Option<Uuid>,
    /// Tenant scope.
    pub tenant_id: Uuid,
}

/// REST DTO for hierarchy context with depth in group responses.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request, response)]
pub struct HierarchyWithDepthDto {
    /// Parent group ID (null for root groups).
    #[schema(required)]
    pub parent_id: Option<Uuid>,
    /// Tenant scope.
    pub tenant_id: Uuid,
    /// Relative distance from reference group.
    pub depth: i32,
}

/// REST DTO for resource group representation.
///
/// Group responses do NOT include `created_at`/`updated_at` (per DESIGN).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request, response)]
pub struct GroupDto {
    /// Group identifier.
    pub id: Uuid,
    /// GTS chained type path.
    #[serde(rename = "type")]
    pub type_path: String,
    /// Display name.
    pub name: String,
    /// Hierarchy context.
    pub hierarchy: HierarchyDto,
    /// Type-specific metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// REST DTO for resource group with depth (hierarchy queries).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request, response)]
pub struct GroupWithDepthDto {
    /// Group identifier.
    pub id: Uuid,
    /// GTS chained type path.
    #[serde(rename = "type")]
    pub type_path: String,
    /// Display name.
    pub name: String,
    /// Hierarchy context with depth.
    pub hierarchy: HierarchyWithDepthDto,
    /// Type-specific metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// REST DTO for creating a new resource group.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
pub struct CreateGroupDto {
    /// Optional caller-supplied ID. If omitted, the server generates a UUID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    /// GTS chained type path. Must have prefix `gts.cf.core.rg.type.v1~`.
    #[serde(rename = "type")]
    pub type_path: String,
    /// Display name (1..255 characters).
    pub name: String,
    /// Parent group ID (null for root groups).
    pub parent_id: Option<Uuid>,
    /// Optional target tenant for the created group.
    ///
    /// If omitted, the tenant scope is derived from the caller's own
    /// `SecurityContext` -- today's unchanged default behavior. If present
    /// and different from the caller's own tenant, the create succeeds only
    /// when the caller's `create`-action `AccessScope` actually covers the
    /// target tenant (platform-admin / onboarding use case); otherwise the
    /// request is rejected as though the target tenant did not exist.
    /// Rejected as a contradiction for tenant-typed groups: their effective
    /// tenant is always `group.id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    /// Type-specific metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// REST DTO for updating a resource group's ordinary attributes (full
/// replacement via PUT).
///
/// **The group's GTS type is immutable after creation.** The payload
/// deliberately does not carry a `type` field — to change a group's type,
/// delete the existing group and create a new one. See the SDK
/// `UpdateGroupRequest` doc for the full rationale.
///
/// **The group's parent is not here either.** Re-parenting is a structural
/// mutation — cycle detection, depth/width invariants, closure-table rebuild —
/// so it has its own operation: `POST /groups/{group_id}/move` with
/// [`MoveGroupDto`]. What is left on this resource is `name` and `metadata`,
/// two ordinary fields, and this payload replaces both.
///
/// Both fields are **required**. An omitted key is a 400, not "preserve the
/// previous value": for `metadata` the two are genuinely indistinguishable to
/// serde, and treating an omission as `null` is what used to erase stored
/// metadata. Send `"metadata": null` to clear it deliberately.
///
/// `deny_unknown_fields` locks the wire envelope, so a client that tries to
/// change the immutable `type`, or that still sends `parent_id` expecting the
/// pre-split move-via-PUT behaviour, gets an explicit 400 instead of a
/// silently-discarded mutation.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub struct UpdateGroupDto {
    /// Display name (1..255 characters). Required.
    #[schema(required, value_type = String)]
    pub name: Option<String>,
    /// Type-specific metadata. Required: send `null` to clear it.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(required, value_type = Option<serde_json::Value>)]
    pub metadata: Option<Option<serde_json::Value>>,
}

/// REST DTO for the group move operation
/// (`POST /groups/{group_id}/move`).
///
/// `parent_id` is **mandatory**, and an explicit `null` is its most important
/// value: `null` means "make this group a root", an omitted key means the
/// caller did not say where to move the group and is a 400. Collapsing those
/// two into one value is the defect this operation was split out to remove,
/// so the distinction is enforced here rather than assumed.
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(request)]
#[serde(deny_unknown_fields)]
#[allow(clippy::option_option)]
pub struct MoveGroupDto {
    /// New parent group ID, or `null` to move the group to the forest root.
    /// The key itself must be present.
    #[serde(default, deserialize_with = "double_option")]
    #[schema(required, value_type = Option<Uuid>)]
    pub parent_id: Option<Option<Uuid>>,
}

impl MoveGroupDto {
    /// Resolve the requested destination: `Ok(None)` means "move to root",
    /// `Ok(Some(id))` means "move under `id`". An omitted `parent_id` key is
    /// rejected.
    pub fn into_new_parent_id(self) -> Result<Option<Uuid>, DomainError> {
        require_key(
            self.parent_id,
            "parent_id",
            "Send \"parent_id\": null to move the group to the root, or a group UUID to move it \
             under that group.",
        )
    }
}

// -- Group conversions --

impl From<ResourceGroup> for GroupDto {
    fn from(g: ResourceGroup) -> Self {
        Self {
            id: g.id,
            type_path: g.code,
            name: g.name,
            hierarchy: HierarchyDto {
                parent_id: g.hierarchy.parent_id,
                tenant_id: g.hierarchy.tenant_id,
            },
            metadata: g.metadata,
        }
    }
}

impl From<ResourceGroupWithDepth> for GroupWithDepthDto {
    fn from(g: ResourceGroupWithDepth) -> Self {
        Self {
            id: g.id,
            type_path: g.code,
            name: g.name,
            hierarchy: HierarchyWithDepthDto {
                parent_id: g.hierarchy.parent_id,
                tenant_id: g.hierarchy.tenant_id,
                depth: g.hierarchy.depth,
            },
            metadata: g.metadata,
        }
    }
}

impl From<CreateGroupDto> for CreateGroupRequest {
    fn from(dto: CreateGroupDto) -> Self {
        Self {
            id: dto.id,
            code: dto.type_path,
            name: dto.name,
            parent_id: dto.parent_id,
            tenant_id: dto.tenant_id,
            metadata: dto.metadata,
        }
    }
}

impl TryFrom<UpdateGroupDto> for UpdateGroupRequest {
    type Error = DomainError;

    fn try_from(dto: UpdateGroupDto) -> Result<Self, Self::Error> {
        Ok(Self {
            name: require_key(
                dto.name,
                "name",
                "Send the group's display name; PUT replaces it.",
            )?,
            metadata: require_key(
                dto.metadata,
                "metadata",
                "Send \"metadata\": null to clear the stored metadata.",
            )?,
        })
    }
}

// -- Membership DTOs --

/// REST DTO for membership representation.
///
/// Membership responses do NOT include `tenant_id` (derived from group).
#[derive(Debug, Clone)]
#[toolkit_macros::api_dto(response)]
pub struct MembershipDto {
    /// Group identifier.
    pub group_id: Uuid,
    /// GTS type path of the resource type.
    pub resource_type: String,
    /// Resource identifier.
    pub resource_id: String,
}

// -- Membership conversions --

impl From<ResourceGroupMembership> for MembershipDto {
    fn from(m: ResourceGroupMembership) -> Self {
        Self {
            group_id: m.group_id,
            resource_type: m.resource_type,
            resource_id: m.resource_id,
        }
    }
}

#[cfg(test)]
#[path = "dto_tests.rs"]
mod tests;
