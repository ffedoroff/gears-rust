// Created: 2026-04-16 by Constructor Tech
// Updated: 2026-04-28 by Constructor Tech
use super::{dto, handlers};
use axum::Router;
use resource_group_sdk::odata::GroupFilterField;
use toolkit::api::OpenApiRegistry;
use toolkit::api::operation_builder::{OperationBuilder, OperationBuilderODataExt};

const API_TAG: &str = "Resource Groups";

#[allow(
    clippy::too_many_lines,
    reason = "eight OperationBuilder chains in linear sequence, same shape as \
              account-management's routes/tenants.rs::register_tenants_routes"
)]
#[allow(
    unknown_lints,
    de0802_use_odata_ext,
    reason = "the /descendants and /ancestors routes below hand-write their `$filter` \
              `.query_param()` instead of `.with_odata_filter::<HierarchyFilterField>()`, \
              which DE0802 otherwise requires. That helper derives its advertised operator \
              list purely from `FieldKind`, with no hook for a narrower grammar; this gear's \
              `domain/hierarchy_filter.rs::parse` accepts strictly less than the generic list \
              (`hierarchy/depth` has no `in`, `type` has no `contains`/`startswith`/`endswith`/\
              comparisons), so the generic list promises forms the gear rejects with 400 \
              (ML-4935). Enforcement lives entirely in `parse`, not in this declaration, so \
              hand-writing the parameter costs nothing at runtime — what it does cost is the \
              machine-readable `x-odata-filter`/`allowedFields` extension the helper emits, \
              which an external SDK generator could consume. The operator-aware hook that \
              would let the helper narrow correctly, keeping the extension, is a toolkit-wide \
              change tracked separately. \
              \
              The allow sits on the whole function rather than the two registrations that \
              need it because placing it on them was tried and rejected by the compiler: \
              `router = OperationBuilder::...;` is an expression statement, and rustc \
              answers `error[E0658]: attributes on expressions are experimental` there. \
              Scoping it tighter would mean extracting the two hierarchy registrations into \
              their own function purely to host an attribute, which trades a real risk of \
              mis-registering a route for a cosmetic gain. Note the cost of the wide scope: \
              DE0802 is silenced for all eight routes here, so a future `$orderby` written \
              by hand would pass unnoticed."
)]
pub(super) fn register_group_routes(mut router: Router, openapi: &dyn OpenApiRegistry) -> Router {
    // GET /resource-group/v1/groups - List groups with cursor-based pagination
    router = OperationBuilder::get("/resource-group/v1/groups")
        .operation_id("resource_group.list_groups")
        .summary("List resource groups")
        .description("Retrieve a paginated list of resource groups with OData filtering")
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .query_param_typed(
            "limit",
            false,
            "Maximum number of groups to return",
            "integer",
        )
        .query_param("cursor", false, "Cursor for pagination")
        .handler(handlers::list_groups)
        .json_response_with_schema::<toolkit_odata::Page<dto::GroupDto>>(
            openapi,
            http::StatusCode::OK,
            "Paginated list of resource groups",
        )
        .with_odata_filter::<GroupFilterField>()
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // POST /resource-group/v1/groups - Create a new group
    router = OperationBuilder::post("/resource-group/v1/groups")
        .operation_id("resource_group.create_group")
        .summary("Create a new resource group")
        .description(
            "Create a new resource group with the provided type, name, and optional parent",
        )
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .json_request::<dto::CreateGroupDto>(openapi, "Group creation data")
        .handler(handlers::create_group)
        .json_response_with_schema::<dto::GroupDto>(
            openapi,
            http::StatusCode::CREATED,
            "Created resource group",
        )
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_409(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /resource-group/v1/groups/{group_id} - Get a specific group
    router = OperationBuilder::get("/resource-group/v1/groups/{group_id}")
        .operation_id("resource_group.get_group")
        .summary("Get resource group by ID")
        .description("Retrieve a specific resource group by its UUID")
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .path_param("group_id", "Group UUID")
        .handler(handlers::get_group)
        .json_response_with_schema::<dto::GroupDto>(
            openapi,
            http::StatusCode::OK,
            "Resource group found",
        )
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // PUT /resource-group/v1/groups/{group_id} - Update a group's attributes
    router = OperationBuilder::put("/resource-group/v1/groups/{group_id}")
        .operation_id("resource_group.update_group")
        .summary("Update resource group")
        .description(
            "Replace a resource group's ordinary attributes: `name` and `metadata`. Both keys \
             are required -- an omitted key is a 400, not \"keep the stored value\"; send \
             `\"metadata\": null` to clear the metadata. The group's `type` is immutable and \
             its parent is not part of this payload: use POST \
             /resource-group/v1/groups/{group_id}/move to re-parent a group. Unknown fields \
             are rejected.",
        )
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .path_param("group_id", "Group UUID")
        .json_request::<dto::UpdateGroupDto>(openapi, "Group update data")
        .handler(handlers::update_group)
        .json_response_with_schema::<dto::GroupDto>(
            openapi,
            http::StatusCode::OK,
            "Updated resource group",
        )
        // No 409: this route writes only `name`/`metadata`
        // (`GroupRepositoryTrait::update_attributes`) -- no unique
        // constraint applies to that write set, and `update_group_inner`
        // raises nothing but `GroupNotFound`. A previously-declared
        // `error_409(openapi)` here was unreachable (ML-4935 audit finding,
        // same defect class as the DELETE-type 409 the ticket named).
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // POST /resource-group/v1/groups/{group_id}/move - Move a group (subtree)
    //
    // An action endpoint rather than a field on PUT: re-parenting is a
    // structural mutation (cycle detection, depth/width invariants,
    // closure-table rebuild under SERIALIZABLE), not an ordinary column
    // write. Shape follows the platform's two existing action endpoints,
    // `POST /bss-ledger/v1/approvals/{approval_id}/cancel` and
    // `POST /usage-collector/v1/records/{id}/deactivate`.
    router = OperationBuilder::post("/resource-group/v1/groups/{group_id}/move")
        .operation_id("resource_group.move_group")
        .summary("Move resource group to a new parent")
        .description(
            "Atomically move a resource group -- and its entire subtree -- to a new parent, or \
             to the forest root. `parent_id` is required: an explicit `null` means \"make this \
             group a root\", while omitting the key is a 400. Cycle detection, parent-type \
             compatibility, depth/width limits, tenant-root uniqueness and the closure-table \
             rebuild all run inside one SERIALIZABLE transaction, so the group is never left \
             detached from both parents. Cross-tenant moves are rejected.",
        )
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .path_param("group_id", "Group UUID")
        .json_request::<dto::MoveGroupDto>(openapi, "Move destination")
        .handler(handlers::move_group)
        .json_response_with_schema::<dto::GroupDto>(
            openapi,
            http::StatusCode::OK,
            "Moved resource group",
        )
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_409(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // DELETE /resource-group/v1/groups/{group_id} - Delete a group
    router = OperationBuilder::delete("/resource-group/v1/groups/{group_id}")
        .operation_id("resource_group.delete_group")
        .summary("Delete resource group")
        .description(
            "Delete a resource group. Use ?force=true to cascade delete subtree and memberships.",
        )
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .path_param("group_id", "Group UUID")
        .query_param_typed(
            "force",
            false,
            "Force cascade delete of subtree and memberships",
            "boolean",
        )
        .handler(handlers::delete_group)
        .no_content_response(http::StatusCode::NO_CONTENT, "Group deleted successfully")
        // No 409: without `force`, an active reference (children or
        // memberships) maps to `ConflictActiveReferences` ->
        // `failed_precondition` (400), not `already_exists`/`aborted`.
        // `delete_group_inner`/`force_delete_subtree` raise nothing that
        // maps to 409. A previously-declared `error_409(openapi)` here was
        // unreachable (ML-4935 audit finding).
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /resource-group/v1/groups/{group_id}/descendants
    router = OperationBuilder::get("/resource-group/v1/groups/{group_id}/descendants")
        .operation_id("resource_group.get_group_descendants")
        .summary("Get group descendants")
        .description("Get descendants of a reference group (depth >= 0) with OData filtering")
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .path_param("group_id", "Reference group UUID")
        .query_param_typed("limit", false, "Maximum entries to return", "integer")
        .query_param("cursor", false, "Cursor for pagination")
        .handler(handlers::get_group_descendants)
        .json_response_with_schema::<toolkit_odata::Page<dto::GroupWithDepthDto>>(
            openapi,
            http::StatusCode::OK,
            "Paginated descendants with relative depth",
        )
        // Hand-written, not `.with_odata_filter::<HierarchyFilterField>()`:
        // that helper derives the advertised operator list purely from each
        // field's `FieldKind` (`operation_builder.rs`'s `with_odata_filter`),
        // with no hook for a narrower, field-specific grammar. This gear's
        // hierarchy `$filter` evaluator (`domain/hierarchy_filter.rs::parse`,
        // ML-4182/ML-8813) accepts strictly less than that: `hierarchy/depth`
        // takes only `eq|ne|gt|ge|lt|le` (no `in` -- the SDK contract promises
        // single-value comparisons only), and `type` takes only `eq|ne|in`
        // (no `contains`/`startswith`/`endswith`/`gt`/`ge`/`lt`/`le`, despite
        // `FieldKind::String` allowing them generically). Advertising the
        // generic superset (as this route did before ML-4935) promises forms
        // the gear has rejected with 400 since `bd4c3a38`; declaring the
        // honest, narrower list here costs nothing at runtime -- enforcement
        // already lives entirely in `hierarchy_filter::parse`, and
        // `x-odata-filter`'s `allowedFields` vendor extension this helper
        // would otherwise emit is itself only ever read by
        // `openapi_registry`'s own tests (documentation, not enforcement), so
        // dropping it costs nothing real either.
        .query_param(
            "$filter",
            false,
            crate::domain::hierarchy_filter::FILTER_PARAM_DESCRIPTION,
        )
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    // GET /resource-group/v1/groups/{group_id}/ancestors
    router = OperationBuilder::get("/resource-group/v1/groups/{group_id}/ancestors")
        .operation_id("resource_group.get_group_ancestors")
        .summary("Get group ancestors")
        .description("Get ancestors of a reference group (depth <= 0) with OData filtering")
        .tag(API_TAG)
        .authenticated()
        .no_license_required()
        .path_param("group_id", "Reference group UUID")
        .query_param_typed("limit", false, "Maximum entries to return", "integer")
        .query_param("cursor", false, "Cursor for pagination")
        .handler(handlers::get_group_ancestors)
        .json_response_with_schema::<toolkit_odata::Page<dto::GroupWithDepthDto>>(
            openapi,
            http::StatusCode::OK,
            "Paginated ancestors with relative depth",
        )
        // Hand-written $filter param: see the doc comment on the
        // /descendants route above for why `with_odata_filter` is wrong
        // here (it would advertise `hierarchy/depth: ...|in` and
        // `type: ...|contains|startswith|endswith|in`, forms
        // `hierarchy_filter::parse` rejects with 400).
        .query_param(
            "$filter",
            false,
            crate::domain::hierarchy_filter::FILTER_PARAM_DESCRIPTION,
        )
        .error_400(openapi)
        .error_401(openapi)
        .error_403(openapi)
        .error_404(openapi)
        .error_500(openapi)
        .register(router, openapi);

    router
}
