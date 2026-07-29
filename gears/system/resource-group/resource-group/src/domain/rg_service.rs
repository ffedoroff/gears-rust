// Created: 2026-04-16 by Constructor Tech
// @cpt-dod:cpt-cf-resource-group-dod-integration-auth-read-service:p1
//! Unified service adapter implementing `ResourceGroupClient` for `ClientHub` registration.
//!
//! Delegates to `TypeService`, `GroupService`, and `MembershipService` to satisfy
//! the full SDK trait contract.

use std::sync::Arc;

use async_trait::async_trait;
use resource_group_sdk::ResourceGroupClient;
use resource_group_sdk::models::{
    CreateGroupRequest, CreateTypeRequest, ResourceGroup, ResourceGroupMembership,
    ResourceGroupType, ResourceGroupWithDepth, UpdateGroupRequest, UpdateTypeRequest,
};
use toolkit_canonical_errors::CanonicalError;
use toolkit_odata::{ODataQuery, Page};
use toolkit_security::SecurityContext;
use tracing::info;
use uuid::Uuid;

use crate::domain::group_service::GroupService;
use crate::domain::membership_service::MembershipService;
use crate::domain::repo::{GroupRepositoryTrait, MembershipRepositoryTrait, TypeRepositoryTrait};
use crate::domain::type_service::TypeService;

/// Unified adapter registered with `ClientHub` as `dyn ResourceGroupClient`.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[allow(clippy::struct_field_names)]
pub struct RgService<
    GR: GroupRepositoryTrait,
    TR: TypeRepositoryTrait,
    MR: MembershipRepositoryTrait,
> {
    type_service: Arc<TypeService<TR>>,
    group_service: Arc<GroupService<GR, TR>>,
    membership_service: Arc<MembershipService<GR, TR, MR>>,
}

impl<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait, MR: MembershipRepositoryTrait>
    RgService<GR, TR, MR>
{
    /// Create a new `RgService`.
    #[must_use]
    pub fn new(
        type_service: Arc<TypeService<TR>>,
        group_service: Arc<GroupService<GR, TR>>,
        membership_service: Arc<MembershipService<GR, TR, MR>>,
    ) -> Self {
        Self {
            type_service,
            group_service,
            membership_service,
        }
    }

    /// Emit an audit trail line for a mutating type-registry call that took
    /// the unscoped, `PolicyEnforcer`-bypassing path below (see the
    /// "Type lifecycle" doc comment). `action` is the trait method name;
    /// `code` is the GTS type path being created/updated/deleted.
    ///
    /// This is the only trace of the bypass: nothing downstream calls
    /// `PolicyEnforcer`, so without this line the call would leave no
    /// AuthZ-relevant log signal at all. `ctx`'s `subject_id`/`subject_type`
    /// are exactly what a caller like account-management's system actor
    /// (`system_actor::for_gear_init` — `subject_type = "am.system"`)
    /// stamps on every request, so this doubles as the audit correlation
    /// key for that caller.
    fn audit_unscoped_type_call(ctx: &SecurityContext, action: &str, code: &str) {
        info!(
            target: "resource_group.rg_service_authz_bypass",
            action,
            code,
            subject_id = %ctx.subject_id(),
            subject_type = ctx.subject_type().unwrap_or("<unset>"),
            subject_tenant_id = %ctx.subject_tenant_id(),
            "RgService type-registry call bypassed PolicyEnforcer (trusted in-process ClientHub path)",
        );
    }
}

#[async_trait]
impl<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait, MR: MembershipRepositoryTrait>
    ResourceGroupClient for RgService<GR, TR, MR>
{
    // -- Type lifecycle --
    //
    // Deliberate `PolicyEnforcer` bypass — do not "fix" this by routing
    // these five methods back through `TypeService::create_type` /
    // `get_type` / `list_types` / `update_type` / `delete_type` (the gated
    // entry points). They call the `*_unscoped` variants directly instead.
    //
    // ## Why
    //
    // `RgService` is the implementation registered in `ClientHub` as
    // `dyn ResourceGroupClient` (see `gear.rs`); it is resolved by
    // in-process consumers, not by an HTTP handler. One such consumer is
    // account-management, which registers its GTS user-group types at gear
    // init via this trait, under a system actor
    // (`account-management/src/domain/system_actor.rs::for_gear_init`,
    // `build_inner(None)`) whose `SecurityContext` carries
    // `subject_tenant_id = Uuid::nil()` — there is no tenant yet this early
    // in platform bootstrap. `static-authz-plugin`'s `Service::evaluate`
    // unconditionally denies a nil-tenant request (`tid ==
    // Uuid::default()` → `decision: false`), so if this call went through
    // `TypeService::gate`, AM's own initialization would fail closed the
    // moment a real `PolicyEnforcer` is wired in — i.e. every dev-stack
    // boot, since no policy exists (or could sensibly exist) for a subject
    // that predates tenants entirely.
    //
    // ## Why this is safe
    //
    // The HTTP surface VHP-2342 was actually about — any authenticated
    // caller hitting `/api/types-registry/v1/types` — is untouched by this:
    // `src/api/rest/handlers/types.rs` resolves `Arc<ConcreteTypeService>`
    // from an `Extension` (wired in `gear.rs`'s `register_rest`, a
    // completely separate object graph from the `RgService` registered in
    // `ClientHub`) and calls its gated `create_type`/`get_type`/
    // `list_types`/`update_type`/`delete_type` — every one of which still
    // runs `TypeService::gate` first. Nothing here changes that path.
    // `RgService` is reachable only from other in-process gears resolving
    // `dyn ResourceGroupClient` via `ClientHub`, never from a network
    // request.
    //
    // ## Precedent
    //
    // This mirrors an existing, documented bypass in this same gear:
    // `ResourceGroupReadHierarchy` (see `RgReadService` /
    // `docs/DESIGN.md`'s notes under the expected-permissions table) is
    // resolved unscoped by the AuthZ plugin for the identical reason a PEP
    // cannot evaluate itself without recursing — there, the trait is
    // narrowed to hierarchy-only reads and the caller supplies its own
    // scope; here, the trait is narrowed to what `ClientHub` alone can
    // reach and the `*_unscoped` methods still run every domain invariant
    // (placement, hierarchy safety, schema validation) — only the PDP call
    // is skipped.
    //
    // `ctx` stays in every method signature below because the SDK trait
    // contract (`ResourceGroupClient`) requires it uniformly across all
    // methods, group/membership included — it is not unused: mutating
    // calls forward it to `audit_unscoped_type_call` so the bypass has an
    // audit trail (`subject_id`/`subject_type`) even though it is not
    // gated.
    //
    // ## Scope of this exception
    //
    // Monolith / in-process only. If AM is ever split into its own
    // microservice, it would call RG over HTTP instead of resolving
    // `dyn ResourceGroupClient` in-process — that path hits the gated REST
    // surface above, not this one, and would need a real deployed policy
    // granting `am.system` the five type actions (see VHP-2342's original
    // commit message warning, still correct for that future topology).

    async fn create_type(
        &self,
        ctx: &SecurityContext,
        request: CreateTypeRequest,
    ) -> Result<ResourceGroupType, CanonicalError> {
        Self::audit_unscoped_type_call(ctx, "create_type", &request.code);
        self.type_service
            .create_type_unscoped(request)
            .await
            .map_err(CanonicalError::from)
    }

    async fn get_type(
        &self,
        _ctx: &SecurityContext,
        code: &str,
    ) -> Result<ResourceGroupType, CanonicalError> {
        self.type_service
            .get_type_unscoped(code)
            .await
            .map_err(CanonicalError::from)
    }

    async fn list_types(
        &self,
        _ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupType>, CanonicalError> {
        self.type_service
            .list_types_unscoped(query)
            .await
            .map_err(CanonicalError::from)
    }

    async fn update_type(
        &self,
        ctx: &SecurityContext,
        code: &str,
        request: UpdateTypeRequest,
    ) -> Result<ResourceGroupType, CanonicalError> {
        Self::audit_unscoped_type_call(ctx, "update_type", code);
        self.type_service
            .update_type_unscoped(code, request)
            .await
            .map_err(CanonicalError::from)
    }

    async fn delete_type(&self, ctx: &SecurityContext, code: &str) -> Result<(), CanonicalError> {
        Self::audit_unscoped_type_call(ctx, "delete_type", code);
        self.type_service
            .delete_type_unscoped(code)
            .await
            .map_err(CanonicalError::from)
    }

    // -- Group lifecycle --

    async fn create_group(
        &self,
        ctx: &SecurityContext,
        request: CreateGroupRequest,
    ) -> Result<ResourceGroup, CanonicalError> {
        let tenant_id = ctx.subject_tenant_id();
        self.group_service
            .create_group(ctx, request, tenant_id)
            .await
            .map_err(CanonicalError::from)
    }

    async fn get_group(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<ResourceGroup, CanonicalError> {
        self.group_service
            .get_group(ctx, id)
            .await
            .map_err(CanonicalError::from)
    }

    async fn list_groups(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroup>, CanonicalError> {
        self.group_service
            .list_groups(ctx, query)
            .await
            .map_err(CanonicalError::from)
    }

    async fn update_group(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
        request: UpdateGroupRequest,
    ) -> Result<ResourceGroup, CanonicalError> {
        self.group_service
            .update_group(ctx, id, request)
            .await
            .map_err(CanonicalError::from)
    }

    async fn delete_group(&self, ctx: &SecurityContext, id: Uuid) -> Result<(), CanonicalError> {
        // Non-cascade variant: surface `ConflictActiveReferences` to the
        // caller; cascade goes through `delete_group_cascade` below.
        self.group_service
            .delete_group(ctx, id, false)
            .await
            .map_err(CanonicalError::from)
    }

    async fn delete_group_cascade(
        &self,
        ctx: &SecurityContext,
        id: Uuid,
    ) -> Result<(), CanonicalError> {
        // Cascade variant: forwards to `delete_group_inner` with
        // `force=true`, which atomically removes the entire subtree,
        // membership rows, and closure rows under a SERIALIZABLE
        // transaction. Mirrors the REST `?force=true` path.
        self.group_service
            .delete_group(ctx, id, true)
            .await
            .map_err(CanonicalError::from)
    }

    async fn get_group_descendants(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupWithDepth>, CanonicalError> {
        self.group_service
            .get_group_descendants(ctx, group_id, query)
            .await
            .map_err(CanonicalError::from)
    }

    async fn get_group_ancestors(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupWithDepth>, CanonicalError> {
        self.group_service
            .get_group_ancestors(ctx, group_id, query)
            .await
            .map_err(CanonicalError::from)
    }

    // -- Membership lifecycle --

    async fn add_membership(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<ResourceGroupMembership, CanonicalError> {
        self.membership_service
            .add_membership(ctx, group_id, resource_type, resource_id)
            .await
            .map_err(CanonicalError::from)
    }

    async fn remove_membership(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), CanonicalError> {
        self.membership_service
            .remove_membership(ctx, group_id, resource_type, resource_id)
            .await
            .map_err(CanonicalError::from)
    }

    async fn list_memberships(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupMembership>, CanonicalError> {
        self.membership_service
            .list_memberships(ctx, query)
            .await
            .map_err(CanonicalError::from)
    }
}
