// Created: 2026-04-16 by Constructor Tech
// Updated: 2026-04-28 by Constructor Tech
//! Domain service for resource group entity management.
//!
//! Implements business rules: type validation, parent compatibility,
//! cycle detection, closure table management, query profile enforcement,
//! and CRUD orchestration.
//!
//! All hierarchy-mutating operations (`create_group`, `move_group`,
//! `delete_group`) use `SERIALIZABLE` transactions with bounded retry (max 3
//! attempts) to prevent phantom reads and ensure closure table consistency
//! under concurrent mutations.
//!
//! `update_group` is deliberately *not* one of them: it replaces a group's
//! ordinary attributes (`name`, `metadata`) and writes no structural column at
//! all -- `parent_id` is written only by `move_group`, through the dedicated
//! `GroupRepositoryTrait::update_parent`. A single-row write by primary key
//! over a column set no other operation touches has no cross-row predicate to
//! protect, so `update_group` runs at the backend default isolation
//! (`docs/db-behavior-audit.md`, TX-02); see its own doc
//! comment for why the former isolation-guessing/restart protocol is gone.

use std::sync::Arc;

use authz_resolver_sdk::pep::{PolicyEnforcer, ResourceType};
use resource_group_sdk::models::{
    CreateGroupRequest, ResourceGroup, ResourceGroupWithDepth, UpdateGroupRequest,
};
use resource_group_sdk::{GROUP_RESOURCE_TYPE, TENANT_RG_TYPE_PATH};
use toolkit_db::secure::{DBRunner, TxConfig};
use toolkit_odata::{ODataQuery, Page};
use toolkit_security::{SecurityContext, pep_properties};
use tracing::debug;
use uuid::Uuid;

use crate::domain::DbProvider;
use crate::domain::error::DomainError;
use crate::domain::repo::{GroupRepositoryTrait, TypeRepositoryTrait};
use crate::domain::validation;

/// `AuthZ` resource type descriptor for resource groups.
pub const RG_GROUP_RESOURCE: ResourceType = ResourceType::from_static(
    GROUP_RESOURCE_TYPE,
    &[pep_properties::OWNER_TENANT_ID, pep_properties::RESOURCE_ID],
);

/// Query profile configuration for depth/width limits.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Debug, Clone)]
pub struct QueryProfile {
    /// Maximum depth allowed. `None` disables depth limit.
    pub max_depth: Option<u32>,
    /// Maximum width (children per parent) allowed. `None` disables width limit.
    pub max_width: Option<u32>,
}

impl Default for QueryProfile {
    fn default() -> Self {
        Self {
            max_depth: Some(10),
            max_width: None,
        }
    }
}

/// Service for resource group entity lifecycle management.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Clone)]
pub struct GroupService<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait> {
    db: Arc<DbProvider>,
    profile: QueryProfile,
    enforcer: PolicyEnforcer,
    group_repo: Arc<GR>,
    type_repo: Arc<TR>,
    types_registry: Arc<dyn types_registry_sdk::TypesRegistryClient>,
}

impl<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait> GroupService<GR, TR> {
    /// Create a new `GroupService` with the given database provider, query profile,
    /// and `PolicyEnforcer` for AuthZ-scoped queries.
    #[must_use]
    pub fn new(
        db: Arc<DbProvider>,
        profile: QueryProfile,
        enforcer: PolicyEnforcer,
        group_repo: Arc<GR>,
        type_repo: Arc<TR>,
        types_registry: Arc<dyn types_registry_sdk::TypesRegistryClient>,
    ) -> Self {
        Self {
            db,
            profile,
            enforcer,
            group_repo,
            type_repo,
            types_registry,
        }
    }

    /// Create a new resource group.
    ///
    /// Runs inside a `SERIALIZABLE` transaction with bounded retry (max 3 attempts)
    /// to ensure invariant checks and closure table mutations are atomic.
    pub async fn create_group(
        &self,
        ctx: &SecurityContext,
        req: CreateGroupRequest,
        tenant_id: Uuid,
    ) -> Result<ResourceGroup, DomainError> {
        // Pre-validation (stateless, outside transaction).
        //
        // The type code is parsed *once*, here, and the canonical result
        // replaces the caller's spelling for the rest of this operation --
        // AuthZ properties, the type lookup, the metadata-schema resolution
        // and the persisted row all see the same string. Validating a
        // normalized copy while carrying the raw input forward is what let an
        // uppercase or space-padded tenant code be stored and then classified
        // as an *ordinary* type below (see `validation::canonical_type_code`).
        let mut req = req;
        req.code = validation::canonical_type_code(&req.code)?;
        Self::validate_name(&req.name)?;

        // Derive `is_tenant` for AuthZ properties from the code prefix: any type
        // whose path starts with `TENANT_RG_TYPE_PATH` opens a new tenant scope.
        let is_tenant = validation::is_tenant_type_code(&req.code);

        // VHP-2162: a tenant-typed group's effective tenant is always its
        // own (generated) id -- see `create_group_inner`'s
        // `effective_tenant_id` derivation. A caller-supplied `tenant_id` on
        // such a request can never be consulted, so treat it as a
        // contradiction rather than silently discarding it.
        Self::reject_tenant_id_on_tenant_type(is_tenant, req.tenant_id)?;

        // VHP-2162: resolve the target tenant for this create. Omitted
        // `tenant_id` (`None`) is today's unchanged default: target == the
        // caller's own tenant (`tenant_id`, derived by the REST handler from
        // `SecurityContext::subject_tenant_id`). A present `tenant_id` lets
        // an authorized caller (platform admin / onboarding) target a
        // tenant other than their own, subject to the AuthZ checks below.
        let target_tenant_id = req.tenant_id.unwrap_or(tenant_id);

        // VHP-2343 guardrail: a client-supplied `id` is already accepted
        // as-is on create (owner decision, tracked separately under
        // VHP-2343 -- no derived-id, no id_seed, no restriction to tenant
        // types). Combined with an explicit cross-tenant target, that
        // identity-capture gap gets strictly worse: today a captured id
        // lands in the attacker's own tenant; letting `tenant_id` differ
        // too would let it be planted directly inside a tenant the caller
        // does not belong to. Reject the combination outright -- a stopgap,
        // not a fix for VHP-2343 -- until an identifier-ownership policy
        // exists.
        if req.id.is_some() && target_tenant_id != tenant_id {
            return Err(DomainError::validation(
                "id and tenant_id cannot both be set on group creation: an explicit id \
                 combined with a cross-tenant target is not accepted while identifier \
                 ownership policy is undecided (VHP-2343)"
                    .to_owned(),
            ));
        }

        // AuthZ gate with provisioning context. `owner_tenant_id` now also
        // carries the *target* tenant (VHP-2162) alongside the pre-existing
        // `is_tenant`/`parent_id` properties, so a policy that keys off it
        // can decide whether this caller may create groups in that tenant --
        // mirrors account-management's `authz_scope` helper
        // (`domain/authz.rs`) and the CREATE example in `AccessRequest`'s
        // own doc comment.
        let scope =
            self.enforcer
                .access_scope_with(
                    ctx,
                    &RG_GROUP_RESOURCE,
                    "create",
                    None,
                    &authz_resolver_sdk::pep::enforcer::AccessRequest::default()
                        .resource_properties(std::collections::HashMap::from([
                            ("is_tenant".to_owned(), serde_json::Value::Bool(is_tenant)),
                            (
                                "parent_id".to_owned(),
                                req.parent_id.map_or(serde_json::Value::Null, |id| {
                                    serde_json::Value::String(id.to_string())
                                }),
                            ),
                            (
                                pep_properties::OWNER_TENANT_ID.to_owned(),
                                serde_json::Value::String(target_tenant_id.to_string()),
                            ),
                        ])),
                )
                .await
                .map_err(DomainError::from)?;

        // VHP-2162: when the target tenant differs from the caller's own
        // token tenant, re-verify it against the *compiled* `AccessScope` --
        // do not rely solely on the PDP's `decision: true`. This is
        // defense-in-depth: a policy misconfiguration that grants "create"
        // unconditionally must not translate into an unbounded cross-tenant
        // create. When the target equals the caller's own tenant (the
        // common case, including every request that omits `tenant_id`),
        // this block is skipped entirely -- byte-for-byte the pre-VHP-2162
        // behavior.
        //
        // **`InTenantSubtree` limitation (deliberate, not a bug).**
        // `AccessScope::contains_uuid` cannot resolve subtree membership --
        // per `toolkit_security::access_scope::ScopeFilter::values`'s
        // documented write-path limitation, it always returns `false` for an
        // `InTenantSubtree` filter, because doing so would require a
        // DB-backed lookup against `tenant_closure` (owned by Account
        // Management; this crate has no dependency on it). A caller whose
        // only grant for the target tenant is an `InTenantSubtree`
        // constraint (e.g. "parent tenant admins may manage descendant
        // tenants") is therefore denied here even when `target_tenant_id` is
        // genuinely inside that subtree. This is a conservative fail-closed
        // choice over trusting an unverifiable claim; lifting it would
        // require RG to gain a dependency on AM's `tenant_closure`, which is
        // out of scope for this change.
        if target_tenant_id != tenant_id {
            let permitted = scope.is_unconstrained()
                || scope.contains_uuid(pep_properties::OWNER_TENANT_ID, target_tenant_id);
            if !permitted {
                // Not-found shape, not forbidden (mirrors the VHP-2341
                // membership gates in `membership_service.rs`): a tenant the
                // caller has no grant for must be indistinguishable from a
                // tenant that does not exist -- this gear owns no tenant
                // data and cannot legitimately claim to know the
                // difference.
                debug!(
                    caller_tenant_id = %tenant_id,
                    target_tenant_id = %target_tenant_id,
                    "create_group rejected: target tenant outside caller's AccessScope"
                );
                return Err(DomainError::tenant_not_found(target_tenant_id));
            }
        }

        // Validate metadata against the GTS type schema before opening the
        // transaction: a cross-gear `ClientHub` call with nothing to gain in-tx (RG-09).
        validation::validate_metadata_via_gts(
            req.metadata.as_ref(),
            &req.code,
            &*self.types_registry,
        )
        .await?;

        let profile = self.profile.clone();
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let req = req.clone();
            let profile = profile.clone();
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            Box::pin(async move {
                Self::create_group_inner(
                    &*group_repo,
                    &*type_repo,
                    tx,
                    &req,
                    target_tenant_id,
                    &profile,
                )
                .await
            })
        })
        .await
    }

    /// Get a resource group by ID (AuthZ-scoped).
    pub async fn get_group(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
    ) -> Result<ResourceGroup, DomainError> {
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "get", Some(group_id))
            .await
            .map_err(DomainError::from)?;
        let conn = self.db.conn()?;
        self.group_repo
            .find_by_id(&conn, &scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))
    }

    /// List resource groups with `OData` filtering and pagination (AuthZ-scoped).
    pub async fn list_groups(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroup>, DomainError> {
        // IF request has JWT bearer token — the SecurityContext arrives here
        // already authenticated by the API Gateway / AuthNResolverClient.
        // Authenticate via AuthNResolverClient → SecurityContext (performed
        // upstream by the API Gateway; `ctx` carries the resulting subject).
        // Run PolicyEnforcer.access_scope() → AccessScope
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "list", None)
            .await
            .map_err(DomainError::from)?;
        // RETURN JWT mode with SecurityContext + AccessScope (the AccessScope
        // is propagated to the data layer below).
        let conn = self.db.conn()?;
        self.group_repo.list_groups(&conn, &scope, query).await
        // ELSE → RETURN 401 Unauthorized (handled upstream by the API Gateway
        // before SecurityContext is constructed; an absent/invalid JWT never
        // reaches this service path).
    }

    /// Update a resource group's ordinary attributes -- `name` and
    /// `metadata` -- as a full replacement (`AuthZ`-scoped).
    ///
    /// **This is not a structural mutation.** `UpdateGroupRequest` carries no
    /// `parent_id`: re-parenting is [`Self::move_group`], a separate
    /// operation. This path writes exactly one row by primary key, through
    /// [`GroupRepositoryTrait::update_attributes`], whose write set
    /// (`name`, `metadata`, `updated_at`) is disjoint from the move path's
    /// (`parent_id`, `updated_at`). There is therefore no cross-row predicate
    /// *and* no shared column a concurrent writer could invalidate, so it
    /// opens its transaction at the backend default isolation
    /// (`TxConfig::default()` -- READ COMMITTED on `PostgreSQL`; `SQLite` always
    /// runs SERIALIZABLE regardless, per `TxIsolationLevel`'s backend notes,
    /// so the saving is PostgreSQL-only) with bounded retry (max 3
    /// attempts). Per the DB-behaviour audit
    /// (`docs/db-behavior-audit.md`, TX-02).
    ///
    /// **Why there is no isolation-level guess any more.** While `parent_id`
    /// still travelled in the update payload, this method could not know
    /// before opening the transaction whether the request was a rename or a
    /// move, so it guessed from a pre-transaction read, and the
    /// authoritative in-transaction read had to be able to restart the whole
    /// operation under `TxConfig::serializable()` when the guess turned out
    /// to be wrong in the dangerous direction (the
    /// `UpdateGroupOutcome::NeedsSerializable` protocol). With the move
    /// extracted, the guess has no subject: an update can no longer *become*
    /// a move mid-flight, so the level is statically correct and the restart
    /// protocol is gone. The guarantee it existed to protect -- every parent
    /// change runs under `SERIALIZABLE`, with cycle detection and the
    /// closure rebuild inside the same transaction -- now lives in
    /// [`Self::move_group`], which is unconditionally serializable.
    ///
    /// **Removing the protocol was only half the fix.** Until the repository's
    /// single full-row `update` was split in two, this path still *wrote*
    /// `parent_id` -- carrying back the value it had read, which is a blind
    /// structural write, not a no-op. A move committing between that read and
    /// this write reverted the parent while leaving the move's rebuilt closure
    /// rows in place, desynchronising `resource_group.parent_id` from
    /// `resource_group_closure` with no serialization conflict on either side
    /// (and, in the other commit order, letting the move overwrite a
    /// concurrent rename). The disjoint write sets are what make the claim
    /// above true; `concurrent_rename_races_move_same_group` in
    /// `tests/pg_concurrency_test.rs` pins it against a real `PostgreSQL`.
    pub async fn update_group(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        req: UpdateGroupRequest,
    ) -> Result<ResourceGroup, DomainError> {
        // Actor sends PUT /api/resource-group/v1/groups/{group_id}
        // AuthZ gate: verify the caller can update this group (tenant check).
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "update", Some(group_id))
            .await
            .map_err(DomainError::from)?;

        // Pre-validation (stateless, outside transaction).
        // Type is immutable on update — `UpdateGroupRequest` deliberately
        // does not carry a `code` field — so there is nothing to validate
        // syntactically here besides the display name.
        Self::validate_name(&req.name)?;

        // Validate metadata against the GTS type schema before opening the
        // transaction: same rationale as `create_group` (RG-09). `conn` is
        // scoped to this block so the pool connection is released before the
        // transaction (below) requests its own. The scoped read also serves
        // as the caller-visibility pre-check, so a group in another tenant
        // is reported as not-found before any write is attempted.
        {
            let conn = self.db.conn()?;
            let existing = self
                .group_repo
                .find_by_id(&conn, &scope, group_id)
                .await?
                .ok_or_else(|| DomainError::group_not_found(group_id))?;
            validation::validate_metadata_via_gts(
                req.metadata.as_ref(),
                &existing.code,
                &*self.types_registry,
            )
            .await?;
        }

        let db = self.db.db();
        let group_repo = self.group_repo.clone();

        db.transaction_with_retry(TxConfig::default(), DomainError::db_err, |tx| {
            let req = req.clone();
            let scope = scope.clone();
            let group_repo = group_repo.clone();
            Box::pin(async move {
                Self::update_group_inner(&*group_repo, tx, &scope, group_id, &req).await
            })
        })
        .await
    }

    /// Move a group -- and its whole subtree -- to a new parent, or to the
    /// forest root when `new_parent_id` is `None` (`AuthZ`-scoped).
    ///
    /// Runs inside a `SERIALIZABLE` transaction with bounded retry (max 3
    /// attempts) so cycle detection, invariant checks and the closure-table
    /// rebuild are atomic. This is the *only* way to change a group's parent:
    /// [`Self::update_group`] cannot.
    ///
    /// The `AuthZ` gate is the same `update` action on
    /// [`RG_GROUP_RESOURCE`] that [`Self::update_group`] uses, and the
    /// resulting `AccessScope` gates the group lookup exactly the same way --
    /// splitting the REST operation must not widen what a caller may do.
    ///
    /// `new_parent_id` is an explicit `Option`, never "an argument the caller
    /// may omit": `None` *means* "make this group a root".
    pub async fn move_group(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> Result<ResourceGroup, DomainError> {
        // Actor sends POST /api/resource-group/v1/groups/{group_id}/move
        // with {"parent_id": <uuid|null>}.
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "update", Some(group_id))
            .await
            .map_err(DomainError::from)?;

        self.move_group_in_tx(&scope, group_id, new_parent_id).await
    }

    /// Move a group without `AuthZ` enforcement (no tenant scoping).
    ///
    /// **Internal API** — never expose this through a REST handler. Mirrors
    /// the other `*_unscoped` methods on this service: every domain
    /// invariant (cycle detection, parent-type compatibility, depth/width
    /// limits, tenant-root uniqueness, the cross-tenant re-parent ban and
    /// the closure rebuild) still runs, because this shares
    /// `move_group_inner` with the public path; only the `PolicyEnforcer`
    /// gate and the caller-scoped visibility check are skipped.
    pub async fn move_group_unscoped(
        &self,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> Result<ResourceGroup, DomainError> {
        let scope = toolkit_security::AccessScope::allow_all();
        self.move_group_in_tx(&scope, group_id, new_parent_id).await
    }

    /// Shared transaction wrapper for [`Self::move_group`] and
    /// [`Self::move_group_unscoped`] -- the single place the move's isolation
    /// level and retry policy are decided.
    async fn move_group_in_tx(
        &self,
        scope: &toolkit_security::AccessScope,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> Result<ResourceGroup, DomainError> {
        let profile = self.profile.clone();
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let profile = profile.clone();
            let scope = scope.clone();
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            Box::pin(async move {
                Self::move_group_inner(
                    &*group_repo,
                    &*type_repo,
                    tx,
                    &scope,
                    group_id,
                    new_parent_id,
                    &profile,
                )
                .await
            })
        })
        .await
    }

    /// Delete a resource group (AuthZ-scoped).
    ///
    /// Runs inside a `SERIALIZABLE` transaction with bounded retry (max 3 attempts)
    /// to ensure reference checks and cascading deletes are atomic.
    pub async fn delete_group(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        force: bool,
    ) -> Result<(), DomainError> {
        // Actor sends DELETE /api/resource-group/v1/groups/{group_id}?force={true|false}
        // AuthZ gate: verify the caller can delete this group (tenant check).
        // Runs outside the transaction since AuthZ is idempotent.
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "delete", Some(group_id))
            .await
            .map_err(DomainError::from)?;

        let db = self.db.db();
        let group_repo = self.group_repo.clone();

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let scope = scope.clone();
            let group_repo = group_repo.clone();
            Box::pin(async move {
                Self::delete_group_inner(&*group_repo, tx, &scope, group_id, force).await
            })
        })
        .await
    }

    /// Get descendants of a group (depth >= 0, AuthZ-scoped).
    pub async fn get_group_descendants(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupWithDepth>, DomainError> {
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "list", Some(group_id))
            .await
            .map_err(DomainError::from)?;
        let conn = self.db.conn()?;
        // Scope-aware preflight: a cross-tenant id must look the same as a
        // non-existent id from the caller's viewpoint, otherwise we leak the
        // existence of cross-tenant roots (random id → 404, foreign id → 200
        // with empty page).
        self.group_repo
            .find_by_id(&conn, &scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;
        self.group_repo
            .get_descendants(&conn, &scope, group_id, query)
            .await
    }

    /// Get ancestors of a group (depth <= 0, AuthZ-scoped).
    pub async fn get_group_ancestors(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupWithDepth>, DomainError> {
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "list", Some(group_id))
            .await
            .map_err(DomainError::from)?;
        let conn = self.db.conn()?;
        // Scope-aware preflight: see comment in `get_group_descendants`.
        self.group_repo
            .find_by_id(&conn, &scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;
        self.group_repo
            .get_ancestors(&conn, &scope, group_id, query)
            .await
    }

    // -- Unscoped reads (for integration read service, bypasses AuthZ) --
    //
    // These methods are exposed via `ResourceGroupReadHierarchy` trait
    // (registered in ClientHub as `dyn ResourceGroupReadHierarchy`).
    // They use `AccessScope::allow_all()` — no tenant WHERE clause.
    //
    // This is by design (DESIGN §3.6): the AuthZ plugin is the primary
    // consumer of these reads. It cannot evaluate itself (circular dep),
    // so the in-process ClientHub path skips AuthZ entirely.
    //
    // SECURITY: do NOT expose these methods via REST handlers.
    // REST uses the scoped variants (`get_group_descendants` / `get_group_ancestors`).

    /// Get descendants without `AuthZ` enforcement (private API, no tenant scoping).
    pub async fn get_group_descendants_unscoped(
        &self,
        group_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupWithDepth>, DomainError> {
        let conn = self.db.conn()?;
        let scope = toolkit_security::AccessScope::allow_all();
        self.group_repo
            .get_descendants(&conn, &scope, group_id, query)
            .await
    }

    /// Get ancestors without `AuthZ` enforcement (private API, no tenant scoping).
    ///
    /// Used by `ResourceGroupReadHierarchy` consumers (e.g., tenant-resolver plugin)
    /// that need full ancestor visibility regardless of the caller's tenant scope.
    pub async fn get_group_ancestors_unscoped(
        &self,
        group_id: Uuid,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupWithDepth>, DomainError> {
        let conn = self.db.conn()?;
        let scope = toolkit_security::AccessScope::allow_all();
        self.group_repo
            .get_ancestors(&conn, &scope, group_id, query)
            .await
    }

    /// List groups without `AuthZ` enforcement (private API, no tenant scoping).
    ///
    /// Used by `ResourceGroupReadHierarchy::list_groups` consumers (e.g.,
    /// the tenant-resolver RG plugin's batch `get_tenants` path) which need
    /// to resolve groups by id/type predicates regardless of the caller's
    /// tenant scope. Mirrors the pattern of `get_group_*_unscoped`.
    pub async fn list_groups_unscoped(
        &self,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroup>, DomainError> {
        let conn = self.db.conn()?;
        let scope = toolkit_security::AccessScope::allow_all();
        self.group_repo.list_groups(&conn, &scope, query).await
    }

    /// Get a single group by id without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler. Used by
    /// the seeding path (which runs at gear init, before any caller
    /// security context exists) to check whether a seeded group is already
    /// present. Mirrors the pattern of the other `*_unscoped` methods.
    pub async fn get_group_unscoped(&self, group_id: Uuid) -> Result<ResourceGroup, DomainError> {
        let conn = self.db.conn()?;
        let scope = toolkit_security::AccessScope::allow_all();
        self.group_repo
            .find_by_id(&conn, &scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))
    }

    /// Create a group without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler. Used by
    /// the seeding path to provision required groups at gear init, before
    /// any caller security context exists. Domain invariants (type
    /// validation, parent compatibility, tenant scoping, closure table
    /// maintenance) still run because this method calls the same
    /// `create_group_inner` as the public path; only the `PolicyEnforcer`
    /// gate is skipped.
    ///
    /// **`tenant_id` vs `req.tenant_id` (VHP-2162).** `tenant_id` is the
    /// caller-trusted target tenant -- seeding already resolved it before
    /// calling in (see `seeding::seed_groups`, which always passes
    /// `req.tenant_id: None`). If `req.tenant_id` is *also* set and
    /// disagrees with the `tenant_id` argument, that is treated as a caller
    /// bug, not a preference to resolve silently: this is a trusted internal
    /// path, so a disagreement most likely means a construction mistake
    /// upstream, and quietly picking a winner (either one) would hide it.
    /// Erroring is the safer choice here; an agreeing (equal) value is
    /// accepted as a no-op.
    pub async fn create_group_unscoped(
        &self,
        req: CreateGroupRequest,
        tenant_id: Uuid,
    ) -> Result<ResourceGroup, DomainError> {
        // Same single canonical parse as `create_group` -- seeding goes
        // through the identical rule, so a seed definition cannot introduce a
        // non-canonical code the public path would have rejected.
        let mut req = req;
        req.code = validation::canonical_type_code(&req.code)?;
        Self::validate_name(&req.name)?;

        let is_tenant = validation::is_tenant_type_code(&req.code);
        Self::reject_tenant_id_on_tenant_type(is_tenant, req.tenant_id)?;

        if let Some(req_tenant_id) = req.tenant_id
            && req_tenant_id != tenant_id
        {
            return Err(DomainError::validation(format!(
                "create_group_unscoped: req.tenant_id ({req_tenant_id}) disagrees with the \
                 trusted tenant_id argument ({tenant_id}); this indicates a caller bug, not a \
                 policy decision to make silently"
            )));
        }

        // Same RG-09 fix as `create_group`: validate metadata against the
        // GTS type schema (a cross-gear ClientHub call) before opening the
        // transaction.
        validation::validate_metadata_via_gts(
            req.metadata.as_ref(),
            &req.code,
            &*self.types_registry,
        )
        .await?;

        let profile = self.profile.clone();
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let req = req.clone();
            let profile = profile.clone();
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            Box::pin(async move {
                Self::create_group_inner(&*group_repo, &*type_repo, tx, &req, tenant_id, &profile)
                    .await
            })
        })
        .await
    }

    // -- Transaction-inner implementations --

    /// Inner logic for `create_group`, runs inside a SERIALIZABLE transaction.
    ///
    /// **Metadata schema validation.** `create_group` already ran
    /// `validate_metadata_via_gts` before opening this transaction (RG-09):
    /// it's a cross-gear `ClientHub` call, not a DB read to make atomic.
    ///
    /// **`tenant_id` parameter (VHP-2162).** This is the already-resolved
    /// *target* tenant, not necessarily the caller's own token tenant:
    /// `create_group` folds an authorized `req.tenant_id` override into this
    /// value (already AuthZ-gated against the caller's `AccessScope`)
    /// before calling in; `create_group_unscoped` (seeding) passes its own
    /// trusted tenant directly. Either way, this function treats it as
    /// *the* tenant to enforce/persist -- it has no separate notion of
    /// "the caller's own tenant".
    #[allow(clippy::too_many_arguments, clippy::cognitive_complexity)]
    async fn create_group_inner(
        group_repo: &GR,
        type_repo: &TR,
        tx: &impl DBRunner,
        req: &CreateGroupRequest,
        tenant_id: Uuid,
        profile: &QueryProfile,
    ) -> Result<ResourceGroup, DomainError> {
        // Resolve type GTS path to surrogate ID; verify type exists.
        // find_by_code_with_id fetches id + type together in one query (RG-11).
        let (type_id, rg_type) = type_repo
            .find_by_code_with_id(tx, &req.code)
            .await?
            .ok_or_else(|| DomainError::type_not_found(&req.code))?;

        // Determine effective tenant_id by code-prefix rule:
        // - code starts with TENANT_RG_TYPE_PATH → tenant_id = group.id (new scope)
        // - otherwise                           → tenant_id from caller / parent
        //
        // `req.code` is already the canonical form (both callers parse it
        // through `validation::canonical_type_code` before opening the
        // transaction), and the prefix test itself canonicalizes again, so
        // this classification cannot disagree with the `is_tenant` value the
        // AuthZ gate above was given.
        let group_id = req.id.unwrap_or_else(Uuid::now_v7);
        let is_tenant_type = validation::is_tenant_type_code(&req.code);
        let effective_tenant_id = if is_tenant_type { group_id } else { tenant_id };

        // A tenant-typed group issues a tenant identifier: its own `id`
        // becomes its `tenant_id`. Identifiers are never reissued, so a
        // create that names one this gear has already retired must be
        // refused — otherwise every audit record, external reference and
        // cached authorization decision still naming it would silently
        // re-point at an unrelated tenant.
        //
        // Checked inside the create transaction so a concurrent delete
        // cannot retire the identifier between this probe and the INSERT.
        // The rejection carries only the identifier the caller supplied:
        // disclosing when or under what name it was retired would turn
        // this endpoint into an oracle over deleted tenants.
        if is_tenant_type
            && group_repo
                .is_tenant_identifier_retired(tx, group_id)
                .await?
        {
            return Err(DomainError::group_already_exists(group_id));
        }

        if let Some(parent_id) = req.parent_id {
            let parent = group_repo
                .find_model_by_id(tx, parent_id)
                .await?
                .ok_or_else(|| DomainError::group_not_found(parent_id))?;

            let parent_type_path = Self::resolve_type_path_from_id(tx, parent.gts_type_id).await?;
            if !rg_type.allowed_parent_types.contains(&parent_type_path) {
                return Err(DomainError::invalid_parent_type(format!(
                    "Type '{}' does not allow parent type '{}'",
                    req.code, parent_type_path
                )));
            }

            // Extract caller effective tenant scope from SecurityContext.subject_tenant_id
            // (tenant_id is passed as parameter from caller's context)
            // IF caller is privileged platform-admin -> pass (but data invariants still checked)
            // (platform-admin bypass handled by middleware; data invariants enforced below)
            // Validate tenant compatibility (child must be same tenant as parent)
            // IF membership write: validate target group's tenant_id is compatible
            // Skip tenant enforcement for tenant-typed groups — they intentionally
            // create a new tenant scope (tenant_id = group.id != parent.tenant_id).
            if !is_tenant_type && parent.tenant_id != tenant_id {
                // VHP-2345: generic message -- do not interpolate the
                // parent's tenant_id. The caller supplies `parent_id`
                // directly, so echoing the foreign tenant_id back would
                // turn this endpoint into a cross-tenant oracle: probe an
                // arbitrary `parent_id` and learn both that the group
                // exists and which tenant owns it. Mirrors
                // `update_group_inner`'s cross-tenant parent-change
                // message below. Real values stay in this debug log only.
                //
                // `tenant_id` here is the resolved *target* tenant
                // (VHP-2162), which for the default (no explicit
                // `CreateGroupRequest::tenant_id`) case is exactly the
                // caller's own tenant -- so this also covers the
                // conflict-with-parent rule for an explicit cross-tenant
                // target: the parent's tenant must match the *requested*
                // tenant, not just the caller's.
                debug!(
                    target_tenant_id = %tenant_id,
                    parent_tenant_id = %parent.tenant_id,
                    parent_id = %parent_id,
                    "create_group rejected: parent belongs to a different tenant"
                );
                return Err(DomainError::validation(
                    "Cannot create group under this parent; parent belongs to a different \
                     tenant"
                        .to_owned(),
                ));
            }
            // RETURN pass (tenant enforcement passed)

            // Check query profile: depth limit
            if let Some(max_depth) = profile.max_depth {
                let parent_depth = group_repo.get_depth(tx, parent_id).await?;
                #[allow(clippy::cast_possible_wrap)]
                if parent_depth + 1 >= max_depth as i32 {
                    return Err(DomainError::limit_violation(format!(
                        "Depth limit exceeded: adding child at depth {} exceeds max_depth {}",
                        parent_depth + 1,
                        max_depth
                    )));
                }
            }

            // Check query profile: width limit
            if let Some(max_width) = profile.max_width {
                let sibling_count = group_repo.count_children(tx, parent_id).await?;
                if sibling_count >= u64::from(max_width) {
                    return Err(DomainError::limit_violation(format!(
                        "Width limit exceeded: parent already has {sibling_count} children, max_width is {max_width}"
                    )));
                }
            }

            // Insert group
            let _model = group_repo
                .insert(
                    tx,
                    group_id,
                    Some(parent_id),
                    type_id,
                    &req.name,
                    req.metadata.as_ref(),
                    effective_tenant_id,
                )
                .await?;

            // Insert closure: self-row
            group_repo.insert_closure_self_row(tx, group_id).await?;

            // Insert ancestor closure rows from parent's ancestors with depth+1
            group_repo
                .insert_ancestor_closure_rows(tx, group_id, parent_id)
                .await?;

            let sys = toolkit_security::AccessScope::allow_all();
            group_repo
                .find_by_id(tx, &sys, group_id)
                .await?
                .ok_or_else(|| DomainError::database("Insert succeeded but group not found"))
        } else {
            // Root group: validate can_be_root
            if !rg_type.can_be_root {
                return Err(DomainError::invalid_parent_type(format!(
                    "Type '{}' cannot be a root group (can_be_root=false)",
                    req.code
                )));
            }

            // Tenant-root uniqueness: at most one tenant-type group may be a
            // forest root. `cpt-cf-resource-group-fr-enforce-tenant-root-uniqueness`.
            if is_tenant_type
                && let Some(existing_root_id) = group_repo
                    .find_root_id_with_type_prefix(tx, TENANT_RG_TYPE_PATH)
                    .await?
            {
                return Err(DomainError::tenant_root_already_exists(
                    existing_root_id,
                    format!(
                        "Cannot create tenant-type root '{}' ({}): tenant root already exists",
                        req.name, req.code
                    ),
                ));
            }

            // Insert group
            let _model = group_repo
                .insert(
                    tx,
                    group_id,
                    None,
                    type_id,
                    &req.name,
                    req.metadata.as_ref(),
                    effective_tenant_id,
                )
                .await?;

            // Insert closure: self-row only
            group_repo.insert_closure_self_row(tx, group_id).await?;

            let sys = toolkit_security::AccessScope::allow_all();
            group_repo
                .find_by_id(tx, &sys, group_id)
                .await?
                .ok_or_else(|| DomainError::database("Insert succeeded but group not found"))
        }
    }

    /// Inner logic for `update_group`, runs inside the transaction opened by
    /// `update_group` at the backend default isolation.
    ///
    /// **Nothing structural happens here, and nothing structural is written.**
    /// `UpdateGroupRequest` carries only `name` and `metadata`, and
    /// [`GroupRepositoryTrait::update_attributes`] writes only those two plus
    /// `updated_at`. `parent_id`, `gts_type_id` and `tenant_id` are not in the
    /// statement's `SET` list at all, so this path cannot re-parent, re-type
    /// or re-tenant a group even by accident.
    ///
    /// The previous shape read the row back and re-supplied `parent_id` /
    /// `gts_type_id` to a repository method that wrote every column
    /// unconditionally. That read-back was not a no-op but a blind structural
    /// write of a value observed before the write: a `move_group` committing
    /// in between had its parent change reverted while its closure rebuild
    /// survived. Not writing the column is the fix; the read it existed to
    /// serve is gone with it.
    ///
    /// **Type immutability.** A group's GTS type is fixed at creation —
    /// `UpdateGroupRequest` does not carry a `code` field, and `gts_type_id`
    /// is no longer writable through any repository method, so all
    /// type-driven validation (allowed parents/children, tenant-root rule,
    /// metadata schema lookup) stays anchored on the existing type.
    ///
    /// **Metadata schema validation.** `update_group` already ran
    /// `validate_metadata_via_gts` before opening this transaction (RG-09);
    /// see `create_group_inner`'s doc comment for why.
    async fn update_group_inner(
        group_repo: &GR,
        tx: &impl DBRunner,
        scope: &toolkit_security::AccessScope,
        group_id: Uuid,
        req: &UpdateGroupRequest,
    ) -> Result<ResourceGroup, DomainError> {
        // DB: SELECT FROM resource_group WHERE id = {group_id} -- scoped read,
        // so a group outside the caller's tenant is reported as not-found.
        group_repo
            .find_by_id(tx, scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        // Persist name/metadata only. Nothing else about the row is read,
        // because nothing else is written.
        let _model = group_repo
            .update_attributes(tx, group_id, &req.name, req.metadata.as_ref())
            .await?;

        let sys = toolkit_security::AccessScope::allow_all();
        group_repo
            .find_by_id(tx, &sys, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))
    }

    /// Inner logic for `move_group` / `move_group_unscoped`, runs inside a
    /// SERIALIZABLE transaction.
    ///
    /// **Tenant immutability.** A group's `tenant_id` is fixed at creation.
    /// Re-parenting is therefore allowed only **within the same tenant** —
    /// the new parent's `tenant_id` must equal the moved group's, otherwise
    /// the move is rejected with the same rule `create_group_inner` uses for
    /// non-tenant children. Tenant-type roots have `tenant_id == group_id` by
    /// construction, so the equality check covers them too.
    ///
    /// **Check order is deliberate.** The cross-tenant test runs *before* the
    /// parent-type-compatibility and limit checks, not after. Both orders
    /// reject the move, but the type check's message names the parent's GTS
    /// type path (`"Type 'X' does not allow parent type 'Y'"`), which for a
    /// foreign parent would disclose a fact about another tenant's data to a
    /// caller who supplied nothing but a UUID. Refusing on the tenant
    /// boundary first keeps the cross-tenant answer uniform.
    #[allow(clippy::too_many_arguments)]
    async fn move_group_inner(
        group_repo: &GR,
        type_repo: &TR,
        tx: &impl DBRunner,
        scope: &toolkit_security::AccessScope,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
        profile: &QueryProfile,
    ) -> Result<ResourceGroup, DomainError> {
        // Scope-checked read first: a group the caller may not see must be
        // indistinguishable from a group that does not exist. Mirrors
        // `update_group_inner` / `delete_group_inner`.
        group_repo
            .find_by_id(tx, scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        // Load group and new parent in transaction
        let existing = group_repo
            .find_model_by_id(tx, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        // Cross-tenant moves are forbidden — see this function's doc comment
        // for the invariant and for why this check comes first.
        if let Some(new_parent_id) = new_parent_id {
            let new_parent = group_repo
                .find_model_by_id(tx, new_parent_id)
                .await?
                .ok_or_else(|| DomainError::group_not_found(new_parent_id))?;
            if new_parent.tenant_id != existing.tenant_id {
                // Generic message: do not interpolate tenant ids — the caller
                // can't act on them legitimately, and disclosing the foreign
                // tenant_id would leak ownership of `new_parent_id` across the
                // tenant boundary. Real values stay in this debug log only.
                debug!(
                    group_id = %group_id,
                    group_tenant_id = %existing.tenant_id,
                    parent_tenant_id = %new_parent.tenant_id,
                    "move_group rejected: new parent belongs to a different tenant"
                );
                return Err(DomainError::validation(format!(
                    "Cannot move group {group_id} to a parent in a different tenant; \
                     cross-tenant moves are not supported"
                )));
            }
        }

        let type_path = Self::resolve_type_path_from_id(tx, existing.gts_type_id).await?;
        let rg_type = type_repo
            .find_by_code(tx, &type_path)
            .await?
            .ok_or_else(|| DomainError::type_not_found(&type_path))?;

        // Cycle detect, type compat, profile enforce, closure rebuild
        Self::move_group_internal_impl(
            group_repo,
            tx,
            group_id,
            existing.tenant_id,
            new_parent_id,
            &rg_type,
            profile,
        )
        .await?;

        // Update parent_id on the group. `name`, `metadata`, `gts_type_id` and
        // `tenant_id` are not in this statement's SET list, so a concurrent
        // `update_group` renaming the same group cannot have its rename
        // clobbered by a stale copy read at the top of this transaction --
        // see `GroupRepositoryTrait::update_parent`.
        group_repo
            .update_parent(tx, group_id, new_parent_id)
            .await?;

        let sys = toolkit_security::AccessScope::allow_all();
        group_repo
            .find_by_id(tx, &sys, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))
    }

    /// Inner logic for `delete_group`, runs inside a SERIALIZABLE transaction.
    async fn delete_group_inner(
        group_repo: &GR,
        tx: &impl DBRunner,
        scope: &toolkit_security::AccessScope,
        group_id: Uuid,
        force: bool,
    ) -> Result<(), DomainError> {
        // DB: SELECT FROM resource_group WHERE id = {group_id}
        group_repo
            .find_by_id(tx, scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        let _existing = group_repo
            .find_model_by_id(tx, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        if force {
            // Force delete: cascade entire subtree + memberships + closure
            #[allow(clippy::let_and_return)]
            let result = Self::force_delete_subtree(group_repo, tx, group_id).await;
            result
        } else {
            // Non-force: collect *both* blocker classes before returning a
            // single rejection. DESIGN.md:1320 requires the response to name
            // children **and/or** memberships; returning as soon as the
            // children check failed made the "or" half unreachable -- a
            // group blocked by both only ever reported the children, never
            // the memberships alongside them.
            let children = Self::get_direct_children(tx, group_id).await?;
            let membership_count = group_repo.count_memberships(tx, group_id).await?;

            if !children.is_empty() || membership_count > 0 {
                let (visible_child_ids, has_hidden_children) =
                    Self::classify_children_for_delete(tx, &children).await?;

                let mut blockers = Vec::new();
                if !visible_child_ids.is_empty() {
                    blockers.push(format!("{} child group(s)", visible_child_ids.len()));
                }
                if has_hidden_children {
                    // No id, no exact count -- see
                    // `classify_children_for_delete`'s doc comment for why a
                    // tenant-typed child can be named neither individually
                    // nor by an exact hidden count.
                    blockers.push("additional child group(s) in another tenant".to_owned());
                }
                if membership_count > 0 {
                    blockers.push(format!("{membership_count} membership(s)"));
                }
                // Reachable only via `!children.is_empty() || membership_count
                // > 0`, and every child is classified into exactly one of
                // `visible_child_ids` / `has_hidden_children` below, so
                // `blockers` always has at least one entry here.
                let message = format!(
                    "Cannot delete group '{group_id}': blocked by {}. Use force=true to cascade.",
                    blockers.join(" and ")
                );
                return Err(DomainError::conflict_active_references(message)
                    .with_blocking_entity_ids(visible_child_ids));
            }

            // Delete closure rows, then the group
            group_repo.delete_all_closure_rows(tx, group_id).await?;
            group_repo.delete_by_id(tx, group_id).await
        }
    }

    // -- Internal helpers --

    /// Internal move logic behind `move_group` / `move_group_unscoped`.
    ///
    /// Performs cycle detection, type compatibility checks, query profile
    /// enforcement, and closure table rebuild. Must be called within a
    /// SERIALIZABLE transaction.
    ///
    /// **Both branches enforce the invariants that are meaningful for them.**
    /// The `Some(new_parent)` branch and the "move to root" branch used to be
    /// asymmetric: `max_depth` / `max_width` were checked only under
    /// `Some(new_parent)`, so a move to root skipped the query profile
    /// entirely. What each branch checks, and why:
    ///
    /// | Invariant | new parent | root |
    /// |---|---|---|
    /// | cycle | yes | n/a — a root has no ancestors, so no cycle is expressible |
    /// | `allowed_parent_types` | yes | replaced by `can_be_root` |
    /// | tenant-root uniqueness | n/a — only a root can be *the* tenant root | yes |
    /// | `max_width` | children of the new parent | root groups of this tenant |
    /// | `max_depth` | yes | **provably unnecessary**, see below |
    ///
    /// `max_depth` needs no check on the root branch: the moved subtree keeps
    /// its internal shape, and its new deepest node sits at
    /// `0 + max_subtree_depth`, whereas before the move it sat at
    /// `old_parent_depth + 1 + max_subtree_depth`. Since `old_parent_depth >=
    /// 0`, promoting to root can only *decrease* (never increase) the deepest
    /// depth reached. A check here could therefore only fire on a tree that
    /// already violated `max_depth` before the move, and rejecting the very
    /// operation that repairs the violation would be perverse. Skipping it
    /// also spares the two closure reads `get_depth` /
    /// `get_descendant_ids_with_depth` cost.
    #[allow(clippy::cognitive_complexity, clippy::too_many_arguments)]
    async fn move_group_internal_impl(
        group_repo: &GR,
        conn: &impl DBRunner,
        group_id: Uuid,
        tenant_id: Uuid,
        new_parent_id: Option<Uuid>,
        rg_type: &resource_group_sdk::ResourceGroupType,
        profile: &QueryProfile,
    ) -> Result<(), DomainError> {
        if let Some(new_pid) = new_parent_id {
            // Cycle detection: self-parent check (covered by is_descendant via self-row)
            let is_desc = group_repo.is_descendant(conn, group_id, new_pid).await?;
            if is_desc {
                debug!(group_id = %group_id, new_parent = %new_pid, "Cycle detected in move_group");
                return Err(DomainError::cycle_detected(format!(
                    "Cannot move group '{group_id}' under '{new_pid}': would create a cycle"
                )));
            }

            // Validate parent type compatibility
            let parent = group_repo
                .find_model_by_id(conn, new_pid)
                .await?
                .ok_or_else(|| DomainError::group_not_found(new_pid))?;

            let parent_type_path =
                Self::resolve_type_path_from_id(conn, parent.gts_type_id).await?;
            if !rg_type.allowed_parent_types.contains(&parent_type_path) {
                return Err(DomainError::invalid_parent_type(format!(
                    "Type '{}' does not allow parent type '{}'",
                    rg_type.code, parent_type_path
                )));
            }

            // Cycle detection passed

            // Load profile config: max_depth (optional), max_width (optional)
            // (profile is passed as parameter with max_depth and max_width)

            // Check query profile: depth limit
            if let Some(max_depth) = profile.max_depth {
                let parent_depth = group_repo.get_depth(conn, new_pid).await?;
                // Check depth of deepest descendant of moved node.
                // get_descendant_ids_with_depth returns id and depth
                // together, so the max is taken in memory over one query (RG-05).
                let subtree_descendants = group_repo
                    .get_descendant_ids_with_depth(conn, group_id)
                    .await?;
                let max_subtree_depth = subtree_descendants
                    .iter()
                    .map(|(_id, depth)| *depth)
                    .max()
                    .unwrap_or(0);
                let new_deepest = parent_depth + 1 + max_subtree_depth;
                #[allow(clippy::cast_possible_wrap)]
                if new_deepest >= max_depth as i32 {
                    debug!(group_id = %group_id, new_deepest, max_depth, "Depth limit exceeded on move");
                    return Err(DomainError::limit_violation(format!(
                        "Depth limit exceeded: moving subtree would create depth {new_deepest}, max_depth is {max_depth}"
                    )));
                }
            }

            // Check query profile: width limit
            if let Some(max_width) = profile.max_width {
                let sibling_count = group_repo.count_children(conn, new_pid).await?;
                if sibling_count >= u64::from(max_width) {
                    return Err(DomainError::limit_violation(format!(
                        "Width limit exceeded: new parent already has {sibling_count} children, max_width is {max_width}"
                    )));
                }
            }
            // Profile checks passed
        } else {
            // Moving to root: validate can_be_root, tenant-root uniqueness
            // and the width of this tenant's root level. See this function's
            // doc comment for the branch-by-branch invariant table and for
            // why `max_depth` is provably unnecessary here.
            if !rg_type.can_be_root {
                return Err(DomainError::invalid_parent_type(format!(
                    "Type '{}' cannot be a root group (can_be_root=false)",
                    rg_type.code
                )));
            }

            // Tenant-root uniqueness: at most one tenant-type group may be a
            // forest root. Mirrors the guard in `create_group_inner` —
            // `cpt-cf-resource-group-fr-enforce-tenant-root-uniqueness`. We
            // exclude the moved group itself so a no-op move (already root)
            // does not falsely fire.
            if validation::is_tenant_type_code(&rg_type.code)
                && let Some(existing_root_id) = group_repo
                    .find_root_id_with_type_prefix(conn, TENANT_RG_TYPE_PATH)
                    .await?
                && existing_root_id != group_id
            {
                return Err(DomainError::tenant_root_already_exists(
                    existing_root_id,
                    format!(
                        "Cannot move tenant-type group '{}' ({group_id}) to root: tenant root already exists",
                        rg_type.code
                    ),
                ));
            }

            // Check query profile: width limit at the root level. The root
            // level's sibling set is scoped to the moved group's own tenant,
            // not to the whole forest: a global count would make one tenant's
            // shape constrain another's, and the rejection message would
            // disclose a cross-tenant total. The moved group is excluded from
            // the count so a no-op move of an existing root does not
            // spuriously trip the limit.
            if let Some(max_width) = profile.max_width {
                let root_count = group_repo
                    .count_root_siblings(conn, tenant_id, group_id)
                    .await?;
                if root_count >= u64::from(max_width) {
                    debug!(group_id = %group_id, root_count, max_width, "Root width limit exceeded on move");
                    return Err(DomainError::limit_violation(format!(
                        "Width limit exceeded: the tenant already has {root_count} root group(s), max_width is {max_width}"
                    )));
                }
            }
        }

        // Rebuild closure table for the subtree
        group_repo
            .rebuild_subtree_closure(conn, group_id, new_parent_id)
            .await?;

        Ok(())
    }

    /// Force-delete an entire subtree (group + descendants + memberships + closure).
    ///
    /// Memberships and closure rows are deleted for the whole subtree in
    /// one batched call each, safe since every node in the batch is removed
    /// together, not partially.
    ///
    /// Groups are deleted depth-level by depth-level, deepest first, since
    /// `parent_id` is `ON DELETE RESTRICT` -- a parent's row is never
    /// removed while a not-yet-removed child still references it (RG-10).
    async fn force_delete_subtree(
        group_repo: &GR,
        conn: &impl DBRunner,
        root_id: Uuid,
    ) -> Result<(), DomainError> {
        let descendants_with_depth = group_repo
            .get_descendant_ids_with_depth(conn, root_id)
            .await?;

        let all_ids: Vec<Uuid> = std::iter::once(root_id)
            .chain(descendants_with_depth.iter().map(|(id, _depth)| *id))
            .collect();

        // Retire the tenant identifiers among these ids before the rows
        // go away. Deleting a tenant-typed group frees its `id`, and that
        // `id` is a `tenant_id` — so this has to happen inside the same
        // transaction, and it has to read `resource_group` while the rows
        // are still there.
        group_repo.retire_tenant_identifiers(conn, &all_ids).await?;

        group_repo.delete_memberships_many(conn, &all_ids).await?;
        group_repo
            .delete_all_closure_rows_many(conn, &all_ids)
            .await?;

        // Group ids by their depth relative to root_id (root itself is
        // depth 0), then delete depth levels from deepest to shallowest.
        let mut ids_by_depth: std::collections::BTreeMap<i32, Vec<Uuid>> =
            std::collections::BTreeMap::new();
        ids_by_depth.entry(0).or_default().push(root_id);
        for (id, depth) in descendants_with_depth {
            ids_by_depth.entry(depth).or_default().push(id);
        }
        for ids in ids_by_depth.into_values().rev() {
            group_repo.delete_by_id_many(conn, &ids).await?;
        }

        Ok(())
    }

    /// Get direct children of a group.
    async fn get_direct_children(
        conn: &impl DBRunner,
        parent_id: Uuid,
    ) -> Result<Vec<crate::infra::storage::entity::resource_group::Model>, DomainError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use toolkit_db::secure::SecureEntityExt;

        let scope = toolkit_security::AccessScope::allow_all();
        crate::infra::storage::entity::resource_group::Entity::find()
            .filter(crate::infra::storage::entity::resource_group::Column::ParentId.eq(parent_id))
            .secure()
            .scope_with(&scope)
            .all(conn)
            .await
            .map_err(|e| DomainError::database(e.to_string()))
    }

    /// Split `children` (read under `AccessScope::allow_all()` by
    /// [`Self::get_direct_children`]) into the ids that are safe to disclose
    /// in a `delete_group` rejection and a flag for the ones that are not.
    ///
    /// **Why this split exists.** A tenant-typed child's `id` *is* a
    /// `tenant_id` (`create_group_inner`'s `effective_tenant_id`
    /// derivation), and such a child is exempt from the cross-tenant
    /// parent-check on create (`create_group_inner`'s `is_tenant_type`
    /// guard), so it can legitimately sit under a parent belonging to a
    /// *different* tenant than the child itself. Naming that id in an error
    /// response would hand the caller a foreign tenant's identifier; RG does
    /// not own tenant data and must not be the one to disclose it
    /// (DESIGN.md:1331-1337, mirrors the VHP-2345 anti-oracle rule elsewhere
    /// in this file). Non-tenant-typed children carry no such risk: they
    /// necessarily share `parent_id`'s tenant, and `parent_id` already
    /// passed the scope-checked preflight in `delete_group_inner`.
    ///
    /// The second return value is deliberately a `bool`, not a count: even
    /// the *number* of hidden tenant-typed children would let a caller
    /// binary-search a foreign tenant's fan-out under a shared parent. It
    /// only says "there are more blockers than what's listed above".
    ///
    /// **Why the rejection names children but only counts memberships.** The
    /// two blocker classes carry different risks, so `DESIGN.md:1320`'s "list
    /// of blocking entities" is satisfied asymmetrically on purpose. A
    /// membership's identity *is* the triple `(group_id, resource_type,
    /// resource_id)` with no surrogate id, so listing memberships would build
    /// the leak `DESIGN.md:1326` names outright — "an existence oracle for any
    /// guessed `(resource_type, resource_id)`" — letting a caller probe
    /// guessed resources and read existence off the list. A non-tenant-typed
    /// child's id discloses nothing the caller cannot already see. Hence ids
    /// here, a count in [`GroupRepositoryTrait::count_memberships`]. The
    /// asymmetry is the requirement, not an unfinished half of it.
    async fn classify_children_for_delete(
        tx: &impl DBRunner,
        children: &[crate::infra::storage::entity::resource_group::Model],
    ) -> Result<(Vec<String>, bool), DomainError> {
        let mut visible_child_ids = Vec::with_capacity(children.len());
        let mut has_hidden_children = false;
        let mut tenant_type_by_gts_id: std::collections::HashMap<i16, bool> =
            std::collections::HashMap::new();

        for child in children {
            // Resolving a type path is a DB round-trip, so memoize per
            // `gts_type_id`: siblings very often share a type, and the
            // rejection path must not fan out one query per child.
            let is_tenant_type =
                if let Some(&cached) = tenant_type_by_gts_id.get(&child.gts_type_id) {
                    cached
                } else {
                    let type_path = Self::resolve_type_path_from_id(tx, child.gts_type_id).await?;
                    let is_tenant_type = validation::is_tenant_type_code(&type_path);
                    tenant_type_by_gts_id.insert(child.gts_type_id, is_tenant_type);
                    is_tenant_type
                };

            if is_tenant_type {
                has_hidden_children = true;
            } else {
                visible_child_ids.push(child.id.to_string());
            }
        }

        Ok((visible_child_ids, has_hidden_children))
    }

    /// Resolve a type ID to its GTS path.
    async fn resolve_type_path_from_id(
        conn: &impl DBRunner,
        type_id: i16,
    ) -> Result<String, DomainError> {
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        use toolkit_db::secure::SecureEntityExt;

        let scope = toolkit_security::AccessScope::allow_all();
        let model = crate::infra::storage::entity::gts_type::Entity::find()
            .filter(crate::infra::storage::entity::gts_type::Column::Id.eq(type_id))
            .secure()
            .scope_with(&scope)
            .one(conn)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?
            .ok_or_else(|| DomainError::database(format!("Type ID {type_id} not found")))?;
        Ok(model.schema_id)
    }

    fn validate_name(name: &str) -> Result<(), DomainError> {
        // Count Unicode scalar values, not UTF-8 bytes, so the limit matches
        // the documented "255 characters" and aligns with the DB-level
        // `length(name) BETWEEN 1 AND 255` CHECK on PostgreSQL/SQLite, where
        // `length(text)` is character-based on both engines.
        if name.is_empty() || name.chars().count() > 255 {
            return Err(DomainError::validation(
                "Group name must be between 1 and 255 characters",
            ));
        }
        Ok(())
    }

    /// Reject an explicit `tenant_id` on a tenant-typed group create
    /// request (VHP-2162).
    ///
    /// A tenant-typed group's effective tenant is always its own generated
    /// id (see `create_group_inner`'s `effective_tenant_id` derivation) --
    /// never a caller-supplied value. Silently accepting `tenant_id` on such
    /// a request would either be ignored (confusing) or, worse, be assumed
    /// by the caller to have taken effect. Shared by `create_group` and
    /// `create_group_unscoped` so both entry points enforce the same rule.
    fn reject_tenant_id_on_tenant_type(
        is_tenant: bool,
        req_tenant_id: Option<Uuid>,
    ) -> Result<(), DomainError> {
        if is_tenant && req_tenant_id.is_some() {
            return Err(DomainError::validation(
                "tenant_id must not be set when creating a tenant-typed group: its tenant \
                 scope is always the group's own id, never a caller-supplied value"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}
