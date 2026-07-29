// Created: 2026-04-16 by Constructor Tech
// Updated: 2026-04-28 by Constructor Tech
// @cpt-begin:cpt-cf-resource-group-dod-entity-hier-entity-service:p1:inst-full
// @cpt-dod:cpt-cf-resource-group-dod-testing-entity-hierarchy:p1
//! Domain service for resource group entity management.
//!
//! Implements business rules: type validation, parent compatibility,
//! cycle detection, closure table management, query profile enforcement,
//! and CRUD orchestration.
//!
//! All hierarchy-mutating operations (`create_group`, `move_group`,
//! `delete_group`, and `update_group`'s parent-change branch) use
//! `SERIALIZABLE` transactions with bounded retry (max 3 attempts) to
//! prevent phantom reads and ensure closure table consistency under
//! concurrent mutations. `update_group`'s pure rename/metadata path (no
//! `parent_id` change) has no cross-row predicate to protect and runs at the
//! backend default isolation instead (`rg-db-audit-transactions.md`,
//! recommendation #3) -- see `update_group`'s own doc comment for the
//! isolation-selection and race-closing rationale.

use std::sync::Arc;

use authz_resolver_sdk::pep::{PolicyEnforcer, ResourceType};
use resource_group_sdk::models::{
    CreateGroupRequest, ResourceGroup, ResourceGroupWithDepth, UpdateGroupRequest,
};
use resource_group_sdk::{GROUP_RESOURCE_TYPE, TENANT_RG_TYPE_PATH};
use toolkit_db::secure::{DBRunner, Db, TxConfig};
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

/// Outcome of one `update_group_inner` attempt.
///
/// Purely an internal control-flow value for `update_group` -- it never
/// crosses a `?` boundary into `DomainError`/`CanonicalError`, so it changes
/// no error semantics visible to callers. See `update_group`'s isolation
/// comment for why this exists: `update_group` opens the transaction at a
/// isolation level chosen from a pre-transaction hint (does this update
/// change the group's parent?). `NeedsSerializable` is how the
/// fresh-inside-the-transaction read tells `update_group` that the hint was
/// stale in the dangerous direction -- the move branch (cycle detection +
/// closure rebuild) is required but the open transaction is not
/// SERIALIZABLE -- so the whole operation must be redone at
/// `TxConfig::serializable()`. It is returned before any write happens in
/// that attempt, so discarding it is always a no-op commit, never a partial
/// write.
enum UpdateGroupOutcome {
    /// The update completed (rename-only or parent-change) under a
    /// transaction whose isolation level was sufficient for what it turned
    /// out to need.
    Done(ResourceGroup),
    /// The fresh in-tx read disagreed with the pre-transaction hint: this
    /// update does need the parent-change (move) branch, but the current
    /// transaction was opened below `TxConfig::serializable()`. No writes
    /// were made in this attempt.
    NeedsSerializable,
}

// @cpt-dod:cpt-cf-resource-group-dod-entity-hier-entity-service:p1
// @cpt-dod:cpt-cf-resource-group-dod-integration-auth-tenant-scope:p1
// @cpt-dod:cpt-cf-resource-group-dod-integration-auth-jwt:p1
// @cpt-flow:cpt-cf-resource-group-flow-integration-auth-jwt-request:p1
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

    // @cpt-flow:cpt-cf-resource-group-flow-entity-hier-create-group:p1
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
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-1
        // Pre-validation (stateless, outside transaction)
        validation::validate_type_code(&req.code)?;
        Self::validate_name(&req.name)?;

        // Derive `is_tenant` for AuthZ properties from the code prefix: any type
        // whose path starts with `TENANT_RG_TYPE_PATH` opens a new tenant scope.
        let is_tenant = req.code.starts_with(TENANT_RG_TYPE_PATH);

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
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-1

        // Validate metadata against the GTS type schema before opening the
        // transaction: a cross-gear `ClientHub` call with nothing to gain in-tx (RG-09).
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5b
        validation::validate_metadata_via_gts(
            req.metadata.as_ref(),
            &req.code,
            &*self.types_registry,
        )
        .await?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5b

        let profile = self.profile.clone();
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-2
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-10
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-9
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-11
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
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-11
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-9
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-10
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-2
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

    // @cpt-algo:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1
    /// List resource groups with `OData` filtering and pagination (AuthZ-scoped).
    pub async fn list_groups(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroup>, DomainError> {
        // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3
        // IF request has JWT bearer token — the SecurityContext arrives here
        // already authenticated by the API Gateway / AuthNResolverClient.
        // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3a
        // Authenticate via AuthNResolverClient → SecurityContext (performed
        // upstream by the API Gateway; `ctx` carries the resulting subject).
        // @cpt-end:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3a
        // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3b
        // Run PolicyEnforcer.access_scope() → AccessScope
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "list", None)
            .await
            .map_err(DomainError::from)?;
        // @cpt-end:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3b
        // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3c
        // RETURN JWT mode with SecurityContext + AccessScope (the AccessScope
        // is propagated to the data layer below).
        let conn = self.db.conn()?;
        self.group_repo.list_groups(&conn, &scope, query).await
        // @cpt-end:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3c
        // @cpt-end:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-3
        // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-4
        // ELSE → RETURN 401 Unauthorized (handled upstream by the API Gateway
        // before SecurityContext is constructed; an absent/invalid JWT never
        // reaches this service path).
        // @cpt-end:cpt-cf-resource-group-algo-integration-auth-auth-mode-decision:p1:inst-auth-decide-4
    }

    // @cpt-flow:cpt-cf-resource-group-flow-entity-hier-update-group:p1
    /// Update a resource group (full replacement via PUT, AuthZ-scoped).
    ///
    /// Runs inside a transaction with bounded retry (max 3 attempts). The
    /// isolation level is chosen per-request, not hard-coded to
    /// `SERIALIZABLE`: see the comment on `guessed_parent_changed` below for
    /// the rationale and for how the race between that pre-transaction hint
    /// and the transaction's own fresh read is closed.
    pub async fn update_group(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        req: UpdateGroupRequest,
    ) -> Result<ResourceGroup, DomainError> {
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-1
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
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-1

        // Validate metadata against the GTS type schema before opening the
        // transaction: same rationale as `create_group` (RG-09). The same
        // read also gives us the group's current `parent_id`, reused below
        // to pick the transaction's isolation level -- no extra query for
        // that. `conn` is scoped to this block so the pool connection is
        // released before the transaction (below) requests its own.
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4e
        let existing = {
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
            existing
        };
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4e

        // Pick the least-strict isolation level that stays correct for this
        // update. Per the DB-behavior audit
        // (`rg-db-audit-transactions.md`, recommendation #3): write-skew
        // (cycle detection racing a concurrent create/move; closure-table
        // rebuild) is only reachable on `update_group_inner`'s parent-change
        // branch (`move_group_internal_impl`). A pure rename/metadata edit
        // touches a single row by primary key and has no cross-row
        // predicate to protect, so it needs nothing stronger than the
        // backend default (`TxConfig::default()` -- READ COMMITTED on
        // PostgreSQL; SQLite always runs SERIALIZABLE regardless, per
        // `TxIsolationLevel`'s backend notes, so this is a PostgreSQL-only
        // saving).
        //
        // This is only a *hint*, computed from the `existing` read above,
        // taken *before* the transaction opens -- it can go stale if a
        // concurrent request changes this group's parent in the window
        // between that read and the transaction start. The authoritative
        // decision is always the fresh, in-transaction read
        // (`update_group_inner`'s own `find_model_by_id`); closing that gap
        // is `attempt_update_group`/`UpdateGroupOutcome`'s job (see their
        // doc comments): if the fresh read disagrees with this hint in the
        // *dangerous* direction (hint said "no move", the fresh read says
        // otherwise), `update_group_inner` bails out with
        // `NeedsSerializable` *before writing anything*, and the retry
        // below reruns the whole operation under
        // `TxConfig::serializable()`. A hint that overshoots (guesses "move"
        // when no move is actually needed) is harmless: SERIALIZABLE is
        // always a safe superset of READ COMMITTED's guarantees for the
        // rename path too, so no downgrade path is needed or attempted.
        let guessed_parent_changed = existing.hierarchy.parent_id != req.parent_id;
        let tx_config = if guessed_parent_changed {
            TxConfig::serializable()
        } else {
            TxConfig::default()
        };

        let profile = self.profile.clone();
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();

        let outcome = Self::attempt_update_group(
            &db,
            tx_config,
            guessed_parent_changed,
            &group_repo,
            &type_repo,
            &scope,
            group_id,
            &req,
            &profile,
        )
        .await?;

        match outcome {
            UpdateGroupOutcome::Done(group) => Ok(group),
            UpdateGroupOutcome::NeedsSerializable => {
                debug!(
                    group_id = %group_id,
                    "update_group: parent-change hint was stale (a concurrent request moved \
                     this group); retrying the whole operation under SERIALIZABLE"
                );
                match Self::attempt_update_group(
                    &db,
                    TxConfig::serializable(),
                    true,
                    &group_repo,
                    &type_repo,
                    &scope,
                    group_id,
                    &req,
                    &profile,
                )
                .await?
                {
                    UpdateGroupOutcome::Done(group) => Ok(group),
                    UpdateGroupOutcome::NeedsSerializable => Err(DomainError::database(
                        "update_group_inner requested a SERIALIZABLE retry while already \
                         running under SERIALIZABLE -- this should be unreachable",
                    )),
                }
            }
        }
    }

    /// Runs one attempt of `update_group_inner` inside a transaction
    /// configured per `tx_config`/`serializable`.
    ///
    /// Factored out so `update_group` can call it twice: once optimistically
    /// (possibly at a weaker-than-`SERIALIZABLE` isolation, for a same-parent
    /// update), and, only if that attempt reports
    /// `UpdateGroupOutcome::NeedsSerializable`, once more forcing
    /// `TxConfig::serializable()`. `serializable` must accurately describe
    /// whether `tx_config` is `TxConfig::serializable()` -- it is threaded
    /// through to `update_group_inner`'s own race-closing check, not
    /// re-derived from `tx_config` there.
    #[allow(clippy::too_many_arguments)]
    async fn attempt_update_group(
        db: &Db,
        tx_config: TxConfig,
        serializable: bool,
        group_repo: &Arc<GR>,
        type_repo: &Arc<TR>,
        scope: &toolkit_security::AccessScope,
        group_id: Uuid,
        req: &UpdateGroupRequest,
        profile: &QueryProfile,
    ) -> Result<UpdateGroupOutcome, DomainError> {
        db.transaction_with_retry(tx_config, DomainError::db_err, |tx| {
            let req = req.clone();
            let scope = scope.clone();
            let profile = profile.clone();
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            Box::pin(async move {
                Self::update_group_inner(
                    &*group_repo,
                    &*type_repo,
                    tx,
                    &scope,
                    group_id,
                    &req,
                    &profile,
                    serializable,
                )
                .await
            })
        })
        .await
    }

    // @cpt-flow:cpt-cf-resource-group-flow-entity-hier-move-group:p1
    /// Move a group to a new parent (or make it a root).
    ///
    /// Runs inside a `SERIALIZABLE` transaction with bounded retry (max 3 attempts)
    /// to ensure cycle detection, invariant checks, and closure table rebuild are atomic.
    pub async fn move_group(
        &self,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
    ) -> Result<ResourceGroup, DomainError> {
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-1
        // Actor sends PUT /api/resource-group/v1/groups/{group_id} with new hierarchy.parent_id
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-1
        let profile = self.profile.clone();
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-2
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-12
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-11
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-13
        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let profile = profile.clone();
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            Box::pin(async move {
                Self::move_group_inner(
                    &*group_repo,
                    &*type_repo,
                    tx,
                    group_id,
                    new_parent_id,
                    &profile,
                )
                .await
            })
        })
        .await
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-13
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-11
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-12
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-2
    }

    // @cpt-flow:cpt-cf-resource-group-flow-entity-hier-delete-group:p1
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
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-1
        // Actor sends DELETE /api/resource-group/v1/groups/{group_id}?force={true|false}
        // AuthZ gate: verify the caller can delete this group (tenant check).
        // Runs outside the transaction since AuthZ is idempotent.
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_GROUP_RESOURCE, "delete", Some(group_id))
            .await
            .map_err(DomainError::from)?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-1

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
        validation::validate_type_code(&req.code)?;
        Self::validate_name(&req.name)?;

        let is_tenant = req.code.starts_with(TENANT_RG_TYPE_PATH);
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
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-3
        // Resolve type GTS path to surrogate ID; verify type exists.
        // find_by_code_with_id fetches id + type together in one query (RG-11).
        let (type_id, rg_type) = type_repo
            .find_by_code_with_id(tx, &req.code)
            .await?
            .ok_or_else(|| DomainError::type_not_found(&req.code))?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-3

        // Determine effective tenant_id by code-prefix rule:
        // - code starts with TENANT_RG_TYPE_PATH → tenant_id = group.id (new scope)
        // - otherwise                           → tenant_id from caller / parent
        let group_id = req.id.unwrap_or_else(Uuid::now_v7);
        let is_tenant_type = req.code.starts_with(TENANT_RG_TYPE_PATH);
        let effective_tenant_id = if is_tenant_type { group_id } else { tenant_id };

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4
        if let Some(parent_id) = req.parent_id {
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4a
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4b
            let parent = group_repo
                .find_model_by_id(tx, parent_id)
                .await?
                .ok_or_else(|| DomainError::group_not_found(parent_id))?;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4b
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4a

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4c
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4d
            let parent_type_path = Self::resolve_type_path_from_id(tx, parent.gts_type_id).await?;
            if !rg_type.allowed_parent_types.contains(&parent_type_path) {
                return Err(DomainError::invalid_parent_type(format!(
                    "Type '{}' does not allow parent type '{}'",
                    req.code, parent_type_path
                )));
            }
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4d
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4c

            // @cpt-algo:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1
            // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-1
            // Extract caller effective tenant scope from SecurityContext.subject_tenant_id
            // (tenant_id is passed as parameter from caller's context)
            // @cpt-end:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-1
            // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-2
            // IF caller is privileged platform-admin -> pass (but data invariants still checked)
            // (platform-admin bypass handled by middleware; data invariants enforced below)
            // @cpt-end:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-2
            // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-3
            // Validate tenant compatibility (child must be same tenant as parent)
            // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-4
            // IF membership write: validate target group's tenant_id is compatible
            // @cpt-end:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-4
            // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-5
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
            // @cpt-end:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-5
            // @cpt-end:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-3
            // @cpt-begin:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-6
            // RETURN pass (tenant enforcement passed)
            // @cpt-end:cpt-cf-resource-group-algo-integration-auth-tenant-scope-enforcement:p1:inst-tenant-enforce-6

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4e
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
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4e

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4f
            // Check query profile: width limit
            if let Some(max_width) = profile.max_width {
                let sibling_count = group_repo.count_children(tx, parent_id).await?;
                if sibling_count >= u64::from(max_width) {
                    return Err(DomainError::limit_violation(format!(
                        "Width limit exceeded: parent already has {sibling_count} children, max_width is {max_width}"
                    )));
                }
            }
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4f
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-4

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-6
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
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-6

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-7
            // Insert closure: self-row
            group_repo.insert_closure_self_row(tx, group_id).await?;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-7

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-8
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-8a
            // Insert ancestor closure rows from parent's ancestors with depth+1
            group_repo
                .insert_ancestor_closure_rows(tx, group_id, parent_id)
                .await?;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-8a
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-8

            let sys = toolkit_security::AccessScope::allow_all();
            group_repo
                .find_by_id(tx, &sys, group_id)
                .await?
                .ok_or_else(|| DomainError::database("Insert succeeded but group not found"))
        } else {
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5a
            // Root group: validate can_be_root
            if !rg_type.can_be_root {
                return Err(DomainError::invalid_parent_type(format!(
                    "Type '{}' cannot be a root group (can_be_root=false)",
                    req.code
                )));
            }
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5a

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5c
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
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5c
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-create-group:p1:inst-create-group-5

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
    /// `attempt_update_group` -- `SERIALIZABLE` when `serializable` is
    /// `true`, otherwise `update_group`'s weaker default.
    ///
    /// **Isolation-mismatch guard (`serializable` parameter).** `serializable`
    /// must describe the isolation level of the transaction `tx` is running
    /// in (set by the caller, `attempt_update_group`) -- it is not derived
    /// from `tx` itself, since `TxConfig` is not recoverable from an open
    /// connection. It exists purely to let this function detect, from the
    /// fresh `existing.parent_id` read just below, that a parent change is
    /// actually required while running below `SERIALIZABLE` (the
    /// pre-transaction hint in `update_group` was stale) and bail out via
    /// `UpdateGroupOutcome::NeedsSerializable` before touching a single row.
    /// See `update_group`'s isolation comment for the full rationale.
    ///
    /// **Type immutability.** A group's GTS type is fixed at creation —
    /// `UpdateGroupRequest` does not carry a `code` field. The existing
    /// `gts_type_id` is reused unchanged for the persisted update, so all
    /// type-driven validation (allowed parents/children, tenant-root rule,
    /// metadata schema lookup) is anchored on the existing type, not on a
    /// caller-supplied one.
    ///
    /// **Tenant immutability.** A group's `tenant_id` is also fixed at
    /// creation. Reparenting is therefore allowed only **within the same
    /// tenant** — the new parent's `tenant_id` must equal the group's
    /// `existing.tenant_id`, otherwise the move is rejected with the same
    /// rule `create_group_inner` uses for non-tenant children. Tenant-type
    /// roots already have `tenant_id = group_id`, so the same equality check
    /// trivially holds for them as well.
    ///
    /// **Metadata schema validation.** `update_group` already ran
    /// `validate_metadata_via_gts` before opening this transaction (RG-09);
    /// see `create_group_inner`'s doc comment for why.
    #[allow(clippy::too_many_arguments)]
    async fn update_group_inner(
        group_repo: &GR,
        type_repo: &TR,
        tx: &impl DBRunner,
        scope: &toolkit_security::AccessScope,
        group_id: Uuid,
        req: &UpdateGroupRequest,
        profile: &QueryProfile,
        serializable: bool,
    ) -> Result<UpdateGroupOutcome, DomainError> {
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-2
        // DB: SELECT FROM resource_group WHERE id = {group_id} -- load existing group
        group_repo
            .find_by_id(tx, scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        let existing = group_repo
            .find_model_by_id(tx, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-2

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-3
        // IF group not found -> RETURN NotFound (handled by ok_or_else above)
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-3

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4
        // IF type is changed — `UpdateGroupRequest` deliberately does not carry
        // a `code` field, so `gts_type_id` is reused unchanged below. The
        // structural-change validation that would run on a type change is
        // therefore enforced via the parent-change branch (move semantics)
        // and the closure-table compatibility checks performed by
        // `move_group_internal_impl`. The 4a/4b/4c/4d sub-steps are realized
        // by that helper and the metadata validation block right below.
        // Type is immutable on update — reuse the existing `gts_type_id` and
        // resolve the type definition for `move_group_internal_impl`'s
        // parent-compatibility check below.
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4a
        // Validate new type's allowed_parents permits current parent's type
        // (or the new type allows root if no parent). For the immutable-type
        // case this collapses into `move_group_internal_impl` running the
        // `rg_type.allowed_parent_types` check on a parent change.
        //
        // load_full_type_by_id fetches the type definition by id in a
        // single query, not a separate resolve-then-find-by-code round trip (RG-11).
        let rg_type = type_repo
            .load_full_type_by_id(tx, existing.gts_type_id)
            .await?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4a

        // Metadata-vs-schema validation (step 4e) already ran in
        // `update_group`, before this transaction opened -- see this
        // function's doc comment (RG-09 fix).

        // Cross-tenant parent change is forbidden. `tenant_id` is established
        // at creation and never rewritten — see the function-level doc above
        // for the invariant. Mirror `create_group_inner`'s tenant-scope
        // enforcement for non-tenant children. (Tenant-type roots have
        // `tenant_id == group_id` by construction; reparenting one under a
        // different parent is also rejected here because the equality check
        // would fail.)
        if let Some(new_parent_id) = req.parent_id
            && new_parent_id != existing.parent_id.unwrap_or_default()
        {
            let new_parent = group_repo
                .find_model_by_id(tx, new_parent_id)
                .await?
                .ok_or_else(|| DomainError::group_not_found(new_parent_id))?;
            if new_parent.tenant_id != existing.tenant_id {
                // Generic message: do not interpolate tenant ids — the caller
                // can't act on them legitimately, and disclosing the foreign
                // tenant_id would leak ownership of `new_parent_id` across the
                // tenant boundary.
                return Err(DomainError::validation(format!(
                    "Cannot move group {group_id} to a parent in a different tenant; \
                     cross-tenant moves are not supported"
                )));
            }
        }

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4b
        // DB: SELECT gts_type_id FROM resource_group WHERE parent_id = {group_id}
        // — load children types (performed inside `move_group_internal_impl`'s
        // closure-table queries when a parent change occurs; type itself is
        // immutable here so a type-driven children rescan is unnecessary).
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4c
        // FOR EACH child: verify child's type includes new type in
        // allowed_parents (no-op for immutable-type updates; the move helper
        // runs the equivalent allowed_parent_types check against the new
        // parent on a parent change).
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4d
        // IF any child would become invalid → RETURN InvalidParentType with
        // child details (returned by `move_group_internal_impl` as
        // `DomainError::invalid_parent_type` when the parent's type is not in
        // the moved subtree's `allowed_parent_types`).
        let parent_changed = existing.parent_id != req.parent_id;

        // Race-closing guard (see this function's and `update_group`'s doc
        // comments): `existing` above is a fresh, authoritative in-tx read,
        // so `parent_changed` is always correct. What can be stale is the
        // transaction's *isolation level*, chosen from a cheaper
        // pre-transaction read in `update_group`. If a parent change is
        // genuinely required (`parent_changed`) but this transaction is not
        // running under SERIALIZABLE, the move branch below (cycle
        // detection racing a concurrent create/move, closure-table rebuild)
        // must not proceed here -- bail out with no writes made yet (every
        // statement above this point is a read) so `update_group` can redo
        // the whole operation under `TxConfig::serializable()`.
        if parent_changed && !serializable {
            debug!(
                group_id = %group_id,
                "update_group_inner: parent-change hint was stale under a non-serializable \
                 transaction; requesting a SERIALIZABLE retry"
            );
            return Ok(UpdateGroupOutcome::NeedsSerializable);
        }

        if parent_changed {
            // Delegate to move logic (cycle detection + closure rebuild).
            // Type stays the same, so use the resolved `rg_type` for parent
            // compatibility checks inside the move helper.
            Self::move_group_internal_impl(
                group_repo,
                tx,
                group_id,
                req.parent_id,
                &rg_type,
                profile,
            )
            .await?;
        }
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4d
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4c
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4b
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-4

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-5
        // Persist name/parent/metadata. `gts_type_id` is reused from the
        // existing row — type is immutable on update.
        let _model = group_repo
            .update(
                tx,
                group_id,
                req.parent_id,
                existing.gts_type_id,
                &req.name,
                req.metadata.as_ref(),
            )
            .await?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-5

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-6
        let sys = toolkit_security::AccessScope::allow_all();
        let updated = group_repo
            .find_by_id(tx, &sys, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;
        Ok(UpdateGroupOutcome::Done(updated))
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-update-group:p1:inst-update-group-6
    }

    /// Inner logic for `move_group`, runs inside a SERIALIZABLE transaction.
    async fn move_group_inner(
        group_repo: &GR,
        type_repo: &TR,
        tx: &impl DBRunner,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
        profile: &QueryProfile,
    ) -> Result<ResourceGroup, DomainError> {
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-3
        // Load group and new parent in transaction
        let existing = group_repo
            .find_model_by_id(tx, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        let type_path = Self::resolve_type_path_from_id(tx, existing.gts_type_id).await?;
        let rg_type = type_repo
            .find_by_code(tx, &type_path)
            .await?
            .ok_or_else(|| DomainError::type_not_found(&type_path))?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-3

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-4
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-5
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-6
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-7
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-8
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-9
        // Cycle detect, type compat, profile enforce, closure rebuild
        Self::move_group_internal_impl(group_repo, tx, group_id, new_parent_id, &rg_type, profile)
            .await?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-9
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-8
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-7
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-6
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-5
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-4

        // Cross-tenant moves are forbidden (`tenant_id` is immutable per the
        // gear-wide invariant). Reject the move when the new parent lives
        // in a different tenant than the moved group; tenant-type roots have
        // `tenant_id == group_id`, so the equality check covers them too.
        if let Some(new_parent_id) = new_parent_id {
            let new_parent = group_repo
                .find_model_by_id(tx, new_parent_id)
                .await?
                .ok_or_else(|| DomainError::group_not_found(new_parent_id))?;
            if new_parent.tenant_id != existing.tenant_id {
                // Generic message: do not interpolate tenant ids — the caller
                // can't act on them legitimately, and disclosing the foreign
                // tenant_id would leak ownership of `new_parent_id` across the
                // tenant boundary.
                return Err(DomainError::validation(format!(
                    "Cannot move group {group_id} to a parent in a different tenant; \
                     cross-tenant moves are not supported"
                )));
            }
        }

        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-10
        // Update parent_id on the group. Type and tenant_id are immutable —
        // both reuse the existing row's values.
        group_repo
            .update(
                tx,
                group_id,
                new_parent_id,
                existing.gts_type_id,
                &existing.name,
                existing.metadata.as_ref(),
            )
            .await?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-move-group:p1:inst-move-group-10

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
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-2
        // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-3
        // DB: SELECT FROM resource_group WHERE id = {group_id}
        group_repo
            .find_by_id(tx, scope, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;

        let _existing = group_repo
            .find_model_by_id(tx, group_id)
            .await?
            .ok_or_else(|| DomainError::group_not_found(group_id))?;
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-3
        // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-2

        if force {
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5a
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5b
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5c
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5d
            // Force delete: cascade entire subtree + memberships + closure
            #[allow(clippy::let_and_return)]
            let result = Self::force_delete_subtree(group_repo, tx, group_id).await;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5d
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5c
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5b
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5a
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-5
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-7
            result
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-7
        } else {
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4
            // Non-force: check children and memberships
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4a
            let children = Self::get_direct_children(tx, group_id).await?;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4a
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4b
            let has_memberships = group_repo.has_memberships(tx, group_id).await?;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4b
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4c
            if !children.is_empty() {
                return Err(DomainError::conflict_active_references(format!(
                    "Cannot delete group '{group_id}': has {} child group(s). Use force=true to cascade.",
                    children.len()
                )));
            }

            if has_memberships {
                return Err(DomainError::conflict_active_references(format!(
                    "Cannot delete group '{group_id}': has active memberships. Use force=true to cascade."
                )));
            }
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4c
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-4

            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-6
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-6a
            // Delete closure rows, then the group
            group_repo.delete_all_closure_rows(tx, group_id).await?;
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-6a
            // @cpt-begin:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-6b
            group_repo.delete_by_id(tx, group_id).await
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-6b
            // @cpt-end:cpt-cf-resource-group-flow-entity-hier-delete-group:p1:inst-delete-group-6
        }
    }

    // -- Internal helpers --

    // @cpt-algo:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1
    // @cpt-algo:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1
    /// Internal move logic shared between `move_group` and `update_group`.
    ///
    /// Performs cycle detection, type compatibility checks, query profile
    /// enforcement, and closure table rebuild. Must be called within a
    /// SERIALIZABLE transaction.
    #[allow(clippy::cognitive_complexity)]
    async fn move_group_internal_impl(
        group_repo: &GR,
        conn: &impl DBRunner,
        group_id: Uuid,
        new_parent_id: Option<Uuid>,
        rg_type: &resource_group_sdk::ResourceGroupType,
        profile: &QueryProfile,
    ) -> Result<(), DomainError> {
        if let Some(new_pid) = new_parent_id {
            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-1
            // Cycle detection: self-parent check (covered by is_descendant via self-row)
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-1
            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-2
            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-3
            let is_desc = group_repo.is_descendant(conn, group_id, new_pid).await?;
            if is_desc {
                debug!(group_id = %group_id, new_parent = %new_pid, "Cycle detected in move_group");
                return Err(DomainError::cycle_detected(format!(
                    "Cannot move group '{group_id}' under '{new_pid}': would create a cycle"
                )));
            }
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-3
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-2

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

            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-4
            // Cycle detection passed
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-cycle-detect:p1:inst-cycle-4

            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-1
            // Load profile config: max_depth (optional), max_width (optional)
            // (profile is passed as parameter with max_depth and max_width)
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-1

            // Check query profile: depth limit
            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-2
            if let Some(max_depth) = profile.max_depth {
                // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-2a
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
                // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-2a
                // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-2b
                #[allow(clippy::cast_possible_wrap)]
                if new_deepest >= max_depth as i32 {
                    debug!(group_id = %group_id, new_deepest, max_depth, "Depth limit exceeded on move");
                    return Err(DomainError::limit_violation(format!(
                        "Depth limit exceeded: moving subtree would create depth {new_deepest}, max_depth is {max_depth}"
                    )));
                }
                // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-2b
            }
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-2

            // Check query profile: width limit
            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-3
            if let Some(max_width) = profile.max_width {
                // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-3a
                let sibling_count = group_repo.count_children(conn, new_pid).await?;
                // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-3a
                // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-3b
                if sibling_count >= u64::from(max_width) {
                    return Err(DomainError::limit_violation(format!(
                        "Width limit exceeded: new parent already has {sibling_count} children, max_width is {max_width}"
                    )));
                }
                // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-3b
            }
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-3
            // @cpt-begin:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-4
            // Profile checks passed
            // @cpt-end:cpt-cf-resource-group-algo-entity-hier-enforce-query-profile:p1:inst-profile-4
        } else {
            // Moving to root: validate can_be_root + tenant-root uniqueness.
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
            if rg_type.code.starts_with(TENANT_RG_TYPE_PATH)
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
// @cpt-end:cpt-cf-resource-group-dod-entity-hier-entity-service:p1:inst-full
