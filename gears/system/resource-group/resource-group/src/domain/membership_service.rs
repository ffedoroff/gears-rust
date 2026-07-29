// Created: 2026-04-16 by Constructor Tech
//! Domain service for resource group membership management.
//!
//! Implements business rules for adding, removing, and listing memberships
//! between resources and groups. Delegates persistence to the infra layer.

use std::sync::Arc;

use authz_resolver_sdk::pep::{PolicyEnforcer, ResourceType};
use resource_group_sdk::{GROUP_MEMBERSHIP_RESOURCE_TYPE, models::ResourceGroupMembership};
use toolkit_db::secure::{DBRunner, TxConfig};
use toolkit_odata::{ODataQuery, Page};
use toolkit_security::{AccessScope, SecurityContext, pep_properties};
use uuid::Uuid;

use tracing::debug;

use crate::domain::DbProvider;
use crate::domain::error::DomainError;
use crate::domain::repo::{GroupRepositoryTrait, MembershipRepositoryTrait, TypeRepositoryTrait};

/// `AuthZ` resource type descriptor for group memberships.
///
/// `supported_properties` deliberately lists only `owner_tenant_id`.
///
/// # VHP-2341: scope source for the group tenant-gate
///
/// `add_membership_in_tx` / `remove_membership_in_tx` / `list_memberships`
/// all need to know whether the *target group* is inside the caller's
/// tenant scope, but the group itself is never re-fetched from the PDP —
/// the `AccessScope` obtained here (for the membership action) is reused
/// directly against `resource_group`. Two options existed:
///
/// (a) **Reuse this scope** (chosen). Cheap — one PDP round trip per
///     operation, same as before this fix.
/// (b) Issue a second `access_scope(..., RG_GROUP_RESOURCE, "get"/"list", ...)`
///     call, mirroring `group_service.rs`. Costs an extra PDP call per
///     membership operation.
///
/// (a) is safe only because `authz-resolver-sdk`'s PEP compiler
/// (`compiler.rs::compile_constraint`) *rejects* any constraint whose
/// property is not in `ResourceType.supported_properties` (fails that
/// constraint closed; see `compiler_tests.rs::supported_properties_validation`).
/// Since this descriptor supports only `owner_tenant_id`, the `AccessScope`
/// returned by `enforcer.access_scope(.., &RG_MEMBERSHIP_RESOURCE, ..)` can
/// **only** ever be: unconstrained, deny-all, or built exclusively from
/// filters keyed `"owner_tenant_id"` — never `resource_id` (that property
/// isn't declared here, so the SDK would reject it before it reaches this
/// code). That rules out the failure mode variant (a) would otherwise risk:
/// a `resource_id` constraint compiled against `resource_group` would
/// resolve to the *group's* id column, which is a different (and wrong)
/// resource than the membership check intends. Because `resource_group`
/// declares `tenant_col = "tenant_id"` (see `resource_group.rs`), every
/// filter that *can* appear in this scope resolves correctly against it via
/// `resolve_property("owner_tenant_id") -> Column::TenantId`. Variant (b)
/// would be strictly safer against a future widening of
/// `supported_properties` on this descriptor, but at the cost of a PDP call
/// on every add/remove/list; (a) is preferred while the descriptor's
/// property list stays narrow — re-evaluate if it ever grows.
pub const RG_MEMBERSHIP_RESOURCE: ResourceType = ResourceType::from_static(
    GROUP_MEMBERSHIP_RESOURCE_TYPE,
    &[pep_properties::OWNER_TENANT_ID],
);

/// Service for resource group membership lifecycle management.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Clone)]
pub struct MembershipService<
    GR: GroupRepositoryTrait,
    TR: TypeRepositoryTrait,
    MR: MembershipRepositoryTrait,
> {
    db: Arc<DbProvider>,
    enforcer: PolicyEnforcer,
    group_repo: Arc<GR>,
    type_repo: Arc<TR>,
    membership_repo: Arc<MR>,
}

impl<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait, MR: MembershipRepositoryTrait>
    MembershipService<GR, TR, MR>
{
    /// Create a new `MembershipService` with the given database provider
    /// and `PolicyEnforcer` for AuthZ-scoped queries.
    #[must_use]
    pub fn new(
        db: Arc<DbProvider>,
        enforcer: PolicyEnforcer,
        group_repo: Arc<GR>,
        type_repo: Arc<TR>,
        membership_repo: Arc<MR>,
    ) -> Self {
        Self {
            db,
            enforcer,
            group_repo,
            type_repo,
            membership_repo,
        }
    }

    fn conn(&self) -> Result<impl toolkit_db::secure::DBRunner + '_, DomainError> {
        self.db
            .conn()
            .map_err(|e| DomainError::database(e.to_string()))
    }

    /// Add a membership link between a resource and a group.
    ///
    /// Validates group existence, `resource_type` registration, `allowed_membership_types`
    /// compatibility, and tenant scope before inserting the membership row.
    pub async fn add_membership(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<ResourceGroupMembership, DomainError> {
        // Validate resource_type is a valid GtsTypePath (validated implicitly by resolve)

        // AuthZ gate: verify the caller can create memberships
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_MEMBERSHIP_RESOURCE, "create", None)
            .await
            .map_err(DomainError::from)?;

        self.add_membership_inner(&scope, group_id, resource_type, resource_id)
            .await
    }

    /// Add a membership link without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler. Used by
    /// the membership seeding adapter (which runs at gear init, before
    /// any caller `SecurityContext` exists). Domain invariants
    /// (group existence, type registration, `allowed_membership_types`
    /// compatibility, tenant scope) still run; only the `PolicyEnforcer`
    /// gate is skipped.
    pub async fn add_membership_unscoped(
        &self,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<ResourceGroupMembership, DomainError> {
        let scope = AccessScope::allow_all();
        self.add_membership_inner(&scope, group_id, resource_type, resource_id)
            .await
    }

    /// Shared post-authz body of `add_membership` / `add_membership_unscoped`.
    ///
    /// Runs inside a `SERIALIZABLE` transaction with bounded retry (RG-01):
    /// two concurrent "first membership" adds for the same resource in
    /// different tenants are write-skew (both read an empty tenants set).
    ///
    /// `PostgreSQL` aborts one, and the retry sees the winner's committed
    /// membership and returns `TenantIncompatibility` instead of a raw failure.
    ///
    /// `scope` gates the target group against the caller's `AccessScope`
    /// (VHP-2341) — see `add_membership_in_tx`. `add_membership_unscoped`
    /// passes `AccessScope::allow_all()` so seeding/internal callers keep
    /// seeing every tenant, matching its pre-existing contract.
    async fn add_membership_inner(
        &self,
        scope: &AccessScope,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<ResourceGroupMembership, DomainError> {
        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();
        let membership_repo = self.membership_repo.clone();
        let resource_type = resource_type.to_owned();
        let resource_id = resource_id.to_owned();
        let scope = scope.clone();

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            let membership_repo = membership_repo.clone();
            let resource_type = resource_type.clone();
            let resource_id = resource_id.clone();
            let scope = scope.clone();
            Box::pin(async move {
                Self::add_membership_in_tx(
                    &*group_repo,
                    &*type_repo,
                    &*membership_repo,
                    tx,
                    &scope,
                    group_id,
                    &resource_type,
                    &resource_id,
                )
                .await
            })
        })
        .await
    }

    /// Inner logic for `add_membership_inner`, runs inside the SERIALIZABLE
    /// transaction.
    #[allow(clippy::too_many_arguments)]
    async fn add_membership_in_tx(
        group_repo: &GR,
        type_repo: &TR,
        membership_repo: &MR,
        tx: &impl DBRunner,
        scope: &AccessScope,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<ResourceGroupMembership, DomainError> {
        // AuthZ gate (VHP-2341) + raw model read, in one query
        // (N+1 audit finding (a)): the target group must be inside the
        // caller's scope before its raw model is used below, but the gate
        // doesn't need a resolved SDK model (with its type path), only the
        // raw row -- which is exactly what the rest of this function needs
        // anyway. `find_model_by_id_scoped` is `find_by_id`'s query
        // (`SELECT resource_group ... AND` the scope's tenant condition)
        // without the unconditional `resolve_type_path` follow-up, so a
        // group belonging to another tenant still resolves to `None` here
        // (-> `GroupNotFound`, identical to a group that doesn't exist at
        // all, never a distinguishable "forbidden") -- but the previous
        // separate `find_by_id` (gate) + `find_model_by_id` (raw read) pair
        // collapses into this single call. Runs inside this transaction
        // (not before it), per VHP-2341's requirement that the gate share
        // the SERIALIZABLE isolation the rest of the check sees.
        let group_model = group_repo
            .find_model_by_id_scoped(tx, scope, group_id)
            .await?
            .ok_or(DomainError::GroupNotFound { id: group_id })?;

        // Resolve the GTS type path to a surrogate SMALLINT ID
        let gts_type_id = type_repo
            .resolve_id(tx, resource_type)
            .await?
            .ok_or_else(|| {
                DomainError::validation(format!("Unknown resource type: {resource_type}"))
            })?;

        // Load group type's allowed_membership_types and validate
        let allowed = type_repo
            .load_full_type_by_id(tx, group_model.gts_type_id)
            .await?;

        if !allowed
            .allowed_membership_types
            .iter()
            .any(|m| m == resource_type)
        {
            return Err(DomainError::validation(format!(
                "Resource type '{resource_type}' is not in allowed_membership_types for group type '{}'",
                allowed.code
            )));
        }

        // Tenant compatibility: check existing memberships for this resource
        let existing_tenants = membership_repo
            .get_existing_membership_tenant_ids(tx, gts_type_id, resource_id)
            .await?;

        // IF no existing memberships → pass (first membership, any tenant allowed)

        // Collect distinct tenant_ids from existing memberships (existing_tenants)

        if !existing_tenants.is_empty() && !existing_tenants.contains(&group_model.tenant_id) {
            debug!(
                group_id = %group_id,
                resource_type = %resource_type,
                resource_id = %resource_id,
                "Tenant incompatibility on membership add"
            );
            return Err(DomainError::tenant_incompatibility(format!(
                "Resource ({resource_type}, {resource_id}) is already linked in tenant {:?}, cannot add to tenant {}",
                existing_tenants, group_model.tenant_id
            )));
        }

        // Insert the membership (repo handles duplicate detection)
        let model = membership_repo
            .insert(tx, group_id, gts_type_id, resource_id)
            .await?;

        // Resolve back to GTS path for the SDK model
        Ok(ResourceGroupMembership {
            group_id: model.group_id,
            resource_type: resource_type.to_owned(),
            resource_id: model.resource_id,
        })
    }

    /// Remove a membership link.
    ///
    /// Resolves the GTS type path, verifies the membership exists, and deletes it.
    ///
    /// Runs inside a transaction with bounded retry (`TxConfig::default()`,
    /// not `SERIALIZABLE`). The delete targets the exact composite primary
    /// key `(group_id, gts_type_id, resource_id)` -- there is no predicate
    /// whose result set a concurrent writer could change out from under this
    /// transaction (contrast `add_membership_in_tx`'s RG-01 check on
    /// "existing tenants for this resource", a genuine write-skew hazard).
    /// The base PR's commit introducing this transaction (`ab073c7a`)
    /// documented `SERIALIZABLE` here as "for symmetry" with `add_membership`,
    /// not as a correctness requirement; the DB-behavior audit
    /// (`rg-db-audit-transactions.md`, finding #7 / recommendation #2)
    /// confirmed write-skew is impossible on a delete-by-primary-key and
    /// recommended the downgrade. Bounded retry is kept (not dropped) because
    /// a real deadlock (`40P01`) is still possible between two transactions
    /// taking row locks in different orders, independent of isolation level;
    /// `is_retryable_contention` already treats `40001`/`40P01` alike, so
    /// this still retries a genuine deadlock exactly as before, just without
    /// paying for SSI predicate tracking on every call. The tenant gate
    /// (`find_model_by_id_scoped`, "foreign tenant -> `GroupNotFound`") and
    /// its semantics are unchanged.
    pub async fn remove_membership(
        &self,
        ctx: &SecurityContext,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), DomainError> {
        // Actor sends DELETE /api/resource-group/v1/memberships/{group_id}/{resource_type}/{resource_id}
        // AuthZ gate: verify the caller can delete memberships
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_MEMBERSHIP_RESOURCE, "delete", None)
            .await
            .map_err(DomainError::from)?;

        let db = self.db.db();
        let group_repo = self.group_repo.clone();
        let type_repo = self.type_repo.clone();
        let membership_repo = self.membership_repo.clone();
        let resource_type = resource_type.to_owned();
        let resource_id = resource_id.to_owned();

        // TxConfig::default() (not ::serializable()) -- see this method's
        // doc comment for why a delete-by-primary-key does not need SSI.
        db.transaction_with_retry(TxConfig::default(), DomainError::db_err, |tx| {
            let group_repo = group_repo.clone();
            let type_repo = type_repo.clone();
            let membership_repo = membership_repo.clone();
            let resource_type = resource_type.clone();
            let resource_id = resource_id.clone();
            let scope = scope.clone();
            Box::pin(async move {
                Self::remove_membership_in_tx(
                    &*group_repo,
                    &*type_repo,
                    &*membership_repo,
                    tx,
                    &scope,
                    group_id,
                    &resource_type,
                    &resource_id,
                )
                .await
            })
        })
        .await
    }

    /// Inner logic for `remove_membership`, runs inside the transaction
    /// opened by `remove_membership` (`TxConfig::default()`, not
    /// `SERIALIZABLE` -- see that method's doc comment).
    #[allow(clippy::too_many_arguments)]
    async fn remove_membership_in_tx(
        group_repo: &GR,
        type_repo: &TR,
        membership_repo: &MR,
        tx: &impl DBRunner,
        scope: &AccessScope,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), DomainError> {
        // AuthZ gate (VHP-2341): same gate as `add_membership_in_tx`, via
        // `find_model_by_id_scoped` -- the group is not otherwise looked up
        // at all on this path (the delete below goes straight to
        // `membership_repo` by composite key), so without this the caller
        // could delete memberships out of a group belonging to any tenant.
        // A group outside scope reports `GroupNotFound`, matching a
        // nonexistent group. Unlike `add_membership_in_tx`, the raw model
        // itself is never needed here, only the existence/visibility check
        // -- but `find_model_by_id_scoped` is still the cheaper call: it
        // skips `find_by_id`'s unconditional `resolve_type_path` query,
        // which this gate never used anyway (N+1 audit finding (a)).
        group_repo
            .find_model_by_id_scoped(tx, scope, group_id)
            .await?
            .ok_or(DomainError::GroupNotFound { id: group_id })?;

        // Resolve resource_type GTS path to surrogate ID
        let gts_type_id = type_repo
            .resolve_id(tx, resource_type)
            .await?
            .ok_or_else(|| {
                DomainError::validation(format!("Unknown resource type: {resource_type}"))
            })?;

        // Verify the membership exists
        membership_repo
            .find_by_composite_key(tx, group_id, gts_type_id, resource_id)
            .await?
            .ok_or_else(|| {
                DomainError::membership_not_found(format!(
                    "({group_id}, {resource_type}, {resource_id})"
                ))
            })?;

        // Delete the membership
        membership_repo
            .delete(tx, group_id, gts_type_id, resource_id)
            .await?;
        Ok(())
    }

    /// List memberships with `OData` filtering and pagination (AuthZ-scoped).
    pub async fn list_memberships(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupMembership>, DomainError> {
        // Actor sends GET /api/resource-group/v1/memberships?$filter={expr}&cursor={token}&limit={n}
        // Parse OData $filter (handled by ODataQuery parameter)
        // AuthZ gate: verify the caller can list memberships
        let scope = self
            .enforcer
            .access_scope(ctx, &RG_MEMBERSHIP_RESOURCE, "list", None)
            .await
            .map_err(DomainError::from)?;

        let conn = self.conn()?;
        // VHP-2341: the real caller scope now reaches the repo (it used to
        // be discarded, so every caller saw every tenant's rows). See
        // `MembershipRepository::list_memberships` for how tenant filtering
        // is applied despite the membership entity having no scopable
        // tenant column of its own.
        #[allow(clippy::let_and_return)]
        let result = self
            .membership_repo
            .list_memberships(&conn, &scope, query)
            .await;
        result
    }

    /// List memberships without `AuthZ` enforcement (private API, no tenant scoping).
    ///
    /// **Internal API** — never expose this through a REST handler. Backs the
    /// membership read (`ResourceGroupReadHierarchy::list_memberships`): an
    /// in-process `AuthZ` PDP resolves a subject's group memberships while
    /// *being* the PDP, so it cannot re-enter the `PolicyEnforcer` (would
    /// recurse). Mirrors `add_membership_unscoped` — only the enforcer gate is
    /// skipped; the caller supplies any subject/tenant `OData` filter.
    ///
    /// Passes `AccessScope::allow_all()` to the repo, which keeps this
    /// path's query shape exactly as it was before VHP-2341 (no join added).
    pub async fn list_memberships_unscoped(
        &self,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupMembership>, DomainError> {
        let conn = self.conn()?;
        let scope = AccessScope::allow_all();
        self.membership_repo
            .list_memberships(&conn, &scope, query)
            .await
    }
}

// -- MembershipAdder trait implementation for seeding --

#[async_trait::async_trait]
impl<GR: GroupRepositoryTrait, TR: TypeRepositoryTrait, MR: MembershipRepositoryTrait>
    crate::domain::seeding::MembershipAdder for MembershipService<GR, TR, MR>
{
    async fn add_membership(
        &self,
        group_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> Result<(), DomainError> {
        // Seeding runs at gear init, before any caller `SecurityContext`
        // exists; using `SecurityContext::anonymous()` here would gate the
        // path on whether anonymous subjects are allowed to create
        // memberships, which is brittle and outright fails in locked-down
        // deployments. Use the dedicated unscoped entry point — domain
        // invariants still run, only the `PolicyEnforcer` gate is skipped.
        self.add_membership_unscoped(group_id, resource_type, resource_id)
            .await
            .map(|_| ())
    }
}
