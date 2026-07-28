// Created: 2026-04-16 by Constructor Tech
// @cpt-dod:cpt-cf-resource-group-dod-membership-service:p1
//! Persistence layer for membership management.
//!
//! All surrogate SMALLINT ID resolution happens here. The domain and API layers
//! work exclusively with string GTS type paths and UUIDs.

use async_trait::async_trait;
use resource_group_sdk::models::ResourceGroupMembership;
use resource_group_sdk::odata::MembershipFilterField;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use toolkit_db::odata::{LimitCfg, paginate_odata};
use toolkit_db::secure::{DBRunner, SecureDeleteExt, SecureEntityExt};
use toolkit_odata::{ODataQuery, Page, SortDir};
use toolkit_security::AccessScope;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::repo::MembershipRepositoryTrait;
use crate::infra::storage::entity::resource_group_membership::{
    self as membership_entity, Entity as MembershipEntity,
};
use crate::infra::storage::odata_mapper::MembershipODataMapper;

/// Default `OData` pagination limits for memberships.
const MEMBERSHIP_LIMIT_CFG: LimitCfg = LimitCfg {
    default: 25,
    max: 200,
};

/// System-level access scope (no tenant/resource filtering).
fn system_scope() -> AccessScope {
    AccessScope::allow_all()
}

/// Repository for membership persistence operations.
pub struct MembershipRepository;

#[async_trait]
impl MembershipRepositoryTrait for MembershipRepository {
    /// List memberships with `OData` filtering and pagination.
    ///
    /// The `OData` filter supports `group_id`, `resource_type`, and `resource_id` fields.
    /// `resource_type` values in filters are GTS type path strings; they are resolved
    /// to surrogate IDs at the persistence boundary.
    async fn list_memberships<C: DBRunner>(
        &self,
        db: &C,
        scope: &AccessScope,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupMembership>, DomainError> {
        // Validate the filter (String kind for `resource_type`) and resolve
        // GTS type-path string values to SMALLINT IDs in the typed
        // FilterNode -- BEFORE paginate_odata. Mirrors
        // `GroupRepository::list_groups`; the tree walk itself is shared via
        // `TypeRepository::resolve_type_filter_node` (VHP-1731).
        let resolved_filter = if let Some(ast) = query.filter.as_deref() {
            let validated =
                toolkit_odata::filter::convert_expr_to_filter_node::<MembershipFilterField>(ast)
                    .map_err(|e| DomainError::validation(format!("invalid $filter: {e}")))?;
            Some(
                crate::infra::storage::type_repo::TypeRepository::resolve_type_filter_node(
                    db,
                    &validated,
                    MembershipFilterField::ResourceType,
                )
                .await?,
            )
        } else {
            None
        };

        // Build base query with the resolved filter applied manually.
        //
        // VHP-2341: `resource_group_membership` declares `#[secure(no_tenant,
        // no_resource, no_owner, no_type)]` (see its entity file) --
        // `Scopable`'s generated `resolve_property` returns `None` for
        // *every* property on that shape, so calling
        // `.secure().scope_with(scope)` directly on `MembershipEntity` with
        // the caller's real (constrained) scope would resolve to deny-all
        // for every caller, not a per-tenant filter -- an empty list for
        // everyone, not tenant isolation. Tenant scoping instead has to run
        // against `resource_group`, which DOES declare
        // `tenant_col = "tenant_id"` (see `resource_group.rs`).
        //
        // A plain SQL JOIN on `group_id = id` was tried first and rejected:
        // both tables happen to have a `gts_type_id` column (the group's
        // own GTS type vs. the member resource's GTS type), and
        // `resource_type` `$filter`/cursor predicates are built by the
        // generic `toolkit_db::odata` helpers via `Expr::col(column)` --
        // an *unqualified* column reference. That's unambiguous against a
        // single-table `FROM`, but once `resource_group` is joined into the
        // same top-level query, `"gts_type_id"` is ambiguous between the two
        // tables and every backend (SQLite included) rejects the query.
        // Rewriting the generic OData helpers to always table-qualify was
        // rejected as out of scope and riskier than this gear's own fix.
        //
        // Instead, tenant scoping runs as a **correlated EXISTS subquery**
        // with its own, separate `FROM resource_group` -- the outer query's
        // `FROM` stays `resource_group_membership` only, so the ambiguity
        // above cannot occur (the outer `$filter`/cursor/order-by columns
        // are only ever resolved against the single outer table). The
        // subquery's `WHERE` correlates back to the specific membership row
        // via `resource_group.id = resource_group_membership.group_id`
        // (table-qualified with `Expr::col((Entity, Column)).equals(..)`,
        // so it never collides with the subquery's own unqualified
        // scope-condition columns either), then ANDs in the ordinary
        // `SecureSelect` scope condition for `resource_group` -- built via
        // the same public `.secure().scope_with(scope)` API every other
        // repo in this gear uses, not a hand-rolled `Condition`.
        //
        // `toolkit_db::secure` has no public helper that returns a bare
        // `Condition` for an arbitrary entity outside a `SecureSelect`
        // chain, and the existing `SecureSelect::scope_via_exists::<J>`
        // helper is deliberately *uncorrelated* (see its doc comment in
        // `libs/toolkit-db/src/secure/select.rs`): it would check whether
        // *any* group in scope exists at all, not whether *this
        // membership's* group is in scope -- exactly the trap VHP-2341
        // warns about. Extending `toolkit-db`'s public API with a
        // correlated-EXISTS or bare-`Condition` builder was considered and
        // rejected: `.secure().scope_with(scope).into_inner().into_query()`
        // (all public `SecureSelect`/`QueryTrait` API) plus a manually
        // built `Expr::exists(..)` wrapper is sufficient, so no library
        // change is needed for this gear-local fix.
        //
        // This is still exactly one SQL statement per page -- a subquery
        // inside the same statement's `WHERE`, not a second round trip.
        //
        // Skipped for an unconstrained scope (`list_memberships_unscoped`:
        // the in-process AuthZ-plugin read path and seeding) so that path's
        // query shape is untouched by this fix -- an unconstrained scope
        // adds no filter either way, so the subquery would be a pure no-op
        // there; omitting it keeps its SQL text (and query-count baseline)
        // exactly as it was before VHP-2341.
        let base_query = if scope.is_unconstrained() {
            MembershipEntity::find().secure().scope_with(scope)
        } else {
            use crate::infra::storage::entity::resource_group::{
                self as rg_entity, Entity as ResourceGroupEntity,
            };
            use sea_orm::QueryTrait;
            use sea_orm::sea_query::Expr;

            let group_in_scope = ResourceGroupEntity::find()
                .filter(
                    Expr::col((ResourceGroupEntity, rg_entity::Column::Id))
                        .equals((MembershipEntity, membership_entity::Column::GroupId)),
                )
                .secure()
                .scope_with(scope)
                .into_inner()
                .into_query();

            MembershipEntity::find()
                .filter(sea_orm::Condition::all().add(Expr::exists(group_in_scope)))
                .secure()
                .scope_with(&AccessScope::allow_all())
        };
        let base_query = if let Some(ref node) = resolved_filter {
            let cond = toolkit_db::odata::sea_orm_filter::filter_node_to_condition::<
                MembershipFilterField,
                MembershipODataMapper,
            >(node)
            .map_err(|e| DomainError::validation(format!("invalid $filter: {e}")))?;
            base_query.filter(cond)
        } else {
            base_query
        };

        // Strip the filter from the query -- already applied above.
        let mut query_no_filter = query.clone();
        query_no_filter.filter = None;

        // Any remaining `paginate_odata` failure (bad `$orderby` field, stale
        // cursor, filter/order mismatch, or a genuine DB error) is
        // classified by `DomainError::from` (VHP-1954): client-caused query
        // rejections map to `Validation` (400), backend failures stay
        // `Database` (500).
        let page = paginate_odata::<MembershipFilterField, MembershipODataMapper, _, _, _, _>(
            base_query,
            db,
            &query_no_filter,
            ("group_id", SortDir::Desc),
            MEMBERSHIP_LIMIT_CFG,
            |m: membership_entity::Model| m,
        )
        .await
        .map_err(DomainError::from)?;

        // Batch-resolve type IDs to GTS paths (single query)
        let type_ids: Vec<i16> = page.items.iter().map(|m| m.gts_type_id).collect();
        let group_repo = crate::infra::storage::group_repo::GroupRepository;
        let type_map = crate::domain::repo::GroupRepositoryTrait::resolve_type_paths_batch(
            &group_repo,
            db,
            &type_ids,
        )
        .await?;

        let memberships = page
            .items
            .into_iter()
            .map(|model| {
                let type_path = type_map
                    .get(&model.gts_type_id)
                    .cloned()
                    .unwrap_or_default();
                ResourceGroupMembership {
                    group_id: model.group_id,
                    resource_type: type_path,
                    resource_id: model.resource_id,
                }
            })
            .collect();

        Ok(Page {
            items: memberships,
            page_info: page.page_info,
        })
    }

    /// Insert a membership. Returns the created membership.
    ///
    /// `secure_insert` already returns the fully-populated `Model` --
    /// every column here was explicitly `Set()`, so there's no DB-generated
    /// value left to recover with a separate re-read (RG-08).
    async fn insert<C: DBRunner>(
        &self,
        db: &C,
        group_id: Uuid,
        gts_type_id: i16,
        resource_id: &str,
    ) -> Result<membership_entity::Model, DomainError> {
        let scope = system_scope();

        let model = membership_entity::ActiveModel {
            group_id: Set(group_id),
            gts_type_id: Set(gts_type_id),
            resource_id: Set(resource_id.to_owned()),
            created_at: Set(time::OffsetDateTime::now_utc()),
        };

        toolkit_db::secure::secure_insert::<MembershipEntity>(model, &scope, db)
            .await
            .map_err(|e| {
                // VHP-2345: same duplicate-key classification as
                // `GroupRepository::insert` -- `ScopeError::is_unique_violation`
                // (SQLSTATE first, string fallback second) instead of a
                // gear-local substring match on "duplicate key" / "UNIQUE
                // constraint", which only ever covered Postgres/SQLite
                // wording and would silently miss e.g. MySQL.
                if e.is_unique_violation() {
                    DomainError::duplicate_membership(
                        format!("({group_id}, type_id={gts_type_id}, {resource_id})"),
                        format!(
                            "Membership already exists: ({group_id}, type_id={gts_type_id}, {resource_id})"
                        ),
                    )
                } else {
                    DomainError::database(e.to_string())
                }
            })
    }

    /// Delete a membership by its composite key. Returns the number of affected rows.
    async fn delete<C: DBRunner>(
        &self,
        db: &C,
        group_id: Uuid,
        gts_type_id: i16,
        resource_id: &str,
    ) -> Result<u64, DomainError> {
        let scope = system_scope();
        let result = MembershipEntity::delete_many()
            .filter(membership_entity::Column::GroupId.eq(group_id))
            .filter(membership_entity::Column::GtsTypeId.eq(gts_type_id))
            .filter(membership_entity::Column::ResourceId.eq(resource_id))
            .secure()
            .scope_with(&scope)
            .exec(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(result.rows_affected)
    }

    /// Find a membership by its composite key.
    async fn find_by_composite_key<C: DBRunner>(
        &self,
        db: &C,
        group_id: Uuid,
        gts_type_id: i16,
        resource_id: &str,
    ) -> Result<Option<membership_entity::Model>, DomainError> {
        let scope = system_scope();
        MembershipEntity::find()
            .filter(membership_entity::Column::GroupId.eq(group_id))
            .filter(membership_entity::Column::GtsTypeId.eq(gts_type_id))
            .filter(membership_entity::Column::ResourceId.eq(resource_id))
            .secure()
            .scope_with(&scope)
            .one(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))
    }

    /// Check existing membership tenants for a resource (for tenant compatibility).
    /// Returns the set of distinct `tenant_ids` for groups that have this resource as a member.
    async fn get_existing_membership_tenant_ids<C: DBRunner>(
        &self,
        db: &C,
        gts_type_id: i16,
        resource_id: &str,
    ) -> Result<Vec<Uuid>, DomainError> {
        use crate::infra::storage::entity::resource_group::{
            self as rg_entity, Entity as ResourceGroupEntity,
        };

        let scope = system_scope();

        // Get all group_ids for this resource
        let memberships = MembershipEntity::find()
            .filter(membership_entity::Column::GtsTypeId.eq(gts_type_id))
            .filter(membership_entity::Column::ResourceId.eq(resource_id))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        if memberships.is_empty() {
            return Ok(Vec::new());
        }

        let group_ids: Vec<Uuid> = memberships.iter().map(|m| m.group_id).collect();

        // Get tenant_ids from those groups
        let groups = ResourceGroupEntity::find()
            .filter(rg_entity::Column::Id.is_in(group_ids))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let mut tenant_ids: Vec<Uuid> = groups.into_iter().map(|g| g.tenant_id).collect();
        tenant_ids.sort();
        tenant_ids.dedup();
        Ok(tenant_ids)
    }
}
