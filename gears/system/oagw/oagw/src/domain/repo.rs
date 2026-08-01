use crate::domain::model::{ListQuery, Route, Upstream};
use async_trait::async_trait;
use toolkit_macros::domain_model;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by repository operations.
#[domain_model]
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("{entity} not found: {id}")]
    NotFound { entity: &'static str, id: Uuid },
    #[error("{entity} conflict on {resource}: {detail}")]
    Conflict {
        entity: &'static str,
        resource: String,
        detail: String,
    },
    #[error("internal: {0}")]
    #[allow(dead_code)]
    Internal(String),
    /// A `ListQuery` the caller handed the repository directly failed the
    /// repository's own structural assertion — currently only `top == 0`
    /// (ML-5024). In-process callers (this gear's own SDK client trait
    /// impl, `domain::services::client`, and `check_route_overlap`'s
    /// "give me every route on this upstream" `top: u32::MAX` query) can
    /// build a `ListQuery` without going through the REST
    /// `PaginationQuery` extractor, so the repository still rejects the
    /// one shape that can never be sane: `top == 0` would silently look
    /// like "zero rows exist" instead of surfacing the caller's bug.
    ///
    /// The repository does **not** re-impose an upper bound here — that
    /// policy belongs to the REST edge (`PaginationQuery::to_list_query`,
    /// `ListRoutesQuery`). Clamping `top` inside the repository would make
    /// an in-process caller that legitimately wants an unbounded read
    /// (like the route/upstream overlap check) silently see an arbitrary
    /// truncated subset once an upstream has more rows than the clamp,
    /// which is a correctness bug, not a resource-limit concern.
    ///
    /// `field` names the *wire* parameter the violation corresponds to
    /// (e.g. `"limit"` for `top == 0`, per the ML-1520 convention that the
    /// wire name is `limit`, not the internal `ListQuery::top` field) so
    /// `DomainError`'s `From<RepositoryError>` impl can surface it on the
    /// wire instead of hardcoding a name that may not match the actual
    /// violation.
    #[error("invalid list query: {detail}")]
    Validation { field: &'static str, detail: String },
}

// ---------------------------------------------------------------------------
// Repository traits
// ---------------------------------------------------------------------------

/// Repository trait for upstream persistence.
#[async_trait]
pub trait UpstreamRepository: Send + Sync {
    /// Insert a new upstream. Returns Conflict if alias is taken for the tenant.
    async fn create(&self, upstream: Upstream) -> Result<Upstream, RepositoryError>;

    /// Get an upstream by id, scoped to a tenant.
    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> Result<Upstream, RepositoryError>;

    /// Get an upstream by alias, scoped to a tenant.
    async fn get_by_alias(&self, tenant_id: Uuid, alias: &str)
    -> Result<Upstream, RepositoryError>;

    /// List upstreams for a tenant with pagination.
    async fn list(
        &self,
        tenant_id: Uuid,
        query: &ListQuery,
    ) -> Result<Vec<Upstream>, RepositoryError>;

    /// Update an existing upstream. Preserves id and tenant_id.
    async fn update(&self, upstream: Upstream) -> Result<Upstream, RepositoryError>;

    /// Delete an upstream. Returns NotFound if it does not exist.
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;

    /// List upstreams with the given alias restricted to a set of tenant IDs.
    /// Used for budget validation where only descendants of a particular
    /// ancestor are relevant.
    ///
    /// The provided `alias` must already be normalized (lowercase) as
    /// implementations perform case-sensitive exact-string matching.
    async fn list_by_alias_for_tenants(
        &self,
        alias: &str,
        tenant_ids: &std::collections::HashSet<Uuid>,
    ) -> Result<Vec<Upstream>, RepositoryError>;
}

/// Repository trait for route persistence.
#[async_trait]
pub trait RouteRepository: Send + Sync {
    /// Insert a new route.
    async fn create(&self, route: Route) -> Result<Route, RepositoryError>;

    /// Get a route by id, scoped to a tenant.
    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> Result<Route, RepositoryError>;

    /// List routes for a tenant with pagination and optional upstream filter.
    async fn list(
        &self,
        tenant_id: Uuid,
        upstream_id: Option<Uuid>,
        query: &ListQuery,
    ) -> Result<Vec<Route>, RepositoryError>;

    /// Find the best matching route for a given method and path.
    /// Match criteria: enabled=true, method matches, longest path prefix, highest priority.
    async fn find_matching(
        &self,
        tenant_id: Uuid,
        upstream_id: Uuid,
        method: &str,
        path: &str,
    ) -> Result<Route, RepositoryError>;

    /// Update an existing route.
    async fn update(&self, route: Route) -> Result<Route, RepositoryError>;

    /// Delete a route.
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<(), RepositoryError>;

    /// Delete all routes for a given upstream. Returns the IDs of deleted routes.
    async fn delete_by_upstream(
        &self,
        tenant_id: Uuid,
        upstream_id: Uuid,
    ) -> Result<Vec<Uuid>, RepositoryError>;
}
