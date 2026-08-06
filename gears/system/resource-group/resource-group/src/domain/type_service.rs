// Created: 2026-04-16 by Constructor Tech
//! Domain service for GTS type management.
//!
//! Implements business rules: input validation, placement invariant,
//! hierarchy safety checks, and CRUD orchestration.

use std::sync::Arc;

use authz_resolver_sdk::pep::{AccessRequest, PolicyEnforcer, ResourceType};
use resource_group_sdk::TYPE_RESOURCE_TYPE;
use resource_group_sdk::models::{CreateTypeRequest, ResourceGroupType, UpdateTypeRequest};
use toolkit_db::secure::{DBRunner, TxConfig};
use toolkit_odata::{ODataQuery, Page};
use toolkit_security::{SecurityContext, pep_properties};

use tracing::{debug, warn};

use crate::domain::DbProvider;
use crate::domain::error::DomainError;
use crate::domain::repo::TypeRepositoryTrait;
use crate::domain::validation;

/// `AuthZ` resource type descriptor for GTS type definitions.
///
/// `gts_type` is a platform-global table (see `m20260306_000001_initial.rs`
/// — no `tenant_id` column, no `#[secure(tenant_col = ...)]` on the entity),
/// so there is no column here for a PDP constraint to filter row-level
/// access on: the gate below (`TypeService::gate`) always discards the
/// `AccessScope` it computes and only cares whether compilation succeeded
/// at all, i.e. whether the PDP said yes.
///
/// ## Why `supported_properties` still lists `OWNER_TENANT_ID` — do not
/// ## "simplify" this back to an empty list
///
/// It was an empty list originally, on exactly the "nothing to filter on"
/// reasoning above. That reasoning is correct about the *scope* being
/// unused, but wrong about the consequence: it broke every legitimately
/// *allowed* call, not just denied ones.
///
/// Every real `AuthZ` plugin in this repo attaches an unconditional
/// baseline `In(OWNER_TENANT_ID, [tid])` constraint to **every** allow
/// decision, for **every** resource, regardless of whether that resource
/// even has a tenant column (see `static-authz-plugin`'s `Service::evaluate`
/// — "Baseline `OWNER_TENANT_ID` clamp — the universal shape every PEP can
/// bind" — and `tr-authz-plugin`'s mandatory `owner_tenant_id` property).
/// `authz_resolver_sdk::pep::compiler::compile_to_access_scope` rejects any
/// constraint whose predicate property is not in `supported_properties`
/// ("unsupported property", fail-closed), and when *every* constraint on
/// the response fails that check, the whole call fails with
/// `Err(ConstraintCompileError::AllConstraintsFailed)` — fail-closed by
/// design. With an empty `supported_properties` list, that is exactly what
/// happened to the baseline clamp on every single call: `EnforcerError::
/// CompileFailed` → `DomainError::InternalError` → HTTP 500, for every
/// legitimately-allowed caller of any of the five gated methods below, not
/// merely the denied ones. `tests/type_authz_test.rs`'s `TenantClampAuthZ`
/// mock reproduces the real plugins' shape and its
/// `all_five_actions_succeed_with_realistic_tenant_clamp_constraint` test
/// caught this exact regression (failing with
/// `AllConstraintsFailed { reason: "unsupported property: owner_tenant_id" }`
/// before this fix); the previous `AllowAllNoConstraintsAuthZ` mock could
/// not, because it never attaches a constraint in the first place.
///
/// Declaring `OWNER_TENANT_ID` here lets that baseline constraint compile
/// normally. That the constraint is tenant-shaped and this table has no
/// tenant column is harmless: `gate()` never reads the resulting
/// `AccessScope`'s filters, only whether compilation succeeded. The
/// compiled scope is *not* guaranteed to be `allow_all()` — a PDP that
/// attaches the baseline `In(OWNER_TENANT_ID, ..)` clamp compiles to a
/// constrained scope via `AccessScope::from_constraints`, exactly what
/// `access_scope_with_realistic_tenant_clamp_constraint_succeeds` (see
/// `tests/type_authz_test.rs`) exercises. Runtime safety comes from `gate()`
/// unconditionally discarding whatever scope it gets back, constrained or
/// not — `gts_type` has no tenant column, so there is nothing for such a
/// filter to apply to — not from the scope somehow always compiling to
/// `allow_all()`. The property list exists purely so the compiler doesn't
/// reject the PDP's normal output before `gate()` gets to ignore it.
///
/// # Why every call site *also* uses `access_scope_with(.., require_constraints(false))`
///
/// This is a *different, still-live* case, not a substitute for the above:
/// a PDP may separately permit with **zero** constraints at all
/// (`decision: true, constraints: []` — see `AllowAllNoConstraintsAuthZ` in
/// the tests), a legitimate response shape for a resource a policy doesn't
/// otherwise care to scope. Under the plain [`PolicyEnforcer::access_scope`]
/// default (`require_constraints = true`), *that* shape compiles to
/// `Err(ConstraintCompileError::ConstraintsRequiredButAbsent)`
/// (`EnforcerError::CompileFailed`), which also maps to
/// `DomainError::InternalError` — a 500 — for an allowed caller.
/// `tests/type_authz_test.rs::access_scope_denied_by_default_require_constraints`
/// reproduces that failure; `access_scope_with_require_constraints_false_succeeds`
/// shows the fix compiles the same response to `AccessScope::allow_all()`.
/// `require_constraints(false)` is the API's documented escape hatch for
/// exactly this "permission check only, no constraints required" shape (see
/// `AccessRequest::require_constraints` doc comment; `mini-chat`'s
/// `ModelService::list_models`/`get_model` use the identical pattern for
/// its own global, non-tenant-scoped catalog). It only changes what happens
/// when constraints are *absent*; declaring `OWNER_TENANT_ID` above is what
/// lets a constraint that *is* present compile instead of being rejected as
/// unsupported. Both are needed: a real PDP's permit may show up in either
/// shape, and each is only handled by one of the two.
pub const RG_TYPE_RESOURCE: ResourceType =
    ResourceType::from_static(TYPE_RESOURCE_TYPE, &[pep_properties::OWNER_TENANT_ID]);

/// Service for GTS type lifecycle management.
#[allow(unknown_lints, de0309_must_have_domain_model)]
#[derive(Clone)]
pub struct TypeService<TR: TypeRepositoryTrait> {
    db: Arc<DbProvider>,
    enforcer: PolicyEnforcer,
    type_repo: Arc<TR>,
}

impl<TR: TypeRepositoryTrait> TypeService<TR> {
    /// Create a new `TypeService` with the given database provider and
    /// `PolicyEnforcer` for `AuthZ` enforcement on the type-registry CRUD
    /// surface.
    #[must_use]
    pub fn new(db: Arc<DbProvider>, enforcer: PolicyEnforcer, type_repo: Arc<TR>) -> Self {
        Self {
            db,
            enforcer,
            type_repo,
        }
    }

    /// Permission-check-only `AuthZ` gate shared by every public type-CRUD
    /// entry point. See [`RG_TYPE_RESOURCE`] for why its
    /// `supported_properties` declares `OWNER_TENANT_ID` (so a real PDP's
    /// baseline constraint compiles instead of failing closed) and why
    /// `require_constraints(false)` is *also* still needed on top of that
    /// (so a permit with zero constraints compiles too). The returned
    /// `AccessScope` is intentionally discarded here: this resource has no
    /// columns to filter on, so nothing downstream ever consults the
    /// scope's constraints — only whether compilation succeeded, i.e.
    /// whether the PDP allowed the call.
    async fn gate(&self, ctx: &SecurityContext, action: &str) -> Result<(), DomainError> {
        self.enforcer
            .access_scope_with(
                ctx,
                &RG_TYPE_RESOURCE,
                action,
                None,
                &AccessRequest::new().require_constraints(false),
            )
            .await
            .map_err(DomainError::from)?;
        Ok(())
    }

    /// Create a new GTS type definition (`AuthZ`-gated: `create` on
    /// [`RG_TYPE_RESOURCE`]).
    pub async fn create_type(
        &self,
        ctx: &SecurityContext,
        req: CreateTypeRequest,
    ) -> Result<ResourceGroupType, DomainError> {
        self.gate(ctx, "create").await?;
        self.create_type_unscoped(req).await
    }

    /// Create a new GTS type definition without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler. Used by
    /// [`crate::domain::seeding::seed_types`], which runs at gear init,
    /// before any caller `SecurityContext` exists. Domain invariants
    /// (placement invariant, parent/membership existence, metadata schema
    /// validation) still run; only the `PolicyEnforcer` gate is skipped.
    ///
    /// The full INSERT-junction sequence (`type_repo.insert` →
    /// `insert_allowed_parent_types` → `insert_allowed_membership_types` →
    /// `load_full_type`) runs in one `SERIALIZABLE` transaction with retry.
    ///
    /// An SSI conflict between two concurrent creates of the same code
    /// (RG-03) then retries to a clean `TypeAlreadyExists` instead of a raw
    /// failure; the transaction also prevents a partial insert.
    pub async fn create_type_unscoped(
        &self,
        req: CreateTypeRequest,
    ) -> Result<ResourceGroupType, DomainError> {
        // Pre-validation (pure, no DB) — runs outside the transaction.
        //
        // Every GTS code on this request is parsed *once*, here, through the
        // canonical `GtsTypePath` / `gts::GtsId` parser, and the canonical
        // result replaces the caller's spelling for the rest of the operation:
        // the uniqueness pre-check, the junction lookups and the persisted
        // `gts_type.schema_id` all see the same string. Validating a
        // normalized copy while persisting the raw input is what allowed two
        // rows differing only in case, and a tenant code that evaded the
        // (case-sensitive) tenant-prefix test in `GroupService`.
        let mut req = req;
        req.code = validation::canonical_type_code(&req.code)?;
        // Validate placement invariant: `can_be_root OR len(allowed_parent_types) >= 1`.
        Self::validate_placement_invariant(req.can_be_root, &req.allowed_parent_types)?;
        if let Some(ref schema) = req.metadata_schema {
            validation::validate_metadata_schema(schema)?;
        }
        // FOR EACH parent_path in allowed_parent_types
        // Validate parent_path has RG type prefix `gts.cf.core.rg.type.v1~`
        req.allowed_parent_types = Self::canonical_parent_types(&req.allowed_parent_types)?;
        // FOR EACH membership_path in allowed_membership_types
        // Validate membership_path is a syntactically valid GtsTypePath.
        // Per DESIGN.md, membership resource types are external domain
        // types (e.g. `gts.cf.core.idp.user.v1~`) and are NOT required
        // to carry the RG type-registry prefix.
        req.allowed_membership_types =
            Self::canonical_membership_types(&req.allowed_membership_types)?;

        let stored_schema =
            Self::build_stored_schema(req.can_be_root, req.metadata_schema.as_ref());
        let db = self.db.db();
        let type_repo = self.type_repo.clone();

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let req = req.clone();
            let type_repo = type_repo.clone();
            let stored_schema = stored_schema.clone();
            Box::pin(
                async move { Self::create_type_in_tx(&*type_repo, tx, &req, &stored_schema).await },
            )
        })
        .await
    }

    /// Inner logic for `create_type`, run inside the SERIALIZABLE
    /// transaction with retry. Each attempt gets a fresh clone of
    /// `req`/`stored_schema`, so a failed attempt's mutations never leak in.
    async fn create_type_in_tx(
        type_repo: &TR,
        tx: &impl DBRunner,
        req: &CreateTypeRequest,
        stored_schema: &serde_json::Value,
    ) -> Result<ResourceGroupType, DomainError> {
        // IF unique constraint violation → RETURN TypeAlreadyExists with
        // conflicting schema_id. Performed in-tx so a concurrent create
        // cannot slip a duplicate row in between this read and the
        // insert below.
        //
        // resolve_id does this existence check with a single, plain id
        // lookup -- no junction reads -- since only the boolean matters
        // here, not the type's contents (RG-13).
        if type_repo.resolve_id(tx, &req.code).await?.is_some() {
            debug!(code = %req.code, "Type already exists, rejecting create");
            return Err(DomainError::type_already_exists(&req.code));
        }

        // IF allowed_parent_types is non-empty
        // DB: SELECT id FROM gts_type WHERE schema_id IN (allowed_parent_types)
        // — verify all referenced parent types exist
        // IF any parent type not found → RETURN Validation error with
        // missing type paths (handled by `resolve_ids` returning
        // `DomainError::validation`).
        // Verify parent_path exists in gts_type table (resolve_ids
        // returns a `validation` error listing missing codes).
        let parent_ids = if req.allowed_parent_types.is_empty() {
            Vec::new()
        } else {
            type_repo.resolve_ids(tx, &req.allowed_parent_types).await?
        };

        // IF allowed_membership_types is non-empty
        // DB: SELECT id FROM gts_type WHERE schema_id IN (allowed_membership_types)
        // — verify all referenced membership types exist
        // IF any membership type not found → RETURN Validation error
        // with missing type paths.
        // Verify membership_path exists in gts_type table (resolve_ids
        // returns a `validation` error listing missing codes).
        let membership_ids = if req.allowed_membership_types.is_empty() {
            Vec::new()
        } else {
            type_repo
                .resolve_ids(tx, &req.allowed_membership_types)
                .await?
        };

        // Resolve GTS type path to SMALLINT surrogate ID at persistence
        // boundary (the `type_repo.insert` call below assigns the
        // surrogate id and the subsequent re-read returns it).
        // DB: INSERT INTO gts_type (schema_id, metadata_schema) — with
        // uniqueness constraint on schema_id.
        let type_model = type_repo.insert(tx, &req.code, Some(stored_schema)).await?;
        // DB: INSERT INTO gts_type_allowed_parent (type_id, parent_type_id)
        // for each allowed parent.
        type_repo
            .insert_allowed_parent_types(tx, type_model.id, &parent_ids)
            .await?;
        // DB: INSERT INTO gts_type_allowed_membership (type_id, membership_type_id)
        // for each allowed membership.
        type_repo
            .insert_allowed_membership_types(tx, type_model.id, &membership_ids)
            .await?;
        // RETURN created ResourceGroupType with schema_id,
        // allowed_parent_types, allowed_membership_types, can_be_root,
        // metadata_schema (loaded with junctions).
        // RETURN validated type definition (loaded with junctions).
        type_repo.load_full_type(tx, &type_model).await
    }

    /// Get a GTS type definition by its code (GTS type path). `AuthZ`-gated:
    /// `read` on [`RG_TYPE_RESOURCE`].
    pub async fn get_type(
        &self,
        ctx: &SecurityContext,
        code: &str,
    ) -> Result<ResourceGroupType, DomainError> {
        self.gate(ctx, "read").await?;
        self.get_type_unscoped(code).await
    }

    /// Get a GTS type definition by its code without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler. Used by
    /// [`crate::domain::seeding::seed_types`] (no caller `SecurityContext`
    /// exists at gear-init time) and by [`crate::domain::local_client::ResourceGroupLocalClient`]
    /// internals that need a plain lookup after their own gate already ran.
    pub async fn get_type_unscoped(&self, code: &str) -> Result<ResourceGroupType, DomainError> {
        // Lookup key: canonicalized, not parsed -- see `update_type_unscoped`.
        let code = validation::canonicalize_code(code);
        let conn = self.db.conn()?;
        self.type_repo
            .find_by_code(&conn, &code)
            .await?
            .ok_or_else(|| DomainError::type_not_found(code))
    }

    /// List GTS type definitions with `OData` filtering and pagination.
    /// `AuthZ`-gated: `list` on [`RG_TYPE_RESOURCE`].
    pub async fn list_types(
        &self,
        ctx: &SecurityContext,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupType>, DomainError> {
        self.gate(ctx, "list").await?;
        self.list_types_unscoped(query).await
    }

    /// List GTS type definitions without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler.
    pub async fn list_types_unscoped(
        &self,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupType>, DomainError> {
        let conn = self.db.conn()?;
        self.type_repo.list_types(&conn, query).await
    }

    /// Update a GTS type definition (full replacement). `AuthZ`-gated:
    /// `update` on [`RG_TYPE_RESOURCE`].
    pub async fn update_type(
        &self,
        ctx: &SecurityContext,
        code: &str,
        req: UpdateTypeRequest,
    ) -> Result<ResourceGroupType, DomainError> {
        self.gate(ctx, "update").await?;
        self.update_type_unscoped(code, req).await
    }

    /// Update a GTS type definition without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler. Used by
    /// [`crate::domain::seeding::seed_types`] (no caller `SecurityContext`
    /// exists at gear-init time). Domain invariants (placement invariant,
    /// hierarchy safety check, parent/membership existence) still run; only
    /// the `PolicyEnforcer` gate is skipped.
    ///
    /// The `delete_allowed_*` / `insert_allowed_*` / `update_type` sequence
    /// runs in one `SERIALIZABLE` transaction with bounded retry, same
    /// rationale as `create_type` (RG-03).
    ///
    /// A failure on any step rolls back the partial junction rewrites, so a
    /// crash never leaves the registry pointing at half the new definition.
    pub async fn update_type_unscoped(
        &self,
        code: &str,
        req: UpdateTypeRequest,
    ) -> Result<ResourceGroupType, DomainError> {
        // Pre-validation (pure, no DB) — runs outside the transaction.
        // Validate placement invariant on new values.
        let mut req = req;
        Self::validate_placement_invariant(req.can_be_root, &req.allowed_parent_types)?;
        req.allowed_parent_types = Self::canonical_parent_types(&req.allowed_parent_types)?;
        req.allowed_membership_types =
            Self::canonical_membership_types(&req.allowed_membership_types)?;
        if let Some(ref schema) = req.metadata_schema {
            validation::validate_metadata_schema(schema)?;
        }

        let stored_schema =
            Self::build_stored_schema(req.can_be_root, req.metadata_schema.as_ref());
        let db = self.db.db();
        let type_repo = self.type_repo.clone();
        // `code` addresses an existing row, so it is canonicalized rather than
        // fully parsed: a code that names nothing must stay a `NotFound`, not
        // become a validation error. Canonicalizing is still required -- rows
        // are written canonically, so a differently-cased path would otherwise
        // miss the row it is meant to update.
        let code = validation::canonicalize_code(code);

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let req = req.clone();
            let type_repo = type_repo.clone();
            let stored_schema = stored_schema.clone();
            let code = code.clone();
            Box::pin(async move {
                Self::update_type_in_tx(&*type_repo, tx, &code, &req, &stored_schema).await
            })
        })
        .await
    }

    /// Inner logic for `update_type`, run inside the SERIALIZABLE
    /// transaction with retry, each attempt on a fresh clone of
    /// `req`/`stored_schema`/`code`.
    async fn update_type_in_tx(
        type_repo: &TR,
        tx: &impl DBRunner,
        code: &str,
        req: &UpdateTypeRequest,
        stored_schema: &serde_json::Value,
    ) -> Result<ResourceGroupType, DomainError> {
        // DB: SELECT FROM gts_type WHERE schema_id = {code} — load existing type.
        // find_by_code_with_id fetches id + type together in one query (RG-11).
        // IF type not found → RETURN NotFound
        let (type_id, existing) = type_repo
            .find_by_code_with_id(tx, code)
            .await?
            .ok_or_else(|| DomainError::type_not_found(code))?;

        // Validate all referenced allowed_parent_types and
        // allowed_membership_types types exist (resolve_ids returns
        // a `validation` error listing missing codes).
        let parent_ids = if req.allowed_parent_types.is_empty() {
            Vec::new()
        } else {
            type_repo.resolve_ids(tx, &req.allowed_parent_types).await?
        };
        let membership_ids = if req.allowed_membership_types.is_empty() {
            Vec::new()
        } else {
            type_repo
                .resolve_ids(tx, &req.allowed_membership_types)
                .await?
        };

        // Invoke hierarchy safety check algorithm for
        // allowed_parent_types and can_be_root changes.
        // IF hierarchy safety check fails → RETURN
        // AllowedParentTypesViolation with violating group details
        // (returned by `check_hierarchy_safety`).
        Self::check_hierarchy_safety(type_repo, tx, type_id, &existing, req).await?;

        // DB: DELETE FROM gts_type_allowed_parent WHERE type_id = {id}
        // — clear old parents.
        type_repo.delete_allowed_parent_types(tx, type_id).await?;
        // DB: INSERT INTO gts_type_allowed_parent — insert new parents.
        type_repo
            .insert_allowed_parent_types(tx, type_id, &parent_ids)
            .await?;
        // DB: DELETE FROM gts_type_allowed_membership WHERE type_id = {id}
        // — clear old memberships.
        type_repo
            .delete_allowed_membership_types(tx, type_id)
            .await?;
        // DB: INSERT INTO gts_type_allowed_membership — insert new
        // memberships.
        type_repo
            .insert_allowed_membership_types(tx, type_id, &membership_ids)
            .await?;

        // DB: UPDATE gts_type SET metadata_schema = {new}, updated_at = now().
        let updated_model = type_repo
            .update_type(tx, type_id, code, Some(stored_schema))
            .await?;
        // RETURN updated ResourceGroupType (loaded with refreshed junctions).
        type_repo.load_full_type(tx, &updated_model).await
    }

    /// Delete a GTS type definition. `AuthZ`-gated: `delete` on
    /// [`RG_TYPE_RESOURCE`].
    pub async fn delete_type(&self, ctx: &SecurityContext, code: &str) -> Result<(), DomainError> {
        self.gate(ctx, "delete").await?;
        self.delete_type_unscoped(code).await
    }

    /// Delete a GTS type definition without `AuthZ` enforcement.
    ///
    /// **Internal API** — never expose this through a REST handler.
    ///
    /// Runs inside a `SERIALIZABLE` transaction with bounded retry (RG-02):
    /// a concurrent `create_group` referencing this type then conflicts with
    /// this read, and the retry gets a clean `ConflictActiveReferences`.
    pub async fn delete_type_unscoped(&self, code: &str) -> Result<(), DomainError> {
        // Actor sends DELETE /api/types-registry/v1/types/{code}
        let db = self.db.db();
        let type_repo = self.type_repo.clone();
        // Lookup key: canonicalized, not parsed -- see `update_type_unscoped`.
        let code = validation::canonicalize_code(code);

        db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, |tx| {
            let type_repo = type_repo.clone();
            let code = code.clone();
            Box::pin(async move { Self::delete_type_in_tx(&*type_repo, tx, &code).await })
        })
        .await
    }

    /// Inner logic for `delete_type`, runs inside the SERIALIZABLE
    /// transaction.
    async fn delete_type_in_tx(
        type_repo: &TR,
        tx: &impl DBRunner,
        code: &str,
    ) -> Result<(), DomainError> {
        let type_id = type_repo
            .resolve_id(tx, code)
            .await?
            .ok_or_else(|| DomainError::type_not_found(code))?;

        // Check for active references
        let count = type_repo.count_groups_of_type(tx, type_id).await?;
        if count > 0 {
            warn!(code = %code, count, "Cannot delete type: active group references exist");
            return Err(DomainError::conflict_active_references(format!(
                "Cannot delete type '{code}': {count} group(s) of this type exist"
            )));
        }

        type_repo.delete_by_id(tx, type_id).await?;
        Ok(())
    }

    // -- Validation helpers --

    /// Parse every `allowed_parent_types` entry, returning the canonical
    /// forms in the caller's order.
    ///
    /// Parent paths are stored as junction rows keyed by the surrogate id
    /// `resolve_ids` looks up from `gts_type.schema_id`, so a non-canonical
    /// entry would either miss an existing row (spurious "type does not
    /// exist") or, once written, make `check_hierarchy_safety`'s
    /// old-minus-new set difference report a parent as removed when only its
    /// spelling changed.
    fn canonical_parent_types(codes: &[String]) -> Result<Vec<String>, DomainError> {
        codes
            .iter()
            .map(|code| validation::canonical_type_code(code))
            .collect()
    }

    /// Parse every `allowed_membership_types` entry, returning the canonical
    /// forms in the caller's order. Same lookup/diff reasoning as
    /// [`Self::canonical_parent_types`], minus the RG-prefix requirement.
    fn canonical_membership_types(codes: &[String]) -> Result<Vec<String>, DomainError> {
        codes
            .iter()
            .map(|code| validation::canonical_membership_type_code(code))
            .collect()
    }

    fn validate_placement_invariant(
        can_be_root: bool,
        allowed_parent_types: &[String],
    ) -> Result<(), DomainError> {
        if !can_be_root && allowed_parent_types.is_empty() {
            return Err(DomainError::validation(
                "Type must allow root placement or have at least one allowed parent",
            ));
        }
        Ok(())
    }

    /// Build the stored `metadata_schema` JSON with internal `__can_be_root` key.
    ///
    /// Whether this type starts a new tenant scope is no longer stored — it is
    /// derived at runtime from the type code prefix ([`TENANT_RG_TYPE_PATH`]).
    fn build_stored_schema(
        can_be_root: bool,
        metadata_schema: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        let mut map = match metadata_schema {
            Some(serde_json::Value::Object(m)) => m.clone(),
            Some(v) => {
                let mut m = serde_json::Map::new();
                m.insert("__user_schema".to_owned(), v.clone());
                m
            }
            None => serde_json::Map::new(),
        };
        map.insert(
            "__can_be_root".to_owned(),
            serde_json::Value::Bool(can_be_root),
        );
        serde_json::Value::Object(map)
    }

    async fn check_hierarchy_safety(
        type_repo: &TR,
        conn: &impl DBRunner,
        type_id: i16,
        existing: &ResourceGroupType,
        req: &UpdateTypeRequest,
    ) -> Result<(), DomainError> {
        // Compute removed parent types: old_allowed_parent_types - new_allowed_parent_types
        let removed_parents: Vec<String> = existing
            .allowed_parent_types
            .iter()
            .filter(|p| !req.allowed_parent_types.contains(p))
            .cloned()
            .collect();

        if !removed_parents.is_empty() {
            // Batch: resolve every removed-parent path and find every
            // violating group in one call (N+1 audit finding (b)) --
            // was one `resolve_id` + one single-parent lookup *per*
            // removed parent (slope 2.0: 1 gts_type + 1 resource_group
            // SELECT per removed parent).
            let violations = type_repo
                .find_groups_violating_removed_parents(conn, type_id, &removed_parents)
                .await?;

            // Report the first removed parent (in `removed_parents` order)
            // that has any violation -- same as the pre-batch loop, which
            // iterated in that order and returned on the first violation
            // it found.
            if let Some(removed_parent) = removed_parents
                .iter()
                .find(|p| violations.iter().any(|(code, _, _)| code == *p))
            {
                let names: Vec<String> = violations
                    .iter()
                    .filter(|(code, _, _)| code == removed_parent)
                    .map(|(_, _, name)| name.clone())
                    .collect();
                return Err(DomainError::allowed_parent_types_violation(format!(
                    "Cannot remove allowed parent '{removed_parent}': groups using this parent relationship: {}",
                    names.join(", ")
                )));
            }
        }

        // Check can_be_root change from true to false
        if existing.can_be_root && !req.can_be_root {
            let root_groups = type_repo.find_root_groups_of_type(conn, type_id).await?;

            if !root_groups.is_empty() {
                let names: Vec<String> = root_groups.iter().map(|(_, name)| name.clone()).collect();
                return Err(DomainError::allowed_parent_types_violation(format!(
                    "Cannot disable root placement: root groups of this type exist: {}",
                    names.join(", ")
                )));
            }
        }

        // IF violations collected -> RETURN AllowedParentTypesViolation (handled inline above)

        Ok(())
    }
}
