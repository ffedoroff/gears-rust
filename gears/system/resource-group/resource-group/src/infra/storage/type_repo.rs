// Created: 2026-04-16 by Constructor Tech
// @cpt-dod:cpt-cf-resource-group-dod-type-mgmt-service-crud:p1
//! Persistence layer for GTS type management.
//!
//! All surrogate SMALLINT ID resolution happens here. The domain and API layers
//! work exclusively with string GTS type paths.

use async_trait::async_trait;
use resource_group_sdk::ResourceGroupType;
use resource_group_sdk::odata::TypeFilterField;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use toolkit_db::odata::{LimitCfg, paginate_odata};
use toolkit_db::secure::{DBRunner, SecureDeleteExt, SecureEntityExt, SecureUpdateExt};
use toolkit_odata::{ODataQuery, Page, SortDir};
use toolkit_security::AccessScope;

use crate::domain::error::DomainError;
use crate::domain::repo::TypeRepositoryTrait;
use crate::infra::storage::entity::{
    gts_type::{self, Entity as GtsTypeEntity},
    gts_type_allowed_membership::{self, Entity as AllowedMembershipEntity},
    gts_type_allowed_parent::{self, Entity as AllowedParentEntity},
    resource_group::{self as rg_entity, Entity as ResourceGroupEntity},
};
use crate::infra::storage::odata_mapper::TypeODataMapper;

/// Default `OData` pagination limits for types.
const TYPE_LIMIT_CFG: LimitCfg = LimitCfg {
    default: 25,
    max: 200,
};

/// System-level access scope (no tenant/resource filtering).
fn system_scope() -> AccessScope {
    AccessScope::allow_all()
}

/// Repository for GTS type persistence operations.
pub struct TypeRepository;

impl TypeRepository {
    /// Resolve a GTS type path to its surrogate SMALLINT ID (static helper for filter resolution).
    pub async fn resolve_id(db: &impl DBRunner, code: &str) -> Result<Option<i16>, DomainError> {
        let scope = system_scope();
        let result = GtsTypeEntity::find()
            .filter(gts_type::Column::SchemaId.eq(code))
            .secure()
            .scope_with(&scope)
            .one(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(result.map(|m| m.id))
    }

    /// Resolve GTS type-path string values to SMALLINT surrogate IDs inside a
    /// validated `FilterNode`, for whichever field represents a GTS type path
    /// in the caller's filter-field enum (e.g. `GroupFilterField::Type`,
    /// `MembershipFilterField::ResourceType`).
    ///
    /// Generic over the filter-field enum `F` so every repository that
    /// filters on a GTS type path shares this tree walk instead of
    /// reimplementing it per field enum --
    /// `GroupRepository::list_groups` and
    /// `MembershipRepository::list_memberships` each call this with their
    /// own field variant (`type_field`).
    ///
    /// Runs as two in-memory tree walks around a single batch query
    /// (N+1 audit finding (b)): `collect_type_filter_paths` gathers every
    /// literal path referenced anywhere in the tree (a `type in (...)`
    /// list contributes all of its values at once), `resolve_paths_for_filter`
    /// resolves the whole set with one `WHERE schema_id IN (...)`, and
    /// `substitute_type_filter_ids` rebuilds the tree from that map. A
    /// `type in (...)` filter with N values used to cost N separate
    /// `resolve_id` round trips (slope 1.0, confirmed by the audit); now
    /// it costs exactly one query regardless of N.
    ///
    /// Must be called AFTER `convert_expr_to_filter_node` has already
    /// validated the filter (so `type_field`'s kind is confirmed `String`).
    pub async fn resolve_type_filter_node<F>(
        db: &impl DBRunner,
        node: &toolkit_odata::filter::FilterNode<F>,
        type_field: F,
    ) -> Result<toolkit_odata::filter::FilterNode<F>, DomainError>
    where
        F: toolkit_odata::filter::FilterField + Send + Sync,
    {
        let mut paths: Vec<String> = Vec::new();
        Self::collect_type_filter_paths(node, type_field, &mut paths);

        let id_by_path = Self::resolve_paths_for_filter(db, &paths).await?;

        Ok(Self::substitute_type_filter_ids(
            node,
            type_field,
            &id_by_path,
        ))
    }

    /// First pass of `resolve_type_filter_node`: collect every literal GTS
    /// type-path string that appears in a `Binary` or `InList` node for
    /// `type_field`, anywhere in the tree. Pure in-memory walk, no I/O.
    fn collect_type_filter_paths<F: toolkit_odata::filter::FilterField>(
        node: &toolkit_odata::filter::FilterNode<F>,
        type_field: F,
        out: &mut Vec<String>,
    ) {
        use toolkit_odata::ast::Value as V;
        use toolkit_odata::filter::FilterNode as FN;

        match node {
            FN::Binary {
                field,
                value: V::String(path),
                ..
            } if *field == type_field => out.push(path.clone()),
            FN::InList { field, values } if *field == type_field => {
                for v in values {
                    if let V::String(path) = v {
                        out.push(path.clone());
                    }
                }
            }
            FN::Composite { children, .. } => {
                for child in children {
                    Self::collect_type_filter_paths(child, type_field, out);
                }
            }
            FN::Not(inner) => Self::collect_type_filter_paths(inner, type_field, out),
            _ => {}
        }
    }

    /// Second pass of `resolve_type_filter_node`: rebuild the tree with
    /// every collected path substituted for its resolved surrogate ID.
    /// Pure in-memory walk, no I/O -- `id_by_path` is assumed to already
    /// contain every path `collect_type_filter_paths` found (guaranteed by
    /// `resolve_paths_for_filter`, which errors out otherwise).
    fn substitute_type_filter_ids<F: toolkit_odata::filter::FilterField>(
        node: &toolkit_odata::filter::FilterNode<F>,
        type_field: F,
        id_by_path: &std::collections::HashMap<String, i16>,
    ) -> toolkit_odata::filter::FilterNode<F> {
        use toolkit_odata::ast::Value as V;
        use toolkit_odata::filter::FilterNode as FN;

        match node {
            FN::Binary {
                field,
                op,
                value: V::String(path),
            } if *field == type_field => FN::Binary {
                field: *field,
                op: *op,
                value: V::Number(id_by_path[path].into()),
            },
            FN::InList { field, values } if *field == type_field => {
                let resolved = values
                    .iter()
                    .map(|v| match v {
                        V::String(path) => V::Number(id_by_path[path].into()),
                        other => other.clone(),
                    })
                    .collect();
                FN::InList {
                    field: *field,
                    values: resolved,
                }
            }
            FN::Composite { op, children } => FN::Composite {
                op: *op,
                children: children
                    .iter()
                    .map(|c| Self::substitute_type_filter_ids(c, type_field, id_by_path))
                    .collect(),
            },
            FN::Not(inner) => FN::Not(Box::new(Self::substitute_type_filter_ids(
                inner, type_field, id_by_path,
            ))),
            other => other.clone(),
        }
    }

    /// Batch-resolve every GTS type path collected from a filter tree to its
    /// surrogate SMALLINT ID with a single `WHERE schema_id IN (...)` query
    /// (mirrors `resolve_ids`'s query shape). Reports the *first* unresolved
    /// path in collection order as `DomainError::Validation` -- matching the
    /// pre-batch code's per-literal error (which failed on the first literal
    /// it walked to and never reached the rest), and keeping the "Unknown
    /// type in filter" wording callers (and tests) match on.
    async fn resolve_paths_for_filter(
        db: &impl DBRunner,
        paths: &[String],
    ) -> Result<std::collections::HashMap<String, i16>, DomainError> {
        use std::collections::{HashMap, HashSet};

        if paths.is_empty() {
            return Ok(HashMap::new());
        }

        let mut seen: HashSet<&str> = HashSet::with_capacity(paths.len());
        let mut unique: Vec<String> = Vec::with_capacity(paths.len());
        for p in paths {
            if seen.insert(p.as_str()) {
                unique.push(p.clone());
            }
        }

        let scope = system_scope();
        let rows = GtsTypeEntity::find()
            .filter(gts_type::Column::SchemaId.is_in(unique.clone()))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let map: HashMap<String, i16> = rows.into_iter().map(|m| (m.schema_id, m.id)).collect();

        if let Some(missing) = unique.iter().find(|p| !map.contains_key(p.as_str())) {
            return Err(DomainError::validation(format!(
                "Unknown type in filter: {missing}"
            )));
        }

        Ok(map)
    }

    /// Resolve allowed parent SMALLINT IDs to string paths.
    async fn load_allowed_parent_types(
        db: &impl DBRunner,
        type_id: i16,
    ) -> Result<Vec<String>, DomainError> {
        let scope = system_scope();
        let parents = AllowedParentEntity::find()
            .filter(gts_type_allowed_parent::Column::TypeId.eq(type_id))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let parent_ids: Vec<i16> = parents.into_iter().map(|m| m.parent_type_id).collect();

        if parent_ids.is_empty() {
            return Ok(Vec::new());
        }

        let parent_types = GtsTypeEntity::find()
            .filter(gts_type::Column::Id.is_in(parent_ids))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let mut codes: Vec<String> = parent_types.into_iter().map(|m| m.schema_id).collect();
        codes.sort();
        Ok(codes)
    }

    /// Resolve allowed membership SMALLINT IDs to string paths.
    async fn load_allowed_membership_types(
        db: &impl DBRunner,
        type_id: i16,
    ) -> Result<Vec<String>, DomainError> {
        let scope = system_scope();
        let memberships = AllowedMembershipEntity::find()
            .filter(gts_type_allowed_membership::Column::TypeId.eq(type_id))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let membership_ids: Vec<i16> = memberships
            .into_iter()
            .map(|m| m.membership_type_id)
            .collect();

        if membership_ids.is_empty() {
            return Ok(Vec::new());
        }

        let membership_types = GtsTypeEntity::find()
            .filter(gts_type::Column::Id.is_in(membership_ids))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let mut codes: Vec<String> = membership_types.into_iter().map(|m| m.schema_id).collect();
        codes.sort();
        Ok(codes)
    }

    /// Assemble a `ResourceGroupType` from a raw model plus resolved junction
    /// data. Shared by `load_full_type` and `load_full_types_batch` so both
    /// derive `can_be_root`/`metadata_schema` identically.
    fn build_resource_group_type(
        type_model: &gts_type::Model,
        allowed_parent_types: Vec<String>,
        allowed_membership_types: Vec<String>,
    ) -> ResourceGroupType {
        // Derive can_be_root from stored metadata_schema internal key.
        // Per the placement invariant: can_be_root == true OR len(allowed_parent_types) >= 1.
        // If no allowed_parent_types, can_be_root must be true.
        let can_be_root = type_model
            .metadata_schema
            .as_ref()
            .and_then(|ms| ms.get("__can_be_root"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(allowed_parent_types.is_empty());

        // Extract the user-facing metadata_schema without internal keys.
        // Non-object schemas are stored under `__user_schema`; restore them on read.
        let metadata_schema = type_model.metadata_schema.as_ref().and_then(|ms| {
            if let serde_json::Value::Object(map) = ms {
                if let Some(user_schema) = map.get("__user_schema") {
                    return Some(user_schema.clone());
                }
                let filtered: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .filter(|(k, _)| !k.starts_with("__"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                if filtered.is_empty() {
                    None
                } else {
                    Some(serde_json::Value::Object(filtered))
                }
            } else {
                Some(ms.clone())
            }
        });

        ResourceGroupType {
            code: type_model.schema_id.clone(),
            can_be_root,
            allowed_parent_types,
            allowed_membership_types,
            metadata_schema,
        }
    }

    /// Batch-resolve full types (junction references) for a whole page of
    /// models in a constant number of queries, regardless of page size.
    ///
    /// One query per junction table across the whole page, one combined
    /// id->code resolution query for every referenced parent/membership
    /// type, then assembles each `ResourceGroupType` in memory (RG-12).
    async fn load_full_types_batch(
        db: &impl DBRunner,
        models: &[gts_type::Model],
    ) -> Result<Vec<ResourceGroupType>, DomainError> {
        if models.is_empty() {
            return Ok(Vec::new());
        }
        let scope = system_scope();
        let type_ids: Vec<i16> = models.iter().map(|m| m.id).collect();

        let parent_rows = AllowedParentEntity::find()
            .filter(gts_type_allowed_parent::Column::TypeId.is_in(type_ids.clone()))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let membership_rows = AllowedMembershipEntity::find()
            .filter(gts_type_allowed_membership::Column::TypeId.is_in(type_ids))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let referenced_ids: std::collections::HashSet<i16> = parent_rows
            .iter()
            .map(|r| r.parent_type_id)
            .chain(membership_rows.iter().map(|r| r.membership_type_id))
            .collect();

        let code_by_id: std::collections::HashMap<i16, String> = if referenced_ids.is_empty() {
            std::collections::HashMap::new()
        } else {
            let ids: Vec<i16> = referenced_ids.into_iter().collect();
            GtsTypeEntity::find()
                .filter(gts_type::Column::Id.is_in(ids))
                .secure()
                .scope_with(&scope)
                .all(db)
                .await
                .map_err(|e| DomainError::database(e.to_string()))?
                .into_iter()
                .map(|m| (m.id, m.schema_id))
                .collect()
        };

        let mut parents_by_type: std::collections::HashMap<i16, Vec<String>> =
            std::collections::HashMap::new();
        for r in &parent_rows {
            if let Some(code) = code_by_id.get(&r.parent_type_id) {
                parents_by_type
                    .entry(r.type_id)
                    .or_default()
                    .push(code.clone());
            }
        }
        let mut memberships_by_type: std::collections::HashMap<i16, Vec<String>> =
            std::collections::HashMap::new();
        for r in &membership_rows {
            if let Some(code) = code_by_id.get(&r.membership_type_id) {
                memberships_by_type
                    .entry(r.type_id)
                    .or_default()
                    .push(code.clone());
            }
        }

        Ok(models
            .iter()
            .map(|m| {
                let mut allowed_parent_types = parents_by_type.remove(&m.id).unwrap_or_default();
                allowed_parent_types.sort();
                let mut allowed_membership_types =
                    memberships_by_type.remove(&m.id).unwrap_or_default();
                allowed_membership_types.sort();
                Self::build_resource_group_type(m, allowed_parent_types, allowed_membership_types)
            })
            .collect())
    }

    /// Find the raw model by code. Used to re-read a row immediately after
    /// `INSERT … RETURNING`-less writes (insert/update); returns a
    /// `DomainError::Database` if the row is unexpectedly missing — i.e. the
    /// write committed but the row vanished (possible only under concurrent
    /// delete with the same `schema_id`).
    async fn find_model_by_code(
        db: &impl DBRunner,
        code: &str,
    ) -> Result<gts_type::Model, DomainError> {
        let scope = system_scope();
        GtsTypeEntity::find()
            .filter(gts_type::Column::SchemaId.eq(code))
            .secure()
            .scope_with(&scope)
            .one(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?
            .ok_or_else(|| {
                DomainError::database(format!(
                    "GTS type row with schema_id={code} not found after write (concurrent delete?)"
                ))
            })
    }
}

#[async_trait]
impl TypeRepositoryTrait for TypeRepository {
    /// Load a full type by its `schema_id` (GTS type path), resolving all
    /// junction table references from SMALLINT IDs to string paths.
    async fn find_by_code<C: DBRunner>(
        &self,
        db: &C,
        code: &str,
    ) -> Result<Option<ResourceGroupType>, DomainError> {
        Ok(self
            .find_by_code_with_id(db, code)
            .await?
            .map(|(_type_id, rg_type)| rg_type))
    }

    /// Same lookup as `find_by_code`, but also returns the surrogate
    /// SMALLINT id, for callers that need both (e.g. a group's
    /// `gts_type_id` FK) from a single query instead of two (RG-11).
    async fn find_by_code_with_id<C: DBRunner>(
        &self,
        db: &C,
        code: &str,
    ) -> Result<Option<(i16, ResourceGroupType)>, DomainError> {
        let scope = system_scope();
        let type_model = GtsTypeEntity::find()
            .filter(gts_type::Column::SchemaId.eq(code))
            .secure()
            .scope_with(&scope)
            .one(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let Some(type_model) = type_model else {
            return Ok(None);
        };

        let type_id = type_model.id;
        self.load_full_type(db, &type_model)
            .await
            .map(|rg_type| Some((type_id, rg_type)))
    }

    /// Load a full type by its surrogate SMALLINT ID.
    async fn load_full_type_by_id<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
    ) -> Result<ResourceGroupType, DomainError> {
        let scope = system_scope();
        let type_model = GtsTypeEntity::find()
            .filter(gts_type::Column::Id.eq(type_id))
            .secure()
            .scope_with(&scope)
            .one(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?
            .ok_or_else(|| DomainError::database(format!("Type ID {type_id} not found")))?;

        self.load_full_type(db, &type_model).await
    }

    /// Load a full type from a model, resolving junction references.
    async fn load_full_type<C: DBRunner>(
        &self,
        db: &C,
        type_model: &gts_type::Model,
    ) -> Result<ResourceGroupType, DomainError> {
        let allowed_parent_types = Self::load_allowed_parent_types(db, type_model.id).await?;
        let allowed_membership_types =
            Self::load_allowed_membership_types(db, type_model.id).await?;

        Ok(Self::build_resource_group_type(
            type_model,
            allowed_parent_types,
            allowed_membership_types,
        ))
    }

    /// Resolve a GTS type path to its surrogate SMALLINT ID.
    async fn resolve_id<C: DBRunner>(
        &self,
        db: &C,
        code: &str,
    ) -> Result<Option<i16>, DomainError> {
        Self::resolve_id(db, code).await
    }

    /// Insert a new GTS type. Returns the inserted model.
    ///
    /// `secure_insert` already returns the fully-populated `Model`,
    /// including the auto-generated SMALLINT id, so no separate re-read is
    /// needed to get it (RG-08).
    ///
    /// Classifies a unique-constraint violation on `schema_id` (the
    /// migration's `UNIQUE(schema_id)`, independent of isolation level) into
    /// the typed `TypeAlreadyExists` domain variant, symmetric with
    /// `GroupRepository::insert`/`MembershipRepository::insert`. Before this,
    /// `create_type_in_tx`'s pre-check (`resolve_id`) plus its SERIALIZABLE
    /// transaction were the only thing standing between a duplicate `code`
    /// and a raw, unclassified `DomainError::Database` -- the SSI abort+retry
    /// papered over the missing mapping rather than the mapping making the
    /// isolation level optional. This does not change when the error is
    /// raised, only that it is now typed (and 409s on the REST layer)
    /// regardless of what isolation level the caller happens to run under.
    async fn insert<C: DBRunner>(
        &self,
        db: &C,
        schema_id: &str,
        metadata_schema: Option<&serde_json::Value>,
    ) -> Result<gts_type::Model, DomainError> {
        let scope = system_scope();

        let model = gts_type::ActiveModel {
            schema_id: Set(schema_id.to_owned()),
            metadata_schema: Set(metadata_schema.cloned()),
            ..Default::default()
        };

        toolkit_db::secure::secure_insert::<GtsTypeEntity>(model, &scope, db)
            .await
            .map_err(|e| {
                if e.is_unique_violation() {
                    DomainError::type_already_exists(schema_id)
                } else {
                    DomainError::database(e.to_string())
                }
            })
    }

    /// Insert allowed parent junction entries.
    ///
    /// Sent as a single multi-row `INSERT` via `secure_insert_many`, not one
    /// `secure_insert` per entry, so statement count stays flat as
    /// `parent_ids` grows (RG-07).
    async fn insert_allowed_parent_types<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
        parent_ids: &[i16],
    ) -> Result<(), DomainError> {
        let scope = system_scope();
        let rows: Vec<gts_type_allowed_parent::ActiveModel> = parent_ids
            .iter()
            .map(|&parent_id| gts_type_allowed_parent::ActiveModel {
                type_id: Set(type_id),
                parent_type_id: Set(parent_id),
            })
            .collect();
        toolkit_db::secure::secure_insert_many::<AllowedParentEntity>(rows, &scope, db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(())
    }

    /// Insert allowed membership junction entries.
    ///
    /// Same RG-07 fix as `insert_allowed_parent_types`, batched via
    /// `secure_insert_many`.
    async fn insert_allowed_membership_types<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
        membership_ids: &[i16],
    ) -> Result<(), DomainError> {
        let scope = system_scope();
        let rows: Vec<gts_type_allowed_membership::ActiveModel> = membership_ids
            .iter()
            .map(|&membership_id| gts_type_allowed_membership::ActiveModel {
                type_id: Set(type_id),
                membership_type_id: Set(membership_id),
            })
            .collect();
        toolkit_db::secure::secure_insert_many::<AllowedMembershipEntity>(rows, &scope, db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(())
    }

    /// Delete all allowed parent junction entries for a type.
    async fn delete_allowed_parent_types<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
    ) -> Result<(), DomainError> {
        let scope = system_scope();
        AllowedParentEntity::delete_many()
            .filter(gts_type_allowed_parent::Column::TypeId.eq(type_id))
            .secure()
            .scope_with(&scope)
            .exec(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(())
    }

    /// Delete all allowed membership junction entries for a type.
    async fn delete_allowed_membership_types<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
    ) -> Result<(), DomainError> {
        let scope = system_scope();
        AllowedMembershipEntity::delete_many()
            .filter(gts_type_allowed_membership::Column::TypeId.eq(type_id))
            .secure()
            .scope_with(&scope)
            .exec(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(())
    }

    /// Update the `gts_type` row (`metadata_schema`, `updated_at`).
    async fn update_type<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
        code: &str,
        metadata_schema: Option<&serde_json::Value>,
    ) -> Result<gts_type::Model, DomainError> {
        let scope = system_scope();

        // Use SecureUpdateMany for scoped update
        GtsTypeEntity::update_many()
            .filter(gts_type::Column::Id.eq(type_id))
            .secure()
            .col_expr(
                gts_type::Column::MetadataSchema,
                Expr::value(metadata_schema.cloned()),
            )
            .col_expr(
                gts_type::Column::UpdatedAt,
                Expr::value(time::OffsetDateTime::now_utc()),
            )
            .scope_with(&scope)
            .exec(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        Self::find_model_by_code(db, code).await
    }

    /// Delete a GTS type by its surrogate ID. CASCADE handles junction rows.
    async fn delete_by_id<C: DBRunner>(&self, db: &C, type_id: i16) -> Result<(), DomainError> {
        let scope = system_scope();
        GtsTypeEntity::delete_many()
            .filter(gts_type::Column::Id.eq(type_id))
            .secure()
            .scope_with(&scope)
            .exec(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(())
    }

    /// Count resource groups of a given type.
    async fn count_groups_of_type<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
    ) -> Result<u64, DomainError> {
        let scope = system_scope();
        let count = ResourceGroupEntity::find()
            .filter(rg_entity::Column::GtsTypeId.eq(type_id))
            .secure()
            .scope_with(&scope)
            .count(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;
        Ok(count)
    }

    /// Batch replacement for a removed-allowed-parent-types sweep -- see the
    /// trait doc comment for the full rationale (N+1 audit finding (b)).
    ///
    /// Three queries regardless of how many `parent_codes` are checked:
    /// resolve every candidate path to its surrogate id, load every group
    /// of `child_type_id` once, then batch-match those groups' actual
    /// parents against every candidate parent-type id at once.
    async fn find_groups_violating_removed_parents<C: DBRunner>(
        &self,
        db: &C,
        child_type_id: i16,
        parent_codes: &[String],
    ) -> Result<Vec<(String, uuid::Uuid, String)>, DomainError> {
        if parent_codes.is_empty() {
            return Ok(Vec::new());
        }
        let scope = system_scope();

        // Resolve every candidate parent-type path in one query. A path
        // that doesn't currently resolve to any gts_type row is silently
        // dropped -- no group can reference a type that no longer exists.
        let parent_types = GtsTypeEntity::find()
            .filter(gts_type::Column::SchemaId.is_in(parent_codes.to_vec()))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        if parent_types.is_empty() {
            return Ok(Vec::new());
        }

        let code_by_id: std::collections::HashMap<i16, String> = parent_types
            .iter()
            .map(|t| (t.id, t.schema_id.clone()))
            .collect();
        let parent_type_ids: Vec<i16> = parent_types.iter().map(|t| t.id).collect();

        // Groups of the child type being updated -- one query, independent
        // of how many candidate parent types there are.
        let groups: Vec<rg_entity::Model> = ResourceGroupEntity::find()
            .filter(rg_entity::Column::GtsTypeId.eq(child_type_id))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let parent_ids: Vec<uuid::Uuid> = groups.iter().filter_map(|g| g.parent_id).collect();
        if parent_ids.is_empty() {
            return Ok(Vec::new());
        }

        // Which of those groups' actual parents are of one of the
        // candidate parent types -- one query for every candidate at once,
        // not one per candidate.
        let parents: Vec<rg_entity::Model> = ResourceGroupEntity::find()
            .filter(rg_entity::Column::Id.is_in(parent_ids))
            .filter(rg_entity::Column::GtsTypeId.is_in(parent_type_ids))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let parent_type_by_id: std::collections::HashMap<uuid::Uuid, i16> =
            parents.into_iter().map(|p| (p.id, p.gts_type_id)).collect();

        Ok(groups
            .into_iter()
            .filter_map(|g| {
                let pid = g.parent_id?;
                let parent_type_id = *parent_type_by_id.get(&pid)?;
                let code = code_by_id.get(&parent_type_id)?.clone();
                Some((code, g.id, g.name))
            })
            .collect())
    }

    /// Find root groups (`parent_id` IS NULL) of a given type.
    async fn find_root_groups_of_type<C: DBRunner>(
        &self,
        db: &C,
        type_id: i16,
    ) -> Result<Vec<(uuid::Uuid, String)>, DomainError> {
        let scope = system_scope();
        let groups: Vec<rg_entity::Model> = ResourceGroupEntity::find()
            .filter(rg_entity::Column::GtsTypeId.eq(type_id))
            .filter(Expr::col(rg_entity::Column::ParentId).is_null())
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        Ok(groups.into_iter().map(|g| (g.id, g.name)).collect())
    }

    /// List GTS types with `OData` filtering and cursor-based pagination.
    async fn list_types<C: DBRunner>(
        &self,
        db: &C,
        query: &ODataQuery,
    ) -> Result<Page<ResourceGroupType>, DomainError> {
        let scope = system_scope();
        let base_query = GtsTypeEntity::find().secure().scope_with(&scope);

        let page = paginate_odata::<TypeFilterField, TypeODataMapper, _, _, _, _>(
            base_query,
            db,
            query,
            ("code", SortDir::Desc),
            TYPE_LIMIT_CFG,
            |m: gts_type::Model| m,
        )
        .await
        .map_err(|e| DomainError::database(e.to_string()))?;

        // Resolve full types (junction references) for the whole page in a
        // constant number of queries (fixes known defect RG-12).
        let types = Self::load_full_types_batch(db, &page.items).await?;

        Ok(Page {
            items: types,
            page_info: page.page_info,
        })
    }

    /// Resolve multiple GTS type paths to their surrogate IDs.
    async fn resolve_ids<C: DBRunner>(
        &self,
        db: &C,
        codes: &[String],
    ) -> Result<Vec<i16>, DomainError> {
        if codes.is_empty() {
            return Ok(Vec::new());
        }

        let scope = system_scope();
        let types = GtsTypeEntity::find()
            .filter(gts_type::Column::SchemaId.is_in(codes.to_vec()))
            .secure()
            .scope_with(&scope)
            .all(db)
            .await
            .map_err(|e| DomainError::database(e.to_string()))?;

        let found_codes: Vec<&str> = types.iter().map(|t| t.schema_id.as_str()).collect();
        let missing: Vec<&str> = codes
            .iter()
            .filter(|c| !found_codes.contains(&c.as_str()))
            .map(String::as_str)
            .collect();

        if !missing.is_empty() {
            return Err(DomainError::validation(format!(
                "Referenced types not found: {}",
                missing.join(", ")
            )));
        }

        Ok(types.into_iter().map(|t| t.id).collect())
    }
}
