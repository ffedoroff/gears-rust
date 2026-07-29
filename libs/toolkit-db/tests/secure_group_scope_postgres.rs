#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]
#![cfg(all(feature = "integration", feature = "pg"))]

//! Real-PostgreSQL reproduction of VHP-2344 defect A.
//!
//! `ScopeFilter::InGroup` / `ScopeFilter::InGroupSubtree` compile to a
//! subquery that compares `resource_group_membership.resource_id` (`TEXT`,
//! see resource-group's
//! `gears/system/resource-group/resource-group/src/infra/storage/migrations/m20260306_000001_initial.rs`)
//! directly against the scoped entity's own resource column via
//! `col.into_expr().in_subquery(...)`
//! (`libs/toolkit-db/src/secure/cond.rs::build_constraint_condition`).
//!
//! Most scoped entities key their resource column as `Uuid` (e.g.
//! `file-storage`'s `file.rs`, `resource_col = "file_id"`). PostgreSQL does
//! not implicitly cast `uuid = text`, so the generated SQL is rejected
//! outright. The existing `cond.rs` unit tests only assert
//! `format!("{cond:?}")`  -- the *shape* of the query tree -- and can never
//! observe this, since they never send the SQL to a real backend. This
//! suite does, against a `testcontainers` PostgreSQL.
//!
//! **Why a Rust `testcontainers` test, not pytest E2E:** this is a
//! deliberate, written-down deviation from
//! `docs/toolkit_unified_system/12_unit_testing.md` (which routes
//! PostgreSQL-specific behavior to E2E) and `13_e2e_testing.md` (which
//! defines E2E as pytest against a running `cf-gears-server`). Precedent:
//! resource-group's PR #4269 established this pattern -- real Postgres via
//! `testcontainers`, in Rust, for a dialect-specific bug a pytest-over-HTTP
//! test could only see as an opaque 500 -- with `pg_concurrency_test.rs`
//! plus the `test-rg-pg` `Makefile` target and its CI step; this file
//! follows the same shape for `toolkit-db`'s own `secure` module, alongside
//! this crate's pre-existing `pg`+`integration` suite (`make test-pg`,
//! already wired into CI). It stays out of the default suite (gated behind
//! `#![cfg(all(feature = "integration", feature = "pg"))]`), so it does not
//! violate the unit-testing guide's speed requirement. And it gives a
//! diagnosis pytest cannot: if `InGroup`/`InGroupSubtree` ever regress, the
//! failure carries PostgreSQL's actual rejected-SQL text ("operator does
//! not exist: uuid = text") directly, not just the HTTP 500 a client of
//! whichever gear owns the scoped entity (e.g. file-storage) would see. See
//! resource-group's `docs/db-behavior-audit.md` for the fuller writeup of
//! this decision.
//!
//! Run via:
//! ```sh
//! cargo nextest run -p cf-gears-toolkit-db --features integration,pg \
//!     --test secure_group_scope_postgres
//! ```

mod common;

use anyhow::{Context, Result};
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use sea_orm_migration::prelude as mig;
use sea_orm_migration::sea_orm::ConnectionTrait;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::secure::{DBRunner, ScopableEntity, ScopeError, SecureEntityExt, secure_insert};
use toolkit_db::{ConnectOpts, connect_db};
use toolkit_security::{AccessScope, ScopeConstraint, ScopeFilter, ScopeValue, pep_properties};
use uuid::Uuid;

/// The scoped entity under test: a `Uuid`-keyed resource, mirroring
/// `file-storage`'s `file.rs` (`resource_col = "file_id"`) -- the shape most
/// scoped entities in the monorepo share.
mod resource_ent {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "secure_group_scope_pg_resource")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: Uuid,
        pub tenant_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

impl ScopableEntity for resource_ent::Entity {
    fn tenant_col() -> Option<<Self as EntityTrait>::Column> {
        Some(resource_ent::Column::TenantId)
    }
    fn resource_col() -> Option<<Self as EntityTrait>::Column> {
        Some(resource_ent::Column::Id)
    }
    fn owner_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn type_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn resolve_property(property: &str) -> Option<<Self as EntityTrait>::Column> {
        match property {
            p if p == pep_properties::OWNER_TENANT_ID => Self::tenant_col(),
            p if p == pep_properties::RESOURCE_ID => Self::resource_col(),
            _ => None,
        }
    }
}

/// A bare-bones mirror of resource-group's `resource_group_membership` table
/// -- keeps only the columns `cond.rs`'s subquery touches. Not itself scoped,
/// matching RG's own entity (`#[secure(no_tenant, no_resource, no_owner, no_type)]`).
mod membership_ent {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "resource_group_membership")]
    #[allow(clippy::struct_field_names)]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub group_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub gts_type_id: i16,
        #[sea_orm(primary_key, auto_increment = false)]
        pub resource_id: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

impl ScopableEntity for membership_ent::Entity {
    fn tenant_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn resource_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn owner_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn type_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn resolve_property(_property: &str) -> Option<<Self as EntityTrait>::Column> {
        None
    }
}

/// Mirror of resource-group's `resource_group_closure` table -- only needed
/// for the `InGroupSubtree` scenario below.
mod closure_ent {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "resource_group_closure")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub ancestor_id: Uuid,
        #[sea_orm(primary_key, auto_increment = false)]
        pub descendant_id: Uuid,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

impl ScopableEntity for closure_ent::Entity {
    fn tenant_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn resource_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn owner_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn type_col() -> Option<<Self as EntityTrait>::Column> {
        None
    }
    fn resolve_property(_property: &str) -> Option<<Self as EntityTrait>::Column> {
        None
    }
}

struct CreateFixtures;

impl mig::MigrationName for CreateFixtures {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "m001_secure_group_scope_pg_fixtures"
    }
}

#[async_trait::async_trait]
impl mig::MigrationTrait for CreateFixtures {
    async fn up(&self, manager: &mig::SchemaManager) -> Result<(), mig::DbErr> {
        // Real-Postgres-only DDL -- this suite is gated on `feature = "pg"`
        // and only ever runs against the testcontainers Postgres brought up
        // by `common::bring_up_postgres()`.
        manager
            .get_connection()
            .execute_unprepared(
                r"
CREATE TABLE IF NOT EXISTS secure_group_scope_pg_resource (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_group_membership (
    group_id UUID NOT NULL,
    gts_type_id SMALLINT NOT NULL,
    resource_id TEXT NOT NULL,
    PRIMARY KEY (group_id, gts_type_id, resource_id)
);

CREATE TABLE IF NOT EXISTS resource_group_closure (
    ancestor_id UUID NOT NULL,
    descendant_id UUID NOT NULL,
    PRIMARY KEY (ancestor_id, descendant_id)
);
                ",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &mig::SchemaManager) -> Result<(), mig::DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r"
DROP TABLE IF EXISTS resource_group_closure;
DROP TABLE IF EXISTS resource_group_membership;
DROP TABLE IF EXISTS secure_group_scope_pg_resource;
                ",
            )
            .await?;
        Ok(())
    }
}

async fn seed_resource(
    conn: &impl DBRunner,
    resource_id: Uuid,
    tenant_id: Uuid,
) -> Result<(), ScopeError> {
    let scope = AccessScope::for_tenant(tenant_id);
    let am = resource_ent::ActiveModel {
        id: Set(resource_id),
        tenant_id: Set(tenant_id),
    };
    secure_insert::<resource_ent::Entity>(am, &scope, conn).await?;
    Ok(())
}

async fn seed_membership(
    conn: &impl DBRunner,
    group_id: Uuid,
    gts_type_id: i16,
    resource_id: Uuid,
) -> Result<(), ScopeError> {
    let am = membership_ent::ActiveModel {
        group_id: Set(group_id),
        gts_type_id: Set(gts_type_id),
        resource_id: Set(resource_id.to_string()),
    };
    secure_insert::<membership_ent::Entity>(am, &AccessScope::allow_all(), conn).await?;
    Ok(())
}

async fn seed_closure(
    conn: &impl DBRunner,
    ancestor_id: Uuid,
    descendant_id: Uuid,
) -> Result<(), ScopeError> {
    let am = closure_ent::ActiveModel {
        ancestor_id: Set(ancestor_id),
        descendant_id: Set(descendant_id),
    };
    secure_insert::<closure_ent::Entity>(am, &AccessScope::allow_all(), conn).await?;
    Ok(())
}

/// VHP-2344 defect A, `InGroup` branch: the resource's `Uuid` primary key
/// must be comparable against `resource_group_membership.resource_id`
/// (`TEXT`) without PostgreSQL rejecting the query outright, and the filter
/// must return exactly the resource holding a membership row in the scoped
/// group -- not an unrelated resource with no membership at all.
#[tokio::test]
async fn in_group_filter_executes_on_postgres() -> Result<()> {
    let dut = common::bring_up_postgres().await?;
    let db = connect_db(&dut.url, ConnectOpts::default()).await?;
    run_migrations_for_testing(&db, vec![Box::new(CreateFixtures)]).await?;

    let conn = db.conn().context("acquire db conn")?;

    let tenant_id = Uuid::new_v4();
    let resource_id = Uuid::new_v4();
    let unrelated_resource_id = Uuid::new_v4();
    let group_id = Uuid::new_v4();

    seed_resource(&conn, resource_id, tenant_id)
        .await
        .context("seed resource row")?;
    seed_resource(&conn, unrelated_resource_id, tenant_id)
        .await
        .context("seed unrelated resource row")?;
    seed_membership(&conn, group_id, 1, resource_id)
        .await
        .context("seed membership row")?;

    let scope =
        AccessScope::from_constraints(vec![ScopeConstraint::new(vec![ScopeFilter::in_group(
            pep_properties::RESOURCE_ID,
            vec![ScopeValue::Uuid(group_id)],
        )])]);

    let result = resource_ent::Entity::find()
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await;

    match result {
        Ok(rows) => {
            let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
            assert_eq!(
                ids,
                vec![resource_id],
                "InGroup must return exactly the resource that holds a membership row \
                 in the scoped group, not the unrelated resource: {ids:?}"
            );
        }
        Err(e) => panic!(
            "ScopeFilter::InGroup produced SQL PostgreSQL rejected -- VHP-2344 defect A \
             (uuid = text mismatch between the entity's resource column and \
             resource_group_membership.resource_id) is unfixed: {e}"
        ),
    }

    Ok(())
}

/// VHP-2344 defect A, `InGroupSubtree` branch: same `uuid = text` mismatch,
/// reached through the closure-table subquery instead of a direct group list.
#[tokio::test]
async fn in_group_subtree_filter_executes_on_postgres() -> Result<()> {
    let dut = common::bring_up_postgres().await?;
    let db = connect_db(&dut.url, ConnectOpts::default()).await?;
    run_migrations_for_testing(&db, vec![Box::new(CreateFixtures)]).await?;

    let conn = db.conn().context("acquire db conn")?;

    let tenant_id = Uuid::new_v4();
    let resource_id = Uuid::new_v4();
    let ancestor_group_id = Uuid::new_v4();
    let descendant_group_id = Uuid::new_v4();

    seed_resource(&conn, resource_id, tenant_id)
        .await
        .context("seed resource row")?;
    // The closure invariant also carries a self-row for every group, but
    // only the ancestor -> descendant edge matters for this reproduction.
    seed_closure(&conn, ancestor_group_id, descendant_group_id)
        .await
        .context("seed closure row")?;
    seed_membership(&conn, descendant_group_id, 1, resource_id)
        .await
        .context("seed membership row")?;

    let scope = AccessScope::from_constraints(vec![ScopeConstraint::new(vec![
        ScopeFilter::in_group_subtree(
            pep_properties::RESOURCE_ID,
            vec![ScopeValue::Uuid(ancestor_group_id)],
        ),
    ])]);

    let result = resource_ent::Entity::find()
        .secure()
        .scope_with(&scope)
        .all(&conn)
        .await;

    match result {
        Ok(rows) => {
            let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
            assert_eq!(
                ids,
                vec![resource_id],
                "InGroupSubtree must resolve through the closure table to the \
                 resource held by the descendant group: {ids:?}"
            );
        }
        Err(e) => panic!(
            "ScopeFilter::InGroupSubtree produced SQL PostgreSQL rejected -- VHP-2344 \
             defect A (uuid = text mismatch) is unfixed: {e}"
        ),
    }

    Ok(())
}
