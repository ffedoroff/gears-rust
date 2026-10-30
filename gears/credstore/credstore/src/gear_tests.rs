//! Gear-level tests for [`CredStoreGear`].
#![allow(clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tenant_resolver_sdk::{
    GetAncestorsOptions, GetAncestorsResponse, GetDescendantsOptions, GetDescendantsResponse,
    GetTenantsOptions, IsAncestorOptions, TenantId, TenantInfo, TenantResolverClient,
    TenantResolverError,
};
use tokio_util::sync::CancellationToken;
use toolkit::{ClientHub, ConfigProvider, Gear, GearCtx};
use toolkit_canonical_errors::CanonicalError;
use toolkit_db::{ConnectOpts, DBProvider, connect_db};
use toolkit_security::SecurityContext;
use types_registry_sdk::testing::MockTypesRegistryClient;
use types_registry_sdk::{
    GtsInstance, GtsTypeSchema, InstanceQuery, RegisterResult, TypeSchemaQuery, TypesRegistryClient,
};
use uuid::Uuid;

use super::CredStoreGear;

/// A config provider answering the gear from one `gears.credstore` section.
struct FixedConfig(Value);

impl ConfigProvider for FixedConfig {
    fn get_gear_config(&self, gear: &str) -> Option<&Value> {
        (gear == CredStoreGear::MODULE_NAME).then_some(&self.0)
    }
}

/// `init` only stores the tenant resolver; nothing here is called.
struct UnusedTenantResolver;

#[async_trait]
impl TenantResolverClient for UnusedTenantResolver {
    async fn get_tenant(
        &self,
        _ctx: &SecurityContext,
        _id: TenantId,
    ) -> Result<TenantInfo, TenantResolverError> {
        Err(TenantResolverError::Unauthorized)
    }

    async fn get_root_tenant(
        &self,
        _ctx: &SecurityContext,
    ) -> Result<TenantInfo, TenantResolverError> {
        Err(TenantResolverError::Unauthorized)
    }

    async fn get_tenants(
        &self,
        _ctx: &SecurityContext,
        _ids: &[TenantId],
        _options: &GetTenantsOptions,
    ) -> Result<Vec<TenantInfo>, TenantResolverError> {
        Err(TenantResolverError::Unauthorized)
    }

    async fn get_ancestors(
        &self,
        _ctx: &SecurityContext,
        _id: TenantId,
        _options: &GetAncestorsOptions,
    ) -> Result<GetAncestorsResponse, TenantResolverError> {
        Err(TenantResolverError::Unauthorized)
    }

    async fn get_descendants(
        &self,
        _ctx: &SecurityContext,
        _id: TenantId,
        _options: &GetDescendantsOptions,
    ) -> Result<GetDescendantsResponse, TenantResolverError> {
        Err(TenantResolverError::Unauthorized)
    }

    async fn is_ancestor(
        &self,
        _ctx: &SecurityContext,
        _ancestor_id: TenantId,
        _descendant_id: TenantId,
        _options: &IsAncestorOptions,
    ) -> Result<bool, TenantResolverError> {
        Err(TenantResolverError::Unauthorized)
    }
}

/// Types registry that accepts every registration, which is all `init` asks
/// of it (the credential type schemas and the audit topic). The SDK mock
/// refuses non-empty registrations; every other call goes to it.
struct AcceptingTypesRegistry(MockTypesRegistryClient);

/// Every entity accepted, under the id it names in `key`.
fn accepted(entities: &[Value], key: &str) -> Vec<RegisterResult> {
    entities
        .iter()
        .map(|e| RegisterResult::Ok {
            gts_id: e[key].as_str().unwrap_or_default().to_owned(),
        })
        .collect()
}

#[async_trait]
impl TypesRegistryClient for AcceptingTypesRegistry {
    async fn register(&self, entities: Vec<Value>) -> Result<Vec<RegisterResult>, CanonicalError> {
        Ok(accepted(&entities, "$id"))
    }
    async fn register_type_schemas(
        &self,
        type_schemas: Vec<Value>,
    ) -> Result<Vec<RegisterResult>, CanonicalError> {
        Ok(accepted(&type_schemas, "$id"))
    }
    async fn get_type_schema(&self, type_id: &str) -> Result<GtsTypeSchema, CanonicalError> {
        self.0.get_type_schema(type_id).await
    }
    async fn get_type_schema_by_uuid(
        &self,
        type_uuid: Uuid,
    ) -> Result<GtsTypeSchema, CanonicalError> {
        self.0.get_type_schema_by_uuid(type_uuid).await
    }
    async fn get_type_schemas(
        &self,
        type_ids: Vec<String>,
    ) -> HashMap<String, Result<GtsTypeSchema, CanonicalError>> {
        self.0.get_type_schemas(type_ids).await
    }
    async fn get_type_schemas_by_uuid(
        &self,
        type_uuids: Vec<Uuid>,
    ) -> HashMap<Uuid, Result<GtsTypeSchema, CanonicalError>> {
        self.0.get_type_schemas_by_uuid(type_uuids).await
    }
    async fn list_type_schemas(
        &self,
        query: TypeSchemaQuery,
    ) -> Result<Vec<GtsTypeSchema>, CanonicalError> {
        self.0.list_type_schemas(query).await
    }
    async fn register_instances(
        &self,
        instances: Vec<Value>,
    ) -> Result<Vec<RegisterResult>, CanonicalError> {
        Ok(accepted(&instances, "id"))
    }
    async fn get_instance(&self, id: &str) -> Result<GtsInstance, CanonicalError> {
        self.0.get_instance(id).await
    }
    async fn get_instance_by_uuid(&self, uuid: Uuid) -> Result<GtsInstance, CanonicalError> {
        self.0.get_instance_by_uuid(uuid).await
    }
    async fn get_instances(
        &self,
        ids: Vec<String>,
    ) -> HashMap<String, Result<GtsInstance, CanonicalError>> {
        self.0.get_instances(ids).await
    }
    async fn get_instances_by_uuid(
        &self,
        uuids: Vec<Uuid>,
    ) -> HashMap<Uuid, Result<GtsInstance, CanonicalError>> {
        self.0.get_instances_by_uuid(uuids).await
    }
    async fn list_instances(
        &self,
        query: InstanceQuery,
    ) -> Result<Vec<GtsInstance>, CanonicalError> {
        self.0.list_instances(query).await
    }
}

/// `AuthZ` is a consumed contract, wired after `init` (locally or remotely), so
/// `init` must not look it up.
#[tokio::test]
async fn init_does_not_need_authz_in_the_hub() {
    let dsn = format!(
        "sqlite:file:credstore_gear_{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );
    let db = connect_db(&dsn, ConnectOpts::default())
        .await
        .expect("connect sqlite");

    let hub = Arc::new(ClientHub::new());
    hub.register::<dyn TenantResolverClient>(Arc::new(UnusedTenantResolver));
    hub.register::<dyn TypesRegistryClient>(Arc::new(AcceptingTypesRegistry(
        MockTypesRegistryClient::new(),
    )));

    let ctx = GearCtx::new(
        CredStoreGear::MODULE_NAME,
        Uuid::new_v4(),
        Arc::new(FixedConfig(json!({ "config": {} }))),
        hub,
        CancellationToken::default(),
    )
    .with_db(DBProvider::new(db));

    CredStoreGear::default()
        .init(&ctx)
        .await
        .expect("init without AuthZ in the hub");
}
