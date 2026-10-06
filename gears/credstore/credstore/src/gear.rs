// Updated: 2026-10-06 by Constructor Tech
//! `ToolKit` gear declaration, dependency wiring, and managed lifecycle.
//!
//! Initialization builds the domain service and registers its SDK client and
//! REST routes. The gear runs no background work at all (ADR-0006): no
//! outbox, no workers, no timers, no database polling, no work at startup.
//! Every store side effect is executed by the request that caused it, and the
//! leftovers of an interrupted request are healed by a later request that
//! touches the same record. The lifecycle entry only reports ready and waits
//! for cancellation.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use authz_resolver_sdk::{AuthZResolverApi, PolicyEnforcer};
use tenant_resolver_sdk::TenantResolverClient;
use tokio_util::sync::CancellationToken;
use toolkit::api::OpenApiRegistry;
use toolkit::contracts::{DatabaseCapability, SystemCapability};
use toolkit::lifecycle::ReadySignal;
use toolkit::{Gear, GearCtx, RestApiCapability};
use toolkit_db::DBProvider;
use tracing::info;

use types_registry_sdk::TypesRegistryClient;

use crate::client::CredStoreLocalClient;
use crate::config::CredStoreConfig;
use crate::domain::ports::audit::AuditSink;
use crate::domain::ports::metrics::CredStoreMetricsPort;
use crate::domain::ports::plugin::PluginSelector;
use crate::domain::secret::service::{ListSettings, Service, WriteSettings};
use crate::infra::audit::{self, BrokerResolver, DEFAULT_PUBLISH_TIMEOUT, EventBrokerAuditSink};
use crate::infra::metrics::CredStoreMetricsMeter;
use crate::infra::plugin_select::GtsCredStorePluginSelector;
use crate::infra::storage::repo_impl::SecretRepoImpl;
use crate::infra::tenant_resolver::TenantResolverDir;
use crate::infra::types_registry::GtsSecretTypeResolver;

// `system` capability is required in this platform: consumers like `oagw` are
// system modules and resolve `CredStoreClientV1` from the ClientHub during their
// `init`. System modules initialize before non-system ones
// (`modules_by_system_priority`), so credstore must also be a system module to
// register its client before those consumers init.
#[toolkit::gear(
    name = "credstore",
    deps = [authz_resolver, tenant_resolver, types_registry],
    capabilities = [system, db, rest, stateful],
    lifecycle(entry = "serve", stop_timeout = "30s", await_ready)
)]
pub struct CredStoreGear {
    service: OnceLock<Arc<Service>>,
}

impl Default for CredStoreGear {
    fn default() -> Self {
        Self {
            service: OnceLock::new(),
        }
    }
}

impl CredStoreGear {
    #[allow(
        clippy::redundant_pub_crate,
        reason = "module-private serve entry-point invoked by the toolkit runtime"
    )]
    pub(crate) async fn serve(
        self: Arc<Self>,
        cancel: CancellationToken,
        ready: ReadySignal,
    ) -> anyhow::Result<()> {
        if self.service.get().is_none() {
            anyhow::bail!("credstore: serve invoked before init");
        }

        ready.notify();
        info!(
            target: "credstore.lifecycle",
            "credstore gear serving; no background work: store cleanup runs inside requests"
        );

        cancel.cancelled().await;

        info!(target: "credstore.lifecycle", "credstore lifecycle cancelled");
        Ok(())
    }
}

#[async_trait]
impl Gear for CredStoreGear {
    #[tracing::instrument(skip_all, fields(module = "credstore"))]
    async fn init(&self, ctx: &GearCtx) -> anyhow::Result<()> {
        let cfg: CredStoreConfig = ctx.config_or_default()?;
        cfg.validate()
            .map_err(|err| anyhow::anyhow!("credstore config invalid: {err}"))?;
        info!(vendor = %cfg.vendor, "initializing credstore module");

        let db_raw = ctx.db_required()?;
        let db: Arc<DBProvider<crate::domain::error::DomainError>> =
            Arc::new(DBProvider::new(db_raw.db()));

        let repo = Arc::new(SecretRepoImpl::new(Arc::clone(&db)));

        let authz_client = ctx
            .client_hub()
            .get::<dyn AuthZResolverApi>()
            .map_err(|e| anyhow::anyhow!("failed to get AuthZResolverApi: {e}"))?;
        // No PDP capabilities: credstore projects no authorization tables
        // (no `tenant_closure`), so the PDP hands it pre-expanded, flat
        // tenant predicates (AUTHZ_USAGE_SCENARIOS S09–S11).
        let enforcer = PolicyEnforcer::new(authz_client);
        info!("authz-resolver client resolved from client hub; PolicyEnforcer wired");

        let tr_client = ctx
            .client_hub()
            .get::<dyn TenantResolverClient>()
            .map_err(|e| anyhow::anyhow!("failed to get TenantResolverClient: {e}"))?;

        let metrics: Arc<dyn CredStoreMetricsPort> = Arc::new(CredStoreMetricsMeter::from_global());

        let dir = Arc::new(TenantResolverDir::new(tr_client, Arc::clone(&metrics)));

        let plugins = Arc::new(GtsCredStorePluginSelector::new(
            ctx.client_hub(),
            cfg.vendor.clone(),
        ));

        // Fail-closed: without the types-registry client no secret type can
        // be resolved, so credstore must not come up (types-registry is a
        // hard `deps` and initializes first).
        let registry = ctx
            .client_hub()
            .get::<dyn TypesRegistryClient>()
            .map_err(|e| anyhow::anyhow!("failed to get TypesRegistryClient: {e}"))?;
        let types = Arc::new(GtsSecretTypeResolver::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
        ));
        info!("types-registry client resolved from client hub; secret-type resolver wired");

        // Audit (`cpt-cf-credstore-nfr-audit`): the event broker is a
        // non-blocking dependency. It is deliberately NOT in `deps` and its
        // client is resolved per event, so credstore starts and works with
        // the broker absent; every dropped event is counted instead.
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            audit::register_audit_types(registry.as_ref()),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(
                target: "credstore.audit",
                error = %e,
                "credstore audit topic/event type not registered; publishing will fail and be \
                 counted until they are"
            ),
            Err(_) => tracing::warn!(
                target: "credstore.audit",
                "registering the credstore audit topic/event type timed out; publishing will \
                 fail and be counted until they are registered"
            ),
        }
        let hub = ctx.client_hub();
        let resolve: BrokerResolver =
            Arc::new(move || hub.try_get::<dyn event_broker_sdk::EventBrokerApi>());
        let audit_sink: Arc<dyn AuditSink> = Arc::new(EventBrokerAuditSink::new(
            resolve,
            Arc::clone(&metrics),
            DEFAULT_PUBLISH_TIMEOUT,
        ));

        let svc = Arc::new(
            Service::new(
                repo,
                dir,
                enforcer,
                Arc::clone(&plugins) as Arc<dyn PluginSelector>,
                types,
                Arc::clone(&metrics),
                ListSettings {
                    max_limit: cfg.list.max_limit,
                },
            )
            .with_audit(audit_sink)
            .with_write_settings(WriteSettings {
                intent_lease: std::time::Duration::from_secs(cfg.write.intent_lease_secs),
            }),
        );

        self.service
            .set(Arc::clone(&svc))
            .map_err(|_| anyhow::anyhow!("{} module already initialized", Self::MODULE_NAME))?;

        let client: Arc<dyn credstore_sdk::CredStoreClientV1> =
            Arc::new(CredStoreLocalClient::new(svc));
        ctx.client_hub()
            .register::<dyn credstore_sdk::CredStoreClientV1>(client);

        info!("credstore module initialized");
        Ok(())
    }
}

// Empty system capability: credstore needs no pre_init/post_init work, only the
// system-priority init ordering (see the module attribute above).
impl SystemCapability for CredStoreGear {}

impl DatabaseCapability for CredStoreGear {
    fn migrations(&self) -> Vec<Box<dyn sea_orm_migration::MigrationTrait>> {
        use sea_orm_migration::MigratorTrait;
        info!("providing credstore database migrations");
        crate::infra::storage::migrations::Migrator::migrations()
    }
}

impl RestApiCapability for CredStoreGear {
    fn register_rest(
        &self,
        _ctx: &GearCtx,
        router: axum::Router,
        openapi: &dyn OpenApiRegistry,
    ) -> anyhow::Result<axum::Router> {
        info!("registering credstore REST routes");
        let svc = self
            .service
            .get()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("credstore Service not initialized"))?;
        let router = crate::api::rest::register_routes(router, openapi, svc);
        info!("credstore REST routes registered");
        Ok(router)
    }
}
