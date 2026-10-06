// Created: 2026-10-04 by Constructor Tech
// Updated: 2026-10-06 by Constructor Tech
//! Shared fixtures of the integration tests: a database in the SHIPPED schema
//! (`m0001` applied through the platform runner, exactly as a deployed gear had
//! it), a fake OLD store, a fake NEW store (the V2
//! contract) with fault injection, and helpers to run the tool and to compare
//! end states.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::use_debug,
    dead_code,
    reason = "test fixtures: a setup failure IS the test failure, and each test binary uses a different subset"
)]

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use credstore::CredStoreGear;
use credstore::infra::storage::migrations::m0001_initial_schema;
use credstore_sdk::{
    CredStoreError, CredStorePluginClientV2, DestroySelector, SecretValue, StoreKey, ValueVersion,
};
use credstore_value_migration::fence::{FENCE_KEY_REF, compute_fp};
use credstore_value_migration::{Exit, LegacyError, LegacyStore, Tuning, run_with};
use sea_orm::{ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, Statement, Value};
use tempfile::TempDir;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use tokio::sync::Notify;
use toolkit_db::migration_runner::run_migrations_for_gear;
use toolkit_db::{ConnectOpts, Db, connect_db};
use uuid::Uuid;

/// The old fence key the standard fixture stores.
pub const FENCE_KEY: [u8; 32] = [7; 32];
/// Secret type A / B (any two distinct UUIDs).
pub const TYPE_A: Uuid = Uuid::from_u128(0xa);
pub const TYPE_B: Uuid = Uuid::from_u128(0xb);

/// A tenant with a readable number.
pub fn tenant(n: u128) -> Uuid {
    Uuid::from_u128(0x1000 + n)
}

/// A row id with a readable number.
pub fn rid(n: u128) -> Uuid {
    Uuid::from_u128(0x2000 + n)
}

// ---------------------------------------------------------------------------------------
// The fake OLD store
// ---------------------------------------------------------------------------------------

pub type OldKey = (Uuid, String, Option<Uuid>);

/// Parks the first `get` until released.
pub struct Gate {
    pub entered: Notify,
    pub release: Notify,
}

/// An in-memory old store with fault injection.
#[derive(Default)]
pub struct FakeOld {
    values: Mutex<HashMap<OldKey, Vec<u8>>>,
    pub gets: AtomicUsize,
    pub deletes: AtomicUsize,
    /// `get` calls with an index at or above this fail with `ServiceUnavailable`.
    fail_get_from: Mutex<Option<usize>>,
    /// Same for `delete`.
    fail_delete_from: Mutex<Option<usize>>,
    /// The next this-many `get`s fail with `ServiceUnavailable`, then it recovers.
    pub transient_gets: AtomicUsize,
    gate: Mutex<Option<Arc<Gate>>>,
}

impl FakeOld {
    pub fn put(&self, tenant: Uuid, reference: &str, owner: Option<Uuid>, value: &[u8]) {
        self.values
            .lock()
            .unwrap()
            .insert((tenant, reference.to_owned(), owner), value.to_vec());
    }

    pub fn has(&self, tenant: Uuid, reference: &str, owner: Option<Uuid>) -> bool {
        self.values
            .lock()
            .unwrap()
            .contains_key(&(tenant, reference.to_owned(), owner))
    }

    pub fn remove(&self, tenant: Uuid, reference: &str, owner: Option<Uuid>) {
        self.values
            .lock()
            .unwrap()
            .remove(&(tenant, reference.to_owned(), owner));
    }

    pub fn snapshot(&self) -> BTreeMap<OldKey, Vec<u8>> {
        self.values
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn fail_get_from(&self, call: Option<usize>) {
        *self.fail_get_from.lock().unwrap() = call;
    }

    pub fn fail_delete_from(&self, call: Option<usize>) {
        *self.fail_delete_from.lock().unwrap() = call;
    }

    pub fn park_first_get(&self) -> Arc<Gate> {
        let gate = Arc::new(Gate {
            entered: Notify::new(),
            release: Notify::new(),
        });
        *self.gate.lock().unwrap() = Some(gate.clone());
        gate
    }

    pub fn calls(&self) -> usize {
        self.gets.load(Ordering::SeqCst) + self.deletes.load(Ordering::SeqCst)
    }
}

/// What the old SDK's `SecretRef` accepted: `[a-zA-Z0-9_-]`, 1 to 255 bytes.
fn valid_old_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 255
        && reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[async_trait]
impl LegacyStore for FakeOld {
    async fn get(
        &self,
        tenant_id: Uuid,
        reference: &str,
        owner_id: Option<Uuid>,
    ) -> Result<Option<SecretValue>, LegacyError> {
        let call = self.gets.fetch_add(1, Ordering::SeqCst);
        let gate = self.gate.lock().unwrap().take();
        if let Some(gate) = gate {
            gate.entered.notify_one();
            gate.release.notified().await;
        }
        if !valid_old_reference(reference) {
            return Err(LegacyError::Failed(
                "invalid secret reference: only [a-zA-Z0-9_-] are allowed".to_owned(),
            ));
        }
        if self
            .fail_get_from
            .lock()
            .unwrap()
            .is_some_and(|limit| call >= limit)
        {
            return Err(LegacyError::Unavailable("injected".to_owned()));
        }
        if self
            .transient_gets
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(LegacyError::Unavailable("injected, transient".to_owned()));
        }
        Ok(self
            .values
            .lock()
            .unwrap()
            .get(&(tenant_id, reference.to_owned(), owner_id))
            .cloned()
            .map(SecretValue::new))
    }

    async fn delete(
        &self,
        tenant_id: Uuid,
        reference: &str,
        owner_id: Option<Uuid>,
    ) -> Result<(), LegacyError> {
        let call = self.deletes.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_delete_from
            .lock()
            .unwrap()
            .is_some_and(|limit| call >= limit)
        {
            return Err(LegacyError::Unavailable("injected".to_owned()));
        }
        self.remove(tenant_id, reference, owner_id);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// The fake NEW store (the V2 contract)
// ---------------------------------------------------------------------------------------

#[derive(Default)]
struct NewInner {
    counters: HashMap<(Uuid, Uuid), u64>,
    versions: BTreeMap<(Uuid, Uuid, u64), Vec<u8>>,
}

/// An in-memory versioned store with ordered numeric versions and fault injection.
pub struct FakeNew {
    inner: Mutex<NewInner>,
    pub puts: AtomicUsize,
    pub gets: AtomicUsize,
    pub destroys: AtomicUsize,
    fail_put_from: Mutex<Option<usize>>,
    fail_get_from: Mutex<Option<usize>>,
    fail_destroy_from: Mutex<Option<usize>>,
    /// The next this-many `get`s answer `None`.
    pub none_gets_left: AtomicUsize,
    /// `get` returns other bytes.
    pub corrupt: AtomicBool,
    /// Whether the store declares `destroy`.
    pub destroy_supported: AtomicBool,
}

impl Default for FakeNew {
    fn default() -> Self {
        Self {
            inner: Mutex::default(),
            puts: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
            destroys: AtomicUsize::new(0),
            fail_put_from: Mutex::new(None),
            fail_get_from: Mutex::new(None),
            fail_destroy_from: Mutex::new(None),
            none_gets_left: AtomicUsize::new(0),
            corrupt: AtomicBool::new(false),
            destroy_supported: AtomicBool::new(true),
        }
    }
}

fn tripped(limit: &Mutex<Option<usize>>, call: usize) -> bool {
    limit.lock().unwrap().is_some_and(|l| call >= l)
}

impl FakeNew {
    pub fn fail_put_from(&self, call: Option<usize>) {
        *self.fail_put_from.lock().unwrap() = call;
    }

    pub fn fail_get_from(&self, call: Option<usize>) {
        *self.fail_get_from.lock().unwrap() = call;
    }

    pub fn fail_destroy_from(&self, call: Option<usize>) {
        *self.fail_destroy_from.lock().unwrap() = call;
    }

    /// Every live version of every key: bytes only, in version order.
    pub fn live(&self) -> BTreeMap<(Uuid, Uuid), Vec<Vec<u8>>> {
        let mut out: BTreeMap<(Uuid, Uuid), Vec<Vec<u8>>> = BTreeMap::new();
        for ((t, r, _), bytes) in &self.inner.lock().unwrap().versions {
            out.entry((*t, *r)).or_default().push(bytes.clone());
        }
        out
    }

    /// The bytes of one version, without going through the failure injection.
    pub fn bytes(&self, key: &StoreKey, version: &str) -> Option<Vec<u8>> {
        let v: u64 = version.parse().ok()?;
        self.inner
            .lock()
            .unwrap()
            .versions
            .get(&(key.tenant_id.0, key.record_id, v))
            .cloned()
    }

    pub fn version_count(&self, key: &StoreKey) -> usize {
        self.inner
            .lock()
            .unwrap()
            .versions
            .range((key.tenant_id.0, key.record_id, 0)..=(key.tenant_id.0, key.record_id, u64::MAX))
            .count()
    }
}

#[async_trait]
impl CredStorePluginClientV2 for FakeNew {
    async fn put(
        &self,
        _ctx: &toolkit_security::SecurityContext,
        key: &StoreKey,
        value: SecretValue,
    ) -> Result<ValueVersion, CredStoreError> {
        let call = self.puts.fetch_add(1, Ordering::SeqCst);
        if tripped(&self.fail_put_from, call) {
            return Err(CredStoreError::service_unavailable("injected"));
        }
        let mut inner = self.inner.lock().unwrap();
        let counter = inner
            .counters
            .entry((key.tenant_id.0, key.record_id))
            .or_insert(0);
        *counter += 1;
        let version = *counter;
        inner.versions.insert(
            (key.tenant_id.0, key.record_id, version),
            value.as_bytes().to_vec(),
        );
        Ok(ValueVersion::new(version.to_string()))
    }

    async fn get(
        &self,
        _ctx: &toolkit_security::SecurityContext,
        key: &StoreKey,
        version: &ValueVersion,
    ) -> Result<Option<SecretValue>, CredStoreError> {
        let call = self.gets.fetch_add(1, Ordering::SeqCst);
        if tripped(&self.fail_get_from, call) {
            return Err(CredStoreError::service_unavailable("injected"));
        }
        if self
            .none_gets_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Ok(None);
        }
        Ok(self.bytes(key, version.as_str()).map(|mut bytes| {
            if self.corrupt.load(Ordering::SeqCst) {
                bytes.push(b'!');
            }
            SecretValue::new(bytes)
        }))
    }

    async fn delete_key(
        &self,
        _ctx: &toolkit_security::SecurityContext,
        key: &StoreKey,
    ) -> Result<(), CredStoreError> {
        self.inner
            .lock()
            .unwrap()
            .versions
            .retain(|(t, r, _), _| (*t, *r) != (key.tenant_id.0, key.record_id));
        Ok(())
    }

    fn supports_destroy(&self) -> bool {
        self.destroy_supported.load(Ordering::SeqCst)
    }

    async fn destroy(
        &self,
        _ctx: &toolkit_security::SecurityContext,
        key: &StoreKey,
        selector: DestroySelector,
    ) -> Result<(), CredStoreError> {
        let call = self.destroys.fetch_add(1, Ordering::SeqCst);
        if tripped(&self.fail_destroy_from, call) {
            return Err(CredStoreError::service_unavailable("injected"));
        }
        let (below, exactly) = match &selector {
            DestroySelector::Below(v) => (v.as_str().parse::<u64>().ok(), None),
            DestroySelector::Exactly(v) => (None, v.as_str().parse::<u64>().ok()),
        };
        self.inner.lock().unwrap().versions.retain(|(t, r, v), _| {
            if (*t, *r) != (key.tenant_id.0, key.record_id) {
                return true;
            }
            !(below.is_some_and(|b| *v < b) || exactly == Some(*v))
        });
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------------------

/// A row of the SHIPPED `credstore_secrets`.
#[derive(Clone, Debug)]
pub struct Row {
    pub id: Uuid,
    pub tenant: Uuid,
    pub reference: String,
    pub sharing: i16,
    pub owner: Uuid,
    pub status: i16,
    pub fp: Option<Vec<u8>>,
    pub fp_key_id: Option<i16>,
    pub ty: Uuid,
}

impl Row {
    /// An `active`, tenant-shared row whose fingerprint matches `value`.
    pub fn fenced(n: u128, tenant: Uuid, reference: &str, value: &[u8]) -> Self {
        Self {
            id: rid(n),
            tenant,
            reference: reference.to_owned(),
            sharing: 2,
            owner: Uuid::nil(),
            status: 2,
            fp: Some(compute_fp(&FENCE_KEY, value)),
            fp_key_id: Some(1),
            ty: TYPE_A,
        }
    }

    /// The value the fixtures give this row (its fingerprint, if any, matches it):
    /// it depends on the reference and the sharing mode, so a private row and a
    /// shared row of one reference differ.
    pub fn value(&self) -> Vec<u8> {
        format!("value-of-{}-sharing-{}", self.reference, self.sharing).into_bytes()
    }

    fn refingerprinted(mut self) -> Self {
        if self.fp.is_some() {
            self.fp = Some(compute_fp(&FENCE_KEY, &self.value()));
        }
        self
    }

    /// A fenced row whose value is [`Row::value`].
    pub fn valued(n: u128, tenant: Uuid, reference: &str) -> Self {
        Self::fenced(n, tenant, reference, b"").refingerprinted()
    }

    /// The old owner of the address: `Some` only for a private row.
    pub fn old_owner(&self) -> Option<Uuid> {
        (self.sharing == 1).then_some(self.owner)
    }

    pub fn private(mut self, owner: Uuid) -> Self {
        self.sharing = 1;
        self.owner = owner;
        self.refingerprinted()
    }

    pub fn sharing(mut self, sharing: i16) -> Self {
        self.sharing = sharing;
        self.refingerprinted()
    }

    pub fn without_fp(mut self) -> Self {
        self.fp = None;
        self.fp_key_id = None;
        self
    }

    pub fn with_status(mut self, status: i16) -> Self {
        self.status = status;
        self
    }
}

/// The standard dataset: every kind of row the shipped gear could leave.
pub struct Standard {
    pub shared: Row,
    pub private: Row,
    pub seeded: Row,
    pub tenant_shared: Row,
    pub provisioning: Row,
    pub deprovisioning: Row,
}

impl Standard {
    /// Rows that carry a value (the four `active` ones).
    pub fn active(&self) -> [&Row; 4] {
        [
            &self.shared,
            &self.private,
            &self.seeded,
            &self.tenant_shared,
        ]
    }
}

/// How many `active` rows the standard dataset has.
pub const STANDARD_ACTIVE: usize = 4;

// ---------------------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Flavor {
    Sqlite,
    Postgres,
}

enum Keep {
    Dir(TempDir),
    Pg(Box<ContainerAsync<Postgres>>),
}

/// What a run of the tool printed and returned.
#[derive(Debug)]
pub struct Outcome {
    pub exit: Exit,
    pub out: String,
    pub err: String,
}

/// Runs the tool with `args` (everything after the program name) and no database
/// of its own: for the commands that never reach one (`--help`, a usage error).
pub async fn run_cli(
    old: &dyn LegacyStore,
    new: &dyn CredStorePluginClientV2,
    args: &[&str],
) -> Outcome {
    let mut command = vec!["credstore-value-migration"];
    command.extend_from_slice(args);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = run_with(command, old, new, &Tuning::immediate(), &mut out, &mut err).await;
    Outcome {
        exit,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
    }
}

/// Fresh fake stores behind `Arc`s, for the process entry point `run_from`, which
/// takes ownership; the caller keeps its own handles to inspect them afterwards.
pub fn shared_stores() -> (Arc<FakeOld>, Arc<FakeNew>) {
    (Arc::new(FakeOld::default()), Arc::new(FakeNew::default()))
}

/// Runs the tool through the process entry point (`run_from`) and returns its exit
/// code. That entry point writes to the REAL stdout and stderr, so only the code
/// can be checked here; `run_cli` captures the text.
pub async fn run_entry_point(
    old: &Arc<FakeOld>,
    new: &Arc<FakeNew>,
    args: &[&str],
) -> std::process::ExitCode {
    let mut command = vec!["credstore-value-migration"];
    command.extend_from_slice(args);
    credstore_value_migration::run_from(command, old.clone(), new.clone())
        .await
        .unwrap()
}

/// The tables the tool and the gear share, whose rows must not change when a run
/// refuses to start.
const WATCHED_TABLES: [&str; 3] = [
    "credstore_secrets",
    "credstore_value_migration",
    "credstore_value_migration_rows",
];

/// A database in the shipped schema plus both fake stores.
pub struct Fixture {
    pub flavor: Flavor,
    pub url: String,
    pub db: DatabaseConnection,
    pub platform: Db,
    pub old: FakeOld,
    pub new: FakeNew,
    _keep: Keep,
}

impl Fixture {
    /// A `SQLite` file database in the shipped schema.
    pub async fn sqlite() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            dir.path().join("db.sqlite").display()
        );
        Self::connect(Flavor::Sqlite, url, Keep::Dir(dir)).await
    }

    /// A `PostgreSQL` container in the shipped schema; `None` when Docker is not
    /// reachable and `CREDSTORE_MIGRATION_REQUIRE_DOCKER` is not set.
    pub async fn postgres() -> Option<Self> {
        let request = test_containers::postgres()
            .with_env_var("POSTGRES_PASSWORD", "pass")
            .with_env_var("POSTGRES_USER", "user")
            .with_env_var("POSTGRES_DB", "credstore");
        let container = match request.start().await {
            Ok(c) => c,
            Err(e) => {
                assert!(
                    std::env::var_os("CREDSTORE_MIGRATION_REQUIRE_DOCKER").is_none(),
                    "CREDSTORE_MIGRATION_REQUIRE_DOCKER is set but the PostgreSQL container could not start: {e}"
                );
                eprintln!("SKIPPING: Docker is not reachable ({e})");
                return None;
            }
        };
        let port = container.get_host_port_ipv4(5432).await.unwrap();
        let url = format!("postgres://user:pass@127.0.0.1:{port}/credstore");
        Some(Self::connect(Flavor::Postgres, url, Keep::Pg(Box::new(container))).await)
    }

    async fn connect(flavor: Flavor, url: String, keep: Keep) -> Self {
        let platform = connect_db(&url, ConnectOpts::default()).await.unwrap();
        let db = Database::connect(&url).await.unwrap();
        // The shipped gear's schema: m0001 through the platform runner, under the
        // gear's name (that is what makes the history table the real one).
        run_migrations_for_gear(
            &platform,
            CredStoreGear::MODULE_NAME,
            vec![Box::new(m0001_initial_schema::Migration)],
        )
        .await
        .unwrap();
        let fixture = Self {
            flavor,
            url,
            db,
            platform,
            old: FakeOld::default(),
            new: FakeNew::default(),
            _keep: keep,
        };
        fixture
            .old
            .put(Uuid::nil(), FENCE_KEY_REF, None, &FENCE_KEY);
        fixture
    }

    pub fn backend(&self) -> DatabaseBackend {
        match self.flavor {
            Flavor::Sqlite => DatabaseBackend::Sqlite,
            Flavor::Postgres => DatabaseBackend::Postgres,
        }
    }

    /// Placeholder `n` for the fixture's backend.
    pub fn p(&self, n: usize) -> String {
        match self.flavor {
            Flavor::Sqlite => format!("?{n}"),
            Flavor::Postgres => format!("${n}"),
        }
    }

    pub async fn exec(&self, sql: &str) {
        self.db.execute_unprepared(sql).await.unwrap();
    }

    pub async fn exec_err(&self, sql: &str) -> sea_orm::DbErr {
        self.db.execute_unprepared(sql).await.unwrap_err()
    }

    pub async fn query(&self, sql: &str, values: Vec<Value>) -> Vec<sea_orm::QueryResult> {
        self.db
            .query_all_raw(Statement::from_sql_and_values(self.backend(), sql, values))
            .await
            .unwrap()
    }

    /// Inserts a shipped row (no old value).
    pub async fn insert(&self, r: &Row) {
        let sql = format!(
            "INSERT INTO credstore_secrets (id, tenant_id, reference, sharing, owner_id, status, \
             secret_type_uuid, value_fp, fp_key_id) VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {})",
            self.p(1),
            self.p(2),
            self.p(3),
            self.p(4),
            self.p(5),
            self.p(6),
            self.p(7),
            self.p(8),
            self.p(9)
        );
        let values: Vec<Value> = vec![
            r.id.into(),
            r.tenant.into(),
            r.reference.clone().into(),
            r.sharing.into(),
            r.owner.into(),
            r.status.into(),
            r.ty.into(),
            r.fp.clone().into(),
            r.fp_key_id.into(),
        ];
        self.db
            .execute_raw(Statement::from_sql_and_values(self.backend(), &sql, values))
            .await
            .unwrap();
    }

    /// Inserts the row and stores `value` at its old address.
    pub async fn seed(&self, r: &Row, value: &[u8]) {
        self.insert(r).await;
        self.old.put(r.tenant, &r.reference, r.old_owner(), value);
    }

    /// The standard dataset, with its values in the old store.
    pub async fn seed_standard(&self) -> Standard {
        let s = Standard {
            shared: Row::valued(1, tenant(1), "api-key"),
            private: Row::valued(2, tenant(1), "api-key").private(Uuid::from_u128(0x77)),
            seeded: Row::valued(3, tenant(2), "seeded").without_fp(),
            tenant_shared: Row::valued(4, tenant(3), "shared-by-3").sharing(3),
            provisioning: Row::valued(5, tenant(2), "half-written").with_status(1),
            deprovisioning: Row::valued(6, tenant(2), "half-deleted").with_status(3),
        };
        for row in s.active() {
            self.seed(row, &row.value()).await;
        }
        // Unfinished rows have entries in the old store too (a half-written value).
        for row in [&s.provisioning, &s.deprovisioning] {
            self.seed(row, b"half").await;
        }
        s
    }

    /// Runs the tool against the fake stores.
    pub async fn run(&self, args: &[&str]) -> Outcome {
        self.run_with_stores(&self.old, &self.new, args).await
    }

    /// Runs the tool against the given stores.
    pub async fn run_with_stores(
        &self,
        old: &dyn LegacyStore,
        new: &dyn CredStorePluginClientV2,
        args: &[&str],
    ) -> Outcome {
        let mut command = vec!["--database-url", self.url.as_str()];
        command.extend_from_slice(args);
        run_cli(old, new, &command).await
    }

    /// Inserts a row into the tool's progress table, as a hand edit would; the
    /// fingerprint columns are taken from `r`.
    pub async fn insert_progress(&self, r: &Row, state: &str) {
        let sql = format!(
            "INSERT INTO credstore_value_migration_rows (id, tenant_id, reference, sharing, \
             owner_id, status_before, secret_type_uuid, value_fp, fp_key_id, state) \
             VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            self.p(1),
            self.p(2),
            self.p(3),
            self.p(4),
            self.p(5),
            self.p(6),
            self.p(7),
            self.p(8),
            self.p(9),
            self.p(10)
        );
        let values: Vec<Value> = vec![
            r.id.into(),
            r.tenant.into(),
            r.reference.clone().into(),
            r.sharing.into(),
            r.owner.into(),
            r.status.into(),
            r.ty.into(),
            r.fp.clone().into(),
            r.fp_key_id.into(),
            state.into(),
        ];
        self.db
            .execute_raw(Statement::from_sql_and_values(self.backend(), &sql, values))
            .await
            .unwrap();
    }

    // -- inspecting the database ------------------------------------------------------

    /// Every row of the watched tables as text (all columns, `quote()`d), sorted;
    /// `None` for a table that does not exist. Two equal digests mean no row of
    /// any of them was added, changed or removed, whatever the schema generation.
    /// `SQLite` only.
    pub async fn tables_digest(&self) -> BTreeMap<&'static str, Option<Vec<String>>> {
        assert_eq!(
            self.flavor,
            Flavor::Sqlite,
            "the digest uses SQLite functions"
        );
        let mut digest = BTreeMap::new();
        for table in WATCHED_TABLES {
            if !self.table_exists(table).await {
                digest.insert(table, None);
                continue;
            }
            let columns: Vec<String> = self
                .query(
                    &format!("SELECT name FROM pragma_table_info('{table}') ORDER BY cid"),
                    vec![],
                )
                .await
                .iter()
                .map(|r| r.try_get("", "name").unwrap())
                .collect();
            let line = columns
                .iter()
                .map(|c| format!("quote(\"{c}\")"))
                .collect::<Vec<_>>()
                .join(" || ',' || ");
            let rows = self
                .query(
                    &format!("SELECT {line} AS line FROM {table} ORDER BY line"),
                    vec![],
                )
                .await;
            digest.insert(
                table,
                Some(
                    rows.iter()
                        .map(|r| r.try_get("", "line").unwrap())
                        .collect(),
                ),
            );
        }
        digest
    }

    pub async fn table_exists(&self, name: &str) -> bool {
        let sql = match self.flavor {
            Flavor::Sqlite => "SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?1".to_owned(),
            Flavor::Postgres => "SELECT 1 AS present FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1".to_owned(),
        };
        !self.query(&sql, vec![name.into()]).await.is_empty()
    }

    /// Whether the gear table holds the row (either schema).
    pub async fn row_exists(&self, id: Uuid) -> bool {
        let sql = format!(
            "SELECT 1 AS present FROM credstore_secrets WHERE id = {}",
            self.p(1)
        );
        !self.query(&sql, vec![id.into()]).await.is_empty()
    }

    /// `(status, value_version, fallback, version)` of a gear row (migrated schema).
    pub async fn secret(&self, id: Uuid) -> Option<(i16, Option<String>, i16, i64)> {
        let sql = format!(
            "SELECT status, value_version, fallback, version FROM credstore_secrets WHERE id = {}",
            self.p(1)
        );
        let rows = self.query(&sql, vec![id.into()]).await;
        rows.first().map(|r| {
            (
                r.try_get("", "status").unwrap(),
                r.try_get("", "value_version").unwrap(),
                r.try_get("", "fallback").unwrap(),
                r.try_get("", "version").unwrap(),
            )
        })
    }

    /// `(state, value_version, activated, tidied, error)` of a progress row.
    pub async fn progress(
        &self,
        id: Uuid,
    ) -> Option<(String, Option<String>, bool, bool, Option<String>)> {
        let sql = format!(
            "SELECT state, value_version, activated, tidied, error FROM credstore_value_migration_rows WHERE id = {}",
            self.p(1)
        );
        let rows = self.query(&sql, vec![id.into()]).await;
        rows.first().map(|r| {
            (
                r.try_get("", "state").unwrap(),
                r.try_get("", "value_version").unwrap(),
                r.try_get("", "activated").unwrap(),
                r.try_get("", "tidied").unwrap(),
                r.try_get("", "error").unwrap(),
            )
        })
    }

    /// `(phase, accept_losses, discard_values)`.
    pub async fn header(&self) -> Option<(String, bool, bool)> {
        if !self.table_exists("credstore_value_migration").await {
            return None;
        }
        let rows = self
            .query(
                "SELECT phase, accept_losses, discard_values FROM credstore_value_migration",
                vec![],
            )
            .await;
        rows.first().map(|r| {
            (
                r.try_get("", "phase").unwrap(),
                r.try_get("", "accept_losses").unwrap(),
                r.try_get("", "discard_values").unwrap(),
            )
        })
    }

    pub async fn phase(&self) -> String {
        self.header().await.expect("a header").0
    }

    /// The versions the platform runner recorded for the gear.
    pub async fn history(&self) -> Vec<String> {
        let sql = match self.flavor {
            Flavor::Sqlite => {
                "SELECT name AS t FROM sqlite_master WHERE type = 'table' AND name LIKE 'toolkit_migrations__credstore__%'"
            }
            Flavor::Postgres => {
                "SELECT table_name AS t FROM information_schema.tables WHERE table_schema = current_schema() AND table_name LIKE 'toolkit_migrations__credstore__%'"
            }
        };
        let tables = self.query(sql, vec![]).await;
        let table: String = tables
            .first()
            .expect("the history table")
            .try_get("", "t")
            .unwrap();
        let mut versions: Vec<String> = self
            .query(
                &format!("SELECT version FROM \"{table}\" ORDER BY version"),
                vec![],
            )
            .await
            .iter()
            .map(|r| r.try_get("", "version").unwrap())
            .collect();
        versions.sort();
        versions
    }

    /// Everything that must be identical however a run was interrupted.
    pub async fn end_state(&self, ids: &[Uuid]) -> EndState {
        let mut secrets = BTreeMap::new();
        let mut progress = BTreeMap::new();
        for id in ids {
            if let Some((status, version, fallback, row_version)) = self.secret(*id).await {
                // The pointer itself differs when an interrupted run left a version
                // behind; what it points AT must not.
                let tenant_id = self.row_tenant(*id).await;
                let bytes = version.as_ref().and_then(|v| {
                    self.new
                        .bytes(&StoreKey::new(credstore_sdk::TenantId(tenant_id), *id), v)
                });
                secrets.insert(*id, (status, fallback, row_version, bytes));
            }
            if let Some((state, version, activated, tidied, _)) = self.progress(*id).await {
                progress.insert(*id, (state, version.is_some(), activated, tidied));
            }
        }
        EndState {
            secrets,
            progress,
            header: self.header().await,
            new_live: self.new.live(),
            old: self.old.snapshot(),
            history: self.history().await,
        }
    }

    async fn row_tenant(&self, id: Uuid) -> Uuid {
        let sql = format!(
            "SELECT tenant_id FROM credstore_secrets WHERE id = {}",
            self.p(1)
        );
        self.query(&sql, vec![id.into()])
            .await
            .first()
            .unwrap()
            .try_get("", "tenant_id")
            .unwrap()
    }
}

/// `(status, fallback, row version, the bytes the pointer resolves to)`.
pub type SecretView = (i16, i16, i64, Option<Vec<u8>>);

/// The comparable end state of a migration.
#[derive(Debug, PartialEq, Eq)]
pub struct EndState {
    /// `(status, fallback, row version, the bytes the pointer resolves to)` per gear row.
    pub secrets: BTreeMap<Uuid, SecretView>,
    /// `(state, has a version, activated, tidied)` per progress row.
    pub progress: BTreeMap<Uuid, (String, bool, bool, bool)>,
    pub header: Option<(String, bool, bool)>,
    /// The bytes of every live version of every key of the new store.
    pub new_live: BTreeMap<(Uuid, Uuid), Vec<Vec<u8>>>,
    pub old: BTreeMap<OldKey, Vec<u8>>,
    pub history: Vec<String>,
}

/// Asserts a run exited with `exit`, printing its streams when it did not.
pub fn expect_exit(outcome: &Outcome, exit: Exit) {
    assert_eq!(
        outcome.exit, exit,
        "stdout:\n{}\nstderr:\n{}",
        outcome.out, outcome.err
    );
}
