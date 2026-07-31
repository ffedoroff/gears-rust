#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(feature = "sqlite")]

//! `SQLite` integration tests for `OData` + Secure ORM execution.
//!
//! Security contract:
//! - Do not use any raw SeaORM/SQLx executors from test code.
//! - Execute queries only through `SecureConn` / `SecureTx` + secure wrappers.

use anyhow::anyhow;
use sea_orm::Set;
use sea_orm::entity::prelude::*;
use sea_orm_migration::prelude as mig;
use toolkit_db::migration_runner::run_migrations_for_testing;
use toolkit_db::odata::pager::OPager;
use toolkit_db::odata::{FieldMap, FieldToColumn, LimitCfg, ODataFieldMapping, paginate_odata};
use toolkit_db::secure::{
    Db, DbConn, ScopableEntity, SecureEntityExt, secure_insert, secure_insert_many,
};
use toolkit_db::{ConnectOpts, connect_db};
use toolkit_odata::filter::{FieldKind, FilterField};
use toolkit_odata::{CursorV1, Error as OdataError, ODataQuery, SortDir};
use toolkit_security::{AccessScope, pep_properties};
use uuid::Uuid;

mod ent {
    use sea_orm::entity::prelude::*;
    use uuid::Uuid;

    #[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "secure_odata_test")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub tenant_id: Uuid,
        pub name: String,
        pub score: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

impl ScopableEntity for ent::Entity {
    fn tenant_col() -> Option<<Self as EntityTrait>::Column> {
        Some(ent::Column::TenantId)
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
    fn resolve_property(property: &str) -> Option<<Self as EntityTrait>::Column> {
        match property {
            p if p == pep_properties::OWNER_TENANT_ID => Self::tenant_col(),
            _ => None,
        }
    }
}

/// Type-safe `FilterField` for `ent::Entity`, used only to exercise
/// [`paginate_odata`] (the `FilterNode<F>`/`ODataFieldMapping` pagination
/// path in `sea_orm_filter.rs`) directly, distinct from the legacy
/// `FieldMap`-based path `OPager` exercises above.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
enum EntFilterField {
    Id,
    Name,
    Score,
}

impl FilterField for EntFilterField {
    const FIELDS: &'static [Self] = &[Self::Id, Self::Name, Self::Score];

    fn name(&self) -> &'static str {
        match self {
            Self::Id => "id",
            Self::Name => "name",
            Self::Score => "score",
        }
    }

    fn kind(&self) -> FieldKind {
        match self {
            Self::Id | Self::Score => FieldKind::I64,
            Self::Name => FieldKind::String,
        }
    }
}

struct EntODataMapper;

impl FieldToColumn<EntFilterField> for EntODataMapper {
    type Column = ent::Column;

    fn map_field(field: EntFilterField) -> ent::Column {
        match field {
            EntFilterField::Id => ent::Column::Id,
            EntFilterField::Name => ent::Column::Name,
            EntFilterField::Score => ent::Column::Score,
        }
    }
}

impl ODataFieldMapping<EntFilterField> for EntODataMapper {
    type Entity = ent::Entity;

    fn extract_cursor_value(model: &ent::Model, field: EntFilterField) -> sea_orm::Value {
        match field {
            EntFilterField::Id => sea_orm::Value::BigInt(Some(model.id)),
            EntFilterField::Name => sea_orm::Value::String(Some(Box::new(model.name.clone()))),
            EntFilterField::Score => sea_orm::Value::BigInt(Some(model.score)),
        }
    }
}

struct CreateSecureOdataTest;

impl mig::MigrationName for CreateSecureOdataTest {
    fn name(&self) -> &'static str {
        "m001_create_secure_odata_test"
    }
}

#[async_trait::async_trait]
impl mig::MigrationTrait for CreateSecureOdataTest {
    async fn up(&self, manager: &mig::SchemaManager) -> Result<(), mig::DbErr> {
        manager
            .create_table(
                mig::Table::create()
                    .table(mig::Alias::new("secure_odata_test"))
                    .if_not_exists()
                    .col(
                        mig::ColumnDef::new(mig::Alias::new("id"))
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(
                        mig::ColumnDef::new(mig::Alias::new("tenant_id"))
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        mig::ColumnDef::new(mig::Alias::new("name"))
                            .string()
                            .not_null(),
                    )
                    .col(
                        mig::ColumnDef::new(mig::Alias::new("score"))
                            .big_integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &mig::SchemaManager) -> Result<(), mig::DbErr> {
        manager
            .drop_table(
                mig::Table::drop()
                    .table(mig::Alias::new("secure_odata_test"))
                    .to_owned(),
            )
            .await
    }
}

// Helper struct to manage test database lifecycle
struct TestDb {
    db: Db,
    tenant_id: Uuid,
    scope: AccessScope,
}

impl TestDb {
    async fn new() -> Self {
        let db = connect_db("sqlite::memory:", ConnectOpts::default())
            .await
            .expect("db connect");

        run_migrations_for_testing(&db, vec![Box::new(CreateSecureOdataTest)])
            .await
            .map_err(|e| anyhow!(e.to_string()))
            .expect("migrate");

        let tenant_id = Uuid::new_v4();
        let scope = AccessScope::for_tenants(vec![tenant_id]);

        Self {
            db,
            tenant_id,
            scope,
        }
    }

    fn conn(&self) -> DbConn<'_> {
        self.db.conn().expect("conn")
    }
}

async fn seed<R: toolkit_db::secure::DBRunner>(runner: &R, tenant_id: Uuid, scope: &AccessScope) {
    let rows = [("alice", 10), ("bob", 20), ("charlie", 30), ("dave", 40)];

    for (name, score) in rows {
        let am = ent::ActiveModel {
            tenant_id: Set(tenant_id),
            name: Set(name.to_owned()),
            score: Set(score),
            ..Default::default()
        };
        secure_insert::<ent::Entity>(am, scope, runner)
            .await
            .expect("insert");
    }
}

#[tokio::test]
async fn paginate_odata_works_with_secure_conn() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();
    seed(&conn, test_db.tenant_id, &test_db.scope).await;

    let fmap: FieldMap<ent::Entity> = FieldMap::new()
        .insert_with_extractor("id", ent::Column::Id, FieldKind::I64, |m: &ent::Model| {
            m.id.to_string()
        })
        .insert("name", ent::Column::Name, FieldKind::String)
        .insert("score", ent::Column::Score, FieldKind::I64);

    let q = ODataQuery {
        limit: Some(2),
        ..Default::default()
    };

    let page = OPager::<ent::Entity, _>::new(&test_db.scope, &conn, &fmap)
        .fetch(&q, |m| (m.name, m.score))
        .await
        .expect("fetch");

    assert_eq!(page.items.len(), 2, "page size");
}

/// ML-8967 regression: `sea_orm_filter::paginate_odata` must reject a
/// cursor whose filter hash disagrees with the query's, INCLUDING the two
/// asymmetric combinations (`Some` vs `None` in either direction) that the
/// pre-fix soft `if let (Some, Some) = ...` check silently let through — in
/// both cases the cursor's keyset position was computed against a
/// different row set than the current request would produce.
///
/// Table-driven over the two new-failure cases (the same-value cases are
/// covered by the pure `#[test]` on `validate_cursor_against` directly);
/// this test's job is to prove the DB-backed path in `sea_orm_filter.rs`
/// actually calls that shared check end-to-end, rather than having kept a
/// local, still-buggy copy of the comparison.
#[tokio::test]
async fn paginate_odata_rejects_asymmetric_filter_hash_cursor() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();
    seed(&conn, test_db.tenant_id, &test_db.scope).await;

    let filtered_query = || {
        let filter = toolkit_odata::parse_filter_string("score ge 20")
            .expect("test filter parses")
            .into_expr();
        // `with_filter` computes a real `filter_hash` from `filter`.
        ODataQuery::default().with_filter(filter)
    };

    let cases: Vec<(&str, ODataQuery, Option<String>)> = vec![
        (
            "hashed query, legacy cursor without a hash",
            filtered_query(),
            None,
        ),
        (
            "unfiltered query, cursor minted with a hash",
            ODataQuery::default(),
            Some("deadbeef".to_owned()),
        ),
    ];

    for (name, query, cursor_filter_hash) in cases {
        let cursor = CursorV1 {
            k: vec!["1".to_owned()],
            o: SortDir::Desc,
            s: "-id".to_owned(),
            f: cursor_filter_hash,
            d: "fwd".to_owned(),
        };
        let query = query.with_cursor(cursor);

        let select = ent::Entity::find().secure().scope_with(&test_db.scope);
        let result = paginate_odata::<EntFilterField, EntODataMapper, ent::Entity, _, _, _>(
            select,
            &conn,
            &query,
            ("id", SortDir::Desc),
            LimitCfg {
                default: 25,
                max: 200,
            },
            |m| (m.name, m.score),
        )
        .await;

        let err = result.expect_err(&format!(
            "{name}: an asymmetric filter-hash cursor must be rejected, not silently accepted"
        ));
        assert!(
            matches!(err, OdataError::FilterMismatch),
            "{name}: expected FilterMismatch, got {err:?}"
        );
    }
}

/// Same ML-8967 regression as `paginate_odata_rejects_asymmetric_filter_hash_cursor`,
/// but through the legacy `FieldMap`-based path (`core::paginate_with_odata`,
/// The acceptance half of the strict filter-hash check: a page minted by
/// `paginate_odata` under a filter must be continuable under the *same*
/// filter.
///
/// The two tests around this one prove the strict comparison rejects
/// asymmetric hashes. On their own they would be satisfied by a check that
/// rejects everything — and rejecting everything is the regression a strict
/// comparison can actually introduce, because a false `FilterMismatch`
/// breaks legitimate pagination just as surely as a missing check corrupts
/// it. This walks the real path: page one, take the cursor it minted, ask
/// for page two under an identically-built query.
#[tokio::test]
async fn paginate_odata_accepts_its_own_cursor_under_the_same_filter() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();
    seed(&conn, test_db.tenant_id, &test_db.scope).await;

    let filtered_query = || {
        let filter = toolkit_odata::parse_filter_string("score ge 0")
            .expect("test filter parses")
            .into_expr();
        ODataQuery::default().with_filter(filter).with_limit(1)
    };

    let first = paginate_odata::<EntFilterField, EntODataMapper, ent::Entity, _, _, _>(
        ent::Entity::find().secure().scope_with(&test_db.scope),
        &conn,
        &filtered_query(),
        ("id", SortDir::Desc),
        LimitCfg {
            default: 25,
            max: 200,
        },
        |m: ent::Model| m,
    )
    .await
    .expect("first page under a filtered query must succeed");

    let next = first
        .page_info
        .next_cursor
        .expect("seeded rows must span more than one page at limit=1");
    let cursor = CursorV1::decode(&next).expect("a cursor we just minted must decode");

    // The cursor carries the hash the query was built with — that is the
    // pairing the strict check is there to enforce, not to break.
    assert!(
        cursor.f.is_some(),
        "a cursor minted under a filtered query must carry its filter hash"
    );

    let second = paginate_odata::<EntFilterField, EntODataMapper, ent::Entity, _, _, _>(
        ent::Entity::find().secure().scope_with(&test_db.scope),
        &conn,
        &filtered_query().with_cursor(cursor),
        ("id", SortDir::Desc),
        LimitCfg {
            default: 25,
            max: 200,
        },
        |m: ent::Model| m,
    )
    .await
    .expect("continuing under the same filter must not be a FilterMismatch");

    assert_eq!(second.items.len(), 1, "page two should return one row");
    assert_ne!(
        second.items[0].id, first.items[0].id,
        "page two must advance past page one rather than repeat it"
    );
}

/// reached here via `OPager`) — the other of the two async DB-backed
/// paginators that must delegate to the shared check instead of keeping
/// its own copy.
#[tokio::test]
async fn opager_rejects_asymmetric_filter_hash_cursor() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();
    seed(&conn, test_db.tenant_id, &test_db.scope).await;

    let fmap: FieldMap<ent::Entity> = FieldMap::new()
        .insert_with_extractor("id", ent::Column::Id, FieldKind::I64, |m: &ent::Model| {
            m.id.to_string()
        })
        .insert("name", ent::Column::Name, FieldKind::String)
        .insert("score", ent::Column::Score, FieldKind::I64);

    let filtered_query = || {
        let filter = toolkit_odata::parse_filter_string("score ge 20")
            .expect("test filter parses")
            .into_expr();
        ODataQuery::default().with_filter(filter)
    };

    let cases: Vec<(&str, ODataQuery, Option<String>)> = vec![
        (
            "hashed query, legacy cursor without a hash",
            filtered_query(),
            None,
        ),
        (
            "unfiltered query, cursor minted with a hash",
            ODataQuery::default(),
            Some("deadbeef".to_owned()),
        ),
    ];

    for (name, query, cursor_filter_hash) in cases {
        let cursor = CursorV1 {
            k: vec!["1".to_owned()],
            o: SortDir::Desc,
            s: "-id".to_owned(),
            f: cursor_filter_hash,
            d: "fwd".to_owned(),
        };
        let query = query.with_cursor(cursor);

        let result = OPager::<ent::Entity, _>::new(&test_db.scope, &conn, &fmap)
            .fetch(&query, |m| (m.name, m.score))
            .await;

        let err = result.expect_err(&format!(
            "{name}: an asymmetric filter-hash cursor must be rejected, not silently accepted"
        ));
        assert!(
            matches!(err, OdataError::FilterMismatch),
            "{name}: expected FilterMismatch, got {err:?}"
        );
    }
}

#[tokio::test]
async fn secure_insert_many_inserts_all_rows_in_one_call() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();

    let rows = [("alice", 10), ("bob", 20), ("charlie", 30)];
    let models: Vec<ent::ActiveModel> = rows
        .iter()
        .map(|(name, score)| ent::ActiveModel {
            tenant_id: Set(test_db.tenant_id),
            name: Set((*name).to_owned()),
            score: Set(*score),
            ..Default::default()
        })
        .collect();

    secure_insert_many::<ent::Entity>(models, &test_db.scope, &conn)
        .await
        .expect("batch insert");

    let count = ent::Entity::find()
        .secure()
        .scope_with(&test_db.scope)
        .count(&conn)
        .await
        .expect("count rows");
    assert_eq!(count, 3, "all three rows must land in a single call");
}

/// The row-count assertion above would also pass for a loop of per-row
/// inserts, which is exactly what `secure_insert_many` exists to replace.
/// This pins the contract that matters: one statement for a batch that fits.
///
/// Needs the recorder, hence the feature gate.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn secure_insert_many_issues_exactly_one_statement() {
    use toolkit_db::test_support::{QueryKind, connect_with_recorder};

    let (db, rec) = connect_with_recorder("sqlite::memory:", ConnectOpts::default())
        .await
        .expect("db connect with recorder");
    run_migrations_for_testing(&db, vec![Box::new(CreateSecureOdataTest)])
        .await
        .map_err(|e| anyhow!(e.to_string()))
        .expect("migrate");
    let tenant_id = Uuid::new_v4();
    let scope = AccessScope::for_tenants(vec![tenant_id]);
    // Migrations ran through the same callback.
    rec.clear();

    let models: Vec<ent::ActiveModel> = (0..8)
        .map(|i| ent::ActiveModel {
            tenant_id: Set(tenant_id),
            name: Set(format!("user{i}")),
            score: Set(i),
            ..Default::default()
        })
        .collect();

    let conn = db.conn().expect("conn");
    secure_insert_many::<ent::Entity>(models, &scope, &conn)
        .await
        .expect("batch insert");

    let inserts = rec
        .events()
        .into_iter()
        .filter(|e| e.kind == QueryKind::Insert)
        .count();
    assert_eq!(
        inserts,
        1,
        "eight rows must go out as one INSERT, not a loop:\n{}",
        rec.dump()
    );
}

#[tokio::test]
async fn secure_insert_many_empty_vec_is_a_noop() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();

    secure_insert_many::<ent::Entity>(Vec::new(), &test_db.scope, &conn)
        .await
        .expect("empty batch must be Ok(())");

    let count = ent::Entity::find()
        .secure()
        .scope_with(&test_db.scope)
        .count(&conn)
        .await
        .expect("count rows");
    assert_eq!(count, 0, "an empty batch must not touch the database");
}

#[tokio::test]
async fn secure_insert_many_rejects_whole_batch_on_one_scope_violation() {
    let test_db = TestDb::new().await;
    let conn = test_db.conn();

    // One row's tenant is outside the scope, so the whole call must fail --
    // scope validation runs in memory over the whole batch before any row
    // reaches the database.
    let other_tenant = Uuid::new_v4();
    let models = vec![
        ent::ActiveModel {
            tenant_id: Set(test_db.tenant_id),
            name: Set("alice".to_owned()),
            score: Set(1),
            ..Default::default()
        },
        ent::ActiveModel {
            tenant_id: Set(other_tenant),
            name: Set("mallory".to_owned()),
            score: Set(2),
            ..Default::default()
        },
        ent::ActiveModel {
            tenant_id: Set(test_db.tenant_id),
            name: Set("bob".to_owned()),
            score: Set(3),
            ..Default::default()
        },
    ];

    let err = secure_insert_many::<ent::Entity>(models, &test_db.scope, &conn)
        .await
        .expect_err("a batch with an out-of-scope row must be rejected");
    assert!(
        matches!(err, toolkit_db::secure::ScopeError::Denied(_)),
        "expected a Denied scope error, got: {err}"
    );

    let count = ent::Entity::find()
        .secure()
        .scope_with(&test_db.scope)
        .count(&conn)
        .await
        .expect("count rows");
    assert_eq!(
        count, 0,
        "no row from the rejected batch may be inserted, not even the in-scope ones"
    );
}
