<!-- Created: 2026-07-26 by Constructor Tech -->

# DB Behavior Testing Guide (v1)

> **v1 — will be revised after the file-storage audit (step 4).** This guide
> was written from the resource-group audit (step 1 of the DB-behavior audit
> program) and is expected to gain detection classes, patterns, and boundary
> notes from later modules' audits. Treat gaps found in a later audit as a
> reason to update this file, not as evidence the later module is exempt from
> it.

This document defines the philosophy, infrastructure, and patterns for
**DB-behavior tests** — a third test layer, alongside unit tests
([`12_unit_testing.md`](12_unit_testing.md)) and E2E tests
([`13_e2e_testing.md`](13_e2e_testing.md)) — across all ToolKit gears.
Gear-specific findings (which defects were found, how severe, what's fixed)
live in each gear's own audit report, e.g.
`gears/system/resource-group/docs/analysis/DB_BEHAVIOR_AUDIT.md`.

---

## Philosophy

### What Is a DB-Behavior Test in This Project

A DB-behavior test calls a service method directly, like a unit test — no
HTTP, no running server — but it asks a different question. A unit test asks
*"is the result correct?"* A DB-behavior test asks *"how did the code talk to
the database to get there?"*: how many statements did it issue, were they
inside a transaction, does a second concurrent caller corrupt the same
invariant, does a retryable error actually get retried. The **result** can be
perfectly correct on a single, sequential call and the **behavior** can still
be broken — a check-then-insert with no transaction returns the right answer
every time you call it once, and corrupts data only when two callers happen
to overlap. Unit tests, which call one thing at a time, are structurally
blind to this; that blindness is the reason this layer exists.

### Why a Third Layer

[`12_unit_testing.md`](12_unit_testing.md) is explicit that this is
out of scope for unit tests: *"Performance, load, concurrency under
contention"* is listed as out of scope, and *"No retry testing — SERIALIZABLE
retry loops are an implementation detail. Tests do not simulate contention."*
Both statements are still true **at the unit-test layer** — a unit test
should not grow a barrier and a retry loop, that would make it slow and
occasionally flaky, exactly what unit tests must never be (see 12's
Reliability Principles). But "out of scope for unit tests" is not the same
as "out of scope, full stop": something has to verify that a write path uses
a transaction, that a SERIALIZABLE retry loop is wired up at all, that a
batch operation stays O(1) instead of becoming O(N). That is this layer.

[`13_e2e_testing.md`](13_e2e_testing.md) is the other place this could
plausibly live, and it deliberately doesn't: E2E's own priority order puts
**positive scenarios only, each API called once** above almost everything
else (§ "Priority Order"), and its reliability principles ban anything that
could introduce timing sensitivity. E2E proves the happy path works
end-to-end through real HTTP and real PostgreSQL; it does not — and should
not, by its own stability rules — spin up two concurrent callers racing for
the same row. A defect that only manifests under concurrent writers (the
majority of what this layer catches) would never surface in an E2E suite
built for **zero-tolerance flaking** on sequential happy-path calls.

So: unit tests verify **domain logic is correct**. E2E tests verify
**integration seams work end-to-end, happy path**. This layer verifies **how
the code talks to the database** — transactionality, statement-count scaling,
concurrency safety, retry correctness — the one axis both of the other two
layers explicitly declare out of scope.

### Three Questions Before Adding a Test

Every DB-behavior test must pass all three:

1. **"Does this test verify a property of the SQL traffic or the concurrency
   behavior, not the returned value?"** If the test is really asserting "the
   returned struct has the right fields" — that's a unit test, put it there.
   This layer asserts things like "zero statements ran outside a
   transaction" or "the statement count didn't grow when N did."

2. **"Would a correct implementation and a subtly broken one return the same
   answer on a single, sequential call?"** If yes — this is exactly the kind
   of defect unit tests are structurally blind to, and it belongs here. A
   check-then-insert race, a missing retry wrapper, and an O(N) loop
   disguised as "it still returns the right list" all pass this test.

3. **"Is the assertion a real, executable claim — not a comment saying
   'should be batched'?"** A known defect gets an assertion that would pass
   once the defect is fixed, marked `#[ignore = "known defect XX-NN: ..."]`
   so the suite stays green while the defect stays documented *and
   re-testable*. See "Known Defects as Executable Assertions" below — this
   is the difference between an audit finding and a permanent regression
   guard.

### What Belongs in DB-Behavior Tests

| Layer | What | How |
|-------|------|-----|
| **Transaction boundaries** | Every write runs inside a `Db::transaction*` closure, not on a bare connection | `QueryRecorder::writes_outside_tx()` against SQLite |
| **Statement-count scaling** | A batch/hierarchy operation's statement count for N items does not grow with N | Scale-invariance: same operation at small N vs large N, assert equal |
| **Retry wiring** | A `SERIALIZABLE` transaction is wrapped in the retry helper, not called directly | Static source-scan (method-name match) |
| **External-call isolation** | No RPC/schema-compile/other non-DB work happens inside a DB transaction | Static source-scan (client-type-shape match) |
| **Error-shape preservation** | A retryable DB error stays inspectable all the way to the retry decision | Manual review today (see "Defect Classes" below); no general static rule yet |
| **Constraint backstops** | An invariant enforced by a check-then-act sequence also has a DB-level constraint, so a broken retry/isolation story degrades to an ugly error, not silent corruption | Manual review today; schema/constraint inventory (see "Method Boundaries") |
| **Real concurrency races** | Two concurrent callers of an unprotected operation actually corrupt the invariant; two concurrent callers of a protected operation never both succeed | `tokio::sync::Barrier` pairs against real PostgreSQL |

### What Does NOT Belong Here

- **Whether the returned value is correct** — unit tests own this. A
  DB-behavior test's assertions are about the *SQL traffic and concurrency
  outcome*, not the domain fields of the returned struct.
- **JSON wire format, HTTP status codes, middleware wiring** — E2E's job (see
  13's "Integration Seams to Test" table).
- **Query plans, index selection, `EXPLAIN` output** — not covered by this
  layer at all yet; see "Method Boundaries".
- **Load testing / throughput benchmarks** — a barrier-synchronized pair of
  callers proves a *correctness* property (does the invariant hold, does the
  retry fire), not a *performance* one. Benchmarking belongs in a dedicated
  perf suite, not here.

### Relationship to Unit and E2E Tests

| Concern | Unit tests (12) | DB-behavior tests (14, this doc) | E2E tests (13) |
|---|---|---|---|
| Domain invariants, field validation | **Yes** (primary) | No | No |
| Transaction boundaries | No (out of scope by design) | **Yes** (primary) | No |
| Statement-count scaling | No | **Yes** (primary) | No |
| Concurrency / retry correctness | Explicitly out of scope | **Yes** (primary) | No (flaking risk too high) |
| Real PostgreSQL dialect quirks (FK, SSI) | No (SQLite) | Partial (the PG concurrency suite) | **Yes** (primary) |
| HTTP wire format, middleware | No | No | **Yes** (primary) |

If a bug only shows up when two writers race, or when N grows, or when a
transaction is silently missing — it lives here. Everything else lives in
12 or 13, exactly as before; this layer doesn't reclaim any of their scope,
it fills the one gap both explicitly left open.

---

## Defect Classes

Each class is defined independently of any specific gear — the rule that
catches it matches on API *shape* (method names, statement kind/table,
type-annotation shape), not on file names or line numbers, so that
rediscovering a defect in a *new* module is evidence the rule generalizes.

### `no-tx-write`

**Definition**: a check-then-act (or read-modify-write) sequence executes on
a bare connection, with no surrounding `Db::transaction*` closure. Each
individual statement commits independently (autocommit), so a concurrent
caller can interleave between the check and the act.

**Example** (resource-group, `add_membership_inner`): reads existing
tenants for a resource, checks the set is empty or contains the target
tenant, then inserts — all on `self.conn()`. Two concurrent "first
membership" adds for the same resource in different tenants both read an
empty set, both pass the check, both insert. The "one tenant per resource"
invariant is gone.

**Caught by**: `QueryRecorder::writes_outside_tx()` — non-empty means some
`INSERT`/`UPDATE`/`DELETE` executed while the transaction-bypass guard was
not armed.

### `no-retry-serializable`

**Definition**: a `SERIALIZABLE` transaction is opened directly (e.g.
`transaction_ref_mapped_with_config`) instead of through a retry-aware
helper (`transaction_with_retry`). Under real contention, PostgreSQL SSI
*will* abort one of two conflicting transactions with a `40001`
serialization failure — that is expected, correct behavior, not a bug. The
bug is that nothing retries it, so the abort surfaces to the caller as a
raw, ugly error instead of the clean domain outcome a retried attempt would
produce.

**Example** (resource-group, `create_type`/`update_type`): use
`db.transaction_ref_mapped_with_config(TxConfig::serializable(), ...)`
directly, unlike `create_group`/`update_group`/`move_group`/`delete_group`,
which all use `db.transaction_with_retry(TxConfig::serializable(), ...)`.

**Caught by**: a static source-scan counting occurrences of the two method
names per file — the retry-eligible one is the *documented good pattern*
elsewhere in the same codebase, giving the rule both a positive and a
negative example to validate against in one pass.

### `n-plus-one` / statement-scale growth

**Definition**: an operation over a collection of N related rows (a
subtree, a batch of junction rows, a page of list results) issues one
statement *per row* instead of one batched statement for the whole
collection. Statement count scales `O(N)` (or worse — `O(A×N)` for a
hierarchy operation with `A` ancestors) instead of `O(1)`.

**Example** (resource-group, closure-table rebuild after a move):
materializes every new `(ancestor, descendant, depth)` closure row in memory,
then calls `secure_insert` once per row in a loop — `A × N` round trips for
a subtree of `N` nodes under a new parent with `A` ancestors.

**Caught by**: scale-invariance — run the identical operation at small N and
large N, group captured statements by `(kind, table)`, assert the count for
the shape under test doesn't change. See "Scale-Invariance" below for why
this must compare *slope*, not just look flat at one N.

### `redundant-io`

**Definition**: a write ignores the model its own ORM call already returned
(or could have returned) and issues a separate, immediate `SELECT` to
re-fetch by id — a strictly unnecessary round trip.

**Example** (resource-group, `GroupRepository::insert`): calls
`secure_insert`, discards its result, then calls `self.find_model_by_id(db,
id)` on the very next line.

**Caught by**: `QueryRecorder::redundant_reads_after_write()` — an
`INSERT`/`UPDATE` on table `T` immediately followed (before any other write
touches `T` again) by a `SELECT` on the same `T`.

> **Measurement caveat**: on SQLite without the `sqlite-use-returning-for-3_35`
> feature, `SeaORM`'s own `ActiveModel::insert()` *always* issues an extra,
> implicit re-`SELECT` after every `INSERT` (`RETURNING` isn't supported, so
> it falls back to insert-then-`find_by_id`) — this is a SeaORM/test-harness
> artifact, invisible on PostgreSQL (which supports `RETURNING`
> unconditionally), and inflates measured redundant-read counts by one per
> row inserted, on top of any genuine application-level redundant read. It
> does not change scale-invariance verdicts (the extra read is a constant
> per-row offset, not a function of N), only absolute counts. See the
> resource-group audit report's "what this method does not cover" section
> for the full trace.

### `external-call-in-tx`

**Definition**: a call to an external dependency — an RPC client, a schema
compiler, anything that is not itself a DB statement — happens while a DB
transaction (especially `SERIALIZABLE`) is open. This extends the
transaction's duration and, for `SERIALIZABLE`, its SSI conflict window,
without the external call itself being part of what the transaction needs
to protect.

**Example** (resource-group, `create_group_inner`): calls
`validate_metadata_via_gts`, which fetches a GTS type schema from the types
registry and compiles it as a JSON Schema validator, from inside the
`SERIALIZABLE` transaction `create_group` opens.

**Caught by**: a static source-scan that discovers parameters typed as an
external "client" trait object (`&dyn some_sdk::FooClient` / `Arc<dyn
some_sdk::FooClient>` — the idiomatic shape for an injected external
dependency in this codebase) by *type shape*, then checks whether a
transaction closure's text references any discovered name. This is a
class-level rule specifically because it keys off the type annotation, not
a field name — an earlier version of this rule that matched the literal
string `"types_registry"` was correctly flagged in review as overfit to one
codebase's current naming, not a general rule; the type-shape version
survives a rename.

**Known limitation**: this proves the external-client *value* is textually
reachable inside the closure, not that an `.await` call on it happens there
specifically (the call can be one or more functions deeper, as in the
example above). A precise version needs real type/dataflow information —
this is an interim source-text heuristic, marked as such wherever it's used,
pending a dylint late lint (see "Method Boundaries").

### `error-shape-swallowing` (new in this revision)

**Definition**: an error-mapping layer converts a structured, inspectable
error — one whose *type* (not just its message text) identifies it as a
specific, classifiable condition (a serialization failure, a deadlock, a
constraint violation) — into an opaque, stringified form before it reaches
code that needs the original structure to make a decision. The archetypal
consumer of that decision is retry-eligibility detection: a helper that
decides "is this worth retrying" by matching on the error's *variant*, not
by re-parsing a string.

**Example** (resource-group, found during step 1's PostgreSQL concurrency
runs): every repository call maps its `sea_orm::DbErr` through
`.map_err(|e| DomainError::database(e.to_string()))`, and
`DomainError::database()` always constructs
`Self::Database(sea_orm::DbErr::Custom(message.into()))` — a string, not the
original error. `toolkit_db::contention::is_retryable_contention()` only
recognizes `DbErr::Exec(_)` / `DbErr::Query(_)`; it returns `false` for
`DbErr::Custom(_)` **unconditionally**, regardless of what the string says.
The result: `transaction_with_retry`'s retry can silently never fire, even
on operations that correctly use it, whenever the SSI abort surfaces from
inside a repo call rather than at `COMMIT` (where the typed error is
preserved by a different conversion path). Reproduced live against real
PostgreSQL: two "correctly retry-wrapped" operations (tenant-root creation,
width-limited creation) both showed the losing transaction getting a raw
`Database(Custom("... could not serialize access ..."))` instead of the
intended clean domain error.

This is a genuinely different failure mode from `no-retry-serializable`:
that class is "the retry helper was never called"; this class is "the retry
helper *was* called, is wired up correctly, and still can't do its job
because the input it needs was already destroyed one layer down." A
`no-retry-serializable` static scan would not catch this — it looks for the
*presence* of `transaction_with_retry`, which is present and correct here.

**Caught by**: today, this has no general static rule — it was found by
direct observation of a live PostgreSQL run, then confirmed by reading
`is_retryable_contention`'s match arms and `DomainError::database`'s
constructor together. The closest thing to a repeatable check is a targeted
grep for the shape `.map_err(|e| SomeError::variant(e.to_string()))` (or
equivalent) on any path that feeds a value into a retry-decision function,
cross-referenced against that function's own match arms to see what error
shapes it actually recognizes. Generalizing this into a real rule needs
dataflow analysis (does this specific stringified value reach that specific
decision point) that source-text scanning cannot do reliably — noted as
future work in "Method Boundaries".

### `check-then-act-without-constraint`

**Definition**: an invariant enforced by a check-then-act sequence has *no*
independent DB-level constraint (`UNIQUE`, `EXCLUDE`, `CHECK`, a FK) backing
it — correctness depends **entirely** on the transaction/isolation-level
behavior around the check. This is a different axis from `no-tx-write`:
the sequence can be inside a perfectly correct `SERIALIZABLE` transaction
with a working retry loop, and the invariant still has no backstop if that
transaction/retry machinery is ever wrong (including in a way this audit
didn't anticipate — see `error-shape-swallowing` immediately above, which
is exactly such a case).

**Example, protected but bare** (resource-group, tenant-root uniqueness): the
"at most one root group whose type code has this prefix" invariant is
checked via `find_root_id_with_type_prefix` inside a `SERIALIZABLE`
transaction with `transaction_with_retry` — the *correct* pattern this audit
uses as its own positive example throughout. It still has **no unique
index** backing it (the predicate is a string-prefix match over a joined
column, which a plain `UNIQUE` constraint can't express directly). Contrast
with `create_type`'s duplicate-code check, which — despite using the
*wrong* (unretried) transaction pattern, `no-retry-serializable` above — is
backed by an actual `schema_id UNIQUE` constraint: even with SSI/retry
completely broken, PostgreSQL itself refuses the second `INSERT` with a
constraint violation. The invariant survives; only the *error shape* the
caller sees is wrong (which is again `error-shape-swallowing`'s territory:
a `no-retry-serializable` create hitting a unique-violation gets a raw DB
error instead of a translated `AlreadyExists`, but the data stays correct).

**Caught by**: no mechanized rule yet. Detecting this requires a schema
constraint inventory (which columns/tables have `UNIQUE`/`EXCLUDE`/`CHECK`)
cross-referenced against which invariants the domain layer enforces purely
in application code — neither the SQL trace nor a source-text scan of the
service layer alone can tell "is there a constraint I'm not seeing." Today
this is a manual review question to ask about every check-then-act
invariant found by the other rules: *if the transaction/retry logic around
this check were wrong in some way nobody has tested yet, would the database
itself still refuse the bad state, or would it silently accept it?* See
"Method Boundaries" for where this could become mechanized (a constraint
inventory diff against the domain layer's invariant list).

---

## Test Infrastructure

### `QueryRecorder`

The reference implementation is
`gears/system/resource-group/resource-group/tests/common/query_recorder.rs`
(on branch `audit/rg-db-behavior` as of this writing — see the note at the
end of this section). It attaches a `SeaORM` `metric` callback to a raw
connection and records, per statement:

- **Normalized SQL** — literals redacted, variadic placeholder lists (`IN
  (?, ?, ?)`, multi-row `VALUES`) collapsed to a canonical shape, so N
  changing doesn't change the grouping key.
- **Statement kind** (`Select`/`Insert`/`Update`/`Delete`/`Other`) and a
  best-effort **target table**, both regex-extracted from the raw SQL (not a
  real parser — see "Method Boundaries").
- **`in_tx`** — see "The `IN_TX` Probe" below.
- **`param_count`** — the number of bound values in the statement, so a
  scale-invariance check can also budget for parameter-count growth on a
  statement whose *count* correctly stays flat (a single `IN (...)` with a
  growing list is one statement, `O(1)` by the statement-count rule, but its
  parameter count is `O(N)` — this is a real, separate cost dimension the
  statement-count rule alone would miss).

### Attaching the Recorder

`DBProvider`/`Db` never expose the inner `SeaORM` connection (that's the
whole point of `toolkit-db`'s security model — see
[`06_authn_authz_secure_orm.md`](06_authn_authz_secure_orm.md)), so a test
cannot attach a metric callback *after* connecting: `SeaORM` captures the
callback by value at query time, so attaching afterward would silently miss
every statement. `toolkit-db` gained a minimal, `test-support`-feature-gated
constructor for exactly this:

```rust
// libs/toolkit-db, feature = "test-support" (never enabled by production code)
pub async fn connect_db_with_metric_callback<F>(
    dsn: &str,
    opts: ConnectOpts,
    callback: F,
) -> Result<Db>
where
    F: Fn(&sea_orm::metric::Info<'_>) + Send + Sync + 'static;
```

A gear's own `tests/common/mod.rs` wraps this the same way it already wraps
plain `connect_db` for its `test_db()` helper:

```rust
pub async fn test_db_with_recorder() -> (Arc<DBProvider<DbError>>, QueryRecorder) {
    let (recorder, callback) = QueryRecorder::attach();
    let db = toolkit_db::connect_db_with_metric_callback(
        "sqlite::memory:", ConnectOpts { max_conns: Some(1), min_conns: Some(1), ..Default::default() }, callback,
    ).await.expect("connect with recorder");
    run_migrations_for_testing(&db, Migrator::migrations()).await.expect("run migrations");
    recorder.clear(); // migrations run through the same callback; start each test from a clean trace
    (Arc::new(DBProvider::new(db)), recorder)
}
```

### API

```rust
rec.total() -> usize                              // all captured statements
rec.total_params() -> usize                       // sum of param_count across the trace
rec.stats() -> BTreeMap<(QueryKind, String), usize>  // counts grouped by (kind, table)
rec.writes_outside_tx() -> Vec<RecordedQuery>     // no-tx-write evidence
rec.redundant_reads_after_write() -> Vec<(RecordedQuery, RecordedQuery)>  // redundant-io evidence
rec.dump() -> String                              // human-readable trace, with tx-scope markers
rec.clear()                                       // reset between the setup phase and the operation under test
```

`rec.clear()` before the operation under test matters: setup (creating
fixtures the operation needs) issues its own statements, and including them
would pollute both the `stats()` grouping and the scale-invariance
comparison.

### The `IN_TX` Probe: What It Actually Measures

`in_tx` is read via a test-support-gated function,
`toolkit_db::secure::in_transaction_for_testing()`, which reads the exact
same task-local the production transaction-bypass guard already
maintains — it does not duplicate or approximate that guard, it observes it.
Because the metric callback fires *synchronously*, on the same async task
that issued the query, reading the task-local from inside the callback is
**exact for the issuing task** — not a heuristic, not a best guess.

The boundary is `tokio::spawn`. Task-locals do not propagate across a
`spawn` boundary: a statement issued from a task spawned *inside* a
transaction closure would be recorded as `in_tx = false`. That is, in a
narrow sense, the *correct* answer — code running in a spawned task is not
guaranteed to complete before the spawning task's `COMMIT`/`ROLLBACK`, so it
was never actually protected by that transaction regardless of what table it
touches. But it means a **detached** spawn — one that outlives the
transaction closure and keeps writing after the test's assertions have
already run — is a genuine blind spot: the recorder has nothing to assert
against for statements it hasn't captured yet when the test function
returns. When auditing a new module, grep for `tokio::spawn`/`task::spawn`
inside the module's write paths; if there are none (as was the case for all
of `resource-group`'s `src/`), this boundary doesn't apply today, but it is
a structural property of the probe, not a fact specific to any one module,
and should be re-checked for each new module audited under this doc.

Also invisible to the trace, for a related reason: literal `BEGIN`/`COMMIT`/
`ROLLBACK` statements. `SeaORM`'s SQLite (and, similarly, other) drivers
issue these through a lower-level path than the `Statement`/metric-callback
machinery — confirmed by reading the driver source directly — so there is
no `Info` event for them at all. `in_tx` is how this layer substitutes for
that; trace dumps mark transaction-scope *transitions* with a synthetic
`-- [enter tx scope] --` / `-- [outside tx] --` marker, not a captured
literal statement.

> **Where the reference implementation lives**: `query_recorder.rs`,
> `db_behavior_audit_test.rs`, and `pg_concurrency_test.rs` are committed on
> branch `audit/rg-db-behavior` (`gears/system/resource-group/resource-group/
> tests/`), not on `main` as of this writing — they ride with the
> resource-group audit rather than being extracted into a shared crate
> pre-emptively. A module adopting this layer should copy the pattern (or,
> once a second module has done so, factor the recorder into a shared
> test-support crate — not done yet, since one instance isn't enough
> evidence of the right shared shape).

---

## Test Patterns

### Budget Assert — Writes Run Inside a Transaction

```rust
#[tokio::test]
async fn trace_update_thing() {
    let (db, rec) = common::test_db_with_recorder().await;
    // ... build fixtures via db, then:
    rec.clear();
    svc.update_thing(&ctx, thing_id, req).await.expect("update should succeed");

    assert!(
        rec.writes_outside_tx().is_empty(),
        "update_thing must run its writes inside a transaction:\n{}",
        rec.dump()
    );
}
```

For an operation already known to be broken, this becomes an executable,
`#[ignore]`d finding instead of a silent gap — see "Known Defects as
Executable Assertions" below.

### Scale-Invariance — Slope, Not Offset

The point of this pattern is not "does it look flat at one N" — a single
measurement can't distinguish `O(1)` from `O(N)` with a small constant. It
is **run the same operation at a small N and a much larger N, and compare**.
Pick N values far enough apart that a linear (or worse) term would be
unmistakable — e.g. N=3 vs N=15, or N=5 vs N=50 for an operation with a
smaller constant factor — not N=3 vs N=4, which a rounding coincidence could
mask.

```rust
async fn closure_inserts_for_new_child_at_depth(depth: usize) -> usize {
    let (db, rec) = common::test_db_with_recorder().await;
    // ... build a chain of `depth` nodes ...
    rec.clear();
    // ... create one more child under the deepest node ...
    count_in(&rec.stats(), QueryKind::Insert, "resource_group_closure")
}

#[tokio::test]
#[ignore = "known defect RG-06: ancestor-closure rows are inserted one at a time"]
async fn scale_create_child_closure_inserts_do_not_grow_with_ancestor_depth() {
    let small = closure_inserts_for_new_child_at_depth(3).await;
    let large = closure_inserts_for_new_child_at_depth(15).await;
    assert_eq!(small, large, "must not scale with ancestor depth (small={small}, large={large})");
}
```

Note what the assertion claims: `small == large`. This is the healthy
invariant, stated directly — not "small is less than some threshold" or "a
comment says this should be batched." When the underlying code is fixed,
this test starts passing with no changes; removing the `#[ignore]` is then
the entire fix-verification step.

Also budget **parameter count**, not just statement count, when the
operation's statement count is expected to stay flat by design (a single
batched `IN (...)`/`VALUES (...)`): `rec.total_params()` or a per-`(kind,
table)` breakdown catches the case where statement count looks perfect but
the query is quietly growing an enormous parameter list.

### Known Defects as Executable Assertions

A defect found during an audit gets a **real assertion that currently
fails**, not a comment. Mark it `#[ignore = "known defect XX-NN: <one-line
description> -- see <path to the module's audit report>"]`:

```rust
#[tokio::test]
#[ignore = "known defect RG-01: add_membership's check-then-insert has no transaction -- see docs/analysis/DB_BEHAVIOR_AUDIT.md"]
async fn trace_add_membership() {
    // ... same shape as any other trace_* test, asserting the healthy invariant ...
    assert!(rec.writes_outside_tx().is_empty(), "...");
}
```

This keeps `cargo test` green (the defect is `#[ignore]`d, not left
untested) while keeping the defect **re-testable**: running
`cargo test ... -- --ignored` re-confirms the defect is still present, and
if a later change accidentally fixes it, the ignored test starts passing —
a signal to remove the `#[ignore]`, not a silent regression the suite would
otherwise never notice either way.

For defects that don't depend on N (e.g. `redundant-io` instances, which are
a fixed shape per operation, not a growth curve), a non-ignored, "pin the
current behavior" assertion is appropriate instead of `#[ignore]` — it isn't
flaky (nothing about it depends on scale or timing), so there's no reason to
exclude it from the normal run; it just happens to assert something
currently true that would be nice to eventually make false.

### Static Source-Scan Rules — For Classes That Aren't SQL

`no-retry-serializable` and `external-call-in-tx` aren't observable in a SQL
trace at all (one is about which Rust method got called, the other is about
what a closure's *text* references), so they're plain `#[test]`s over
`include_str!`'d source, no DB involved:

```rust
#[test]
fn static_rule_flags_missing_retry() {
    let src = include_str!("../src/domain/type_service.rs");
    let unretried = src.matches(".transaction_ref_mapped_with_config(TxConfig::serializable()").count();
    let retried = src.matches(".transaction_with_retry(TxConfig::serializable()").count();
    assert!(unretried >= 1, "known defect ...");
    assert_eq!(retried, 0, "... if this now uses transaction_with_retry, the defect may be fixed");
}
```

Every static rule needs a **negative control in the same test file** — proof
it doesn't fire on every closure indiscriminately, run against the
*correctly-written* operations in the same codebase (see the resource-group
implementation's `static_rule_passes_group_service_uses_retry` and the
"clean" half of `static_rule_flags_external_call_inside_create_group_tx`).
Without a negative control, a rule that always returns "flagged" would pass
every test that only checks "is it flagged" and never get caught.

These are explicitly **interim, source-text heuristics** — regex over text,
not a parsed AST, no type information, no dataflow. Document that plainly at
the point of use (see "Method Boundaries"); a precise version of either rule
belongs in a dylint late lint.

---

## PostgreSQL Concurrency Suite

SQLite cannot stand in for real concurrency testing: its own
`SERIALIZABLE` is a whole-database writer lock, not row/predicate-level SSI,
and it has no FK-driven `RESTRICT` behavior under concurrent writers the way
PostgreSQL does. Races have to run against real PostgreSQL.

### `testcontainers` by Default

Bring up PostgreSQL via `testcontainers`/`testcontainers-modules` (already
workspace dependencies — used the same way by `libs/toolkit-db`'s own tests
and by account-management's `tests/common/mod.rs::pg::bring_up_postgres()`),
shared across the file's tests via a process-wide `OnceCell` so the
container starts once:

```rust
static PG: tokio::sync::OnceCell<Option<Arc<PgFixture>>> = tokio::sync::OnceCell::const_new();

async fn shared_pg() -> Option<Arc<PgFixture>> {
    PG.get_or_init(|| async {
        let request = ContainerRequest::from(Postgres::default())
            .with_tag("16-alpine") // the module's own default predates gen_random_uuid()
            .with_env_var("POSTGRES_PASSWORD", "pass")
            .with_env_var("POSTGRES_USER", "user")
            .with_env_var("POSTGRES_DB", "app");
        match request.start().await {
            Ok(container) => /* build PgFixture with the resolved port */,
            Err(e) => {
                eprintln!("skipping PostgreSQL concurrency tests: {e}. Install/start Docker to run these for real.");
                None
            }
        }
    }).await.clone()
}
```

Tests run for real, automatically, as part of a normal `cargo test` — **no
`#[ignore]`, no environment variable to remember to set.** An earlier design
gated these tests behind `#[ignore]` plus a `RG_PG_TEST_URL` environment
variable; that was corrected after review because `#[ignore]`d tests
practically never get run in day-to-day development, which defeats the
entire point of having a PostgreSQL-backed concurrency repro at all.

### Barrier-Based Race Pairs

Every scenario is a pair of tasks synchronized by a `tokio::sync::Barrier`
so both reach their first `.await` at the same instant:

```rust
let barrier = Arc::new(Barrier::new(2));
let (b1, b2) = (Arc::clone(&barrier), Arc::clone(&barrier));

let t1 = tokio::spawn(async move { b1.wait().await; svc1.add_membership(&ctx_a, ...).await });
let t2 = tokio::spawn(async move { b2.wait().await; svc2.add_membership(&ctx_b, ...).await });

let (r1, r2) = tokio::join!(t1, t2);
```

Use `#[tokio::test(flavor = "multi_thread", worker_threads = 4)]`, not the
default single-threaded flavor — two tasks on a `current_thread` runtime
cooperatively hand off at `.await` points and can end up not actually
overlapping, making a real bug look intermittently absent for reasons that
have nothing to do with whether it's fixed.

Two kinds of scenario pair:

- **Repro an unprotected race**: assert the invariant the code *should*
  enforce is violated (e.g. two distinct tenants both hold a membership for
  the same resource). Because a genuine two-task network race isn't
  guaranteed to interleave on every single attempt (scheduler/system-load
  variance), run several trials and require the bug to reproduce in *at
  least one* rather than every single attempt — see
  `membership_first_write_race_both_tenants_succeed`'s 8-trial loop for the
  reference shape.
- **Negative control — an SSI-protected invariant**: assert the invariant
  *always* holds (`ok_count == 1` for "exactly one of two concurrent
  attempts succeeds") across every run. This is what proves the detector can
  tell a protected invariant from a broken one using the *same* mechanism
  that catches the unprotected race — not merely "this path has no writes."
  Treat the *error shape* the loser gets (clean domain error vs. something
  else — see `error-shape-swallowing`) as a secondary, logged check, not a
  hard assertion: the invariant holding is what the test exists to guard,
  and a still-open `error-shape-swallowing` finding elsewhere in the stack
  can make the secondary check fail for reasons unrelated to what this test
  is protecting.

### Graceful Skip Without Docker

Every test calls the shared bring-up helper and returns early — a soft skip,
not a failure — if it comes back `None`:

```rust
macro_rules! pg_db_or_skip {
    () => {{
        let _guard = PG_TEST_LOCK.lock().await;
        match pg_db().await {
            Some(db) => (db, _guard),
            None => return,
        }
    }};
}
```

Verify both paths when writing a new suite: point `DOCKER_HOST` at a closed
port and confirm every test in the file passes having done nothing (with a
clear stderr message explaining why); then with Docker actually available,
confirm the suite exercises the real thing. Both were verified for the
resource-group reference implementation.

`PG_TEST_LOCK` (a plain `tokio::sync::Mutex<()>`, held for the whole test)
matters when more than one test in the file shares state that isn't scoped
per-test — e.g. a global uniqueness invariant keyed by a fixed prefix rather
than a per-test id. `cargo test`'s default parallel-by-function scheduling
would otherwise let two such tests race against *each other*, which is a
different, unwanted race from the one each test deliberately constructs
*within* itself via its own `Barrier`.

---

## Validation Protocol for a New Module

A detector is not considered valid for a module until all four steps below
are done. Skipping any of them means the "10/10" (or whatever the count is
for the new module) claim in the module's audit report is not backed by
evidence.

1. **Ground truth by line-by-line audit.** Read the module's write paths
   directly — every service method that inserts, updates, or deletes — and
   record every instance of the defect classes above, by file:line, before
   writing a single test. This is the ground truth the detector is validated
   against; a detector that was tuned to make its own findings look good
   proves nothing.

2. **The detector must rediscover every ground-truth defect via a
   class-level rule.** Not a bespoke check per defect — the *same*
   `writes_outside_tx()`, the *same* scale-invariance harness, the *same*
   static-scan pattern that would also flag a different, hypothetical
   instance of the same class. Produce a validation matrix: defect ID → rule
   that reopens it → test name. Target 100%; every miss either means the
   rule needs to generalize further or the "defect" needs re-classifying
   (e.g. into `check-then-act-without-constraint`, which doesn't have a
   mechanized rule yet — see above).

3. **Fault-injection table.** For each rule class, temporarily inject a
   *synthetic* instance of the defect into a currently-correct operation
   elsewhere in the module (remove a transaction from a healthy write; wrap
   a currently-batched query in a loop; strip a retry wrapper; reach an
   external client into a previously-clean transaction closure), confirm the
   relevant rule/test newly fails, then revert (`git checkout --`,
   confirmed via `git status`/`git diff` showing no residue) **before any
   commit**. This is the check that the rule generalizes to a defect it
   wasn't written to find, not just the ones already known. If a class has
   no available injection site (e.g. because every write in the module
   already follows the "bad" shape uniformly, as `redundant-io` did in the
   resource-group audit), say so explicitly in the table rather than
   skipping the row silently.

4. **Negative controls.** Run the detector against: (a) the module's
   correctly-protected operations (must not flag them — proves the rule
   isn't just "everything is broken"); (b) the module's read paths (the
   write-oriented rules must produce zero findings trivially; the
   scale-invariance rule is not write-specific and *can* legitimately fire
   on a read path — that's a true positive, report it as a finding, not
   noise); (c) under real PostgreSQL concurrency, the module's SSI-protected
   invariants (must hold on every run — see "Barrier-Based Race Pairs"
   above).

A module's audit report should present all four as explicit tables (matrix,
fault-injection, negative controls) — see
`gears/system/resource-group/docs/analysis/DB_BEHAVIOR_AUDIT.md` (branch
`audit/rg-db-behavior`) for the reference shape.

---

## Method Boundaries

Listed honestly because a detector that doesn't say what it can't see is
more dangerous than one that does — a green run at this layer proves the
things above, and nothing else. Carried forward from the resource-group
audit report's own "what this method does not cover" section, generalized
beyond that one module:

- **Cost of a single large statement.** Scale-invariance proves a query's
  *shape* doesn't multiply with N; it doesn't model planner/execution cost
  of one statement with an enormous parameter list. `param_count` gives a
  partial budget (visible per-statement and summable), not a cost model —
  it says nothing about a driver's behavior at extreme parameter counts or
  about planner plan changes at scale.
- **Predicate correctness, as opposed to predicate presence.** The trace
  shows a `WHERE tenant_id = ?` clause exists; it does not prove the bound
  value is the *right* one, or that a deliberate scope bypass (a
  system-level query that intentionally ignores tenant scoping) is the
  intended one and not a leaked one. That's the AccessScope/SecureORM test
  suite's job, not this layer's.
- **Constraint inventory.** This layer doesn't systematically enumerate a
  schema's `UNIQUE`/`EXCLUDE`/`CHECK`/FK constraints against what the domain
  layer assumes exists — see `check-then-act-without-constraint` above,
  which depends entirely on this being done manually today.
- **`error-shape-swallowing` has no general rule yet** — found once, by
  direct observation against a live PostgreSQL run, not by a repeatable
  scan. Generalizing it needs dataflow analysis (does *this* stringified
  error value reach *that* specific retry-decision call), which source-text
  scanning cannot do reliably.
- **`EXPLAIN`/query plans/index usage.** Not run, not inspected, by anything
  in this layer.
- **Deadlock ordering** (`40P01`, as opposed to the `40001` serialization
  failures this layer's PG suite reproduces). Not exercised unless the
  module under test takes explicit row locks to order against.
- **Pool starvation / connection exhaustion under load.** Qualitative
  concern only; this layer's harness never runs enough concurrent load to
  observe connection-pool queuing.
- **Migration drift on an existing production schema.** This layer always
  runs migrations fresh against a clean SQLite/PostgreSQL instance.
- **The static rules are text heuristics, not a parser.** No AST, no type
  resolution, no dataflow — regex over `include_str!`'d source. Both
  `no-retry-serializable` and `external-call-in-tx` are marked "interim"
  wherever they're implemented for exactly this reason.

**Where these go** (future work, not owned by this layer today):

- A **dylint late lint** for `external-call-in-tx` and (eventually)
  `error-shape-swallowing` — real type information would replace both
  rules' textual heuristics with an actual dataflow check.
- A **constraint-inventory cross-reference** tool for
  `check-then-act-without-constraint` — diff the schema's actual
  constraints against the invariants the domain layer's tests assert,
  flagging invariants with no independent DB-level backstop.
- **`EXPLAIN`/plan analysis and a dedicated perf/load suite** — a separate
  effort; this layer proves correctness properties (transactionality,
  scaling shape, concurrency safety), not throughput or latency.

---

## Acceptance Criteria

**Suite-level:**
- SQLite-backed dynamic tests + static source-scan tests run as part of a
  normal `cargo test -p <gear>` — fast (sub-second per binary is typical),
  no `#[ignore]` needed for anything except genuinely-known, currently-true
  defects.
- The PostgreSQL concurrency suite also runs as part of a normal `cargo test
  -p <gear>` — no `#[ignore]`, no environment variable required — and skips
  gracefully (passes, with a clear stderr message) when Docker is
  unreachable. Verify both the skip path and the real-run path when adding
  a new suite.
- `cargo fmt --check` / `cargo clippy -p <gear> --tests -- -D warnings`
  clean, same as any other test code in the workspace.

**Per-module validation:**
- A ground-truth defect list built by direct code reading, before the
  detector is validated against it (Validation Protocol step 1).
- 100% of ground-truth defects rediscovered by a *class-level* rule, not a
  bespoke check (step 2) — reported as an explicit matrix in the module's
  audit report.
- A fault-injection table covering every rule class used, or an explicit
  note for any class with no available injection site (step 3).
- Negative controls against protected operations, read paths, and (where a
  PostgreSQL suite exists) real-concurrency SSI-protected invariants
  (step 4).
- Every known-and-not-yet-fixed defect has a real, currently-failing
  assertion marked `#[ignore = "known defect XX-NN: ... -- see <report
  path>"]` — never a comment in place of an assertion.
- The module's audit report states plainly what this layer did **not**
  cover for that module (Method Boundaries, above, plus anything specific
  to that module) — a report that only lists findings without this section
  is incomplete.

**Isolation and reliability** (same spirit as 12 and 13, applied to this
layer's own tests):
- Each SQLite-backed test builds its own fresh in-memory database — no
  shared state between tests.
- No `time.sleep()`/`tokio::time::sleep` anywhere in this layer's own tests;
  waiting for two tasks to race uses a `Barrier`, not a timer.
- PostgreSQL concurrency tests that share one container-backed database
  (rather than one per test) explicitly serialize against each other via a
  lock when — and only when — they share state that isn't scoped per-test
  (see "Graceful Skip Without Docker" above); tests with fully independent,
  uniquely-identified fixtures don't need this.
