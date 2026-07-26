<!-- Created: 2026-07-26 by Constructor Tech -->

# DB Behavior Audit — resource-group (Step 1)

Step 1 of the DB-behavior audit program: build a defect-detection system for
`gears/system/resource-group/`, validate it against a known-defect ground
truth, and produce a full inventory. This document is the report; the
executable system lives in:

- `resource-group/tests/common/query_recorder.rs` — SQL trace recorder (SeaORM
  metric callback + a toolkit-db transaction-boundary probe).
- `resource-group/tests/db_behavior_audit_test.rs` — dynamic trace tests
  (SQLite) + static source-scan rules.
- `resource-group/tests/pg_concurrency_test.rs` — real-PostgreSQL concurrency
  harness (`testcontainers`).
- `docs/analysis/traces/*.txt` — captured trace snapshots for 11 operations.
- `docs/analysis/concurrent-write-performance-analysis.md` and
  `docs/analysis/transaction-isolation-analysis.md` — the prior static
  analysis this audit's dynamic evidence corroborates (see the cross-links at
  the top of each).

This document does not repeat those two analyses' reasoning; it reports what
the *executable* detector actually measured, where that confirms them, where
it goes further (real PostgreSQL races, new findings), and where it falls
short of them (no query plans, no load test).

## 1. Methodology

Three complementary, independent detection mechanisms, deliberately built as
*class*-level rules (matching on API/statement *shape*, not specific line
numbers) so that rediscovering the ground-truth defects is evidence the
system generalizes, not that it was fitted to them.

### 1.1 Dynamic SQL trace analysis (SQLite, deterministic)

`QueryRecorder` attaches a SeaORM `metric` callback to a raw connection
*before* it is wrapped into a toolkit-db `DBProvider` (SeaORM captures the
callback by value at query time; attaching after construction would miss
every statement). For each statement it records:

- **Normalized SQL** — literals redacted, variadic placeholder lists (`IN (?,
  ?, ?)`, multi-row `VALUES`) collapsed to a canonical shape, so batch size
  doesn't change the "shape" used for grouping.
- **Statement kind** (`SELECT`/`INSERT`/`UPDATE`/`DELETE`/other) and a
  best-effort **target table**, both extracted via regex from the raw SQL
  (not a real parser — see §5).
- **`in_tx`** — whether the statement executed while toolkit-db's
  transaction-bypass guard was armed, read via
  `toolkit_db::secure::in_transaction_for_testing()` (a new, minimal,
  `test-support`-feature-gated probe added to `libs/toolkit-db` for this
  audit — see the commit `test-support(toolkit-db): expose metric-callback
  attach + tx-boundary probe`). This is **precise, not a heuristic**: the
  metric callback fires synchronously on the same async task that issued the
  query, and the guard is a task-local, so reading it from inside the
  callback observes the exact state that governs whether `Db::conn()` would
  itself be rejected as a transaction bypass. §5 documents its one real
  boundary (spawned tasks).
- **`param_count`** — the number of bound values, so a scale-invariance check
  can also budget for parameter-count growth on an otherwise flat statement
  count (added after adversarial review — see §5).

Rules built on top of the recorded trace:

- **`no-tx-write`**: `rec.writes_outside_tx()` — any `INSERT`/`UPDATE`/`DELETE`
  captured with `in_tx == false`. A non-empty result means a write ran on a
  bare connection, outside any `Db::transaction*` closure.
- **`n-plus-one`** (scale-invariance): run the same operation at small N and
  large N (subtree size / ancestor depth / junction-list length); a
  statement-count for a given `(kind, table)` shape that *grows* with N is
  the defect. Tests assert equality (`small == large`) as a real,
  executable claim — passing tests prove flatness, `#[ignore]`d failing
  tests document growth.
- **`redundant-io`**: `rec.redundant_reads_after_write()` — an
  `INSERT`/`UPDATE` on table `T` immediately followed (before any other
  write touches `T` again) by a `SELECT` on the same `T`. Matches "write,
  discard the model, re-read by id".

### 1.2 Static source-scan rules (no DB)

Two defect classes aren't observable as SQL at all:

- **`no-retry-serializable`**: counts occurrences of
  `.transaction_ref_mapped_with_config(TxConfig::serializable()` (direct,
  unretried) vs `.transaction_with_retry(TxConfig::serializable()` (retried)
  per file. Class-level because it matches on the *method being called*, the
  distinguishing API shape toolkit-db itself provides for this purpose — not
  on any file- or line-specific text.
- **`external-call-in-tx`**: `external_client_param_names()` discovers
  parameter names by their *type shape* — `&dyn some_sdk::FooClient` /
  `Arc<dyn some_sdk::FooClient>`, the idiomatic signature for an injected
  external dependency in this codebase (`AuthZResolverClient`,
  `TypesRegistryClient`, etc.) — then checks whether a `transaction_with_retry`
  closure's text references any discovered name. This replaced an earlier
  version that matched the literal string `"types_registry"`, which
  adversarial review correctly flagged as fit to this codebase's current
  field name rather than a general rule (see the follow-up commit `fix
  (resource-group): make the external-call-in-tx static rule class-based`).
  It is still an interim, source-text heuristic: it proves an external-client
  *value* is textually reachable inside the closure, not that an `.await`
  call on it happens there specifically (`create_group_inner` takes it one
  call deeper, into `validate_metadata_via_gts`). A precise version belongs
  in a **dylint late lint** with real type/dataflow information; this is the
  interim source-text version, documented as such in the test file itself.

### 1.3 Real PostgreSQL concurrency harness

SQLite's own `SERIALIZABLE` is a whole-database writer lock, not row/
predicate-level SSI, and it has no FK-driven `RESTRICT` semantics under
concurrent writers — real races need real PostgreSQL.
`tests/pg_concurrency_test.rs` brings up a `testcontainers` PostgreSQL
(pinned `16-alpine`; the module's own default, `11-alpine`, predates
`gen_random_uuid()` becoming a built-in) once per process, runs RG's
migrations against it, and drives paired tasks through a `tokio::sync::
Barrier` so both reach their first `.await` at the same instant. Tests run
for real, automatically, as part of a normal `cargo test -p
cf-gears-resource-group` — no `#[ignore]`, no environment variable to
remember to set (an earlier, env-gated + `#[ignore]`d design was replaced
after adversarial review pointed out that `#[ignore]`d tests practically
never get run). Each test skips itself gracefully (passes, with a stderr
message) if Docker isn't reachable, verified by pointing `DOCKER_HOST` at a
closed port: all 5 tests pass having done nothing, printing the skip
reason. With Docker present (verified locally against Docker Desktop), they
exercise the real thing — results in §2 and §4 are from that real run, not
a projection.

Because a two-task race over a real network round-trip isn't guaranteed to
interleave on every single attempt (scheduler/system-load variance),
`membership_first_write_race_both_tenants_succeed` runs 8 trials and
requires the bug to reproduce in at least one (in practice it reproduces on
essentially every trial when the host isn't under heavy concurrent load);
`delete_type_races_create_group_reproduces_check_window` runs 15 trials and
reports the outcome split. The other three scenarios (single-shot races)
were stable across repeated runs.

## 2. Validation matrix — known defects × general rule

All 10 ground-truth defects are rediscovered by a general, class-level rule
(not a bespoke check per defect). **10/10.**

| # | Class | Location | Rule that reopens it | Executable evidence |
|---|-------|----------|----------------------|----------------------|
| RG-01 | no-tx-write | `membership_service.rs:122-230` (`add_membership_inner`); conn at :128, tenant check :179, insert :217 | `writes_outside_tx()` | `trace_add_membership` (SQLite, `#[ignore]`); `membership_first_write_race_both_tenants_succeed` (real PG, both tenants' first-membership succeed) |
| RG-02 | no-tx-write | `type_service.rs:331-365` (`delete_type`) | `writes_outside_tx()` | `trace_delete_type` (SQLite, `#[ignore]`); `delete_type_races_create_group_reproduces_check_window` (real PG) |
| RG-03 | no-retry-serializable | `type_service.rs:91` (create_type), `:241` (update_type) — vs `group_service.rs`'s `transaction_with_retry` | static rule (`.transaction_ref_mapped_with_config` count) | `static_rule_flags_type_service_missing_retry` + negative control `static_rule_passes_group_service_uses_retry`; real-PG repro `create_type_conflict_no_retry_yields_raw_error_for_loser` (loser gets a raw serialization-failure error, not `TypeAlreadyExists`) |
| RG-04 | n-plus-one | `group_repo.rs:1002-1006` (`rebuild_subtree_closure`, `for row in new_rows`) | scale-invariance (`Insert`, `resource_group_closure`) | `scale_move_closure_inserts_do_not_grow_with_subtree_size` (`#[ignore]`): 6 inserts at N=3, 30 at N=15 — exactly `2×N` (A=2 ancestors × N) |
| RG-05 | n-plus-one | `group_service.rs:1127-1133` (`move_group_internal_impl`: `is_descendant` :1129 + `get_relative_depth` :1133 per descendant) | scale-invariance (`Select`, `resource_group_closure`) | `scale_move_descendant_depth_selects_do_not_grow_with_subtree_size` (`#[ignore]`): 16 selects at N=3, 64 at N=15 |
| RG-06 | n-plus-one | `group_repo.rs:757-766` (`insert_ancestor_closure_rows`, loop insert at :763) | scale-invariance (`Insert`, `resource_group_closure`) | `scale_create_child_closure_inserts_do_not_grow_with_ancestor_depth` (`#[ignore]`): 4 inserts at chain depth 3, 16 at depth 15 — exactly `depth + 1` |
| RG-07 | n-plus-one | `type_repo.rs:278-315` (`insert_allowed_parent_types` loop :285, `insert_allowed_membership_types` loop :305) | scale-invariance (`Insert`, `gts_type_allowed_parent`) | `scale_create_type_junction_inserts_do_not_grow_with_parent_count` (`#[ignore]`): 2 inserts at N=2, 8 at N=8 |
| RG-08 | redundant-io | `group_repo.rs:656` (`insert`), `:699` (`update`); same pattern in `type_repo.rs` (`insert`/`update_type`) and `membership_repo.rs::insert` | `redundant_reads_after_write()` | `trace_update_group` (non-ignored, pins the finding directly: `!rec.redundant_reads_after_write().is_empty()`) |
| RG-09 | external-call-in-tx | `group_service.rs:561` (`validate_metadata_via_gts(...)` inside `create_group_inner`, itself inside `transaction_with_retry` from `group_service.rs:150`) | static rule (`external_client_param_names` + closure-body scan) | `static_rule_flags_external_call_inside_create_group_tx` + negative control (move/delete's closures don't reference any discovered client) |
| RG-10 | n-plus-one | `group_service.rs:1210-1234` (`force_delete_subtree`, two `for &gid in all_ids.iter().rev()` loops at :1223 and :1229) | scale-invariance (`rec.total()`) | `scale_force_delete_statements_do_not_grow_with_subtree_size` (`#[ignore]`): 16 statements at N=3, 64 at N=15 |

Every `#[ignore]`d test's reason string names the defect and points back to
this document, per the "known defect RG-XX" convention used throughout
`db_behavior_audit_test.rs`.

## 3. Fault-injection validation

For each rule *class* except `redundant-io` (see below), a synthetic defect
was injected into a currently-*correct* operation, the relevant test/rule
was run to confirm it now catches it, then the injection was reverted
(`git checkout --`, confirmed via `git status`/`git diff` showing no
residue). This is the "does the rule generalize, or did we just special-case
the ten defects we already knew about" check.

| Class | Injected change (temporary, reverted) | Rule / test that caught it | Negative control |
|-------|-----------------------------------------|------------------------------|-------------------|
| no-tx-write | `group_service.rs::update_group`: replaced `db.transaction_with_retry(...)` with a direct call on `self.db.conn()?` (no transaction) | `trace_update_group` (`writes_outside_tx()`) — failed with the full untransacted trace printed | Same test passes on the unmodified file (verified before and after revert) |
| no-retry-serializable | `group_service.rs::create_group`: changed `db.transaction_with_retry(TxConfig::serializable(), DomainError::db_err, \|tx\| ...)` to `db.transaction_ref_mapped_with_config(TxConfig::serializable(), \|tx\| ...)` | `static_rule_passes_group_service_uses_retry` — failed (`unretried` went from 0 to 1) | Same test passes on the unmodified file |
| n-plus-one | `group_repo.rs::resolve_type_paths_batch`: replaced the single `IN (...)` query with one `SELECT ... WHERE id = ?` per id | Temporary scale test (`list_groups` with N distinct types, 2 vs 8): failed, 2 vs 8 selects on `gts_type` | Same temporary test passes (1 vs 1) on the unmodified file — confirmed *before* applying the injection, not just after reverting |
| external-call-in-tx | `group_service.rs::move_group`: captured `self.types_registry.clone()` and referenced it inside the (previously clean) `transaction_with_retry` closure | `static_rule_flags_external_call_inside_create_group_tx`, temporarily strengthened from `clean >= 1` to `clean >= 2` (the true baseline count of untainted closures — move_group, delete_group) — failed after injection (`clean` dropped to 1) | Same strengthened assertion passes on the unmodified file (verified by `git stash` on just the source file, keeping the strengthened test) |
| redundant-io | *(not injected — see note)* | — | — |

**Redundant-io note**: every `INSERT`/`UPDATE` call site in the repo layer
already follows the "write, then re-read" shape by construction (it's how
the code is uniformly written — see RG-08), so there was no currently-clean
call site to inject a *new* instance of the pattern into as a control; the
rule's validity rests on the organic, non-ignored finding at RG-08
(`trace_update_group`) instead of a synthetic injection. This is itself a
data point: the repo layer has no operation that returns a freshly-inserted/
updated model without a redundant re-read.

All four injections were confirmed reverted (`git status`/`git diff` clean,
full `cargo test -p cf-gears-resource-group` green) before the corresponding
commits were made — the injected defects themselves were never committed.

### 3.1 Negative controls beyond the fault-injection table

- **Read paths don't trigger write rules**:
  `negative_control_read_paths_produce_no_write_statements` runs
  `get_group`/`list_groups`/`list_types` and asserts zero `Insert`/`Update`/
  `Delete` statements — trivially true, confirming the write-oriented rules
  can't misfire on reads. The scale-invariance rule is *not* write-specific,
  though, and legitimately fires on a read path — see RG-12 in §4; that's a
  true positive, not noise.
- **SSI-protected invariants under real load**:
  `negative_control_tenant_root_race_exactly_one_succeeds` and
  `negative_control_width_limited_race_exactly_one_succeeds` (real PostgreSQL)
  assert the actual invariant (`ok_count == 1`) always holds under a genuine
  concurrent race — proving the detector can tell a protected invariant from
  a broken one using the *same* concurrent-race mechanism that catches RG-01,
  not merely by "this path has no writes". Both hold on every run. Their
  secondary check (does the loser get the *clean* domain error) surfaced
  RG-15 (§4) instead — logged, not hard-asserted, since the invariant itself
  is what the test exists to guard.

## 4. Full findings inventory

IDs RG-01 through RG-10 are the ground-truth defects (§2); RG-11 onward are
new, found by reading the captured traces and static-scan output rather than
by further code reading. Severity is this audit's own judgment (impact ×
likelihood under the gear's actual write surface — see §6), not a
CVSS-style score.

| ID | Class | Severity | Location | Repro |
|----|-------|----------|----------|-------|
| RG-01 | no-tx-write | **Critical** | `membership_service.rs:122-230` | `trace_add_membership` (`#[ignore]`); `membership_first_write_race_both_tenants_succeed` (real PG) |
| RG-02 | no-tx-write | Medium | `type_service.rs:331-365` | `trace_delete_type` (`#[ignore]`); `delete_type_races_create_group_reproduces_check_window` (real PG) |
| RG-03 | no-retry-serializable | High | `type_service.rs:91,241` | `static_rule_flags_type_service_missing_retry`; `create_type_conflict_no_retry_yields_raw_error_for_loser` (real PG) |
| RG-04 | n-plus-one | High | `group_repo.rs:986-1006` | `scale_move_closure_inserts_do_not_grow_with_subtree_size` (`#[ignore]`) |
| RG-05 | n-plus-one | Medium | `group_service.rs:1122-1140` | `scale_move_descendant_depth_selects_do_not_grow_with_subtree_size` (`#[ignore]`) |
| RG-06 | n-plus-one | Medium-High | `group_repo.rs:739-766` | `scale_create_child_closure_inserts_do_not_grow_with_ancestor_depth` (`#[ignore]`) |
| RG-07 | n-plus-one | Low-Medium | `type_repo.rs:278-315` | `scale_create_type_junction_inserts_do_not_grow_with_parent_count` (`#[ignore]`) |
| RG-08 | redundant-io | Low-Medium | `group_repo.rs:652-701`, `type_repo.rs` (`insert`/`update_type`), `membership_repo.rs::insert` | `trace_update_group` (non-ignored, pinned) |
| RG-09 | external-call-in-tx | High | `group_service.rs:559-562` (call), `:150` (enclosing tx) | `static_rule_flags_external_call_inside_create_group_tx` |
| RG-10 | n-plus-one | High | `group_service.rs:1209-1234` | `scale_force_delete_statements_do_not_grow_with_subtree_size` (`#[ignore]`) |
| RG-11 | redundant-io (new) | Low | `group_service.rs:548-556` (`create_group_inner`: `resolve_id` then `find_by_code` for the same code); `:801-806` (`update_group_inner`, same pattern) | Visible directly in `docs/analysis/traces/create_root_group.txt` and `update_type.txt`: two `SELECT ... gts_type WHERE schema_id = ?` for the same code within one operation |
| RG-12 | n-plus-one (new, **read path**) | Medium | `type_repo.rs:481-512` (`list_types`: `load_full_type` per row, `:503-504`) | Not covered by a committed test (found via code reading after the trace review prompted a second pass over read paths); reproducible the same way as RG-04/06/07/10 — a page of N types costs `2N+1` queries (junction reads per row) |
| RG-13 | redundant-io (new) | Low | `type_service.rs:98` (`create_type`'s duplicate-check calls `find_by_code`, which loads full junction data just to test existence) | Visible in `docs/analysis/traces/create_type.txt`, statement 1: the pre-insert existence check is a plain `schema_id` lookup only when the type *doesn't* exist yet (short-circuits before `load_full_type`); the over-fetch triggers specifically on the **conflict path** (creating an already-existing code), not the happy path |
| RG-14 | no-tx-write (new) | Medium | `membership_service.rs:235-286` (`remove_membership`: conn at `:252`, existence check, delete at `:280`) | `trace_remove_membership` (`#[ignore]`) — same shape as RG-01 (check-then-write, no transaction), not called out in the original ground-truth list; the general rule caught it anyway |
| RG-15 | reliability (new) | **Critical** | `libs/toolkit-db/src/contention.rs:88` (`is_retryable_contention` only matches `DbErr::Exec`/`DbErr::Query`) × `error.rs:203` (`DomainError::database()` always wraps as `DbErr::Custom`) | `negative_control_tenant_root_race_exactly_one_succeeds` / `negative_control_width_limited_race_exactly_one_succeeds` (real PG): loser's error was `Database(Custom("... could not serialize access ..."))`, not the clean domain error, in every observed run |

### RG-15 in detail (new, highest-impact finding)

Every repo call in `group_repo.rs`/`type_repo.rs`/`membership_repo.rs` maps
its `sea_orm::DbErr` through `.map_err(|e| DomainError::database(e.to_string()))`,
and `DomainError::database()` always constructs
`Self::Database(sea_orm::DbErr::Custom(message.into()))` — a string, not the
original typed error. `toolkit_db::contention::is_retryable_contention()`
only recognizes `DbErr::Exec(_)` / `DbErr::Query(_)`; it returns `false` for
`DbErr::Custom(_)` unconditionally, regardless of what the string says.

`transaction_with_retry`'s decision to retry depends on
`extract_db_err(&e).is_some_and(|db_err| is_retryable_contention(backend, db_err))`.
Whenever the SSI abort surfaces from *within* a repo call (as opposed to at
`COMMIT`, where the `toolkit_db::DbError → DomainError` conversion path
*does* preserve the typed `DbErr` — see `error.rs`'s
`impl From<toolkit_db::DbError> for DomainError`), the retry helper can never
tell the failure was retryable, and returns the raw serialization-failure
error on the very first attempt. This was reproduced live against real
PostgreSQL: both `negative_control_tenant_root_race_exactly_one_succeeds`
and `negative_control_width_limited_race_exactly_one_succeeds` — operations
that *do* use `transaction_with_retry`, exactly the "correct" pattern this
audit uses as its positive example throughout — showed the loser getting
`Database(Custom("... could not serialize access due to read/write
dependencies among transactions"))` instead of `TenantRootAlreadyExists` /
`LimitViolation`, consistently.

This means the retry protection `group_service.rs` is documented as relying
on (see its module doc: "use `SERIALIZABLE` transactions with bounded
retry... to prevent phantom reads") is **not reliably effective** — not
because the retry *logic* is wrong, but because the error-mapping
convention used throughout the repo layer silently discards the one piece
of information the retry logic needs. This is a toolkit-db/resource-group
boundary issue: fixing it requires either resource-group's repo layer to
stop stringifying (preserve `DbErr` through the `?` chain, which `impl
From<sea_orm::DbErr> for DomainError` already supports directly) or
toolkit-db's `is_retryable_contention` to also inspect `DbErr::Custom`
message text (weaker, string-matching an already-stringified error). Not
fixed as part of this audit (audit-only scope); flagged here because it's
the single highest-leverage finding — it affects every SERIALIZABLE +
retry call site in the gear, not just one operation.

## 5. What this method does not cover

Honestly listing this matters as much as the findings above. This audit's
mechanisms answer a specific question ("does the write path use a
transaction, does its statement count grow with N, is a SERIALIZABLE
transaction retried, does an external call reach inside a transaction") and
are silent on several other axes of "DB behavior":

- **Cost of a single large statement.** Scale-invariance proves a query's
  *shape* doesn't multiply with N (one `IN (...)` regardless of list
  length), but a single statement with an enormous `IN`/`VALUES` list still
  has real planner/execution cost that this method doesn't model.
  `param_count` (added after adversarial review) gives a partial budget —
  it's visible in the trace dumps as `params=N` per statement, and
  `QueryRecorder::total_params()` sums it — but it's still a parameter
  *count*, not a cost model; it says nothing about the query planner's
  behavior at 10,000 parameters (e.g. Postgres switching plans, or hitting
  parameter-count limits on some drivers).
- **Predicate semantics.** The trace shows a `WHERE tenant_id IN (?)` clause
  is *present*, not that its bound value is *correct* (e.g., that it's
  actually the caller's scope and not an internal id, or that a `system_scope()`
  bypass — used deliberately in several places, e.g.
  `find_root_id_with_type_prefix` — is the intended one and not a leaked one).
  Auditing predicate *correctness* needs the AccessScope/SecureORM test
  suite (`tenant_filtering_db_test.rs`, `tenant_scoping_test.rs`), which is
  a separate, already-existing layer this audit doesn't duplicate.
- **Constraint inventory.** This audit relies on knowing a couple of specific
  constraints exist (the `gts_type.schema_id` unique constraint behind RG-03;
  `resource_group.gts_type_id ... ON DELETE RESTRICT` behind RG-02's "no
  corruption" result) from the imported analysis docs and from directly
  observing FK-driven failures in the PG harness. It does not systematically
  enumerate the schema's constraints (unique/check/FK) against what the
  domain layer assumes.
- **Error-mapping beyond `40001`.** RG-15 was found because it happened to
  surface through the exact two negative-control tests already in the
  harness. The audit did not systematically enumerate every `DomainError`
  variant's mapping back to HTTP/canonical errors, or every other
  `sea_orm::DbErr` shape (`DbErr::Conn`, `DbErr::Type`, etc.) that a
  production incident might hit.
- **`EXPLAIN`/query plans/indexes.** Nothing here runs `EXPLAIN (ANALYZE,
  BUFFERS)` or inspects index usage; the two imported analysis documents
  flag specific index candidates (e.g. a covering closure index) that this
  audit neither confirms nor refutes.
- **Deadlock ordering.** The PG harness reproduces SSI serialization
  failures, not lock-ordering deadlocks (`40P01`); RG's operations don't
  currently take explicit row locks (`SELECT ... FOR UPDATE`) to test
  ordering against, so this wasn't exercised.
- **Pool starvation / connection exhaustion.** Not tested; the imported
  performance analysis discusses this qualitatively (long transactions
  holding a pool connection under `max_conns=10`), but this audit's harness
  never runs enough concurrent load to observe pool queuing.
- **Migration drift.** Not tested — this audit runs RG's migrations fresh
  against SQLite and a fresh PostgreSQL container each time; it says nothing
  about upgrade-path correctness on an existing production schema.
- **Static rules are text heuristics, not a real parser.** Both static rules
  (§1.2) operate on `include_str!`'d source text via regex; they don't parse
  the AST, don't resolve types, and don't perform dataflow analysis. They
  are deliberately marked as *interim* — a real implementation belongs in a
  dylint late lint with type information. Concretely: `extract_call_args`'s
  brace-matching doesn't understand string literals or comments containing
  unbalanced parens (none currently exist in the scanned files, but the
  scan would mis-parse if one were introduced); `external_client_param_names`
  matches a `&dyn ...Client` / `Arc<dyn ...Client>` shape textually, so a
  renamed-and-reformatted parameter spanning multiple lines in an unusual
  way could evade it.
- **The `in_tx` probe's precise boundary.** `in_transaction_for_testing()` is
  exact for the *issuing task*: it reads a task-local, and the callback
  fires synchronously on the same task that made the query, so there is no
  heuristic involved for any statement issued directly within a
  `Db::transaction*` closure's `async` body. The boundary is
  `tokio::spawn`: a statement issued from a task spawned *inside* a
  transaction closure would **not** inherit the task-local (task-locals
  don't propagate across `tokio::spawn`) and would be recorded as
  `in_tx = false` — which is actually the *correct* answer for whether that
  statement is protected by the transaction (spawned work outside the
  original task's control-flow isn't guaranteed to run before `COMMIT`
  regardless of what table it's touching), but it means "in_tx" measures
  "is this issued as part of the transaction's synchronous control flow",
  not literally "did this run between `BEGIN` and `COMMIT` in wall-clock
  time". A *detached* spawn that outlives the transaction closure and keeps
  writing after the recorder's assertions have already run is a genuine
  blind spot — the recorder would show nothing to assert against. Checked
  for this gear specifically: **zero** `tokio::spawn`/`task::spawn` call
  sites in `gears/system/resource-group/resource-group/src/` (`grep -rn
  "tokio::spawn\|task::spawn" .../src/` — zero matches), so this boundary is
  not currently exercised by any RG code path; documented here because it's
  a structural property of the probe, not a fact specific to today's
  source.
- **Literal `BEGIN`/`COMMIT`/`ROLLBACK` are invisible to the SQL trace.**
  SeaORM's SQLite driver issues these through `sqlx`'s `TransactionManager`,
  which for SQLite talks to the connection's dedicated worker thread
  directly (`sqlx-sqlite`'s `conn.worker.begin/commit/rollback`), bypassing
  the `Statement`/metric-callback machinery entirely — confirmed by reading
  `sqlx-sqlite-0.8.6`'s `transaction.rs`/`worker.rs`. There is no `Info`
  event for these. The `in_tx` probe (above) is how this audit substitutes
  for that; the trace dumps mark transaction-scope *transitions* with a
  synthetic `-- [enter tx scope] --` / `-- [outside tx] --` marker rather
  than a literal captured `BEGIN` statement — documented in
  `query_recorder.rs`'s module doc.
- **SQLite's lack of native `RETURNING` inflates measured statement counts
  relative to production PostgreSQL.** `sea_orm::DbBackend::support_returning()`
  is unconditionally `true` for Postgres but `false` for SQLite unless the
  `sqlite-use-returning-for-3_35` feature is enabled (it isn't, in this
  workspace's `sea-orm` feature set). Confirmed by reading
  `sea-orm-1.1.20/src/executor/insert.rs::exec_insert_with_returning`: on
  the `false` branch, every `ActiveModel::insert()` call issues the `INSERT`
  *and then a separate `find_by_id` SELECT* to hydrate the returned model —
  purely a SeaORM/SQLite artifact, invisible on Postgres. This means every
  single-row insert this audit measured on SQLite carries one extra `SELECT`
  that a production Postgres deployment would not: e.g. `create_root_group`'s
  trace shows `INSERT resource_group` immediately followed by *two*
  `SELECT resource_group` statements (the SeaORM-implicit one, then
  `GroupRepository::insert`'s own explicit re-read — RG-08) where Postgres
  would show only the second, explicit one. **This does not change the
  scale-invariance verdicts** (RG-04/06/07/10 are about statement count
  *growing with N*, and the constant SeaORM-artifact overhead is per-row
  regardless of backend, so the *slope* is what matters and is backend-
  independent) but it does mean the *absolute* per-operation statement
  counts in `docs/analysis/traces/*.txt` are inflated relative to what the
  same code path would show against PostgreSQL, by roughly one extra
  `SELECT` per row inserted. Noted inline in `query_recorder.rs`'s
  `RecordedQuery::param_count` doc and repeated here for visibility.

## 6. Concurrent-write risk framing

**Not** "resource-group has no concurrent production writers, so the risk
is low." That's not accurate: in-process `ClientHub` consumers of
resource-group (e.g. tenant-resolver's `rg-tr-plugin`, verified by reading
`gears/system/tenant-resolver/plugins/rg-tr-plugin/src/domain/service.rs`)
only call **read** methods (`list_groups`, `get_group_ancestors`,
`get_group_descendants`) — there is no in-process `ClientHub` writer today.
But the **REST write surface is public**: `POST /resource-group/v1/groups`,
`PUT /resource-group/v1/groups/{group_id}`, `DELETE
/resource-group/v1/groups/{group_id}`, `POST
/resource-group/v1/memberships/{group_id}/{resource_type}/{resource_id}`,
`DELETE` on the same path, `POST`/`PUT`/`DELETE
/types-registry/v1/types[/{code}]` (all confirmed in
`src/api/rest/routes/{groups,memberships,types}.rs`) are reachable by any
authenticated HTTP caller. Concurrent-write risk is therefore **non-zero**
and depends on external HTTP traffic patterns (multiple API clients/
replicas hitting the same tenant, group, or type concurrently), not on
whether another *gear* calls into resource-group's write path in-process.

## 7. Related documents

- [concurrent-write-performance-analysis.md](./concurrent-write-performance-analysis.md)
  — the prior static analysis of write-path cost (round-trips, write
  amplification, transaction duration under load). This audit's dynamic
  traces corroborate its per-operation cost breakdown with actual measured
  statement counts (§2, §4) rather than estimates, and its "lots of
  round-trips" diagnosis is the same n-plus-one class this audit's
  scale-invariance rule catches mechanically.
- [transaction-isolation-analysis.md](./transaction-isolation-analysis.md) —
  the prior analysis of isolation-level correctness (where SERIALIZABLE is
  necessary vs redundant, and the membership race). This audit reproduces
  its central claims against real PostgreSQL (RG-01's race, RG-03's missing
  retry) rather than by static reasoning alone, and adds RG-15 (retry
  silently defeated by error stringification) as a mechanism that
  document's "type transactions not retry-aware" section didn't have
  visibility into.

## 8. Self-check against acceptance criteria

- `cargo test -p cf-gears-resource-group`: green (SQLite audit tests fast,
  ~0.1-0.3s per binary; the PG harness binary runs in ~2-3s when Docker is
  present, and in well under a second when it skips).
- `cargo fmt --check` / `cargo clippy -p cf-gears-resource-group --tests -- -D
  warnings`: clean.
- 10/10 known defects rediscovered by general rules (§2).
- 5 commits beyond the "±1" budget were needed to address two rounds of
  adversarial review (testcontainers migration, class-based static rule,
  param-count tracking, plus this report) — each is its own commit with
  DCO sign-off, none amend prior history.
