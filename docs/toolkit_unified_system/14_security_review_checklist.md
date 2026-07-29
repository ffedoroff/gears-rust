<!-- Created: 2026-07-29 by Constructor Tech -->

# Security Review Checklist

What must be thought through before a gear PR is merged.

Every item is a yes/no question about **the diff in front of you**. An item that does not apply
needs one line of justification in the PR description — silence is not an answer.

Each item carries a real violation as an example. The examples are not decoration: they show what
the defect looked like in code that passed review, CI and a written specification claiming the
protection was in place.

For the mechanics behind these rules see [`06_authn_authz_secure_orm.md`](./06_authn_authz_secure_orm.md)
(AccessScope, PolicyEnforcer, SecureORM) and [`11_database_patterns.md`](./11_database_patterns.md)
(execution and transactions). For what a gear must expose regardless of security, see
[`15_gear_api_baseline.md`](./15_gear_api_baseline.md).

---

## S1. Tenant scope on every path

- **S1.1** Every public service method that reads or writes a tenant-scoped entity obtains an
  `AccessScope` from `PolicyEnforcer` **and passes it down**. The diff contains no
  `let _scope = …` and no `let _ = enforcer.access_scope(…)`.
  *Violation:* `membership_service.rs` computed the scope in all three membership operations and
  discarded it — a caller in tenant A could add members to, remove members from, and list rows of
  tenant B (VHP-2341).

- **S1.2** The diff contains no `AccessScope::allow_all()`, and no local helper returning it,
  outside of (a) gear-init seeding, (b) the named prefetch pattern in `06_authn_authz_secure_orm.md`,
  (c) a documented in-process exception. Each occurrence carries a comment stating the reason.
  *Violation:* `fn system_scope() -> AccessScope { AccessScope::allow_all() }` in two repositories,
  used by 20+ call sites — while `.secure().scope_with(&scope)` was present everywhere and created
  the appearance of scoping.

- **S1.3** The diff contains no `AccessScope::for_tenant(ctx.tenant_id())` in production code. The
  scope comes from the PDP. If a gear deliberately does not depend on the authz resolver, that
  decision is written in its `DESIGN.md`.

- **S1.4** Every new read path has a test proving a context in tenant B does **not** see an object
  of tenant A. Every new write path has a test proving B cannot modify, delete or attach to A's
  object.
  *Violation:* `remove_membership` never read the group at all — deletion went straight to the
  composite key, so nothing tenant-related was ever checked.

- **S1.5** If an entity is declared `#[secure(no_tenant, …)]` or `#[secure(unrestricted)]`, a naive
  `.secure().scope_with(scope)` on it is **not** used as isolation: for such entities it yields
  deny-all or a no-op. The scope is applied through a correlated `EXISTS` against a parent entity
  that owns `tenant_col`, and a test confirms "own tenant sees, foreign tenant does not".
  *Trap:* on `resource_group_membership` the naive form silently returned zero rows for everyone;
  a plain JOIN also failed, because both tables share a `gts_type_id` column and the generic
  filter helpers emit unqualified column references.

## S2. Gates on global (non-tenant) tables

- **S2.1** Every new entity declared `unrestricted`, or with all four `no_*`, is listed in the
  gear's `DESIGN.md` under global tables, together with the answer to: who may change it.

- **S2.2** Every service method reading or writing such an entity calls `enforcer.access_scope*` —
  even when the resulting scope is discarded. Row-level security cannot help here; the call is the
  only protection.
  *Violation:* the GTS type registry took no `SecurityContext` at all, so any authenticated user of
  any tenant could rewrite the rules every resource group is validated against. One `PUT` emptying
  `allowed_membership_types` stopped user additions platform-wide (VHP-2342).

- **S2.3** `ResourceType.supported_properties` for such a resource is **not empty**. Real PDP
  plugins attach a baseline `In(owner_tenant_id, …)` constraint to every permit, and the PEP
  compiler rejects a constraint on an undeclared property, failing closed into
  `AllConstraintsFailed` → 500 for **permitted** callers.
  *Trap:* the first version of the type-registry gate declared `&[]` and would have returned 500 to
  every allowed caller in any real deployment; unit tests passed because the mock attached no
  constraints.

- **S2.4** The gate is tested under a mock reproducing the shape of a **real** plugin response
  (permit plus `In(owner_tenant_id, [...])`), not only under permit-without-constraints.

## S3. What is visible from outside (leaks and oracles)

- **S3.1** No error message contains an identifier, name or attribute of an object the caller has
  no access to.
  *Violation:* `"Child group tenant_id (X) must match parent tenant_id (Y)"` — by supplying an
  arbitrary `parent_id` a caller learned both that the group exists and which tenant owns it. Real
  values belong in `tracing::debug!`, not in the response.

- **S3.2** Where the difference between "no access" and "not found" is itself a leak, both cases
  return the **same** response (usually 404), and a test compares the two responses byte for byte
  (status and body).
  *Applied:* a group outside the caller's scope reports as non-existent; a foreign target tenant
  returns 404, not 403.

- **S3.3** The response body carries no surrogate ids and no internal fields
  (`assert_no_surrogate_ids`), and no `stack`/`trace`/`backtrace` (`assert_problem_shape`). Checked
  on **every** new REST response, successful and failing alike.

- **S3.4** If an operation accepts a client-supplied identifier (`id`, `code`, a foreign key), the
  PR answers: what happens on collision (must be a typed 409, never a 500), and can a client
  thereby squat an identifier another tenant intends to use.

## S4. In-process paths

- **S4.1** The local ClientHub adapter calls the **same** gated methods as the REST handler. An
  adapter method that accepts `ctx` and ignores it is a defect.
  *Violation:* the type methods of the resource-group adapter took `_ctx` and dropped it, so the
  in-process path was ungated while the HTTP path looked protected.

- **S4.2** Any bypass of `PolicyEnforcer` for in-process calls is **narrowed** to a specific
  scenario (named caller, named operation), documented in `DESIGN.md`, and covered by a test proving
  the gate still applies outside that scenario.
  *Rejected precedent:* a bypass granted to the whole shared client trait — every gear in the binary
  could rewrite the global registry under any context; reverted after review.
  *Accepted precedent:* hierarchy reads for the PEP itself, which would otherwise recurse into the
  authorization it is answering.

- **S4.3** If a gate is added to a path used by another gear's bootstrap, the PR states explicitly
  what happens at platform start.
  *Example:* GTS type registration by account-management runs under a nil-tenant system actor, and
  the static authz plugin denies nil-tenant unconditionally, so on dev stacks registration fails
  closed until policy grants it. Accepted knowingly and recorded in `DESIGN.md`.

## S5. Data and SQL

- **S5.1** Every comparison of a column against an external value is verified for type compatibility
  **on PostgreSQL**, not only on SQLite. Different types mean either an explicit cast or resolution
  to the right type before the value reaches the query.
  *Violations:* `uuid = text` in a group-scope subquery, and `smallint = text` in a filter on a GTS
  path. On SQLite both silently returned an empty page; PostgreSQL rejected the statement.

- **S5.2** A string domain identifier on the wire (GTS path, code) stored as a surrogate is resolved
  **before** `paginate_odata`, including `InList` branches and nested composites, and an unresolvable
  value yields 400 — not an empty page and not a 500.

- **S5.3** A unique-violation is classified through SQLSTATE (`is_unique_violation`), not by matching
  a substring of the driver message. One classifier per gear, not one per repository.
  *Violation:* matching `"duplicate key"` / `"UNIQUE constraint"` would have missed MySQL wording
  entirely, and degrades silently to 500 if driver text changes.

---

## How to use this list

Do not paste the whole list into the PR. The pull-request template carries only triggers
("does the diff touch `domain/` or `infra/storage/`? → walk S1–S5"), and the full text lives here.

Anything on this list that a machine can check must eventually leave it: a checklist that grows
stops being read. Items S1.1, S1.2, S3.3 are the first candidates for lint rules and CI steps.

## Why these specific items

Every item above corresponds to a defect that survived code review, a green CI run, and in six cases
a written contract asserting the protection existed. The value of the list is not that the rules are
clever — they are obvious — but that nothing in the pipeline was checking them.
