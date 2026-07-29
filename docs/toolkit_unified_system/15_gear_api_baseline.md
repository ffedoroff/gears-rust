<!-- Created: 2026-07-29 by Constructor Tech -->

# Gear API Baseline

What a gear must provide by default, so that "the consumer reasonably expected it" becomes a
checkable minimum instead of a ticket argued about for months.

Each item is marked **required**, **required with a documented refusal**, or **optional**. A refusal
is recorded as a line in the gear's `DESIGN.md` — not by leaving the question unanswered.

Examples come from tickets filed against a shipped gear. None of them were bugs in the sense of
"code does the wrong thing"; every one was a gap between what the gear provided and what an
integrator had to build around. That is exactly the category this document exists to prevent.

Related: [`04_rest_operation_builder.md`](./04_rest_operation_builder.md) (how routes are declared),
[`05_errors_rfc9457.md`](./05_errors_rfc9457.md) (error shape),
[`07_odata_pagination_select_filter.md`](./07_odata_pagination_select_filter.md) (lists),
[`14_security_review_checklist.md`](./14_security_review_checklist.md) (security side).

---

## B1. CRUD completeness

- **B1.1** (required with a documented refusal) If a resource has several independently mutable
  fields, a client can change one of them without sending the others. Either method satisfies this:
  `PATCH` with partial semantics (omitted field = leave as is, explicit `null` = clear where the field
  is nullable), or `PUT` where unsent fields keep their stored value. If the only way to change one
  field is a `PUT` that requires all of them, `DESIGN.md` states why partial update is inexpressible.

  This is **not** a requirement that every `PUT` be joined by a `PATCH`. A resource replaced as a
  whole — a policy document, a secret value, a metadata document, a rule set — has no independently
  mutable fields, and full replacement is the correct and safer shape for it. The test is not which
  verb is present but whether changing one field forces the client to know, and resend, the rest.

  *Convention across the platform (verified):* no resource in the repository exposes both verbs. Gears
  pick one per resource — `PUT` for whole-document replacement (`file-storage` `/policy`, `credstore`
  `/secrets/{ref}`, `account-management` metadata entries, the resource-group type registry, `oagw`
  upstreams and routes), `PATCH` for records with independent fields (`account-management` tenants and
  users, `mini-chat` chats, `simple-user-settings`, `ledger` annotations). Both are legitimate; the
  choice belongs to the resource's nature.

  *Violation:* a group resource with three independent fields — name, parent, metadata — whose only
  update method is a `PUT` that deliberately requires every one of them. Partial update is not merely
  missing, it is unrepresentable: an omitted field cannot be distinguished from "do not change". Note
  also that the parent field is not an ordinary column — changing it triggers cycle detection and a
  closure-table rebuild — so a `PATCH` here is a design question, not a mechanical addition.

- **B1.2** (required) The create request shape and the read response shape agree: a field the client
  sends flat comes back at the same level. Otherwise a client cannot read an object and send it back
  without rearranging fields.
  *Example:* `parent_id` accepted flat on create, returned nested under `hierarchy` on read.

- **B1.3** (required with a documented refusal) If an entity lives in a container and can move
  between containers, there is an **atomic** move operation — not "delete then add" on the client
  side, which leaves the entity in neither container if the second call fails.

- **B1.4** (required with a documented refusal) For every operation a client may retry, the behaviour
  on repeat is defined: either idempotent, or a typed conflict.

## B2. Lists

- **B2.1** (required with a documented refusal) If the UI shows a counter next to a list item, the
  counter arrives in the same response, as one aggregate per page — not as N client requests.
  *Example:* counters absent from the model, so the front end rendered zeros for every row, while the
  batch-per-page technique was already in use elsewhere in the same gear.

- **B2.2** (optional, platform decision) An envelope `total` is not a single gear's call: `PageInfo`
  lives in the shared OData crate and changes for everyone. A gear records the need rather than
  inventing its own field. Note that an exact total re-introduces a full count over the filtered set
  on every page, which is what keyset pagination exists to avoid; `$count` as an opt-in is the
  idiomatic answer.

- **B2.3** (required) Every field declared filterable has an end-to-end test through HTTP: a value
  that should match does match, a value that should not returns an empty page, and a **malformed**
  value returns 400.
  *Example:* after a resolver was generalised to serve two list endpoints, one of them had no filter
  test of its own — breaking the resolver turned exactly one unrelated test red, and the whole
  second path was unguarded.

- **B2.4** (required) The number of SQL statements per page depends neither on page size nor on the
  number of values in an `in (...)` filter — or the dependency is explicitly documented.
  *Example:* a filter resolver issued one query per value: 20 values produced 21 statements, slope
  exactly 1.0. Guard it with a test that measures at two different N and asserts equality; a test
  pinning a single number does not catch a slope.

## B3. Error codes and shapes

- **B3.1** (required) An error caused by client input is 4xx. 500 is reserved for backend failures.
  The diff contains no `map_err` collapsing a foreign error type into one variant without inspecting
  it.
  *Example:* a list endpoint wrapped every failure of the pagination helper into a database error, so
  a filter with a quoted UUID — a client mistake — returned 500.

- **B3.2** (required) Unique violation → 409 with a typed domain variant; foreign-key violation on
  delete → 409; serialization conflict → retry, never a 500.
  *Example:* a duplicate primary key surfaced as 500 with the body "An internal error occurred",
  making a deliberate identifier squat indistinguishable from a flaky database error in monitoring.

- **B3.3** (required) Every negative REST test goes through `assert_problem_shape`: status,
  `application/problem+json`, the `status`/`title`/`detail` fields, and the absence of
  `stack`/`trace`/`backtrace`.

- **B3.4** (required) The codes and shapes a gear returns match the platform status-code guideline;
  deviations are listed in `DESIGN.md` with a reason.
  *Example:* six error classes documented as 409 return 400 after a deliberate wire change — the
  change was accepted, but recorded only as a code comment, so every consumer reading the docs is
  misled.

## B4. The contract as an artifact

- **B4.1** (required) Every operation appears in OpenAPI with its real response codes, including 409
  and 403 where reachable. If the spec is hand-maintained, it drifts; prefer generating it from the
  route declarations.
  *Example:* a hand-written spec described an entirely different type-registry API than the one
  implemented — different payload, different path parameter, different filter field — and 403 was
  documented nowhere while reachable everywhere.

- **B4.2** (required) Uniqueness that is **not** enforced (name, code, arbitrary field) is explicitly
  called out in `DESIGN.md` as not unique — otherwise a consumer is entitled to assume the opposite.
  *Example:* duplicate group names accepted with 201, the index behind the field being non-unique.
  Against the gear's own contract this is not a bug — and precisely because the decision was never
  written down, the ticket stayed unresolvable.

- **B4.3** (required) A specification step marked as implemented has a code anchor that covers the
  implementation, not a comment. A checkbox is a claim about code; if nothing verifies the claim, the
  checkbox is worse than no checkbox at all — it stops people from looking.

---

## How to use this list

At design time, before the first endpoint is written: B1 and B2 shape the API. At review time: B3 and
B4 are checked against the diff.

A refusal is a legitimate outcome for every item marked "with a documented refusal" — the point is
that the refusal is visible to the consumer, in `DESIGN.md`, rather than discovered during
integration.
