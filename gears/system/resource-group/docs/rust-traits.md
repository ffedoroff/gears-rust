<!-- Updated: 2026-07-30 by Constructor Tech -->

# Rust SDK Contracts — Resource Group


<!-- toc -->

- [Two traits, two audiences](#two-traits-two-audiences)
- [What the signatures will tell you, so this page does not](#what-the-signatures-will-tell-you-so-this-page-does-not)
- [Contract decisions that a signature does not show](#contract-decisions-that-a-signature-does-not-show)
- [Errors](#errors)
- [ClientHub registration](#clienthub-registration)

<!-- /toc -->

> **The canonical source is the code, not this page.** Signatures, field names, error types and
> doc-comments live in [`resource-group-sdk/src/api.rs`](../resource-group-sdk/src/api.rs) and
> [`resource-group-sdk/src/models.rs`](../resource-group-sdk/src/models.rs). Read them, or
> `cargo doc -p cf-gears-resource-group-sdk --open`.

This page used to carry a hand-transcribed copy of those two files. The copy drifted twice — wrong
field names (`allowed_parents` for `allowed_parent_types`), wrong argument types (a by-value
`ListQuery` that never existed instead of `&ODataQuery`), wrong error type (`ResourceGroupError` where
the trait returns `CanonicalError`), a `metadata` map flattened into the parent object where the model
carries a nested `Option<Value>`, a `Hierarchy` type actually named `GroupHierarchy`, a `type` field
actually named `code`, and a method count that omitted `delete_group_cascade` and `move_group` — and
each time a consumer wrote code against it and had to be corrected by the compiler. Prose cannot be
kept honest about a signature; the compiler can. So what follows is only the part that *is* stable:
which traits exist, what each is for, and the handful of contract decisions that are not visible from
a signature alone.

## Two traits, two audiences

| Trait | Methods | For | ClientHub key |
|-------|---------|-----|---------------|
| `ResourceGroupClient` | 17 | general consumers: domain services, apps, admin flows | `dyn ResourceGroupClient` |
| `ResourceGroupReadHierarchy` | 5 | in-process plugin consumers that must not re-enter the PEP: the AuthZ resolver plugin, the tenant-resolver RG plugin, an in-process AuthZ PDP | `dyn ResourceGroupReadHierarchy` |

`ResourceGroupClient` covers five type operations, seven group operations (including `move_group` and
`delete_group_cascade`), the two hierarchy walks, and three membership operations.
`ResourceGroupReadHierarchy` carries `get_group_descendants`, `get_group_ancestors`, `list_groups`,
`get_group` and `list_memberships` — nothing else, and no writes.

The narrow trait is **not** a subset relationship in the type system: it is a separate trait, backed
in production by a separate object. There is no `ResourceGroupReadPluginClient`; an earlier two-tier
design was collapsed, and `list_memberships` / `get_group` moved onto `ResourceGroupReadHierarchy`
itself.

## What the signatures will tell you, so this page does not

- **List methods take `&ODataQuery`** (from `toolkit-odata`), not a bespoke query struct, and return
  `toolkit_odata::Page<T>` / `PageInfo` — the platform's pagination types, reused rather than
  redeclared.
- **Membership methods take scalar arguments** (`group_id`, `resource_type`, `resource_id`), not a
  request struct.
- **Every fallible method returns `Result<_, CanonicalError>`**, on both traits. See "Errors" below.
- **Model field names are the wire names**, with two deliberate exceptions: `ResourceGroup.code` and
  `ResourceGroupWithDepth.code` serialize as `type`. Type definitions use `allowed_parent_types` /
  `allowed_membership_types`; hierarchy context is `GroupHierarchy` / `GroupHierarchyWithDepth`;
  `metadata` is a nested `Option<serde_json::Value>`, never flattened into its parent.
- **SDK structs serialize `camelCase`; the REST DTOs serialize `snake_case`.** These are two different
  vocabularies over the same model, and that is a property of the contract, not an accident — a
  consumer serializing an SDK struct directly gets `canBeRoot`, a consumer reading REST gets
  `can_be_root`.

## Contract decisions that a signature does not show

**A group's type is immutable after creation.** `UpdateGroupRequest` carries no `code` / `type` field,
and none will be added. Re-typing a group would invalidate its own placement, its children's
placements and possibly its tenant identity at once; the supported migration is delete-and-recreate.

**Re-parenting is `move_group`, not a field on `update_group`.** `update_group` replaces the two
ordinary attributes `name` and `metadata`. `move_group` is the gear's only structural mutation: cycle
detection, `allowed_parent_types` / `can_be_root` compatibility, `max_depth` / `max_width`,
tenant-root uniqueness and the closure-table rebuild all run in one `SERIALIZABLE` transaction with
bounded retry. `new_parent_id: Option<Uuid>` is an explicit choice, not an optional argument: `None`
**means** "make this group a root" and never "leave the parent alone". A caller that does not want to
move a group must not call the method. Full rationale in `DESIGN.md` § API Baseline Decisions,
B1.1/B1.3.

**Both request types are strict.** Every replaceable key is required — an omitted key is a 400, not
"keep the stored value" — and unknown keys are rejected rather than dropped. `metadata` and
`metadata_schema` are tri-state on the wire, so an explicit `null` (clear it) is distinguishable from
an omission (an error).

**Tenant-ness is derived from the type code, not declared.** A group whose type code starts with
`TENANT_RG_TYPE_PATH` opens a new tenant scope (`tenant_id = group.id`); every other group inherits its
parent's tenant. There is no `is_tenant` flag anywhere. The constant is expanded once, in
[ADR-001](./ADR/ADR-001-gts-type-system.md#the-tenant-type-path-is-a-code-constant-not-a-documentation-choice).

**The hierarchy walks are two operations, not one filtered operation.** `get_group_descendants`
returns `depth ≥ 0`, `get_group_ancestors` returns `depth ≤ 0`, and both include the reference group at
`depth = 0`. They mirror `GET /groups/{id}/descendants` and `GET /groups/{id}/ancestors`; there is no
aggregating `/hierarchy` route and no single method that returns both directions.

**`ResourceGroupReadHierarchy` reads are resolved unscoped** — they bypass `PolicyEnforcer` by
construction. A consumer that *is* the PDP cannot route reads back through the PEP without recursing
into itself, so the implementation resolves them with `AccessScope::allow_all()`. The caller supplies
any subject/tenant OData filter and owns its own scoping. This is why the trait is narrow: the type
system, not a runtime check, is what stops a plugin from reaching writes or non-hierarchy reads through
this channel.

**`delete_group_cascade` exists for cross-gear cleanup**, mirroring the REST `force=true` flag, and has
a default implementation that delegates to the non-cascade `delete_group`. Most consumers want
`delete_group` and should surface its `FailedPrecondition` / `Subject::ActiveReferences` to their caller.

## Errors

The trait boundary is `CanonicalError` (per platform ADR 0005 on canonical SDK projections). The single
authoritative AIP-193 ladder is `From<DomainError> for CanonicalError` in the impl crate's
`api::rest::error` — the SDK surfaces that envelope unchanged and adds no classification of its own.

`ResourceGroupError` is an **optional typed projection** over `CanonicalError`
(`From<CanonicalError>`), offered for consumers who want flat `match` dispatch. It is not the trait's
error type and it is not the source of the mapping — the direction of dependency is the opposite of
what earlier revisions of this page implied. Its variants are the canonical families (`NotFound`,
`AlreadyExists`, `InvalidArgument`, `FailedPrecondition`, `Aborted`, `PermissionDenied`, `Internal`,
`Other`), not RG-specific ones; domain families inside `FailedPrecondition` are distinguished by
`precondition::Subject` rather than by a variant. See the `error` module's own docs for the dispatch
table.

## ClientHub registration

Two registrations, and — unlike what this page previously claimed — **two distinct objects**:
`ResourceGroupLocalClient` implements `ResourceGroupClient`, `RgReadService` implements
`ResourceGroupReadHierarchy`. Both are constructed in `Gear::init` (the ordinary phase; `pre_init` is
for gears with the `system` capability). See `resource-group/src/gear.rs` for the current wiring, and
`resource-group/src/domain/local_client.rs` for the adapter that bridges the SDK trait to the domain
services.

Consumers resolve them the usual way:

```rust
let rg = hub.get::<dyn ResourceGroupClient>()?;              // full CRUD
let rg_reads = hub.get::<dyn ResourceGroupReadHierarchy>()?; // narrow, unscoped reads
```

Both traits also have a REST surface; the gear registers `/resource-group/v1/...` and
`/types-registry/v1/...` and declares `capabilities = [db, rest]` — there is no gRPC surface. REST
handlers call the domain services directly rather than going through the SDK trait, per the platform's
gear-layout convention.
