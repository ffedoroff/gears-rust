---
status: proposed
date: 2026-08-03
decision-makers: Constructor Fabric Steering Committee
---

# ADR-0009: Resolve the Contradiction Between ADR-0004 and the Shipped RG Tenant Resolver Plugin


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Supersede ADR-0004: accept the projection with owned lifecycle](#supersede-adr-0004-accept-the-projection-with-owned-lifecycle)
  - [Uphold ADR-0004: make AM's resolver canonical and forbid the RG resolver](#uphold-adr-0004-make-ams-resolver-canonical-and-forbid-the-rg-resolver)
  - [Leave both in place and treat symptoms individually](#leave-both-in-place-and-treat-symptoms-individually)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

## Context and Problem Statement

[ADR-0004](0004-cpt-cf-account-management-adr-resource-group-tenant-hierarchy-source.md) rejected making Resource Group (RG) the canonical tenant hierarchy store, and rejected the alternative "keep both stores and synchronize" specifically because it "introduces split-brain risk between the two hierarchy stores" and makes "reconciliation, dual-write ordering, and failure recovery first-class architectural problems".

The platform nevertheless ships `rg-tr-plugin`, which its own module documentation calls a "Production replacement for `static-tr-plugin`". It answers Tenant Resolver `get_descendants` / `is_ancestor` by walking RG's group closure filtered on the tenant type path, and `tr-authz-plugin` builds every list scope from that answer, denying when the descendant set comes back empty. AM's own tenant-resolver plugin is disabled by default and carries a lower priority.

So the running system resolves tenants from the store ADR-0004 declined to make canonical, while AM continues to own `tenants` and `tenant_closure` as the source of truth. Both representations of a tenant exist, neither is authoritative for all consumers, and nothing reconciles them.

Three concrete consequences were observed while auditing tenant deletion:

* No code in the repository creates the RG tenant node. AM never calls `create_group`; RG's seeding path has no production caller; RG's own PRD states each root "carries its own `tenant_id` (inherited from the main tenant via external seeding)". The node is created by operator tooling through the public API.
* Nothing removes it either. AM's hard-delete hook cascades only its own user-group subtree. A tenant therefore leaves a permanent node behind in RG's ownership graph.
* AM's soft-delete precondition `TENANT_HAS_RESOURCES` probes RG for groups carrying the tenant's id — and the tenant node carries its own id as `tenant_id`, so the node counts itself. While the node exists, soft-delete is refused. The only way through is deleting the node first, which inverts the lifecycle: the irreversible step precedes the authorizing one.

The contradiction, not any single defect, is what blocks progress: every candidate fix silently commits the platform to one of the two models.

## Decision Drivers

* Tenant lifecycle correctness — a tenant must not be resolvable as active after AM has marked it deleted, and must not become unresolvable while AM still considers it live.
* Split-brain avoidance — the reason ADR-0004 gave for rejecting dual stores has not gone away; if two stores are kept, reconciliation must be owned rather than implied.
* Ownership clarity — `cpt-cf-account-management-principle-source-of-truth` claims AM owns tenant hierarchy and lifecycle semantics; a shipped plugin resolving tenants from RG contradicts that claim unless the boundary is stated.
* Deletion must be authorizable — the step that destroys data must come after the step that approves it, and must be retryable against a durable record.
* Deferred lifecycle events — tenant lifecycle CloudEvents are explicitly deferred until the events bus exists, so no event-driven reconciliation is available today.

## Considered Options

* Supersede ADR-0004: accept RG as the tenant hierarchy projection, with AM remaining the source of truth and an owned reconciliation path.
* Uphold ADR-0004: declare `rg-tr-plugin` a deviation, make AM's resolver canonical, and forbid enabling the RG resolver in production.
* Leave both in place undocumented and treat each observed symptom as an isolated defect.

## Decision Outcome

Chosen option: **supersede ADR-0004 in part — accept the RG tenant node as a projection of AM's tenant, with AM remaining the source of truth and the projection's lifecycle explicitly owned.**

ADR-0004's rejection of RG as the *canonical* store stands and is not reopened. What is superseded is its rejection of a second representation: one already exists in production, and refusing to name it has left it unowned rather than absent.

The boundary this ADR fixes:

* AM remains the source of truth for tenant existence, hierarchy and lifecycle state. The RG tenant node carries no lifecycle state of its own — RG has no status column and cannot express soft deletion.
* The RG tenant node is a projection whose creation and removal are triggered by the tenant lifecycle, not by RG's own API acting alone.
* Removal is triggered from AM's existing hard-delete pipeline, alongside the user-group cleanup it already performs, and before the AM row is torn down. AM triggers; RG executes and owns the semantics. This does not make AM the manager of downstream resource CRUD, which its scope excludes — it is the same signalling AM already performs for user groups.
* `TENANT_HAS_RESOURCES` must not count the tenant's own projection node. The node is the ownership boundary, not a resource under it.
* RG must refuse to cascade a delete across a tenant boundary. That guard is an RG-internal invariant and is required regardless of this ADR's outcome.

### Consequences

* Good, because the irreversible step moves after the authorizing step: the AM row survives until RG cleanup has succeeded, giving a durable record to retry and diagnose against.
* Good, because the existing hard-delete pipeline already provides idempotency, retry and fencing, so the projection's removal inherits them rather than needing new machinery.
* Good, because it removes the deadlock that currently makes tenant soft-delete unreachable whenever a projection node exists.
* Bad, because it accepts the split-brain window ADR-0004 warned about: between AM marking a tenant deleted and RG cleanup completing, the RG-backed resolver still reports the tenant active. This window must be bounded and monitored, and a reconciler becomes a first-class obligation rather than an implied one.
* Bad, because it adds a cross-gear ordering dependency to a pipeline that previously touched only AM-owned data.
* Neutral: deployments that read AM's tables directly and never materialize an RG node are unaffected; for them the projection simply does not exist.

### Confirmation

* A cross-gear end-to-end scenario, run in both authorization stacks, asserting that the selected resolver never reports a tenant active after AM has marked it deleted, and that after hard deletion the tenant resolves through neither path.
* A fault-injection scenario crashing before and after RG cleanup, asserting the AM row survives an incomplete cleanup and that a retry converges.
* A test asserting the soft-delete precondition ignores the projection node while still counting every other group and membership carrying the tenant's id.

## Pros and Cons of the Options

### Supersede ADR-0004: accept the projection with owned lifecycle

* Good, because it describes the system that is actually deployed instead of the one the record claims.
* Good, because naming the projection makes its lifecycle assignable; today it is unowned by omission.
* Good, because it keeps AM's source-of-truth claim intact — the projection is derived, not authoritative.
* Bad, because it concedes the dual-store risk ADR-0004 rejected, and that concession must be paid for with a reconciler.
* Bad, because the consistency window is observable by authorization decisions, not merely by reporting.

### Uphold ADR-0004: make AM's resolver canonical and forbid the RG resolver

* Good, because it eliminates the second store and with it the entire class of reconciliation problems.
* Good, because it needs no new ownership rules — AM already owns everything that would remain.
* Bad, because it disables a plugin shipped and documented as the production resolver, which is a behavioural change for every deployment using it.
* Bad, because the RG tenant type, tenant-root uniqueness enforcement and the group hierarchy that realizes the tenant tree would become vestigial while remaining in RG's design.
* Bad, because it is the larger migration, and nothing in the audit suggests the RG-backed resolution is failing on its own terms.

### Leave both in place and treat symptoms individually

* Good, because it requires no decision and no migration now.
* Bad, because each of the three observed consequences has a fix that presupposes one model, so choosing per-symptom decides the architecture by accident.
* Bad, because the record would continue to state that a deployed configuration was rejected.
* Bad, because the deadlock stays: tenant deletion remains unreachable through the documented path.

## More Information

Review expectation: this ADR should be revisited when tenant lifecycle CloudEvents land, since an event bus would allow the projection to be maintained by subscription rather than by a pipeline hook, and may make the reconciler cheaper than it is today.

Supersession: this ADR supersedes ADR-0004 only in its rejection of a second tenant representation. ADR-0004's core decision — that RG is not the canonical tenant hierarchy store — remains in force, and any future attempt to make RG canonical requires a new ADR superseding ADR-0004 in full.

Out of scope: the mechanics of the RG-side cascade guard, the size bound on cascade operations, and the error-envelope shape used to report blocked deletions. Those are design and defect concerns, recorded separately.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-account-management-principle-source-of-truth` — Reaffirms AM as canonical owner of tenant existence and lifecycle while naming the RG node a derived projection.
* `cpt-cf-account-management-principle-delegation-to-rg` — Extends the delegation boundary from user groups to an explicitly derived tenant projection, without transferring canonical ownership.
* `cpt-cf-account-management-fr-tenant-soft-delete` — Removes the deadlock in the `TENANT_HAS_RESOURCES` precondition by excluding the tenant's own projection node.
* `cpt-cf-account-management-nfr-data-lifecycle` — Places projection removal inside the deprovisioning sequence that must complete before final hard deletion.
* `cpt-cf-account-management-fr-tenant-hard-delete` — Extends the hard-delete pipeline with projection cleanup ahead of AM storage teardown.
* `cpt-cf-account-management-dbtable-tenants` — Keeps the AM tenant table authoritative; the projection derives from it.
