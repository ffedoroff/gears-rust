---
status: proposed
date: 2026-08-03
decision-makers: Constructor Fabric Steering Committee
---

# ADR-0006: How a Failed Precondition Names the Entities That Block It


<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [Typed optional list inside one violation](#typed-optional-list-inside-one-violation)
  - [One violation per blocking entity](#one-violation-per-blocking-entity)
  - [Identifiers inside `description`](#identifiers-inside-description)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

## Context and Problem Statement

Gears that refuse a mutation because other rows depend on it are required by their own design documents to tell the caller *what* blocks it. Resource Group's delete contract states the response body must include a list of blocking entities — children and/or memberships — so the caller can display what prevents deletion.

The canonical `FailedPrecondition` context carries `violations: Vec<PreconditionViolation>`, and each violation carries three strings: `type`, `subject`, `description`. There is no field for the identity of a blocking entity. A gear wanting to name blockers therefore has three shapes available, and the choice is a platform contract question rather than a gear-local one:

* encode identifiers inside `description` as prose or as an ad-hoc format;
* emit one violation per blocker, using `subject` or `description` per entity;
* extend `PreconditionViolation` with a typed field for blocking-entity identifiers.

Two facts constrain the choice. First, the published JSON schema for the `FailedPrecondition` category closes `PreconditionViolation` with `"additionalProperties": false`, and that schema describes a versioned GTS error type — so adding a field is a schema change, not a free extension. Nothing in the repository validates responses against that schema today, which makes the current situation drift rather than breakage, but the schema is the published contract external consumers may validate against. Second, at least one gear's SDK documents an invariant that it emits exactly one violation per `FailedPrecondition`, and its typed projection collapses the violation list to its first element — so "one violation per blocker" is a breaking change for that gear's consumers, not a neutral encoding choice.

A related precedent already drifts the same way: `QuotaViolation` carries a `retry_after_seconds` field that its own published category schema does not list, and that schema is closed too. Whatever this ADR decides should also settle whether that field is legitimate.

## Decision Drivers

* Machine readability — the canonical error envelope exists so consumers do not parse prose; encoding identity in free text reintroduces exactly the coupling the envelope removes.
* Published-contract integrity — a versioned error type whose instances do not validate against its own schema is worse than one that lacks a field.
* Additivity for existing emitters — sixty-four call sites across nine gears construct violations today; none should need editing.
* Anti-oracle constraints — some blockers must not be named at all, so whatever field exists must be legitimately omittable without the response looking malformed.
* SDK stability — typed projections that assume a single violation must not silently lose data.

## Considered Options

* Extend `PreconditionViolation` with a typed, optional list of blocking-entity identifiers, and version the category schema accordingly.
* Emit one violation per blocking entity, reusing `subject` for identity.
* Keep identifiers in `description` under a documented string format.

## Decision Outcome

Chosen option: **extend `PreconditionViolation` with a typed, optional list of blocking-entity identifiers, and update the published category schema in the same change.**

The field is additive in the Rust API — the three-argument constructor is unchanged and identifiers are attached through a separate setter, so existing emitters compile untouched. It is additive on the wire — the field is omitted when empty, so responses from emitters that never set it are byte-identical to today. The list lives *inside a single violation* rather than across several, which preserves the single-violation invariant that at least one SDK documents and keeps its typed projection lossless.

The schema is not treated as optional collateral. Because the category schema closes the violation object and describes a versioned type, the same change must add the field to that schema. Emitting a field the published contract forbids is not acceptable even while nothing enforces it, and the `retry_after_seconds` precedent shows that leaving such gaps unrecorded lets them multiply.

Emitters remain responsible for *what* they put in the field. The field's documentation must state that it is legitimately empty when the emitter cannot disclose identities without leaking information it does not own, and that an empty list is not a defect. Anti-oracle rules stay with the emitting gear; the envelope only provides the channel.

### Consequences

* Good, because blocker identity becomes machine-readable without any consumer parsing prose.
* Good, because no existing emitter or consumer needs changing: the constructor, the wire shape for current emitters, and single-violation projections all keep working.
* Good, because it settles the `retry_after_seconds` precedent instead of leaving a second undocumented extension in place.
* Bad, because it changes a published schema for a versioned error type, which requires deciding whether the version increments — an additive optional field argues against it, but the schema's own `additionalProperties: false` means consumers were entitled to assume the field set was final.
* Bad, because a shared field invites over-disclosure: any gear can now put identifiers in an error body, and only its own review discipline prevents leaking what the caller may not see. The field's documentation mitigates this; it does not enforce it.
* Neutral: gears that never set the field are unaffected in every respect.

### Confirmation

* Round-trip tests in the canonical error library covering an absent field, an empty list and a populated list, including deserialization of payloads written before the field existed.
* A schema-conformance check for at least one populated instance against the updated category schema, so the drift this ADR closes cannot silently reopen.
* A test in the emitting gear asserting that identifiers the gear must not disclose are absent from the field, so the anti-oracle rule is pinned where it is owned.

## Pros and Cons of the Options

### Typed optional list inside one violation

* Good, because identity is structured, so consumers dispatch on data rather than on text.
* Good, because it is additive in both the Rust API and the wire format.
* Good, because it does not disturb single-violation SDK projections.
* Bad, because it requires changing a published, closed schema for a versioned type.
* Bad, because the field is generic, so its misuse is a review concern across every gear rather than a local one.

### One violation per blocking entity

* Good, because it needs no new field at all — the existing triple already has a `subject`.
* Good, because it models "several independent problems" honestly when that is what the situation is.
* Bad, because it breaks a documented single-violation invariant and a typed projection that keeps only the first element, silently discarding the rest.
* Bad, because `subject` is used as a stable dispatch classifier, so overloading it with per-entity identity conflates routing with payload.
* Bad, because no gear in the platform emits multiple violations for one precondition today, so it introduces a shape consumers have never had to handle.

### Identifiers inside `description`

* Good, because it changes nothing: no schema edit, no library change, no version question.
* Good, because it satisfies a requirement worded as "so the caller can display what prevents deletion" — displaying text is exactly what it supports.
* Bad, because it recreates the parse-the-message pattern the canonical envelope was introduced to eliminate.
* Bad, because it creates an undocumented string format that nothing validates, which is the same contract-drift surface the platform rejects elsewhere.
* Bad, because a second consumer of the same shape — a sibling operation blocked by the same class of entity — would have to agree on that format informally.

## More Information

Review expectation: revisit if a second gear needs to name blockers whose identity is not a single opaque string, since the field's element type would then need reconsidering rather than extending.

Supersession: this ADR does not supersede the RFC 9457 wire-format or typed-enum decisions; it extends one context payload within them. A future decision to carry structured entity references — rather than identifier strings — in error contexts would supersede this ADR.

Out of scope: which identifiers a given gear may disclose, and the wording of any gear's blocking-entity requirement. Both belong to the emitting gear's design document.

## Traceability

- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-adr-rfc9457-wire-format` — Keeps the extension inside the established problem-details envelope rather than adding a parallel channel.
* `cpt-cf-adr-typed-enum-impl` — Preserves the typed context representation; the new field is part of the typed precondition context, not an untyped bag.
* `cpt-cf-adr-sdk-canonical-projection` — Constrains the choice so that existing single-violation projections stay lossless.
* `cpt-cf-adr-gts-error-identification` — Requires the versioned category schema to be updated alongside, since the type is GTS-identified.
