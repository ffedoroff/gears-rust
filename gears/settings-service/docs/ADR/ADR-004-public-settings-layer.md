---
description: "ADR of the Settings Service: anonymous-exposable values are served by a separate public-settings gear that calls the authenticated Settings Service API with its own service identity, so no Settings Service route is anonymous."
status: proposed
date: 2026-11-09
decision-makers: Constructor Fabric Steering Committee
---

# ADR-004: Anonymous-Exposable Values Are Served by a Separate Gear Above the Authenticated API

**ID**: `cpt-cf-settings-service-adr-public-settings-layer`

<!-- toc -->

- [Context and Problem Statement](#context-and-problem-statement)
- [Decision Drivers](#decision-drivers)
- [Considered Options](#considered-options)
- [Decision Outcome](#decision-outcome)
  - [Consequences](#consequences)
  - [Confirmation](#confirmation)
- [Pros and Cons of the Options](#pros-and-cons-of-the-options)
  - [A separate public-settings gear above the authenticated API](#a-separate-public-settings-gear-above-the-authenticated-api)
  - [A vendor presentation gateway above the authenticated API](#a-vendor-presentation-gateway-above-the-authenticated-api)
  - [A public route in the vendor's host process over the in-process SDK](#a-public-route-in-the-vendors-host-process-over-the-in-process-sdk)
  - [An anonymous route inside the Settings Service](#an-anonymous-route-inside-the-settings-service)
- [More Information](#more-information)
- [Traceability](#traceability)

<!-- /toc -->

## Context and Problem Statement

The PRD requires (`cpt-cf-settings-service-fr-anonymous-exposable`, p2) that a declaration can be marked anonymous-exposable. The default is off; the mark is forbidden for `secret` and `pii` declarations; only a platform administrator can set it, with an audit record; and the full set of marked declarations MUST be listable. One unauthenticated read, taking the tenant as a parameter, returns the effective values of marked settings only. It reveals nothing else, gives no error that tells an empty tenant from an unknown one, is rate-limited, and never writes.

The same PRD lists the unauthenticated read surface as out of scope: the service exposes no unauthenticated operation, and the pre-login page is served by a presentation gateway, an authenticated trusted caller that reads values the ordinary way and decides what to show without a token. These two statements contradict each other.

The first implementation put an anonymous, externally exposed route into the gear itself. Review asked to keep the Settings Service API always authenticated and to build the public read as a layer on top that calls the service through its ordinary API with its own security context. This matches the repository rules: the toolkit checklist reserves anonymous routes for truly unauthenticated endpoints such as health checks and the OpenAPI document; an anonymous route that returns user data is a critical review finding; every anonymous route must be justified explicitly. The anonymous routes that exist in gears today are health, readiness, OpenAPI, links where a secret token grants access, and service callbacks with a signed token. None of them returns tenant data by an open identifier.

The first consumer is tenant branding on the login page of the Constructor vendor, and other vendors may need the same. Where should the unauthenticated read of anonymous-exposable values live, so that every Settings Service route stays authenticated, the guarantees of the PRD are implemented once for every vendor, and the reader of the values is authorized for real?

## Decision Drivers

* Every Settings Service route is authenticated, and every read of a value is authorized by the PDP against a verified caller.
* The guarantees of the anonymous surface (only flagged settings, no tenant enumeration, failures distinct from empty) are implemented and tested once, not per vendor.
* The layer authenticates as itself with a service identity validated per hop (ADR-0008), not with an anonymous in-process context, so it stays deployable out of process (one gear, one pod).
* An unauthenticated surface is throttled by client IP at the gateway, because identity-keyed zones cannot apply to it.
* Mapping a domain to a tenant is vendor-specific, and the platform has no such lookup.
* The first consumer's delivery must not wait for a new gear's review.
* A service identity reads only its own subtree, so standalone tenants need their own provisioning whichever option is chosen.

## Considered Options

* A separate public-settings gear above the authenticated API
* A vendor presentation gateway above the authenticated API
* A public route in the vendor's host process over the in-process SDK
* An anonymous route inside the Settings Service

## Decision Outcome

Chosen option: "A separate public-settings gear above the authenticated API", because it is the only option that keeps every Settings Service route authenticated and still delivers the anonymous surface the PRD asks for, once, for every vendor, with the reader authorized for real. The Settings Service gains a filter and loses its anonymous route; the unauthenticated read moves to a small gear whose only job is this.

### Consequences

* Settings Service: the anonymous route is removed and every route is authenticated again. `anonymous_exposable` becomes a filter on the authenticated settings browse (`GET /settings-service/v1/settings?tenant=...` with `$filter=anonymous_exposable eq true`) and on the declarations listing (`GET /settings-service/v1/declarations`). The listing filter also meets the PRD clause that the full set of flagged declarations is listable. This is an additive contract change.
* PRD and DESIGN of the Settings Service follow. The unauthenticated read surface clause moves to the public-settings gear with every MUST kept (only flagged values, no enumeration, rate-limited, no writes). The scope statement that the service exposes no unauthenticated operation then holds without exception. The DESIGN anonymous-read section is replaced by a pointer to the new gear, and this ADR is listed in Key ADRs.
* The public-settings gear (working name; the final name is agreed with the Settings Service authors) has one GET route, anonymous and exposed, taking a tenant id. It answers only the key and effective value of flagged settings. An unknown tenant, a tenant it may not read and a tenant with nothing flagged give the same empty `200`. A failure of the Settings Service or of its own identity gives `503`, and any other method gives `405`. It has its own PRD and DESIGN.
* Its identity is an OAuth2 client-credentials service account configured for the gear. The token is cached and refreshed, never exchanged per anonymous request, so anonymous traffic cannot be amplified into the identity provider.
* Its call is the authenticated REST browse above. The Settings Service SDK has no REST binding today and its in-process reader does not authorize the caller in R1, so the gear does not read through the SDK. A REST binding of the SDK, when R2 adds one, may replace the gear's own client.
* PDP: a deployment that runs the gear grants its service identity `read` on setting values in the tenants it serves. A service identity of the root tenant reaches its subtree only, so standalone tenants are not served unless a vendor provisions an identity or policy for them. This is a known limitation, recorded here and not solved here.
* Throttling and load: the route binds an IP-keyed rate-limit zone of the platform gateway, and a vendor that fronts the platform with another edge configures an equivalent limit there. The gear caches each tenant's answer for no longer than the Settings Service's own value-cache staleness bound, so anonymous traffic reaches the Settings Service as a bounded stream of authenticated reads.
* Domain to tenant stays with the vendor: the vendor's own service or page resolves the tenant first and calls the gear by tenant id.
* Delivery in stages: the Settings Service change (route removed, filter added) ships first and alone, and the gear follows in its own change. Until it lands, a vendor that needs the surface may call the authenticated browse from its own presentation gateway, as in the vendor presentation gateway option. The same filtered call serves both, so moving to the gear later changes the caller, not the Settings Service.
* Reversibility: the Settings Service change is additive and independent of the gear, and the gear can be dropped in favour of vendor gateways without touching the Settings Service.
* Data and compliance: no new storage is introduced, and values on the surface stay limited by schema to non-`secret`, non-`pii` declarations, unchanged.

### Confirmation

* The Settings Service route-surface test asserts that no route opts out of authentication, with no exception.
* The public-settings gear's tests assert that an unflagged setting is absent; that an unknown tenant and a tenant with nothing flagged answer a byte-identical empty `200`; that a failed Settings Service call answers `503`; that non-GET methods answer `405`; and that the route binds an IP-keyed zone.
* Review of a deployment that enables the gear checks the PDP grant for its service identity and the edge rate limit.

## Pros and Cons of the Options

### A separate public-settings gear above the authenticated API

A dedicated gear with one anonymous route. It authenticates as a service and reads the flagged values through the authenticated API.

* Good, because every Settings Service route stays authenticated.
* Good, because the guarantees are implemented and tested once, every vendor reuses them, and a vendor that does not need the surface does not deploy the gear.
* Good, because the reader is a real caller authorized by the PDP on every request and is ready for out-of-process deployment.
* Good, because the one anonymous route with tenant data sits in a small gear whose only job is this, so its justification is explicit and local.
* Neutral, because the vendor still maps domain to tenant.
* Bad, because it is a new gear to build, document, package and review, which is slower for the first consumer, and it needs its own REST client to the Settings Service.
* Bad, because a service secret, a PDP grant and an extra network hop must be operated, and the IP zone acts only behind the platform gateway.

### A vendor presentation gateway above the authenticated API

Each vendor's own pre-login service resolves the tenant and calls the authenticated browse with its own token, which is the role the PRD scope section already names.

* Good, because no anonymous route with tenant data exists anywhere in the platform.
* Good, because it is the smallest platform change (the filter only) and the authorization is real.
* Good, because the vendor already owns domain to tenant, caching and edge limits, so it is the fastest path for a vendor that already has such an endpoint.
* Bad, because each vendor re-implements the guarantees (only flagged, no enumeration, failure distinct from empty) outside platform tests, and the implementations drift.
* Bad, because the platform does not deliver the surface the PRD asks for, so the requirement becomes a vendor responsibility.
* Bad, because a vendor whose pre-login service is on a legacy stack ties the surface to that stack.

### A public route in the vendor's host process over the in-process SDK

The host that embeds the Settings Service adds an anonymous route and reads through the in-process SDK client.

* Good, because there is no extra network hop.
* Good, because it deploys together with the Settings Service.
* Neutral, because the vendor still maps domain to tenant.
* Bad, because the in-process reader does not authorize its caller in R1, so the security context passed is nominal; this is the anonymous in-process coupling the platform plans to remove.
* Bad, because the SDK cannot select flagged settings, so a new SDK method is needed.
* Bad, because it is vendor-specific and not reusable.
* Bad, because the public surface cannot be deployed or scaled apart from the Settings Service.

### An anonymous route inside the Settings Service

The design as first written and first implemented: an anonymous, externally exposed route of the gear resolves flagged settings at the tenant directly.

* Good, because it has the fewest moving parts: selection, resolution and the guarantees sit next to the flag.
* Good, because there is no service identity to operate.
* Good, because it matches the PRD requirement and the DESIGN section as written.
* Bad, because it is the case the anonymous-route review rule marks critical, tenant data behind a public identifier, and review asked to keep the API authenticated.
* Bad, because it contradicts the PRD scope statement that the service exposes no unauthenticated operation.
* Bad, because reads run with no caller identity, so no PDP decision covers them.
* Bad, because anonymous traffic reaches the gear and its database directly.

## More Information

Scope: only the read of anonymous-exposable values. Other anonymous surfaces are out of scope. The decision is revisited if R2 gives the SDK a REST binding with caller authorization (the gear then reads through it), or if the platform gains a domain-to-tenant lookup (the gear may then accept a domain).

This ADR amends the anonymous-read section of the DESIGN and does not supersede ADR-002. Platform references:

* [ADR-0008 two-plane authentication](../../../../docs/arch/toolkit-oop/ADR/0008-cpt-cf-adr-two-plane-auth.md): service-to-service client credentials and per-hop validation.
* [Toolkit OoP DESIGN, "Runs outside Flight Control (OoP)"](../../../../docs/arch/toolkit-oop/DESIGN.md#runs-outside-flight-control-oop): one gear per pod; an anonymous context between gears is safe only inside one process and is a temporary coupling.
* [Authn, authz and secure ORM](../../../../docs/toolkit_unified_system/06_authn_authz_secure_orm.md): an anonymous route receives an anonymous context, and the checklist reserves such routes for truly unauthenticated endpoints such as health checks and the OpenAPI document.
* [Toolkit review rules](../../../../docs/toolkit-pr-review/rules/toolkit.md): rule TOOLKIT-REST-002, an anonymous route with user data is CRITICAL.
* [SECURITY.md](../../../../docs/security/SECURITY.md): every anonymous route is justified explicitly.

## Traceability

- **PRD**: [PRD.md](../PRD.md)
- **DESIGN**: [DESIGN.md](../DESIGN.md)

This decision directly addresses the following requirements or design elements:

* `cpt-cf-settings-service-fr-anonymous-exposable`: the unauthenticated surface moves to the public-settings gear; the flag, its constraints and the listable set stay in the Settings Service.
* `cpt-cf-settings-service-nfr-security-baseline`: the threshold of zero unauthenticated operations holds for the Settings Service without exception.
