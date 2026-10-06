---
status: superseded by ADR-0006
date: 2026-07-08
---

Created:  2026-07-07 by Virtuozzo International GmbH
Updated:  2026-10-01 by Constructor Tech

# ADR-0003: Value-Fingerprint Fence for the Metadata/Value Dual Write

**ID**: `cpt-cf-credstore-adr-value-fingerprint-fence`

**Superseded by [ADR-0006](0006-cpt-cf-credstore-adr-immutable-value-versions.md).**

## Context and Problem Statement

A write spans the gear's metadata row and the backend value with no shared transaction, so two concurrent last-writer-wins writes could interleave crosswise and leave a value under a sharing label that a different writer set. Separately, the bare-version `ETag` restarted at 1 for every re-created row, so a stale validator could match a different generation (ABA).

## Decision

Each row stored `value_fp = HMAC(fence_key, value)` written atomically with the metadata; a read recomputed it and failed closed (404) on a mismatch. The `ETag` became the generation-bound pair `(row id, version)`.

## Why it was replaced

Under immutable value versions with an exact-bytes `get`, a mismatch between a row and the backend is impossible by construction: there is nothing for a fingerprint to detect, so `value_fp`, the fence key and the fence metrics are removed. A backend that returns different bytes violates the plugin contract; the gear does not detect out-of-band tampering. The generation-bound `ETag` is **kept**: the record id is minted at create and never reused. See ADR-0006.
