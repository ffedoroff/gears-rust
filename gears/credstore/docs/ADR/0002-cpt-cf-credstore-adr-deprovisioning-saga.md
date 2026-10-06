---
status: superseded
date: 2026-07-04
---

Created:  2026-07-07 by Virtuozzo International GmbH
Updated:  2026-10-03 by Constructor Tech

# ADR-0002: Status-Driven Deprovisioning Saga with Name Retention

**ID**: `cpt-cf-credstore-adr-deprovisioning-saga`

**Superseded by [ADR-0006](0006-cpt-cf-credstore-adr-immutable-value-versions.md).**

## Context and Problem Statement

With a stateful gear ([ADR-0001](0001-cpt-cf-credstore-adr-stateful-gear.md)) a delete spans two stores, the metadata row and the backend value, and a failure between the two steps left no owner for the leftover.

## Decision

Delete was a saga: the row moved to a `deprovisioning` status that held the reference until the backend value was removed, resumed by a `DELETE` retry or a periodic reaper.

## Why it was replaced

The saga and its name retention existed because a successor's value shared the deleted value's backend key. With immutable value versions that race cannot occur: deleting a record is one row transaction that records a purge of the record's key, executed by the request; a failed purge stays recorded until a possible external cleanup job. There is no `deprovisioning` status, no reaper and no name retention. See ADR-0006.
