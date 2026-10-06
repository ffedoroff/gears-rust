Created:  2026-10-02 by Constructor Tech
Updated:  2026-10-06 by Constructor Tech

# `CredStore` value migration

One-off, stop-the-world operator tool that moves the secret values of an existing
`CredStore` installation into the immutable-versions store introduced by ADR-0006
(`CredStorePluginClientV2`). It stays an isolated crate and is **deleted from the
repository once every installation has migrated**.

It works for any old store whose values can only be read through its own Rust code
(for example in-process AES-GCM encryption): you link your **old plugin** and your
**new plugin** (`CredStorePluginClientV2`) into a small binary and call `run`. The
tool owns the procedure: it is resumable after any failure and keeps its progress in
the credstore database.

This crate is the engine: the phases, the progress tables, the commands and the
`LegacyStore` seam through which it reads the old store. **For an old plugin of the
published contract** (`CredStorePluginClientV1` of `cf-gears-credstore-sdk` 0.2) use
the sibling crate **`credstore-value-migration-v1`**
(`gears/credstore/credstore-value-migration-v1`): it bridges that contract to
`LegacyStore`, so the plugin's existing V1 implementation plugs in with no adapter,
and its `run(old, new)` is the operator's entry point. It lives outside the
workspace because depending on the published SDK puts a second version of
`cf-gears-credstore-sdk` into the Cargo graph, which makes every
`cargo -p cf-gears-credstore-sdk` ambiguous.

## The operator's flow

1. Stop the old credstore. Take a snapshot of the database and of the old store.
2. Run `credstore-value-migration migrate`. If it fails (exit `1`), fix the cause
   and run it again: it resumes. If it needs a decision (exit `2`) read its report.
   Repeat until it exits `0`.
3. Start the new credstore. The schema migrations are already applied (by the
   tool, through the platform's own runner), so the gear just starts.
4. Later, after the values are verified in the running gear:
   `credstore-value-migration cleanup`.
5. Delete the crate when every installation is done.

## The old store

The engine reads the old store through [`LegacyStore`]: `get` the current value at an
old address and `delete` it. The address is what the shipped gear passed to its
plugin, `(tenant_id, reference, owner_id)`, with `owner_id` only for a private record.
A `LegacyError::Unavailable` is transient (retried), `LegacyError::Failed` is final;
an error text never carries a value.

```no_run
use std::process::ExitCode;
use std::sync::Arc;

use async_trait::async_trait;
use credstore_sdk::{CredStorePluginClientV2, SecretValue};
use credstore_value_migration::{LegacyError, LegacyStore};
use uuid::Uuid;

struct MyOldStore;

#[async_trait]
impl LegacyStore for MyOldStore {
    async fn get(
        &self,
        _tenant_id: Uuid,
        _reference: &str,
        _owner_id: Option<Uuid>,
    ) -> Result<Option<SecretValue>, LegacyError> {
        // Read (and decrypt) the entry; `Ok(None)` when it is absent.
        Ok(None)
    }

    async fn delete(
        &self,
        _tenant_id: Uuid,
        _reference: &str,
        _owner_id: Option<Uuid>,
    ) -> Result<(), LegacyError> {
        // Delete the entry; an absent entry is success.
        Ok(())
    }
}

// Constructed directly (no `ClientHub`) with the SAME configuration the new gear will use.
async fn build_new_plugin() -> anyhow::Result<Arc<dyn CredStorePluginClientV2>> {
    anyhow::bail!("construct your new plugin here")
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    credstore_value_migration::run(Arc::new(MyOldStore), build_new_plugin().await?).await
}
```

## Commands

```text
credstore-value-migration [--database-url URL] migrate [--accept-losses] [--discard-values]
credstore-value-migration [--database-url URL] cleanup [--dry-run] [--include-fence-key] [--drop-state]
```

`--database-url` (a `postgres://` or `sqlite://` URL of the credstore gear's
database; an in-memory `SQLite` database is refused) can also be given in
`CREDSTORE_MIGRATION_DATABASE_URL`.

| Exit | Meaning |
|---|---|
| `0` | done |
| `1` | aborted by an error (also a bad command line): the reason is on stderr, fix the cause and run the **same command** again |
| `2` | the operator has to decide: `migrate` found rows that end up without a value (read the report, then run again with `--accept-losses`); `cleanup --drop-state` found evidence rows it keeps |

* `migrate --accept-losses` accepts that rows whose value is missing from the old
  store, or fails its fingerprint check, end up without a value. The decision is
  **persisted**: later runs do not ask again.
* `migrate --discard-values` is for an installation whose old backend was the
  in-memory plugin (no value survived): nothing is read or copied, every row is
  marked `discarded` and stays `declared`, the schema is migrated. The old plugin
  is never called (pass a stub). It cannot be chosen once values were copied.
* `cleanup` deletes by default; `--dry-run` only reports.

Only one run may work on a database at a time. On `PostgreSQL` a second run
refuses at once (a session advisory lock); on `SQLite` there is no such lock and
the operator guarantees it.

## What `migrate` does

The header row of the progress table names the **phase**; every phase is
idempotent, the per-row **state** says what is left within it, and a restart
resumes from them.

| Phase | What it does | Next |
|---|---|---|
| `verifying` | takes a snapshot of every credential row of the shipped `credstore_secrets` (re-taken on every run while still here, since nothing is decided per row yet); reads every `active` value from the old store and checks it against the shipped fingerprint; **writes nothing else**. Rows that would end up without a value are listed (id, tenant, reference, outcome; never a value): exit `2` unless accepted | `copying` |
| `copying` | per row: read the old value, judge it again, `put` it under `(tenant_id, record_id = row id)` in the new store, read that version back and compare, record `copied` / `unverified_copied` with the version. The snapshot is frozen | `schema` |
| `schema` | applies the gear's own migrations (`m0001`, `m0002`) with the **platform** runner under the gear's name, so the new gear finds them recorded and has nothing left to do for the table. The `m0002` guard lets it through because the header names this phase (or `discard_values`) | `activating` |
| `activating` | per row, in its own short transaction together with its progress update: copied rows get `status = 2, value_version, version = version + 1`; rows without a value get `fallback = 2` (`none`, so the reference does not fall through to an ancestor's value) and stay `declared` | `tidying` |
| `tidying` | per copied row: `destroy(key, Below(value_version))`, which removes the versions an interrupted `put` left behind (nobody else writes during the downtime and versions are ordered). Skipped when the new store does not support `destroy` | `done` |
| `done` | prints the tally per state; a re-run only reports it | |

Transient errors (`ServiceUnavailable`) of either store are retried with a bounded
backoff (5 attempts, 1 s doubling to at most 30 s); anything else, or running out
of attempts, aborts the run (exit `1`) with nothing wrongly marked. A `put` whose
result was not recorded leaves a version nobody points at; the tidy phase removes it.

Fingerprint rules (mirroring the shipped gear): the old fence key is read from the
old store at the nil tenant, reference `cfs-internal-fence-key`, tenant key class
(raw bytes). A row with a fingerprint whose `fp_key_id` is not `1` is
`unknown_fence_key`; otherwise `HMAC-SHA256(fence_key, value)` must match
(constant-time) or the row is `fp_mismatch`. A value absent from the old store is
`missing`. A row without a fingerprint (seeded out of band, served on trust by the
shipped gear) is copied as `unverified_copied`: nothing can prove it right, check
that list. If the fence key is absent while a row carries a fingerprint, the run
aborts. The old address of a row is `(tenant_id, reference, owner)` with
`owner = Some(owner_id)` for a private row (`sharing = 1`) and `None` otherwise.
Statuses `1` and `3` are not copied (`unfinished`; `m0002` deletes those rows).

Before the schema change the tool refuses (exit `1`) when `credstore_secrets`
holds a row that was not there when the snapshot was taken: the old credstore must
stay stopped, and `m0002` is irreversible.

## The progress tables

Created by the tool, never touched by the gear's migrations (the `m0002` guard only
reads the header). No secret value and no fence key is ever stored in them.

`credstore_value_migration` - one header row:
`id` (always `1`), `phase` (`verifying`, `copying`, `schema`, `activating`,
`tidying`, `done`), `accept_losses`, `discard_values`, `started_at`, `updated_at`.

`credstore_value_migration_rows` - one row per credential row of the shipped table:
`id` (the credential row id, also the new store's `record_id`), `tenant_id`,
`reference`, `sharing`, `owner_id`, `status_before`, `secret_type_uuid`, `value_fp`
and `fp_key_id` (copied from the shipped schema, which `m0002` drops), `state`,
`value_version`, `activated`, `tidied`, `error` (the last store error text, never a value).

| `state` | |
|---|---|
| `pending` | an `active` row, value not copied yet |
| `copied` / `unverified_copied` | copied, with its `value_version` |
| `missing` / `fp_mismatch` / `unknown_fence_key` | ends up without a value |
| `unfinished` | status `1`/`3` |
| `superseded` | rewritten or deleted after `m0002`: the copy is not what the row points at |
| `discarded` | `--discard-values` |

The tool never `COUNT`s: progress is a log line per batch and in-memory counters,
the final tally scans the table by id. Operators may query it freely, e.g.
`SELECT state, reference FROM credstore_value_migration_rows WHERE state <> 'copied'`.

## The `m0002` guard

The gear's `m0002` migration cannot carry values. It therefore fails, changing
nothing, when `credstore_secrets` holds a row with `status = 2` and the tool has not
recorded that copying finished (the header is in phase `schema` or later, or
`discard_values` is set), with the message to run `credstore-value-migration
migrate` (or `migrate --discard-values`). A fresh installation has no rows and
passes. The guard stays in `m0002` permanently.

## What `cleanup` does

Run it only after the values are verified in the running gear (the point of no
return for the old store). It needs the migration to be `done` and is driven by the
progress table, strictly by recorded addresses (never by enumerating the store):

* `copied`, `unverified_copied`, `unfinished`, `superseded`: delete the old entry
  (an absent entry is success), then remove the progress row;
* `missing`, `discarded`: nothing was there; the progress row is removed;
* `fp_mismatch`, `unknown_fence_key`: **kept**, with their old entries, as evidence;
  reported;
* before deleting anything, every candidate whose reference parses as a UUID equal
  to the id of any credential record is refused (see below): the run aborts, exit `1`;
* the old fence key goes **last**, only with `--include-fence-key`, and only when
  nothing but evidence is left;
* `--drop-state` finally drops the two progress tables when no row is left; evidence
  rows block it (exit `2`). Without the flag the tables stay.

It is resumable: a progress row is removed right after its old entry is deleted.

**Do not let the old and the new store share a mount and a prefix.** The old layout
and the new key `{prefix}/{tenant_id}/{record_id}` have the same shape, so an old
reference that is a UUID equal to a record id *is* a new key. `cleanup` refuses such
references; `migrate` cannot know whether the stores share a path. A fingerprint
catches a wrongly read value, but not for a row without one (`unverified_copied`).

## Tests

```text
cargo test -p cf-gears-credstore-value-migration                      # SQLite, no Docker
CREDSTORE_MIGRATION_REQUIRE_DOCKER=1 cargo test -p cf-gears-credstore-value-migration -- --ignored
```

The first runs the end-to-end suites over `SQLite` (the real `m0001`/`m0002` through
the platform runner, fake old and new stores, failures injected at every phase
boundary and in the middle of every phase: each re-run completes and the end state
equals an undisturbed run's). The ignored tests need Docker: the same flows on a
real `PostgreSQL` (including the advisory lock). The bridge for the published V1
contract and the rehearsal on real services (Vault and `PostgreSQL`) are tested in
`credstore-value-migration-v1`.
