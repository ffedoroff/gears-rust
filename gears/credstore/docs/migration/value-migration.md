Created:  2026-09-15 by Constructor Tech
Updated:  2026-10-04 by Constructor Tech

# Moving existing values into the immutable-versions store

> **Temporary document.** Delete it, together with the `docs/migration/`
> directory, once every deployment that held credentials written before ADR-0006
> has completed the procedure below, together with the two tool crates it
> describes (`gears/credstore/credstore-value-migration` and
> `gears/credstore/credstore-value-migration-v1`).
>
> None of it applies to an installation created after ADR-0006 shipped: it never
> wrote a value at the old address, so `m0002` runs over an empty table and there
> is nothing to move. An installation whose old backend was the in-memory plugin
> has no values to copy either (they did not survive a restart), but it still
> runs the tool once, with `--discard-values`: the schema migration refuses to run
> over credential rows the tool has not accounted for (see "The `m0002` guard").

ADR-0006 changes how a value is addressed in the value store:

| | Old | New |
|---|---|---|
| Store key | `tenant_id` + `reference` + key class (owner or tenant) | `(tenant_id, record_id)`, where `record_id` is the row's `id` |
| Which value is current | the one value under the key | the immutable version the row points at: column `value_version` of `credstore_secrets` |
| Integrity check | fingerprint columns `value_fp` / `fp_key_id` with a fence key kept in the store | none; PostgreSQL alone decides which version is current |

A store key holds many immutable versions. A write is a `put` that returns an
opaque `value_version`; the row is then switched to that version in PostgreSQL.
A row with `value_version IS NULL` is `declared` (`status = 4`); a row with a
`value_version` is `active` (`status = 2`). The table enforces this pairing with a
`CHECK`, so the two columns are always set together.

No value written before ADR-0006 is reachable by the new contract: nothing was
ever written under the new key. The gear's schema migration `m0002` therefore
cannot carry values; it reshapes the schema and leaves every surviving row
`declared`:

- adds `value_version` (`NULL`) and `fallback` (default `1`, `inherit`);
- deletes the rows in the retired statuses `1` and `3` (unfinished writes and
  deletes), drops the shipped `status` check (PostgreSQL does this before it
  rewrites any row, because the shipped check rejects the new code), turns every
  `active` row into `declared`, and only then narrows the `status` check to
  `(2, 4)`;
- drops `value_fp`, `fp_key_id` and the index that swept unfinished rows;
- creates two empty internal tables: the write-intent table
  `credstore_write_intents` (in-flight secret writes, with the record's
  reference) and the cleanup-debt table `credstore_store_cleanup`
  (obligations on the value store that the gear executes right after a commit
  or heals on a later access).

`m0002` moves no store bytes and mints no `value_version`. There is **no gc
table, no maintenance job, no background work and no fingerprint fence** after
it. Moving the values
is a separate, one-off job: the **value-migration tool**, run by the operator
outside the gear, against the database and the stores. The gear does not
contain or run it.

**Part 1** is what the operator does. **Part 2** is what the tool consists of
and how to build the binary the operator runs.

---

# Part 1 — Running the migration

## The flow

The migration is stop-the-world. The old and new key shapes and plugin contracts
cannot both serve the same reference, so a rolling or mixed-version rollout is
not supported.

```
1. stop the old credstore; snapshot the database and the old store
2. credstore-value-migration migrate     (repeat until it exits 0)
3. start the new credstore
3b. after verification: credstore-value-migration cleanup
4. delete the tool crates from the repository once every installation has migrated
```

**Step 2** is the whole migration. `migrate` verifies every old value against its
shipped fingerprint, copies it into the new store, applies the gear's own schema
migrations (`m0001`, `m0002`) through the platform's migration runner, points each
row at its new version (`activate`) and tidies the versions an interrupted write
left behind. It keeps its progress in the credstore database, so it is
**resumable**: after any failure, run the same command again.

**Step 3**: the new credstore finds the schema migrations already recorded in its
migration history and has nothing left to do for the table, so it just starts.

**Step 3b**: `cleanup` retires the superseded entries of the old store. Nothing
forces it: the entries harm nothing beyond occupying space and holding a second
copy of every secret. Run it only after the values are verified in the running
gear (see "After the migration").

## Commands and exit codes

```text
credstore-value-migration [--database-url URL] migrate [--accept-losses] [--discard-values]
credstore-value-migration [--database-url URL] cleanup [--dry-run] [--include-fence-key] [--drop-state]
```

`credstore-value-migration` is whatever you named your binary (Part 2).
`--database-url` is the credstore gear's database (`postgres://` or `sqlite://`;
an in-memory SQLite database is refused) and can also be given in
`CREDSTORE_MIGRATION_DATABASE_URL`.

| Exit | Meaning | What you do |
|---|---|---|
| `0` | done | continue with the next step |
| `1` | the run aborted (also a bad command line); the reason is on stderr | fix the cause, run the **same command** again: it resumes |
| `2` | a decision is needed | `migrate`: some rows end up without a value; read the report, then run again with `--accept-losses`. `cleanup --drop-state`: evidence rows are kept, so the tables stay |

- `migrate --accept-losses` accepts that rows whose value is missing from the old
  store, or fails its fingerprint check, end up without a value. The decision is
  **persisted**: later runs do not ask again.
- `migrate --discard-values` is for an installation whose old backend was the
  in-memory plugin: nothing is read or copied, every row is marked `discarded` and
  stays `declared`, the schema is migrated. The old store is never called (a stub
  will do). It cannot be chosen once values were copied.
- `cleanup` deletes by default; `--dry-run` only reports.

## Prerequisites

1. The new store is in place and is a versioned backend with ordered versions.
   For Vault / OpenBao that is the `vault-credstore-plugin` over a KV v2 mount with
   **`delete_version_after = 0s`** (disabled) and **`cas_required = false`**. KV v2
   keeps **10 versions per key by default** (`max_versions` of `0` or unset also
   means 10, not unlimited). The effective limit of a key is the **larger** of the
   mount's `max_versions` and the key's own (`vault kv metadata put
   -max-versions=N`): a per-key value can raise the limit above the mount's, never
   lower it. Whoever needs more sets a larger `max_versions` on the mount (or
   raises it per key). A key normally holds the current version plus at most a few
   transient ones, so 10 is enough unless many writes to the same record fail
   between successful ones; above the limit Vault permanently removes the oldest
   versions, which can be the one the database row points at, and that record then
   answers `SECRET_UNREADABLE` until rewritten. These settings are the operator's
   obligation: the plugin does not check them at startup or later. A mount that
   expires versions by age (`delete_version_after` above zero) would lose values
   the database still points at.
2. Register the new credential types in the types registry — the base type, every
   derived type, and any custom types of your own, under
   `gts.cf.core.credstore.credential.v1~`. This is additive; the old version does
   not see them.
3. Issue PDP policies for the new resource type and its six actions (`list`,
   `read`, `write`, `delete`, `read_secret`, `write_secret`). They are inert
   while the old version runs, **and that is what keeps authorization from
   failing the moment the new version starts.** See the type-scoped authorization
   ADR (0010) for who reissues what. Skipping this breaks every call regardless
   of how well the values migrate.
4. Remove any `static-credstore-plugin.config.secrets` block from deployment
   configuration. Config seeding was withdrawn and the field is now rejected
   (config validation fails at boot), so the new version will refuse to start
   with it present.
5. Build the migration binary (Part 2).
6. **Rehearse it** (see "Rehearsal"). Do not meet the tool for the first time
   inside the downtime window.
7. The tool and the new credstore must reach the same new store with the same
   configuration (mount, prefix, namespace, credentials): a different mount,
   prefix or key makes the whole copy useless.

## The migration (downtime)

1. **Stop the old credstore.** Take a snapshot (or a dump) of the credstore
   database and a snapshot of the old store, and of the new one if it is not empty.
   Not optional: `m0002` is irreversible with respect to data.
2. Run `credstore-value-migration migrate`. Read what it prints. It works through
   these phases, each idempotent:

   | Phase | What it does |
   |---|---|
   | `verifying` | snapshots every credential row of the shipped `credstore_secrets` (re-taken on every run while still in this phase, since nothing is decided per row yet), reads every `active` value from the old store and checks it against its shipped fingerprint. Writes nothing else. Rows that would end up without a value are listed (row id, tenant, reference, outcome; never a value) and the run exits `2` unless the decision was accepted |
   | `copying` | per row: reads the old value, judges it again, `put`s it under `(tenant_id, record_id = row id)` in the new store, reads that version back and compares, and records `copied` / `unverified_copied` together with the version. The snapshot is frozen |
   | `schema` | applies the gear's migrations (`m0001`, `m0002`) with the platform runner, under the gear's name, so the new gear finds them recorded. The `m0002` guard lets this through because the progress table says copying finished (or `discard_values`) |
   | `activating` | per row, in its own short transaction together with its progress update: copied rows get `status = 2`, their `value_version` and a bumped row `version`; rows without a value get `fallback = 2` (`none`) and stay `declared` |
   | `tidying` | per copied row: `destroy(key, Below(value_version))`, which removes the versions an interrupted `put` left behind (nobody else writes during the downtime, and versions are ordered). Skipped when the new store does not support `destroy`; the leftovers are then inert |
   | `done` | prints the tally per state; a re-run only reports it |

   If it exits `1`, fix the cause (the reason is on stderr) and run it again; if it
   exits `2`, read the list, understand each entry, and run it again with
   `--accept-losses`. Repeat until it exits `0`.
3. **Start the new credstore.** A row left `declared` (see "Rows that did not get a
   value") returns no value; that is expected and listed in the report.

## After the migration

Verify in the running gear: read a value, read an inherited value, list, rotate.
Check a sample of records of each sharing mode. The tool's progress tables are
there to be queried, for example

```sql
SELECT state, reference FROM credstore_value_migration_rows WHERE state <> 'copied';
```

If anything goes badly, roll back (below); the old store entries are still there,
because only `cleanup` touches them.

When you are satisfied, run `credstore-value-migration cleanup` (add `--dry-run`
first to see what it would do). **It is the point of no return for the old
store.**

- It needs the migration to be `done`. It is driven by the progress table,
  strictly by the old addresses recorded there, never by enumerating the store. Deleting an absent entry counts as
  success, and a progress row is removed right after its old entry is deleted, so
  a re-run is safe and resumes.
- It keeps the entries of rows that failed the fingerprint check
  (`fp_mismatch`, `unknown_fence_key`), with their progress rows, as **evidence**,
  and reports them.
- It deletes the old fence-key entry last, **only** with `--include-fence-key`
  (after which the kept evidence entries can no longer be verified), and only when
  nothing but evidence is left.
- `--drop-state` finally drops the two progress tables, when no row is left;
  evidence rows block it (exit `2`). Without the flag the tables stay.
- Before deleting anything it refuses (exit `1`) if an old reference looks like a
  UUID equal to the `id` of a credential record: that is the shape of a new key,
  and the old and the new store may share a mount (see "Constraints").

When every installation has migrated, delete the two tool crates, this document
and the `docs/migration/` directory from the repository.

## The `m0002` guard

The schema migration cannot carry a value, so it must never run over credentials
whose values have not been moved. It therefore **fails, changing nothing**, when
`credstore_secrets` holds a row with `status = 2` and the tool has not recorded
that copying finished (its header is in phase `schema` or later, or
`discard_values` is set). The new credstore refuses to start with an error that
names the tool and its command. A fresh installation has no rows and passes. The
guard stays in `m0002` permanently; once no installation holds shipped rows it is
inert.

So the order is enforced by the database, not only by this document: starting the
new credstore before `migrate` has finished does not damage anything, it only
fails at boot.

## What each failure does

| Failure | The tool |
|---|---|
| A transient store error (`ServiceUnavailable`, an unavailable old store) | retries with a bounded backoff: 5 attempts, 1 s doubling to at most 30 s. If it still fails, the run stops with exit `1`; nothing is marked that was not done. Run it again |
| A **loss**: an `active` row whose value is missing from the old store, fails the fingerprint check (`fp_mismatch`) or names an unknown fence key (`unknown_fence_key`) | not copied, listed in the report, exit `2` until the operator decides with `--accept-losses`. Afterwards the row stays `declared` (see below) |
| A **store contract violation**: the new store returns other bytes than were written, or holds nothing at the version it just returned (after a few more attempts) | the run stops with exit `1`, nothing is marked as done for that row. It is a store failure, not a property of the data: re-running does not help until the store or the plugin is fixed |
| A final (non-transient) error of either store, or the old fence key absent while rows carry fingerprints (nothing can be verified) | the run stops with exit `1`; the reason, and for a row-level error its id, is on stderr |
| A credential row appeared after the snapshot (the old credstore ran during the migration) | before the schema change the run stops with exit `1`: the old credstore must stay stopped; restore the database snapshot and start over |
| The progress tables and `credstore_secrets` disagree (for example the database was restored from another snapshot) | the run stops with exit `1`; restore the snapshot taken before the migration and start over |

A `put` whose result was not recorded (the run died in between) leaves a version
nobody points at. The tidy phase removes it where the store supports `destroy`.

## Rows that did not get a value

A row whose value was missing from the old store, or failed the fingerprint check
(`missing`, `fp_mismatch`, `unknown_fence_key`), is **not** copied and stays
`declared`. The `activating` phase marks it `fallback = 2` (`none`). Reason:
`fallback = 1` (`inherit`) would make resolution walk past the row and up the
tenant chain, so the moment an ancestor is given a value the descendant would
quietly serve *that* secret instead of returning an honest "no value". `none`
fails closed. These records need their secret provisioned again by their owner.

Rows with no fingerprint at all (seeded out of band, which the shipped gear served
on trust) are copied and recorded as `unverified_copied`: nothing can prove them
right, so check that list in the report.

Rows in the retired statuses `1` and `3` are recorded as `unfinished` and not
copied; `m0002` deletes them.

## Type-divergent pairs

`migrate` also reports, read-only, every **same-tenant** pair of a private and a
non-private row with one reference whose secret types differ. Both rows keep
working after the cutover. What changes is that a **new** private override whose
type differs from the type it overrides is rejected with
`TYPE_MISMATCH_WITH_INHERITED`; records that already exist are not touched. The
report is information for the owners of those references (they may want to align
the types before writing new overrides). A divergence between a tenant and an
**ancestor** needs the tenant hierarchy and is not computed by the tool.

## Rollback

- **Before `cleanup` has deleted anything:** restore the database snapshot and
  start the old version. The old entries are exactly what the old version reads.
  The values `migrate` wrote to the new store are inert: no restored row points
  at them. A later re-run writes new versions under the same keys and its tidy
  phase removes the earlier ones where the store supports `destroy`; otherwise
  remove them with the store's own tooling. Policies and type registrations are
  additive and do not interfere. The progress tables live in the database, so
  restoring it discards them and a new attempt starts from the beginning.
- **After `cleanup`:** restore the database snapshot **and** the snapshot of the
  old store, because the old entries are gone. A list of key names is not a
  backup; take a store snapshot if the backend offers one.

Do **not** use a schema `down` migration against live data: `m0002`'s `down`
always fails, because it cannot bring back fingerprints or dropped rows.

## Constraints

- **Do not let the old and the new store share a mount and a prefix.** The old
  layout and the new key `{prefix}/{tenant_id}/{record_id}` have the same shape,
  so an old reference that is a UUID equal to a record id *is* a new key.
  `cleanup` refuses to delete such references, but `migrate` cannot know whether
  the stores share a path. A fingerprint catches a wrongly read value, but not for
  a row without one.
- **One run at a time on a database.** On PostgreSQL the tool takes a session
  advisory lock, so a second run refuses at once. That lock lives as long as the
  tool's connection, so the connection must go to PostgreSQL directly or through a
  pooler in **session** mode, **not** PgBouncer in transaction mode (there the lock
  would be released behind the tool's back). On SQLite there is no such lock: the
  operator guarantees that one process works on the database file.
- **The old credstore stays stopped** from the snapshot until the tool exits `0`.
- The binary, the old plugin code and the progress tables all handle plaintext
  secrets or the means to read them: treat the host that runs them accordingly,
  and remove the binary when the migration is verified. The progress tables hold no
  value and no fence key, only the old addresses, fingerprints, states and new
  versions.

## Rehearsal

Rehearse the whole procedure before the window opens: restore a copy of the
production database into a scratch database, point the binary at it and at a
scratch new store, and run `migrate` (and later `cleanup`) the way you will run
them. The tool has no separate pre-downtime dry run; its `verifying` phase writes
nothing but its snapshot into its own progress tables, so the rehearsal on a copy
is how you see the loss report, the unverified list and the time it takes, and
find a plugin that cannot read back what it wrote.

## Verification summary

- After `migrate` exits `0`: every credential row of the shipped table has a
  progress row; every `active` one is `copied` / `unverified_copied` with a
  `value_version`, or listed as `missing` / `fp_mismatch` / `unknown_fence_key`
  (or `discarded`).
- After the new credstore starts: no row has `status = 2` with `value_version IS
  NULL` (the table rejects that anyway), and reads through the gear return the
  expected values for a sample of records of each sharing mode, including an
  inherited one.
- After `cleanup`: the old entries recorded as migrated are gone; evidence entries
  (if any) are still there.

---

# Part 2 — The tool and its binary

## Who needs it

Any installation that holds credential rows written before ADR-0006, including one
whose old backend was the in-memory plugin (`migrate --discard-values`, with a stub
for the old store). An installation created after ADR-0006 needs nothing: its table is empty,
so `m0002` has nothing to guard.

## Two crates

| Crate | Where | What it is |
|---|---|---|
| `cf-gears-credstore-value-migration` | `gears/credstore/credstore-value-migration`, **in the workspace** | the engine: the phases, the progress tables, the commands and exit codes, and a small interface to the old store (`LegacyStore`: `get` the current value at an old address, `delete` it) |
| `credstore-value-migration-v1` | `gears/credstore/credstore-value-migration-v1`, **outside the workspace** | the operator-facing front for an old plugin that implements the published `CredStorePluginClientV1` (`cf-gears-credstore-sdk` 0.2): it accepts that existing implementation **directly** (`V1Store` bridges it to the engine's interface), and brings the reference Vault layout of the old store and the Docker rehearsal |

Neither is part of the gear, and neither is linked into it. The front lives outside
the workspace on purpose: depending on the published SDK 0.2 puts a second version
of `cf-gears-credstore-sdk` into the Cargo graph, which would make every
`cargo -p cf-gears-credstore-sdk` in the workspace ambiguous. The engine therefore
never sees the old SDK. Build the front through its own manifest:

```text
cargo build --manifest-path gears/credstore/credstore-value-migration-v1/Cargo.toml --example migrate
```

The old store's addresses are what the shipped gear handed to its plugin:
`(tenant_id, reference, owner_id)`, with `owner_id = Some(..)` only for a private
record (the owner's key class) and `None` for a tenant or shared record. An error
from the old store is **transient** (`Unavailable`; retried) or **final**
(`Failed`; aborts); an error text must never carry a value.

## The operator binary

If your old plugin implements the published `CredStorePluginClientV1`, the binary
is about twenty lines: construct the two plugins directly (no `ClientHub`, no
gear), with the deployment's own configuration, and hand them to `run`.

```rust
use std::process::ExitCode;
use std::sync::Arc;

use credstore_sdk::CredStorePluginClientV2;
use credstore_sdk_v02::CredStorePluginClientV1;

// Your pre-ADR-0006 plugin, through its published contract (it decrypts in-process).
async fn build_old_plugin() -> anyhow::Result<Arc<dyn CredStorePluginClientV1>> {
    anyhow::bail!("construct your old plugin here, with the deployment's own configuration")
}

// Your new plugin, constructed directly with the SAME configuration the new gear will use.
async fn build_new_plugin() -> anyhow::Result<Arc<dyn CredStorePluginClientV2>> {
    anyhow::bail!("construct your new plugin here")
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let old = build_old_plugin().await?;
    let new = build_new_plugin().await?;
    credstore_value_migration_v1::run(old, new).await
}
```

`gears/credstore/credstore-value-migration-v1/examples/migrate.rs` is a compilable
skeleton of the same shape: copy it into your crate and fill in the placeholders.

- The binary depends on the front (by path or git: it is not published), on the
  current `cf-gears-credstore-sdk` (the contract of the new store), and on your
  two plugins. Your old plugin keeps compiling against the published SDK, under a
  renamed dependency, for example `credstore-sdk-v02 = { package =
  "cf-gears-credstore-sdk", version = "0.2" }`.
- The old plugin is only called through `get` (verify and copy) and `delete`
  (`cleanup`). The calls carry the tool's fixed service identity in the old
  contract's `SecurityContext`. `ServiceUnavailable` is transient, `NotFound` is
  read as an absent entry, anything else aborts the run (exit `1`). A reference the
  old SDK rejects never reaches the plugin: it aborts the run naming the row.
- The **old fence key** is read through the same plugin, at the nil tenant
  (`00000000-0000-0000-0000-000000000000`), reference `cfs-internal-fence-key`,
  tenant key class (no owner); it is raw bytes. `cleanup --include-fence-key`
  deletes it the same way.
- If the old plugin does **not** implement the published contract, implement the
  engine's `LegacyStore` yourself (an adapter over your old code) and call the
  engine's `run(legacy, new)`; see the engine's README.

The reference old store for Vault (`vault::VaultV1` in the front) is a
`CredStorePluginClientV1` over KV v2 used only by the rehearsal: the value, base64,
in the field `value` at `{mount}/data/{prefix}/{tenant_id}/{reference}` (tenant key
class) or `.../{reference}/owner/{owner_id}` (owner class), the latest KV version
being the current value; the fence key at the nil tenant. **No such plugin shipped
in this repository**; a real installation brings its own old plugin.

## Constructing the new store outside ClientHub

The tool calls the new store through `CredStorePluginClientV2` (`put`, `get` by
version, `delete_key`, and `destroy` when supported) on the `Arc<dyn
CredStorePluginClientV2>` you pass in. Build your new plugin directly, with the
deployment's own configuration (endpoint, credentials, encryption key), as the
plugin's `init` would, but without registering anything in the ClientHub and
without starting the gear. It is called with a fixed service identity of the tool
in the `SecurityContext`; a plugin may use it for correlation only and must not
authorise on it.

Use the **same configuration the new gear will use**, so that the versions the tool
writes are readable by the running gear: a different mount, key or namespace makes
the whole copy useless.

For the Vault / OpenBao plugin of this repository (`cf-gears-vault-credstore-plugin`)
this is one call, `vault_credstore_plugin::client_from_config(&cfg)`, which returns
`anyhow::Result<Arc<dyn CredStorePluginClientV2>>` ready for `run`:

```rust
use vault_credstore_plugin::client_from_config;
use vault_credstore_plugin::config::VaultCredStorePluginConfig;

let cfg = VaultCredStorePluginConfig {
    address: "https://vault.internal:8200".to_owned(),
    token_file: Some("/vault/secrets/token".to_owned()),
    mount: "secret".to_owned(),
    path_prefix: "credstore".to_owned(),
    ..VaultCredStorePluginConfig::default()
};
let new = client_from_config(&cfg)?;
```

It validates the configuration exactly as the gear does at startup and builds the
very client the gear registers; it sends nothing to Vault, publishes nothing and
starts no gear. `${VAR}` placeholders are not expanded by it (the gear expands them
while loading its `config` block), so pass resolved values. The Docker rehearsal in
`credstore-value-migration-v1` builds the new store this way.

## What the plugin author ships before the cutover

1. A **`CredStorePluginClientV2` implementation** that passes the SDK conformance
   suite (the `conformance` feature of the SDK, one macro invocation):
   - `put` stores a new immutable version under `(tenant_id, record_id)` and
     returns the provider's version; `get` returns exactly the bytes of that
     `put` or `None` when that version is gone;
   - if it supports `destroy` (and `supports_destroy` returns `true`), it must
     provide **ordered versions** per key; without `destroy` there is no tidy and no
     cleanup of old versions (they stay until `delete_key`);
   - `get` may report `SecretUnreadable` for a version it holds but can never
     return (lost or rotated decryption key, corrupt entry), as opposed to a
     transient `ServiceUnavailable`. The tool reads each copied value back and
     stops on any difference, so a plugin that cannot read back what it just wrote
     is found during the rehearsal, not in production.
2. The **old code kept compiling**, for the migration binary only: its `get` and
   `delete` over the old addresses, against the published SDK under a renamed
   dependency. It is not shipped with, or loaded by, the new gear.
3. A **built and rehearsed migration binary**, or the means for the operator to
   build one (the two constructors above), before the downtime window opens.

## The progress tables

Created by the tool, never touched by the gear's migrations (the `m0002` guard only
reads the header). No secret value and no fence key is ever stored in them.

`credstore_value_migration` — one header row: `id` (always `1`), `phase`
(`verifying`, `copying`, `schema`, `activating`, `tidying`, `done`),
`accept_losses`, `discard_values`, `started_at`, `updated_at`.

`credstore_value_migration_rows` — one row per credential row of the shipped table:
`id` (the credential row id, also the new store's `record_id`), `tenant_id`,
`reference`, `sharing`, `owner_id`, `status_before`, `secret_type_uuid`, `value_fp`
and `fp_key_id` (copied from the shipped schema, which `m0002` drops), `state`,
`value_version`, `activated`, `tidied`, and `error` (the last store error text,
never a value).

| `state` | |
|---|---|
| `pending` | an `active` row, value not copied yet |
| `copied` / `unverified_copied` | copied, with its `value_version` |
| `missing` / `fp_mismatch` / `unknown_fence_key` | ends up without a value |
| `unfinished` | status `1` / `3` |
| `superseded` | rewritten or deleted after `m0002`: the copy is not what the row points at |
| `discarded` | `--discard-values` |

The header's `phase` is what a restart resumes in; the per-row `state` says what
is left within a phase. The tables stay after `cleanup` unless `--drop-state` is
given.

## Fingerprint rules (mirroring the shipped gear)

The old fence key is read from the old store (above). A row with a fingerprint whose
`fp_key_id` is not `1` is `unknown_fence_key`; otherwise `HMAC-SHA256(fence_key,
value)` must match (constant-time) or the row is `fp_mismatch`. A value absent from
the old store is `missing`. A row without a fingerprint is `unverified_copied`. If
the fence key is absent while a row carries a fingerprint, the run aborts.
