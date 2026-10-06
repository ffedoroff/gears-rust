Updated:  2026-10-06 by Constructor Tech

# `CredStore` SDK

SDK crate for the `CredStore` gear, providing public API contracts for credential storage in Gears.

## Overview

This crate defines the transport-agnostic interface for the `CredStore` gear:

- **`CredStoreClientV1`** — consumer-facing trait
  (`get_record`/`get_secret`/`put`/`patch`/`list`/`delete`); `get_record`
  returns the record's metadata (`Credential`, never the value) and
  `get_secret` the value with its usage envelope (`Secret`)
- **`CredStorePluginClientV2`** — backend trait: a versioned value store keyed
  by `StoreKey { tenant_id, record_id }`. Required: `put` (returns the
  provider's `ValueVersion`), `get` (by version), `delete_key`. Optional:
  `destroy` (`DestroySelector::Below` / `Exactly`), declared through
  `supports_destroy`. It holds no sharing/hierarchy/policy — that lives in the
  gear (ADR-0006)
- **`SecretRef`** / **`SecretValue`** / **`SharingMode`** / **`Credential`** / **`Secret`** — Domain models
- **`CredStoreError`** — Error types for all operations; `SecretExpired` means the decisive record's secret has expired (its metadata stays readable with status `expired`; never served, never replaced by an ancestor's value); a stored version the backend can never return (lost or rotated decryption key, corrupt entry, or a version gone although the pointer did not move) surfaces as `Internal` — permanent, retrying does not help, the record must be rewritten or deleted (REST: `500`; in secret-mode `list` such an item fails the request)
- **`CredStorePluginSpecV1`** — GTS schema for plugin registration

## `CredStoreClientV1`

The consumer trait has six methods over one item shape shared by the record
and its optional secret (ADR-0004, ADR-0007):

- `get_record` — point read of one credential's metadata (`Credential`, never the
  secret; `read`); the source of the validator a secret-blind writer needs.
  Named `get_record`, not `get`: before 0.3 `get` returned the secret value,
  so the rename makes every stale call site fail to compile instead of
  silently returning `Some` for a value-less (`declared`) record
- `get_secret` — the secret with its usage envelope (`Secret`: reference,
  type, expiry, secret; `read_secret`). Over REST both are one item shape at
  `/credentials/{ref}`, where `$select=secret` decides whether the secret is
  included; the in-process trait keeps two typed methods instead
- `put` — precondition-guarded create-or-replace of the record together with a
  **tri-state** `secret`: a string writes it, an explicit `null` creates or
  leaves the record without one. Under the create-only precondition it is how
  a credential is created
- `patch` — precondition-guarded partial update with RFC 7396 merge-patch
  semantics: present fields replace, absent fields are untouched; metadata
  edit, secret rotation and secret removal (a `null` secret) go through it;
  never creates
- `list` — takes an `OData` query (`filter`, `select`, `orderby`, `limit`,
  `cursor`) over credential records; an item's `secret` is present only when
  `select` names it. Selecting `secret` switches the call into **secret mode**
  (ADR-0005): `limit` and `cursor` are rejected, results are capped and not
  paginated, and only `reference in (...)` or `type eq`/`in` may filter.
  Without `secret` selected, `list` is paginated and never carries secrets
- `delete` — precondition-guarded delete of the record and its secret

There is no `create` (`put` under the create-only precondition is create) and
no separate bulk-read method (`list` in secret mode is the bulk read).

Rotating only the secret is a `patch` with only `secret`. `put` is a whole
replace: an omitted expiry is cleared and `fallback` resets to `inherit` (the
pre-0.3 `put` preserved the expiry), so use `patch` to change one field.

## Plugin SPI

`CredStorePluginClientV2` is a versioned value store keyed by
`StoreKey { tenant_id, record_id }`: `put` stores a new immutable version and
returns the provider's `ValueVersion`; `get` reads exactly that version
(`Ok(None)` when it is gone, `ServiceUnavailable` for a transient failure,
`Internal` for a version held but permanently unreadable);
`delete_key` removes the key with all versions (idempotent); `destroy` is
optional and declared through `supports_destroy`. The gear calls both from the
request that recorded the cleanup, right after the commit, or when it heals a
live record on a later access (after a rotation, a secret removal, or a write
that lost its compare-and-set); the same version or key may be passed again,
so both calls must be idempotent.

### Plugin conformance suite

Any `CredStorePluginClientV2` implementation, in-tree or out-of-tree (a
customer's `PostgreSQL` plugin, say), can prove it meets the backend contract
with the suite in `credstore_sdk::conformance`, behind the `conformance`
feature. Add the feature to the plugin's dev-dependencies (the generated tests
also need `tokio` with `rt` and `macros`):

```toml
[dev-dependencies]
credstore-sdk = { package = "cf-gears-credstore-sdk", version = "0.3", features = ["conformance"] }
tokio = { version = "1", features = ["rt", "macros"] }
```

One macro line then generates one `#[tokio::test]` per check, each against a
fresh plugin built by the expression (it may `.await`):

```no_run
# #[cfg(feature = "conformance")]
# mod conformance_tests {
# use async_trait::async_trait;
# use credstore_sdk::{
#     CredStoreError, CredStorePluginClientV2, SecretValue, StoreKey, ValueVersion,
# };
# use toolkit_security::SecurityContext;
# #[derive(Default)]
# struct MyPlugin;
# #[async_trait]
# impl CredStorePluginClientV2 for MyPlugin {
#     async fn put(&self, _: &SecurityContext, _: &StoreKey, _: SecretValue)
#         -> Result<ValueVersion, CredStoreError> { unimplemented!() }
#     async fn get(&self, _: &SecurityContext, _: &StoreKey, _: &ValueVersion)
#         -> Result<Option<SecretValue>, CredStoreError> { unimplemented!() }
#     async fn delete_key(&self, _: &SecurityContext, _: &StoreKey)
#         -> Result<(), CredStoreError> { unimplemented!() }
# }
use credstore_sdk::credstore_plugin_conformance;

credstore_plugin_conformance!(MyPlugin::default());
# }
# fn main() {}
```

Outer attributes written before the expression are applied to every generated
test. A plugin whose backend needs Docker keeps the suite out of a default
`cargo test` with `#[ignore]`:

```no_run
# #[cfg(feature = "conformance")]
# mod conformance_tests {
# use async_trait::async_trait;
# use credstore_sdk::{
#     CredStoreError, CredStorePluginClientV2, SecretValue, StoreKey, ValueVersion,
# };
# use toolkit_security::SecurityContext;
# struct MyPlugin;
# impl MyPlugin {
#     async fn connect_to_docker_backend() -> Self {
#         Self
#     }
# }
# #[async_trait]
# impl CredStorePluginClientV2 for MyPlugin {
#     async fn put(&self, _: &SecurityContext, _: &StoreKey, _: SecretValue)
#         -> Result<ValueVersion, CredStoreError> { unimplemented!() }
#     async fn get(&self, _: &SecurityContext, _: &StoreKey, _: &ValueVersion)
#         -> Result<Option<SecretValue>, CredStoreError> { unimplemented!() }
#     async fn delete_key(&self, _: &SecurityContext, _: &StoreKey)
#         -> Result<(), CredStoreError> { unimplemented!() }
# }
use credstore_sdk::credstore_plugin_conformance;

credstore_plugin_conformance!(
    #[ignore = "needs Docker; run with `-- --ignored`"]
    MyPlugin::connect_to_docker_backend().await
);
# }
# fn main() {}
```

The checks cover exact bytes (text, binary with NUL and invalid UTF-8, empty,
64 KiB), a new immutable version per `put`, absence (`None` for a never-written
key or a never-issued version), key isolation across tenants and records,
`delete_key` (removes every version, idempotent), concurrent puts, and, when
`supports_destroy()` is `true`, `destroy` (`Below`, `Exactly`, idempotency) and
ordered versions, observed through `destroy(Below(..))` because versions are
opaque. A plugin that does not declare `destroy` skips those checks and is
never asked to destroy. Every check uses fresh random ids, so checks can share
one backend. See the module docs for the full list and what the suite leaves
to the plugin (a permanently unreadable version, `ServiceUnavailable`, durability across a
restart).

## Usage

A `ToolKit` consumer normally obtains `CredStoreClientV1` from `ClientHub`. The SDK
itself is transport-independent, so the example accepts the resolved client directly:

```no_run
use credstore_sdk::{CredStoreClientV1, CredStoreError, SecretRef};
use toolkit_security::SecurityContext;

async fn secret_length(
    credstore: &dyn CredStoreClientV1,
    security: &SecurityContext,
) -> Result<Option<usize>, CredStoreError> {
    let key = SecretRef::new("my-api-key")?;
    let response = credstore.get_secret(security, &key).await?;

    Ok(response.map(|secret| secret.secret.as_bytes().len()))
}
```

The record's metadata alone (no value; `Ok(Some(_))` even for a value-less
`declared` record) is `credstore.get_record(security, &key)`.

A missing or out-of-scope secret is expressed as `Ok(None)`, preventing existence
leaks. An explicit denial of the read action is returned as `CredStoreError::AccessDenied`.

## License

Apache-2.0
