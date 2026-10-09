# Storage Architecture

> **Status: REFERENCE** · Last verified: 2026-10-09
> The `KVClient` contract, the domain store interfaces and where each backend implements them.

Each domain package declares the store interface it needs. `cmd/signald` picks the implementation from `storage.backend` (see [../architecture/overview.md](../architecture/overview.md#storage)). The `file` backend and the `store_kv.go` implementations sit on the `KVClient` interface below; the `postgres` backend implements the domain interfaces directly.

## KVClient Interface

Defined in `pkg/store/kv.go`.

```go
type KVClient interface {
    Put(ctx context.Context, key string, value []byte) error
    Get(ctx context.Context, key string) ([]byte, error)
    Delete(ctx context.Context, key string) error
    DeleteIfPresent(ctx context.Context, key string) (bool, error)
    List(ctx context.Context, prefix string) ([]string, error)
    Scan(ctx context.Context, prefix string, fn func(key string, value []byte) error) error
    Exists(ctx context.Context, key string) (bool, error)
}
```

| Method | Behavior |
|---|---|
| `Put` | Stores a value at the given key. Overwrites any existing value. |
| `Get` | Retrieves the value at the given key. Returns `KeyNotFoundError` if absent. |
| `Delete` | Removes the value at the given key. Returns `KeyNotFoundError` if absent. |
| `DeleteIfPresent` | Atomically removes the key and reports whether *this* call removed it. Among racing deletes of the same key, exactly one observes `true`. |
| `List` | Returns all keys matching the given prefix. |
| `Scan` | Iterates key-value pairs matching the prefix. Stops early if `fn` returns an error. |
| `Exists` | Reports whether a key is present without returning the value. |

`DeleteIfPresent` is the primitive that makes one-time pre-key consumption single-use: `KVPreKeyStore.TakeEC` / `TakeKEM` (`pkg/keys/store_kv.go`) claim a candidate key with it and only return the key when the call observed `true`. KEM last-resort pre-keys live in a separate `signal/keys/kem_last_resort/` namespace and are read with `GetKEMLastResortPreKey`, never consumed.

### Typed Errors

| Error Type | When |
|---|---|
| `KeyNotFoundError` | `Get` or `Delete` called with a key that does not exist |
| `KeyExistsError` | A create operation encounters a duplicate key |

Both are struct types in `pkg/store`. Callers match them with `errors.As`.

### Implementations

| Type | Source | Notes |
|---|---|---|
| `MemoryKVClient` | `pkg/store/kv_memory.go` | In-process map; for tests and the `memory` backend's KV needs. |
| `FileKVClient` | `pkg/store/kv_file.go` | Keys map to file paths under a root directory (`storage.file.dataDir`). Writes are atomic (temp file, fsync, rename). |
| failing wrapper | `pkg/store/kv_failing.go` | Fault injection for tests. |
| qrdb adapter | `pkg/storage/qrdb/kvclient_adapter.go` | Adapts a go-qrdb store to `KVClient`. |

## Key Prefix Convention

Keys follow `signal/{domain}/{resource-type}/{identifier}`. The prefixes in the code:

| Prefix | Owner |
|---|---|
| `signal/accounts/` (`by-number/`, `by-pni/`) | `pkg/accounts` |
| `signal/keys/` (`ec/`, `signed/`, `kem/`, `kem_last_resort/`) | `pkg/keys` |
| `signal/messages/` | `pkg/messages` |
| `signal/reports/`, `signal/reports-by-reporter/` | `pkg/messages` |
| `signal/profiles/` | `pkg/profiles` |
| `signal/verification/` | `pkg/verification` |
| `signal/fido2/creds/` (`by-account/`), `signal/fido2/sessions/` | `pkg/fido2` |

Secondary indexes are stored as additional keys under parallel prefixes.

## Domain Stores

Where each interface is defined and implemented:

| Interface | Defined in | Memory | KV | qrdb | Postgres |
|---|---|---|---|---|---|
| `AccountStore` | `pkg/accounts/store.go` | `pkg/storage/memory/accounts.go` | `pkg/accounts/store_kv.go` | `pkg/storage/qrdb/accounts.go` | `pkg/storage/postgres/accounts.go` |
| `PreKeyStore` | `pkg/keys/store.go` | `.../memory/keys.go` | `pkg/keys/store_kv.go` | `.../qrdb/keys.go` | `.../postgres/keys.go` |
| `MessageStore` | `pkg/messages/store.go` | `.../memory/messages.go` | `pkg/messages/store_kv.go` | `.../qrdb/messages.go` | `.../postgres/messages.go` |
| `ProfileStore` | `pkg/profiles/store.go` | `.../memory/profiles.go` | `pkg/profiles/store_kv.go` | `.../qrdb/profiles.go` | `.../postgres/profiles.go` |
| `VerificationSessionStore` | `pkg/verification/store.go` | `pkg/verification/store_memory.go` | `pkg/verification/store_kv.go` | `.../qrdb/verification.go` | `.../postgres/verification.go` |
| `FIDO2AccountsStore` (build tag `fido2`) | `pkg/fido2/accounts_store.go` | `pkg/fido2/accounts_store_memory.go` | `pkg/fido2/store_kv.go` | `.../qrdb/fido2.go` | `.../postgres/fido2.go` |
| `UsernameStore` | `pkg/usernames/store.go` | `.../memory/usernames.go` | none | `.../qrdb/usernames.go` | `.../postgres/usernames.go` |
| `ProvisioningStore` | `pkg/devices/store.go` | `.../memory/devices.go` | none | `.../qrdb/devices.go` | `.../postgres/provisioning.go` |

The memory, qrdb and postgres packages also hold stores for groups, backups, secure storage, recovery passwords, reports, jobs and remote config (and call quality in postgres).

### AccountStore

`Create`, `Get`, `GetByNumber`, `GetByPNI`, `Update`, `Delete`, `ListAll(fn)`. `ListAll` streams every account to `fn` (used by the directory bootstrap) and does not guarantee ordering.

`KVAccountStore` keeps the by-number and by-PNI secondary indexes as separate keys beside the primary UUID record. Because a multi-key write is not transactional across an arbitrary `KVClient`, `Create` and `Update` perform compensating rollback: if a secondary-index write fails, the store reverts the primary record and any index entries already written.

Errors: `AccountAlreadyExistsError`, `AccountNotFoundError`.

### PreKeyStore

`StoreECPreKeys`, `StoreKEMPreKeys`, `StoreKEMLastResortPreKey`, `StoreSignedPreKey`, `TakeEC`, `TakeKEM`, `GetKEMLastResortPreKey`, `GetSignedPreKey`, `GetPreKeyCount`, `DeleteAllForDevice`, `DeleteAllForAccount`, `ListAccountUUIDs`. `ListAccountUUIDs` lets the orphan-prekey sweeper find pre-keys whose account no longer exists.

### MessageStore

`Insert`, `GetMessagesForDevice`, `Delete`, `DeleteForDevice`, `DeleteForAccount`, `RemoveExpired`, `HasMessagesForDevice`. See [../messaging/overview.md](../messaging/overview.md).

### ProfileStore

`Set`, `Get(uuid, version)`, `GetLatest`, `Delete`. `Delete` removes all versions for a UUID.

### VerificationSessionStore

`Create`, `Get`, `Update`, `Delete`, `Count`, `DeleteExpired`. The KV implementation stores sessions under `signal/verification/` with a wrapper struct for JSON serialization, because `VerificationSession.Code` is tagged `json:"-"` on the public struct but must be persisted.

Error: `SessionNotFoundError`.

### FIDO2AccountsStore

`CreateCredential`, `GetCredential`, `GetCredentialsByAccount`, `UpdateCredential`, `DeleteCredential`, `StoreSession`, `GetSession`, `DeleteSession`. The KV implementation uses `signal/fido2/creds/`, the index `signal/fido2/creds/by-account/{uuid}/`, and `signal/fido2/sessions/`.

Errors: `CredentialExistsError`, `CredentialNotFoundError`, `SessionNotFoundError`.

### UsernameStore

`ReserveHash`, `ConfirmHash`, `LookupByHash`, `DeleteHash`, `HashForUUID`, `SetLink`, `GetLink`, `LinkForUUID`, `DeleteLink`, `DeleteExpiredReservations`.

Username claim is two-phase. `ReserveHash` picks the first available hash from the candidates, returns a reservation token and holds the hash for 5 minutes (`reservationTTL`). `ConfirmHash` validates the token and promotes the reservation.

Errors: `UsernameHashConflictError`, `InvalidReservationTokenError`, `UsernameNotFoundError`, `UsernameLinkNotFoundError`.

### ProvisioningStore

`StoreSession`, `GetSession(code)`, `DeleteSession(code)`. Device provisioning sessions are keyed by verification code.

Error: `InvalidProvisioningCodeError`.

## In-Memory Implementations

The stores in `pkg/storage/memory/` hold data for the life of the process and are used by the `memory` backend and by unit tests. They are guarded by a `sync.RWMutex` and return copies, so callers cannot mutate stored state.
