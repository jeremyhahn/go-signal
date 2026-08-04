# Storage Architecture

The storage layer is built on a single key-value abstraction. Every domain-specific store (accounts, messages, keys, profiles, etc.) is implemented on top of this interface, which keeps backend selection independent from business logic.

## KVClient Interface

Defined in `pkg/store/kv.go`. This is the lowest-level storage contract in the system.

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
| `List` | Returns all keys matching the given prefix, sorted lexicographically. |
| `Scan` | Iterates key-value pairs matching the prefix in sorted order. Stops early if `fn` returns an error. |
| `Exists` | Reports whether a key is present without returning the value. |

`DeleteIfPresent` is the primitive that makes one-time pre-key consumption single-use: `KVPreKeyStore.TakeEC` / `TakeKEM` (`pkg/keys/store_kv.go`) claim a candidate key with `DeleteIfPresent` and only return it when the call observed `true`, so a one-time pre-key is never handed to two concurrent sessions. KEM *last-resort* pre-keys live in a separate `signal/keys/kem_last_resort/` namespace and are read with `GetKEMLastResortPreKey` (never consumed), so a device always has fallback key material.

### Typed Errors

| Error Type | When |
|---|---|
| `KeyNotFoundError` | `Get` or `Delete` called with a key that does not exist |
| `KeyExistsError` | A create operation encounters a duplicate key |

Both are struct types with a `Key string` field and an `Error() string` method. No sentinel errors.

---

## Key Prefix Convention

All keys follow the pattern:

```
signal/{domain}/{resource-type}/{identifier}
```

Examples from the codebase:

| Store | Prefix | Example Key |
|---|---|---|
| Verification sessions | `signal/verification/` | `signal/verification/sess-abc123` |
| FIDO2 credentials | `signal/fido2/creds/` | `signal/fido2/creds/cred-xyz` |
| FIDO2 creds by account | `signal/fido2/creds/by-account/` | `signal/fido2/creds/by-account/{uuid}/{credId}` |
| FIDO2 sessions | `signal/fido2/sessions/` | `signal/fido2/sessions/sess-456` |

This prefix scheme lets `List` and `Scan` efficiently retrieve all records of a given type, and enables secondary indexes by storing additional keys under parallel prefix trees.

---

## Backends

### MemoryKVClient

Source: `pkg/store/kv_memory.go`

A thread-safe `map[string][]byte` protected by `sync.RWMutex`. Suitable for tests and single-process standalone operation.

Key properties:
- **Deep-copy semantics** on both `Put` and `Get`. The stored byte slice is copied on write, and a fresh copy is returned on read. This prevents callers from mutating stored data through retained slice references.
- **Sorted output** for `List` and `Scan`. Keys are collected from the map, filtered by prefix, and sorted lexicographically before being returned or iterated.
- **Snapshot iteration** for `Scan`. The matching key-value pairs are snapshot-copied under the read lock, then the lock is released before calling `fn`. This prevents the callback from deadlocking if it needs to call back into the store.

### File-backed KVClient

Single-node persistence for development or edge deployments. Data is written to disk through the KVClient interface.

### QuicBaaS TenantKVClient

Distributed, multi-tenant storage through the QuicBaaS platform. Provides the same KVClient interface with replication, tenant isolation, and horizontal scaling.

---

## Domain-Specific Stores

Each domain package defines its own store interface with typed methods. In-memory implementations live in `pkg/storage/memory/`. KV-backed implementations that can work with any `KVClient` backend live alongside the domain types.

### AccountStore

Source: `pkg/accounts/store.go`
In-memory: `pkg/storage/memory/accounts.go`

```go
type AccountStore interface {
    Create(ctx context.Context, account *Account) error
    Get(ctx context.Context, uuid string) (*Account, error)
    GetByNumber(ctx context.Context, number string) (*Account, error)
    GetByPNI(ctx context.Context, pni string) (*Account, error)
    Update(ctx context.Context, account *Account) error
    Delete(ctx context.Context, uuid string) error
    ListAll(ctx context.Context, fn func(*Account) error) error
}
```

The in-memory implementation (`MemoryAccountStore`) maintains three maps: `byUUID` for primary lookup, `byNumber` for phone-number lookup, and a PNI index for `GetByPNI`. All are indexed at write time. Reads and writes produce deep clones of `Account` structs, including nested `Device` slices and byte slice fields like `IdentityKey`, `PhoneNumberIdentityKey`, `UnidentifiedAccessKey`, and `UsernameHash`.

The KV-backed `KVAccountStore` (`pkg/accounts/store_kv.go`) keeps the by-number (`signal/accounts/by-number/`) and by-PNI (`signal/accounts/by-pni/`) secondary indexes as separate keys alongside the primary UUID record. Because a multi-key write is not transactional across an arbitrary `KVClient`, `Create` and `Update` perform **compensating rollback**: if a secondary-index write fails (or, on a number/PNI change, the new index entry cannot be written), the store reverts the primary record and any index entries it had already written, so the account is never left reachable by UUID but missing from — or stale in — the by-number/by-PNI indexes.

Errors: `AccountAlreadyExistsError`, `AccountNotFoundError`

### PreKeyStore

Source: `pkg/keys/store.go`
In-memory: `pkg/storage/memory/keys.go`

```go
type PreKeyStore interface {
    StoreECPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*PreKey) error
    StoreKEMPreKeys(ctx context.Context, uuid string, deviceID uint64, preKeys []*KEMSignedPreKey) error
    StoreSignedPreKey(ctx context.Context, uuid string, deviceID uint64, signedPreKey *SignedPreKey) error
    TakeEC(ctx context.Context, uuid string, deviceID uint64) (*PreKey, error)
    TakeKEM(ctx context.Context, uuid string, deviceID uint64) (*KEMSignedPreKey, error)
    GetSignedPreKey(ctx context.Context, uuid string, deviceID uint64) (*SignedPreKey, error)
    GetPreKeyCount(ctx context.Context, uuid string, deviceID uint64) (*PreKeyState, error)
    DeleteAllForDevice(ctx context.Context, uuid string, deviceID uint64) error
    DeleteAllForAccount(ctx context.Context, uuid string) error
}
```

The in-memory implementation (`MemoryPreKeyStore`) stores keys in maps keyed by a `deviceKey{uuid, deviceID}` composite. EC and KEM one-time keys are stored as slices. `TakeEC` and `TakeKEM` pop from the front of the slice (FIFO). Signed pre-keys are a single value per device, overwritten on each store call. All key data is deep-cloned on read and write.

### MessageStore

Source: `pkg/messages/store.go`
In-memory: `pkg/storage/memory/messages.go`

```go
type MessageStore interface {
    Insert(ctx context.Context, destinationUUID string, destinationDevice uint64, envelope *Envelope) (uint64, error)
    GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) ([]*Envelope, error)
    Delete(ctx context.Context, destinationUUID string, serverGUID string) error
    DeleteForDevice(ctx context.Context, destinationUUID string, destinationDevice uint64) error
    DeleteForAccount(ctx context.Context, uuid string) error
}
```

The in-memory implementation (`MemoryMessageStore`) uses `atomic.Uint64` for monotonic ID generation and maintains two indexes: `byDevice` for per-device message queues and `byGUID` for O(1) deletion by server GUID. Message envelopes are deep-cloned, including `Content` and `ReportSpamToken` byte slices.

### ProfileStore

Source: `pkg/profiles/store.go`
In-memory: `pkg/storage/memory/profiles.go`

```go
type ProfileStore interface {
    Set(ctx context.Context, profile *Profile) error
    Get(ctx context.Context, uuid string, version string) (*Profile, error)
    GetLatest(ctx context.Context, uuid string) (*Profile, error)
    Delete(ctx context.Context, uuid string) error
}
```

The in-memory implementation (`MemoryProfileStore`) supports versioned profiles. It maps `uuid -> version -> Profile` and separately tracks the latest version per UUID. `Delete` removes all versions for a UUID. Profile fields like `Name`, `About`, `AboutEmoji`, `Commitment`, and `PaymentAddress` are deep-cloned as byte slices.

### VerificationSessionStore

Source: `pkg/verification/store.go`
KV-backed: `pkg/verification/store_kv.go`
In-memory: `pkg/verification/store_memory.go`

```go
type VerificationSessionStore interface {
    Create(ctx context.Context, session *VerificationSession) error
    Get(ctx context.Context, sessionID string) (*VerificationSession, error)
    Update(ctx context.Context, session *VerificationSession) error
    Delete(ctx context.Context, sessionID string) error
}
```

The KV-backed implementation stores sessions under the `signal/verification/` prefix. It uses a wrapper struct for JSON serialization because the `VerificationSession.Code` field is tagged `json:"-"` on the public struct (to prevent it from leaking in API responses) but needs to be persisted.

Error: `SessionNotFoundError`

### FIDO2AccountsStore

Source: `pkg/fido2/accounts_store.go` (build tag: `fido2`)
KV-backed: `pkg/fido2/store_kv.go`
In-memory: `pkg/fido2/accounts_store_memory.go`

```go
type FIDO2AccountsStore interface {
    CreateCredential(ctx context.Context, cred *FIDO2Credential) error
    GetCredential(ctx context.Context, credentialID string) (*FIDO2Credential, error)
    GetCredentialsByAccount(ctx context.Context, accountUUID string) ([]*FIDO2Credential, error)
    UpdateCredential(ctx context.Context, cred *FIDO2Credential) error
    DeleteCredential(ctx context.Context, credentialID string) error
    StoreSession(ctx context.Context, session *FIDO2Session) error
    GetSession(ctx context.Context, sessionID string) (*FIDO2Session, error)
    DeleteSession(ctx context.Context, sessionID string) error
}
```

The KV-backed implementation uses three prefix spaces:
- `signal/fido2/creds/` for primary credential storage
- `signal/fido2/creds/by-account/{uuid}/` as a secondary index mapping accounts to credential IDs
- `signal/fido2/sessions/` for WebAuthn ceremony sessions

`GetCredentialsByAccount` lists the secondary index prefix, then fetches each credential individually. `DeleteCredential` fetches the credential first to find the account UUID, deletes the primary entry, then does best-effort cleanup of the secondary index.

Errors: `CredentialExistsError`, `CredentialNotFoundError`, `SessionNotFoundError`

### UsernameStore

Source: `pkg/usernames/store.go`
In-memory: `pkg/storage/memory/usernames.go`

```go
type UsernameStore interface {
    ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error)
    ConfirmHash(ctx context.Context, uuid string, hash []byte, token string) error
    LookupByHash(ctx context.Context, hash []byte) (string, error)
    DeleteHash(ctx context.Context, uuid string) error
    SetLink(ctx context.Context, link *UsernameLink) error
    GetLink(ctx context.Context, handle string) (*UsernameLink, error)
    DeleteLink(ctx context.Context, uuid string) error
}
```

Implements a two-phase username claim flow. `ReserveHash` selects the first available hash from a candidate list, generates a reservation token, and holds the hash for 5 minutes. `ConfirmHash` validates the token and promotes the reservation to a confirmed mapping. The in-memory implementation manages four maps: `hashToUUID` and `uuidToHash` for confirmed usernames, `reservations` for pending claims, and `handleToLink`/`uuidToHandle` for username links.

Errors: `UsernameHashConflictError`, `InvalidReservationTokenError`, `UsernameNotFoundError`, `UsernameLinkNotFoundError`

### ProvisioningStore (DeviceStore)

Source: `pkg/devices/store.go`
In-memory: `pkg/storage/memory/devices.go`

```go
type ProvisioningStore interface {
    StoreSession(ctx context.Context, session *ProvisioningSession) error
    GetSession(ctx context.Context, code string) (*ProvisioningSession, error)
    DeleteSession(ctx context.Context, code string) error
}
```

Manages device provisioning sessions keyed by verification code. The in-memory implementation clones sessions on read and write. `DeleteSession` is idempotent.

Error: `InvalidProvisioningCodeError`

---

## In-Memory Implementation Patterns

All in-memory stores in `pkg/storage/memory/` follow the same patterns:

1. **Compile-time interface check.** Each file has a `var _ SomeStore = (*MemorySomeStore)(nil)` line to catch interface drift at build time.

2. **`sync.RWMutex` for concurrency.** Read operations take `RLock`, write operations take `Lock`. No lock-free structures are used at the domain store level (the KVClient layer uses `sync.RWMutex` as well).

3. **Deep cloning for data isolation.** Every read and write copies all byte slices and nested structs. This prevents test or caller code from accidentally mutating stored state. The `cloneBytes` helper in `pkg/storage/memory/accounts.go` is shared across stores in that package.

4. **No persistence.** Data lives only for the lifetime of the process. Intended for unit tests and development.
