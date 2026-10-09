# Phone Number Identity (PNI)

> **Status: REFERENCE** · Last verified: 2026-10-09
> How go-signal models the ACI and PNI identifiers: account lifecycle, storage indexes, pre-key namespacing and message addressing.

Signal distinguishes two identifiers per account:

- **ACI** — the Account Identity. A stable UUID assigned at account creation and never regenerated. Stored in `Account.UUID`. Used for every ACI-identified message, linked-device auth and session-ratchet namespace.
- **PNI** — the Phone Number Identity. A UUID tied to the account's phone number, regenerated on phone-number change so contacts who only know a phone number can reach a newly-numbered account without the original ACI being exposed. Stored in `Account.PNI`.

Both identifiers are valid message recipients. Clients choose one or the other based on what they know about the recipient.

## Account lifecycle

1. **Create**: `AccountsManager.Create` assigns a random UUID to `Account.PNI` when the caller does not supply one; a supplied PNI is kept.
2. **Phone number change**: `AccountsManager.ChangeNumber` generates a new PNI. The PNI secondary index follows the account update.
3. **Account delete**: the PNI index entry is removed with the account.

## Storage

Every `AccountStore` implementation can look an account up by PNI (`GetByPNI`):

| Backend | Primary | PNI lookup |
|---|---|---|
| `memory` | `byUUID[uuid]` | `byPNI[pni] → uuid` |
| `qrdb` | `account:_primary:{uuid}` | `account:by-pni:{pni} → uuid` |
| KV (`store.KVClient`) | `signal/accounts/{uuid}` | `signal/accounts/by-pni/{pni} → uuid` |
| `postgres` | `accounts` row | `accounts.pni` column (`UUID NOT NULL UNIQUE`) |

See [../storage/schema-qrdb.md](../storage/schema-qrdb.md) and [../storage/schema-postgres.md](../storage/schema-postgres.md) for the full layouts.

## Manager API

```go
acctByACI, _ := manager.Get(ctx, aciUUID)
acctByPNI, _ := manager.GetByPNI(ctx, pniUUID)
acctByE164, _ := manager.GetByNumber(ctx, number)
```

## Key namespacing

Pre-keys, signed pre-keys and KEM keys live in separate ACI and PNI keyspaces. The key stores are identifier-agnostic: the namespace is the UUID string passed in. `KeysManager` exposes `*ForIdentity` variants (`StoreKeysForIdentity`, `GetPreKeysForIdentity`, `GetPreKeyCountForIdentity`, `StoreSignedPreKeyForIdentity`, `GetSignedPreKeyForIdentity`, `StoreKEMPreKeysForIdentity`, `StoreKEMLastResortPreKeyForIdentity`) that take an `accounts.Account` and an `accounts.IdentityType` and resolve the right UUID before calling the store. See `pkg/keys/identity.go`.

## Message addressing

`messages.IncomingMessage` and `messages.Envelope` carry `DestinationIdentityType` (`accounts.IdentityType`). The zero value is ACI, so clients that predate PNI addressing keep working. The recipient is resolved by `(identityType, uuid)`: the ACI path uses `Get`, the PNI path uses `GetByPNI` (`pkg/messages/identity.go`). Messages are stored under the destination string itself (the ACI or the PNI), so ACI and PNI queues never collide.

## References

- [ADR-0004](../architecture/decisions/0004-verification-transport-abstraction.md)
- Java reference: the `Account` class and the phone-number-identifier tables in Signal-Server (not checked here; no Java checkout available on this host).
