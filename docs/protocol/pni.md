# Phone Number Identity (PNI)

Signal distinguishes two identifiers per account:

- **ACI** — the Account Identity. A stable 16-byte UUID assigned at
  account creation and never regenerated. Stored in `Account.UUID`.
  Used for every ACI-identified message, linked-device auth, and
  session-ratchet namespace.
- **PNI** — the Phone Number Identity. A 16-byte UUID tied to the
  account's phone number. Regenerated on phone-number change so
  contacts who only know a phone number can reach a newly-numbered
  account without the original ACI being exposed. Stored in
  `Account.PNI`.

Both identifiers are valid recipients for messages. Signal clients
choose one or the other based on what they know about the recipient:
an ACI contact uses the ACI; a newly-discovered phone number resolves
to a PNI via the directory service.

## Account lifecycle

1. **Create**: `AccountsManager.Create` auto-assigns a random
   `uuid.NewString()` to `Account.PNI` if the caller doesn't supply
   one. Callers that manage PNI externally (e.g. account-transfer
   flows) may set PNI explicitly and the manager respects it.
2. **Phone number change**: a new PNI is generated. The PNI secondary
   index is updated during the same `AccountStore.Update` call.
3. **Account delete**: the PNI mirror is cleaned up alongside the
   phone-number mirror.

## Storage

Every `AccountStore` implementation maintains a PNI secondary index:

| Backend           | Primary                               | PNI mirror                              |
|-------------------|---------------------------------------|-----------------------------------------|
| `memory`          | `byUUID[uuid]`                        | `byPNI[pni] → uuid`                     |
| `qrdb`            | `account:_primary:{uuid}`             | `account:by-pni:{pni} → uuid`           |
| KV (`store.KVClient`) | `signal/accounts/{uuid}`          | `signal/accounts/by-pni/{pni} → uuid`   |

See [../storage/schema-qrdb.md](../storage/schema-qrdb.md) for the
complete qrdb key layout.

## Manager API

```go
// Distinct lookup methods per identifier:
acctByACI, _ := manager.Get(ctx, aciUUID)
acctByPNI, _ := manager.GetByPNI(ctx, pniUUID)
acctByE164, _ := manager.GetByNumber(ctx, number)
```

## Remaining work (later tasks)

What ships in task 2.1.1 (complete as of this entry):

- ✅ `Account.PNI` field.
- ✅ Auto-assignment on `Create`.
- ✅ `GetByPNI` on manager + all three store backends.
- ✅ PNI mirror maintenance on `Update` and `Delete`.

What's still to do and where it lands:

- ✅ **Key namespacing by identity** (task 2.1.2): pre-keys, signed
  pre-keys, and KEM keys live in ACI-namespaced and PNI-namespaced
  keyspaces. The store implementations are identifier-agnostic — the
  namespace is the UUID string passed in. `KeysManager` exposes
  `*ForIdentity` variants that take an `accounts.Account` and an
  `accounts.IdentityType` and resolve the correct UUID before calling
  the underlying store. See `pkg/keys/identity.go`.
- **Message routing** (task 2.1.3): extend `Envelope` with
  `DestinationServiceId`; resolve devices by identifier type;
  register WebSocket sessions under both ACI and PNI.
- **Verification flow** (task 2.7): generate a fresh PNI at
  account-registration completion so every new account has both
  identifiers from the first API call.

## References

- [ADR-0004](../architecture/decisions/0004-verification-transport-abstraction.md)
- Java reference: `Signal-Server/service/src/main/java/org/whispersystems/textsecuregcm/storage/Account.java`
  and the `PhoneNumberIdentifiers` table in `AccountsTableConfiguration.java`.
