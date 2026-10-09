# qrdb storage schema

> **Status: REFERENCE** · Last verified: 2026-10-09
> The key layout of the stores in `pkg/storage/qrdb/`.

The qrdb backend stores every domain value as a JSON document keyed by a
domain-specific prefix. Secondary lookups are handled with mirror keys
that map an indexed field to a primary ID. The stores run on a `KVClient`
adapter (`kvclient_adapter.go`); `cmd/signald` wires them to an in-process
fake KV store, so the `qrdb` backend is not durable (see
[../architecture/overview.md](../architecture/overview.md#storage)).

All stores live in `pkg/storage/qrdb/`.

## Accounts

| Key                              | Value                       | Purpose                               |
|----------------------------------|-----------------------------|---------------------------------------|
| `account:_primary:{uuid}`        | JSON `accounts.Account`     | Primary record                        |
| `account:by-number:{e164}`       | UUID string                 | Mirror for `GetByNumber`              |
| `account:by-pni:{pni}`           | UUID string                 | Mirror for `GetByPNI`                 |

Create and Update are not atomic across the primary + mirror keys. A
process crash between Put calls leaves a missing mirror; the next
write for the same UUID heals it. A dangling mirror (primary deleted,
mirror orphaned) is cleaned up on the next Update that changes the
phone number; no background scan is currently required.

Optimistic locking on `Account.Version` is enforced on every Update:
the incoming version must be exactly one greater than the stored
version, or the store returns `accounts.VersionConflictError`.

## Provisioning sessions

| Key                            | Value                                |
|--------------------------------|--------------------------------------|
| `provisioning:{code}`          | JSON `devices.ProvisioningSession`   |

Codes are TTL-bearing in their payload (`ExpiresAt`).

## Groups

| Key                    | Value                |
|------------------------|----------------------|
| `group:{id}`           | JSON `groups.Group`  |

Optimistic locking on `Group.Revision`.

## Profiles

| Key                              | Value                    |
|----------------------------------|--------------------------|
| `profile:{uuid}:{version}`       | JSON `profiles.Profile`  |
| `profile:{uuid}:_latest`         | JSON `profiles.Profile`  |

Every `Set` writes both keys. `Get(uuid, version)` reads the versioned
key; `GetLatest(uuid)` reads the mirror. `Delete(uuid)` scans the
`profile:{uuid}:` prefix and deletes every hit.

## Verification sessions

| Key                              | Value                                      |
|----------------------------------|--------------------------------------------|
| `verification:{sessionID}`       | JSON `verification.VerificationSession`    |

`DeleteExpired` scans the prefix and removes every entry whose
`ExpiresAt` is in the past. At the session volumes verification sees
(bounded by rate limits) this is cheap; higher-traffic deployments can
later add a native qrdb TTL index.

## Spam reports

| Key                                         | Value                        |
|---------------------------------------------|------------------------------|
| `report:{reporterUUID}:{reportID}`          | JSON `messages.SpamReport`   |

`GetByReporter` scans the `report:{reporterUUID}:` prefix.

## Secure storage

| Key                                  | Value                                | Purpose                          |
|--------------------------------------|--------------------------------------|----------------------------------|
| `ss:{accountUUID}:manifest`          | JSON `securestorage.StorageManifest` | Per-account manifest             |
| `ss:{accountUUID}:item:{b64key}`     | JSON `securestorage.StorageItem`     | Encrypted item                   |

Item keys are base64-RawURL encoded because the client-supplied key
bytes may be non-printable. `DeleteAll(accountUUID)` scans
`ss:{accountUUID}:`.

Monotonic version check on `PutManifest`: the submitted version must
be strictly greater than the stored one.

## Usernames

| Key                                        | Value                     | Purpose                            |
|--------------------------------------------|---------------------------|------------------------------------|
| `username:confirmed:{hex(hash)}`           | UUID string               | Hash-to-UUID lookup                |
| `username:byuuid:{uuid}`                   | hex(hash)                 | Reverse for delete                 |
| `username:reservation:{uuid}`              | JSON `reservationEntry`   | Pending reservation (5-minute TTL) |
| `username-link:{handle}`                   | JSON `usernames.UsernameLink` | Handle-to-link            |
| `username-link:byuuid:{uuid}`              | handle                    | Reverse for replacement           |

Reservations are not actively expired on read; the next
`ReserveHash(uuid, …)` call overwrites any stale reservation for the
same UUID, and the `RemoveExpiredUsernameHoldsWorker` sweeps the rest
on its daily schedule.

## Messages

| Key                                           | Value                    | Purpose                       |
|-----------------------------------------------|--------------------------|-------------------------------|
| `msg:{uuid}:{device}:{seq}`                   | JSON `messages.Envelope` | Per-device queue              |
| `msg:byguid:{uuid}:{guid}`                    | Full primary key         | Mirror for `Delete` by GUID   |

`seq` is a zero-padded uint64 allocated atomically within the
MessageStore instance. Cross-instance global ordering is not
guaranteed here.

## Pre-keys

All keyed under `prekeys:` so `DeleteAllForDevice` /
`DeleteAllForAccount` can clear across sub-kinds in one sweep.

| Key                                                  | Value                                | Purpose                      |
|------------------------------------------------------|--------------------------------------|------------------------------|
| `prekeys:ec:{uuid}:{device}:{keyID}`                 | JSON `keys.PreKey`                   | EC one-time pre-key          |
| `prekeys:kem:{uuid}:{device}:{keyID}`                | JSON `keys.KEMSignedPreKey`          | KEM one-time pre-key         |
| `prekeys:kem-lastresort:{uuid}:{device}`             | JSON `keys.KEMSignedPreKey`          | KEM last-resort              |
| `prekeys:signed:{uuid}:{device}`                     | JSON `keys.SignedPreKey`             | Current signed pre-key       |

EC and KEM one-time keys are consumed in ascending `keyID` order.
`TakeEC` / `TakeKEM` hold a per-device mutex across the
List→Get→Delete sequence so two concurrent takes never race on the
same key.

## FIDO2 credentials (build tag `fido2`)

| Key                                        | Value                        |
|--------------------------------------------|------------------------------|
| `fido2:cred:{credentialID}`                | JSON `fido2.FIDO2Credential` |
| `fido2:cred-by-account:{uuid}:{credID}`    | Empty (presence-only mirror) |
| `fido2:session:{sessionID}`                | JSON `fido2.FIDO2Session`    |

`GetCredentialsByAccount` scans the `fido2:cred-by-account:{uuid}:`
prefix and fetches each credential via the primary key.

## Other domains

| Prefix                          | Store                                   |
|---------------------------------|-----------------------------------------|
| `signal:backup:`, `signal:backup:pending:` | Backups (`backups.go`)       |
| `signal:rrp:`                   | Recovery passwords (`recoverypasswords.go`) |
| `remoteconfig:`                 | Remote config (`remoteconfig.go`)       |
| `scheduledjobs:`                | Scheduled jobs (`jobs.go`)              |

## Not qrdb-backed

Attachment blobs are not stored in qrdb. Binary attachments go through
`pkg/storage/blob/`, which has a filesystem driver and an S3 driver.
