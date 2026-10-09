# REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-09
> As-built description of the go-signal REST routes registered in `pkg/api/rest/server.go` and `server_fido2.go`.

The go-signal REST API is served over HTTP/2 using Go's standard `net/http` package with Go 1.22+ pattern matching. Endpoints accept and return JSON with `Content-Type: application/json`, except the CDN, static-resource and secure-storage routes, which carry binary or protobuf bodies.

The server applies a global `jsonMiddleware` that sets the Content-Type header on every response, and a `loggingMiddleware` that records method, path, status code, and duration for each request.

## Authentication

Routes carry one of these auth marks in the tables below:

| Mark | Meaning |
|------|---------|
| Yes | HTTP Basic authentication (`authMiddleware`) |
| No | No credentials |
| Basic or UAK | `optionalAuthMiddleware`: Basic auth, or an `Unidentified-Access-Key` header (sealed sender) checked against the destination account |
| ZK | No Signal session; the handler validates the backup `X-Signal-ZK-Auth` headers itself |

The Basic credential format after base64 decoding is:

```
uuid.deviceId:password
```

or simply:

```
uuid:password
```

The auth middleware extracts the UUID and device ID, looks up the account, and verifies the password against the **addressed device's** stored token hash (HKDF-SHA256, constant-time) — not always the primary device. A credential of the form `uuid:password` targets the primary device. On failure, a `401 Unauthorized` response is returned with `WWW-Authenticate: Basic realm="signal"`. See [../auth/authentication.md](../auth/authentication.md) for the full model, including the timing-equalisation and sealed-sender paths.

## Rate limiting

When a rate-limit registry is configured, registration, verification, message, pre-key, profile, attachment, username, account-check, device and call-link routes are wrapped in per-route limiters keyed by client IP (`ipKey`, trusted-proxy aware) or by account UUID (`uuidKey`). Without a registry the routes run unwrapped.

## Error Responses

Errors are JSON objects with an `error` field:

```json
{
  "error": "description of what went wrong"
}
```

Common HTTP status codes:

| Status | Meaning |
|--------|---------|
| 400 | Bad request / malformed JSON |
| 401 | Missing or invalid credentials |
| 404 | Resource not found |
| 409 | Conflict. On message send, a `MismatchedDevicesResponse` (`missingDevices`, `extraDevices`) |
| 410 | On message send, a `StaleDevicesResponse` (`staleDevices`) |
| 423 | Registration blocked by a registration lock: `{"timeRemaining": <seconds>}` |
| 428 | Spam challenge required on message send: `{"token": ..., "options": "captcha"\|"push"}` |
| 500 | Internal server error |

---

## Registration and Verification

Account creation follows a two-phase flow: create a verification session, verify the phone number, then register the account with identity keys and signed pre-keys.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/registration` | No | Create account |
| POST | `/v1/verification/session` | No | Create verification session |
| GET | `/v1/verification/session/{id}` | No | Get session status |
| PATCH | `/v1/verification/session/{id}` | No | Update session (captcha solution) |
| POST | `/v1/verification/session/{id}/code` | No | Request verification code |
| PUT | `/v1/verification/session/{id}/code` | No | Submit verification code |

### POST /v1/verification/session

Create a new verification session for a phone number.

**Request:**

```json
{
  "number": "+14155551234",
  "transport": "sms"
}
```

**Response (200):**

```json
{
  "id": "abc123",
  "allowedToRequestCode": true,
  "verified": false,
  "requestedInformation": []
}
```

### PATCH /v1/verification/session/{id}

Body `{"captcha": "provider.sitekey.action.token"}`. Returns the session in the same shape.

### PUT /v1/verification/session/{id}/code

Submit the verification code received via SMS or voice.

**Request:**

```json
{
  "code": "123456"
}
```

**Response (200):** the session, with `verified: true` on success.

### POST /v1/registration

Register a new account after phone number verification. The phone number comes from the Basic `Authorization` header. Exactly one of `sessionId` (a verified, unexpired session for that number) or `recoveryPassword` (base64) must be supplied. `captcha` is optional unless the request trips the fraud heuristics. A blocked registration lock returns `423`.

**Request:**

```json
{
  "sessionId": "verification-session-id",
  "accountAttributes": {
    "fetchesMessages": true,
    "registrationId": 12345,
    "pniRegistrationId": 67890,
    "name": "encrypted-device-name",
    "unidentifiedAccessKey": "base64-key",
    "registrationLock": "optional-pin",
    "capabilities": {
      "storage": true,
      "transfer": true
    }
  },
  "aciIdentityKey": "base64-public-key",
  "pniIdentityKey": "base64-public-key",
  "aciSignedPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "pniSignedPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "aciPqLastResortPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "pniPqLastResortPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  }
}
```

**Response (200):**

```json
{
  "uuid": "account-aci-uuid",
  "pni": "account-pni-uuid",
  "storageCapable": true
}
```

---

## Accounts

Core account management endpoints.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/accounts/whoami` | Yes | Get authenticated account |
| PUT | `/v1/accounts/attributes/` | Yes | Update account attributes |
| HEAD | `/v1/accounts/account/{identifier}` | No | Check if account exists |
| DELETE | `/v1/accounts/me` | Yes | Delete account |
| PUT | `/v1/accounts/gcm/` | Yes | Register GCM push token |
| DELETE | `/v1/accounts/gcm/` | Yes | Unregister GCM push token |
| PUT | `/v1/accounts/apn/` | Yes | Register APN push tokens |
| DELETE | `/v1/accounts/apn/` | Yes | Unregister APN push tokens |

### GET /v1/accounts/whoami (auth)

**Response (200):**

```json
{
  "uuid": "account-aci-uuid",
  "number": "+14155551234",
  "pni": "account-pni-uuid"
}
```

### PUT /v1/accounts/gcm/ (auth)

```json
{
  "gcmRegistrationId": "fcm-device-token"
}
```

### PUT /v1/accounts/apn/ (auth)

```json
{
  "apnRegistrationId": "apn-device-token",
  "voipRegistrationId": "voip-device-token"
}
```

### HEAD /v1/accounts/account/{identifier}

Check whether an account exists. Returns `200 OK` if found, `404 Not Found` otherwise. No response body.

---

## Accounts V2

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v2/accounts/number` (and `/v2/accounts/number/`) | Yes | Change phone number |
| PUT | `/v1/accounts/registration_lock` | Yes | Set registration lock |
| DELETE | `/v1/accounts/registration_lock` | Yes | Remove registration lock |
| PUT | `/v2/accounts/phone_number_discoverability` | Yes | Set phone number discoverability |
| GET | `/v2/accounts/data_report` | Yes | Get data report |

### PUT /v2/accounts/number (auth, primary device only)

Change the phone number associated with the account. Only the primary device may call this — a request authenticated as a linked device is rejected with `403`.

**Proof of ownership of the new number is mandatory.** The caller must supply exactly one of:

- `sessionId` — a verification session that has been verified for the *new* `number`, or
- `recoveryPassword` — the registration recovery password that matches the *new* `number`.

Supplying both is a `400`; supplying neither is a `403`. This prevents an authenticated account from seizing an arbitrary victim's number. The change rotates the account's PNI; when per-device PNI pre-keys are included they are validated against `pniIdentityKey` *before* any state is mutated and then re-published into the rotated PNI namespace. `pniIdentityKey` is required whenever `devicePniSignedPrekeys` or `devicePniPqLastResortPrekeys` are present.

**Request:**

```json
{
  "number": "+14155559876",
  "sessionId": "verification-session-id",
  "recoveryPassword": "base64-recovery-password",
  "reglock": "optional-registration-lock",
  "pniIdentityKey": "base64-new-pni-key",
  "deviceMessages": [],
  "devicePniSignedPrekeys": {},
  "devicePniPqLastResortPrekeys": {},
  "pniRegistrationIds": {}
}
```

**Response (200):**

```json
{
  "uuid": "account-aci-uuid",
  "number": "+14155559876",
  "pni": "new-pni-uuid",
  "storageCapable": true
}
```

`usernameHash` and `usernameLinkHandle` are added when the account has them.

| Status | Meaning |
|--------|---------|
| 400 | `sessionId` and `recoveryPassword` both supplied, or invalid encoding |
| 403 | Non-primary device, or no proof of ownership supplied / proof did not match the new number |
| 422 | Empty `number` |

### PUT /v1/accounts/registration_lock (auth)

```json
{
  "registrationLock": "base64-registration-lock"
}
```

### PUT /v2/accounts/phone_number_discoverability (auth)

```json
{
  "discoverableByPhoneNumber": true
}
```

---

## Usernames

Username hash and username link management. Usernames are stored as hashes, not plaintext.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/accounts/username_hash/reserve` | Yes | Reserve username hash |
| PUT | `/v1/accounts/username_hash/confirm` | Yes | Confirm username hash |
| DELETE | `/v1/accounts/username_hash` | Yes | Delete username hash |
| GET | `/v1/accounts/username_hash/{usernameHash}` | No | Lookup username hash |
| PUT | `/v1/accounts/username_link` | Yes | Set username link |
| DELETE | `/v1/accounts/username_link` | Yes | Delete username link |
| GET | `/v1/accounts/username_link/{uuid}` | No | Lookup username link |

### PUT /v1/accounts/username_hash/reserve (auth)

Reserve one of a set of candidate username hashes.

```json
{
  "usernameHashes": ["base64-hash-1", "base64-hash-2"]
}
```

**Response (200):**

```json
{
  "usernameHash": "base64-hash-1",
  "reservationToken": "reservation-token"
}
```

### PUT /v1/accounts/username_hash/confirm (auth)

Confirm a reserved hash. `zkProof` (base64) proves knowledge of the nickname and discriminator behind the hash; the server verifies it before binding the hash.

```json
{
  "usernameHash": "base64-hash-1",
  "reservationToken": "reservation-token",
  "zkProof": "base64-proof"
}
```

**Response (200):** `{"usernameHash": "base64-hash-1"}`

### GET /v1/accounts/username_hash/{usernameHash}

**Response (200):** `{"uuid": "account-uuid"}`

### PUT /v1/accounts/username_link (auth)

Create or update a username link. `keepLinkHandle: true` re-uses the existing handle when one exists.

```json
{
  "usernameLinkEncryptedValue": "base64-encrypted-value",
  "keepLinkHandle": false
}
```

**Response (200):** `{"usernameLinkHandle": "link-handle-uuid"}`

### GET /v1/accounts/username_link/{uuid}

Resolve a link handle. **Response (200):** `{"usernameLinkEncryptedValue": "base64-encrypted-value"}`

---

## Keys

Pre-key management for the Signal Protocol.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/keys` | Yes | Get pre-key count |
| PUT | `/v2/keys` | Yes | Upload pre-keys |
| GET | `/v2/keys/{identifier}/{device_id}` | Basic or UAK | Get pre-key bundle |
| POST | `/v2/keys/check` | Yes | Check key status |

### GET /v2/keys (auth)

Count of remaining one-time pre-keys for the authenticated device.

```json
{
  "count": 47,
  "pqCount": 100,
  "hasLastResort": true
}
```

### PUT /v2/keys (auth)

Upload pre-keys for the authenticated device.

```json
{
  "preKeys": [
    {
      "keyId": 1,
      "publicKey": "base64-public-key"
    }
  ],
  "signedPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "pqPreKeys": [
    {
      "keyId": 1,
      "publicKey": "base64-public-key",
      "signature": "base64-signature"
    }
  ],
  "pqLastResortPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  }
}
```

**Response:** `204 No Content`

### GET /v2/keys/{identifier}/{device_id}

Fetch the pre-key bundle for a device; `device_id` can be `*` for all devices. The caller must present Basic credentials or an `Unidentified-Access-Key` for the target account, otherwise `401`.

```json
{
  "identityKey": "base64-identity-key",
  "devices": [
    {
      "deviceId": 1,
      "registrationId": 12345,
      "signedPreKey": {
        "keyId": 1,
        "publicKey": "base64-public-key",
        "signature": "base64-signature"
      },
      "preKey": {
        "keyId": 42,
        "publicKey": "base64-public-key"
      },
      "pqPreKey": {
        "keyId": 7,
        "publicKey": "base64-public-key",
        "signature": "base64-signature"
      }
    }
  ]
}
```

`preKey` and `pqPreKey` are omitted when none is available.

### POST /v2/keys/check (auth)

Check submitted identity keys against the server's records. Returns the mismatches.

```json
{
  "identityKeys": [
    {
      "uuid": "target-uuid",
      "identityKey": "base64-identity-key"
    }
  ]
}
```

**Response (200):** `{"identityKeyFingerprints": []}`, each entry shaped like a request item.

---

## Messages

Send and receive encrypted messages. Messages are stored until the recipient retrieves them via polling or WebSocket.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/messages/{destination}` | Basic or UAK | Send to single recipient |
| PUT | `/v1/messages/multi_recipient` | Basic or UAK | Send to multiple recipients |
| GET | `/v1/messages` | Yes | Fetch pending messages |
| DELETE | `/v1/messages/uuid/{guid}` | Yes | Delete message |
| POST | `/v1/messages/report/{source}/{messageGuid}` | Yes | Report spam |

### PUT /v1/messages/{destination}

Send one or more messages to a destination account, one per device. The `timestamp` belongs to the batch and becomes the delivered envelope's timestamp; messages carry no timestamp of their own. `registrationId` is the sender's last-known registration id for the device and drives the stale-device check (`410`). A wrong device set returns `409`.

```json
{
  "messages": [
    {
      "type": 1,
      "destinationDeviceId": 1,
      "content": "base64-encrypted-content",
      "registrationId": 12345
    }
  ],
  "timestamp": 1700000000000,
  "online": false,
  "urgent": true
}
```

**Response (200):** `{"needsSync": true}`

### PUT /v1/messages/multi_recipient

```json
{
  "recipients": [
    {
      "uuid": "recipient-uuid-1",
      "deviceIds": [1],
      "registrationIds": [12345]
    },
    {
      "uuid": "recipient-uuid-2",
      "deviceIds": [1, 2],
      "registrationIds": [23456, 34567]
    }
  ],
  "commonPayload": "base64-encrypted-payload",
  "timestamp": 1700000000000
}
```

**Response (200):** `{"uuids404": []}`. Recipients that were not found are listed there.

### GET /v1/messages (auth)

```json
{
  "messages": [
    {
      "type": 1,
      "timestamp": 1700000000000,
      "source": "sender-uuid",
      "sourceDevice": 1,
      "content": "base64-encrypted-content",
      "serverTimestamp": 1700000001000,
      "guid": "message-guid",
      "urgent": true
    }
  ],
  "more": false
}
```

`source` and `sourceDevice` are omitted for sealed-sender messages.

### DELETE /v1/messages/uuid/{guid} (auth)

Delete a message by its server-assigned GUID. **Response:** `204 No Content`

### POST /v1/messages/report/{source}/{messageGuid} (auth)

Report a message as spam. Optional body `{"token": "report-token"}`. **Response:** `200 OK`

---

## Profiles

Profile retrieval and updates.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/profile` (and `/v1/profile/`) | Yes | Set profile |
| GET | `/v1/profile/{identifier}` | Basic or UAK | Get latest profile |
| GET | `/v1/profile/{identifier}/{version}` | Basic or UAK | Get versioned profile |
| GET | `/v1/profile/{identifier}/{version}/{credentialRequest}` | Basic or UAK | Get profile with credential |
| POST | `/v1/profile/identity_check/batch` | Yes | Batch identity check |

The three GET routes reject a request that carries neither credential with `401`.

### PUT /v1/profile (auth)

```json
{
  "version": "profile-version-hex",
  "name": "base64-encrypted-name",
  "about": "base64-encrypted-about",
  "aboutEmoji": "base64-encrypted-emoji",
  "paymentAddress": "base64-encrypted-payment-address",
  "avatar": true,
  "sameAvatar": false,
  "commitment": "base64-profile-key-commitment"
}
```

Each encrypted field is decoded from base64 and must match one of its allowed exact ciphertext byte lengths (empty/omitted fields are accepted as "not provided"); a present field of any other size is rejected with `400`:

| Field | Allowed decoded byte lengths |
|-------|------------------------------|
| `name` | 81, 285 |
| `about` | 156, 282, 540 |
| `aboutEmoji` | 60 |
| `paymentAddress` | 582 |
| `commitment` | 97 (zkgroup `ProfileKeyCommitment`) |

When `avatar` is `true` and `sameAvatar` is `false`, the response carries AWS SigV4 S3 POST-policy upload attributes signed with the configured CDN credentials:

```json
{
  "key": "profiles/avatar-key",
  "credential": "aws-credential",
  "acl": "private",
  "algorithm": "AWS4-HMAC-SHA256",
  "date": "20231115T000000Z",
  "policy": "base64-policy",
  "signature": "hex-signature"
}
```

If an avatar upload is requested but no CDN credentials are configured, the endpoint fails closed with `503`. When no avatar upload is needed, the response is `200 OK` with an empty JSON object.

### GET /v1/profile/{identifier}

The `identifier` is an account service identifier.

```json
{
  "identityKey": "base64-identity-key",
  "unidentifiedAccess": "base64-unidentified-access-key",
  "unrestrictedUnidentifiedAccess": false,
  "capabilities": {
    "storage": true
  },
  "badges": [],
  "uuid": "account-uuid",
  "name": "base64-encrypted-name",
  "about": "base64-encrypted-about",
  "aboutEmoji": "base64-encrypted-emoji",
  "avatar": "avatar-path",
  "paymentAddress": "base64-encrypted-payment-address"
}
```

`name`, `about`, `aboutEmoji`, `avatar` and `paymentAddress` are omitted when empty.

### GET /v1/profile/{identifier}/{version}/{credentialRequest}

Same as the versioned profile, plus a `credential` field holding an `ExpiringProfileKeyCredential`. The `credentialRequest` path parameter is a hex-encoded zkgroup `ProfileKeyCredentialRequest`. The server loads the stored profile-key commitment for that version and issues the credential via go-libsignal's zkgroup. Issuance fails closed: a request whose proof does not match the stored commitment is rejected with `400`. The credential expires at a UTC day boundary seven days out.

| Status | Meaning |
|--------|---------|
| 400 | Malformed `credentialRequest`, or the proof did not match the stored commitment |
| 404 | Account or profile version not found, or no stored commitment |

### POST /v1/profile/identity_check/batch (auth)

```json
{
  "elements": [
    {
      "uuid": "account-uuid",
      "fingerprint": "base64-fingerprint"
    }
  ]
}
```

**Response (200):** `{"elements": [{"uuid": ..., "identityKey": ...}]}`, listing only the accounts whose identity key does not match the submitted fingerprint.

---

## Devices

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/devices` (and `/v1/devices/`) | Yes | List linked devices |
| DELETE | `/v1/devices/{device_id}` | Yes | Remove device |
| GET | `/v1/devices/provisioning/code` | Yes | Get provisioning code |
| PUT | `/v1/devices/link` | Yes | Link new device |
| PUT | `/v1/devices/capabilities` | Yes | Set device capabilities |

### GET /v1/devices (auth)

```json
{
  "devices": [
    {
      "id": 1,
      "name": "encrypted-device-name",
      "created": 1700000000,
      "lastSeen": 1700086400
    }
  ]
}
```

### PUT /v1/devices/link (auth)

```json
{
  "verificationCode": "provisioning-code",
  "accountAttributes": {
    "fetchesMessages": true,
    "registrationId": 54321,
    "pniRegistrationId": 98765,
    "name": "encrypted-device-name",
    "capabilities": {}
  },
  "aciSignedPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "pniSignedPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "aciPqLastResortPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  },
  "pniPqLastResortPreKey": {
    "keyId": 1,
    "publicKey": "base64-public-key",
    "signature": "base64-signature"
  }
}
```

### PUT /v1/devices/capabilities (auth)

```json
{
  "capabilities": {
    "storage": true,
    "transfer": true
  }
}
```

---

## Provisioning

Send provisioning messages to devices waiting on the provisioning WebSocket.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/provisioning/{destination}` | Yes | Send provisioning message |

`destination` is the provisioning address the waiting socket received on connect.

```json
{
  "body": "base64-provisioning-message"
}
```

---

## WebSocket

WebSocket upgrade endpoints. See [websocket.md](websocket.md) for protocol details.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/websocket/` | Handshake | Messaging WebSocket |
| GET | `/v1/websocket/provisioning` (and `/v1/websocket/provisioning/`) | No | Provisioning WebSocket |

The messaging socket authenticates during the handshake via a Basic header or the `login` and `password` query parameters; without either it is an unauthenticated session. Both routes are rate-limited by IP with the verification limiter.

---

## Keepalive

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/keepalive` | No | Health check |
| GET | `/v1/keepalive/provisioning` | No | Provisioning health check |

---

## Configuration

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/config` | No | Get server config |
| GET | `/v2/config` | Yes | Get remote config |

### GET /v2/config (auth)

A single map of fully-qualified flag names to their rendered per-account values:

```json
{
  "config": {
    "android.someFeature": "1"
  }
}
```

---

## Certificates

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/certificate/delivery` | Yes | Get delivery certificate |
| GET | `/v1/certificate/auth/group` | Yes | Get group credentials |

### GET /v1/certificate/delivery (auth)

```json
{
  "certificate": "base64-signed-certificate",
  "certificateExpiry": 1700172800
}
```

---

## Challenge

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/challenge` | Yes | Submit challenge response |
| POST | `/v1/challenge/push` | Yes | Request push challenge |

---

## Attachments and CDN

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v4/attachments/form/upload` | Yes | Get upload form |
| PUT/POST/PATCH/HEAD | `/cdn/{rest...}`, `/cdn2/{rest...}`, `/cdn3/{rest...}` | No | CDN upload operations |
| GET | `/cdn/{rest...}`, `/cdn2/{rest...}`, `/cdn3/{rest...}` | No | CDN download |

### GET /v4/attachments/form/upload (auth)

```json
{
  "cdn": 3,
  "key": "attachments/upload-key",
  "headers": {
    "Authorization": "bearer-token"
  },
  "signedUploadLocation": "https://cdn3.example.com/upload"
}
```

When an external TUS server is wired (`SetAttachmentTus`), the form points at it; otherwise it falls back to the embedded `/cdn3` path. The `/cdn*` routes are served by the embedded attachment store and rate-limited by IP.

---

## Static Resources

When `staticResourcesDir` is configured: `GET /resources/{path...}` and `GET /updates/{path...}` (no auth) serve emoji, dictionaries and release notes. Neither route is registered otherwise.

---

## Stickers

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/sticker/pack/form/{count}` | Yes | Get sticker pack upload form |

---

## Directory

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/directory/auth` | Yes | Get directory auth token |
| PUT | `/v1/directory/lookup` | No | Directory lookup (service credentials from `/v2/directory/auth`; rate-limited by IP) |

---

## Secure Storage

Encrypted storage for syncing contacts, groups, and settings across devices. When the embedded storage service is not enabled (`secureStorage` nil or disabled, for example when `storageService.remoteUrl` points at an external binary), every storage route replies `204 No Content` without reading credentials. The wire protocol is protobuf (`pkg/securestorage/proto/storage.proto`, generated into `pkg/securestorage/storagepb`).

When enabled, all storage routes require Basic authentication.

| Method | Path | Auth | Operation |
|--------|------|------|-----------|
| GET | `/v1/storage/auth` | Yes | Get storage auth token (HMAC credential) |
| GET | `/storage/manifest` | Yes | Fetch the current `StorageManifest` |
| GET | `/storage/manifest/version/{version}` | Yes | Conditional fetch: the manifest only if newer than `{version}`, else `204` |
| PUT | `/storage/manifest` | Yes | Apply a `WriteOperation` |
| PUT | `/storage/read` | Yes | Resolve a `ReadOperation` into `StorageItems` |

Request and response bodies are serialized protobuf, not JSON. The server also registers the `/storage/v1/storage/manifest` and `/storage/v1/storage/manifest/version/{version}` variants and the catch-alls `GET /storage/{rest...}` and `PUT /storage/{rest...}`, because signal-cli appends paths to a rewritten `/storage` base URL. One handler dispatches by method and path: a `GET` whose path contains `manifest` fetches the manifest, a `PUT` ending in `/read` resolves a read, any other `PUT` applies a write, and anything else is `204`.

A write that loses the optimistic-concurrency race returns `409 Conflict` with the current `StorageManifest`.

---

## SVR (Secure Value Recovery)

signald only issues and checks SVR credentials. The SVR2 enclave WebSocket is served by `cmd/svr2`, which clients connect to directly; signald registers no `/svr2/` route.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/backup/auth` | Yes | Get SVR backup auth |
| GET | `/v2/svr/auth` | Yes | Get SVR auth |
| POST | `/v2/backup/auth/check` | Yes | Check SVR backup auth |
| POST | `/v2/svr/auth/check` | Yes | Check SVR auth |

---

## Payments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/payments/auth` | Yes | Get payments auth |
| GET | `/v1/payments/conversions` | No | Get payment conversions |

---

## Calling

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/calling/relays` | Yes | Get TURN relay credentials |
| POST | `/v1/call-link/create-auth` | Yes | Get call link auth (rate-limited by account) |
| PUT | `/v1/call_quality_survey` | No | Submit a call quality survey |
| POST | `/v1/call/offer` | Yes | Relay a 1:1 call offer |
| POST | `/v1/call/answer` | Yes | Relay a call answer |
| POST | `/v1/call/ice` | Yes | Relay ICE candidates |
| POST | `/v1/call/hangup` | Yes | Relay a hangup |

---

## Key Transparency

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/key-transparency/search` | Yes | Search key transparency |
| POST | `/v1/key-transparency/monitor` | Yes | Monitor key transparency |
| GET | `/v1/key-transparency/distinguished` | No | Get distinguished key |

---

## Subscriptions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/subscription/configuration` | No | Get subscription config |
| PUT | `/v1/subscription/{subscriberId}` | No | Update subscriber |
| GET | `/v1/subscription/{subscriberId}` | No | Get subscription |
| DELETE | `/v1/subscription/{subscriberId}` | No | Delete subscriber |

---

## Donations

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/donation/redeem-receipt` | Yes | Redeem donation receipt |

---

## Archives / Backup

Message backup and restore. Two authentication models coexist.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/archives/backupid` | Yes | Set backup ID |
| GET | `/v1/archives/backupid/limits` | Yes | Get backup ID limits |
| POST | `/v1/archives/redeem-receipt` | Yes | Redeem backup receipt |
| GET | `/v1/archives/auth` | Yes | Get backup auth |
| GET | `/v1/archives` | ZK | Get backup info |
| POST | `/v1/archives` | ZK | Refresh backup |
| DELETE | `/v1/archives` | ZK | Delete backup |
| PUT | `/v1/archives/keys` | ZK | Set backup public key |
| GET | `/v1/archives/upload/form` | ZK | Get backup upload form |
| GET | `/v1/archives/media/upload/form` | ZK | Get media upload form |
| PUT | `/v1/archives/media` | ZK | Copy media |
| PUT | `/v1/archives/media/batch` | ZK | Copy media in batch |
| GET | `/v1/archives/media` | ZK | List media |
| POST | `/v1/archives/media/delete` | ZK | Delete media |
| GET | `/v1/archives/auth/read` | ZK | Get CDN read auth |
| GET | `/v1/archives/auth/svrb` | ZK | Get SVR-B auth |

---

## Device Check

Apple DeviceCheck attestation and assertion for iOS clients.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/devicecheck/attest` | No | Get attestation challenge |
| PUT | `/v1/devicecheck/attest` | Yes | Submit attestation |
| GET | `/v1/devicecheck/assert` | No | Get assertion challenge |
| POST | `/v1/devicecheck/assert` | Yes | Submit assertion |

---

## Web UI and frontend

When a web UI handler is wired the server also registers its client-facing routes under `/api/v1/*` and an event-hub route. When a frontend filesystem is supplied, `/` is a single-page-app catch-all registered last, so every API route above takes priority. These are outside the Signal wire protocol.

---

## FIDO2 (build tag: `fido2`)

FIDO2/WebAuthn endpoints for passwordless registration and MFA enrollment. They exist only in a binary built with `-tags fido2` and registered through `Server.RegisterFIDO2`. Until the server has FIDO2 state, every handler replies `404 fido2 not configured`.

See [../auth/fido2.md](../auth/fido2.md) for the ceremony flows.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/fido2/capabilities` | No | Server FIDO2 configuration |
| POST | `/v1/fido2/session` | No | Begin FIDO2-only registration |
| GET | `/v1/fido2/session/{id}` | No | Get session status |
| POST | `/v1/fido2/session/{id}/complete` | No | Complete attestation |
| POST | `/v1/fido2/auth/begin` | Yes | Begin FIDO2 assertion |
| POST | `/v1/fido2/auth/complete` | No | Complete assertion |
| POST | `/v1/fido2/enroll` | Yes | Begin enrollment (MFA) |
| POST | `/v1/fido2/enroll/{id}/complete` | Yes | Complete enrollment |
| GET | `/v1/fido2/credentials` | Yes | List credentials |
| DELETE | `/v1/fido2/credentials/{id}` | Yes | Remove credential |
| PUT | `/v1/fido2/credentials/{id}/name` | Yes | Rename credential |

Errors map as: credential or session not found `404`, no credentials `404`, duplicate credential `409`, expired session `410`, ceremony failure or wrong session type `400`, anything else `500`.

### GET /v1/fido2/capabilities

```json
{
  "enabled": true,
  "rpId": "example.com",
  "rpName": "Signal Server",
  "allowFido2Only": false,
  "requireMfa": false,
  "attestation": "none",
  "userVerification": "preferred"
}
```

### POST /v1/fido2/session

Begin a FIDO2-only registration ceremony. Body `{"username": "user@example.com"}` (required).

```json
{
  "session": {
    "sessionId": "session-uuid",
    "type": "registration",
    "expiresAt": 1700003600
  },
  "options": {
    "publicKey": {}
  }
}
```

`options` holds the WebAuthn `PublicKeyCredentialCreationOptions` for `navigator.credentials.create()`. `GET /v1/fido2/session/{id}` returns just the `session` object. `POST /v1/fido2/session/{id}/complete` takes the attestation as the request body and returns the stored credential (shape below).

### POST /v1/fido2/enroll (auth)

Begin enrollment of an additional credential. Body `{"credentialName": "YubiKey 5"}`. Returns the same `session` and `options` shape. `POST /v1/fido2/enroll/{id}/complete` returns the credential.

### POST /v1/fido2/auth/begin (auth)

Begin a login assertion. Body `{"accountUuid": "account-uuid"}` (required). Returns `session` and `options` (a WebAuthn credential assertion). The route is wrapped in the same Basic `authMiddleware` as the other authenticated routes.

### POST /v1/fido2/auth/complete

Complete the login assertion. Body: the assertion, with the session id as `sessionId` (required).

```json
{
  "accountUuid": "account-uuid",
  "token": ""
}
```

`token` is always empty: the handler verifies the assertion and returns the account, and issues no token ("token generation is handled by the auth layer").

### GET /v1/fido2/credentials (auth)

```json
{
  "credentials": [
    {
      "credentialId": "base64-credential-id",
      "name": "YubiKey 5",
      "attestationType": "none",
      "transport": ["usb"],
      "createdAt": 1700000000,
      "lastUsedAt": 1700086400
    }
  ]
}
```

### DELETE /v1/fido2/credentials/{id} (auth)

**Response:** `204 No Content`.

### PUT /v1/fido2/credentials/{id}/name (auth)

```json
{
  "name": "Office YubiKey"
}
```
