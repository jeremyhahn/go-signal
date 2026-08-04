# REST API Reference

The go-signal REST API is served over HTTP/2 using Go's standard `net/http` package with Go 1.22+ pattern matching. All endpoints accept and return JSON with `Content-Type: application/json`.

The server applies a global `jsonMiddleware` that sets the Content-Type header on every response, and a `loggingMiddleware` that records method, path, status code, and duration for each request.

## Authentication

Endpoints marked **(auth)** require HTTP Basic Authentication. The credential format after base64 decoding is:

```
uuid.deviceId:password
```

or simply:

```
uuid:password
```

The auth middleware extracts the UUID and device ID, looks up the account, and verifies the password against the **addressed device's** stored token hash (HKDF-SHA256, constant-time) — not always the primary device. A credential of the form `uuid:password` targets the primary device. On failure, a `401 Unauthorized` response is returned with `WWW-Authenticate: Basic realm="signal"`. See [../auth/authentication.md](../auth/authentication.md) for the full model, including the timing-equalisation and sealed-sender (`Unidentified-Access-Key`) paths.

## Error Responses

All errors are returned as JSON objects with an `error` field:

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
| 409 | Conflict (e.g. stale device list) |
| 500 | Internal server error |

---

## Registration and Verification

Account creation follows a two-phase flow: create a verification session, verify the phone number, then register the account with identity keys and signed pre-keys.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/registration` | No | Create account |
| POST | `/v1/verification/session` | No | Create verification session |
| GET | `/v1/verification/session/{id}` | No | Get session status |
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

### PUT /v1/verification/session/{id}/code

Submit the verification code received via SMS or voice.

**Request:**

```json
{
  "code": "123456"
}
```

**Response (200):**

```json
{
  "id": "abc123",
  "allowedToRequestCode": true,
  "verified": true,
  "requestedInformation": []
}
```

### POST /v1/registration

Register a new account after phone number verification.

**Request:**

```json
{
  "accountAttributes": {
    "fetchesMessages": true,
    "registrationId": 12345,
    "pniRegistrationId": 67890,
    "name": "encrypted-device-name",
    "unidentifiedAccessKey": "base64-key",
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

Core account management endpoints for the authenticated user.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/accounts/whoami` | Yes | Get authenticated account |
| PUT | `/v1/accounts/attributes/` | Yes | Update account attributes |
| HEAD | `/v1/accounts/account/{identifier}` | No | Check if account exists |
| DELETE | `/v1/accounts/me` | Yes | Delete account |
| PUT | `/v1/accounts/gcm/` | Yes | Register GCM push token |
| DELETE | `/v1/accounts/gcm/` | Yes | Unregister GCM push token |
| PUT | `/v1/accounts/apn/` | Yes | Register APN push token |
| DELETE | `/v1/accounts/apn/` | Yes | Unregister APN push token |

### GET /v1/accounts/whoami (auth)

Returns the authenticated account's identifiers.

**Response (200):**

```json
{
  "uuid": "account-aci-uuid",
  "number": "+14155551234",
  "pni": "account-pni-uuid"
}
```

### PUT /v1/accounts/gcm/ (auth)

Register a GCM push token.

**Request:**

```json
{
  "gcmRegistrationId": "fcm-device-token"
}
```

### PUT /v1/accounts/apn/ (auth)

Register APN push tokens.

**Request:**

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

Enhanced account operations including phone number changes and privacy settings.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v2/accounts/number` | Yes | Change phone number |
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

| Status | Meaning |
|--------|---------|
| 400 | `sessionId` and `recoveryPassword` both supplied, or invalid encoding |
| 403 | Non-primary device, or no proof of ownership supplied / proof did not match the new number |
| 422 | Empty `number` |

### PUT /v1/accounts/registration_lock (auth)

Set a registration lock (SRP-derived value) on the account.

**Request:**

```json
{
  "registrationLock": "base64-registration-lock"
}
```

### PUT /v2/accounts/phone_number_discoverability (auth)

Control whether the account can be found by phone number.

**Request:**

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

**Request:**

```json
{
  "usernameHashes": ["base64-hash-1", "base64-hash-2"]
}
```

**Response (200):**

```json
{
  "usernameHash": "base64-hash-1"
}
```

### PUT /v1/accounts/username_hash/confirm (auth)

Confirm a previously reserved username hash.

**Request:**

```json
{
  "usernameHash": "base64-hash-1",
  "reservationToken": "reservation-token"
}
```

### GET /v1/accounts/username_hash/{usernameHash}

Lookup the account UUID for a given username hash.

**Response (200):**

```json
{
  "uuid": "account-uuid"
}
```

### PUT /v1/accounts/username_link (auth)

Create or update a username link (encrypted value for sharing).

**Request:**

```json
{
  "usernameLinkEncryptedValue": "base64-encrypted-value"
}
```

**Response (200):**

```json
{
  "usernameLinkHandle": "link-handle-uuid"
}
```

### GET /v1/accounts/username_link/{uuid}

Resolve a username link handle to its encrypted value.

**Response (200):**

```json
{
  "usernameLinkEncryptedValue": "base64-encrypted-value"
}
```

---

## Keys

Pre-key management for the Signal Protocol. Clients upload one-time pre-keys, signed pre-keys, and post-quantum last-resort pre-keys. Other clients fetch key bundles to establish sessions.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/keys` | Yes | Get pre-key count |
| PUT | `/v2/keys` | Yes | Upload pre-keys |
| GET | `/v2/keys/{identifier}/{device_id}` | No | Get pre-key bundle |
| POST | `/v2/keys/check` | Yes | Check key status |

### GET /v2/keys (auth)

Returns the count of remaining one-time pre-keys for the authenticated device.

**Response (200):**

```json
{
  "count": 47,
  "pqCount": 100
}
```

### PUT /v2/keys (auth)

Upload pre-keys for the authenticated device.

**Request:**

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

Fetch the pre-key bundle for a specific device. The `device_id` can be `*` to request keys for all devices.

**Response (200):**

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

### POST /v2/keys/check (auth)

Check whether submitted identity keys match the server's records. Returns any mismatches.

**Request:**

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

**Response (200):**

```json
{
  "identityKeyFingerprints": []
}
```

---

## Messages

Send and receive encrypted messages. Messages are stored until the recipient retrieves them via polling or WebSocket.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/messages/{destination}` | Yes | Send to single recipient |
| PUT | `/v1/messages/multi_recipient` | Yes | Send to multiple recipients |
| GET | `/v1/messages` | Yes | Fetch pending messages |
| DELETE | `/v1/messages/uuid/{guid}` | Yes | Delete message |
| POST | `/v1/messages/report/{source}/{messageGuid}` | Yes | Report spam |

### PUT /v1/messages/{destination} (auth)

Send one or more messages to a destination account. Each message targets a specific device.

**Request:**

```json
{
  "messages": [
    {
      "type": 1,
      "destinationDeviceId": 1,
      "content": "base64-encrypted-content",
      "timestamp": 1700000000000
    }
  ],
  "timestamp": 1700000000000,
  "online": false,
  "urgent": true
}
```

**Response (200):**

```json
{
  "needsSync": true
}
```

### PUT /v1/messages/multi_recipient (auth)

Send a single message payload to multiple recipients at once.

**Request:**

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

**Response (200):**

```json
{
  "uuids404": []
}
```

If some recipients are not found, their UUIDs appear in the `uuids404` array.

### GET /v1/messages (auth)

Fetch pending messages for the authenticated device.

**Response (200):**

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

### DELETE /v1/messages/uuid/{guid} (auth)

Delete a specific message by its server-assigned GUID.

**Response:** `204 No Content`

### POST /v1/messages/report/{source}/{messageGuid} (auth)

Report a message as spam. Accepts an optional body:

```json
{
  "token": "report-token"
}
```

**Response:** `200 OK`

---

## Profiles

Profile retrieval and updates. Profiles contain encrypted name, about text, emoji, avatar, and payment address fields.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/profile` | Yes | Set profile |
| GET | `/v1/profile/{identifier}` | No | Get latest profile |
| GET | `/v1/profile/{identifier}/{version}` | No | Get versioned profile |
| GET | `/v1/profile/{identifier}/{version}/{credentialRequest}` | No | Get profile with credential |
| POST | `/v1/profile/identity_check/batch` | Yes | Batch identity check |

### PUT /v1/profile (auth)

Update the authenticated account's profile.

**Request:**

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

When `avatar` is `true` and `sameAvatar` is `false`, the response includes real AWS SigV4 S3 POST-policy upload attributes signed with the configured CDN credentials:

**Response (200):**

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

If an avatar upload is requested but no CDN credentials are configured, the endpoint fails closed with `503 Service Unavailable` rather than returning a non-functional placeholder signature. When no avatar upload is needed, the response is `200 OK` with an empty JSON object.

### GET /v1/profile/{identifier}

Get the latest profile for an account. The `identifier` is a UUID.

**Response (200):**

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

### GET /v1/profile/{identifier}/{version}/{credentialRequest}

Same as the versioned profile, but also returns an `ExpiringProfileKeyCredential`. The `credentialRequest` path parameter is a hex-encoded zkgroup `ProfileKeyCredentialRequest`. The server deserializes it, loads the stored profile-key commitment for that version, and issues a real credential via go-libsignal's zkgroup. Issuance fails closed: a request whose zero-knowledge proof does not match the stored commitment is rejected with `400`, never a usable-but-wrong credential. The credential expires at a UTC day boundary seven days out (matching the Java server's `EXPIRING_PROFILE_KEY_CREDENTIAL_EXPIRATION`).

| Status | Meaning |
|--------|---------|
| 400 | Malformed `credentialRequest`, or the proof did not match the stored commitment |
| 404 | Account or profile version not found, or no stored commitment |

### POST /v1/profile/identity_check/batch (auth)

Check identity key fingerprints for a batch of accounts.

**Request:**

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

**Response (200):**

```json
{
  "elements": [
    {
      "uuid": "account-uuid",
      "identityKey": "base64-identity-key"
    }
  ]
}
```

Only accounts whose identity key does not match the submitted fingerprint are returned.

---

## Devices

Device management for multi-device support.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/devices` | Yes | List linked devices |
| DELETE | `/v1/devices/{device_id}` | Yes | Remove device |
| GET | `/v1/devices/provisioning/code` | Yes | Get provisioning code |
| PUT | `/v1/devices/link` | Yes | Link new device |
| PUT | `/v1/devices/capabilities` | Yes | Set device capabilities |

### GET /v1/devices (auth)

List all devices linked to the authenticated account.

**Response (200):**

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

Link a new device to the account.

**Request:**

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

Update the current device's capability flags.

**Request:**

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
| PUT | `/v1/provisioning/{destination}` | No | Send provisioning message |

### PUT /v1/provisioning/{destination}

Send a provisioning message to the device identified by `destination` (the provisioning address assigned during WebSocket connection).

**Request:**

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
| GET | `/v1/websocket/` | No* | WebSocket connection |
| GET | `/v1/websocket/provisioning` | No | Provisioning WebSocket |

*Authentication is performed during the WebSocket handshake via Basic Auth header or query parameters (`login` and `password`).

---

## Keepalive

Health check endpoints used by load balancers and clients.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/keepalive` | No | Health check |
| GET | `/v1/keepalive/provisioning` | No | Provisioning health check |

Both return `200 OK` with an empty JSON object.

---

## Configuration

Server and remote configuration.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/config` | No | Get server config |
| GET | `/v2/config` | Yes | Get remote config |

### GET /v2/config (auth)

Returns the list of remote configuration flags for the authenticated account.

**Response (200):**

```json
{
  "config": [
    {
      "name": "android.someFeature",
      "enabled": true,
      "value": "1"
    }
  ]
}
```

---

## Certificates

Delivery certificates for sealed-sender messaging and group credentials.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/certificate/delivery` | Yes | Get delivery certificate |
| GET | `/v1/certificate/auth/group` | Yes | Get group credentials |

### GET /v1/certificate/delivery (auth)

Returns a signed delivery certificate used for sealed-sender messaging.

**Response (200):**

```json
{
  "certificate": "base64-signed-certificate",
  "certificateExpiry": 1700172800
}
```

---

## Challenge

Anti-abuse challenge/response endpoints.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/v1/challenge` | Yes | Submit challenge response |
| POST | `/v1/challenge/push` | Yes | Request push challenge |

---

## Attachments and CDN

File upload endpoints for message attachments.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v4/attachments/form/upload` | Yes | Get upload form |
| PUT/POST/PATCH/HEAD | `/cdn/{rest...}` | No | CDN upload operations |
| PUT/POST/PATCH/HEAD | `/cdn2/{rest...}` | No | CDN2 upload operations |
| PUT/POST/PATCH/HEAD | `/cdn3/{rest...}` | No | CDN3 upload operations |

### GET /v4/attachments/form/upload (auth)

Returns a pre-signed upload form for uploading an attachment to the CDN.

**Response (200):**

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

The CDN proxy routes (`/cdn/`, `/cdn2/`, `/cdn3/`) accept PUT, POST, PATCH, and HEAD requests and forward them to the configured CDN backend.

---

## Stickers

Sticker pack upload management.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/sticker/pack/form/{count}` | Yes | Get sticker pack upload form |

The `{count}` path parameter specifies the number of stickers in the pack.

---

## Directory

Contact discovery service integration.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/directory/auth` | Yes | Get directory auth token |
| PUT | `/v1/directory/lookup` | No | Directory lookup |

---

## Secure Storage

Encrypted storage service for syncing contacts, groups, and settings across devices. The embedded storage-service is enabled by default in monolithic deployments (when `storageService.remoteUrl` is empty); when an external `storage-service` binary is configured, clients are pointed at it instead and these in-process routes return a `204` stub. The wire protocol is protobuf (`pkg/securestorage/proto/storage.proto`, generated into `pkg/securestorage/storagepb`) and is validated wire-compatible with `libsignal-service-java`.

All storage routes require authentication.

| Method | Path | Auth | Operation |
|--------|------|------|-----------|
| GET | `/v1/storage/auth` | Yes | Get storage auth token (HMAC credential) |
| GET | `/storage/manifest` | Yes | Fetch the current `StorageManifest` |
| GET | `/storage/manifest/version/{version}` | Yes | Conditional fetch: returns the manifest only if newer than `{version}`, else `204` |
| PUT | `/storage/manifest` | Yes | Apply a `WriteOperation` |
| PUT | `/storage/read` | Yes | Resolve a `ReadOperation` into `StorageItems` |

Request and response bodies are serialized protobuf, not JSON. The routes also accept the `/storage/v1/storage/...` prefix variants and a catch-all (`/storage/{rest...}`) so that the path shapes used by different clients (signal-cli rewrites against a `/storage` base URL) all resolve. A single handler dispatches by method and path: a `GET` whose path contains `manifest` fetches the manifest, a `PUT` ending in `/read` resolves a read, and any other `PUT` applies a write.

A write that loses the optimistic-concurrency race returns `409 Conflict` with the current `StorageManifest` so the client can rebase and retry. Manifest versions are monotonic.

---

## SVR (Secure Value Recovery)

Secure Value Recovery manages encrypted backup credentials.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET/PUT | `/svr2/{rest...}` | No | SVR2 WebSocket (enclave communication) |
| GET | `/v2/backup/auth` | Yes | Get SVR backup auth |
| GET | `/v2/svr/auth` | Yes | Get SVR auth |
| POST | `/v2/backup/auth/check` | Yes | Check SVR backup auth |
| POST | `/v2/svr/auth/check` | Yes | Check SVR auth |

The `/svr2/` routes are catch-all paths that upgrade to WebSocket connections for communicating with SVR2 enclaves. Clients may use various subpaths (`/v1/{mrenclave}`, `/{enclaveId}`, etc.).

---

## Payments

Payment service integration.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/payments/auth` | Yes | Get payments auth |
| GET | `/v1/payments/conversions` | No | Get payment conversions |

---

## Calling

Voice/video calling support.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v2/calling/relays` | Yes | Get TURN relay credentials |
| POST | `/v1/call-link/create-auth` | Yes | Get call link auth |

---

## Key Transparency

Key transparency log for verifying identity key consistency.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/key-transparency/search` | No | Search key transparency |
| POST | `/v1/key-transparency/monitor` | No | Monitor key transparency |
| GET | `/v1/key-transparency/distinguished` | No | Get distinguished key |

---

## Subscriptions

Subscription and recurring payment management.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/subscription/configuration` | No | Get subscription config |
| PUT | `/v1/subscription/{subscriberId}` | No | Update subscriber |
| GET | `/v1/subscription/{subscriberId}` | No | Get subscription |
| DELETE | `/v1/subscription/{subscriberId}` | No | Delete subscriber |

---

## Donations

One-time donation receipt redemption.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/donation/redeem-receipt` | Yes | Redeem donation receipt |

---

## Archives / Backup

Message backup and restore.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/archives/auth` | Yes | Get backup auth |
| GET | `/v1/archives/upload/form` | Yes | Get backup upload form |
| PUT | `/v1/archives/backupid` | Yes | Set backup ID |
| POST | `/v1/archives` | Yes | Refresh backup |
| GET | `/v1/archives` | Yes | Get backup info |

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

## FIDO2 (build tag: `fido2`)

FIDO2/WebAuthn endpoints for passwordless authentication and MFA enrollment. These routes are only available when the server is built with the `fido2` build tag.

See [../auth/fido2.md](../auth/fido2.md) for detailed FIDO2 flow documentation.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/v1/fido2/capabilities` | No | Server FIDO2 configuration |
| POST | `/v1/fido2/session` | No | Begin FIDO2-only registration |
| GET | `/v1/fido2/session/{id}` | No | Get session status |
| POST | `/v1/fido2/session/{id}/complete` | No | Complete attestation |
| POST | `/v1/fido2/enroll` | Yes | Begin enrollment (MFA) |
| POST | `/v1/fido2/enroll/{id}/complete` | Yes | Complete enrollment |
| POST | `/v1/fido2/auth/begin` | Yes* | Begin FIDO2 assertion |
| POST | `/v1/fido2/auth/complete` | No | Complete assertion |
| GET | `/v1/fido2/credentials` | Yes | List credentials |
| DELETE | `/v1/fido2/credentials/{id}` | Yes | Remove credential |
| PUT | `/v1/fido2/credentials/{id}/name` | Yes | Rename credential |

*Uses Basic Auth directly (not the full auth middleware wrapper).

### GET /v1/fido2/capabilities

Returns the server's FIDO2/WebAuthn configuration.

**Response (200):**

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

Begin a FIDO2-only registration ceremony (passwordless account creation).

**Request:**

```json
{
  "username": "user@example.com"
}
```

**Response (200):**

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

The `options` field contains the WebAuthn `PublicKeyCredentialCreationOptions` for the browser's `navigator.credentials.create()` call.

### POST /v1/fido2/enroll (auth)

Begin enrollment of an additional FIDO2 credential (MFA) for an already-authenticated account.

**Request:**

```json
{
  "credentialName": "YubiKey 5"
}
```

### POST /v1/fido2/auth/begin (auth)

Begin a FIDO2 login assertion ceremony.

**Request:**

```json
{
  "accountUuid": "account-uuid"
}
```

### POST /v1/fido2/auth/complete

Complete the FIDO2 login assertion. Returns an auth token on success.

**Response (200):**

```json
{
  "accountUuid": "account-uuid",
  "token": "auth-token"
}
```

### GET /v1/fido2/credentials (auth)

List all FIDO2 credentials for the authenticated account.

**Response (200):**

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

### PUT /v1/fido2/credentials/{id}/name (auth)

Rename a FIDO2 credential.

**Request:**

```json
{
  "name": "Office YubiKey"
}
```
