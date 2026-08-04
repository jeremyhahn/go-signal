# Authentication

go-signal authenticates API requests using HTTP Basic Auth. After initial registration, clients include credentials in every request. The server validates them in middleware before any handler runs.

## Basic Auth Format

The `Authorization` header carries base64-encoded credentials in one of two forms:

```
Authorization: Basic base64(uuid.deviceId:password)
Authorization: Basic base64(uuid:password)
```

- **Username**: The account UUID, optionally suffixed with `.deviceId` (e.g., `550e8400-e29b.1`). The UUID selects the account; the `.deviceId` suffix selects which device's credential to verify. When the suffix is absent the credential targets the primary device (`accounts.PrimaryDeviceID`). An invalid or zero device suffix is rejected as bad credentials.
- **Password**: The auth token of the *specific device* named in the username, set when the device was registered or linked.

The `authMiddleware` function in `pkg/api/rest/middleware.go` extracts credentials via `r.BasicAuth()`, looks up the account through `AccountService.Get()`, then verifies the password against the addressed device's stored token hash — `device.AuthTokenHash.Verify(password)` — not the primary device's. This means a linked device authenticates as itself, and the authenticated device ID is available to downstream handlers via `deviceIDFromContext()`. On success the account is stored in context with `contextWithAccount()` and the device ID with `contextWithDevice()`; handlers read them back through `accountFromContext()` and `deviceIDFromContext()`.

Auth tokens are never compared in plaintext. Each device stores a `*auth.SaltedTokenHash` (a salted HKDF-SHA256 digest, `pkg/auth/token.go`); `Verify` re-derives the digest and compares it in constant time. To prevent a UUID-existence or device-existence timing oracle, every failure path — unknown account, missing/credential-less device, invalid device suffix — still performs a dummy `SaltedTokenHash.Verify` so response latency does not reveal which check failed.

If authentication fails at any step, the middleware returns `401 Unauthorized` with a `WWW-Authenticate: Basic realm="signal"` header.

### gRPC parity

The gRPC interceptor `AuthenticatedUnary` in `pkg/api/grpc/interceptors/auth.go` mirrors this model exactly: it parses the same `uuid.deviceId:password` credential from the `authorization` metadata entry, verifies it against the addressed device's `AuthTokenHash`, performs the same timing-equalisation, and exposes the principal through `interceptors.AccountFromContext` / `interceptors.DeviceIDFromContext`. The REST and gRPC layers use distinct, layer-private context keys. `AnonymousUnary` rejects any request that carries an `authorization` entry, for services that must only be reached by unauthenticated (sealed-sender / group-send-credentialed) callers.

## Registration Modes

go-signal supports three registration modes. The mode determines what credentials the server requires and how post-registration authentication works.

| Mode | Phone Required | FIDO2 Required | Post-Auth |
|---|---|---|---|
| Standard | Yes | No | Basic Auth |
| Standard + FIDO2 MFA | Yes | Yes (enrolled) | Basic Auth + FIDO2 assertion |
| FIDO2-Only | Optional | Yes | FIDO2 assertion |

### Standard Registration

Phone-based verification followed by account creation. This is the default path.

1. **Create session**: `POST /v1/verification/session` with the phone number in the request body. Returns a session ID.
2. **Request code**: `POST /v1/verification/session/{id}/code` triggers delivery of a verification code via the configured transport (SMS gateway, stub logger, etc.).
3. **Submit code**: `PUT /v1/verification/session/{id}/code` with the received code. The server validates using constant-time comparison. On success, the session is marked `verified: true`.
4. **Register**: `PUT /v1/registration` with the verified `session_id`, identity keys (`aciIdentityKey`, `pniIdentityKey`), signed pre-keys, and account attributes. The server generates a UUID, creates the account, and stores the pre-keys.

After registration, the client authenticates all subsequent requests with Basic Auth using the UUID and the password provided during registration.

### Standard + FIDO2 MFA

Adds a FIDO2 enrollment step after standard registration. Requires the `fido2` build tag.

1. Complete the standard registration flow above.
2. **Begin enrollment**: `POST /v1/fido2/enroll` (authenticated). The server starts a WebAuthn credential creation ceremony and returns a challenge.
3. **Complete enrollment**: The client responds with the attestation from the authenticator. The server verifies it and stores the new credential.

After enrollment, authentication requires both Basic Auth credentials and a valid FIDO2 assertion. The server verifies the assertion through `FIDO2AccountsManager.CompleteLogin()`.

### FIDO2-Only Registration

Creates an account using only a FIDO2 authenticator. Phone number is optional. Requires the `fido2` build tag with `allowFido2Only: true` in configuration.

1. **Begin session**: `POST /v1/fido2/session` starts a WebAuthn registration ceremony. The server generates a challenge and returns credential creation options.
2. **Complete attestation**: The client sends the authenticator's attestation response. The server verifies it, creates the account, and stores the credential.

Post-registration authentication uses FIDO2 assertions exclusively. No shared password is involved.

## Security Properties

| Property | Standard | Standard + MFA | FIDO2-Only |
|---|---|---|---|
| Phishing resistant | No | Yes (FIDO2) | Yes |
| SIM swap resistant | No | Yes (FIDO2) | Yes |
| No shared secrets | No | Partial | Yes |
| Hardware authenticator | No | Yes | Yes |
| Clone detection | N/A | Yes | Yes |

Standard registration relies on a phone number and a shared password. Both are vulnerable to phishing, SIM swaps, and credential theft. FIDO2 MFA keeps the password but adds a hardware-bound factor that is origin-scoped and resistant to replay. FIDO2-Only eliminates shared secrets entirely.

Clone detection works through the WebAuthn sign counter. Each assertion increments the counter stored in the credential. If the server sees a counter value lower than or equal to the stored value, it sets `CloneWarning: true` on the credential, signaling that the authenticator may have been duplicated.

## Implementation Details

The auth middleware is defined in `pkg/api/rest/middleware.go`. Key behaviors:

- Username parsing splits on `.` to separate the UUID from the device ID. The UUID drives the `AccountService.Get()` lookup; the device ID selects which device credential is verified.
- Password comparison runs through `device.AuthTokenHash.Verify()` (HKDF-SHA256, constant-time). It targets the addressed device, so device-scoped authorization is enforceable downstream via `deviceIDFromContext()`. The auth token is a server-generated random value, not a user-chosen password.
- Every rejection path performs a dummy hash verification so that account/device existence cannot be inferred from response timing.
- `optionalAuthMiddleware` additionally accepts the sealed-sender path: a request with no Basic credentials but a valid `Unidentified-Access-Key` header (constant-time compared against the destination account's stored key) is admitted and marked as an unidentified sender.
- The middleware does not handle FIDO2 assertion validation. That is performed separately when the `fido2` build tag is active, through the FIDO2 accounts manager.
- Routes that do not require authentication (registration, verification endpoints) bypass the middleware entirely.
