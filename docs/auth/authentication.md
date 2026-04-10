# Authentication

go-signal authenticates API requests using HTTP Basic Auth. After initial registration, clients include credentials in every request. The server validates them in middleware before any handler runs.

## Basic Auth Format

The `Authorization` header carries base64-encoded credentials in one of two forms:

```
Authorization: Basic base64(uuid.deviceId:password)
Authorization: Basic base64(uuid:password)
```

- **Username**: The account UUID, optionally suffixed with `.deviceId` (e.g., `550e8400-e29b.1`). If the `.deviceId` suffix is present, the middleware strips it and uses only the UUID for account lookup.
- **Password**: The primary device's `AuthToken`, set during registration.

The `authMiddleware` function in `pkg/api/rest/middleware.go` extracts credentials via `r.BasicAuth()`, looks up the account through `AccountsManager.Get()`, and compares the password against `acct.PrimaryDevice().AuthToken`. On success, the authenticated account is stored in the request context using `contextWithAccount()` and retrieved downstream with `accountFromContext()`.

If authentication fails at any step, the middleware returns `401 Unauthorized` with a `WWW-Authenticate: Basic realm="signal"` header.

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

- Username parsing splits on `.` to separate UUID from device ID. Only the UUID portion is used for the `AccountsManager.Get()` lookup.
- Password comparison is a direct string equality check against `PrimaryDevice().AuthToken`. This is acceptable because the auth token is a server-generated random value, not a user-chosen password.
- The middleware does not handle FIDO2 assertion validation. That is performed separately when the `fido2` build tag is active, through the FIDO2 accounts manager.
- Routes that do not require authentication (registration, verification endpoints) bypass the middleware entirely.
