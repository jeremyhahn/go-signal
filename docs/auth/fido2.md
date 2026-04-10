# FIDO2 / WebAuthn

The FIDO2 package provides WebAuthn credential management for go-signal, supporting hardware authenticator registration, enrollment (MFA), and login ceremonies. All FIDO2 code is gated behind the `fido2` build tag and requires `libfido2-dev` at build time.

**Package**: `pkg/fido2/`

**Build tag**: `fido2`

```bash
go build -tags fido2 ./...
```

## Core Types

### FIDO2Credential

Represents a registered WebAuthn credential bound to an account.

```go
type FIDO2Credential struct {
    CredentialID    string    `json:"credentialId"`    // base64url-encoded credential ID
    AccountUUID     string    `json:"accountUuid"`
    Name            string    `json:"name"`            // human-readable label
    PublicKey       []byte    `json:"publicKey"`
    AttestationType string    `json:"attestationType"`
    AAGUID          []byte    `json:"aaguid"`          // authenticator model identifier
    SignCount       uint32    `json:"signCount"`        // monotonic counter for clone detection
    CloneWarning    bool      `json:"cloneWarning"`     // true if counter regression detected
    Transport       []string  `json:"transport"`        // e.g., "usb", "nfc", "ble", "internal"
    CreatedAt       time.Time `json:"createdAt"`
    LastUsedAt      time.Time `json:"lastUsedAt"`
}
```

### FIDO2Session

Tracks the state of an in-progress WebAuthn ceremony. Sessions are short-lived (default 60 seconds).

```go
type FIDO2Session struct {
    ID          string           `json:"id"`
    AccountUUID string           `json:"accountUuid,omitempty"`
    Username    string           `json:"username,omitempty"`
    Challenge   []byte           `json:"challenge"`
    SessionData []byte           `json:"sessionData"`    // serialized webauthn.SessionData
    Type        FIDO2SessionType `json:"type"`
    CreatedAt   time.Time        `json:"createdAt"`
    ExpiresAt   time.Time        `json:"expiresAt"`
}
```

Session types:

| Type | Constant | Purpose |
|---|---|---|
| `registration` | `SessionTypeRegistration` | Initial credential creation for a new account |
| `login` | `SessionTypeLogin` | Authentication assertion |
| `enrollment` | `SessionTypeEnrollment` | Adding a credential to an existing account (MFA) |

The `IsExpired()` method checks whether `time.Now()` is past `ExpiresAt`.

### WebAuthnUser

Implements the `webauthn.User` interface from the `go-webauthn/webauthn` library.

```go
type WebAuthnUser struct {
    ID          []byte
    Name        string
    DisplayName string
}
```

Methods: `WebAuthnID()`, `WebAuthnName()`, `WebAuthnDisplayName()`. During ceremonies, `FIDO2AccountsManager` wraps this in a `webAuthnUserWithCredentials` struct that adds `WebAuthnCredentials()` to satisfy the full interface.

## FIDO2AccountsStore Interface

Persists credentials and ceremony sessions.

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

- `CreateCredential` returns `*CredentialExistsError` if the credential ID is already stored.
- `GetCredential` returns `*CredentialNotFoundError` if the ID does not exist.
- `GetCredentialsByAccount` returns an empty slice (not an error) when the account has no credentials.
- `DeleteCredential` removes both the primary entry and the account index entry (best-effort on index cleanup).
- Session methods return `*SessionNotFoundError` when the session does not exist.

## FIDO2AccountsManager

Orchestrates WebAuthn ceremony flows. Created with `NewFIDO2AccountsManager(store, provider, config)`.

### Ceremonies

**Registration** (new account):

1. `BeginRegistration(ctx, userID, username)` -- Creates a `WebAuthnUser`, calls `provider.BeginRegistration()`, stores a session of type `registration`, and returns the session along with `*protocol.CredentialCreation` options for the client.
2. `CompleteRegistration(ctx, sessionID, httpRequest)` -- Retrieves and validates the session, calls `provider.FinishRegistration()` with the attestation from the HTTP request body, converts the result to a `FIDO2Credential`, stores it, and deletes the session.

**Enrollment** (existing account, MFA):

1. `BeginEnrollment(ctx, accountUUID, credentialName)` -- Fetches existing credentials for the account, builds an exclude list to prevent re-registration of the same authenticator, calls `provider.BeginRegistration()` with exclusions, and stores a session of type `enrollment`.
2. `CompleteEnrollment(ctx, sessionID, httpRequest)` -- Same flow as `CompleteRegistration` but uses the `enrollment` session type. Sets the credential name from the session (defaults to "FIDO2 Key" if empty).

**Login** (authentication):

1. `BeginLogin(ctx, accountUUID)` -- Fetches the account's credentials. Returns `*NoCredentialsError` if none exist. Calls `provider.BeginLogin()` and stores a session of type `login`. Returns `*protocol.CredentialAssertion` for the client.
2. `CompleteLogin(ctx, sessionID, httpRequest)` -- Validates the session, calls `provider.FinishLogin()`, updates the matched credential's `SignCount`, `CloneWarning`, and `LastUsedAt`, deletes the session, and returns the `accountUUID`.

All ceremony methods wrap failures in `*CeremonyError` with the relevant `Phase` string (e.g., `"begin_registration"`, `"complete_login"`). Session cleanup after completion is best-effort -- a failure to delete does not cause the ceremony to fail.

### Credential Management

- `ListCredentials(ctx, accountUUID)` -- Returns all credentials for the account.
- `DeleteCredential(ctx, accountUUID, credentialID)` -- Verifies the credential belongs to the account before deleting. Returns `*CredentialNotFoundError` if the credential exists but belongs to a different account.
- `RenameCredential(ctx, accountUUID, credentialID, name)` -- Same ownership check, then updates the name.
- `HasCredentials(ctx, accountUUID)` -- Returns true if the account has at least one credential.

### Session Validation

`getValidatedSession(ctx, sessionID, expectedType)` is used internally by all `Complete*` methods. It checks:

1. The session exists (returns store error if not).
2. The session type matches the expected type (returns `*InvalidSessionTypeError` if not).
3. The session has not expired (returns `*SessionExpiredError` if it has).

## WebAuthnProvider Interface

Wraps the `go-webauthn/webauthn` library for testability.

```go
type WebAuthnProvider interface {
    BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
    FinishRegistration(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
    BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
    FinishLogin(user webauthn.User, session webauthn.SessionData, response *http.Request) (*webauthn.Credential, error)
}
```

`DefaultWebAuthnProvider` delegates directly to `*webauthn.WebAuthn`. Tests can substitute a mock provider.

## KV Storage Layout

The `KVFIDO2AccountsStore` uses the following key structure in the KV backend:

| Key Pattern | Content |
|---|---|
| `signal/fido2/creds/{credentialID}` | JSON-serialized `FIDO2Credential` |
| `signal/fido2/creds/by-account/{uuid}/{credentialID}` | Credential ID (string) -- secondary index |
| `signal/fido2/sessions/{sessionID}` | JSON-serialized `FIDO2Session` |

The secondary index under `by-account/` enables efficient lookup of all credentials for a given account. When listing credentials, the store first calls `kv.List()` on the account prefix, then fetches each credential by ID.

## Configuration

`FIDO2Config` is defined in `pkg/config/config_fido2.go` (build-tagged).

```yaml
fido2:
  enabled: true
  rpId: "signal.example.com"
  rpName: "Signal"
  rpOrigins:
    - "https://signal.example.com"
  attestation: "none"           # none | indirect | direct
  userVerification: "preferred" # required | preferred | discouraged
  timeoutSeconds: 60
  requireMfa: false
  allowFido2Only: false
```

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | false | Activates FIDO2 support |
| `rpId` | string | (required) | Relying Party ID, typically the domain |
| `rpName` | string | (required) | Human-readable RP name |
| `rpOrigins` | []string | (required) | Allowed origins for WebAuthn ceremonies |
| `attestation` | string | `"none"` | Attestation conveyance preference |
| `userVerification` | string | `"preferred"` | User verification requirement |
| `timeoutSeconds` | int | `60` | Ceremony timeout in seconds |
| `requireMfa` | bool | false | Require FIDO2 as a second factor for all accounts |
| `allowFido2Only` | bool | false | Allow registration without phone verification |

Validation enforces that `rpId`, `rpName`, and at least one origin are set when `enabled` is true. Invalid `attestation` or `userVerification` values are rejected.

## Typed Errors

| Error Type | When |
|---|---|
| `*CredentialNotFoundError` | Credential ID does not exist, or belongs to a different account |
| `*CredentialExistsError` | Attempting to create a credential with a duplicate ID |
| `*SessionNotFoundError` | Session ID does not exist in the store |
| `*SessionExpiredError` | Session's `ExpiresAt` is in the past |
| `*NoCredentialsError` | `BeginLogin` called for an account with zero credentials |
| `*CeremonyError` | Failure during any WebAuthn ceremony phase; wraps underlying cause via `Unwrap()` |
| `*InvalidSessionTypeError` | Session type does not match the expected ceremony type |
