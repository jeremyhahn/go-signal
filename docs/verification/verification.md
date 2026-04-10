# Verification

The verification package handles phone number verification for account registration. It manages session lifecycle, generates cryptographically random codes, delivers them through pluggable transports, and validates submissions with constant-time comparison.

**Package**: `pkg/verification/`

## VerificationTransport Interface

```go
type VerificationTransport interface {
    SendCode(ctx context.Context, destination string, code string, opts ...SendOption) error
    Name() string
}
```

Transports are pluggable. The server ships with two implementations:

- **Stub** (default): Logs codes to stdout. Used during development.
- **SMTP** (build tag `smtp`): Delivers codes via carrier email-to-SMS gateways. See [SMTP Gateway](smtp-gateway.md).

The `SendOption` functional option pattern allows transport-specific configuration. Currently one option exists: `WithCarrier(carrier string)`, which specifies the mobile carrier for SMS routing.

## VerificationManager

The `Manager` in `pkg/verification/manager.go` orchestrates the full verification flow. Created with:

```go
mgr := verification.NewManager(store, transport, verification.ManagerConfig{
    CodeLength:  6,            // digits in the code (default: 6)
    CodeTTL:     5 * time.Minute, // code validity window (default: 5m)
    MaxAttempts: 3,            // max wrong submissions (default: 3)
})
```

Zero-value fields get production defaults applied by `defaultManagerConfig()`.

### Flow

**1. CreateSession(ctx, phoneNumber)**

Creates a new session with a UUID, sets `AllowedToRequestCode: true`, and persists it via the store. The session's `ExpiresAt` is set to `now + CodeTTL`.

```go
session, err := mgr.CreateSession(ctx, "+15551234567")
// session.ID = "a1b2c3d4-..."
// session.AllowedToRequestCode = true
// session.Verified = false
```

**2. SendCode(ctx, sessionID)**

Retrieves the session, checks expiration, then generates a code using `crypto/rand`. Each digit is independently sampled from [0,9] using `rand.Int(rand.Reader, big.NewInt(10))`. The code is stored in the session, `AllowedToRequestCode` is set to false, and `ExpiresAt` is reset. The code is then delivered via the configured transport.

If the transport fails, the error is wrapped in `*TransportError` with the transport name, destination, and underlying cause.

**3. SubmitCode(ctx, sessionID, code)**

Validates the submitted code against the stored session code. Checks, in order:

1. Session expiration -- returns `*SessionExpiredError`
2. Code presence -- returns `*CodeExpiredError` if the code field is empty
3. Attempt count -- returns `*MaxAttemptsExceededError` if `session.Attempts >= MaxAttempts`
4. Code comparison -- uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks; returns `*InvalidCodeError` on mismatch

On success, the session is marked `Verified: true` and the code is cleared. The attempt counter is incremented regardless of outcome.

**GetSession(ctx, sessionID)** retrieves a session without modifying it.

## Session Lifecycle

```
Created                    Code Sent                     Submitted
  AllowedToRequestCode=true   AllowedToRequestCode=false    Verified=true
  Verified=false              ExpiresAt reset               Code=""
  Code=""                     Code=<random>
```

## VerificationSession

```go
type VerificationSession struct {
    ID                   string    `json:"id"`
    Number               string    `json:"number"`
    Code                 string    `json:"-"`  // never serialized to clients
    Verified             bool      `json:"verified"`
    Attempts             int       `json:"attempts"`
    AllowedToRequestCode bool      `json:"allowedToRequestCode"`
    CreatedAt            time.Time `json:"createdAt"`
    ExpiresAt            time.Time `json:"expiresAt"`
}
```

The `Code` field uses `json:"-"` to prevent it from appearing in API responses. This is critical -- the code must never leave the server except through the transport.

## VerificationSessionStore Interface

```go
type VerificationSessionStore interface {
    Create(ctx context.Context, session *VerificationSession) error
    Get(ctx context.Context, sessionID string) (*VerificationSession, error)
    Update(ctx context.Context, session *VerificationSession) error
    Delete(ctx context.Context, sessionID string) error
}
```

### MemoryVerificationSessionStore

In-memory implementation using `sync.RWMutex`. Returns deep copies from `Get()` to prevent callers from mutating internal state. All methods that access a non-existent session return `*SessionNotFoundError`.

### KVVerificationSessionStore

KV-backed implementation using the `store.KVClient` interface. Keys follow the pattern:

```
signal/verification/{sessionID}
```

Because `VerificationSession.Code` is tagged `json:"-"`, the KV store uses an internal `kvSession` struct that embeds `VerificationSession` and adds a separate `Code string` field with a proper JSON tag. This preserves the code during marshal/unmarshal while keeping it hidden from API serialization.

The `marshalSession` function wraps the session in a `kvSession` before encoding. The `unmarshalSession` function decodes into `kvSession` and copies the code back into the embedded `VerificationSession`.

## Security

- **Code generation**: Each digit is independently sampled from `crypto/rand` using `rand.Int(rand.Reader, big.NewInt(10))`. No `math/rand` is used anywhere in the verification path.
- **Code comparison**: `crypto/subtle.ConstantTimeCompare` prevents timing side-channel attacks when validating submitted codes.
- **Attempt limiting**: The session tracks `Attempts` and rejects submissions after `MaxAttempts` is reached.
- **Session expiration**: `ExpiresAt` is checked before code generation and before code validation. Expired sessions cannot be used.
- **Code exclusion**: The `json:"-"` tag on `Code` ensures it is never included in JSON responses to clients.

## Typed Errors

| Error Type | Trigger |
|---|---|
| `*SessionNotFoundError` | Session ID does not exist in the store |
| `*SessionExpiredError` | `time.Now()` is past `session.ExpiresAt` |
| `*CodeExpiredError` | Session exists but `Code` field is empty |
| `*MaxAttemptsExceededError` | `session.Attempts >= MaxAttempts` |
| `*InvalidCodeError` | Submitted code does not match stored code |
| `*TransportError` | Transport failed to deliver the code; wraps cause via `Unwrap()` |
| `*CarrierNotFoundError` | Specified carrier key is not in the gateway map |
