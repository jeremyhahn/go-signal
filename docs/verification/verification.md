# Verification

> **Status: REFERENCE** · Last verified: 2026-10-09
> Phone-number verification: the transport interface, the session engine in `pkg/registration/core`, the session stores and the typed errors.

Verification sessions gate account registration. The session engine generates cryptographically random codes, delivers them through a pluggable transport and validates submissions with a constant-time comparison.

**Packages**: `pkg/verification/` (types, stores, transports, errors) and `pkg/registration/core/` (the `Service` engine). With `verification.remoteAddr` set, signald talks to the `registration-service` binary instead of running the engine in process (see [../architecture/decisions/0004-verification-transport-abstraction.md](../architecture/decisions/0004-verification-transport-abstraction.md)).

## VerificationTransport Interface

```go
type VerificationTransport interface {
    SendCode(ctx context.Context, destination string, code string, opts ...SendOption) error
    Name() string
}
```

Implementations in the tree:

| Transport | Package | Selectable through the factory |
|---|---|---|
| Stub | `pkg/verification` (`StubTransport`) | Yes: `verification.transport: stub`, also the default when empty |
| Twilio Verify | `pkg/verification/twilio` | Yes: `verification.transport: twilio` |
| SMTP (build tag `smtp`) | `pkg/verification/smtp` | No. See [SMTP Gateway](smtp-gateway.md). |
| AWS SES | `pkg/verification/ses` | No |

`pkg/verification/factory.Build` is the single place that maps `verification.transport` to a transport; any other value, including `smtp`, returns an invalid-argument error. The stub logs the code and a redacted destination instead of delivering it, and the production config gate rejects it. `RouterTransport` (`pkg/verification/router.go`) dispatches to an SMS or an email transport by destination channel; it is a building block and is not wired into the factory.

`SendOption` is a functional option. One option exists: `WithCarrier(carrier string)`, which names the mobile carrier for SMS gateway routing.

## Service (`pkg/registration/core`)

```go
svc := core.NewService(store, transport, core.Config{ /* zero values get defaults */ })
defer svc.Shutdown()
```

`NewService` starts a background goroutine that calls `store.DeleteExpired` every `CleanupInterval`; `Shutdown` stops it and is safe to call more than once.

| `Config` field | Default |
|---|---|
| `CodeLength` | 6 digits |
| `CodeTTL` | 5 minutes |
| `MaxAttempts` | 3 |
| `MaxSessions` | 10,000 |
| `SessionTTL` | 10 minutes |
| `CleanupInterval` | 60 seconds |
| `RequestCodeCooldowns` | 0, 1 min, 5 min, 30 min, 60 min |
| `FixedCode` | empty (random codes); for integration tests with the stub transport only |

### Flow

**1. CreateSession(ctx, number)** returns `*SessionLimitExceededError` when the store already holds `MaxSessions` sessions. Otherwise it creates a session with a random UUID and `AllowedToRequestCode: true`. `ExpiresAt` is `now + SessionTTL`.

**2. SendCode(ctx, sessionID)** checks, in order:

1. Session expiry: `*SessionExpiredError`.
2. Already verified: `*SessionAlreadyVerifiedError`. This precedes the cooldown check, so a client that just verified is not told to wait.
3. Cooldown: `*RequestCodeRateLimitedError` (carrying `RetryAfter`) while `NextCodeRequestAt` is in the future.

It then generates the code, stores it on the session, resets `ExpiresAt` to `now + CodeTTL`, sets `AllowedToRequestCode` to false, increments `CodeRequests` and sets `NextCodeRequestAt` from the cooldown schedule (indexed by `CodeRequests`, clamped to the last entry; an empty schedule disables the cooldown). The session is persisted before the transport is called. A transport failure is returned as `*TransportError`.

**3. SubmitCode(ctx, sessionID, code)** checks, in order:

1. Session expiry: `*SessionExpiredError`.
2. Empty stored code: `*CodeExpiredError`.
3. `Attempts >= MaxAttempts`: `*MaxAttemptsExceededError`.
4. `Attempts` is incremented, then the code is compared with `crypto/subtle.ConstantTimeCompare`; a mismatch persists the new count and returns `*InvalidCodeError`.

On success the session is marked `Verified: true` and the code is cleared.

**GetSession(ctx, sessionID)** returns the session, or `*SessionExpiredError` when it has expired.

## Session Lifecycle

```
Created                       Code Sent                     Submitted
  AllowedToRequestCode=true     AllowedToRequestCode=false    Verified=true
  Verified=false                ExpiresAt = now + CodeTTL     Code=""
  Code=""                       Code=<random>
```

## VerificationSession

```go
type VerificationSession struct {
    ID                   string    `json:"id"`
    Number               string    `json:"number"`
    Code                 string    `json:"-"` // never serialized to clients
    Verified             bool      `json:"verified"`
    Attempts             int       `json:"attempts"`
    AllowedToRequestCode bool      `json:"allowedToRequestCode"`
    CreatedAt            time.Time `json:"createdAt"`
    ExpiresAt            time.Time `json:"expiresAt"`
    NextCodeRequestAt    time.Time `json:"nextCodeRequestAt,omitempty"`
    CodeRequests         int       `json:"codeRequests,omitempty"`
    CaptchaRequired      bool      `json:"captchaRequired,omitempty"`
}
```

`Code` uses `json:"-"` so it never appears in API responses; the code leaves the server only through the transport. `NextCodeRequestAt` and `CodeRequests` drive the per-session cooldown. `CaptchaRequired` marks a session that needs a successful captcha before the next `SendCode`.

## VerificationSessionStore Interface

```go
type VerificationSessionStore interface {
    Create(ctx context.Context, session *VerificationSession) error
    Get(ctx context.Context, sessionID string) (*VerificationSession, error)
    Update(ctx context.Context, session *VerificationSession) error
    Delete(ctx context.Context, sessionID string) error
    Count(ctx context.Context) (int, error)
    DeleteExpired(ctx context.Context) error
}
```

`Count` enforces `MaxSessions`; `DeleteExpired` removes sessions whose `ExpiresAt` is in the past and is what the cleanup goroutine calls. The qrdb and Postgres implementations are listed in [../storage/overview.md](../storage/overview.md).

### MemoryVerificationSessionStore

In-memory implementation using `sync.RWMutex`. Returns copies from `Get` so callers cannot mutate internal state. Missing sessions return `*SessionNotFoundError`.

### KVVerificationSessionStore

KV-backed implementation over `store.KVClient`. Keys follow the pattern:

```
signal/verification/{sessionID}
```

Because `VerificationSession.Code` is tagged `json:"-"`, the KV store encodes through an internal `kvSession` struct that embeds `VerificationSession` and adds a `Code` field with a JSON tag, so the code survives a round trip. `marshalSession` and `unmarshalSession` perform the wrapping. The Postgres store does not persist the code.

## Security

- **Code generation**: each digit is sampled independently from `crypto/rand` (`rand.Int(rand.Reader, big.NewInt(10))`).
- **Code comparison**: `crypto/subtle.ConstantTimeCompare`.
- **Attempt limiting**: submissions are rejected once `Attempts` reaches `MaxAttempts`.
- **Cooldown**: `SendCode` is rate limited per session by `RequestCodeCooldowns`.
- **Session expiry**: `ExpiresAt` is checked in `SendCode`, `SubmitCode` and `GetSession`.
- **Code exclusion**: `json:"-"` keeps the code out of JSON responses.

## Typed Errors

| Error Type | Trigger |
|---|---|
| `*SessionNotFoundError` | Session ID does not exist in the store |
| `*SessionExpiredError` | The session's `ExpiresAt` is in the past |
| `*CodeExpiredError` | Session exists but `Code` is empty |
| `*MaxAttemptsExceededError` | `Attempts >= MaxAttempts` |
| `*InvalidCodeError` | Submitted code does not match the stored code |
| `*TransportError` | Transport failed to deliver the code; wraps the cause via `Unwrap()` |
| `*CarrierNotFoundError` | The carrier key is not in the gateway map (SMTP transport) |
| `*SessionLimitExceededError` | `CreateSession` with the store at `MaxSessions` |
| `*SessionAlreadyVerifiedError` | `SendCode` on a verified session |
| `*RequestCodeRateLimitedError` | `SendCode` before `NextCodeRequestAt` |

`CaptchaRequiredError`, `CaptchaCheckUnavailableError` and `CaptchaRejectedError` are also declared in `pkg/verification/errors.go`.
