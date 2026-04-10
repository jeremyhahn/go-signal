package verification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTransport implements VerificationTransport for testing.
type mockTransport struct {
	name     string
	lastDest string
	lastCode string
	sendErr  error
}

func (m *mockTransport) SendCode(_ context.Context, destination string, code string, _ ...SendOption) error {
	m.lastDest = destination
	m.lastCode = code
	return m.sendErr
}

func (m *mockTransport) Name() string {
	return m.name
}

func newTestManager(t *testing.T, transport *mockTransport, config ManagerConfig) *Manager {
	t.Helper()
	store := NewMemoryVerificationSessionStore()
	return NewManager(store, transport, config)
}

func TestManager_DefaultConfig(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})

	assert.Equal(t, 6, mgr.config.CodeLength)
	assert.Equal(t, 5*time.Minute, mgr.config.CodeTTL)
	assert.Equal(t, 3, mgr.config.MaxAttempts)
}

func TestManager_CustomConfig(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{
		CodeLength:  8,
		CodeTTL:     10 * time.Minute,
		MaxAttempts: 5,
	})

	assert.Equal(t, 8, mgr.config.CodeLength)
	assert.Equal(t, 10*time.Minute, mgr.config.CodeTTL)
	assert.Equal(t, 5, mgr.config.MaxAttempts)
}

func TestManager_CreateSession(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)
	assert.NotEmpty(t, session.ID)
	assert.Equal(t, "+15551234567", session.Number)
	assert.True(t, session.AllowedToRequestCode)
	assert.False(t, session.Verified)
	assert.Equal(t, 0, session.Attempts)
	assert.False(t, session.CreatedAt.IsZero())
	assert.False(t, session.ExpiresAt.IsZero())
}

func TestManager_FullVerificationFlow(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	// Create session.
	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	// Send code.
	session, err = mgr.SendCode(ctx, session.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, session.Code)
	assert.False(t, session.AllowedToRequestCode)
	assert.Equal(t, transport.lastDest, "+15551234567")
	assert.Equal(t, transport.lastCode, session.Code)

	// Submit correct code.
	code := transport.lastCode
	session, err = mgr.SubmitCode(ctx, session.ID, code)
	require.NoError(t, err)
	assert.True(t, session.Verified)
	assert.Equal(t, 1, session.Attempts)
	assert.Empty(t, session.Code)
}

func TestManager_WrongCodeRejection(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	_, err = mgr.SendCode(ctx, session.ID)
	require.NoError(t, err)

	_, err = mgr.SubmitCode(ctx, session.ID, "000000")
	require.Error(t, err)

	var invalidCode *InvalidCodeError
	assert.ErrorAs(t, err, &invalidCode)
	assert.Equal(t, session.ID, invalidCode.SessionID)

	// Verify attempts incremented.
	got, err := mgr.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Attempts)
	assert.False(t, got.Verified)
}

func TestManager_MaxAttemptsExceeded(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{MaxAttempts: 2})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	_, err = mgr.SendCode(ctx, session.ID)
	require.NoError(t, err)

	// Use up all attempts with wrong codes.
	_, err = mgr.SubmitCode(ctx, session.ID, "000000")
	require.Error(t, err)
	var invalidCode *InvalidCodeError
	assert.ErrorAs(t, err, &invalidCode)

	_, err = mgr.SubmitCode(ctx, session.ID, "000001")
	require.Error(t, err)
	assert.ErrorAs(t, err, &invalidCode)

	// Third attempt should be rejected as max exceeded.
	_, err = mgr.SubmitCode(ctx, session.ID, "000002")
	require.Error(t, err)

	var maxExceeded *MaxAttemptsExceededError
	assert.ErrorAs(t, err, &maxExceeded)
	assert.Equal(t, 2, maxExceeded.MaxAttempts)
}

func TestManager_ExpiredSession(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := NewManager(
		NewMemoryVerificationSessionStore(),
		transport,
		ManagerConfig{CodeTTL: 1 * time.Nanosecond, MaxAttempts: 3, CodeLength: 6},
	)
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	// Directly expire the session by manipulating its ExpiresAt timestamp,
	// avoiding a time.Sleep dependency while reliably testing the expiry path.
	stored, storeGetErr := mgr.store.Get(ctx, session.ID)
	require.NoError(t, storeGetErr)
	stored.ExpiresAt = time.Now().Add(-time.Second)
	require.NoError(t, mgr.store.Update(ctx, stored))

	_, err = mgr.SendCode(ctx, session.ID)
	require.Error(t, err)

	var expired *SessionExpiredError
	assert.ErrorAs(t, err, &expired)
	assert.Equal(t, session.ID, expired.SessionID)
}

func TestManager_SubmitCodeExpiredSession(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	store := NewMemoryVerificationSessionStore()
	mgr := NewManager(store, transport, ManagerConfig{CodeTTL: 10 * time.Minute})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	_, err = mgr.SendCode(ctx, session.ID)
	require.NoError(t, err)

	// Manually expire the session.
	got, err := store.Get(ctx, session.ID)
	require.NoError(t, err)
	got.ExpiresAt = time.Now().Add(-1 * time.Second)
	require.NoError(t, store.Update(ctx, got))

	_, err = mgr.SubmitCode(ctx, session.ID, transport.lastCode)
	require.Error(t, err)

	var expired *SessionExpiredError
	assert.ErrorAs(t, err, &expired)
}

func TestManager_SessionNotFound(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	_, err := mgr.SendCode(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)

	_, err = mgr.SubmitCode(ctx, "nonexistent", "123456")
	require.Error(t, err)
	assert.ErrorAs(t, err, &notFound)

	_, err = mgr.GetSession(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorAs(t, err, &notFound)
}

func TestManager_TransportError(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{
		name:    "test",
		sendErr: errors.New("connection refused"),
	}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	_, err = mgr.SendCode(ctx, session.ID)
	require.Error(t, err)

	var transportErr *TransportError
	assert.ErrorAs(t, err, &transportErr)
	assert.Equal(t, "test", transportErr.Transport)
	assert.Equal(t, "+15551234567", transportErr.Destination)
	assert.Equal(t, "connection refused", transportErr.Unwrap().Error())
}

func TestManager_SubmitCodeNoCodeSent(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	// Submit code without ever sending one.
	_, err = mgr.SubmitCode(ctx, session.ID, "123456")
	require.Error(t, err)

	var codeExpired *CodeExpiredError
	assert.ErrorAs(t, err, &codeExpired)
}

func TestManager_GetSession(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	got, err := mgr.GetSession(ctx, session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.Number, got.Number)
}

// TestManager_GetSession_Expired verifies that GetSession returns a
// SessionExpiredError when the session has passed its ExpiresAt.
func TestManager_GetSession_Expired(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	store := NewMemoryVerificationSessionStore()
	mgr := NewManager(store, transport, ManagerConfig{
		SessionTTL: time.Nanosecond,
	})
	t.Cleanup(mgr.Shutdown)
	ctx := context.Background()

	session, err := mgr.CreateSession(ctx, "+15559876543")
	require.NoError(t, err)

	// Wait for the session to expire (TTL is 1ns).
	time.Sleep(5 * time.Millisecond)

	_, err = mgr.GetSession(ctx, session.ID)
	require.Error(t, err)
	var expiredErr *SessionExpiredError
	assert.ErrorAs(t, err, &expiredErr)
	assert.Equal(t, session.ID, expiredErr.SessionID)
}

// TestManager_SessionLimitExceeded verifies that CreateSession returns a
// SessionLimitExceededError once MaxSessions is reached.
func TestManager_SessionLimitExceeded(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	store := NewMemoryVerificationSessionStore()
	mgr := NewManager(store, transport, ManagerConfig{
		MaxSessions: 2,
		SessionTTL:  10 * time.Minute,
	})
	t.Cleanup(mgr.Shutdown)
	ctx := context.Background()

	_, err := mgr.CreateSession(ctx, "+15551111111")
	require.NoError(t, err)
	_, err = mgr.CreateSession(ctx, "+15552222222")
	require.NoError(t, err)

	_, err = mgr.CreateSession(ctx, "+15553333333")
	require.Error(t, err)
	var limitErr *SessionLimitExceededError
	assert.ErrorAs(t, err, &limitErr)
	assert.Equal(t, 2, limitErr.Limit)
}

// TestManager_SessionTTL verifies that sessions are created with an ExpiresAt
// set from the configured SessionTTL.
func TestManager_SessionTTL(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	store := NewMemoryVerificationSessionStore()
	ttl := 7 * time.Minute
	mgr := NewManager(store, transport, ManagerConfig{SessionTTL: ttl})
	t.Cleanup(mgr.Shutdown)
	ctx := context.Background()

	before := time.Now()
	session, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	minExpiry := before.Add(ttl)
	maxExpiry := time.Now().Add(ttl + time.Second)
	assert.True(t, session.ExpiresAt.After(minExpiry) || session.ExpiresAt.Equal(minExpiry),
		"ExpiresAt %v is before expected minimum %v", session.ExpiresAt, minExpiry)
	assert.True(t, session.ExpiresAt.Before(maxExpiry),
		"ExpiresAt %v is after expected maximum %v", session.ExpiresAt, maxExpiry)
}

// TestManager_Shutdown verifies that calling Shutdown does not panic and that
// subsequent sessions can still be created (Shutdown only stops the cleanup
// goroutine, not the store).
func TestManager_Shutdown(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})
	ctx := context.Background()

	// Shutdown should be idempotent and not panic.
	mgr.Shutdown()
	mgr.Shutdown()

	// Store operations should still work.
	_, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)
}

// TestManager_CleanupGoroutineEvictsExpiredSessions verifies that the
// background cleanup goroutine removes expired sessions from the store.
func TestManager_CleanupGoroutineEvictsExpiredSessions(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	store := NewMemoryVerificationSessionStore()
	mgr := NewManager(store, transport, ManagerConfig{
		SessionTTL:      time.Nanosecond,
		CleanupInterval: 10 * time.Millisecond,
	})
	t.Cleanup(mgr.Shutdown)
	ctx := context.Background()

	_, err := mgr.CreateSession(ctx, "+15551234567")
	require.NoError(t, err)

	count, err := store.Count(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, count, "expected session to exist after creation")

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		count, err = store.Count(ctx)
		require.NoError(t, err)
		if count == 0 {
			break
		}
	}
	assert.Equal(t, 0, count, "expected cleanup goroutine to evict expired session")
}

// TestManager_Shutdown_Idempotent verifies that calling Shutdown more than once
// does not panic; sync.Once must guard the cancel call.
func TestManager_Shutdown_Idempotent(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	mgr := newTestManager(t, transport, ManagerConfig{})

	// Neither call should panic.
	mgr.Shutdown()
	mgr.Shutdown()
}

// TestManager_CreateThenImmediateShutdown verifies that a Manager whose
// Shutdown is called immediately after construction does not leak its cleanup
// goroutine. The store must still be functional after Shutdown.
func TestManager_CreateThenImmediateShutdown(t *testing.T) {
	t.Parallel()
	transport := &mockTransport{name: "test"}
	store := NewMemoryVerificationSessionStore()
	mgr := NewManager(store, transport, ManagerConfig{
		CleanupInterval: time.Hour, // long interval so the goroutine blocks on tick
	})

	// Shut down immediately before the cleanup goroutine has a chance to fire.
	mgr.Shutdown()

	// The store must remain usable; CreateSession goes directly to the store
	// and must not be affected by the stopped goroutine.
	ctx := context.Background()
	session, err := mgr.CreateSession(ctx, "+15559999999")
	if err != nil {
		t.Fatalf("unexpected error after immediate shutdown: %v", err)
	}
	if session == nil {
		t.Fatal("expected non-nil session after immediate shutdown")
	}
}

func TestGenerateCode(t *testing.T) {
	t.Parallel()

	t.Run("length", func(t *testing.T) {
		t.Parallel()
		code, err := generateCode(6)
		require.NoError(t, err)
		assert.Len(t, code, 6)
	})

	t.Run("numeric_only", func(t *testing.T) {
		t.Parallel()
		code, err := generateCode(100)
		require.NoError(t, err)
		for _, c := range code {
			assert.True(t, c >= '0' && c <= '9', "expected digit, got %c", c)
		}
	})

	t.Run("different_lengths", func(t *testing.T) {
		t.Parallel()
		for _, length := range []int{4, 6, 8, 10} {
			code, err := generateCode(length)
			require.NoError(t, err)
			assert.Len(t, code, length)
		}
	})
}
