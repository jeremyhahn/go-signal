package verification

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKVStore_Create(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	session := &VerificationSession{
		ID:        "kv-session-1",
		Number:    "+15551234567",
		Code:      "654321",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	err := kvStore.Create(ctx, session)
	require.NoError(t, err)

	got, err := kvStore.Get(ctx, "kv-session-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.Number, got.Number)
	assert.Equal(t, session.Code, got.Code)
}

func TestKVStore_CreateOverwrite(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	session1 := &VerificationSession{
		ID:     "kv-session-1",
		Number: "+15551234567",
		Code:   "111111",
	}
	session2 := &VerificationSession{
		ID:     "kv-session-1",
		Number: "+15559876543",
		Code:   "222222",
	}

	require.NoError(t, kvStore.Create(ctx, session1))
	require.NoError(t, kvStore.Create(ctx, session2))

	got, err := kvStore.Get(ctx, "kv-session-1")
	require.NoError(t, err)
	assert.Equal(t, "+15559876543", got.Number)
	assert.Equal(t, "222222", got.Code)
}

func TestKVStore_GetNotFound(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	_, err := kvStore.Get(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
	assert.Equal(t, "nonexistent", notFound.SessionID)
}

func TestKVStore_GetPreservesCode(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	session := &VerificationSession{
		ID:     "kv-session-code",
		Number: "+15551234567",
		Code:   "987654",
	}
	require.NoError(t, kvStore.Create(ctx, session))

	got, err := kvStore.Get(ctx, "kv-session-code")
	require.NoError(t, err)
	assert.Equal(t, "987654", got.Code)
}

func TestKVStore_Update(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	session := &VerificationSession{
		ID:       "kv-session-1",
		Number:   "+15551234567",
		Code:     "123456",
		Verified: false,
	}
	require.NoError(t, kvStore.Create(ctx, session))

	updated := &VerificationSession{
		ID:       "kv-session-1",
		Number:   "+15551234567",
		Code:     "123456",
		Verified: true,
		Attempts: 1,
	}
	err := kvStore.Update(ctx, updated)
	require.NoError(t, err)

	got, err := kvStore.Get(ctx, "kv-session-1")
	require.NoError(t, err)
	assert.True(t, got.Verified)
	assert.Equal(t, 1, got.Attempts)
}

func TestKVStore_UpdateNotFound(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	err := kvStore.Update(ctx, &VerificationSession{ID: "nonexistent"})
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestKVStore_Delete(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	session := &VerificationSession{
		ID:     "kv-session-1",
		Number: "+15551234567",
	}
	require.NoError(t, kvStore.Create(ctx, session))

	err := kvStore.Delete(ctx, "kv-session-1")
	require.NoError(t, err)

	_, err = kvStore.Get(ctx, "kv-session-1")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestKVStore_DeleteNotFound(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	err := kvStore.Delete(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestKVStore_Count_Empty(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	count, err := kvStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestKVStore_Count_AfterCreate(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	for i := range 3 {
		sess := &VerificationSession{
			ID:        fmt.Sprintf("kv-sess-%d", i),
			Number:    "+15551234567",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, kvStore.Create(ctx, sess))
	}

	count, err := kvStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestKVStore_DeleteExpired_RemovesOnlyExpired(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	expired := &VerificationSession{
		ID:        "kv-expired",
		Number:    "+15551111111",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	live := &VerificationSession{
		ID:        "kv-live",
		Number:    "+15552222222",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	require.NoError(t, kvStore.Create(ctx, expired))
	require.NoError(t, kvStore.Create(ctx, live))

	require.NoError(t, kvStore.DeleteExpired(ctx))

	count, err := kvStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	_, err = kvStore.Get(ctx, "kv-live")
	require.NoError(t, err)

	_, err = kvStore.Get(ctx, "kv-expired")
	require.Error(t, err)
}

func TestKVStore_DeleteExpired_EmptyStore(t *testing.T) {
	t.Parallel()
	kvStore := NewKVVerificationSessionStore(store.NewMemoryKVClient())
	ctx := context.Background()

	err := kvStore.DeleteExpired(ctx)
	require.NoError(t, err)

	count, err := kvStore.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
