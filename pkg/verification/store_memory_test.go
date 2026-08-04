package verification

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryStore_Create(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	session := &VerificationSession{
		ID:        "session-1",
		Number:    "+15551234567",
		Code:      "123456",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	err := store.Create(ctx, session)
	require.NoError(t, err)

	got, err := store.Get(ctx, "session-1")
	require.NoError(t, err)
	assert.Equal(t, session.ID, got.ID)
	assert.Equal(t, session.Number, got.Number)
	assert.Equal(t, session.Code, got.Code)
}

func TestMemoryStore_CreateDuplicateID_RejectsWithError(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	session1 := &VerificationSession{
		ID:     "session-1",
		Number: "+15551234567",
		Code:   "111111",
	}
	session2 := &VerificationSession{
		ID:     "session-1",
		Number: "+15559876543",
		Code:   "222222",
	}

	require.NoError(t, store.Create(ctx, session1))

	err := store.Create(ctx, session2)
	require.Error(t, err, "expected error when creating session with duplicate ID")

	// The original session must remain unchanged.
	got, err := store.Get(ctx, "session-1")
	require.NoError(t, err)
	assert.Equal(t, "+15551234567", got.Number)
	assert.Equal(t, "111111", got.Code)
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
	assert.Equal(t, "nonexistent", notFound.SessionID)
}

func TestMemoryStore_GetDeepCopy(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	session := &VerificationSession{
		ID:       "session-1",
		Number:   "+15551234567",
		Code:     "123456",
		Attempts: 0,
	}
	require.NoError(t, store.Create(ctx, session))

	got1, err := store.Get(ctx, "session-1")
	require.NoError(t, err)

	// Mutate the returned copy.
	got1.Attempts = 99
	got1.Code = "mutated"

	// The stored session should be unaffected.
	got2, err := store.Get(ctx, "session-1")
	require.NoError(t, err)
	assert.Equal(t, 0, got2.Attempts)
	assert.Equal(t, "123456", got2.Code)
}

func TestMemoryStore_CreateDeepCopy(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	session := &VerificationSession{
		ID:     "session-1",
		Number: "+15551234567",
		Code:   "123456",
	}
	require.NoError(t, store.Create(ctx, session))

	// Mutate the original after creation.
	session.Code = "mutated"

	got, err := store.Get(ctx, "session-1")
	require.NoError(t, err)
	assert.Equal(t, "123456", got.Code)
}

func TestMemoryStore_Update(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	session := &VerificationSession{
		ID:       "session-1",
		Number:   "+15551234567",
		Code:     "123456",
		Verified: false,
	}
	require.NoError(t, store.Create(ctx, session))

	updated := &VerificationSession{
		ID:       "session-1",
		Number:   "+15551234567",
		Code:     "123456",
		Verified: true,
		Attempts: 1,
	}
	err := store.Update(ctx, updated)
	require.NoError(t, err)

	got, err := store.Get(ctx, "session-1")
	require.NoError(t, err)
	assert.True(t, got.Verified)
	assert.Equal(t, 1, got.Attempts)
}

func TestMemoryStore_UpdateNotFound(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	err := store.Update(ctx, &VerificationSession{ID: "nonexistent"})
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestMemoryStore_Delete(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	session := &VerificationSession{
		ID:     "session-1",
		Number: "+15551234567",
	}
	require.NoError(t, store.Create(ctx, session))

	err := store.Delete(ctx, "session-1")
	require.NoError(t, err)

	_, err = store.Get(ctx, "session-1")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestMemoryStore_DeleteNotFound(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *SessionNotFoundError
	assert.ErrorAs(t, err, &notFound)
}

func TestMemoryStore_Count_Empty(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestMemoryStore_Count_AfterCreate(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	for i := range 3 {
		sess := &VerificationSession{
			ID:        fmt.Sprintf("session-%d", i),
			Number:    "+15551234567",
			ExpiresAt: time.Now().Add(10 * time.Minute),
		}
		require.NoError(t, store.Create(ctx, sess))
	}

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestMemoryStore_DeleteExpired_RemovesOnlyExpired(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	// One expired session.
	expired := &VerificationSession{
		ID:        "expired",
		Number:    "+15551111111",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	// One live session.
	live := &VerificationSession{
		ID:        "live",
		Number:    "+15552222222",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	require.NoError(t, store.Create(ctx, expired))
	require.NoError(t, store.Create(ctx, live))

	require.NoError(t, store.DeleteExpired(ctx))

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	_, err = store.Get(ctx, "live")
	require.NoError(t, err)

	_, err = store.Get(ctx, "expired")
	require.Error(t, err)
}

func TestMemoryStore_DeleteExpired_EmptyStore(t *testing.T) {
	t.Parallel()
	store := NewMemoryVerificationSessionStore()
	ctx := context.Background()

	err := store.DeleteExpired(ctx)
	require.NoError(t, err)

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
