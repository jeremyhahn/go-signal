package verification

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

// --- Create error paths ---

func TestKVStore_Create_PutError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	fkv.PutErr = errors.New("put failure")
	kvStore := NewKVVerificationSessionStore(fkv)

	sess := &VerificationSession{
		ID:        "sess-err-1",
		Number:    "+15551234567",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	err := kvStore.Create(context.Background(), sess)
	require.Error(t, err)
	assert.Equal(t, "put failure", err.Error())
}

// --- Get error paths ---

func TestKVStore_Get_NonKNFError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	fkv.GetErr = errors.New("storage io error")
	kvStore := NewKVVerificationSessionStore(fkv)

	_, err := kvStore.Get(context.Background(), "any-id")
	require.Error(t, err)
	assert.Equal(t, "storage io error", err.Error())
}

func TestKVStore_Get_UnmarshalError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	kvStore := NewKVVerificationSessionStore(fkv)
	ctx := context.Background()

	// Write invalid JSON directly to the delegate.
	require.NoError(t, fkv.Delegate.Put(ctx, kvSessionPrefix+"bad-sess", []byte("not-json")))

	_, err := kvStore.Get(ctx, "bad-sess")
	require.Error(t, err)
}

// --- Update error paths ---

func TestKVStore_Update_ExistsError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	fkv.ExistsErr = errors.New("exists check failure")
	kvStore := NewKVVerificationSessionStore(fkv)

	sess := &VerificationSession{ID: "sess-update-err"}
	err := kvStore.Update(context.Background(), sess)
	require.Error(t, err)
	assert.Equal(t, "exists check failure", err.Error())
}

func TestKVStore_Update_PutError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	kvStore := NewKVVerificationSessionStore(fkv)
	ctx := context.Background()

	// Seed a valid session so Exists returns true.
	sess := &VerificationSession{
		ID:        "sess-put-err",
		Number:    "+15551234567",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, kvStore.Create(ctx, sess))

	// Now cause Put to fail on subsequent calls.
	fkv.PutErr = errors.New("put failure")
	err := kvStore.Update(ctx, sess)
	require.Error(t, err)
	assert.Equal(t, "put failure", err.Error())
}

// --- Delete error paths ---

func TestKVStore_Delete_ExistsError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	fkv.ExistsErr = errors.New("exists check failure")
	kvStore := NewKVVerificationSessionStore(fkv)

	err := kvStore.Delete(context.Background(), "any-id")
	require.Error(t, err)
	assert.Equal(t, "exists check failure", err.Error())
}

func TestKVStore_Delete_DeleteError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	kvStore := NewKVVerificationSessionStore(fkv)
	ctx := context.Background()

	// Seed a valid session so Exists returns true.
	sess := &VerificationSession{
		ID:        "sess-del-err",
		Number:    "+15551234567",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, kvStore.Create(ctx, sess))

	// Cause Delete to fail.
	fkv.DeleteErr = errors.New("delete failure")
	err := kvStore.Delete(ctx, "sess-del-err")
	require.Error(t, err)
	assert.Equal(t, "delete failure", err.Error())
}

// --- Count error paths ---

func TestKVStore_Count_ListError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	fkv.ListErr = errors.New("list failure")
	kvStore := NewKVVerificationSessionStore(fkv)

	_, err := kvStore.Count(context.Background())
	require.Error(t, err)
	assert.Equal(t, "list failure", err.Error())
}

// --- DeleteExpired error paths ---

func TestKVStore_DeleteExpired_ScanError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	fkv.ScanErr = errors.New("scan failure")
	kvStore := NewKVVerificationSessionStore(fkv)

	err := kvStore.DeleteExpired(context.Background())
	require.Error(t, err)
	assert.Equal(t, "scan failure", err.Error())
}

func TestKVStore_DeleteExpired_DeleteError(t *testing.T) {
	t.Parallel()
	fkv := store.NewFailingKVClient()
	kvStore := NewKVVerificationSessionStore(fkv)
	ctx := context.Background()

	// Create an expired session.
	expired := &VerificationSession{
		ID:        "kv-expire-del-err",
		Number:    "+15551111111",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	require.NoError(t, kvStore.Create(ctx, expired))

	// Cause Delete to fail so DeleteExpired propagates it.
	fkv.DeleteErr = errors.New("delete failure on expired")
	err := kvStore.DeleteExpired(ctx)
	require.Error(t, err)
	assert.Equal(t, "delete failure on expired", err.Error())
}

// --- unmarshalSession error path ---

func TestUnmarshalSession_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := unmarshalSession([]byte("not-json"))
	require.Error(t, err)
}

func TestUnmarshalSession_ValidJSON(t *testing.T) {
	t.Parallel()
	sess := &VerificationSession{
		ID:        "marshal-test",
		Number:    "+15551234567",
		Code:      "654321",
		Verified:  false,
		Attempts:  1,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	data, err := marshalSession(sess)
	require.NoError(t, err)

	got, err := unmarshalSession(data)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, sess.Code, got.Code)
	assert.Equal(t, sess.Attempts, got.Attempts)
}
