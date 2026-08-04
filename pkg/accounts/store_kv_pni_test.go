package accounts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

// --- GetByPNI tests ---

func TestKVAccountStore_GetByPNI_Success(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-pni-1", "+15551234567")
	acct.PNI = "pni-uuid-abc"
	require.NoError(t, s.Create(ctx, acct))

	got, err := s.GetByPNI(ctx, "pni-uuid-abc")
	require.NoError(t, err)
	assert.Equal(t, "uuid-pni-1", got.UUID)
}

func TestKVAccountStore_GetByPNI_NotFound(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	_, err := s.GetByPNI(ctx, "nonexistent-pni")
	require.Error(t, err)

	var target *AccountNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent-pni", target.Identifier)
}

func TestKVAccountStore_GetByPNI_NonKNFError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.GetErr = errors.New("storage error")
	s := NewKVAccountStore(fkv)

	_, err := s.GetByPNI(context.Background(), "some-pni")
	require.Error(t, err)
	assert.Equal(t, "storage error", err.Error())
}

func TestKVAccountStore_Create_CreatesPNIIndex(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-pni-2", "+15552222222")
	acct.PNI = "pni-uuid-def"
	require.NoError(t, s.Create(ctx, acct))

	got, err := s.GetByPNI(ctx, "pni-uuid-def")
	require.NoError(t, err)
	assert.Equal(t, "uuid-pni-2", got.UUID)
}

func TestKVAccountStore_Create_NoPNI(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	// An account with no PNI must still be created without error.
	acct := testAccount("uuid-nopni", "+15553333333")
	acct.PNI = ""
	require.NoError(t, s.Create(ctx, acct))

	got, err := s.Get(ctx, "uuid-nopni")
	require.NoError(t, err)
	assert.Equal(t, "", got.PNI)
}

func TestKVAccountStore_Update_PNIChange(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-pni-change", "+15554444444")
	acct.PNI = "old-pni"
	require.NoError(t, s.Create(ctx, acct))

	acct.PNI = "new-pni"
	require.NoError(t, s.Update(ctx, acct))

	// Old PNI should no longer resolve.
	_, err := s.GetByPNI(ctx, "old-pni")
	require.Error(t, err)
	var notFound *AccountNotFoundError
	require.True(t, errors.As(err, &notFound))

	// New PNI should resolve.
	got, err := s.GetByPNI(ctx, "new-pni")
	require.NoError(t, err)
	assert.Equal(t, "uuid-pni-change", got.UUID)
}

func TestKVAccountStore_Update_PNIChangeNewIndexPutError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVAccountStore(fkv)
	ctx := context.Background()

	// Seed: account with old PNI.
	data := []byte(`{"uuid":"uuid-1","number":"+15551111111","pni":"old-pni","version":1}`)
	require.NoError(t, fkv.Delegate.Put(ctx, "signal/accounts/uuid-1", data))
	require.NoError(t, fkv.Delegate.Put(ctx, "signal/accounts/by-pni/old-pni", []byte("uuid-1")))

	// Make Put fail so new PNI index write fails.
	fkv.PutErr = errors.New("pni put failure")

	acct := testAccount("uuid-1", "+15551111111")
	acct.PNI = "new-pni"
	err := s.Update(ctx, acct)
	require.Error(t, err)
}

func TestKVAccountStore_Update_PNIChangeDeleteOldIndexError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVAccountStore(fkv)
	ctx := context.Background()

	// Seed account with old PNI.
	data := []byte(`{"uuid":"uuid-pni-del","number":"+15551234567","pni":"old-pni","version":1}`)
	require.NoError(t, fkv.Delegate.Put(ctx, "signal/accounts/uuid-pni-del", data))
	require.NoError(t, fkv.Delegate.Put(ctx, "signal/accounts/by-pni/old-pni", []byte("uuid-pni-del")))

	fkv.DeleteErr = errors.New("pni delete failure")

	acct := testAccount("uuid-pni-del", "+15551234567")
	acct.PNI = "new-pni"
	err := s.Update(ctx, acct)
	require.Error(t, err)
	assert.Equal(t, "pni delete failure", err.Error())
}

func TestKVAccountStore_Delete_RemovesPNIIndex(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-pni-del2", "+15555555555")
	acct.PNI = "pni-to-delete"
	require.NoError(t, s.Create(ctx, acct))
	require.NoError(t, s.Delete(ctx, "uuid-pni-del2"))

	_, err := s.GetByPNI(ctx, "pni-to-delete")
	require.Error(t, err)
	var notFound *AccountNotFoundError
	require.True(t, errors.As(err, &notFound))
}

func TestKVAccountStore_Delete_NoPNI(t *testing.T) {
	s, _ := newTestAccountStore()
	ctx := context.Background()

	// Account without a PNI must delete cleanly.
	acct := &Account{
		UUID:        "uuid-nopni-del",
		Number:      "+15556666666",
		PNI:         "",
		IdentityKey: []byte("ik"),
		Devices: []Device{
			{
				ID:        PrimaryDeviceID,
				AuthToken: "tok",
				SignedPreKey: &SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pk"),
					Signature: []byte("sig"),
				},
				CreatedAt: time.Now(),
			},
		},
		CreatedAt: time.Now(),
		Version:   1,
	}
	require.NoError(t, s.Create(ctx, acct))
	require.NoError(t, s.Delete(ctx, "uuid-nopni-del"))

	_, err := s.Get(ctx, "uuid-nopni-del")
	var notFound *AccountNotFoundError
	require.True(t, errors.As(err, &notFound))
}
