package profiles

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

func newTestProfileStore() (*KVProfileStore, store.KVClient) {
	kv := store.NewMemoryKVClient()
	return NewKVProfileStore(kv), kv
}

func testKVProfile(uuid, version string) *Profile {
	return &Profile{
		UUID:           uuid,
		Version:        version,
		Name:           []byte("test-name"),
		About:          []byte("test-about"),
		AboutEmoji:     []byte("test-emoji"),
		Avatar:         "avatar-url",
		Commitment:     []byte("test-commitment"),
		PaymentAddress: []byte("test-payment"),
	}
}

// --- NewKVProfileStore tests ---

func TestNewKVProfileStore(t *testing.T) {
	s, _ := newTestProfileStore()
	require.NotNil(t, s)
}

func TestNewKVProfileStore_KVAssigned(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVProfileStore(kv)
	assert.NotNil(t, s.kv)
}

// --- Set tests ---

func TestKVSet_Success(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	profile := testKVProfile("uuid-1", "v1")
	err := s.Set(ctx, profile)
	require.NoError(t, err)

	got, err := s.Get(ctx, "uuid-1", "v1")
	require.NoError(t, err)
	assert.Equal(t, "uuid-1", got.UUID)
	assert.Equal(t, "v1", got.Version)
}

func TestKVSet_OverwriteVersion(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))

	updated := testKVProfile("uuid-1", "v1")
	updated.Name = []byte("updated-name")
	require.NoError(t, s.Set(ctx, updated))

	got, err := s.Get(ctx, "uuid-1", "v1")
	require.NoError(t, err)
	assert.Equal(t, []byte("updated-name"), got.Name)
}

func TestKVSet_MultipleVersions(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v2")))

	got1, err := s.Get(ctx, "uuid-1", "v1")
	require.NoError(t, err)
	assert.Equal(t, "v1", got1.Version)

	got2, err := s.Get(ctx, "uuid-1", "v2")
	require.NoError(t, err)
	assert.Equal(t, "v2", got2.Version)
}

func TestKVSet_UpdatesLatestMarker(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v2")))

	latest, err := s.GetLatest(ctx, "uuid-1")
	require.NoError(t, err)
	assert.Equal(t, "v2", latest.Version)
}

// --- Get tests ---

func TestKVGet_Success(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))

	got, err := s.Get(ctx, "uuid-1", "v1")
	require.NoError(t, err)
	assert.Equal(t, "avatar-url", got.Avatar)
	assert.Equal(t, []byte("test-commitment"), got.Commitment)
}

func TestKVGet_NotFound(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	_, err := s.Get(ctx, "nonexistent", "v1")
	require.Error(t, err)

	var target *ProfileNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.UUID)
	assert.Equal(t, "v1", target.Version)
}

func TestKVGet_VersionNotFound(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))

	_, err := s.Get(ctx, "uuid-1", "v999")
	require.Error(t, err)

	var target *ProfileNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestKVGet_PreservesAllFields(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	profile := &Profile{
		UUID:           "uuid-full",
		Version:        "v1",
		Name:           []byte("name"),
		About:          []byte("about"),
		AboutEmoji:     []byte("emoji"),
		Avatar:         "avatar.png",
		Commitment:     []byte("commit"),
		PaymentAddress: []byte("payment"),
	}
	require.NoError(t, s.Set(ctx, profile))

	got, err := s.Get(ctx, "uuid-full", "v1")
	require.NoError(t, err)
	assert.Equal(t, []byte("name"), got.Name)
	assert.Equal(t, []byte("about"), got.About)
	assert.Equal(t, []byte("emoji"), got.AboutEmoji)
	assert.Equal(t, "avatar.png", got.Avatar)
	assert.Equal(t, []byte("commit"), got.Commitment)
	assert.Equal(t, []byte("payment"), got.PaymentAddress)
}

// --- GetLatest tests ---

func TestKVGetLatest_Success(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))

	p2 := testKVProfile("uuid-1", "v2")
	p2.Name = []byte("latest-name")
	require.NoError(t, s.Set(ctx, p2))

	got, err := s.GetLatest(ctx, "uuid-1")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.Version)
	assert.Equal(t, []byte("latest-name"), got.Name)
}

func TestKVGetLatest_NotFound(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	_, err := s.GetLatest(ctx, "nonexistent")
	require.Error(t, err)

	var target *ProfileNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.UUID)
}

func TestKVGetLatest_ReturnsLatestVersion(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	for _, ver := range []string{"v1", "v2", "v3"} {
		require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", ver)))
	}

	got, err := s.GetLatest(ctx, "uuid-1")
	require.NoError(t, err)
	assert.Equal(t, "v3", got.Version)
}

// --- Delete tests ---

func TestKVDelete_Success(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))

	err := s.Delete(ctx, "uuid-1")
	require.NoError(t, err)

	_, err = s.Get(ctx, "uuid-1", "v1")
	require.Error(t, err)
}

func TestKVDelete_NotFound(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	err := s.Delete(ctx, "nonexistent")
	require.Error(t, err)

	var target *ProfileNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestKVDelete_AllVersionsRemoved(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v2")))

	require.NoError(t, s.Delete(ctx, "uuid-1"))

	_, err := s.Get(ctx, "uuid-1", "v1")
	require.Error(t, err)
	_, err = s.Get(ctx, "uuid-1", "v2")
	require.Error(t, err)
	_, err = s.GetLatest(ctx, "uuid-1")
	require.Error(t, err)
}

func TestKVDelete_DoesNotAffectOtherUUIDs(t *testing.T) {
	s, _ := newTestProfileStore()
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	require.NoError(t, s.Set(ctx, testKVProfile("uuid-2", "v1")))

	require.NoError(t, s.Delete(ctx, "uuid-1"))

	got, err := s.Get(ctx, "uuid-2", "v1")
	require.NoError(t, err)
	assert.Equal(t, "uuid-2", got.UUID)
}

// --- Error injection tests ---

func TestKVSet_PutError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.PutErr = errors.New("put failure")
	s := NewKVProfileStore(fkv)

	err := s.Set(context.Background(), testKVProfile("uuid-1", "v1"))
	require.Error(t, err)
	assert.Equal(t, "put failure", err.Error())
}

func TestKVGet_NonKNFError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.GetErr = errors.New("io error")
	s := NewKVProfileStore(fkv)

	_, err := s.Get(context.Background(), "uuid-1", "v1")
	require.Error(t, err)
	assert.Equal(t, "io error", err.Error())
}

func TestKVGetLatest_GetError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVProfileStore(fkv)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	fkv.GetErr = errors.New("io error")

	_, err := s.GetLatest(ctx, "uuid-1")
	require.Error(t, err)
	assert.Equal(t, "io error", err.Error())
}

func TestKVDelete_ListError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.ListErr = errors.New("list failure")
	s := NewKVProfileStore(fkv)

	err := s.Delete(context.Background(), "uuid-1")
	require.Error(t, err)
	assert.Equal(t, "list failure", err.Error())
}

func TestKVDelete_ExistsError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVProfileStore(fkv)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	fkv.ExistsErr = errors.New("exists failure")

	err := s.Delete(ctx, "uuid-1")
	require.Error(t, err)
	assert.Equal(t, "exists failure", err.Error())
}

func TestKVDelete_DeleteError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVProfileStore(fkv)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, testKVProfile("uuid-1", "v1")))
	fkv.DeleteErr = errors.New("delete failure")

	err := s.Delete(ctx, "uuid-1")
	require.Error(t, err)
	assert.Equal(t, "delete failure", err.Error())
}

// --- Interface compliance ---

func TestKVProfileStore_ImplementsProfileStore(t *testing.T) {
	var _ ProfileStore = &KVProfileStore{}
}
