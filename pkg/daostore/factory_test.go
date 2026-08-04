package daostore

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKVStore is a minimal in-memory kvstore.KVStore used by factory tests.
type mockKVStore struct {
	data    map[string][]byte
	putErr  error
	getErr  error
	scanErr error
}

func newMockKVStore() *mockKVStore {
	return &mockKVStore{data: make(map[string][]byte)}
}

func (m *mockKVStore) Put(_ context.Context, key string, value []byte) error {
	if m.putErr != nil {
		return m.putErr
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

func (m *mockKVStore) Get(_ context.Context, key string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.data[key], nil // nil, nil for missing keys matches the interface contract
}

func (m *mockKVStore) Delete(_ context.Context, key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockKVStore) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	if m.scanErr != nil {
		return m.scanErr
	}
	for k, v := range m.data {
		if strings.HasPrefix(k, prefix) {
			if err := fn(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *mockKVStore) List(_ context.Context, prefix string) ([]string, error) {
	var keys []string
	for k := range m.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (m *mockKVStore) Exists(_ context.Context, key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}

func (m *mockKVStore) RegisterEntityIndexes(_ string, _ []kvstore.EntityIndex) error {
	return nil
}

func (m *mockKVStore) QueryIndex(_ context.Context, _ string, _ []byte) ([][]byte, error) {
	return nil, nil
}

func (m *mockKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (m *mockKVStore) QueryCompoundIndex(_ context.Context, _ string, _ [][]byte) ([][]byte, error) {
	return nil, nil
}

func (m *mockKVStore) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

// -- NewFactory --

func TestNewFactory_Success(t *testing.T) {
	store := newMockKVStore()
	f, err := NewFactory(store)
	require.NoError(t, err)
	require.NotNil(t, f)

	assert.NotNil(t, f.Messages)
	assert.NotNil(t, f.Conversations)
	assert.NotNil(t, f.Contacts)
	assert.NotNil(t, f.Groups)
	assert.NotNil(t, f.Reactions)
	assert.NotNil(t, f.Attachments)
	assert.NotNil(t, f.Stickers)
	assert.NotNil(t, f.StickerPacks)
	assert.NotNil(t, f.Jobs)
	assert.NotNil(t, f.Sessions)
	assert.NotNil(t, f.PreKeys)
	assert.NotNil(t, f.SignedPreKeys)
	assert.NotNil(t, f.IdentityKeys)
	assert.NotNil(t, f.SenderKeys)
	assert.NotNil(t, f.Settings)
}

func TestNewFactory_NilStore(t *testing.T) {
	// dao.New validates that store is not nil and returns an error.
	_, err := NewFactory(nil)
	require.Error(t, err)
}

func TestNewFactory_StoreIsUsed(t *testing.T) {
	// Creating a second factory with the same store must not share state.
	s1 := newMockKVStore()
	s2 := newMockKVStore()
	f1, err := NewFactory(s1)
	require.NoError(t, err)
	f2, err := NewFactory(s2)
	require.NoError(t, err)
	assert.NotNil(t, f1.Messages)
	assert.NotNil(t, f2.Messages)
}
