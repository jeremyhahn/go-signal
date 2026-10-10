package daostore

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/consistency"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-qrdb/pkg/service"
	"github.com/jeremyhahn/go-qrdb/pkg/writemode"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockKVServicer is a minimal in-memory service.KVServicer used in adapter tests.
// Only Put, Get, Delete, List, and Scan are exercised by kvStoreAdapter; the
// remaining interface methods are stubs.
type mockKVServicer struct {
	data    map[string][]byte
	putErr  error
	getErr  error
	delErr  error
	listErr error
	scanErr error
	scanFn  func(prefix string) (map[string][]byte, error)
}

func newMockKVServicer() *mockKVServicer {
	return &mockKVServicer{data: make(map[string][]byte)}
}

func (m *mockKVServicer) Put(_ context.Context, key string, value []byte) error {
	if m.putErr != nil {
		return m.putErr
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return nil
}

// PutIfAbsent stores only when the key is absent, matching the real engines.
// The map lookup is the same check they perform; this mock is single-threaded,
// so it needs no further synchronisation. It reports stored=false with a nil
// error when the key already exists and leaves the store untouched.
func (m *mockKVServicer) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	if m.putErr != nil {
		return false, m.putErr
	}
	if _, exists := m.data[key]; exists {
		return false, nil
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.data[key] = cp
	return true, nil
}

func (m *mockKVServicer) Get(_ context.Context, key string) ([]byte, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	v, ok := m.data[key]
	if !ok {
		return nil, errors.New("key not found: " + key)
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (m *mockKVServicer) Delete(_ context.Context, key string) error {
	if m.delErr != nil {
		return m.delErr
	}
	delete(m.data, key)
	return nil
}

func (m *mockKVServicer) List(_ context.Context, _ string) ([]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockKVServicer) Scan(_ context.Context, prefix string) (map[string][]byte, error) {
	if m.scanFn != nil {
		return m.scanFn(prefix)
	}
	if m.scanErr != nil {
		return nil, m.scanErr
	}
	result := make(map[string][]byte)
	for k, v := range m.data {
		cp := make([]byte, len(v))
		copy(cp, v)
		result[k] = cp
	}
	return result, nil
}

// Unused interface stubs.
func (m *mockKVServicer) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	if v, ok := m.data[key]; !ok || !bytes.Equal(v, expected) {
		return false, nil
	}
	return true, m.Delete(context.Background(), key)
}
func (m *mockKVServicer) CompareAndSwap(_ context.Context, key string, expected, next []byte) (bool, error) {
	if v, ok := m.data[key]; !ok || !bytes.Equal(v, expected) {
		return false, nil
	}
	return true, m.Put(context.Background(), key, next)
}
func (m *mockKVServicer) ListAll(_ context.Context, prefix string) ([]string, error) {
	return m.List(context.Background(), prefix)
}
func (m *mockKVServicer) GetStale(_ context.Context, key string) ([]byte, error) {
	return m.Get(context.Background(), key)
}
func (m *mockKVServicer) ListStale(_ context.Context, prefix string) ([]string, error) {
	return m.List(context.Background(), prefix)
}
func (m *mockKVServicer) ScanStale(_ context.Context, prefix string) (map[string][]byte, error) {
	return m.Scan(context.Background(), prefix)
}
func (m *mockKVServicer) PutWithMode(_ context.Context, key string, value []byte, _ writemode.Mode) error {
	return m.Put(context.Background(), key, value)
}
func (m *mockKVServicer) DeleteWithMode(_ context.Context, key string, _ writemode.Mode) error {
	return m.Delete(context.Background(), key)
}
func (m *mockKVServicer) GetWithConsistency(_ context.Context, key string, _ consistency.ReadOptions) ([]byte, error) {
	return m.Get(context.Background(), key)
}
func (m *mockKVServicer) ListWithConsistency(_ context.Context, prefix string, _ consistency.ReadOptions) ([]string, error) {
	return m.List(context.Background(), prefix)
}
func (m *mockKVServicer) ScanWithConsistency(_ context.Context, prefix string, _ consistency.ReadOptions) (map[string][]byte, error) {
	return m.Scan(context.Background(), prefix)
}
func (m *mockKVServicer) ExistsWithConsistency(_ context.Context, key string, _ consistency.ReadOptions) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}
func (m *mockKVServicer) PutEntity(_ context.Context, _ *service.PutEntityRequest) (*service.PutEntityResponse, error) {
	return nil, nil
}
func (m *mockKVServicer) GetEntity(_ context.Context, _ *service.GetEntityRequest) (*service.GetEntityResponse, error) {
	return nil, nil
}
func (m *mockKVServicer) DeleteEntity(_ context.Context, _ *service.DeleteEntityRequest) (*service.DeleteEntityResponse, error) {
	return nil, nil
}
func (m *mockKVServicer) ListEntities(_ context.Context, _ *service.ListEntitiesRequest) (*service.ListEntitiesResponse, error) {
	return nil, nil
}

// Compile-time interface check.
var _ service.KVServicer = (*mockKVServicer)(nil)

// -- NewKVStoreAdapter --

func TestNewKVStoreAdapter_ReturnsKVStore(t *testing.T) {
	svc := newMockKVServicer()
	store := NewKVStoreAdapter(svc)
	require.NotNil(t, store)
	var _ kvstore.KVStore = store
}

func TestNewKVStoreAdapter_ImplementsInterface(t *testing.T) {
	var _ kvstore.KVStore = NewKVStoreAdapter(newMockKVServicer())
}

// -- Put --

func TestKVStoreAdapter_Put_Success(t *testing.T) {
	svc := newMockKVServicer()
	store := NewKVStoreAdapter(svc)
	ctx := context.Background()

	err := store.Put(ctx, "k1", []byte("value1"))
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), svc.data["k1"])
}

func TestKVStoreAdapter_Put_Error(t *testing.T) {
	svc := newMockKVServicer()
	svc.putErr = errors.New("put failed")
	store := NewKVStoreAdapter(svc)

	err := store.Put(context.Background(), "k", []byte("v"))
	require.Error(t, err)
	assert.Equal(t, "put failed", err.Error())
}

// -- Get --

func TestKVStoreAdapter_Get_HitReturnsValue(t *testing.T) {
	svc := newMockKVServicer()
	svc.data["mykey"] = []byte("myval")
	store := NewKVStoreAdapter(svc)

	v, err := store.Get(context.Background(), "mykey")
	require.NoError(t, err)
	assert.Equal(t, []byte("myval"), v)
}

func TestKVStoreAdapter_Get_NotFoundReturnsNil(t *testing.T) {
	// A "not found" error from the service must be converted to nil, nil.
	svc := newMockKVServicer()
	store := NewKVStoreAdapter(svc)

	v, err := store.Get(context.Background(), "missing")
	require.NoError(t, err)
	assert.Nil(t, v)
}

func TestKVStoreAdapter_Get_NonNotFoundError(t *testing.T) {
	// Errors not containing "not found" must be propagated.
	svc := newMockKVServicer()
	svc.getErr = errors.New("io error")
	store := NewKVStoreAdapter(svc)

	_, err := store.Get(context.Background(), "k")
	require.Error(t, err)
	assert.Equal(t, "io error", err.Error())
}

// -- Delete --

func TestKVStoreAdapter_Delete_Success(t *testing.T) {
	svc := newMockKVServicer()
	svc.data["dk"] = []byte("x")
	store := NewKVStoreAdapter(svc)

	err := store.Delete(context.Background(), "dk")
	require.NoError(t, err)
	assert.NotContains(t, svc.data, "dk")
}

func TestKVStoreAdapter_Delete_Error(t *testing.T) {
	svc := newMockKVServicer()
	svc.delErr = errors.New("del failed")
	store := NewKVStoreAdapter(svc)

	err := store.Delete(context.Background(), "k")
	require.Error(t, err)
	assert.Equal(t, "del failed", err.Error())
}

// -- Scan --

func TestKVStoreAdapter_Scan_CallsFn(t *testing.T) {
	svc := newMockKVServicer()
	svc.data["a"] = []byte("1")
	svc.data["b"] = []byte("2")
	store := NewKVStoreAdapter(svc)

	visited := map[string][]byte{}
	err := store.Scan(context.Background(), "", func(key string, value []byte) error {
		visited[key] = value
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, visited, 2)
}

func TestKVStoreAdapter_Scan_ServiceError(t *testing.T) {
	svc := newMockKVServicer()
	svc.scanErr = errors.New("scan error")
	store := NewKVStoreAdapter(svc)

	err := store.Scan(context.Background(), "", func(_ string, _ []byte) error { return nil })
	require.Error(t, err)
	assert.Equal(t, "scan error", err.Error())
}

func TestKVStoreAdapter_Scan_FnError(t *testing.T) {
	svc := newMockKVServicer()
	svc.data["x"] = []byte("v")
	store := NewKVStoreAdapter(svc)

	fnErr := errors.New("fn error")
	err := store.Scan(context.Background(), "", func(_ string, _ []byte) error { return fnErr })
	require.Error(t, err)
	assert.Equal(t, "fn error", err.Error())
}

// -- List --

func TestKVStoreAdapter_List_Success(t *testing.T) {
	svc := newMockKVServicer()
	svc.data["k1"] = []byte("v1")
	svc.data["k2"] = []byte("v2")
	store := NewKVStoreAdapter(svc)

	keys, err := store.List(context.Background(), "")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestKVStoreAdapter_List_Error(t *testing.T) {
	svc := newMockKVServicer()
	svc.listErr = errors.New("list error")
	store := NewKVStoreAdapter(svc)

	_, err := store.List(context.Background(), "")
	require.Error(t, err)
	assert.Equal(t, "list error", err.Error())
}

// -- Exists --

func TestKVStoreAdapter_Exists_True(t *testing.T) {
	svc := newMockKVServicer()
	svc.data["ek"] = []byte("ev")
	store := NewKVStoreAdapter(svc)

	ok, err := store.Exists(context.Background(), "ek")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestKVStoreAdapter_Exists_False(t *testing.T) {
	svc := newMockKVServicer()
	store := NewKVStoreAdapter(svc)

	ok, err := store.Exists(context.Background(), "nope")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestKVStoreAdapter_Exists_GetError(t *testing.T) {
	svc := newMockKVServicer()
	svc.getErr = errors.New("storage error")
	store := NewKVStoreAdapter(svc)

	_, err := store.Exists(context.Background(), "k")
	require.Error(t, err)
}

// -- Stub methods --

func TestKVStoreAdapter_RegisterEntityIndexes_NoOp(t *testing.T) {
	store := NewKVStoreAdapter(newMockKVServicer())
	err := store.RegisterEntityIndexes("messages", nil)
	require.NoError(t, err)
}

func TestKVStoreAdapter_QueryIndex_ReturnsNil(t *testing.T) {
	store := NewKVStoreAdapter(newMockKVServicer())
	keys, err := store.QueryIndex(context.Background(), "idx", []byte("v"))
	require.NoError(t, err)
	assert.Nil(t, keys)
}

func TestKVStoreAdapter_ScanIndex_ReturnsNil(t *testing.T) {
	store := NewKVStoreAdapter(newMockKVServicer())
	m, err := store.ScanIndex(context.Background(), "idx", nil, nil)
	require.NoError(t, err)
	assert.Nil(t, m)
}

func TestKVStoreAdapter_QueryCompoundIndex_ReturnsNil(t *testing.T) {
	store := NewKVStoreAdapter(newMockKVServicer())
	keys, err := store.QueryCompoundIndex(context.Background(), "cidx", nil)
	require.NoError(t, err)
	assert.Nil(t, keys)
}

func TestKVStoreAdapter_ScanCompoundIndex_ReturnsNil(t *testing.T) {
	store := NewKVStoreAdapter(newMockKVServicer())
	m, err := store.ScanCompoundIndex(context.Background(), "cidx", nil, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, m)
}
