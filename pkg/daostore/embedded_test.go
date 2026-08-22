package daostore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/engine"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"
	"github.com/jeremyhahn/go-qrdb/pkg/storage"
	"github.com/jeremyhahn/go-qrdb/pkg/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Custom storage stubs for dead-code branch coverage
// ---------------------------------------------------------------------------

// failIter is a storage.Iterator that reports a fixed error and yields no keys.
type failIter struct{ err error }

func (f *failIter) SeekToFirst() bool  { return false }
func (f *failIter) SeekToLast() bool   { return false }
func (f *failIter) Seek(_ []byte) bool { return false }
func (f *failIter) Next() bool         { return false }
func (f *failIter) Prev() bool         { return false }
func (f *failIter) Valid() bool        { return false }
func (f *failIter) Key() []byte        { return nil }
func (f *failIter) Value() []byte      { return nil }
func (f *failIter) Error() error       { return f.err }
func (f *failIter) Close() error       { return nil }

// outOfBoundsIter is a storage.Iterator that yields exactly one key which is
// outside any reasonable prefix.  It simulates a storage implementation that
// does not honour the UpperBound hint, exposing the defensive break in Scan.
type outOfBoundsIter struct {
	key  []byte
	done bool
}

func (o *outOfBoundsIter) SeekToFirst() bool  { o.done = false; return true }
func (o *outOfBoundsIter) SeekToLast() bool   { o.done = false; return true }
func (o *outOfBoundsIter) Seek(_ []byte) bool { o.done = false; return true }
func (o *outOfBoundsIter) Next() bool         { o.done = true; return false }
func (o *outOfBoundsIter) Prev() bool         { return false }
func (o *outOfBoundsIter) Valid() bool        { return !o.done }
func (o *outOfBoundsIter) Key() []byte        { return o.key }
func (o *outOfBoundsIter) Value() []byte      { return nil }
func (o *outOfBoundsIter) Error() error       { return nil }
func (o *outOfBoundsIter) Close() error       { return nil }

// outOfBoundsStorage wraps MemoryStorage but always hands out an outOfBoundsIter,
// simulating a backend that returns keys outside the requested prefix range.
type outOfBoundsStorage struct {
	*memory.MemoryStorage
	outsideKey []byte
}

func (s *outOfBoundsStorage) NewIterator(_ *storage.IteratorOptions) storage.Iterator {
	return &outOfBoundsIter{key: s.outsideKey}
}

// countingStorage wraps MemoryStorage and returns a failIter for every
// NewIterator call after the first n successful ones.  This lets the
// backfill during index registration succeed (call 1) while making the
// subsequent StoragePebbleIndex.Get call fail (call 2), covering the
// non-"not found" error path in QueryIndex.
type countingStorage struct {
	*memory.MemoryStorage
	n    int32
	cnt  atomic.Int32
	ferr error
}

func (s *countingStorage) NewIterator(opts *storage.IteratorOptions) storage.Iterator {
	if s.cnt.Add(1) > s.n {
		return &failIter{err: s.ferr}
	}
	return s.MemoryStorage.NewIterator(opts)
}

// Compile-time interface checks.
var _ storage.Iterator = (*failIter)(nil)
var _ storage.Iterator = (*outOfBoundsIter)(nil)
var _ storage.Storage = (*outOfBoundsStorage)(nil)
var _ storage.Storage = (*countingStorage)(nil)

// newTestAdapter returns an engineKVStoreAdapter backed by an in-memory
// storage backend.  All operations are fully in-process and do not touch disk.
func newTestAdapter(t *testing.T) *engineKVStoreAdapter {
	t.Helper()
	stg := memory.NewStorage()
	t.Cleanup(func() { _ = stg.Close() })
	eng := engine.NewKVEngine(stg)
	return &engineKVStoreAdapter{stg: stg, engine: eng}
}

// -- hasBytePrefix --

func TestHasBytePrefix_EmptyPrefixAlwaysTrue(t *testing.T) {
	assert.True(t, hasBytePrefix([]byte("anything"), []byte{}))
	assert.True(t, hasBytePrefix([]byte{}, []byte{}))
}

func TestHasBytePrefix_PrefixLongerThanB(t *testing.T) {
	assert.False(t, hasBytePrefix([]byte("ab"), []byte("abc")))
	assert.False(t, hasBytePrefix([]byte{}, []byte{0x01}))
}

func TestHasBytePrefix_ExactMatch(t *testing.T) {
	assert.True(t, hasBytePrefix([]byte("foo"), []byte("foo")))
}

func TestHasBytePrefix_PrefixMatch(t *testing.T) {
	assert.True(t, hasBytePrefix([]byte("foobar"), []byte("foo")))
}

func TestHasBytePrefix_MismatchAtFirstByte(t *testing.T) {
	assert.False(t, hasBytePrefix([]byte("bar"), []byte("foo")))
}

func TestHasBytePrefix_MismatchInMiddle(t *testing.T) {
	assert.False(t, hasBytePrefix([]byte("fox"), []byte("foo")))
}

// -- incrementPrefixBytes --

func TestIncrementPrefixBytes_Normal(t *testing.T) {
	got := incrementPrefixBytes([]byte("abc"))
	// 'c' == 0x63, incremented to 0x64 == 'd'
	assert.Equal(t, []byte("abd"), got)
}

func TestIncrementPrefixBytes_LastByteMaxFF(t *testing.T) {
	// [0x61, 0xff] → [0x62, 0x00]: 0xff rolls over and carries into 'a'→'b'
	got := incrementPrefixBytes([]byte{0x61, 0xff})
	assert.Equal(t, []byte{0x62, 0x00}, got)
}

func TestIncrementPrefixBytes_AllFF(t *testing.T) {
	// All 0xff: all bytes roll to 0x00 and a trailing 0x00 is appended.
	got := incrementPrefixBytes([]byte{0xff, 0xff})
	assert.Equal(t, []byte{0x00, 0x00, 0x00}, got)
}

func TestIncrementPrefixBytes_Empty(t *testing.T) {
	// Empty slice: loop does not run, append produces [0x00].
	got := incrementPrefixBytes([]byte{})
	assert.Equal(t, []byte{0x00}, got)
}

func TestIncrementPrefixBytes_SingleByte(t *testing.T) {
	got := incrementPrefixBytes([]byte{0x01})
	assert.Equal(t, []byte{0x02}, got)
}

func TestIncrementPrefixBytes_DoesNotMutateInput(t *testing.T) {
	in := []byte{0x41, 0x42}
	out := incrementPrefixBytes(in)
	assert.Equal(t, []byte{0x41, 0x42}, in, "input must not be mutated")
	assert.Equal(t, []byte{0x41, 0x43}, out)
}

// -- engineKVStoreAdapter: Put / Get --

func TestEngineKVStoreAdapter_PutGet_Roundtrip(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	require.NoError(t, a.Put(ctx, "messages/1", []byte(`{"id":1}`)))

	val, err := a.Get(ctx, "messages/1")
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"id":1}`), val)
}

func TestEngineKVStoreAdapter_Get_MissingKeyReturnsNil(t *testing.T) {
	a := newTestAdapter(t)
	val, err := a.Get(context.Background(), "messages/999")
	require.NoError(t, err)
	assert.Nil(t, val)
}

func TestEngineKVStoreAdapter_Put_Overwrite(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "k", []byte("v1")))
	require.NoError(t, a.Put(ctx, "k", []byte("v2")))
	val, err := a.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), val)
}

// -- engineKVStoreAdapter: Delete --

func TestEngineKVStoreAdapter_Delete_RemovesKey(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "messages/del", []byte("bye")))
	require.NoError(t, a.Delete(ctx, "messages/del"))

	val, err := a.Get(ctx, "messages/del")
	require.NoError(t, err)
	assert.Nil(t, val)
}

func TestEngineKVStoreAdapter_Delete_NonExistentKeyNoError(t *testing.T) {
	a := newTestAdapter(t)
	// Deleting a key that doesn't exist must not return an error.
	err := a.Delete(context.Background(), "messages/ghost")
	require.NoError(t, err)
}

// -- engineKVStoreAdapter: Scan --

func TestEngineKVStoreAdapter_Scan_WithPrefix(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "msgs/1", []byte("a")))
	require.NoError(t, a.Put(ctx, "msgs/2", []byte("b")))
	require.NoError(t, a.Put(ctx, "other/1", []byte("c")))

	visited := map[string]bool{}
	err := a.Scan(ctx, "msgs/", func(key string, _ []byte) error {
		visited[key] = true
		return nil
	})
	require.NoError(t, err)
	assert.Len(t, visited, 2)
	assert.True(t, visited["msgs/1"])
	assert.True(t, visited["msgs/2"])
}

func TestEngineKVStoreAdapter_Scan_EmptyPrefix(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "k1", []byte("v1")))
	require.NoError(t, a.Put(ctx, "k2", []byte("v2")))

	count := 0
	err := a.Scan(ctx, "", func(_ string, _ []byte) error {
		count++
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestEngineKVStoreAdapter_Scan_FnError(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "x/1", []byte("v")))

	fnErr := errors.New("stop")
	err := a.Scan(ctx, "x/", func(_ string, _ []byte) error { return fnErr })
	require.Error(t, err)
	assert.Equal(t, "stop", err.Error())
}

func TestEngineKVStoreAdapter_Scan_OutOfBoundsTriggerBreak(t *testing.T) {
	// outOfBoundsStorage returns a key that lies outside any prefix so that
	// the defensive break on line 66-67 of embedded.go is exercised.
	stg := &outOfBoundsStorage{
		MemoryStorage: memory.NewStorage(),
		outsideKey:    []byte("zzz/outside"),
	}
	t.Cleanup(func() { _ = stg.MemoryStorage.Close() })
	eng := engine.NewKVEngine(stg)
	a := &engineKVStoreAdapter{stg: stg, engine: eng}

	called := false
	err := a.Scan(context.Background(), "msgs/", func(_ string, _ []byte) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	// fn must not be called because the only key is outside the prefix.
	assert.False(t, called)
}

// -- engineKVStoreAdapter: List --

func TestEngineKVStoreAdapter_List_WithPrefix(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "p/a", []byte("1")))
	require.NoError(t, a.Put(ctx, "p/b", []byte("2")))
	require.NoError(t, a.Put(ctx, "q/a", []byte("3")))

	keys, err := a.List(ctx, "p/")
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestEngineKVStoreAdapter_List_Empty(t *testing.T) {
	a := newTestAdapter(t)
	keys, err := a.List(context.Background(), "nothing/")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// -- engineKVStoreAdapter: Exists --

func TestEngineKVStoreAdapter_Exists_True(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.Put(ctx, "ek", []byte("ev")))

	ok, err := a.Exists(ctx, "ek")
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestEngineKVStoreAdapter_Exists_False(t *testing.T) {
	a := newTestAdapter(t)
	ok, err := a.Exists(context.Background(), "nope")
	require.NoError(t, err)
	assert.False(t, ok)
}

// -- engineKVStoreAdapter: RegisterEntityIndexes --

func TestEngineKVStoreAdapter_RegisterEntityIndexes_Empty(t *testing.T) {
	a := newTestAdapter(t)
	err := a.RegisterEntityIndexes("messages", []kvstore.EntityIndex{})
	require.NoError(t, err)
}

func TestEngineKVStoreAdapter_RegisterEntityIndexes_WithIndexes(t *testing.T) {
	a := newTestAdapter(t)
	indexes := []kvstore.EntityIndex{
		{FieldName: "ConversationID", JSONFieldName: "conversationId"},
		{FieldName: "Timestamp", JSONFieldName: "timestamp"},
	}
	err := a.RegisterEntityIndexes("messages", indexes)
	require.NoError(t, err)
}

func TestEngineKVStoreAdapter_RegisterEntityIndexes_UniqueIndex(t *testing.T) {
	a := newTestAdapter(t)
	indexes := []kvstore.EntityIndex{
		{FieldName: "UUID", JSONFieldName: "uuid", Unique: true},
	}
	err := a.RegisterEntityIndexes("contacts", indexes)
	require.NoError(t, err)
}

func TestEngineKVStoreAdapter_RegisterEntityIndexes_CompoundIndex(t *testing.T) {
	a := newTestAdapter(t)
	indexes := []kvstore.EntityIndex{
		{
			FieldNames:     []string{"QueueType", "Status"},
			JSONFieldNames: []string{"queueType", "status"},
		},
	}
	err := a.RegisterEntityIndexes("jobs", indexes)
	require.NoError(t, err)
}

// -- engineKVStoreAdapter: QueryIndex --

func TestEngineKVStoreAdapter_QueryIndex_NonExistentReturnsNil(t *testing.T) {
	// Lookup on a non-existent index returns "not found" which is absorbed.
	a := newTestAdapter(t)
	keys, err := a.QueryIndex(context.Background(), "messages.NoSuchIndex", []byte("v"))
	require.NoError(t, err)
	assert.Nil(t, keys)
}

func TestEngineKVStoreAdapter_QueryIndex_AfterRegister(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()

	require.NoError(t, a.RegisterEntityIndexes("contacts", []kvstore.EntityIndex{
		{FieldName: "UUID", JSONFieldName: "uuid", Unique: true},
	}))

	// With no data inserted the result is nil/empty, but must not error.
	keys, err := a.QueryIndex(ctx, "contacts.UUID", []byte("some-uuid"))
	require.NoError(t, err)
	// May be nil or empty slice; neither is an error.
	_ = keys
}

func TestEngineKVStoreAdapter_QueryIndex_NonNotFoundError(t *testing.T) {
	// countingStorage lets the backfill iterator (call 1) succeed so that
	// RegisterEntityIndexes returns nil, then injects an I/O error on the
	// next iterator creation (call 2) inside StoragePebbleIndex.Get.
	// This exercises the "return nil, err" branch in QueryIndex (line 115)
	// that fires when the error from the engine does not contain "not found".
	stg := &countingStorage{
		MemoryStorage: memory.NewStorage(),
		n:             1,
		ferr:          errors.New("io: disk failure"),
	}
	t.Cleanup(func() { _ = stg.MemoryStorage.Close() })
	eng := engine.NewKVEngine(stg)
	a := &engineKVStoreAdapter{stg: stg, engine: eng}

	ctx := context.Background()
	require.NoError(t, a.RegisterEntityIndexes("contacts", []kvstore.EntityIndex{
		{FieldName: "UUID", JSONFieldName: "uuid"},
	}))

	_, err := a.QueryIndex(ctx, "contacts.UUID", []byte("some-uuid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk failure")
}

// -- engineKVStoreAdapter: ScanIndex --

func TestEngineKVStoreAdapter_ScanIndex_NonExistentReturnsError(t *testing.T) {
	// ScanIndex does not absorb "not found" — it returns the error directly.
	a := newTestAdapter(t)
	_, err := a.ScanIndex(context.Background(), "messages.NoSuchIndex", nil, nil)
	require.Error(t, err)
}

func TestEngineKVStoreAdapter_ScanIndex_RegisteredReturnsNilOrEmpty(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.RegisterEntityIndexes("contacts", []kvstore.EntityIndex{
		{FieldName: "UUID", JSONFieldName: "uuid", Unique: true},
	}))
	m, err := a.ScanIndex(ctx, "contacts.UUID", nil, nil)
	require.NoError(t, err)
	_ = m
}

// -- engineKVStoreAdapter: QueryCompoundIndex --

func TestEngineKVStoreAdapter_QueryCompoundIndex_NonExistentReturnsError(t *testing.T) {
	a := newTestAdapter(t)
	_, err := a.QueryCompoundIndex(context.Background(), "messages.NoSuchCompound", nil)
	require.Error(t, err)
}

func TestEngineKVStoreAdapter_QueryCompoundIndex_RegisteredReturnsNilOrEmpty(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.RegisterEntityIndexes("jobs", []kvstore.EntityIndex{
		{FieldNames: []string{"QueueType", "Status"}, JSONFieldNames: []string{"queueType", "status"}},
	}))
	keys, err := a.QueryCompoundIndex(ctx, "jobs.QueueType_Status", [][]byte{[]byte("send"), []byte("0")})
	require.NoError(t, err)
	_ = keys
}

// -- engineKVStoreAdapter: ScanCompoundIndex --

func TestEngineKVStoreAdapter_ScanCompoundIndex_NonExistentReturnsError(t *testing.T) {
	a := newTestAdapter(t)
	_, err := a.ScanCompoundIndex(context.Background(), "messages.NoSuchCompound", nil, nil, nil)
	require.Error(t, err)
}

func TestEngineKVStoreAdapter_ScanCompoundIndex_RegisteredReturnsResult(t *testing.T) {
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.RegisterEntityIndexes("jobs", []kvstore.EntityIndex{
		{FieldNames: []string{"QueueType", "Status"}, JSONFieldNames: []string{"queueType", "status"}},
	}))
	m, err := a.ScanCompoundIndex(ctx, "jobs.QueueType_Status", [][]byte{[]byte("send")}, nil, nil)
	require.NoError(t, err)
	_ = m
}

// -- engineKVStoreAdapter: Get error path --

func TestEngineKVStoreAdapter_Get_EmptyKeyReturnsNil(t *testing.T) {
	// An empty key causes the underlying storage to return ErrEmptyKey.
	// The adapter absorbs the error and returns nil, nil.
	a := newTestAdapter(t)
	val, err := a.Get(context.Background(), "")
	require.NoError(t, err)
	assert.Nil(t, val)
}

// -- engineKVStoreAdapter: ScanCompoundIndex success branch --

func TestEngineKVStoreAdapter_ScanCompoundIndex_WithNonNilRange(t *testing.T) {
	// With a non-nil rangeEnd the engine calls ScanCompound (not GetPrefix).
	// ScanCompound returns map[string][][]byte, so the type assertion succeeds
	// and the "return m, nil" branch (line 157) is covered.
	a := newTestAdapter(t)
	ctx := context.Background()
	require.NoError(t, a.RegisterEntityIndexes("jobs", []kvstore.EntityIndex{
		{FieldNames: []string{"QueueType", "Status"}, JSONFieldNames: []string{"queueType", "status"}},
	}))
	m, err := a.ScanCompoundIndex(ctx, "jobs.QueueType_Status", [][]byte{[]byte("send")}, nil, []byte("z"))
	require.NoError(t, err)
	_ = m
}

// -- NewEmbeddedKVStore --

func TestNewEmbeddedKVStore_Success(t *testing.T) {
	dir := t.TempDir()
	store, err := NewEmbeddedKVStore(dir)
	require.NoError(t, err)
	require.NotNil(t, store)
	t.Cleanup(func() { _ = store.(*engineKVStoreAdapter).Close() })
}

// TestEmbeddedKVStore_CloseReleasesTheDirectory pins the reason Close exists.
//
// PebbleDB holds an exclusive lock on its directory for as long as it is open,
// and nothing in the chain could release it: kvstore.KVStore does not declare
// Close, and the adapter is the only thing holding the storage handle. So a
// caller that shut down correctly still left the database open (#55). Reopening
// the same directory is the observable proof, and it fails with "lock held by
// current process" if Close stops closing.
func TestEmbeddedKVStore_CloseReleasesTheDirectory(t *testing.T) {
	dir := t.TempDir()

	store, err := NewEmbeddedKVStore(dir)
	require.NoError(t, err)
	require.NoError(t, store.(*engineKVStoreAdapter).Close())

	reopened, err := NewEmbeddedKVStore(dir)
	require.NoError(t, err, "the directory lock was not released")
	require.NoError(t, reopened.(*engineKVStoreAdapter).Close())
}

// A zero adapter has nothing to close, and saying so is cheaper than making
// every caller check.
func TestEmbeddedKVStore_CloseIsSafeWithoutStorage(t *testing.T) {
	require.NoError(t, (&engineKVStoreAdapter{}).Close())
}

func TestNewEmbeddedKVStore_InvalidPath(t *testing.T) {
	// /dev/null is a character device; creating a PebbleDB subdirectory there fails.
	_, err := NewEmbeddedKVStore("/dev/null/invalid")
	require.Error(t, err)
}

// -- engineKVStoreAdapter: interface compliance --

func TestEngineKVStoreAdapter_ImplementsKVStore(t *testing.T) {
	var _ kvstore.KVStore = (*engineKVStoreAdapter)(nil)
}
