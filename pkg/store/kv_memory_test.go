package store

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMemoryKVClient(t *testing.T) {
	kv := NewMemoryKVClient()
	require.NotNil(t, kv)
	require.NotNil(t, kv.data)
}

func TestNewMemoryKVClient_EmptyInitially(t *testing.T) {
	kv := NewMemoryKVClient()
	keys, err := kv.List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// --- Put tests ---

func TestPut_NewKey(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	err := kv.Put(ctx, "key1", []byte("value1"))
	require.NoError(t, err)

	got, err := kv.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("value1"), got)
}

func TestPut_OverwriteExisting(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "key1", []byte("v1")))
	require.NoError(t, kv.Put(ctx, "key1", []byte("v2")))

	got, err := kv.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
}

func TestPut_CopiesInput(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	input := []byte("original")
	require.NoError(t, kv.Put(ctx, "key1", input))

	// Mutate the input slice.
	input[0] = 'X'

	got, err := kv.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), got)
}

func TestPut_EmptyValue(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "empty", []byte{}))

	got, err := kv.Get(ctx, "empty")
	require.NoError(t, err)
	assert.Equal(t, []byte{}, got)
}

// --- Get tests ---

func TestGet_Existing(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("val")))

	got, err := kv.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("val"), got)
}

func TestGet_NotFound(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	_, err := kv.Get(ctx, "missing")
	require.Error(t, err)

	var target *KeyNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "missing", target.Key)
}

func TestGet_ReturnsDefensiveCopy(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("original")))

	got, err := kv.Get(ctx, "k")
	require.NoError(t, err)
	got[0] = 'X'

	got2, err := kv.Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("original"), got2)
}

// --- Delete tests ---

func TestDelete_Existing(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("val")))

	err := kv.Delete(ctx, "k")
	require.NoError(t, err)

	_, err = kv.Get(ctx, "k")
	var target *KeyNotFoundError
	require.True(t, errors.As(err, &target))
}

func TestDelete_NotFound(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	err := kv.Delete(ctx, "nonexistent")
	require.Error(t, err)

	var target *KeyNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.Key)
}

func TestDelete_DoesNotAffectOtherKeys(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k1", []byte("v1")))
	require.NoError(t, kv.Put(ctx, "k2", []byte("v2")))

	require.NoError(t, kv.Delete(ctx, "k1"))

	got, err := kv.Get(ctx, "k2")
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), got)
}

// --- List tests ---

func TestList_WithPrefix(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "prefix/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "prefix/b", []byte("2")))
	require.NoError(t, kv.Put(ctx, "other/c", []byte("3")))

	keys, err := kv.List(ctx, "prefix/")
	require.NoError(t, err)
	assert.Equal(t, []string{"prefix/a", "prefix/b"}, keys)
}

func TestList_EmptyPrefix(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "b", []byte("2")))

	keys, err := kv.List(ctx, "")
	require.NoError(t, err)
	sort.Strings(keys)
	assert.Equal(t, []string{"a", "b"}, keys)
}

func TestList_NoMatches(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "a", []byte("1")))

	keys, err := kv.List(ctx, "nonexistent/")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestList_ReturnsSorted(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "c", []byte("3")))
	require.NoError(t, kv.Put(ctx, "a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "b", []byte("2")))

	keys, err := kv.List(ctx, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, keys)
}

// --- Scan tests ---

func TestScan_AllPrefixed(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))
	require.NoError(t, kv.Put(ctx, "other/c", []byte("3")))

	var collected []string
	err := kv.Scan(ctx, "ns/", func(key string, value []byte) error {
		collected = append(collected, key+"="+string(value))
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"ns/a=1", "ns/b=2"}, collected)
}

func TestScan_StopsOnError(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "ns/a", []byte("1")))
	require.NoError(t, kv.Put(ctx, "ns/b", []byte("2")))

	scanErr := errors.New("stop scanning")
	count := 0
	err := kv.Scan(ctx, "ns/", func(key string, value []byte) error {
		count++
		return scanErr
	})
	require.ErrorIs(t, err, scanErr)
	assert.Equal(t, 1, count)
}

func TestScan_EmptyPrefix(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "x", []byte("1")))

	var keys []string
	err := kv.Scan(ctx, "", func(key string, value []byte) error {
		keys = append(keys, key)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"x"}, keys)
}

func TestScan_NoMatches(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "a", []byte("1")))

	called := false
	err := kv.Scan(ctx, "none/", func(key string, value []byte) error {
		called = true
		return nil
	})
	require.NoError(t, err)
	assert.False(t, called)
}

// --- Exists tests ---

func TestExists_KeyPresent(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("v")))

	exists, err := kv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestExists_KeyAbsent(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	exists, err := kv.Exists(ctx, "missing")
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestExists_AfterDelete(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()

	require.NoError(t, kv.Put(ctx, "k", []byte("v")))
	require.NoError(t, kv.Delete(ctx, "k"))

	exists, err := kv.Exists(ctx, "k")
	require.NoError(t, err)
	assert.False(t, exists)
}

// --- Concurrency tests ---

func TestConcurrentAccess(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()
	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := range goroutines {
		go func(id int) {
			defer wg.Done()
			key := "key-" + string(rune('A'+id%26))
			for range iterations {
				_ = kv.Put(ctx, key, []byte("val"))
				_, _ = kv.Get(ctx, key)
				_, _ = kv.List(ctx, "key-")
				_, _ = kv.Exists(ctx, key)
			}
		}(g)
	}

	wg.Wait()
}

func TestConcurrentPutDelete(t *testing.T) {
	kv := NewMemoryKVClient()
	ctx := context.Background()
	const goroutines = 20

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for g := range goroutines {
		key := "ckey-" + string(rune('A'+g%26))
		go func() {
			defer wg.Done()
			for range 50 {
				_ = kv.Put(ctx, key, []byte("v"))
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				_ = kv.Delete(ctx, key)
			}
		}()
	}

	wg.Wait()
}

// --- Error type tests ---

func TestKeyNotFoundError_Error(t *testing.T) {
	e := &KeyNotFoundError{Key: "test/key"}
	assert.Equal(t, "key not found: test/key", e.Error())
}

func TestKeyNotFoundError_ImplementsError(t *testing.T) {
	var _ error = &KeyNotFoundError{}
}

func TestKeyExistsError_Error(t *testing.T) {
	e := &KeyExistsError{Key: "test/key"}
	assert.Equal(t, "key already exists: test/key", e.Error())
}

func TestKeyExistsError_ImplementsError(t *testing.T) {
	var _ error = &KeyExistsError{}
}

func TestKeyNotFoundError_ErrorsAs(t *testing.T) {
	var err error = &KeyNotFoundError{Key: "k"}
	var target *KeyNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "k", target.Key)
}

func TestKeyExistsError_ErrorsAs(t *testing.T) {
	var err error = &KeyExistsError{Key: "k"}
	var target *KeyExistsError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "k", target.Key)
}
