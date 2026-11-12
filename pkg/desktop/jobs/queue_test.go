//go:build desktop

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"

	"github.com/jeremyhahn/go-signal/pkg/daostore/entities"
)

// ---------------------------------------------------------------------------
// In-memory KVStore with index support
// ---------------------------------------------------------------------------

type memKVStore struct {
	mu          sync.RWMutex
	data        map[string][]byte
	regIndexes  map[string][]kvstore.EntityIndex
	singleIdx   map[string]map[string][]string
	compoundIdx map[string]map[string][]string
}

func newMemKVStore() kvstore.KVStore {
	return &memKVStore{
		data:        make(map[string][]byte),
		regIndexes:  make(map[string][]kvstore.EntityIndex),
		singleIdx:   make(map[string]map[string][]string),
		compoundIdx: make(map[string]map[string][]string),
	}
}

func (s *memKVStore) entityTypeFromKey(key string) string {
	idx := strings.Index(key, "/")
	if idx < 0 {
		return ""
	}
	return key[:idx]
}

func (s *memKVStore) addToIndexes(entityType, key string, value []byte) {
	indexes, ok := s.regIndexes[entityType]
	if !ok {
		return
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(value, &fields); err != nil {
		return
	}
	for _, idx := range indexes {
		if len(idx.FieldNames) > 0 {
			idxName := entityType + "." + strings.Join(idx.FieldNames, "_")
			vals := make([]string, len(idx.JSONFieldNames))
			for i, jn := range idx.JSONFieldNames {
				if v, ok := fields[jn]; ok {
					vals[i] = fmt.Sprint(v)
				}
			}
			encoded := strings.Join(vals, "|")
			if s.compoundIdx[idxName] == nil {
				s.compoundIdx[idxName] = make(map[string][]string)
			}
			s.compoundIdx[idxName][encoded] = appendUnique(s.compoundIdx[idxName][encoded], key)
		} else if idx.JSONFieldName != "" {
			idxName := entityType + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[idxName] == nil {
					s.singleIdx[idxName] = make(map[string][]string)
				}
				s.singleIdx[idxName][fv] = appendUnique(s.singleIdx[idxName][fv], key)
			}
		}
	}
}

func (s *memKVStore) removeFromIndexes(entityType, key string, value []byte) {
	indexes, ok := s.regIndexes[entityType]
	if !ok {
		return
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(value, &fields); err != nil {
		return
	}
	for _, idx := range indexes {
		if len(idx.FieldNames) > 0 {
			idxName := entityType + "." + strings.Join(idx.FieldNames, "_")
			vals := make([]string, len(idx.JSONFieldNames))
			for i, jn := range idx.JSONFieldNames {
				if v, ok := fields[jn]; ok {
					vals[i] = fmt.Sprint(v)
				}
			}
			encoded := strings.Join(vals, "|")
			if s.compoundIdx[idxName] != nil {
				s.compoundIdx[idxName][encoded] = removeFromSlice(s.compoundIdx[idxName][encoded], key)
			}
		} else if idx.JSONFieldName != "" {
			idxName := entityType + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[idxName] != nil {
					s.singleIdx[idxName][fv] = removeFromSlice(s.singleIdx[idxName][fv], key)
				}
			}
		}
	}
}

func (s *memKVStore) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	et := s.entityTypeFromKey(key)
	if et != "" {
		if old, exists := s.data[key]; exists {
			s.removeFromIndexes(et, key, old)
		}
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.data[key] = cp
	if et != "" {
		s.addToIndexes(et, key, cp)
	}
	return nil
}

func (s *memKVStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.data[key]
	if !ok {
		return nil, &dberrors.QRDBError{Code: dberrors.ErrNotFound, Op: "kv.get"}
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (s *memKVStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, exists := s.data[key]; exists {
		et := s.entityTypeFromKey(key)
		if et != "" {
			s.removeFromIndexes(et, key, old)
		}
		delete(s.data, key)
	}
	return nil
}

func (s *memKVStore) Scan(_ context.Context, prefix string, fn func(key string, value []byte) error) error {
	s.mu.RLock()
	var keys []string
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	vals := make(map[string][]byte, len(keys))
	for _, k := range keys {
		v := s.data[k]
		cp := make([]byte, len(v))
		copy(cp, v)
		vals[k] = cp
	}
	s.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		if err := fn(k, vals[k]); err != nil {
			return err
		}
	}
	return nil
}

func (s *memKVStore) List(_ context.Context, prefix string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var keys []string
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (s *memKVStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key]
	return ok, nil
}

func (s *memKVStore) RegisterEntityIndexes(entityType string, indexes []kvstore.EntityIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Registration accumulates, as kvstore.KVStore requires: pkg/dao registers
	// single-field and compound indexes in separate calls.
	for _, idx := range indexes {
		if !slices.ContainsFunc(s.regIndexes[entityType], func(r kvstore.EntityIndex) bool {
			return r.FieldName == idx.FieldName && slices.Equal(r.FieldNames, idx.FieldNames)
		}) {
			s.regIndexes[entityType] = append(s.regIndexes[entityType], idx)
		}
	}
	return nil
}

func (s *memKVStore) QueryIndex(_ context.Context, indexName string, value []byte) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.singleIdx[indexName]
	if !ok {
		return nil, nil
	}
	keys, ok := idx[string(value)]
	if !ok {
		return nil, nil
	}
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = []byte(k)
	}
	return result, nil
}

func (s *memKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (s *memKVStore) QueryCompoundIndex(_ context.Context, indexName string, values [][]byte) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.compoundIdx[indexName]
	if !ok {
		return nil, nil
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = string(v)
	}
	encoded := strings.Join(parts, "|")
	keys, ok := idx[encoded]
	if !ok {
		return nil, nil
	}
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = []byte(k)
	}
	return result, nil
}

func (s *memKVStore) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*memKVStore)(nil)

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func removeFromSlice(slice []string, s string) []string {
	result := make([]string, 0, len(slice))
	for _, v := range slice {
		if v != s {
			result = append(result, v)
		}
	}
	return result
}

// newJobDAO creates a real GenericDAO backed by the in-memory KVStore.
func newJobDAO(t *testing.T) dao.GenericDAO[*entities.JobEntity] {
	t.Helper()
	store := newMemKVStore()
	d, err := dao.New(store, "jobs", func() *entities.JobEntity { return &entities.JobEntity{} })
	require.NoError(t, err)
	return d
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestNewQueue verifies Queue construction.
func TestNewQueue(t *testing.T) {
	t.Run("NotNil", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		require.NotNil(t, q)
	})
	t.Run("HandlersInitialized", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		require.NotNil(t, q.handlers)
	})
}

// TestQueue_Register verifies handler registration.
func TestQueue_Register(t *testing.T) {
	t.Run("RegisterSingleHandler", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		q.Register("send_message", func(_ context.Context, _ json.RawMessage) error { return nil })
		q.mu.RLock()
		_, ok := q.handlers["send_message"]
		q.mu.RUnlock()
		assert.True(t, ok)
	})
	t.Run("RegisterMultipleHandlers", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		q.Register("type_a", func(_ context.Context, _ json.RawMessage) error { return nil })
		q.Register("type_b", func(_ context.Context, _ json.RawMessage) error { return nil })
		q.mu.RLock()
		_, okA := q.handlers["type_a"]
		_, okB := q.handlers["type_b"]
		q.mu.RUnlock()
		assert.True(t, okA)
		assert.True(t, okB)
	})
	t.Run("OverwriteHandler", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		called := 0
		q.Register("x", func(_ context.Context, _ json.RawMessage) error { called++; return nil })
		q.Register("x", func(_ context.Context, _ json.RawMessage) error { called += 10; return nil })
		// call the registered handler
		q.mu.RLock()
		h := q.handlers["x"]
		q.mu.RUnlock()
		_ = h(context.Background(), nil)
		assert.Equal(t, 10, called)
	})
}

// TestQueue_Enqueue verifies job persistence.
func TestQueue_Enqueue(t *testing.T) {
	t.Run("EnqueueSerializableData", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		err := q.Enqueue(context.Background(), "send_message", map[string]string{"to": "alice"})
		require.NoError(t, err)
	})
	t.Run("EnqueueMultipleJobs", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		require.NoError(t, q.Enqueue(context.Background(), "job_a", "payload1"))
		require.NoError(t, q.Enqueue(context.Background(), "job_b", 42))
	})
	t.Run("UnmarshalableDataReturnsError", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		// Channels cannot be marshalled to JSON.
		err := q.Enqueue(context.Background(), "bad", make(chan int))
		require.Error(t, err)
	})
}

// TestQueue_StartStop verifies the lifecycle.
func TestQueue_StartStop(t *testing.T) {
	t.Run("StartAndStopWithoutPanic", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		ctx := context.Background()
		assert.NotPanics(t, func() {
			q.Start(ctx)
			q.Stop()
		})
	})
	t.Run("StopBeforeStartIsNoop", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		assert.NotPanics(t, q.Stop)
	})
	t.Run("DoubleStopIsNoop", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		q.Start(context.Background())
		q.Stop()
		assert.NotPanics(t, q.Stop)
	})
}

// TestQueue_ProcessPending verifies job execution via internal method.
func TestQueue_ProcessPending(t *testing.T) {
	t.Run("ExecutesPendingJob", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		var called bool
		q.Register("test_job", func(_ context.Context, data json.RawMessage) error {
			called = true
			return nil
		})
		require.NoError(t, q.Enqueue(context.Background(), "test_job", "payload"))

		// Start/stop the queue with a very short poll interval to trigger processing.
		q.pollInterval = 10 * time.Millisecond
		q.Start(context.Background())
		time.Sleep(50 * time.Millisecond)
		q.Stop()

		assert.True(t, called, "handler should have been called by processPending")
	})

	t.Run("RetriesFailingJob", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		attempts := 0
		q.Register("fail_job", func(_ context.Context, _ json.RawMessage) error {
			attempts++
			return errors.New("transient error")
		})
		require.NoError(t, q.Enqueue(context.Background(), "fail_job", nil))

		q.pollInterval = 10 * time.Millisecond
		q.Start(context.Background())
		time.Sleep(50 * time.Millisecond)
		q.Stop()

		// At least one attempt should have been made.
		assert.GreaterOrEqual(t, attempts, 1)
	})

	t.Run("SkipsJobWithNoHandler", func(t *testing.T) {
		q := NewQueue(newJobDAO(t))
		// No handler registered for "unknown_type".
		require.NoError(t, q.Enqueue(context.Background(), "unknown_type", "data"))
		// processPending should silently skip it.
		q.mu.Lock()
		q.ctx, q.cancel = context.WithCancel(context.Background())
		q.mu.Unlock()
		assert.NotPanics(t, q.processPending)
	})
}
