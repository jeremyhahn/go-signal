//go:build desktop

package bindings

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// ---------------------------------------------------------------------------
// In-memory index-aware KVStore for bindings tests
// ---------------------------------------------------------------------------

type bindKVStore struct {
	mu          sync.RWMutex
	data        map[string][]byte
	regIndexes  map[string][]kvstore.EntityIndex
	singleIdx   map[string]map[string][]string
	compoundIdx map[string]map[string][]string
}

func newBindKVStore() kvstore.KVStore {
	return &bindKVStore{
		data:        make(map[string][]byte),
		regIndexes:  make(map[string][]kvstore.EntityIndex),
		singleIdx:   make(map[string]map[string][]string),
		compoundIdx: make(map[string]map[string][]string),
	}
}

func (s *bindKVStore) etFromKey(key string) string {
	if i := strings.Index(key, "/"); i >= 0 {
		return key[:i]
	}
	return ""
}

func (s *bindKVStore) addIdx(et, key string, value []byte) {
	idxs, ok := s.regIndexes[et]
	if !ok {
		return
	}
	var fields map[string]interface{}
	if json.Unmarshal(value, &fields) != nil {
		return
	}
	for _, idx := range idxs {
		if len(idx.FieldNames) > 0 {
			name := et + "." + strings.Join(idx.FieldNames, "_")
			vals := make([]string, len(idx.JSONFieldNames))
			for i, jn := range idx.JSONFieldNames {
				if v, ok := fields[jn]; ok {
					vals[i] = fmt.Sprint(v)
				}
			}
			enc := strings.Join(vals, "|")
			if s.compoundIdx[name] == nil {
				s.compoundIdx[name] = make(map[string][]string)
			}
			s.compoundIdx[name][enc] = bindAppendUniq(s.compoundIdx[name][enc], key)
		} else if idx.JSONFieldName != "" {
			name := et + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[name] == nil {
					s.singleIdx[name] = make(map[string][]string)
				}
				s.singleIdx[name][fv] = bindAppendUniq(s.singleIdx[name][fv], key)
			}
		}
	}
}

func (s *bindKVStore) removeIdx(et, key string, value []byte) {
	idxs, ok := s.regIndexes[et]
	if !ok {
		return
	}
	var fields map[string]interface{}
	if json.Unmarshal(value, &fields) != nil {
		return
	}
	for _, idx := range idxs {
		if len(idx.FieldNames) > 0 {
			name := et + "." + strings.Join(idx.FieldNames, "_")
			vals := make([]string, len(idx.JSONFieldNames))
			for i, jn := range idx.JSONFieldNames {
				if v, ok := fields[jn]; ok {
					vals[i] = fmt.Sprint(v)
				}
			}
			enc := strings.Join(vals, "|")
			if s.compoundIdx[name] != nil {
				s.compoundIdx[name][enc] = bindRemoveFrom(s.compoundIdx[name][enc], key)
			}
		} else if idx.JSONFieldName != "" {
			name := et + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[name] != nil {
					s.singleIdx[name][fv] = bindRemoveFrom(s.singleIdx[name][fv], key)
				}
			}
		}
	}
}

func (s *bindKVStore) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	et := s.etFromKey(key)
	if et != "" {
		if old, ok := s.data[key]; ok {
			s.removeIdx(et, key, old)
		}
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	s.data[key] = cp
	if et != "" {
		s.addIdx(et, key, cp)
	}
	return nil
}

func (s *bindKVStore) Get(_ context.Context, key string) ([]byte, error) {
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

func (s *bindKVStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.data[key]; ok {
		if et := s.etFromKey(key); et != "" {
			s.removeIdx(et, key, old)
		}
		delete(s.data, key)
	}
	return nil
}

func (s *bindKVStore) Scan(_ context.Context, prefix string, fn func(string, []byte) error) error {
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

func (s *bindKVStore) List(_ context.Context, prefix string) ([]string, error) {
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

func (s *bindKVStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key]
	return ok, nil
}

func (s *bindKVStore) RegisterEntityIndexes(et string, idxs []kvstore.EntityIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Registration accumulates, as kvstore.KVStore requires: pkg/dao registers
	// single-field and compound indexes in separate calls.
	for _, idx := range idxs {
		if !slices.ContainsFunc(s.regIndexes[et], func(r kvstore.EntityIndex) bool {
			return r.FieldName == idx.FieldName && slices.Equal(r.FieldNames, idx.FieldNames)
		}) {
			s.regIndexes[et] = append(s.regIndexes[et], idx)
		}
	}
	return nil
}

func (s *bindKVStore) QueryIndex(_ context.Context, indexName string, value []byte) ([][]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.singleIdx[indexName]
	if !ok {
		return nil, nil
	}
	keys := idx[string(value)]
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = []byte(k)
	}
	return result, nil
}

func (s *bindKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (s *bindKVStore) QueryCompoundIndex(_ context.Context, indexName string, values [][]byte) ([][]byte, error) {
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
	enc := strings.Join(parts, "|")
	keys := idx[enc]
	result := make([][]byte, len(keys))
	for i, k := range keys {
		result[i] = []byte(k)
	}
	return result, nil
}

func (s *bindKVStore) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*bindKVStore)(nil)

func bindAppendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func bindRemoveFrom(slice []string, s string) []string {
	out := make([]string, 0, len(slice))
	for _, v := range slice {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// newTestBindFactory creates a daostore.Factory backed by the in-memory KVStore.
func newTestBindFactory(t *testing.T) *daostore.Factory {
	t.Helper()
	f, err := daostore.NewFactory(newBindKVStore())
	require.NoError(t, err)
	return f
}

// ---------------------------------------------------------------------------
// Stub signal.Client components for bindings that need a client
// ---------------------------------------------------------------------------

// stubBindStore is a no-op signal.Store for creating a test Client.
type stubBindStore struct{}

func (stubBindStore) GetCredentials() (*signal.Credentials, error) { return nil, nil }
func (stubBindStore) SaveCredentials(_ *signal.Credentials) error  { return nil }
func (stubBindStore) GetContacts() ([]signal.Contact, error)       { return nil, nil }
func (stubBindStore) SaveContact(_ *signal.Contact) error          { return nil }
func (stubBindStore) DeleteContact(_ string) error                 { return nil }
func (stubBindStore) GetMessages(_ string, _ int) ([]signal.Message, error) {
	return nil, nil
}
func (stubBindStore) SaveMessage(_ *signal.Message) error { return nil }
func (stubBindStore) GetGroups() ([]signal.Group, error)  { return nil, nil }
func (stubBindStore) SaveGroup(_ *signal.Group) error     { return nil }
func (stubBindStore) GetStickerPacks() ([]signal.InstalledStickerPack, error) {
	return nil, nil
}
func (stubBindStore) SaveStickerPack(_ *signal.InstalledStickerPack) error { return nil }
func (stubBindStore) DeleteStickerPack(_ string) error                     { return nil }
func (stubBindStore) Close() error                                         { return nil }

var _ signal.Store = stubBindStore{}

// newBindClient creates a minimal signal.Client for bindings tests that
// need a client reference. The client will not be able to make network calls.
func newBindClient(t *testing.T) *signal.Client {
	t.Helper()
	cfg := signal.ClientConfig{
		ServerURL: "http://127.0.0.1:19998",
		DataDir:   "/tmp/go-signal-bind-test",
		UserAgent: "test/0.0",
		Store:     stubBindStore{},
	}
	c, err := signal.NewClient(cfg)
	require.NoError(t, err)
	return c
}

// newBindClientURL creates a signal.Client pointed at the given server URL.
// Used by tests that stand up an httptest.Server to exercise HTTP-delegating methods.
func newBindClientURL(t *testing.T, serverURL string) *signal.Client {
	t.Helper()
	cfg := signal.ClientConfig{
		ServerURL: serverURL,
		DataDir:   t.TempDir(),
		UserAgent: "test/0.0",
		Store:     stubBindStore{},
	}
	c, err := signal.NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// ---------------------------------------------------------------------------
// Stores that carry contacts / groups for client-side tests
// ---------------------------------------------------------------------------

// contactsBindStore is a stubBindStore whose GetContacts returns a canned list.
type contactsBindStore struct {
	stubBindStore
	contacts []signal.Contact
}

func (s *contactsBindStore) GetContacts() ([]signal.Contact, error) {
	return s.contacts, nil
}

// groupsClientStore is a stubBindStore whose GetGroups / SaveGroup are backed
// by an in-memory slice. Used to pre-populate groups in the SDK client store
// for UpdateGroup tests.
type groupsClientStore struct {
	stubBindStore
	groups []signal.Group
}

func (s *groupsClientStore) GetGroups() ([]signal.Group, error) {
	return s.groups, nil
}

func (s *groupsClientStore) SaveGroup(g *signal.Group) error {
	for i, gr := range s.groups {
		if gr.ID == g.ID {
			s.groups[i] = *g
			return nil
		}
	}
	s.groups = append(s.groups, *g)
	return nil
}

var _ signal.Store = (*contactsBindStore)(nil)
var _ signal.Store = (*groupsClientStore)(nil)

// newBindClientWithContacts creates a client whose store returns the provided contacts.
func newBindClientWithContacts(t *testing.T, contacts []signal.Contact) *signal.Client {
	t.Helper()
	store := &contactsBindStore{contacts: contacts}
	cfg := signal.ClientConfig{
		ServerURL: "http://127.0.0.1:19998",
		DataDir:   t.TempDir(),
		UserAgent: "test/0.0",
		Store:     store,
	}
	c, err := signal.NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// newBindClientWithGroups creates a client whose store returns the provided groups.
func newBindClientWithGroups(t *testing.T, groups []signal.Group) *signal.Client {
	t.Helper()
	store := &groupsClientStore{groups: groups}
	cfg := signal.ClientConfig{
		ServerURL: "http://127.0.0.1:19998",
		DataDir:   t.TempDir(),
		UserAgent: "test/0.0",
		Store:     store,
	}
	c, err := signal.NewClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}
