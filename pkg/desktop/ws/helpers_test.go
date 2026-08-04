//go:build desktop

package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"

	dberrors "github.com/jeremyhahn/go-qrdb/pkg/errors"
	"github.com/jeremyhahn/go-qrdb/pkg/kvstore"

	"github.com/jeremyhahn/go-signal/pkg/daostore"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// ---------------------------------------------------------------------------
// In-memory index-aware KVStore for ws tests
// ---------------------------------------------------------------------------

type wsKVStore struct {
	mu          sync.RWMutex
	data        map[string][]byte
	regIndexes  map[string][]kvstore.EntityIndex
	singleIdx   map[string]map[string][]string
	compoundIdx map[string]map[string][]string
}

func newWSKVStore() kvstore.KVStore {
	return &wsKVStore{
		data:        make(map[string][]byte),
		regIndexes:  make(map[string][]kvstore.EntityIndex),
		singleIdx:   make(map[string]map[string][]string),
		compoundIdx: make(map[string]map[string][]string),
	}
}

func (s *wsKVStore) etFromKey(key string) string {
	if i := strings.Index(key, "/"); i >= 0 {
		return key[:i]
	}
	return ""
}

func (s *wsKVStore) addIdx(et, key string, value []byte) {
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
			s.compoundIdx[name][enc] = wsAppendUniq(s.compoundIdx[name][enc], key)
		} else if idx.JSONFieldName != "" {
			name := et + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[name] == nil {
					s.singleIdx[name] = make(map[string][]string)
				}
				s.singleIdx[name][fv] = wsAppendUniq(s.singleIdx[name][fv], key)
			}
		}
	}
}

func (s *wsKVStore) removeIdx(et, key string, value []byte) {
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
				s.compoundIdx[name][enc] = wsRemoveFrom(s.compoundIdx[name][enc], key)
			}
		} else if idx.JSONFieldName != "" {
			name := et + "." + idx.FieldName
			if v, ok := fields[idx.JSONFieldName]; ok {
				fv := fmt.Sprint(v)
				if s.singleIdx[name] != nil {
					s.singleIdx[name][fv] = wsRemoveFrom(s.singleIdx[name][fv], key)
				}
			}
		}
	}
}

func (s *wsKVStore) Put(_ context.Context, key string, value []byte) error {
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

func (s *wsKVStore) Get(_ context.Context, key string) ([]byte, error) {
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

func (s *wsKVStore) Delete(_ context.Context, key string) error {
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

func (s *wsKVStore) Scan(_ context.Context, prefix string, fn func(string, []byte) error) error {
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

func (s *wsKVStore) List(_ context.Context, prefix string) ([]string, error) {
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

func (s *wsKVStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.data[key]
	return ok, nil
}

func (s *wsKVStore) RegisterEntityIndexes(et string, idxs []kvstore.EntityIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.regIndexes[et] = idxs
	return nil
}

func (s *wsKVStore) QueryIndex(_ context.Context, indexName string, value []byte) ([][]byte, error) {
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

func (s *wsKVStore) ScanIndex(_ context.Context, _ string, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

func (s *wsKVStore) QueryCompoundIndex(_ context.Context, indexName string, values [][]byte) ([][]byte, error) {
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

func (s *wsKVStore) ScanCompoundIndex(_ context.Context, _ string, _ [][]byte, _, _ []byte) (map[string][][]byte, error) {
	return nil, nil
}

var _ kvstore.KVStore = (*wsKVStore)(nil)

func wsAppendUniq(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func wsRemoveFrom(slice []string, s string) []string {
	out := make([]string, 0, len(slice))
	for _, v := range slice {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

// newWSFactory creates a daostore.Factory backed by the in-memory KVStore.
func newWSFactory() (*daostore.Factory, error) {
	return daostore.NewFactory(newWSKVStore())
}

// ---------------------------------------------------------------------------
// Stub signal.Store for creating a signal.Client in tests
// ---------------------------------------------------------------------------

// stubSignalStore is a no-op implementation of signal.Store.
// GetCredentials returns nil so ConnectWebSocket fails fast,
// allowing Manager lifecycle tests to run without a real server.
type stubSignalStore struct{}

func (stubSignalStore) GetCredentials() (*signal.Credentials, error) { return nil, nil }
func (stubSignalStore) SaveCredentials(_ *signal.Credentials) error  { return nil }
func (stubSignalStore) GetContacts() ([]signal.Contact, error)       { return nil, nil }
func (stubSignalStore) SaveContact(_ *signal.Contact) error          { return nil }
func (stubSignalStore) DeleteContact(_ string) error                 { return nil }
func (stubSignalStore) GetMessages(_ string, _ int) ([]signal.Message, error) {
	return nil, nil
}
func (stubSignalStore) SaveMessage(_ *signal.Message) error { return nil }
func (stubSignalStore) GetGroups() ([]signal.Group, error)  { return nil, nil }
func (stubSignalStore) SaveGroup(_ *signal.Group) error     { return nil }
func (stubSignalStore) GetStickerPacks() ([]signal.InstalledStickerPack, error) {
	return nil, nil
}
func (stubSignalStore) SaveStickerPack(_ *signal.InstalledStickerPack) error {
	return nil
}
func (stubSignalStore) DeleteStickerPack(_ string) error { return nil }
func (stubSignalStore) Close() error                     { return nil }

var _ signal.Store = stubSignalStore{}

// newTestClient creates a signal.Client with the stub store so it can be
// used in Manager tests without needing a real server or filesystem.
func newTestClient() (*signal.Client, error) {
	cfg := signal.ClientConfig{
		ServerURL: "http://127.0.0.1:19999",
		DataDir:   "/tmp/go-signal-ws-test",
		UserAgent: "test/0.0",
		Store:     stubSignalStore{},
	}
	return signal.NewClient(cfg)
}

// ---------------------------------------------------------------------------
// Credential-aware store for WebSocket connection tests
// ---------------------------------------------------------------------------

// credentialStore is a stubSignalStore whose GetCredentials returns a preset
// *signal.Credentials. Used to make ConnectWebSocket proceed past the early
// "no credentials" guard.
type credentialStore struct {
	stubSignalStore
	creds *signal.Credentials
}

func (s *credentialStore) GetCredentials() (*signal.Credentials, error) {
	return s.creds, nil
}

var _ signal.Store = (*credentialStore)(nil)

// newTestClientWithCreds creates a signal.Client that has credentials and whose
// ServerURL points at the given server, allowing ConnectWebSocket to dial it.
func newTestClientWithCreds(t *testing.T, serverURL string, creds *signal.Credentials) (*signal.Client, error) {
	t.Helper()
	cfg := signal.ClientConfig{
		ServerURL: serverURL,
		DataDir:   t.TempDir(),
		UserAgent: "test/0.0",
		Store:     &credentialStore{creds: creds},
	}
	return signal.NewClient(cfg)
}
