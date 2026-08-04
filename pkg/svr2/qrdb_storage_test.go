package svr2

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubKV is an in-memory implementation of the qrdbKV interface for
// tests. Mirrors the qrdb in-memory client's semantics: missing keys
// return nil (not an error).
type stubKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newStubKV() *stubKV { return &stubKV{data: map[string][]byte{}} }

func (s *stubKV) Put(_ context.Context, key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	s.data[key] = cp
	return nil
}

func (s *stubKV) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return nil, nil
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

func (s *stubKV) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *stubKV) Scan(_ context.Context, prefix string, fn func(string, []byte) error) error {
	s.mu.Lock()
	keys := make([]string, 0, len(s.data))
	for k := range s.data {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	s.mu.Unlock()
	for _, k := range keys {
		if err := fn(k, s.data[k]); err != nil {
			return err
		}
	}
	return nil
}

func TestNewQrdbStorage_RequiresKV(t *testing.T) {
	if _, err := NewQrdbStorage(QrdbStorageConfig{}); err == nil {
		t.Error("expected error on missing KV")
	}
}

func TestQrdbStorage_PutGetRoundTrip(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: newStubKV()})
	ctx := context.Background()

	in := &Record{
		Version:               1,
		MaxTries:              5,
		TriesRemaining:        5,
		OPRFSecretShare:       []byte{1, 2, 3},
		AuthCommitment:        []byte{4, 5, 6},
		EncryptionSecretShare: []byte{7, 8, 9},
		ZeroSecretShare:       []byte{10, 11},
		CreatedAt:             time.Unix(1_700_000_000, 0).UTC(),
		UpdatedAt:             time.Unix(1_700_000_100, 0).UTC(),
	}
	if err := s.Put(ctx, "alice", in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	out, err := s.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.Version != in.Version || out.MaxTries != in.MaxTries ||
		out.TriesRemaining != in.TriesRemaining {
		t.Errorf("scalar fields drifted: %+v vs %+v", out, in)
	}
	if string(out.OPRFSecretShare) != string(in.OPRFSecretShare) {
		t.Errorf("OPRFSecretShare drift")
	}
	if !out.CreatedAt.Equal(in.CreatedAt) {
		t.Errorf("CreatedAt drift: %v vs %v", out.CreatedAt, in.CreatedAt)
	}
}

func TestQrdbStorage_GetMissing_ReturnsErrRecordNotFound(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: newStubKV()})
	_, err := s.Get(context.Background(), "missing")
	if !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("expected ErrRecordNotFound, got %v", err)
	}
}

func TestQrdbStorage_DeleteIsIdempotent(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: newStubKV()})
	ctx := context.Background()
	if err := s.Delete(ctx, "missing"); err != nil {
		t.Errorf("Delete on missing key: %v", err)
	}
	_ = s.Put(ctx, "bob", &Record{Version: 1})
	if err := s.Delete(ctx, "bob"); err != nil {
		t.Errorf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "bob"); !errors.Is(err, ErrRecordNotFound) {
		t.Errorf("post-Delete Get expected ErrRecordNotFound, got %v", err)
	}
}

func TestQrdbStorage_Count(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: newStubKV()})
	ctx := context.Background()
	if n, _ := s.Count(ctx); n != 0 {
		t.Errorf("initial count = %d", n)
	}
	_ = s.Put(ctx, "alice", &Record{Version: 1})
	_ = s.Put(ctx, "bob", &Record{Version: 1})
	_ = s.Put(ctx, "carol", &Record{Version: 1})
	if n, _ := s.Count(ctx); n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	_ = s.Delete(ctx, "bob")
	if n, _ := s.Count(ctx); n != 2 {
		t.Errorf("count after delete = %d, want 2", n)
	}
}

func TestQrdbStorage_PendingRotationRoundTrip(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: newStubKV()})
	in := &Record{
		Version:  1,
		MaxTries: 5,
		PendingRotation: &PendingRotation{
			NewVersion:                 2,
			OPRFSecretShareDelta:       []byte{0xAA, 0xBB},
			EncryptionSecretShareDelta: []byte{0xCC, 0xDD},
		},
	}
	_ = s.Put(context.Background(), "alice", in)
	out, _ := s.Get(context.Background(), "alice")
	if out.PendingRotation == nil {
		t.Fatal("PendingRotation lost")
	}
	if out.PendingRotation.NewVersion != 2 {
		t.Errorf("NewVersion = %d", out.PendingRotation.NewVersion)
	}
	if string(out.PendingRotation.OPRFSecretShareDelta) != string(in.PendingRotation.OPRFSecretShareDelta) {
		t.Error("OPRFSecretShareDelta drift")
	}
}

func TestQrdbStorage_KeyPrefixHonored(t *testing.T) {
	kv := newStubKV()
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: kv, KeyPrefix: "tenant-a:svr2:"})
	_ = s.Put(context.Background(), "alice", &Record{Version: 1})
	// Confirm the underlying KV used the right key.
	found := false
	for k := range kv.data {
		if strings.HasPrefix(k, "tenant-a:svr2:") {
			found = true
		}
	}
	if !found {
		t.Error("custom KeyPrefix not honored")
	}
}

// --------------------------------------------------------------------------
// errKV: always returns errors.
// --------------------------------------------------------------------------

type errKV struct{}

func (errKV) Put(_ context.Context, _ string, _ []byte) error {
	return errors.New("kv error")
}
func (errKV) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("kv error")
}
func (errKV) Delete(_ context.Context, _ string) error {
	return errors.New("kv error")
}
func (errKV) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return errors.New("kv error")
}

// --------------------------------------------------------------------------
// toQrdb / fromQrdb nil guards
// --------------------------------------------------------------------------

func TestToQrdb_NilInput_ReturnsNil(t *testing.T) {
	if toQrdb(nil) != nil {
		t.Error("expected nil from toQrdb(nil)")
	}
}

func TestFromQrdb_NilInput_ReturnsNil(t *testing.T) {
	if fromQrdb(nil) != nil {
		t.Error("expected nil from fromQrdb(nil)")
	}
}

// --------------------------------------------------------------------------
// QrdbStorage error paths via errKV
// --------------------------------------------------------------------------

func TestQrdbStorage_Get_KVError_WrapsError(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: errKV{}})
	_, err := s.Get(context.Background(), "alice")
	if err == nil {
		t.Error("expected error from failing KV.Get")
	}
}

func TestQrdbStorage_Get_InvalidJSON_ReturnsError(t *testing.T) {
	// A KV that returns non-nil bytes that are invalid JSON.
	kv := newStubKV()
	_ = kv.Put(context.Background(), "svr2:record:alice", []byte("not-valid-json"))
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: kv})
	_, err := s.Get(context.Background(), "alice")
	if err == nil {
		t.Error("expected unmarshal error for invalid JSON")
	}
}

func TestQrdbStorage_Put_KVError_WrapsError(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: errKV{}})
	err := s.Put(context.Background(), "alice", &Record{Version: 1})
	if err == nil {
		t.Error("expected error from failing KV.Put")
	}
}

func TestQrdbStorage_Delete_KVError_WrapsError(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: errKV{}})
	err := s.Delete(context.Background(), "alice")
	if err == nil {
		t.Error("expected error from failing KV.Delete")
	}
}

func TestQrdbStorage_Count_ScanError_WrapsError(t *testing.T) {
	s, _ := NewQrdbStorage(QrdbStorageConfig{KV: errKV{}})
	_, err := s.Count(context.Background())
	if err == nil {
		t.Error("expected error from failing KV.Scan")
	}
}

// --------------------------------------------------------------------------
// Record.Clone nil-receiver guard
// --------------------------------------------------------------------------

func TestRecord_Clone_NilReceiver_ReturnsNil(t *testing.T) {
	var r *Record
	if r.Clone() != nil {
		t.Error("expected nil from nil receiver Clone()")
	}
}
