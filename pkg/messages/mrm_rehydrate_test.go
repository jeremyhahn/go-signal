package messages

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"

	"github.com/jeremyhahn/go-signal/pkg/cache"
)

func managerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// fakeMessageStore is a minimal MessageStore implementation backed by a
// per-device slice. Just enough surface for the rehydrate tests.
type fakeMessageStore struct {
	queues  map[string][]*Envelope // key = uuid|deviceID, value = envelopes in order
	deletes []string               // serverGUIDs of envelopes deleted on stale-MRM cleanup
}

func newFakeMessageStore() *fakeMessageStore {
	return &fakeMessageStore{queues: make(map[string][]*Envelope)}
}

func (f *fakeMessageStore) qkey(uuid string, dev uint64) string {
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[:8], dev)
	return uuid + "|" + string(buf[:8])
}

func (f *fakeMessageStore) Insert(_ context.Context, uuid string, dev uint64, env *Envelope) (uint64, error) {
	k := f.qkey(uuid, dev)
	f.queues[k] = append(f.queues[k], env)
	return uint64(len(f.queues[k])), nil
}

func (f *fakeMessageStore) GetMessagesForDevice(_ context.Context, uuid string, dev uint64) ([]*Envelope, error) {
	out := make([]*Envelope, len(f.queues[f.qkey(uuid, dev)]))
	copy(out, f.queues[f.qkey(uuid, dev)])
	return out, nil
}

func (f *fakeMessageStore) Delete(_ context.Context, _ string, serverGUID string) error {
	f.deletes = append(f.deletes, serverGUID)
	return nil
}

func (f *fakeMessageStore) DeleteForDevice(_ context.Context, _ string, _ uint64) error {
	return nil
}

func (f *fakeMessageStore) DeleteForAccount(_ context.Context, _ string) error { return nil }

func (f *fakeMessageStore) RemoveExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (f *fakeMessageStore) HasMessagesForDevice(_ context.Context, uuid string, dev uint64) (bool, error) {
	return len(f.queues[f.qkey(uuid, dev)]) > 0, nil
}

// fakeCache is a minimal cache.Client backed by maps for HSet/HGet/HDel/Eval
// used by MRMCache. Only the operations exercised by the rehydrate path are
// implemented.
type fakeCache struct {
	hashes map[string]map[string][]byte
}

func newFakeCache() *fakeCache {
	return &fakeCache{hashes: make(map[string]map[string][]byte)}
}

func (c *fakeCache) HSet(_ context.Context, key, field string, value []byte) error {
	if c.hashes[key] == nil {
		c.hashes[key] = make(map[string][]byte)
	}
	c.hashes[key][field] = value
	return nil
}

func (c *fakeCache) HGet(_ context.Context, key, field string) ([]byte, error) {
	h := c.hashes[key]
	if h == nil {
		return nil, cache.ErrKeyNotFound
	}
	v, ok := h[field]
	if !ok {
		return nil, cache.ErrKeyNotFound
	}
	return v, nil
}

// Stub remaining methods to satisfy cache.Client; they panic if called by a
// test, surfacing unexpected dependencies clearly.
func (c *fakeCache) Set(context.Context, string, []byte, time.Duration) error {
	panic("unused")
}

// We need more stubs; provide a small subset of cache.Client noop implementations.
// To avoid panics on unrelated method calls, return nil/zero values.
func (c *fakeCache) Get(context.Context, string) ([]byte, error)  { return nil, cache.ErrKeyNotFound }
func (c *fakeCache) Del(context.Context, ...string) error         { return nil }
func (c *fakeCache) Exists(context.Context, string) (bool, error) { return false, nil }
func (c *fakeCache) Expire(context.Context, string, time.Duration) (bool, error) {
	return false, nil
}
func (c *fakeCache) TTL(context.Context, string) (time.Duration, error)        { return 0, nil }
func (c *fakeCache) Incr(context.Context, string) (int64, error)               { return 0, nil }
func (c *fakeCache) IncrBy(context.Context, string, int64) (int64, error)      { return 0, nil }
func (c *fakeCache) Lock(context.Context, string, string, time.Duration) error { return nil }
func (c *fakeCache) Unlock(context.Context, string, string) error              { return nil }
func (c *fakeCache) ZAdd(context.Context, string, ...cache.ScoredMember) error { return nil }
func (c *fakeCache) ZRange(context.Context, string, int64, int64) ([][]byte, error) {
	return nil, nil
}
func (c *fakeCache) ZRem(context.Context, string, ...[]byte) error { return nil }
func (c *fakeCache) ZCard(context.Context, string) (int64, error)  { return 0, nil }
func (c *fakeCache) HDel(context.Context, string, ...string) error { return nil }
func (c *fakeCache) HLen(context.Context, string) (int64, error)   { return 0, nil }
func (c *fakeCache) Publish(context.Context, string, []byte) (int64, error) {
	return 0, nil
}
func (c *fakeCache) Subscribe(context.Context, ...string) (cache.Subscription, error) {
	return nil, errors.New("not implemented")
}
func (c *fakeCache) Eval(context.Context, string, []string, ...interface{}) (interface{}, error) {
	return nil, errors.New("not implemented")
}
func (c *fakeCache) Ping(context.Context) error { return nil }
func (c *fakeCache) Close() error               { return nil }

// buildSyntheticView builds a 13-byte serializedRecipientView header pointing
// at a synthetic full-message buffer where the shared bytes start at
// `sharedOffset` and the recipient's key material runs `keyMaterialLength`
// bytes from `keyMaterialOffset`. Used to construct fake MRM cache content
// without needing a real SealedSender v2 ciphertext.
func buildSyntheticView(sharedOffset, keyMaterialOffset, keyMaterialLength uint32) []byte {
	const versionByte = 0x01 // matches sealed.serializedRecipientViewVersion
	out := make([]byte, 13)
	out[0] = versionByte
	binary.BigEndian.PutUint32(out[1:5], sharedOffset)
	binary.BigEndian.PutUint32(out[5:9], keyMaterialOffset)
	binary.BigEndian.PutUint32(out[9:13], keyMaterialLength)
	return out
}

func TestGetMessagesForDevice_MRMRehydratesContent(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	mgr.SetMRMCache(NewMRMCache(newFakeCache(), managerTestLogger()))

	// Seed the cache with a synthetic full-message buffer and view header.
	// Layout of the buffer: [version 0x22][16 bytes recipient key][32 bytes shared].
	full := make([]byte, 1+16+32)
	full[0] = 0x22
	for i := 1; i < 17; i++ {
		full[i] = byte(i)
	}
	for i := 17; i < 49; i++ {
		full[i] = byte(0x80 + i)
	}
	view := buildSyntheticView(uint32(17), uint32(1), uint32(16))

	// Stash the data + view directly into the fake cache via the MRMCache.
	cache := mgr.loadMRMCache()
	if cache == nil {
		t.Fatal("MRM cache not configured")
		return
	}
	sharedKey := SharedMRMKey(uuid.New())
	if err := cache.client.HSet(context.Background(), sharedKey, mrmDataField, full); err != nil {
		t.Fatal(err)
	}
	viewKey := SharedMRMViewKey(protocol.NewACI([16]byte{1, 2}), 1)
	if err := cache.client.HSet(context.Background(), sharedKey, viewKey, view); err != nil {
		t.Fatal(err)
	}

	// Insert an envelope referencing the cache row.
	env := &Envelope{
		Type:                   EnvelopeTypeUnidentifiedSender,
		DestinationUUID:        "uuid-rh",
		DestinationDevice:      1,
		Timestamp:              123,
		SharedMrmKey:           []byte(sharedKey),
		SharedMrmRecipientView: []byte(viewKey),
		ServerGUID:             "guid-1",
	}
	if _, err := store.Insert(context.Background(), "uuid-rh", 1, env); err != nil {
		t.Fatal(err)
	}

	got, err := mgr.GetMessagesForDevice(context.Background(), "uuid-rh", 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("returned envelopes = %d, want 1", len(got))
	}
	out := got[0]
	if out.SharedMrmKey != nil || out.SharedMrmRecipientView != nil {
		t.Error("rehydrated envelope still has SharedMrm* fields")
	}
	// Reconstructed content layout: [0x22 version][16 bytes key material][32 bytes shared].
	wantContent := make([]byte, 0, 1+16+32)
	wantContent = append(wantContent, 0x22)
	wantContent = append(wantContent, full[1:17]...)
	wantContent = append(wantContent, full[17:]...)
	if string(out.Content) != string(wantContent) {
		t.Errorf("rehydrated content mismatch: got %x, want %x", out.Content, wantContent)
	}
}

func TestGetMessagesForDevice_MRMStaleDataDropsEnvelope(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	mgr.SetMRMCache(NewMRMCache(newFakeCache(), managerTestLogger()))

	// Insert an envelope whose SharedMrmKey points at nothing in the cache.
	env := &Envelope{
		DestinationUUID:        "uuid-stale",
		DestinationDevice:      1,
		SharedMrmKey:           []byte(SharedMRMKey(uuid.New())),
		SharedMrmRecipientView: []byte("any"),
		ServerGUID:             "stale-guid",
	}
	if _, err := store.Insert(context.Background(), "uuid-stale", 1, env); err != nil {
		t.Fatal(err)
	}

	got, err := mgr.GetMessagesForDevice(context.Background(), "uuid-stale", 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("stale MRM envelope should be dropped, got %d", len(got))
	}
	// Best-effort store delete should have run.
	if len(store.deletes) != 1 || store.deletes[0] != "stale-guid" {
		t.Errorf("expected delete of stale-guid, got %v", store.deletes)
	}
}

func TestGetMessagesForDevice_NoCache_PassesThrough(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store) // no SetMRMCache

	env := &Envelope{DestinationUUID: "u", DestinationDevice: 1}
	if _, err := store.Insert(context.Background(), "u", 1, env); err != nil {
		t.Fatal(err)
	}
	got, err := mgr.GetMessagesForDevice(context.Background(), "u", 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 1 || got[0] != env {
		t.Error("no-cache path should pass envelopes through unchanged")
	}
}

func TestSendMRMBinary_NoCache_ReturnsErr(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store) // no MRM cache

	_, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      []byte("anything"),
		Timestamp: 1,
		Lookup: func(_ context.Context, _ string) (*MRMRecipientAccount, error) {
			return nil, errors.New("nope")
		},
	})
	if !errors.Is(err, ErrMRMNoCache) {
		t.Errorf("expected ErrMRMNoCache, got %v", err)
	}
}

func TestSendMRMBinary_LookupRequired(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	mgr.SetMRMCache(NewMRMCache(newFakeCache(), managerTestLogger()))

	_, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      []byte("x"),
		Timestamp: 1,
		Lookup:    nil,
	})
	if err == nil {
		t.Error("expected error when Lookup is nil")
	}
}

func TestSendMRMBinary_BadCiphertextReturnsErr(t *testing.T) {
	store := newFakeMessageStore()
	mgr := NewMessagesManager(store)
	mgr.SetMRMCache(NewMRMCache(newFakeCache(), managerTestLogger()))

	_, err := mgr.SendMRMBinary(context.Background(), MRMSendRequest{
		Body:      []byte("definitely-not-ssv2"),
		Timestamp: 1,
		Lookup: func(_ context.Context, _ string) (*MRMRecipientAccount, error) {
			return nil, errors.New("not called")
		},
	})
	if err == nil {
		t.Error("expected parse error for bogus body")
	}
}

func TestParseServiceIDLabel_Variants(t *testing.T) {
	cases := []struct {
		in   string
		kind protocol.ServiceIdKind
	}{
		{"11111111-2222-3333-4444-555555555555", protocol.ServiceIdKindACI},
		{"ACI:11111111-2222-3333-4444-555555555555", protocol.ServiceIdKindACI},
		{"PNI:11111111-2222-3333-4444-555555555555", protocol.ServiceIdKindPNI},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			sid, err := parseServiceIDLabel(c.in)
			if err != nil {
				t.Fatalf("parseServiceIDLabel(%q): %v", c.in, err)
			}
			if sid.Kind() != c.kind {
				t.Errorf("kind = %v, want %v", sid.Kind(), c.kind)
			}
		})
	}
}
