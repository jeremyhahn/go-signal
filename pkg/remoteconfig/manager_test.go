package remoteconfig

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// canonical UUIDs used across tests. The exact bucket each lands in
// depends on the SHA-256 hash chain — we don't pre-compute the values,
// just sweep across config Percentages and assert determinism.
const (
	uuidA = "11111111-1111-4111-8111-111111111111"
	uuidB = "22222222-2222-4222-8222-222222222222"
	uuidC = "33333333-3333-4333-8333-333333333333"
)

func mustManager(t *testing.T, configs ...Config) *Manager {
	t.Helper()
	store := NewMemoryStore()
	ctx := context.Background()
	for _, c := range configs {
		if err := store.Put(ctx, c); err != nil {
			t.Fatalf("Put %s: %v", c.Name, err)
		}
	}
	mgr, err := NewManager(ctx, ManagerConfig{Store: store, RefreshInterval: time.Hour})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Stop)
	return mgr
}

func TestFirstSegment(t *testing.T) {
	if got := FirstSegment("ios.foo.bar"); got != "ios" {
		t.Errorf("got %q", got)
	}
	if got := FirstSegment("nodot"); got != "nodot" {
		t.Errorf("got %q", got)
	}
}

func TestIsPlatformPrefix(t *testing.T) {
	for _, p := range []string{"ios", "android", "desktop", "IOS"} {
		if !IsPlatformPrefix(p) {
			t.Errorf("expected %q to be a platform prefix", p)
		}
	}
	if IsPlatformPrefix("global") {
		t.Error("global must not be a platform prefix")
	}
}

func TestPlatformFromUserAgent(t *testing.T) {
	cases := []struct {
		ua, want string
	}{
		{"Signal-iOS/7.1 iOS/17.0", "ios"},
		{"Signal-Android/7.1.0 (Android)", "android"},
		{"Signal-Desktop/7.5.0 macOS", "desktop"},
		{"curl/7.88.1", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := PlatformFromUserAgent(c.ua); got != c.want {
			t.Errorf("PlatformFromUserAgent(%q) = %q, want %q", c.ua, got, c.want)
		}
	}
}

func TestMemoryStore_PutGetDelete(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	if err := s.Put(ctx, Config{Name: "global.foo", Percentage: 100}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	all, err := s.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	if len(all) != 1 || all[0].Name != "global.foo" {
		t.Errorf("GetAll: got %+v", all)
	}
	if err := s.Delete(ctx, "global.foo"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if all, _ := s.GetAll(ctx); len(all) != 0 {
		t.Error("expected empty after Delete")
	}
}

func TestMemoryStore_PutValidation(t *testing.T) {
	s := NewMemoryStore()
	cases := []Config{
		{Name: "", Percentage: 50},
		{Name: "x", Percentage: -1},
		{Name: "x", Percentage: 101},
	}
	for _, c := range cases {
		err := s.Put(context.Background(), c)
		var inv *InvalidConfigError
		if !errors.As(err, &inv) {
			t.Errorf("expected *InvalidConfigError for %+v, got %v", c, err)
		}
	}
}

func TestMemoryStore_GetAllSorted(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	_ = s.Put(ctx, Config{Name: "c", Percentage: 50})
	_ = s.Put(ctx, Config{Name: "a", Percentage: 50})
	_ = s.Put(ctx, Config{Name: "b", Percentage: 50})
	all, _ := s.GetAll(ctx)
	if all[0].Name != "a" || all[1].Name != "b" || all[2].Name != "c" {
		t.Errorf("unsorted: %+v", all)
	}
}

func TestMemoryStore_PutRoundTripsUUIDs(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	uuids := map[string]struct{}{uuidA: {}, uuidB: {}}
	_ = s.Put(ctx, Config{Name: "x", Percentage: 0, UUIDs: uuids})
	// Mutate the input map after Put — the stored copy must NOT change.
	uuids[uuidC] = struct{}{}
	all, _ := s.GetAll(ctx)
	if _, ok := all[0].UUIDs[uuidC]; ok {
		t.Error("MemoryStore.Put must deep-copy UUIDs")
	}
}

func TestNewManager_RequiresStore(t *testing.T) {
	if _, err := NewManager(context.Background(), ManagerConfig{}); err == nil {
		t.Fatal("expected error without store")
	}
}

func TestManager_Evaluate_PlatformFiltering(t *testing.T) {
	mgr := mustManager(t,
		Config{Name: "global.foo", Percentage: 100, Value: "ON"},
		Config{Name: "ios.bar", Percentage: 100, Value: "ON"},
		Config{Name: "android.baz", Percentage: 100, Value: "ON"},
	)
	iOS := mgr.Evaluate(uuidA, "Signal-iOS/7.1 iOS/17.0")
	if iOS["global.foo"] != "ON" || iOS["ios.bar"] != "ON" {
		t.Errorf("iOS should see global+ios; got %+v", iOS)
	}
	if _, ok := iOS["android.baz"]; ok {
		t.Errorf("iOS must not see android.baz: %+v", iOS)
	}
	android := mgr.Evaluate(uuidA, "Signal-Android/7.1.0")
	if _, ok := android["ios.bar"]; ok {
		t.Errorf("Android must not see ios.bar: %+v", android)
	}
}

func TestManager_Evaluate_UnrecognizedUAGetsNeutralOnly(t *testing.T) {
	mgr := mustManager(t,
		Config{Name: "global.foo", Percentage: 100, Value: "ON"},
		Config{Name: "ios.bar", Percentage: 100, Value: "ON"},
	)
	got := mgr.Evaluate(uuidA, "curl/8.0")
	if got["global.foo"] != "ON" {
		t.Errorf("global must be delivered to unrecognized UA")
	}
	if _, ok := got["ios.bar"]; ok {
		t.Errorf("platform-scoped configs must NOT ship to unrecognized UA: %+v", got)
	}
}

func TestManager_Evaluate_FullBucketReturnsValue(t *testing.T) {
	mgr := mustManager(t, Config{Name: "global.full", Percentage: 100, Value: "ON", DefaultValue: "OFF"})
	got := mgr.Evaluate(uuidA, "Signal-iOS/7.1")
	if got["global.full"] != "ON" {
		t.Errorf("100%% bucket must return Value: %+v", got)
	}
}

func TestManager_Evaluate_ZeroBucketReturnsDefault(t *testing.T) {
	mgr := mustManager(t, Config{Name: "global.empty", Percentage: 0, Value: "ON", DefaultValue: "OFF"})
	got := mgr.Evaluate(uuidA, "Signal-iOS/7.1")
	if got["global.empty"] != "OFF" {
		t.Errorf("0%% bucket must return DefaultValue: %+v", got)
	}
}

func TestManager_Evaluate_AllowlistOverridesBucket(t *testing.T) {
	mgr := mustManager(t, Config{
		Name: "global.allow", Percentage: 0,
		UUIDs: map[string]struct{}{uuidA: {}},
		Value: "ON", DefaultValue: "OFF",
	})
	got := mgr.Evaluate(uuidA, "Signal-iOS/7.1")
	if got["global.allow"] != "ON" {
		t.Errorf("explicit UUID allowlist must override Percentage=0: %+v", got)
	}
	if mgr.Evaluate(uuidB, "Signal-iOS/7.1")["global.allow"] != "OFF" {
		t.Error("non-allowlisted uuid must still get default")
	}
}

func TestManager_Evaluate_MissingValueFallsBackToBool(t *testing.T) {
	mgr := mustManager(t, Config{Name: "global.bool", Percentage: 100})
	got := mgr.Evaluate(uuidA, "Signal-iOS/7.1")
	if got["global.bool"] != "true" {
		t.Errorf("missing Value should yield \"true\": %+v", got)
	}
	mgr2 := mustManager(t, Config{Name: "global.bool", Percentage: 0})
	got2 := mgr2.Evaluate(uuidA, "Signal-iOS/7.1")
	if got2["global.bool"] != "false" {
		t.Errorf("missing DefaultValue should yield \"false\": %+v", got2)
	}
}

func TestManager_Evaluate_DeterministicAcrossCalls(t *testing.T) {
	// The same (uuid, configs) must produce byte-identical output so
	// REST handlers can compute a stable ETag.
	mgr := mustManager(t,
		Config{Name: "global.a", Percentage: 50, Value: "ON"},
		Config{Name: "global.b", Percentage: 75, Value: "ON"},
		Config{Name: "global.c", Percentage: 1, Value: "ON"},
	)
	first := mgr.Evaluate(uuidA, "")
	second := mgr.Evaluate(uuidA, "")
	if len(first) != len(second) {
		t.Fatalf("len mismatch")
	}
	for k, v := range first {
		if second[k] != v {
			t.Errorf("non-deterministic: key=%s first=%q second=%q", k, v, second[k])
		}
	}
}

func TestManager_Evaluate_HashKeyShiftsBucket(t *testing.T) {
	// Two configs with identical Name + Percentage but different
	// HashKeys must (with high probability) deliver different verdicts
	// to at least one of a small UUID sample. The chance of both
	// HashKeys producing the same bucket for every sampled UUID at
	// Percentage=50 is (1/2)^N — for N=8 that's 1/256, low enough that
	// a green test gives high confidence the HashKey actually shifted
	// the bucketing.
	configA := Config{Name: "global.x", Percentage: 50, HashKey: "alpha", Value: "ON"}
	configB := Config{Name: "global.x", Percentage: 50, HashKey: "beta", Value: "ON"}
	uuids := []string{
		"11111111-1111-4111-8111-111111111111",
		"22222222-2222-4222-8222-222222222222",
		"33333333-3333-4333-8333-333333333333",
		"44444444-4444-4444-8444-444444444444",
		"55555555-5555-4555-8555-555555555555",
		"66666666-6666-4666-8666-666666666666",
		"77777777-7777-4777-8777-777777777777",
		"88888888-8888-4888-8888-888888888888",
	}
	anyDifferent := false
	for _, u := range uuids {
		if evaluate(configA, u) != evaluate(configB, u) {
			anyDifferent = true
			break
		}
	}
	if !anyDifferent {
		t.Error("HashKey override produced identical bucketing for 8 UUIDs (cryptographically unlikely)")
	}
}

func TestManager_Evaluate_MalformedUUIDFallsBackToBucket50(t *testing.T) {
	// Both 50%-percentage and 49%-percentage tests pin the behavior of
	// the documented fall-back path: bucket=50 means a 50% config
	// returns DefaultValue (because the bucket is NOT < Percentage),
	// while a 51% config returns Value.
	mgr := mustManager(t,
		Config{Name: "global.fifty", Percentage: 50, Value: "ON", DefaultValue: "OFF"},
		Config{Name: "global.fiftyone", Percentage: 51, Value: "ON", DefaultValue: "OFF"},
	)
	got := mgr.Evaluate("not-a-uuid", "")
	if got["global.fifty"] != "OFF" {
		t.Errorf("bucket=50 should not be in <50%% (got %q)", got["global.fifty"])
	}
	if got["global.fiftyone"] != "ON" {
		t.Errorf("bucket=50 should be in <51%% (got %q)", got["global.fiftyone"])
	}
}

func TestManager_RefreshLoopPicksUpNewConfigs(t *testing.T) {
	// Manager starts with an empty store, then a config is added.
	// Without manual refresh, Evaluate must continue returning the
	// initial empty map. After a manual refresh() the new config
	// should appear. We bypass the ticker for determinism.
	store := NewMemoryStore()
	ctx := context.Background()
	mgr, err := NewManager(ctx, ManagerConfig{Store: store, RefreshInterval: time.Hour})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Stop)
	if got := mgr.Evaluate(uuidA, ""); len(got) != 0 {
		t.Fatalf("expected empty: got %+v", got)
	}
	if err := store.Put(ctx, Config{Name: "global.late", Percentage: 100, Value: "ON"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := mgr.refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := mgr.Evaluate(uuidA, "")["global.late"]; got != "ON" {
		t.Errorf("refresh did not pick up new config: got %q", got)
	}
}

func TestManager_Stop_Idempotent(t *testing.T) {
	mgr := mustManager(t)
	mgr.Stop()
	mgr.Stop() // must not panic.
}

func TestBucketForAccount_StaysWithinRange(t *testing.T) {
	for _, u := range []string{uuidA, uuidB, uuidC} {
		b := bucketForAccount(u, []byte("key"))
		if b < 0 || b > 99 {
			t.Errorf("bucket out of range for %s: %d", u, b)
		}
	}
}

func TestBucketForAccount_Deterministic(t *testing.T) {
	first := bucketForAccount(uuidA, []byte("key"))
	second := bucketForAccount(uuidA, []byte("key"))
	if first != second {
		t.Errorf("non-deterministic: %d vs %d", first, second)
	}
}

func TestBucketForAccount_DistinctUUIDsHashDistinctly(t *testing.T) {
	a := bucketForAccount(uuidA, []byte("k"))
	b := bucketForAccount(uuidB, []byte("k"))
	// They might collide, but it's extremely unlikely for two UUIDs in
	// a 100-slot range to share a bucket — assert at least once across
	// a 3-UUID sample.
	c := bucketForAccount(uuidC, []byte("k"))
	if a == b && b == c {
		t.Errorf("all 3 UUIDs landed in the same bucket %d (cryptographically unlikely)", a)
	}
}

func TestUUIDToUint64Pair_HappyPath(t *testing.T) {
	_, _, ok := uuidToUint64Pair(uuidA)
	if !ok {
		t.Error("expected canonical UUID to parse")
	}
}

func TestUUIDToUint64Pair_Malformed(t *testing.T) {
	cases := []string{
		"",
		"not-a-uuid",
		strings.Repeat("z", 36),
		"11111111x1111-4111-8111-111111111111", // wrong dash position
	}
	for _, c := range cases {
		if _, _, ok := uuidToUint64Pair(c); ok {
			t.Errorf("expected parse failure for %q", c)
		}
	}
}

func TestInvalidConfigError_String(t *testing.T) {
	if got := (&InvalidConfigError{Reason: "x"}).Error(); got != "remoteconfig: invalid config: x" {
		t.Errorf("got %q", got)
	}
}

// Failing store ensures NewManager surfaces the seed-time error so the
// caller fails fast rather than booting with a stale cache.
type failingStore struct{ err error }

func (f *failingStore) GetAll(_ context.Context) ([]Config, error) { return nil, f.err }
func (f *failingStore) Put(_ context.Context, _ Config) error      { return f.err }
func (f *failingStore) Delete(_ context.Context, _ string) error   { return f.err }

func TestNewManager_SurfacesSeedError(t *testing.T) {
	_, err := NewManager(context.Background(), ManagerConfig{Store: &failingStore{err: errors.New("kaboom")}})
	if err == nil {
		t.Fatal("expected seed error")
	}
}
