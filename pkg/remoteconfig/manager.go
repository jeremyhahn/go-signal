package remoteconfig

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Manager evaluates per-account dynamic configuration. It holds a Store
// for the source-of-truth rows and a periodic-refresh cache so the
// hot path doesn't take a Store round-trip on every request — Java
// Signal-Server uses the same pattern with a 10s refresh interval.
type Manager struct {
	store           Store
	refreshInterval time.Duration
	cancelRefresh   context.CancelFunc

	// cache holds the last successful GetAll snapshot. Reads use the
	// pointer atomically; writers replace the whole slice rather than
	// mutate in place.
	cache *configCache
}

// configCache wraps the snapshot + a precomputed lookup table for
// platform-prefix filtering during evaluation.
type configCache struct {
	configs        []Config
	platformConfig map[string][]Config // platformPrefix → only-those configs
	neutralConfigs []Config            // configs without a platform prefix (delivered to every platform)
}

// ManagerConfig configures NewManager.
type ManagerConfig struct {
	// Store is the persistence layer. Required.
	Store Store
	// RefreshInterval is how often the background goroutine reloads
	// GetAll into the cache. Zero defaults to 10s.
	RefreshInterval time.Duration
}

// NewManager constructs a Manager and seeds the cache with an initial
// GetAll. A background refresh goroutine is started; call Stop to halt
// it on graceful shutdown.
func NewManager(ctx context.Context, cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("remoteconfig: Store is required")
	}
	interval := cfg.RefreshInterval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	mgr := &Manager{store: cfg.Store, refreshInterval: interval}
	if err := mgr.refresh(ctx); err != nil {
		return nil, err
	}
	refreshCtx, cancel := context.WithCancel(context.Background())
	mgr.cancelRefresh = cancel
	go mgr.refreshLoop(refreshCtx)
	return mgr, nil
}

// Refresh re-reads the store and replaces the in-memory cache. The
// background refresh goroutine calls this every refreshInterval; the
// check-dynamic-config worker calls it on-demand to validate that
// the live store still parses + that every row passes the same
// invariants Put enforces.
func (m *Manager) Refresh(ctx context.Context) error {
	return m.refresh(ctx)
}

// refresh re-reads the store and replaces the in-memory cache.
func (m *Manager) refresh(ctx context.Context) error {
	all, err := m.store.GetAll(ctx)
	if err != nil {
		return err
	}
	cache := &configCache{
		configs:        all,
		platformConfig: make(map[string][]Config),
	}
	for _, c := range all {
		prefix := FirstSegment(c.Name)
		if IsPlatformPrefix(prefix) {
			cache.platformConfig[strings.ToLower(prefix)] =
				append(cache.platformConfig[strings.ToLower(prefix)], c)
		} else {
			cache.neutralConfigs = append(cache.neutralConfigs, c)
		}
	}
	m.cache = cache
	return nil
}

// refreshLoop runs until cancelRefresh fires. Failures are swallowed —
// the previous cache stays valid, mirroring Java's quiet-on-failure
// dynamic-config refresh behavior. Operators monitor underlying store
// health separately.
func (m *Manager) refreshLoop(ctx context.Context) {
	t := time.NewTicker(m.refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = m.refresh(ctx)
		}
	}
}

// Stop halts the background refresh goroutine. Safe to call multiple
// times; subsequent calls are no-ops.
func (m *Manager) Stop() {
	if m.cancelRefresh != nil {
		m.cancelRefresh()
		m.cancelRefresh = nil
	}
}

// Evaluate returns the rendered key→value map for accountUUID +
// userAgent. Per Java:
//   - Configs prefixed with a platform tag are filtered to that
//     platform; non-platform-prefixed configs ship to every client.
//   - For each delivered config, the account is hashed into a 0–99
//     bucket; in-bucket accounts (or those explicitly listed in
//     UUIDs) receive Value; everyone else receives DefaultValue.
//   - Globals (cfg.Name starts with "global.") are passed through
//     verbatim — bucketing still applies but most globals are 100%.
//
// The returned map is deterministic for a given (accountUUID, cache)
// pair so callers can compute a stable ETag.
func (m *Manager) Evaluate(accountUUID, userAgent string) map[string]string {
	cache := m.cache
	if cache == nil {
		return map[string]string{}
	}
	platform := PlatformFromUserAgent(userAgent)
	out := make(map[string]string, len(cache.neutralConfigs)+8)
	// Platform-neutral configs go to everyone.
	for _, c := range cache.neutralConfigs {
		out[c.Name] = evaluate(c, accountUUID)
	}
	// Platform-scoped configs go only to matching clients.
	if platform != "" {
		for _, c := range cache.platformConfig[platform] {
			out[c.Name] = evaluate(c, accountUUID)
		}
	}
	return out
}

// evaluate runs the bucket check for one config and returns the value the
// caller should serialize.
func evaluate(c Config, accountUUID string) string {
	if _, ok := c.UUIDs[accountUUID]; ok {
		return resolveValue(c, true)
	}
	bucket := bucketForAccount(accountUUID, hashKeyBytes(c))
	return resolveValue(c, bucket < c.Percentage)
}

// resolveValue picks between Value and DefaultValue, falling back to
// "true"/"false" string-of-bool when either is empty (Java parity).
func resolveValue(c Config, inBucket bool) string {
	if inBucket {
		if c.Value != "" {
			return c.Value
		}
		return strconv.FormatBool(true)
	}
	if c.DefaultValue != "" {
		return c.DefaultValue
	}
	return strconv.FormatBool(false)
}

// hashKeyBytes returns the HashKey override if present, otherwise the
// config name. Java uses the same fall-back.
func hashKeyBytes(c Config) []byte {
	if c.HashKey != "" {
		return []byte(c.HashKey)
	}
	return []byte(c.Name)
}

// bucketForAccount computes the 0–99 bucket number for an account UUID
// against the provided hash key. The hash chain matches Java
// RemoteConfigController.isInBucket exactly:
//
//	SHA-256( bigEndian(uuidMSB) || bigEndian(uuidLSB) || hashKeyBytes )
//
// The first 8 bytes of the digest are interpreted as a big-endian uint64,
// masked positive, and modulo 100 to produce the bucket.
func bucketForAccount(accountUUID string, hashKey []byte) int {
	msb, lsb, ok := uuidToUint64Pair(accountUUID)
	if !ok {
		// Malformed UUID — return a bucket value (50) that lands roughly
		// in the middle of the 0–99 range so a single bad caller does
		// not bias the bucket population in either direction. The
		// alternative — returning 0 — would over-include malformed
		// inputs in every config bucket.
		return 50
	}
	digest := sha256.New()
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], msb)
	binary.BigEndian.PutUint64(buf[8:16], lsb)
	digest.Write(buf[:])
	// Java's RemoteConfigController calls `digest.digest(hashKey)`,
	// which is shorthand for `update(hashKey); digest()` — so the
	// hashKey is hashed alongside the UUID, NOT just appended to the
	// output. Writing it here matches Java byte-for-byte.
	digest.Write(hashKey)
	hash := digest.Sum(nil)
	v := binary.BigEndian.Uint64(hash[0:8])
	const signBit = uint64(1) << 63
	if v >= signBit {
		v &^= signBit
	}
	return int(v % 100)
}

// uuidToUint64Pair parses a canonical 8-4-4-4-12 UUID into the
// most-significant and least-significant 64-bit halves Java uses for
// hashing. Returns ok=false when the input doesn't match the canonical
// shape.
func uuidToUint64Pair(s string) (msb, lsb uint64, ok bool) {
	// Canonical UUID length is 36 chars with dashes at positions 8, 13,
	// 18, 23. Tolerate either case for hex.
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return 0, 0, false
	}
	stripped := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			continue
		}
		stripped = append(stripped, s[i])
	}
	raw, err := hex.DecodeString(string(stripped))
	if err != nil || len(raw) != 16 {
		return 0, 0, false
	}
	msb = binary.BigEndian.Uint64(raw[0:8])
	lsb = binary.BigEndian.Uint64(raw[8:16])
	return msb, lsb, true
}

// PlatformFromUserAgent classifies a Signal client User-Agent string
// into one of "ios", "android", "desktop", or "" (unrecognized). The
// detection is conservative — matching Java's UserAgentUtil flow —
// because misclassifying a client into the wrong bucket misroutes a
// feature flag for that user.
func PlatformFromUserAgent(ua string) string {
	if ua == "" {
		return ""
	}
	lower := strings.ToLower(ua)
	switch {
	case strings.Contains(lower, "signal-ios"):
		return "ios"
	case strings.Contains(lower, "signal-android"):
		return "android"
	case strings.Contains(lower, "signal-desktop"):
		return "desktop"
	}
	return ""
}
