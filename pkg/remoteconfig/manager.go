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

// Manager evaluates per-account dynamic configuration from a Store through a periodically refreshed cache.
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

// Refresh re-reads and validates the store and replaces the cache.
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

// refreshLoop runs until cancelRefresh; a failed refresh keeps the previous cache.
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

// Evaluate returns the config map for an account and user agent: platform-prefixed configs only to that platform, Value for in-bucket or listed accounts, else DefaultValue; deterministic.
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

// bucketForAccount returns SHA-256(uuidMSB || uuidLSB || hashKey)'s first 8 bytes, big-endian, masked positive, mod 100.
func bucketForAccount(accountUUID string, hashKey []byte) int {
	msb, lsb, ok := uuidToUint64Pair(accountUUID)
	if !ok {
		// A malformed UUID gets bucket 50, the middle of the range.
		return 50
	}
	digest := sha256.New()
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], msb)
	binary.BigEndian.PutUint64(buf[8:16], lsb)
	digest.Write(buf[:])
	// hashKey is hashed with the UUID, not appended to the digest.
	digest.Write(hashKey)
	hash := digest.Sum(nil)
	v := binary.BigEndian.Uint64(hash[0:8])
	const signBit = uint64(1) << 63
	if v >= signBit {
		v &^= signBit
	}
	return int(v % 100)
}

// uuidToUint64Pair splits a canonical UUID into its two 64-bit halves; ok is false for any other shape.
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

// PlatformFromUserAgent returns "ios", "android", "desktop" or "" for a Signal User-Agent.
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
