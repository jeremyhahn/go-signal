// Package remoteconfig implements Signal-Server's dynamic feature-flag
// system. Each Config carries a name, a per-account bucket size, an
// optional explicit allowlist of UUIDs, and value / default strings.
// Per-request evaluation hashes the account UUID into a 0–99 bucket
// using SHA-256(uuid bytes || hashKey) — accounts whose bucket falls
// below Percentage receive Value; everyone else gets DefaultValue.
//
// Mirrors Java's RemoteConfig + RemoteConfigController.isInBucket.
package remoteconfig

import (
	"strings"
)

// Config is a single dynamic-configuration entry.
type Config struct {
	// Name is the dotted feature key (e.g. "global.calling",
	// "ios.callingMesh"). The first dot-separated segment is treated as
	// a platform prefix (see PlatformPrefixes) — configs whose prefix
	// matches a platform are only returned to clients on that platform.
	Name string
	// Percentage is the bucket cap in [0, 100]. Bucket numbers below
	// this value receive Value; the rest receive DefaultValue.
	Percentage int
	// UUIDs explicitly carry these accounts into the bucket regardless
	// of Percentage. Java's enrollment-override mechanism.
	UUIDs map[string]struct{}
	// Value is the string returned to clients in the bucket. When Value
	// is empty Java returns "true" / "false" string-of-bool; we follow
	// the same fall-back in Manager.evaluate.
	Value string
	// DefaultValue is the string returned to clients outside the bucket.
	// Optional; same fall-back applies.
	DefaultValue string
	// HashKey overrides Name as the bucket-hash input. Lets ops shift
	// the bucket population without renaming the config. Java parity.
	HashKey string
}

// PlatformPrefixes is the set of first-segment platform tags that
// trigger platform-scoped delivery. Configs prefixed with one of these
// only ship to clients running that platform; configs with any other
// prefix (or no platform prefix) ship to every platform.
//
// Matches Java's ClientPlatform enum values lower-cased.
var PlatformPrefixes = map[string]struct{}{
	"ios":     {},
	"android": {},
	"desktop": {},
}

// FirstSegment returns the dot-separated leading segment of name. Used
// for platform-prefix filtering.
func FirstSegment(name string) string {
	if i := strings.Index(name, "."); i >= 0 {
		return name[:i]
	}
	return name
}

// IsPlatformPrefix reports whether segment is one of the well-known
// platform tags. Exposed for tests + REST handler logic.
func IsPlatformPrefix(segment string) bool {
	_, ok := PlatformPrefixes[strings.ToLower(segment)]
	return ok
}
