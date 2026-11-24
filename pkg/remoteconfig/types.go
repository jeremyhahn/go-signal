// Package remoteconfig implements dynamic feature flags: an account gets Value when SHA-256(uuid || hashKey) buckets it below Percentage, else DefaultValue.
package remoteconfig

import (
	"strings"
)

// Config is a single dynamic-configuration entry.
type Config struct {
	// Name is the dotted key; a first segment in PlatformPrefixes limits delivery to that platform.
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

// PlatformPrefixes are the first segments that limit a config to one platform.
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

// IsPlatformPrefix reports whether segment is a platform tag.
func IsPlatformPrefix(segment string) bool {
	_, ok := PlatformPrefixes[strings.ToLower(segment)]
	return ok
}
