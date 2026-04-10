package rest

import (
	"context"
	"net/http"
	"strings"

	"github.com/jeremyhahn/go-signal/pkg/version"
)

// statusDeprecatedClient is the HTTP status code returned when a client's
// version is below the minimum supported version. 499 is an unofficial
// client-side error code used by Signal to indicate a deprecated client.
const statusDeprecatedClient = 499

// clientVersionContextKey is the context key for the parsed client version.
type clientVersionContextKey struct{}

// clientVersionMiddleware inspects the User-Agent or Signal-Client-Version
// header and enforces the ClientVersionConfig policy:
//
//   - If the version is in BlockedVersions, the request is rejected with 403.
//   - If the version is below DeprecatedBefore, the request is rejected with
//     499 and a JSON body containing the minimum_version field.
//   - If the header is absent or cannot be parsed, the request is allowed
//     through (lenient behaviour for scripts and tooling).
//   - Parsed version strings are stored in the request context for logging.
func clientVersionMiddleware(cfg *ClientVersionConfig, next http.Handler) http.Handler {
	if cfg == nil {
		return next
	}

	blockedSet := make(map[string]struct{}, len(cfg.BlockedVersions))
	for _, v := range cfg.BlockedVersions {
		blockedSet[v] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Signal-Client-Version")
		if raw == "" {
			raw = r.Header.Get("User-Agent")
		}

		parsed, ok := parseClientVersion(raw)
		if !ok {
			// Missing or unparseable header: allow through (lenient).
			next.ServeHTTP(w, r)
			return
		}

		// Store parsed version in context for downstream logging.
		ctx := context.WithValue(r.Context(), clientVersionContextKey{}, parsed)
		r = r.WithContext(ctx)

		// Check blocked versions first (exact match on full version string).
		if _, blocked := blockedSet[parsed.Version]; blocked {
			writeError(w, http.StatusForbidden, "client version is blocked")
			return
		}

		// Check deprecated-before threshold.
		if cfg.DeprecatedBefore != "" && version.Less(parsed.Version, cfg.DeprecatedBefore) {
			writeJSON(w, statusDeprecatedClient, map[string]string{
				"minimum_version": cfg.MinimumVersion,
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ClientVersionConfig holds the policy for enforcing minimum and blocked
// client versions. It is applied by clientVersionMiddleware on every request.
type ClientVersionConfig struct {
	// MinimumVersion is the minimum accepted client version string. Clients
	// reporting a version below DeprecatedBefore receive a 499 response with
	// this value in the JSON body so they can prompt for an upgrade.
	MinimumVersion string

	// DeprecatedBefore is the exclusive lower bound for accepted versions.
	// Clients with a version strictly less than this value receive 499.
	// An empty string disables the deprecated-before check.
	DeprecatedBefore string

	// BlockedVersions is an exact-match set of version strings that are
	// unconditionally rejected with 403 regardless of the deprecated range.
	BlockedVersions []string
}

// ClientVersion holds the parsed components of a Signal client version header.
type ClientVersion struct {
	// Platform is the client platform extracted from the User-Agent or
	// Signal-Client-Version header (e.g. "Android", "iOS", "Desktop").
	Platform string

	// Version is the semantic version string (e.g. "5.1.0").
	Version string

	// Raw is the original unparsed header value.
	Raw string
}

// ClientVersionFromContext retrieves the parsed ClientVersion from the context.
// Returns nil if no version is present (e.g. for unauthenticated or non-client
// requests).
func ClientVersionFromContext(ctx context.Context) *ClientVersion {
	v, _ := ctx.Value(clientVersionContextKey{}).(*ClientVersion)
	return v
}

// parseClientVersion attempts to extract a platform and version from a raw
// Signal client header value. The expected formats are:
//
//   - "Signal-Android/5.1.0 Android/13"
//   - "Signal-iOS/5.1.0 iOS/16.0"
//   - "Signal-Desktop/5.1.0 Linux"
//   - Plain semver: "5.1.0"
//
// Returns the parsed ClientVersion and true on success; false if the value is
// empty or contains no recognisable version information.
func parseClientVersion(raw string) (*ClientVersion, bool) {
	if raw == "" {
		return nil, false
	}

	// Known platform prefixes in User-Agent / Signal-Client-Version headers.
	// Each maps to a canonical platform name.
	platformPrefixes := []struct {
		prefix   string
		platform string
	}{
		{"Signal-Android/", "Android"},
		{"Signal-iOS/", "iOS"},
		{"Signal-Desktop/", "Desktop"},
		{"Signal-FOSS/", "Android"},
	}

	for _, pp := range platformPrefixes {
		if strings.HasPrefix(raw, pp.prefix) {
			rest := raw[len(pp.prefix):]
			// Version ends at the first space (may be followed by OS info).
			ver := rest
			if idx := strings.IndexByte(rest, ' '); idx >= 0 {
				ver = rest[:idx]
			}
			if !version.IsValid(ver) {
				return nil, false
			}
			return &ClientVersion{Platform: pp.platform, Version: ver, Raw: raw}, true
		}
	}

	// Fall back: treat the entire header as a bare version string.
	if version.IsValid(raw) {
		return &ClientVersion{Platform: "unknown", Version: raw, Raw: raw}, true
	}

	return nil, false
}
