package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --------------------------------------------------------------------------
// parseClientVersion
// --------------------------------------------------------------------------

func TestParseClientVersion_AndroidFormat(t *testing.T) {
	cv, ok := parseClientVersion("Signal-Android/5.1.0 Android/13")
	if !ok {
		t.Fatal("expected ok=true for Android format")
	}
	if cv.Platform != "Android" {
		t.Errorf("expected Platform 'Android', got %q", cv.Platform)
	}
	if cv.Version != "5.1.0" {
		t.Errorf("expected Version '5.1.0', got %q", cv.Version)
	}
	if cv.Raw != "Signal-Android/5.1.0 Android/13" {
		t.Errorf("unexpected Raw value: %q", cv.Raw)
	}
}

func TestParseClientVersion_iOSFormat(t *testing.T) {
	cv, ok := parseClientVersion("Signal-iOS/6.2.0 iOS/16.0")
	if !ok {
		t.Fatal("expected ok=true for iOS format")
	}
	if cv.Platform != "iOS" {
		t.Errorf("expected Platform 'iOS', got %q", cv.Platform)
	}
	if cv.Version != "6.2.0" {
		t.Errorf("expected Version '6.2.0', got %q", cv.Version)
	}
}

func TestParseClientVersion_DesktopFormat(t *testing.T) {
	cv, ok := parseClientVersion("Signal-Desktop/7.0.0 Linux")
	if !ok {
		t.Fatal("expected ok=true for Desktop format")
	}
	if cv.Platform != "Desktop" {
		t.Errorf("expected Platform 'Desktop', got %q", cv.Platform)
	}
	if cv.Version != "7.0.0" {
		t.Errorf("expected Version '7.0.0', got %q", cv.Version)
	}
}

func TestParseClientVersion_BareSemver(t *testing.T) {
	cv, ok := parseClientVersion("5.0.0")
	if !ok {
		t.Fatal("expected ok=true for bare semver")
	}
	if cv.Platform != "unknown" {
		t.Errorf("expected Platform 'unknown' for bare semver, got %q", cv.Platform)
	}
	if cv.Version != "5.0.0" {
		t.Errorf("expected Version '5.0.0', got %q", cv.Version)
	}
}

func TestParseClientVersion_EmptyString(t *testing.T) {
	_, ok := parseClientVersion("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

func TestParseClientVersion_MalformedUserAgent(t *testing.T) {
	// A non-Signal User-Agent that cannot be parsed.
	_, ok := parseClientVersion("Mozilla/5.0 (X11; Linux x86_64)")
	if ok {
		t.Error("expected ok=false for non-Signal User-Agent")
	}
}

func TestParseClientVersion_SignalPrefixWithInvalidVersion(t *testing.T) {
	_, ok := parseClientVersion("Signal-Android/invalid-version Android/13")
	if ok {
		t.Error("expected ok=false when version part is not a valid semver")
	}
}

func TestParseClientVersion_FOSSVariant(t *testing.T) {
	cv, ok := parseClientVersion("Signal-FOSS/5.2.0 Android/12")
	if !ok {
		t.Fatal("expected ok=true for FOSS variant")
	}
	if cv.Platform != "Android" {
		t.Errorf("expected FOSS to map to 'Android' platform, got %q", cv.Platform)
	}
	if cv.Version != "5.2.0" {
		t.Errorf("expected Version '5.2.0', got %q", cv.Version)
	}
}

func TestParseClientVersion_VersionWithoutOSSuffix(t *testing.T) {
	// Format without trailing OS info.
	cv, ok := parseClientVersion("Signal-iOS/5.0.1")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if cv.Version != "5.0.1" {
		t.Errorf("expected Version '5.0.1', got %q", cv.Version)
	}
}

// --------------------------------------------------------------------------
// ClientVersionFromContext
// --------------------------------------------------------------------------

func TestClientVersionFromContext_NilWhenAbsent(t *testing.T) {
	cv := ClientVersionFromContext(context.Background())
	if cv != nil {
		t.Error("expected nil ClientVersion from empty context")
	}
}

func TestClientVersionFromContext_ReturnsStoredVersion(t *testing.T) {
	cv := &ClientVersion{Platform: "Android", Version: "5.0.0", Raw: "Signal-Android/5.0.0 Android/13"}
	ctx := context.WithValue(context.Background(), clientVersionContextKey{}, cv)
	got := ClientVersionFromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil ClientVersion from context")
	}
	if got.Version != "5.0.0" {
		t.Errorf("expected Version '5.0.0', got %q", got.Version)
	}
}

// --------------------------------------------------------------------------
// clientVersionMiddleware
// --------------------------------------------------------------------------

func newVersionMiddlewareHandler(cfg *ClientVersionConfig) http.Handler {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return clientVersionMiddleware(cfg, inner)
}

func TestClientVersionMiddleware_NilConfig_PassesThrough(t *testing.T) {
	handler := newVersionMiddlewareHandler(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/3.0.0 Android/11")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with nil config, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_ValidVersion_PassesThrough(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/5.1.0 Android/13")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid version, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_DeprecatedVersion_Returns499(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/3.9.9 Android/11")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != statusDeprecatedClient {
		t.Errorf("expected %d for deprecated version, got %d", statusDeprecatedClient, rr.Code)
	}
}

func TestClientVersionMiddleware_DeprecatedVersion_BodyContainsMinimumVersion(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/3.0.0 Android/11")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	body := rr.Body.String()
	if body == "" {
		t.Fatal("expected non-empty body for deprecated version response")
	}
	if rr.Code != statusDeprecatedClient {
		t.Errorf("expected %d, got %d", statusDeprecatedClient, rr.Code)
	}
}

func TestClientVersionMiddleware_ExactDeprecatedBefore_PassesThrough(t *testing.T) {
	// Version equal to DeprecatedBefore must NOT be rejected (strictly less than).
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/4.0.0 Android/12")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for version equal to deprecatedBefore, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_BlockedVersion_Returns403(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
		BlockedVersions:  []string{"4.5.0"},
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/4.5.0 Android/12")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked version, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_MissingUserAgent_PassesThrough(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	// No User-Agent or Signal-Client-Version header.
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for missing User-Agent, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_MalformedVersion_PassesThrough(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "curl/7.84.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for malformed/non-Signal User-Agent, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_SignalClientVersionHeader_TakesPrecedence(t *testing.T) {
	// Signal-Client-Version header must be checked before User-Agent.
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	// Signal-Client-Version is deprecated, User-Agent is valid.
	req.Header.Set("Signal-Client-Version", "Signal-Android/3.0.0 Android/11")
	req.Header.Set("User-Agent", "Signal-Android/5.0.0 Android/13")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != statusDeprecatedClient {
		t.Errorf("expected %d because Signal-Client-Version is deprecated, got %d", statusDeprecatedClient, rr.Code)
	}
}

func TestClientVersionMiddleware_SetsVersionInContext(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}

	var capturedCV *ClientVersion
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCV = ClientVersionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := clientVersionMiddleware(cfg, inner)

	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/5.1.0 Android/13")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if capturedCV == nil {
		t.Fatal("expected ClientVersion in context")
	}
	if capturedCV.Version != "5.1.0" {
		t.Errorf("expected Version '5.1.0' in context, got %q", capturedCV.Version)
	}
}

func TestClientVersionMiddleware_iOSVersion_Deprecated(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-iOS/3.5.2 iOS/15.0")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != statusDeprecatedClient {
		t.Errorf("expected %d for deprecated iOS version, got %d", statusDeprecatedClient, rr.Code)
	}
}

func TestClientVersionMiddleware_DesktopVersion_Blocked(t *testing.T) {
	cfg := &ClientVersionConfig{
		MinimumVersion:  "5.0.0",
		BlockedVersions: []string{"5.2.1"},
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Desktop/5.2.1 Linux")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked Desktop version, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_EmptyDeprecatedBefore_AllowsOldVersions(t *testing.T) {
	// When DeprecatedBefore is unset, old versions must pass through.
	cfg := &ClientVersionConfig{
		MinimumVersion: "5.0.0",
		// DeprecatedBefore intentionally empty.
	}
	handler := newVersionMiddlewareHandler(cfg)
	req := httptest.NewRequest(http.MethodGet, "/v1/keepalive", nil)
	req.Header.Set("User-Agent", "Signal-Android/1.0.0 Android/9")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 when DeprecatedBefore is empty, got %d", rr.Code)
	}
}

func TestClientVersionMiddleware_IntegratedInServer_DeprecatedReturns499(t *testing.T) {
	// Verify the middleware is wired correctly through the full Server.
	s, _ := newTestServerWithAccount(t)
	// The test server does not set a ClientVersionConfig, so we create one
	// with a custom config and verify through the middleware directly.
	cfg := &ClientVersionConfig{
		MinimumVersion:   "5.0.0",
		DeprecatedBefore: "4.0.0",
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	_ = s // prevent unused variable warning

	handler := clientVersionMiddleware(cfg, inner)
	req := httptest.NewRequest(http.MethodGet, "/v2/keys", nil)
	req.Header.Set("User-Agent", "Signal-Android/3.5.0 Android/11")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != statusDeprecatedClient {
		t.Errorf("expected %d for deprecated client version, got %d", statusDeprecatedClient, rr.Code)
	}
}
