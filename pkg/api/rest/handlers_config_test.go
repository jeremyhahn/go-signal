package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
)

// --------------------------------------------------------------------------
// handleGetConfig (legacy /v1/config endpoint)
// --------------------------------------------------------------------------

func TestHandleGetConfig_Success(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if _, ok := resp["config"]; !ok {
		t.Error("expected 'config' key in response")
	}
}

func TestHandleGetConfig_NoAuthRequired(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// TestHandleGetConfig_ServesGlobalConfig verifies the legacy /v1/config
// endpoint delivers the platform-neutral global flags from the wired
// remoteconfig.Manager (rather than an empty stub), in the canonical
// name→value map shape.
func TestHandleGetConfig_ServesGlobalConfig(t *testing.T) {
	s := newTestServer(t)
	wireRemoteConfig(t, s)

	req := httptest.NewRequest(http.MethodGet, "/v1/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Config map[string]string `json:"config"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	// Platform-neutral global flag must be present and rendered.
	if resp.Config["global.calling"] != "TRUE" {
		t.Errorf("expected global.calling=TRUE, got %q (full: %v)", resp.Config["global.calling"], resp.Config)
	}
	// Platform-scoped flags require a User-Agent; with none they must NOT
	// leak into the global response.
	if _, ok := resp.Config["ios.foo"]; ok {
		t.Errorf("platform-scoped ios.foo must not appear in unauthenticated /v1/config: %v", resp.Config)
	}
}

// --------------------------------------------------------------------------
// handleGetRemoteConfig (/v2/config)
// --------------------------------------------------------------------------

// wireRemoteConfig attaches a freshly-seeded remoteconfig.Manager to s
// and returns it. The manager carries the two test configs every /v2
// test below relies on.
func wireRemoteConfig(t *testing.T, s *Server) *remoteconfig.Manager {
	t.Helper()
	store := remoteconfig.NewMemoryStore()
	ctx := context.Background()
	for _, c := range []remoteconfig.Config{
		{Name: "global.calling", Percentage: 100, Value: "TRUE"},
		{Name: "ios.foo", Percentage: 100, Value: "TRUE"},
	} {
		if err := store.Put(ctx, c); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	mgr, err := remoteconfig.NewManager(ctx, remoteconfig.ManagerConfig{Store: store, RefreshInterval: time.Hour})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(mgr.Stop)
	s.remoteConfig = mgr
	return mgr
}

func TestHandleGetRemoteConfig_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	wireRemoteConfig(t, s)

	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("ETag") == "" {
		t.Error("expected ETag header")
	}
	if rr.Header().Get("X-Signal-Timestamp") == "" {
		t.Error("expected X-Signal-Timestamp header")
	}

	var resp RemoteConfigResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := resp.Config["global.calling"]; !ok || v != "TRUE" {
		t.Errorf("expected global.calling=TRUE, got %+v", resp.Config)
	}
	// No UA header => platform-scoped configs must NOT be delivered.
	if _, ok := resp.Config["ios.foo"]; ok {
		t.Error("ios.foo should NOT be delivered without matching User-Agent")
	}
}

func TestHandleGetRemoteConfig_PlatformFilteringByUA(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	wireRemoteConfig(t, s)
	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	req.Header.Set("User-Agent", "Signal-iOS/7.5 (iPhone)")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp RemoteConfigResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Config["ios.foo"] != "TRUE" {
		t.Errorf("iOS UA should receive ios.foo: %+v", resp.Config)
	}
}

func TestHandleGetRemoteConfig_IfNoneMatch_Returns304(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	wireRemoteConfig(t, s)

	// First request: capture the ETag.
	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	etag := rr.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag on first response")
	}

	// Second request: replay ETag via If-None-Match — must return 304.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	req2.SetBasicAuth(testAccountUUID, testAuthToken)
	req2.Header.Set("If-None-Match", etag)
	rr2 := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d", rr2.Code)
	}
}

func TestHandleGetRemoteConfig_ETagStableAcrossCalls(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	wireRemoteConfig(t, s)
	getETag := func() string {
		req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
		req.SetBasicAuth(testAccountUUID, testAuthToken)
		rr := httptest.NewRecorder()
		s.httpServer.Handler.ServeHTTP(rr, req)
		return rr.Header().Get("ETag")
	}
	a := getETag()
	b := getETag()
	if a == "" || a != b {
		t.Errorf("ETag must be stable across identical requests: %q vs %q", a, b)
	}
}

func TestHandleGetRemoteConfig_NoManagerReturnsEmpty(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	// Leave s.remoteConfig nil to exercise the "no manager" branch.
	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp RemoteConfigResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Config) != 0 {
		t.Errorf("expected empty config when manager unset, got %+v", resp.Config)
	}
}

func TestHandleGetRemoteConfig_Unauthenticated(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/v2/config", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
