package rest

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	ws "github.com/coder/websocket"
)

// --------------------------------------------------------------------------
// handleSVR2WebSocket
// --------------------------------------------------------------------------

func TestHandleSVR2WebSocket_NonWebSocketRequest(t *testing.T) {
	s := newTestServer(t)

	// A non-WebSocket GET request fails the WebSocket upgrade. The websocket
	// library writes a 426 Upgrade Required when the Connection header lacks
	// the "Upgrade" token.
	req := httptest.NewRequest(http.MethodGet, "/svr2/v1/abc123", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUpgradeRequired {
		t.Errorf("expected 426, got %d", rr.Code)
	}
}

func TestHandleSVR2WebSocket_NonWebSocketRequest_HasBody(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/svr2/v1/abc123", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Body.Len() == 0 {
		t.Error("expected error body from failed WebSocket upgrade")
	}
}

func TestHandleSVR2WebSocket_SuccessfulUpgradeAndClose(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Start a real HTTP server for the WebSocket upgrade.
	ts := httptest.NewServer(s.httpServer.Handler)
	defer ts.Close()

	// Build a WebSocket URL with basic auth.
	wsURL := "ws" + ts.URL[len("http"):] + "/svr2/v1/abc123"

	ctx := context.Background()
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(testAccountUUID+":"+testAuthToken)))

	conn, _, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPHeader: headers,
	})
	if err != nil {
		t.Fatalf("failed to dial SVR2 websocket: %v", err)
	}

	// The server should close the connection immediately. Reading should
	// return a close error with normal closure status.
	_, _, readErr := conn.Read(ctx)
	if readErr == nil {
		t.Fatal("expected read error after server close")
	}

	closeStatus := ws.CloseStatus(readErr)
	if closeStatus != ws.StatusNormalClosure {
		t.Errorf("expected normal closure status (%d), got %d", ws.StatusNormalClosure, closeStatus)
	}
}

func TestHandleSVR2WebSocket_DifferentHash(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Start a real HTTP server for the WebSocket upgrade.
	ts := httptest.NewServer(s.httpServer.Handler)
	defer ts.Close()

	wsURL := "ws" + ts.URL[len("http"):] + "/svr2/v1/deadbeef"

	ctx := context.Background()
	headers := http.Header{}
	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(testAccountUUID+":"+testAuthToken)))

	conn, _, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPHeader: headers,
	})
	if err != nil {
		t.Fatalf("failed to dial SVR2 websocket: %v", err)
	}

	_, _, readErr := conn.Read(ctx)
	if readErr == nil {
		t.Fatal("expected read error after server close")
	}

	closeStatus := ws.CloseStatus(readErr)
	if closeStatus != ws.StatusNormalClosure {
		t.Errorf("expected normal closure status (%d), got %d", ws.StatusNormalClosure, closeStatus)
	}
}

// --------------------------------------------------------------------------
// wsAcceptOptions
// --------------------------------------------------------------------------

func TestWSAcceptOptions_NoAllowedOrigins_NoInsecureSkip(t *testing.T) {
	s := newTestServer(t)

	opts := s.wsAcceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false with no allowed origins")
	}
	if len(opts.OriginPatterns) != 0 {
		t.Errorf("expected empty OriginPatterns, got %v", opts.OriginPatterns)
	}
}

func TestWSAcceptOptions_WithAllowedOrigins_SetsPatterns(t *testing.T) {
	logger := testLogger()
	s := NewServer(ServerConfig{
		Host:           "127.0.0.1",
		Port:           0,
		Logger:         logger,
		AllowedOrigins: []string{"https://signal.example.com"},
	})

	opts := s.wsAcceptOptions()
	if opts.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify to be false even with allowed origins")
	}
	if len(opts.OriginPatterns) != 1 {
		t.Fatalf("expected 1 OriginPattern, got %d", len(opts.OriginPatterns))
	}
	if opts.OriginPatterns[0] != "https://signal.example.com" {
		t.Errorf("expected origin pattern %q, got %q", "https://signal.example.com", opts.OriginPatterns[0])
	}
}
