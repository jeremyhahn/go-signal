package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// --------------------------------------------------------------------------
// HandleUnauthenticated
// --------------------------------------------------------------------------

func TestHandleUnauthenticated_NonWebSocketRequest(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	// A plain HTTP request (no Upgrade header) causes ws.Accept to fail.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/websocket/unauth", nil)
	h.HandleUnauthenticated(rec, req)

	if rec.Code == http.StatusSwitchingProtocols {
		t.Error("expected non-101 for plain HTTP request")
	}
}

func TestHandleUnauthenticated_FullWebSocket_Keepalive(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleUnauthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/unauth"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a keepalive request and verify the handler responds.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   5,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})

	resp := wsRead(t, conn)
	if resp.Type != "response" {
		t.Errorf("Type = %q, want %q", resp.Type, "response")
	}
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 5 {
		t.Errorf("Response.ID = %d, want 5", resp.Response.ID)
	}
	if resp.Response.Status != http.StatusOK {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusOK)
	}
}

func TestHandleUnauthenticated_FullWebSocket_UnknownRoute(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleUnauthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/unauth"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	defer func() {
		if err := conn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("conn.Close: %v", err)
		}
	}()

	// Send a request to an unknown route; it should be forwarded via routeToHTTP.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   7,
			Verb: "GET",
			Path: "/v1/remote/config",
		},
	})

	resp := wsRead(t, conn)
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 7 {
		t.Errorf("Response.ID = %d, want 7", resp.Response.ID)
	}
	// NotFoundHandler returns 404.
	if resp.Response.Status != http.StatusNotFound {
		t.Errorf("Response.Status = %d, want %d", resp.Response.Status, http.StatusNotFound)
	}
}

func TestHandleUnauthenticated_ConnectionLifecycle(t *testing.T) {
	logger := handlerTestLogger()
	acctStore := newStubAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	msgStore := newStubMessageStore()
	msgMgr := messages.NewMessagesManager(msgStore)
	sessions := signalws.NewSessionManager(logger)

	h := NewHandler(acctMgr, msgMgr, sessions, http.NotFoundHandler(), logger)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.HandleUnauthenticated(w, r)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/websocket/unauth"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}

	// Send a keepalive to confirm the session is active and receiving messages.
	wsWrite(t, conn, &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   1,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	})
	resp := wsRead(t, conn)
	if resp.Response == nil || resp.Response.Status != http.StatusOK {
		t.Errorf("expected 200 keepalive response, got %v", resp)
	}

	// Close the connection; handler should unregister the session.
	_ = conn.Close(ws.StatusNormalClosure, "done")
}
