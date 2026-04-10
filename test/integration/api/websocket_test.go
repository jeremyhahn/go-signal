//go:build integration

package api

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// wsURL converts the base HTTP(S) URL to a WebSocket URL.
func toWSURL(baseURL string) string {
	u := strings.Replace(baseURL, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return u
}

// wsHTTPClient returns an HTTP client with TLS verification disabled for
// WebSocket dialing through self-signed test certificates.
func wsHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func TestWebSocket_Connect(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-ws-connect"
	uuid, _ := registerTestAccount(t, env, number, password)

	// Connect via WebSocket with Basic Auth.
	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"
	creds := base64.StdEncoding.EncodeToString([]byte(uuid + ".1:" + password))
	header := http.Header{}
	header.Set("Authorization", "Basic "+creds)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, resp, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
		HTTPHeader: header,
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	defer conn.Close(ws.StatusNormalClosure, "test done")

	// Connection is established; send a keepalive to verify bidirectional
	// communication.
	keepalive := &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   100,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	}
	data, err := json.Marshal(keepalive)
	require.NoError(t, err)

	err = conn.Write(ctx, ws.MessageText, data)
	require.NoError(t, err)

	// Read response.
	_, respData, err := conn.Read(ctx)
	require.NoError(t, err)

	var msg signalws.WebSocketMessage
	err = json.Unmarshal(respData, &msg)
	require.NoError(t, err)
	assert.Equal(t, "response", msg.Type)
	assert.NotNil(t, msg.Response)
	assert.Equal(t, uint64(100), msg.Response.ID)
	assert.Equal(t, http.StatusOK, msg.Response.Status)
}

func TestWebSocket_ConnectWithQueryParams(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-ws-query"
	uuid, _ := registerTestAccount(t, env, number, password)

	// Connect via WebSocket with query parameter auth.
	wsURL := toWSURL(env.baseURL) +
		"/v1/websocket/?login=" + uuid + ".1&password=" + password

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, resp, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	defer conn.Close(ws.StatusNormalClosure, "test done")
}

func TestWebSocket_ReceiveMessage(t *testing.T) {
	env := setupTestEnv(t)

	// Register two users.
	numberA := uniquePhoneNumber()
	passwordA := "test-password-ws-recv-a"
	uuidA, _ := registerTestAccount(t, env, numberA, passwordA)

	numberB := uniquePhoneNumber()
	passwordB := "test-password-ws-recv-b"
	uuidB, _ := registerTestAccount(t, env, numberB, passwordB)

	// Connect user A via WebSocket.
	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"
	creds := base64.StdEncoding.EncodeToString([]byte(uuidA + ".1:" + passwordA))
	header := http.Header{}
	header.Set("Authorization", "Basic "+creds)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
		HTTPHeader: header,
	})
	require.NoError(t, err)
	defer conn.Close(ws.StatusNormalClosure, "test done")

	// Brief pause to let the session register.
	time.Sleep(100 * time.Millisecond)

	// User B sends a message to user A via REST API.
	msgContent := base64.StdEncoding.EncodeToString([]byte("hello from user B"))
	sendReq := map[string]any{
		"messages": []map[string]any{
			{
				"type":                1,
				"destinationDeviceId": 1,
				"content":             msgContent,
				"timestamp":           time.Now().UnixMilli(),
			},
		},
		"timestamp": time.Now().UnixMilli(),
		"urgent":    true,
	}

	resp := env.doAuthRequest(t, "PUT", "/v1/messages/"+uuidA, sendReq, uuidB, passwordB)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// User A should receive the message via WebSocket.
	readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readCancel()

	_, msgData, err := conn.Read(readCtx)
	require.NoError(t, err)

	var wsMsg signalws.WebSocketMessage
	err = json.Unmarshal(msgData, &wsMsg)
	require.NoError(t, err)
	assert.Equal(t, "request", wsMsg.Type)
	assert.NotNil(t, wsMsg.Request)
	assert.Equal(t, "PUT", wsMsg.Request.Verb)
	assert.Equal(t, "/api/v1/message", wsMsg.Request.Path)
	assert.NotEmpty(t, wsMsg.Request.Body)

	// Acknowledge the message.
	ack := &signalws.WebSocketMessage{
		Type: "response",
		Response: &signalws.WebSocketResponse{
			ID:      wsMsg.Request.ID,
			Status:  200,
			Message: "OK",
		},
	}
	ackData, err := json.Marshal(ack)
	require.NoError(t, err)
	err = conn.Write(ctx, ws.MessageText, ackData)
	require.NoError(t, err)
}

func TestWebSocket_Keepalive(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-ws-ka"
	uuid, _ := registerTestAccount(t, env, number, password)

	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"
	creds := base64.StdEncoding.EncodeToString([]byte(uuid + ".1:" + password))
	header := http.Header{}
	header.Set("Authorization", "Basic "+creds)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
		HTTPHeader: header,
	})
	require.NoError(t, err)
	defer conn.Close(ws.StatusNormalClosure, "test done")

	// Send keepalive request.
	keepalive := &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   42,
			Verb: "GET",
			Path: "/api/v1/keepalive",
		},
	}
	data, err := json.Marshal(keepalive)
	require.NoError(t, err)
	err = conn.Write(ctx, ws.MessageText, data)
	require.NoError(t, err)

	// Read response.
	_, respData, err := conn.Read(ctx)
	require.NoError(t, err)

	var msg signalws.WebSocketMessage
	err = json.Unmarshal(respData, &msg)
	require.NoError(t, err)
	assert.Equal(t, "response", msg.Type)
	assert.NotNil(t, msg.Response)
	assert.Equal(t, uint64(42), msg.Response.ID)
	assert.Equal(t, http.StatusOK, msg.Response.Status)
	assert.Equal(t, "OK", msg.Response.Message)
}

func TestWebSocket_KeepaliveMultiple(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-ws-ka-multi"
	uuid, _ := registerTestAccount(t, env, number, password)

	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"
	creds := base64.StdEncoding.EncodeToString([]byte(uuid + ".1:" + password))
	header := http.Header{}
	header.Set("Authorization", "Basic "+creds)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
		HTTPHeader: header,
	})
	require.NoError(t, err)
	defer conn.Close(ws.StatusNormalClosure, "test done")

	// Send multiple keepalive requests.
	for i := uint64(1); i <= 3; i++ {
		keepalive := &signalws.WebSocketMessage{
			Type: "request",
			Request: &signalws.WebSocketRequest{
				ID:   i,
				Verb: "GET",
				Path: "/api/v1/keepalive",
			},
		}
		data, err := json.Marshal(keepalive)
		require.NoError(t, err)
		err = conn.Write(ctx, ws.MessageText, data)
		require.NoError(t, err)

		_, respData, err := conn.Read(ctx)
		require.NoError(t, err)

		var msg signalws.WebSocketMessage
		err = json.Unmarshal(respData, &msg)
		require.NoError(t, err)
		assert.Equal(t, "response", msg.Type)
		assert.Equal(t, i, msg.Response.ID)
		assert.Equal(t, http.StatusOK, msg.Response.Status)
	}
}

func TestWebSocket_ConnectWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)

	// Attempt to connect without authentication.
	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, resp, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
	})
	// Should fail - either an error or a non-101 status.
	if err == nil {
		t.Fatal("expected error when connecting without auth")
	}
	if resp != nil {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestWebSocket_ConnectWithInvalidAuth(t *testing.T) {
	env := setupTestEnv(t)

	// Attempt to connect with invalid credentials.
	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"
	creds := base64.StdEncoding.EncodeToString([]byte("invalid-uuid.1:bad-password"))
	header := http.Header{}
	header.Set("Authorization", "Basic "+creds)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, resp, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
		HTTPHeader: header,
	})
	if err == nil {
		t.Fatal("expected error when connecting with invalid auth")
	}
	if resp != nil {
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}
}

func TestWebSocket_UnknownPath(t *testing.T) {
	env := setupTestEnv(t)
	number := uniquePhoneNumber()
	password := "test-password-ws-unknown"
	uuid, _ := registerTestAccount(t, env, number, password)

	wsURL := toWSURL(env.baseURL) + "/v1/websocket/"
	creds := base64.StdEncoding.EncodeToString([]byte(uuid + ".1:" + password))
	header := http.Header{}
	header.Set("Authorization", "Basic "+creds)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := ws.Dial(ctx, wsURL, &ws.DialOptions{
		HTTPClient: wsHTTPClient(),
		HTTPHeader: header,
	})
	require.NoError(t, err)
	defer conn.Close(ws.StatusNormalClosure, "test done")

	// Send request to unknown path.
	req := &signalws.WebSocketMessage{
		Type: "request",
		Request: &signalws.WebSocketRequest{
			ID:   99,
			Verb: "GET",
			Path: "/api/v1/nonexistent",
		},
	}
	data, err := json.Marshal(req)
	require.NoError(t, err)
	err = conn.Write(ctx, ws.MessageText, data)
	require.NoError(t, err)

	_, respData, err := conn.Read(ctx)
	require.NoError(t, err)

	var msg signalws.WebSocketMessage
	err = json.Unmarshal(respData, &msg)
	require.NoError(t, err)
	assert.Equal(t, "response", msg.Type)
	assert.Equal(t, uint64(99), msg.Response.ID)
	assert.Equal(t, http.StatusNotFound, msg.Response.Status)
}
