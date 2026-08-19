package signal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

func TestClient_Send_PlaintextFallback(t *testing.T) {
	// Server returns 404 for key bundle so crypto falls back to plaintext.
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/keys/"):
			// No pre-key bundle → ensureSession fails → plaintext fallback.
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/messages/"):
			gotPath = r.URL.Path
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": false})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	result, err := c.Send(context.Background(), "recipient-uuid", "Hello, Signal!", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if result.Timestamp == 0 {
		t.Error("expected non-zero timestamp")
	}
	if gotPath != "/v1/messages/recipient-uuid" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestClient_Send_WithGroupID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			http.Error(w, "not found", http.StatusNotFound)
		case r.Method == http.MethodPut:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": true})
		}
	}))
	defer srv.Close()

	ms := &mockStore{}
	c := newTestClient(t, srv.URL, ms)
	result, err := c.Send(context.Background(), "recipient", "Hi group!", &SendOptions{GroupID: "group-abc"})
	if err != nil {
		t.Fatalf("Send with group: %v", err)
	}
	if !result.NeedsSync {
		t.Error("expected NeedsSync=true")
	}
}

func TestClient_Send_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.Send(context.Background(), "recipient", "Hello", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_Receive_Empty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{}, "more": false})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	msgs, err := c.Receive(context.Background(), nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestClient_Receive_WithPlaintextMessages(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("hello from sender"))
	var deleteCallCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages":
			messages := []ReceivedMessage{
				{
					Type:      8, // PlaintextContent
					Content:   encoded,
					Source:    "sender-uuid",
					GUID:      "msg-guid-1",
					Timestamp: 1234567890,
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages, "more": false})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/messages/uuid/"):
			deleteCallCount++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	msgs, err := c.Receive(context.Background(), nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Source != "sender-uuid" {
		t.Errorf("Source = %q", msgs[0].Source)
	}
	if deleteCallCount != 1 {
		t.Errorf("expected 1 DELETE (ACK), got %d", deleteCallCount)
	}
}

func TestClient_Receive_WithReceiveOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"messages": []any{}, "more": false})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	opts := &ReceiveOptions{Timeout: 30, IgnoreAttachments: true}
	msgs, err := c.Receive(context.Background(), opts)
	if err != nil {
		t.Fatalf("Receive with opts: %v", err)
	}
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages, got %d", len(msgs))
	}
}

func TestClient_Receive_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.Receive(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SendReaction_Success(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		var envelope struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		if len(envelope.Messages) > 0 {
			data, _ := base64.StdEncoding.DecodeString(envelope.Messages[0].Content)
			_ = json.Unmarshal(data, &gotBody)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	reaction := Reaction{Emoji: "👍", Author: "sender", Timestamp: 12345}
	if err := c.SendReaction(context.Background(), "recipient", reaction); err != nil {
		t.Fatalf("SendReaction: %v", err)
	}
}

func TestClient_SendReaction_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SendReaction(context.Background(), "r", Reaction{Emoji: "🔥"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SendReceipt_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.SendReceipt(context.Background(), "recipient", "READ", []int64{1000, 2000})
	if err != nil {
		t.Fatalf("SendReceipt: %v", err)
	}
}

func TestClient_SendReceipt_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SendReceipt(context.Background(), "r", "READ", []int64{1}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SendTyping_Start(t *testing.T) {
	var gotContent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		if len(envelope.Messages) > 0 {
			data, _ := base64.StdEncoding.DecodeString(envelope.Messages[0].Content)
			_ = json.Unmarshal(data, &gotContent)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SendTyping(context.Background(), "recipient", false); err != nil {
		t.Fatalf("SendTyping start: %v", err)
	}
	if typing, ok := gotContent["typingMessage"].(map[string]any); ok {
		if typing["action"] != "STARTED" {
			t.Errorf("action = %q", typing["action"])
		}
	}
}

func TestClient_SendTyping_Stop(t *testing.T) {
	var gotContent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var envelope struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		if len(envelope.Messages) > 0 {
			data, _ := base64.StdEncoding.DecodeString(envelope.Messages[0].Content)
			_ = json.Unmarshal(data, &gotContent)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SendTyping(context.Background(), "recipient", true); err != nil {
		t.Fatalf("SendTyping stop: %v", err)
	}
	if typing, ok := gotContent["typingMessage"].(map[string]any); ok {
		if typing["action"] != "STOPPED" {
			t.Errorf("action = %q", typing["action"])
		}
	}
}

func TestClient_RemoteDelete_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.RemoteDelete(context.Background(), "recipient", 1234567890); err != nil {
		t.Fatalf("RemoteDelete: %v", err)
	}
}

func TestClient_RemoteDelete_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.RemoteDelete(context.Background(), "r", 123); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_Send_EncryptedPath(t *testing.T) {
	// Generate a real prekey bundle for the recipient so ProcessBundle succeeds.
	identityKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair identity: %v", err)
	}
	identityPub := identityKP.PublicKey().Serialize() // 33 bytes

	signedPKKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair signedPK: %v", err)
	}
	signedPKPub := signedPKKP.PublicKey().Serialize() // 33 bytes

	// Sign the signed-pre-key with the identity private key (Signal protocol).
	sig, err := ecc.CalculateSignature(identityKP.PrivateKey(), signedPKPub)
	if err != nil {
		t.Fatalf("CalculateSignature: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v2/keys/"):
			// Return a valid prekey bundle; ProcessBundle will verify the signature.
			bundle := map[string]any{
				"identityKey": base64.StdEncoding.EncodeToString(identityPub),
				"devices": []any{
					map[string]any{
						"deviceId":       1,
						"registrationId": 1234,
						"signedPreKey": map[string]any{
							"keyId":     1,
							"publicKey": base64.StdEncoding.EncodeToString(signedPKPub),
							"signature": base64.StdEncoding.EncodeToString(sig[:]),
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(bundle)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/v1/messages/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": false})
		default:
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Client needs credentials so localAddress() can build a SignalAddress.
	creds := &Credentials{UUID: "sender-uuid", DeviceID: 1, Password: mustSecurePassword("pw")}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms)

	result, err := c.Send(context.Background(), "recipient-uuid", "hello encrypted", nil)
	if err != nil {
		t.Fatalf("Send (encrypted path): %v", err)
	}
	if result.Timestamp == 0 {
		t.Error("expected non-zero timestamp")
	}
}

func TestClient_Send_EncryptedPath_WithPreKey(t *testing.T) {
	// Same as above but also includes an optional one-time pre-key in the bundle,
	// exercising the dev.PreKey != nil branch in ensureSession.
	identityKP, _ := ecc.GenerateKeyPair()
	identityPub := identityKP.PublicKey().Serialize()

	signedPKKP, _ := ecc.GenerateKeyPair()
	signedPKPub := signedPKKP.PublicKey().Serialize()
	sig, _ := ecc.CalculateSignature(identityKP.PrivateKey(), signedPKPub)

	oneTimePKKP, _ := ecc.GenerateKeyPair()
	oneTimePKPub := oneTimePKKP.PublicKey().Serialize()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/v2/keys/"):
			bundle := map[string]any{
				"identityKey": base64.StdEncoding.EncodeToString(identityPub),
				"devices": []any{
					map[string]any{
						"deviceId":       1,
						"registrationId": 5678,
						"signedPreKey": map[string]any{
							"keyId":     2,
							"publicKey": base64.StdEncoding.EncodeToString(signedPKPub),
							"signature": base64.StdEncoding.EncodeToString(sig[:]),
						},
						"preKey": map[string]any{
							"keyId":     10,
							"publicKey": base64.StdEncoding.EncodeToString(oneTimePKPub),
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(bundle)
		case r.Method == http.MethodPut:
			_ = json.NewEncoder(w).Encode(map[string]any{"needsSync": true})
		}
	}))
	defer srv.Close()

	creds := &Credentials{UUID: "alice-uuid", DeviceID: 2, Password: mustSecurePassword("pw2")}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms)

	result, err := c.Send(context.Background(), "bob-uuid", "hello with prekey", nil)
	if err != nil {
		t.Fatalf("Send with one-time prekey: %v", err)
	}
	_ = result
}

func TestClient_Receive_WithPreKeyTypeMessage(t *testing.T) {
	// Server returns a PREKEY_TYPE (3) message. decryptMessage will be called but
	// fail gracefully because the content is not a real pre-key message.
	garbage := base64.StdEncoding.EncodeToString([]byte("not-a-real-prekey-message"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages":
			messages := []ReceivedMessage{{
				Type:         protocol.PREKEY_TYPE,
				Content:      garbage,
				Source:       "sender-uuid",
				SourceDevice: 1,
				GUID:         "",
				Timestamp:    1234567890,
			}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages, "more": false})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	// Credentials are required for decryptMessage's localAddress() call.
	creds := &Credentials{UUID: "me-uuid", DeviceID: 1, Password: mustSecurePassword("pw")}
	c := newTestClientWithCreds(t, srv.URL, creds)

	msgs, err := c.Receive(context.Background(), nil)
	if err != nil {
		t.Fatalf("Receive with PREKEY_TYPE: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	// Body is empty because decryptMessage failed on garbage content.
}

func TestClient_Receive_WithWhisperTypeMessage(t *testing.T) {
	// Server returns a WHISPER_TYPE (2) message with garbage content.
	garbage := base64.StdEncoding.EncodeToString([]byte("not-a-real-whisper-message"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/messages" {
			messages := []ReceivedMessage{{
				Type:         protocol.WHISPER_TYPE,
				Content:      garbage,
				Source:       "sender-uuid",
				SourceDevice: 1,
			}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": messages, "more": false})
		}
	}))
	defer srv.Close()

	creds := &Credentials{UUID: "receiver-uuid", DeviceID: 1, Password: mustSecurePassword("pw")}
	c := newTestClientWithCreds(t, srv.URL, creds)

	msgs, err := c.Receive(context.Background(), nil)
	if err != nil {
		t.Fatalf("Receive with WHISPER_TYPE: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
}

func TestMarshalJSON_Map(t *testing.T) {
	data, err := marshalJSON(map[string]any{"key": "value", "num": 42})
	if err != nil {
		t.Fatalf("marshalJSON: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty JSON output")
	}
}

func TestMarshalJSON_Struct(t *testing.T) {
	type S struct{ Name string }
	data, err := marshalJSON(S{Name: "test"})
	if err != nil {
		t.Fatalf("marshalJSON struct: %v", err)
	}
	if !strings.Contains(string(data), "test") {
		t.Errorf("output = %s", data)
	}
}

func TestClient_Receive_WithGUIDMessage(t *testing.T) {
	// Server returns a message with a non-empty GUID.  Receive should issue a
	// DELETE /v1/messages/uuid/<guid> ACK, covering that branch.
	var deleteCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/messages":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"messages": []any{
					map[string]any{
						"type":      0,
						"source":    "sender-uuid",
						"content":   base64.StdEncoding.EncodeToString([]byte("hello")),
						"timestamp": 1234567890,
						"guid":      "test-guid-abc",
					},
				},
				"more": false,
			})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "test-guid-abc"):
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	msgs, err := c.Receive(context.Background(), nil)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if !deleteCalled {
		t.Error("expected DELETE ACK for non-empty GUID")
	}
}
