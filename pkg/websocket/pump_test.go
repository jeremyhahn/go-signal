package websocket

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	ws "github.com/coder/websocket"
)

func pumpTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func dialTestWS(t *testing.T, url string) *ws.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wsURL := "ws" + strings.TrimPrefix(url, "http")
	conn, _, err := ws.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("failed to dial websocket: %v", err)
	}
	return conn
}

// setupWSPair creates a connected pair: a server conn held by a Session and
// a client conn for the test to interact with. The session runs on the server
// side of the httptest server.
func setupWSPair(t *testing.T, serverHandler func(serverConn *ws.Conn)) (*ws.Conn, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, nil)
		if err != nil {
			return
		}
		serverHandler(conn)
	}))
	clientConn := dialTestWS(t, srv.URL)
	return clientConn, srv
}

func TestReadPump_ReceivesValidMessages(t *testing.T) {
	var received []*WebSocketMessage
	var mu sync.Mutex
	readDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "read-uuid", 1, nil, pumpTestLogger())
		session.ReadPump(func(msg *WebSocketMessage) {
			mu.Lock()
			received = append(received, msg)
			mu.Unlock()
		})
		close(readDone)
	})
	defer srv.Close()

	// Send a valid message from the client.
	msg := WebSocketMessage{Type: "request", Request: &WebSocketRequest{ID: 1, Verb: "GET", Path: "/test"}}
	data, _ := json.Marshal(msg)
	ctx := context.Background()
	if err := clientConn.Write(ctx, ws.MessageText, data); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	// Close client connection to make ReadPump exit.
	if err := clientConn.Close(ws.StatusNormalClosure, "done"); err != nil {
		t.Logf("clientConn.Close: %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ReadPump to finish")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 received message, got %d", len(received))
	}
	if received[0].Type != "request" {
		t.Errorf("Type = %q, want %q", received[0].Type, "request")
	}
	if received[0].Request.ID != 1 {
		t.Errorf("Request.ID = %d, want 1", received[0].Request.ID)
	}
}

func TestReadPump_InvalidJSONContinues(t *testing.T) {
	var received []*WebSocketMessage
	var mu sync.Mutex
	readDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "read-uuid", 1, nil, pumpTestLogger())
		session.ReadPump(func(msg *WebSocketMessage) {
			mu.Lock()
			received = append(received, msg)
			mu.Unlock()
		})
		close(readDone)
	})
	defer srv.Close()

	ctx := context.Background()

	// Send invalid JSON.
	if err := clientConn.Write(ctx, ws.MessageText, []byte("{invalid")); err != nil {
		t.Fatalf("failed to write invalid json: %v", err)
	}

	// Send valid message.
	msg := WebSocketMessage{Type: "response", Response: &WebSocketResponse{ID: 2, Status: 200}}
	data, _ := json.Marshal(msg)
	if err := clientConn.Write(ctx, ws.MessageText, data); err != nil {
		t.Fatalf("failed to write valid message: %v", err)
	}

	// Close to end the test.
	if err := clientConn.Close(ws.StatusNormalClosure, "done"); err != nil {
		t.Logf("clientConn.Close: %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 message (invalid skipped), got %d", len(received))
	}
	if received[0].Type != "response" {
		t.Errorf("Type = %q, want %q", received[0].Type, "response")
	}
}

func TestReadPump_ExitsOnConnectionClose(t *testing.T) {
	readDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "read-uuid", 1, nil, pumpTestLogger())
		session.ReadPump(func(msg *WebSocketMessage) {
			t.Error("unexpected message received")
		})
		close(readDone)
	})
	defer srv.Close()

	// Close immediately.
	if err := clientConn.Close(ws.StatusNormalClosure, "bye"); err != nil {
		t.Logf("clientConn.Close: %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestReadPump_MultipleMessages(t *testing.T) {
	var received []*WebSocketMessage
	var mu sync.Mutex
	readDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "read-uuid", 1, nil, pumpTestLogger())
		session.ReadPump(func(msg *WebSocketMessage) {
			mu.Lock()
			received = append(received, msg)
			mu.Unlock()
		})
		close(readDone)
	})
	defer srv.Close()

	ctx := context.Background()
	for i := uint64(0); i < 5; i++ {
		msg := WebSocketMessage{
			Type:    "request",
			Request: &WebSocketRequest{ID: i, Verb: "PUT", Path: "/api/v1/message"},
		}
		data, _ := json.Marshal(msg)
		if err := clientConn.Write(ctx, ws.MessageText, data); err != nil {
			t.Fatalf("failed to write message %d: %v", i, err)
		}
	}

	if err := clientConn.Close(ws.StatusNormalClosure, "done"); err != nil {
		t.Logf("clientConn.Close: %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 5 {
		t.Fatalf("expected 5 messages, got %d", len(received))
	}
}

func TestWritePump_SendsQueuedMessages(t *testing.T) {
	clientReceived := make(chan []byte, 10)
	writeDone := make(chan struct{})
	// msgDelivered is closed by the client reader once the first message arrives,
	// letting the server goroutine close the session without a fixed sleep.
	msgDelivered := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "write-uuid", 1, nil, pumpTestLogger())

		// Enqueue message before starting WritePump.
		msg := &WebSocketMessage{
			Type:    "request",
			Request: &WebSocketRequest{ID: 1, Verb: "PUT", Path: "/api/v1/message"},
		}
		if err := session.Send(msg); err != nil {
			t.Errorf("Send failed: %v", err)
			return
		}

		// Close after message delivery is confirmed to stop WritePump.
		go func() {
			select {
			case <-msgDelivered:
			case <-time.After(5 * time.Second):
			}
			session.Close()
		}()

		session.WritePump()
		close(writeDone)
	})
	defer srv.Close()

	// Read on client side.
	go func() {
		for {
			_, data, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
			clientReceived <- data
			// Signal delivery of the first message so the server can close.
			select {
			case <-msgDelivered:
			default:
				close(msgDelivered)
			}
		}
	}()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	select {
	case data := <-clientReceived:
		// NewSession defaults to FrameFormatProtobuf, so WritePump sends
		// binary protobuf frames. Unmarshal accordingly.
		msg, err := UnmarshalFrame(data, FrameFormatProtobuf)
		if err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}
		if msg.Request == nil {
			t.Fatal("Request is nil")
		}
		if msg.Request.ID != 1 {
			t.Errorf("Request.ID = %d, want 1", msg.Request.ID)
		}
	default:
		t.Error("expected message from WritePump")
	}
}

func TestWritePump_MultipleMessages(t *testing.T) {
	clientReceived := make(chan []byte, 20)
	writeDone := make(chan struct{})
	const messageCount = 5
	// allDelivered is closed when all messageCount messages have been received
	// by the client, allowing the server goroutine to close the session.
	allDelivered := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "write-uuid", 1, nil, pumpTestLogger())

		for i := 0; i < messageCount; i++ {
			msg := &WebSocketMessage{
				Type:    "request",
				Request: &WebSocketRequest{ID: uint64(i), Verb: "PUT", Path: "/api/v1/message"},
			}
			if err := session.Send(msg); err != nil {
				t.Errorf("Send %d failed: %v", i, err)
				return
			}
		}

		go func() {
			select {
			case <-allDelivered:
			case <-time.After(5 * time.Second):
			}
			session.Close()
		}()

		session.WritePump()
		close(writeDone)
	})
	defer srv.Close()

	go func() {
		received := 0
		for {
			_, data, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
			clientReceived <- data
			received++
			if received >= messageCount {
				select {
				case <-allDelivered:
				default:
					close(allDelivered)
				}
			}
		}
	}()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}

	// Drain all messages received before writeDone.
	select {
	case <-allDelivered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for all messages to be delivered")
	}

	count := len(clientReceived)
	if count != messageCount {
		t.Errorf("received %d messages, want %d", count, messageCount)
	}
}

func TestWritePump_ExitsOnDoneClosed(t *testing.T) {
	writeDone := make(chan struct{})
	// closeReady is closed to signal the server goroutine to close the session.
	// We close it immediately since we just need WritePump to exit on done.
	closeReady := make(chan struct{})
	close(closeReady)

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "write-uuid", 1, nil, pumpTestLogger())

		go func() {
			select {
			case <-closeReady:
			case <-time.After(5 * time.Second):
			}
			session.Close()
		}()

		session.WritePump()
		close(writeDone)
	})
	defer srv.Close()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	// Keep reading on client side so server writes don't block.
	go func() {
		for {
			_, _, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSession_Close_WithConnection(t *testing.T) {
	closeDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "close-uuid", 1, nil, pumpTestLogger())
		session.Close()

		// Verify done channel is closed.
		select {
		case <-session.Done():
		default:
			t.Error("Done() channel should be closed after Close()")
		}

		// Second Close should not panic.
		session.Close()
		close(closeDone)
	})
	defer srv.Close()

	// Client must actively read to allow server-side Close handshake to complete.
	go func() {
		for {
			_, _, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSession_Close_IdempotentWithConnection(t *testing.T) {
	closeDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "close-uuid", 1, nil, pumpTestLogger())

		// Call Close multiple times concurrently.
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				session.Close()
			}()
		}
		wg.Wait()
		close(closeDone)
	})
	defer srv.Close()

	// Client must actively read to allow server-side Close handshake to complete.
	go func() {
		for {
			_, _, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestSession_Send_BufferFull(t *testing.T) {
	s := &Session{
		UUID:     "uuid",
		DeviceID: 1,
		logger:   pumpTestLogger().With(slog.String("uuid", "uuid"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, 1),
		done:     make(chan struct{}),
	}

	// Fill the buffer.
	msg1 := &WebSocketMessage{Type: "request", Request: &WebSocketRequest{ID: 1, Verb: "GET", Path: "/test"}}
	if err := s.Send(msg1); err != nil {
		t.Fatalf("first Send failed: %v", err)
	}

	// Close the session so the second select in Send picks up <-s.done.
	close(s.done)

	msg2 := &WebSocketMessage{Type: "request", Request: &WebSocketRequest{ID: 2, Verb: "GET", Path: "/test"}}
	err := s.Send(msg2)
	if err == nil {
		t.Fatal("expected error when sending to full buffer on closed session")
	}
}

func TestWritePump_ExitsOnSendChannelClosed(t *testing.T) {
	writeDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "write-uuid", 1, nil, pumpTestLogger())

		// Close the send channel so the next receive on s.send yields ok=false.
		close(session.send)

		session.WritePump()
		close(writeDone)
	})
	defer srv.Close()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	// Keep reading on client side so server writes don't block.
	go func() {
		for {
			_, _, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WritePump to exit on closed send channel")
	}
}

func TestWritePump_ExitsOnWriteError(t *testing.T) {
	writeDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "write-uuid", 1, nil, pumpTestLogger())

		// Close the underlying connection before WritePump starts so the
		// first write attempt fails immediately.
		if err := serverConn.Close(ws.StatusGoingAway, "force close"); err != nil {
			t.Logf("serverConn.Close: %v", err)
		}

		// Enqueue a message that WritePump will attempt to write.
		session.send <- []byte(`{"type":"request"}`)

		session.WritePump()
		close(writeDone)
	})
	defer srv.Close()
	defer func() {
		if err := clientConn.Close(ws.StatusNormalClosure, ""); err != nil {
			t.Logf("clientConn.Close: %v", err)
		}
	}()

	// Keep reading on client side to drain any close frames.
	go func() {
		for {
			_, _, err := clientConn.Read(context.Background())
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for WritePump to exit on write error")
	}
}

func TestReadPump_And_WritePump_Together(t *testing.T) {
	var receivedByServer []*WebSocketMessage
	var mu sync.Mutex
	serverDone := make(chan struct{})

	clientConn, srv := setupWSPair(t, func(serverConn *ws.Conn) {
		session := NewSession(serverConn, "combo-uuid", 1, nil, pumpTestLogger())

		go session.WritePump()

		session.ReadPump(func(msg *WebSocketMessage) {
			mu.Lock()
			receivedByServer = append(receivedByServer, msg)
			mu.Unlock()

			// Echo a response.
			if msg.Request != nil {
				resp := &WebSocketMessage{
					Type:     "response",
					Response: &WebSocketResponse{ID: msg.Request.ID, Status: 200, Message: "OK"},
				}
				if err := session.Send(resp); err != nil {
					t.Errorf("session.Send: %v", err)
				}
			}
		})
		close(serverDone)
	})
	defer srv.Close()

	// Send a request.
	reqMsg := WebSocketMessage{Type: "request", Request: &WebSocketRequest{ID: 42, Verb: "GET", Path: "/keepalive"}}
	data, _ := json.Marshal(reqMsg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := clientConn.Write(ctx, ws.MessageText, data); err != nil {
		cancel()
		t.Fatalf("failed to write: %v", err)
	}
	cancel()

	// Read the echoed response.
	readCtx, readCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, respData, err := clientConn.Read(readCtx)
	readCancel()
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	var resp WebSocketMessage
	if err := json.Unmarshal(respData, &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.Response == nil {
		t.Fatal("Response is nil")
	}
	if resp.Response.ID != 42 {
		t.Errorf("Response.ID = %d, want 42", resp.Response.ID)
	}
	if resp.Response.Status != 200 {
		t.Errorf("Response.Status = %d, want 200", resp.Response.Status)
	}

	// Close client to end pumps.
	if err := clientConn.Close(ws.StatusNormalClosure, "done"); err != nil {
		t.Logf("clientConn.Close: %v", err)
	}

	select {
	case <-serverDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pumps to finish")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedByServer) != 1 {
		t.Fatalf("expected 1 server-received message, got %d", len(receivedByServer))
	}
}
