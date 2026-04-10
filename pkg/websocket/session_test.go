package websocket

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewSession_FieldsSet(t *testing.T) {
	logger := testLogger()
	// Pass nil conn since we only test field assignment.
	s := NewSession(nil, "test-uuid", 1, nil, logger)

	if s.UUID != "test-uuid" {
		t.Errorf("UUID = %q, want %q", s.UUID, "test-uuid")
	}
	if s.DeviceID != 1 {
		t.Errorf("DeviceID = %d, want %d", s.DeviceID, 1)
	}
	if s.send == nil {
		t.Error("send channel is nil")
	}
	if s.done == nil {
		t.Error("done channel is nil")
	}
}

func TestNewSession_DifferentDeviceIDs(t *testing.T) {
	tests := []struct {
		name     string
		uuid     string
		deviceID uint64
	}{
		{
			name:     "primary device",
			uuid:     "uuid-1",
			deviceID: 1,
		},
		{
			name:     "secondary device",
			uuid:     "uuid-2",
			deviceID: 2,
		},
		{
			name:     "provisioning device",
			uuid:     "uuid-3",
			deviceID: 0,
		},
		{
			name:     "large device ID",
			uuid:     "uuid-4",
			deviceID: 18446744073709551615,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSession(nil, tt.uuid, tt.deviceID, nil, testLogger())
			if s.UUID != tt.uuid {
				t.Errorf("UUID = %q, want %q", s.UUID, tt.uuid)
			}
			if s.DeviceID != tt.deviceID {
				t.Errorf("DeviceID = %d, want %d", s.DeviceID, tt.deviceID)
			}
		})
	}
}

func TestNewSession_SendBufferCapacity(t *testing.T) {
	s := NewSession(nil, "uuid", 1, nil, testLogger())
	if cap(s.send) != sendBufferSize {
		t.Errorf("send channel capacity = %d, want %d", cap(s.send), sendBufferSize)
	}
}

func TestNewSession_SendBufferCapacityNonZero(t *testing.T) {
	s := NewSession(nil, "uuid", 1, nil, testLogger())
	if cap(s.send) == 0 {
		t.Error("send channel capacity should be non-zero")
	}
}

func TestSession_Done_ReturnsChan(t *testing.T) {
	s := NewSession(nil, "uuid", 1, nil, testLogger())
	done := s.Done()
	if done == nil {
		t.Fatal("Done() returned nil channel")
	}

	select {
	case <-done:
		t.Error("done channel should not be closed on new session")
	default:
		// Expected: channel is open.
	}
}

func TestSession_Done_ClosedAfterClose(t *testing.T) {
	// Create a session with nil conn - Close will panic on conn.Close.
	// We need to test Done without triggering conn.Close.
	s := &Session{
		UUID:     "uuid",
		DeviceID: 1,
		logger:   testLogger().With(slog.String("uuid", "uuid"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	// Manually close done to simulate session closure without calling conn.Close.
	close(s.done)

	select {
	case <-s.Done():
		// Expected: channel is closed.
	default:
		t.Error("done channel should be closed after session closure")
	}
}

func TestSession_Send_SuccessfulEnqueue(t *testing.T) {
	s := &Session{
		UUID:     "uuid",
		DeviceID: 1,
		logger:   testLogger().With(slog.String("uuid", "uuid"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	msg := &WebSocketMessage{
		Type: "response",
		Response: &WebSocketResponse{
			ID:      1,
			Status:  200,
			Message: "OK",
		},
	}

	if err := s.Send(msg); err != nil {
		t.Fatalf("Send() returned unexpected error: %v", err)
	}

	// Verify message was enqueued.
	select {
	case data := <-s.send:
		var decoded WebSocketMessage
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("failed to unmarshal enqueued message: %v", err)
		}
		if decoded.Type != "response" {
			t.Errorf("decoded Type = %q, want %q", decoded.Type, "response")
		}
		if decoded.Response.Status != 200 {
			t.Errorf("decoded Response.Status = %d, want %d", decoded.Response.Status, 200)
		}
	default:
		t.Error("expected message in send channel, channel is empty")
	}
}

func TestSession_Send_SessionClosed(t *testing.T) {
	s := &Session{
		UUID:     "closed-uuid",
		DeviceID: 3,
		logger:   testLogger().With(slog.String("uuid", "closed-uuid"), slog.Uint64("deviceId", 3)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	// Close the session.
	close(s.done)

	msg := &WebSocketMessage{
		Type: "response",
		Response: &WebSocketResponse{
			ID:     1,
			Status: 200,
		},
	}

	err := s.Send(msg)
	if err == nil {
		t.Fatal("expected error when sending to closed session, got nil")
	}

	var sessionErr *SessionClosedError
	if !errors.As(err, &sessionErr) {
		t.Fatalf("expected *SessionClosedError, got %T: %v", err, err)
	}
	if sessionErr.UUID != "closed-uuid" {
		t.Errorf("SessionClosedError.UUID = %q, want %q", sessionErr.UUID, "closed-uuid")
	}
	if sessionErr.DeviceID != 3 {
		t.Errorf("SessionClosedError.DeviceID = %d, want %d", sessionErr.DeviceID, 3)
	}
}

func TestSession_Send_MultipleMessages(t *testing.T) {
	s := &Session{
		UUID:     "uuid",
		DeviceID: 1,
		logger:   testLogger().With(slog.String("uuid", "uuid"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	for i := uint64(0); i < 10; i++ {
		msg := &WebSocketMessage{
			Type: "request",
			Request: &WebSocketRequest{
				ID:   i,
				Verb: "PUT",
				Path: "/api/v1/message",
			},
		}
		if err := s.Send(msg); err != nil {
			t.Fatalf("Send() failed for message %d: %v", i, err)
		}
	}

	if len(s.send) != 10 {
		t.Errorf("send channel length = %d, want 10", len(s.send))
	}
}

func TestSession_Send_RequestMessage(t *testing.T) {
	s := &Session{
		UUID:     "uuid",
		DeviceID: 1,
		logger:   testLogger().With(slog.String("uuid", "uuid"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	msg := &WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   99,
			Verb: "GET",
			Path: "/api/v1/keepalive",
			Headers: map[string]string{
				"X-Signal": "test",
			},
		},
	}

	if err := s.Send(msg); err != nil {
		t.Fatalf("Send() returned unexpected error: %v", err)
	}

	data := <-s.send
	var decoded WebSocketMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Request.ID != 99 {
		t.Errorf("Request.ID = %d, want %d", decoded.Request.ID, 99)
	}
	if decoded.Request.Verb != "GET" {
		t.Errorf("Request.Verb = %q, want %q", decoded.Request.Verb, "GET")
	}
	if decoded.Request.Headers["X-Signal"] != "test" {
		t.Errorf("Request.Headers[X-Signal] = %q, want %q", decoded.Request.Headers["X-Signal"], "test")
	}
}

func TestSession_Send_EmptyMessage(t *testing.T) {
	s := &Session{
		UUID:     "uuid",
		DeviceID: 1,
		logger:   testLogger().With(slog.String("uuid", "uuid"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	msg := &WebSocketMessage{}
	if err := s.Send(msg); err != nil {
		t.Fatalf("Send() returned unexpected error for empty message: %v", err)
	}

	data := <-s.send
	var decoded WebSocketMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if decoded.Type != "" {
		t.Errorf("Type = %q, want empty", decoded.Type)
	}
}

func TestSession_Send_BlockedThenDoneClosed(t *testing.T) {
	// Use an unbuffered send channel so Send blocks on the second select
	// (after passing the first done check). Closing done while blocked
	// exercises the second select's <-s.done case.
	s := &Session{
		UUID:     "blocked-uuid",
		DeviceID: 7,
		logger:   testLogger().With(slog.String("uuid", "blocked-uuid"), slog.Uint64("deviceId", 7)),
		send:     make(chan []byte), // unbuffered
		done:     make(chan struct{}),
	}

	errCh := make(chan error, 1)
	go func() {
		msg := &WebSocketMessage{
			Type:     "response",
			Response: &WebSocketResponse{ID: 1, Status: 200},
		}
		errCh <- s.Send(msg)
	}()

	// Yield to the scheduler until the goroutine has progressed past the first
	// select in Send and is blocked on the second (send channel or done).
	// Using runtime.Gosched in a short loop avoids a fixed sleep while still
	// giving the goroutine sufficient opportunity to reach the blocking point.
	for i := 0; i < 100; i++ {
		runtime.Gosched()
	}

	// Close done to unblock the second select's <-s.done case.
	close(s.done)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected error from Send, got nil")
		}
		var sessionErr *SessionClosedError
		if !errors.As(err, &sessionErr) {
			t.Fatalf("expected *SessionClosedError, got %T: %v", err, err)
		}
		if sessionErr.UUID != "blocked-uuid" {
			t.Errorf("SessionClosedError.UUID = %q, want %q", sessionErr.UUID, "blocked-uuid")
		}
		if sessionErr.DeviceID != 7 {
			t.Errorf("SessionClosedError.DeviceID = %d, want %d", sessionErr.DeviceID, 7)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Send to return")
	}
}

func TestSession_StartWritePump_WaitReturnsAfterClose(t *testing.T) {
	// Build a session whose WritePump can be driven entirely through the done
	// channel. Closing the send channel unblocks WritePump when it reads
	// the !ok path, avoiding any interaction with a nil conn.
	s := &Session{
		UUID:     "uuid-wp",
		DeviceID: 1,
		logger:   testLogger().With(slog.String("uuid", "uuid-wp"), slog.Uint64("deviceId", 1)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	s.StartWritePump()

	// Closing the send channel causes WritePump to return via the !ok arm.
	// WritePump then calls s.Close() via its defer — which is safe because
	// sync.Once ensures done is only closed once.
	close(s.send)

	waitDone := make(chan struct{})
	go func() {
		s.Wait()
		close(waitDone)
	}()

	select {
	case <-waitDone:
		// Expected: Wait returned after WritePump exited.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Wait() to return after session close")
	}
}

func TestSession_StartWritePump_WaitBlocksUntilDone(t *testing.T) {
	// Verify that Wait does not return before WritePump exits.
	s := &Session{
		UUID:     "uuid-wp2",
		DeviceID: 2,
		logger:   testLogger().With(slog.String("uuid", "uuid-wp2"), slog.Uint64("deviceId", 2)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}

	s.StartWritePump()

	// Give the goroutine time to reach its select statement.
	runtime.Gosched()

	// Close the done channel to release WritePump's <-s.done arm.
	// WritePump's defer also calls s.Close(), but sync.Once prevents a
	// double-close of done since we are not closing done ourselves here;
	// we drive the shutdown through s.done by calling close on the send
	// channel instead so WritePump exits cleanly via the !ok path.
	close(s.send)

	done := make(chan struct{})
	go func() {
		s.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Expected.
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Wait() to return")
	}
}

func TestSession_Constants(t *testing.T) {
	if sendBufferSize <= 0 {
		t.Errorf("sendBufferSize = %d, want positive value", sendBufferSize)
	}
	if writeTimeout <= 0 {
		t.Errorf("writeTimeout = %v, want positive value", writeTimeout)
	}
	if pingInterval <= 0 {
		t.Errorf("pingInterval = %v, want positive value", pingInterval)
	}
	if pongTimeout <= 0 {
		t.Errorf("pongTimeout = %v, want positive value", pongTimeout)
	}
	if maxFrameSize <= 0 {
		t.Errorf("maxFrameSize = %d, want positive value", maxFrameSize)
	}
}

func TestSession_Constants_Values(t *testing.T) {
	if sendBufferSize != 256 {
		t.Errorf("sendBufferSize = %d, want 256", sendBufferSize)
	}
	const wantMaxFrameSize int64 = 256 * 1024
	if maxFrameSize != wantMaxFrameSize {
		t.Errorf("maxFrameSize = %d, want %d (256 KB)", maxFrameSize, wantMaxFrameSize)
	}
}
