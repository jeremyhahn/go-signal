package websocket

import (
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

func managerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTestSession(uuid string, deviceID uint64) *Session {
	return &Session{
		UUID:     uuid,
		DeviceID: deviceID,
		logger:   managerTestLogger().With(slog.String("uuid", uuid), slog.Uint64("deviceId", deviceID)),
		send:     make(chan []byte, sendBufferSize),
		done:     make(chan struct{}),
	}
}

func TestNewSessionManager_NotNil(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	if m == nil {
		t.Fatal("NewSessionManager returned nil")
	}
}

func TestNewSessionManager_EmptySessions(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	if m.sessions == nil {
		t.Fatal("sessions map is nil")
	}
	if len(m.sessions) != 0 {
		t.Errorf("sessions map length = %d, want 0", len(m.sessions))
	}
}

func TestSessionManager_Register_NewSession(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)

	m.Register(s)

	if !m.HasActiveSession("uuid-1", 1) {
		t.Error("expected session to be active after Register")
	}
}

func TestSessionManager_Register_ReplacesExisting(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s1 := newTestSession("uuid-1", 1)
	s2 := newTestSession("uuid-1", 1)

	m.Register(s1)
	m.Register(s2)

	// s1 should be closed.
	select {
	case <-s1.Done():
		// Expected: old session was closed.
	default:
		t.Error("expected old session to be closed after replacement")
	}

	got := m.GetSession("uuid-1", 1)
	if got != s2 {
		t.Error("expected GetSession to return the new session")
	}
}

func TestSessionManager_Register_DifferentDevices(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s1 := newTestSession("uuid-1", 1)
	s2 := newTestSession("uuid-1", 2)

	m.Register(s1)
	m.Register(s2)

	if !m.HasActiveSession("uuid-1", 1) {
		t.Error("expected device 1 session to be active")
	}
	if !m.HasActiveSession("uuid-1", 2) {
		t.Error("expected device 2 session to be active")
	}
}

func TestSessionManager_Register_DifferentAccounts(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s1 := newTestSession("uuid-1", 1)
	s2 := newTestSession("uuid-2", 1)

	m.Register(s1)
	m.Register(s2)

	if !m.HasActiveSession("uuid-1", 1) {
		t.Error("expected uuid-1 session to be active")
	}
	if !m.HasActiveSession("uuid-2", 1) {
		t.Error("expected uuid-2 session to be active")
	}
}

func TestSessionManager_Unregister_ExistingSession(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)

	m.Register(s)
	m.Unregister(s)

	if m.HasActiveSession("uuid-1", 1) {
		t.Error("expected session to be inactive after Unregister")
	}
}

func TestSessionManager_Unregister_NonExistentSession(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)

	// Unregister without Register should not panic.
	m.Unregister(s)

	if m.HasActiveSession("uuid-1", 1) {
		t.Error("expected no active session for unregistered session")
	}
}

func TestSessionManager_Unregister_SkipsReplacement(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s1 := newTestSession("uuid-1", 1)
	s2 := newTestSession("uuid-1", 1)

	m.Register(s1)
	m.Register(s2) // replaces s1

	// Unregistering s1 should not remove s2.
	m.Unregister(s1)

	if !m.HasActiveSession("uuid-1", 1) {
		t.Error("expected session to remain active (s2 should not be removed by unregistering s1)")
	}

	got := m.GetSession("uuid-1", 1)
	if got != s2 {
		t.Error("expected GetSession to return s2 after unregistering s1")
	}
}

func TestSessionManager_DeliverMessage_ActiveSession(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)

	envelope := &messages.Envelope{
		ID:              42,
		Type:            messages.EnvelopeTypeCiphertext,
		SourceUUID:      "sender-uuid",
		DestinationUUID: "uuid-1",
		Content:         []byte("encrypted-data"),
	}

	ok := m.DeliverMessage("uuid-1", 1, envelope)
	if !ok {
		t.Error("DeliverMessage returned false for active session")
	}

	// Verify a message was enqueued.
	select {
	case data := <-s.send:
		if len(data) == 0 {
			t.Error("enqueued message is empty")
		}
	default:
		t.Error("expected message in send channel")
	}
}

func TestSessionManager_DeliverMessage_NoActiveSession(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	envelope := &messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypeCiphertext,
		DestinationUUID: "nonexistent-uuid",
	}

	ok := m.DeliverMessage("nonexistent-uuid", 1, envelope)
	if ok {
		t.Error("DeliverMessage returned true for non-existent session")
	}
}

func TestSessionManager_DeliverMessage_ClosedSession(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)

	// Close the session.
	close(s.done)

	envelope := &messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypeCiphertext,
		DestinationUUID: "uuid-1",
	}

	ok := m.DeliverMessage("uuid-1", 1, envelope)
	if ok {
		t.Error("DeliverMessage returned true for closed session")
	}
}

func TestSessionManager_HasActiveSession_Exists(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)

	if !m.HasActiveSession("uuid-1", 1) {
		t.Error("HasActiveSession returned false for registered session")
	}
}

func TestSessionManager_HasActiveSession_NotExists(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	if m.HasActiveSession("uuid-1", 1) {
		t.Error("HasActiveSession returned true for non-existent session")
	}
}

func TestSessionManager_HasActiveSession_WrongDevice(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)

	if m.HasActiveSession("uuid-1", 2) {
		t.Error("HasActiveSession returned true for wrong device ID")
	}
}

func TestSessionManager_HasActiveSession_WrongUUID(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)

	if m.HasActiveSession("uuid-2", 1) {
		t.Error("HasActiveSession returned true for wrong UUID")
	}
}

func TestSessionManager_GetSession_Exists(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)

	got := m.GetSession("uuid-1", 1)
	if got != s {
		t.Error("GetSession did not return the registered session")
	}
}

func TestSessionManager_GetSession_NotExists(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	got := m.GetSession("uuid-1", 1)
	if got != nil {
		t.Errorf("GetSession returned %v, want nil for non-existent session", got)
	}
}

func TestSessionManager_GetSession_AfterUnregister(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	s := newTestSession("uuid-1", 1)
	m.Register(s)
	m.Unregister(s)

	got := m.GetSession("uuid-1", 1)
	if got != nil {
		t.Errorf("GetSession returned %v, want nil after unregister", got)
	}
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	m := NewSessionManager(managerTestLogger())
	var wg sync.WaitGroup

	// Concurrent registration.
	for i := uint64(0); i < 50; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			s := newTestSession("uuid-concurrent", id)
			m.Register(s)
		}(i)
	}
	wg.Wait()

	// Concurrent reads.
	for i := uint64(0); i < 50; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			m.HasActiveSession("uuid-concurrent", id)
			m.GetSession("uuid-concurrent", id)
		}(i)
	}
	wg.Wait()

	// Concurrent unregistration.
	for i := uint64(0); i < 50; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			s := m.GetSession("uuid-concurrent", id)
			if s != nil {
				m.Unregister(s)
			}
		}(i)
	}
	wg.Wait()
}

func TestSessionManager_ConcurrentDeliverMessage(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	// Register sessions for multiple devices.
	sessions := make([]*Session, 10)
	for i := range sessions {
		sessions[i] = newTestSession("uuid-deliver", uint64(i))
		m.Register(sessions[i])
	}

	var wg sync.WaitGroup
	for i := uint64(0); i < 10; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			env := &messages.Envelope{
				ID:              id,
				Type:            messages.EnvelopeTypeCiphertext,
				DestinationUUID: "uuid-deliver",
			}
			m.DeliverMessage("uuid-deliver", id, env)
		}(i)
	}
	wg.Wait()
}

func TestBuildDeliveryMessage_Structure(t *testing.T) {
	envelope := &messages.Envelope{
		ID:              42,
		Type:            messages.EnvelopeTypeCiphertext,
		SourceUUID:      "sender",
		DestinationUUID: "dest",
		Content:         []byte("content"),
	}

	msg := buildDeliveryMessage(envelope)

	if msg.Type != "request" {
		t.Errorf("Type = %q, want %q", msg.Type, "request")
	}
	if msg.Request == nil {
		t.Fatal("Request is nil")
	}
	if msg.Request.ID != 42 {
		t.Errorf("Request.ID = %d, want %d", msg.Request.ID, 42)
	}
	if msg.Request.Verb != "PUT" {
		t.Errorf("Request.Verb = %q, want %q", msg.Request.Verb, "PUT")
	}
	if msg.Request.Path != "/api/v1/message" {
		t.Errorf("Request.Path = %q, want %q", msg.Request.Path, "/api/v1/message")
	}
	if msg.Request.Body == "" {
		t.Error("Request.Body is empty")
	}
	if msg.Response != nil {
		t.Error("Response should be nil")
	}
}

func TestBuildDeliveryMessage_EnvelopeBodyEncoded(t *testing.T) {
	envelope := &messages.Envelope{
		ID:              1,
		Type:            messages.EnvelopeTypePrekeyBundle,
		SourceUUID:      "src",
		DestinationUUID: "dst",
	}

	msg := buildDeliveryMessage(envelope)

	// Body should be base64-encoded JSON.
	if msg.Request.Body == "" {
		t.Fatal("body is empty")
	}

	// Verify the body matches encodeEnvelopeBody output.
	expected := encodeEnvelopeBody(envelope)
	if msg.Request.Body != expected {
		t.Errorf("body = %q, want %q", msg.Request.Body, expected)
	}
}

func TestSessionManager_CloseAll_ClosesAllSessions(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	s1 := newTestSession("uuid-1", 1)
	s2 := newTestSession("uuid-2", 1)
	s3 := newTestSession("uuid-3", 1)
	m.Register(s1)
	m.Register(s2)
	m.Register(s3)

	m.CloseAll()

	// All sessions must be closed.
	for _, s := range []*Session{s1, s2, s3} {
		select {
		case <-s.Done():
			// Expected.
		default:
			t.Errorf("session uuid=%s deviceID=%d was not closed by CloseAll", s.UUID, s.DeviceID)
		}
	}

	// Map must be cleared.
	if m.HasActiveSession("uuid-1", 1) {
		t.Error("expected no active session for uuid-1 after CloseAll")
	}
	if m.HasActiveSession("uuid-2", 1) {
		t.Error("expected no active session for uuid-2 after CloseAll")
	}
	if m.HasActiveSession("uuid-3", 1) {
		t.Error("expected no active session for uuid-3 after CloseAll")
	}
}

func TestSessionManager_CloseAll_EmptyManager(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	// Must not panic on an empty manager.
	m.CloseAll()

	if m.HasActiveSession("any", 0) {
		t.Error("expected no active sessions after CloseAll on empty manager")
	}
}

func TestSessionManager_CloseAll_FollowedByRegister(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	s1 := newTestSession("uuid-1", 1)
	m.Register(s1)
	m.CloseAll()

	// After CloseAll, registering a new session must succeed.
	s2 := newTestSession("uuid-1", 1)
	m.Register(s2)

	if !m.HasActiveSession("uuid-1", 1) {
		t.Error("expected new session to be active after CloseAll + Register")
	}
	if m.GetSession("uuid-1", 1) != s2 {
		t.Error("expected GetSession to return the newly registered session")
	}
}

func TestSessionManager_CloseAll_ClearsMap(t *testing.T) {
	m := NewSessionManager(managerTestLogger())

	for i := uint64(0); i < 5; i++ {
		m.Register(newTestSession("uuid-bulk", i))
	}

	m.CloseAll()

	m.mu.RLock()
	remaining := len(m.sessions)
	m.mu.RUnlock()

	if remaining != 0 {
		t.Errorf("session map length = %d after CloseAll, want 0", remaining)
	}
}

func TestSessionKey_Equality(t *testing.T) {
	k1 := sessionKey{uuid: "uuid-1", deviceID: 1}
	k2 := sessionKey{uuid: "uuid-1", deviceID: 1}
	k3 := sessionKey{uuid: "uuid-1", deviceID: 2}
	k4 := sessionKey{uuid: "uuid-2", deviceID: 1}

	if k1 != k2 {
		t.Error("expected equal keys to be equal")
	}
	if k1 == k3 {
		t.Error("expected keys with different device IDs to be unequal")
	}
	if k1 == k4 {
		t.Error("expected keys with different UUIDs to be unequal")
	}
}

func TestSessionKey_AsMapKey(t *testing.T) {
	m := make(map[sessionKey]string)
	k1 := sessionKey{uuid: "uuid-1", deviceID: 1}
	k2 := sessionKey{uuid: "uuid-1", deviceID: 2}

	m[k1] = "session-1"
	m[k2] = "session-2"

	if m[k1] != "session-1" {
		t.Errorf("m[k1] = %q, want %q", m[k1], "session-1")
	}
	if m[k2] != "session-2" {
		t.Errorf("m[k2] = %q, want %q", m[k2], "session-2")
	}
	if len(m) != 2 {
		t.Errorf("map length = %d, want 2", len(m))
	}
}
