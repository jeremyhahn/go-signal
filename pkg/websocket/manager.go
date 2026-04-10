package websocket

import (
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// sessionKey uniquely identifies a WebSocket session by account UUID and device
// ID.
type sessionKey struct {
	uuid     string
	deviceID uint64
}

// SessionManager tracks active WebSocket sessions and delivers messages to
// connected clients. It is safe for concurrent use.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[sessionKey]*Session
	logger   *slog.Logger
}

// NewSessionManager creates a new SessionManager.
func NewSessionManager(logger *slog.Logger) *SessionManager {
	return &SessionManager{
		sessions: make(map[sessionKey]*Session),
		logger:   logger.With(slog.String("component", "websocket-manager")),
	}
}

// Register stores the session, closing any previous session for the same
// account+device combination. This ensures only one active connection per
// device.
func (m *SessionManager) Register(session *Session) {
	key := sessionKey{uuid: session.UUID, deviceID: session.DeviceID}

	m.mu.Lock()
	prev, exists := m.sessions[key]
	m.sessions[key] = session
	m.mu.Unlock()

	if exists {
		m.logger.Info("replacing existing websocket session",
			slog.String("uuid", session.UUID),
			slog.Uint64("deviceId", session.DeviceID))
		prev.Close()
	}

	m.logger.Info("websocket session registered",
		slog.String("uuid", session.UUID),
		slog.Uint64("deviceId", session.DeviceID))
}

// Unregister removes the session from the manager. If the stored session for
// the key differs from the provided session (due to a replacement), the
// removal is skipped.
func (m *SessionManager) Unregister(session *Session) {
	key := sessionKey{uuid: session.UUID, deviceID: session.DeviceID}

	m.mu.Lock()
	current, exists := m.sessions[key]
	if exists && current == session {
		delete(m.sessions, key)
	}
	m.mu.Unlock()

	m.logger.Info("websocket session unregistered",
		slog.String("uuid", session.UUID),
		slog.Uint64("deviceId", session.DeviceID))
}

// DeliverMessage attempts to send a message envelope to an active session for
// the specified account and device. It returns true if the message was
// successfully enqueued for delivery.
func (m *SessionManager) DeliverMessage(uuid string, deviceID uint64, envelope *messages.Envelope) bool {
	key := sessionKey{uuid: uuid, deviceID: deviceID}

	m.mu.RLock()
	session, exists := m.sessions[key]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	msg := buildDeliveryMessage(envelope)
	if err := session.Send(msg); err != nil {
		m.logger.Warn("failed to deliver message via websocket",
			slog.String("uuid", uuid),
			slog.Uint64("deviceId", deviceID),
			slog.String("error", err.Error()))
		return false
	}

	return true
}

// HasActiveSession returns true if there is an active WebSocket session for
// the specified account and device.
func (m *SessionManager) HasActiveSession(uuid string, deviceID uint64) bool {
	key := sessionKey{uuid: uuid, deviceID: deviceID}

	m.mu.RLock()
	_, exists := m.sessions[key]
	m.mu.RUnlock()

	return exists
}

// GetSession returns the active session for the specified account and device,
// or nil if none exists.
func (m *SessionManager) GetSession(uuid string, deviceID uint64) *Session {
	key := sessionKey{uuid: uuid, deviceID: deviceID}

	m.mu.RLock()
	session := m.sessions[key]
	m.mu.RUnlock()

	return session
}

// CloseAll closes all active sessions and clears the session map. It is used
// during server shutdown to ensure all WebSocket connections are terminated
// before the HTTP server stops accepting connections.
func (m *SessionManager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessions = make(map[sessionKey]*Session)
	m.mu.Unlock()

	for _, s := range sessions {
		s.Close()
	}
	m.logger.Info("all websocket sessions closed", slog.Int("count", len(sessions)))
}

// buildDeliveryMessage constructs a WebSocketMessage that delivers an envelope
// to a connected client using the Signal WebSocket protocol convention.
func buildDeliveryMessage(envelope *messages.Envelope) *WebSocketMessage {
	encoded := encodeEnvelopeBody(envelope)

	return &WebSocketMessage{
		Type: "request",
		Request: &WebSocketRequest{
			ID:   envelope.ID,
			Verb: "PUT",
			Path: "/api/v1/message",
			Body: encoded,
		},
	}
}
