package websocket

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jeremyhahn/go-signal/pkg/cache"
	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// wsNotifyChannelPrefix prefixes the empty wake-up channel "<prefix><uuid>:<deviceID>"; subscribers re-read the MessageStore.
const wsNotifyChannelPrefix = "signal:ws:notify:"

// notifyChannel returns the pub/sub channel name for a given destination.
func notifyChannel(uuid string, deviceID uint64) string {
	return fmt.Sprintf("%s%s:%d", wsNotifyChannelPrefix, uuid, deviceID)
}

// MessageFlusher returns a device's queued messages in delivery order from the durable store.
type MessageFlusher func(ctx context.Context, uuid string, deviceID uint64) ([]*messages.Envelope, error)

// sessionKey uniquely identifies a WebSocket session by account UUID and device
// ID.
type sessionKey struct {
	uuid     string
	deviceID uint64
}

// SessionManager tracks WebSocket sessions and delivers messages, across instances via pub/sub when built with a cache; safe for concurrent use.
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[sessionKey]*Session
	logger   *slog.Logger

	// cache is the optional cluster-wide pub/sub backend. When nil, the
	// manager operates in single-instance mode and does not subscribe to
	// cross-instance notifications.
	cache cache.Client

	// flusher is consulted when a wake-up notification arrives. It returns
	// the queued envelopes to push to the locally-registered session.
	flusher MessageFlusher
}

// NewSessionManager returns a local-only SessionManager, for tests and single-instance use.
func NewSessionManager(logger *slog.Logger) *SessionManager {
	return &SessionManager{
		sessions: make(map[sessionKey]*Session),
		logger:   logger.With(slog.String("component", "websocket-manager")),
	}
}

// NewSessionManagerWithCache returns a SessionManager that wakes sessions on any instance through cache pub/sub and flusher; flusher must not be nil.
func NewSessionManagerWithCache(logger *slog.Logger, c cache.Client, flusher MessageFlusher) *SessionManager {
	if c == nil {
		// Defensive: treat a nil cache as local-only to avoid surprising
		// callers; flusher is still retained so NotifyMessageAvailable can
		// take the in-process flush path.
		return &SessionManager{
			sessions: make(map[sessionKey]*Session),
			logger:   logger.With(slog.String("component", "websocket-manager")),
			flusher:  flusher,
		}
	}
	return &SessionManager{
		sessions: make(map[sessionKey]*Session),
		logger:   logger.With(slog.String("component", "websocket-manager")),
		cache:    c,
		flusher:  flusher,
	}
}

// Register stores the session, closing any previous one for the device, and subscribes it to wake-ups when a cache is set.
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

	if m.cache != nil {
		m.startSubscription(session)
	}

	m.logger.Info("websocket session registered",
		slog.String("uuid", session.UUID),
		slog.Uint64("deviceId", session.DeviceID))
}

// Unregister removes session unless it has been replaced.
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

// DeliverMessage sends envelope to a local session and reports whether it was queued; cross-instance delivery uses NotifyMessageAvailable.
func (m *SessionManager) DeliverMessage(uuid string, deviceID uint64, envelope *messages.Envelope) bool {
	// Rejected before anything else so the encoding-failure branch below can
	// name the envelope it could not encode. A nil envelope is a caller bug,
	// not a delivery outcome, and must not take down the process.
	if envelope == nil {
		m.logger.Error("refusing to deliver a nil envelope",
			slog.String("uuid", uuid),
			slog.Uint64("deviceId", deviceID))
		return false
	}

	key := sessionKey{uuid: uuid, deviceID: deviceID}

	m.mu.RLock()
	session, exists := m.sessions[key]
	m.mu.RUnlock()

	if !exists {
		return false
	}

	msg := buildDeliveryMessage(envelope)
	if msg == nil {
		m.logger.Error("failed to encode envelope for websocket delivery",
			slog.String("uuid", uuid),
			slog.Uint64("deviceId", deviceID),
			slog.String("serverGuid", envelope.ServerGUID))
		return false
	}
	if err := session.Send(msg); err != nil {
		m.logger.Warn("failed to deliver message via websocket",
			slog.String("uuid", uuid),
			slog.Uint64("deviceId", deviceID),
			slog.String("error", err.Error()))
		return false
	}

	return true
}

// NotifyMessageAvailable publishes a wake-up for the device when a cache is set, else flushes the local session in a goroutine; it never blocks on socket I/O.
func (m *SessionManager) NotifyMessageAvailable(ctx context.Context, uuid string, deviceID uint64) error {
	if m.cache != nil {
		// Cross-instance fanout: the recipient instance(s) drive the flush.
		_, err := m.cache.Publish(ctx, notifyChannel(uuid, deviceID), nil)
		if err != nil {
			m.logger.Warn("websocket notify publish failed",
				slog.String("uuid", uuid),
				slog.Uint64("deviceId", deviceID),
				slog.String("error", err.Error()))
		}
		return err
	}

	if m.flusher == nil {
		// Local-only mode without a flusher: the caller should be using
		// DeliverMessage with the envelope in hand. Nothing to do here.
		return nil
	}

	// Single-instance with flusher: drive the flush in the foreground so the
	// caller observes any error. flushSessionLocked is a no-op if the session
	// is not registered on this instance.
	return m.flushBy(ctx, uuid, deviceID)
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

// CloseAll closes every session and clears the map, for shutdown.
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

// startSubscription subscribes session to its wake-up channel and flushes on each notification until either closes.
func (m *SessionManager) startSubscription(session *Session) {
	ctx, cancel := context.WithCancel(context.Background())
	sub, err := m.cache.Subscribe(ctx, notifyChannel(session.UUID, session.DeviceID))
	if err != nil {
		cancel()
		m.logger.Error("websocket subscribe failed",
			slog.String("uuid", session.UUID),
			slog.Uint64("deviceId", session.DeviceID),
			slog.String("error", err.Error()))
		return
	}

	go m.runSubscription(ctx, cancel, session, sub)
}

// runSubscription closes the subscription when the session closes, but not when the cache already closed it.
func (m *SessionManager) runSubscription(ctx context.Context, cancel context.CancelFunc, session *Session, sub cache.Subscription) {
	defer cancel()

	ch := sub.Channel()
	for {
		select {
		case <-session.Done():
			if err := sub.Close(); err != nil {
				m.logger.Debug("websocket subscription close error",
					slog.String("uuid", session.UUID),
					slog.Uint64("deviceId", session.DeviceID),
					slog.String("error", err.Error()))
			}
			return
		case _, ok := <-ch:
			if !ok {
				// Cache-side teardown closed our subscription channel;
				// calling sub.Close() now would race with the upstream
				// cleanup. Just exit.
				return
			}
			if err := m.flushToSession(ctx, session); err != nil {
				m.logger.Warn("websocket flush after notify failed",
					slog.String("uuid", session.UUID),
					slog.Uint64("deviceId", session.DeviceID),
					slog.String("error", err.Error()))
			}
		}
	}
}

// flushBy looks up the local session for (uuid, deviceID) and, if registered,
// drives a flush via flushToSession. If no local session is registered the
// call is a harmless no-op (some other instance is expected to flush).
func (m *SessionManager) flushBy(ctx context.Context, uuid string, deviceID uint64) error {
	session := m.GetSession(uuid, deviceID)
	if session == nil {
		return nil
	}
	return m.flushToSession(ctx, session)
}

// flushToSession sends queued messages, stopping at the first send error; the rest stay queued.
func (m *SessionManager) flushToSession(ctx context.Context, session *Session) error {
	if m.flusher == nil {
		return nil
	}

	envs, err := m.flusher(ctx, session.UUID, session.DeviceID)
	if err != nil {
		return err
	}

	for _, env := range envs {
		if env == nil {
			continue
		}
		msg := buildDeliveryMessage(env)
		if msg == nil {
			// The message stays queued in the durable store, so skipping
			// it here costs a redelivery attempt rather than the message.
			m.logger.Error("failed to encode envelope during flush",
				slog.String("uuid", session.UUID),
				slog.Uint64("deviceId", session.DeviceID),
				slog.String("serverGuid", env.ServerGUID))
			continue
		}
		if sendErr := session.Send(msg); sendErr != nil {
			return sendErr
		}
	}
	return nil
}

// buildDeliveryMessage constructs a WebSocketMessage that delivers an envelope
// to a connected client using the Signal WebSocket protocol convention.
func buildDeliveryMessage(envelope *messages.Envelope) *WebSocketMessage {
	encoded := encodeEnvelopeBody(envelope)
	if encoded == "" {
		return nil
	}

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
