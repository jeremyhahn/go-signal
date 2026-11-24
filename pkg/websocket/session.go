package websocket

import (
	"context"
	"log/slog"
	"sync"
	"time"

	ws "github.com/coder/websocket"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

const (
	// sendBufferSize is the capacity of the outbound message channel per session.
	sendBufferSize = 256

	// writeTimeout is the maximum time allowed for writing a single message.
	writeTimeout = 10 * time.Second

	// pingInterval is how often the server sends a ping to keep the connection alive.
	pingInterval = 30 * time.Second

	// pongTimeout is how long the server waits for a pong response before considering
	// the connection dead.
	pongTimeout = 10 * time.Second

	// maxFrameSize is the maximum allowed size of a single WebSocket frame.
	// Frames exceeding this size cause the connection to be closed, preventing
	// memory exhaustion from oversized messages.
	maxFrameSize int64 = 256 * 1024 // 256 KB
)

// Session represents an authenticated WebSocket connection for a specific
// account and device. It manages bidirectional communication through separate
// read and write pumps.
type Session struct {
	UUID      string
	DeviceID  uint64
	AuthToken *secrets.SecureString
	conn      *ws.Conn
	logger    *slog.Logger
	send      chan []byte
	done      chan struct{}
	once      sync.Once
	wg        sync.WaitGroup // tracks WritePump goroutine
	format    FrameFormat
	formatSet bool
	formatMu  sync.Mutex
}

// NewSession creates a new Session bound to the given WebSocket connection.
// The caller must start ReadPump and WritePump to begin processing messages.
func NewSession(conn *ws.Conn, uuid string, deviceID uint64, authToken *secrets.SecureString, logger *slog.Logger) *Session {
	return &Session{
		UUID:      uuid,
		DeviceID:  deviceID,
		AuthToken: authToken,
		conn:      conn,
		logger:    logger.With(slog.String("uuid", uuid), slog.Uint64("deviceId", deviceID)),
		send:      make(chan []byte, sendBufferSize),
		done:      make(chan struct{}),
		format:    FrameFormatProtobuf,
	}
}

// Format returns the frame format detected for this session.
func (s *Session) Format() FrameFormat {
	s.formatMu.Lock()
	defer s.formatMu.Unlock()
	return s.format
}

// SetFormat forces the frame format for this session. This must be called
// before sending or receiving any messages, and takes effect only once.
// Use this when the protocol requires a specific format (e.g. provisioning
// always uses protobuf).
func (s *Session) SetFormat(f FrameFormat) {
	s.setFormat(f)
}

// setFormat sets the frame format for this session (called once on first message).
func (s *Session) setFormat(f FrameFormat) {
	s.formatMu.Lock()
	defer s.formatMu.Unlock()
	if !s.formatSet {
		s.format = f
		s.formatSet = true
	}
}

// Send marshals the given WebSocketMessage and enqueues it for delivery. If
// the session is closed or the send buffer is full, a SessionClosedError is
// returned.
func (s *Session) Send(msg *WebSocketMessage) error {
	// Check if the session is closed before attempting to send.
	select {
	case <-s.done:
		return &SessionClosedError{UUID: s.UUID, DeviceID: s.DeviceID}
	default:
	}

	data, err := MarshalFrame(msg, s.Format())
	if err != nil {
		return &DeliveryFailedError{UUID: s.UUID, DeviceID: s.DeviceID, Cause: err}
	}

	select {
	case s.send <- data:
		return nil
	case <-s.done:
		return &SessionClosedError{UUID: s.UUID, DeviceID: s.DeviceID}
	}
}

// Close gracefully closes the WebSocket connection. It is safe to call
// multiple times.
func (s *Session) Close() {
	s.once.Do(func() {
		close(s.done)
		if s.AuthToken != nil {
			s.AuthToken.Destroy()
		}
		if s.conn != nil {
			if err := s.conn.Close(ws.StatusNormalClosure, "session closed"); err != nil {
				s.logger.Debug("websocket close error", slog.String("error", err.Error()))
			}
		}
		s.logger.Info("websocket session closed")
	})
}

// Done returns a channel that is closed when the session terminates.
func (s *Session) Done() <-chan struct{} {
	return s.done
}

// ReadPump reads messages from the WebSocket connection in a loop and
// dispatches each parsed frame to the provided handler. It detects the frame
// format (binary = protobuf, text = JSON) from the first message and uses that
// format for the session lifetime. It blocks until the connection is closed or
// an error occurs, at which point it calls Close.
func (s *Session) ReadPump(handler func(*WebSocketMessage)) {
	defer s.Close()

	s.conn.SetReadLimit(maxFrameSize)

	for {
		msgType, data, err := s.conn.Read(context.Background())
		if err != nil {
			select {
			case <-s.done:
				// Graceful shutdown; do not log.
			default:
				s.logger.Debug("websocket read error", slog.String("error", err.Error()))
			}
			return
		}

		// Detect frame format from the WebSocket message type.
		if msgType == ws.MessageBinary {
			s.setFormat(FrameFormatProtobuf)
		} else {
			s.setFormat(FrameFormatJSON)
		}

		msg, err := UnmarshalFrame(data, s.Format())
		if err != nil {
			s.logger.Warn("failed to unmarshal websocket message",
				slog.String("error", err.Error()),
				slog.String("format", frameFormatName(s.Format())))
			continue
		}

		handler(msg)
	}
}

// WritePump writes messages from the send channel to the WebSocket connection.
// It also sends periodic pings to keep the connection alive. It blocks until
// the session is closed.
func (s *Session) WritePump() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()
	defer s.Close()

	for {
		select {
		case data, ok := <-s.send:
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			wsType := ws.MessageText
			if s.Format() == FrameFormatProtobuf {
				wsType = ws.MessageBinary
			}
			err := s.conn.Write(ctx, wsType, data)
			cancel()
			if err != nil {
				s.logger.Debug("websocket write error", slog.String("error", err.Error()))
				return
			}

		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), pongTimeout)
			err := s.conn.Ping(ctx)
			cancel()
			if err != nil {
				s.logger.Debug("websocket ping failed", slog.String("error", err.Error()))
				return
			}

		case <-s.done:
			return
		}
	}
}

// StartWritePump starts the write pump in a tracked goroutine. Use Wait()
// to block until the pump exits.
func (s *Session) StartWritePump() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.WritePump()
	}()
}

// Wait blocks until all tracked goroutines (WritePump) have exited.
func (s *Session) Wait() {
	s.wg.Wait()
}

// frameFormatName returns a human-readable name for the frame format.
func frameFormatName(f FrameFormat) string {
	switch f {
	case FrameFormatProtobuf:
		return "protobuf"
	default:
		return "json"
	}
}
