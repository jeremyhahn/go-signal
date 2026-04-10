package websocket

// SessionClosedError indicates an operation was attempted on a closed session.
type SessionClosedError struct {
	UUID     string
	DeviceID uint64
}

func (e *SessionClosedError) Error() string {
	return "websocket session closed for " + e.UUID
}

// DeliveryFailedError indicates a message could not be delivered to the target
// session.
type DeliveryFailedError struct {
	UUID     string
	DeviceID uint64
	Cause    error
}

func (e *DeliveryFailedError) Error() string {
	msg := "message delivery failed for " + e.UUID
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *DeliveryFailedError) Unwrap() error {
	return e.Cause
}

// FrameDecodeError indicates a failure to decode a specific field within a
// WebSocket frame during protobuf marshaling.
type FrameDecodeError struct {
	// Field identifies which part of the frame failed to decode
	// (e.g. "request body", "response body").
	Field string
	// Cause is the underlying decoding error.
	Cause error
}

func (e *FrameDecodeError) Error() string {
	msg := "frame decode error"
	if e.Field != "" {
		msg += " in " + e.Field
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

func (e *FrameDecodeError) Unwrap() error {
	return e.Cause
}
