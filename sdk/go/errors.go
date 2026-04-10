package signal

import "fmt"

// APIError represents an error response from the Signal server.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("signal API error %d: %s", e.StatusCode, e.Message)
}

// NotRegisteredError indicates the account is not registered.
type NotRegisteredError struct {
	Number string
}

func (e *NotRegisteredError) Error() string {
	return fmt.Sprintf("account not registered: %s", e.Number)
}

// SessionError indicates a Signal Protocol session error.
type SessionError struct {
	Recipient string
	Cause     error
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("session error for %s: %v", e.Recipient, e.Cause)
}

func (e *SessionError) Unwrap() error {
	return e.Cause
}
