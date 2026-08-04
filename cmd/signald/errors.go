package main

import "fmt"

// StartupError wraps a server startup failure with a descriptive stage.
type StartupError struct {
	Stage string
	Cause error
}

func (e *StartupError) Error() string { return e.Stage + ": " + e.Cause.Error() }
func (e *StartupError) Unwrap() error { return e.Cause }

// UsageError indicates a configuration or runtime validation failure.
type UsageError struct {
	Message string
}

func (e *UsageError) Error() string { return e.Message }

// UnknownBackendError indicates an unrecognized backend or provider name.
type UnknownBackendError struct {
	Backend string
}

func (e *UnknownBackendError) Error() string {
	return fmt.Sprintf("unknown backend: %q", e.Backend)
}
