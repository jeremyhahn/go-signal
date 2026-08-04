package cmd

import "fmt"

// UsageError indicates a CLI validation or usage failure.
type UsageError struct {
	Message string
}

func (e *UsageError) Error() string { return e.Message }

// CLIError wraps an SDK or I/O operation error with the operation name.
type CLIError struct {
	Op    string
	Cause error
}

func (e *CLIError) Error() string { return e.Op + ": " + e.Cause.Error() }
func (e *CLIError) Unwrap() error { return e.Cause }

// NotImplementedError indicates a command is not yet implemented.
type NotImplementedError struct {
	Command string
}

func (e *NotImplementedError) Error() string {
	return fmt.Sprintf("%s: not yet implemented", e.Command)
}
