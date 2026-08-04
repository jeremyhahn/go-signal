package main

import (
	"io"
	"log/slog"
)

// newDiscardLogger returns a *slog.Logger that discards all output.
// Used in unit tests to suppress log noise without modifying slog.Default().
func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
