// Package main is the standalone registration-service binary: verification sessions, codes, rate limits and transport delivery over gRPC.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jeremyhahn/go-signal/pkg/securemem"
)

var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

func main() {
	logger := newLogger()
	slog.SetDefault(logger)
	mem := securemem.New(logger)
	if err := mem.Run(func() error { return Execute(logger, mem.Start) }); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newLogger builds the binary's logger: the one sink and format for every
// record the process writes, the secure-memory lifecycle's included.
func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}
