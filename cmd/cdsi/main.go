// Package main is the entry point for the standalone cdsi binary.
//
// cdsi hosts the Contact Discovery v2 server-side state machine over
// a Noise NKhfs-encrypted WebSocket. Mobile clients connect here
// directly (signald is not on the call path); signald issues HMAC
// credentials at /v2/directory/auth which clients present as HTTP
// Basic on the WebSocket upgrade.
//
// At startup, cdsi opens a gRPC channel to signald's
// DirectoryService and streams the directory snapshot to populate
// its local in-memory index. Future deployments add live
// replication via DirectoryService.Subscribe.
//
// Attestation reuses the pluggable Attester from pkg/attestation
// (software ed25519 / TPM 2.0) introduced in Phase 4.2.
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
