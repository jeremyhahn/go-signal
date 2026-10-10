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
	"os"

	"github.com/jeremyhahn/go-signal/pkg/securemem"
)

var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := securemem.Run(Execute); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
