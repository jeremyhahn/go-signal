// Package main is the entry point for the standalone svr2 binary.
//
// svr2 hosts the SVR4 (Secure Value Recovery v4) state machine over a
// Noise NKhfs-encrypted WebSocket. Clients connect directly to this
// binary (the chat-server does NOT proxy SVR2 traffic — that follows
// Java's reference architecture); signald only issues HMAC credentials
// via /v2/svr/auth and calls the admin DELETE /v1/delete endpoint
// on account deletion.
//
// Attestation is pluggable. The development default is software
// attestation with a deployment-time ed25519 signing key. Production
// deployments using TPM 2.0 (or future TDX/SEV-SNP) flip the
// attester config to "tpm".
package main

import (
	"fmt"
	"os"
)

var (
	version   = "dev"
	gitCommit = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
