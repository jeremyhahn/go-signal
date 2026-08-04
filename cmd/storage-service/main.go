// Package main is the entry point for the standalone storage-service
// binary.
//
// storage-service hosts per-account encrypted manifest + item storage
// over plain HTTPS with HMAC Basic auth. Mobile clients connect here
// directly; signald is not on the data path — per Java's
// SecureStorageClient architecture, signald only issues credentials
// at /v1/storage/auth and calls the admin DELETE /v1/storage endpoint
// on account deletion.
//
// The wire shape is JSON request/response with opaque encrypted blobs
// supplied by the client; this binary never decrypts or interprets
// the payloads (end-to-end encrypted from the client's perspective).
//
// Storage is backed by the same pkg/securestorage.ManifestStore the
// monolithic deployment uses, so the in-memory / qrdb / postgres
// backends are interchangeable.
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
