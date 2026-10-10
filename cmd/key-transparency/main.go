// Package main is the entry point for the standalone key-transparency
// binary. Hosts the KeyTransparencyQueryService gRPC contract: signald
// reads from this service to answer mobile-client KT REST endpoints
// (handlers_keytransparency.go).
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
