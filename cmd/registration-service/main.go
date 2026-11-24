// Package main is the entry point for the standalone
// registration-service binary.
//
// registration-service hosts the lower half of the verification stack
// — session lifecycle, code generation, per-session SMS/voice rate-
// limit bookkeeping, and transport delivery (Twilio Verify, SES, SMTP,
// or a stub for development). It exposes the gRPC contract defined by
// pkg/api/grpc/proto/RegistrationService.proto.
//
// signald talks to this binary through pkg/extservice/registration. The
// captcha gate (requestedInformation:["captcha"]) lives on the signald
// side via pkg/registration/sessionshim — registration-service is
// intentionally unaware of captcha state, mirroring the Java Signal-
// Server architectural split.
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
