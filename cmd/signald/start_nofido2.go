//go:build !fido2

package main

import (
	"log/slog"

	"github.com/jeremyhahn/go-signal/pkg/api/rest"
)

func initFIDO2(_ *rest.Server, _ string, _ *slog.Logger) {
	// FIDO2 support not compiled in.
}
