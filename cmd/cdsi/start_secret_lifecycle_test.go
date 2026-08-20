package main

import (
	"context"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestRunStart_AbortedStartupWipesSharedSecret is the lifecycle guarantee for
// the standalone cdsi daemon. Its CDS shared secret is enclave-backed as of
// this change, so every return path — validation failure as much as graceful
// shutdown — has to wipe it. Without the deferred Destroy the secret stayed
// reachable through the package-global cfg, which matters whenever the command
// is driven in-process rather than followed immediately by process exit.
//
// The abort is the missing signald directory address, which returns before any
// listener is opened.
func TestRunStart_AbortedStartupWipesSharedSecret(t *testing.T) {
	saved := cfg
	t.Cleanup(func() { cfg = saved })

	cfg = &config.Config{
		CDSI: config.CDSIConfig{
			SharedSecret: secrets.MustNewSecureString("cdsi-secret"),
			// SignaldDirectoryAddr deliberately empty: runStart aborts here.
		},
	}
	secret := cfg.CDSI.SharedSecret

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	if err := runStart(cmd, nil); err == nil {
		t.Fatal("expected runStart to abort on the missing directory address")
	}
	if !secret.IsDestroyed() {
		t.Error("CDSI.SharedSecret survived an aborted startup")
	}
}

// TestRunStart_MissingSecretStillWipesTheConfig covers the other early return:
// the daemon must not leave the rest of the config's protected material
// resident just because its own secret was absent.
func TestRunStart_MissingSecretStillWipesTheConfig(t *testing.T) {
	saved := cfg
	t.Cleanup(func() { cfg = saved })

	cfg = &config.Config{
		SVR2: config.SVR2Config{SharedSecret: secrets.MustNewSecureString("svr2-secret")},
	}
	other := cfg.SVR2.SharedSecret

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	if err := runStart(cmd, nil); err == nil {
		t.Fatal("expected runStart to abort on the missing shared secret")
	}
	if !other.IsDestroyed() {
		t.Error("SVR2.SharedSecret survived an aborted startup")
	}
}
