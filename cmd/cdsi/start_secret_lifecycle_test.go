package main

import (
	"context"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestRunStart_AbortedStartupWipesSharedSecret checks an aborted startup (no directory address) wipes the CDS shared secret.
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
