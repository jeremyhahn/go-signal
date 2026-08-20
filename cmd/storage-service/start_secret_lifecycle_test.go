package main

import (
	"context"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestRunStart_AbortedStartupWipesTheConfigSecrets is the lifecycle guarantee
// for the standalone storage-service daemon. Its shared secret is
// enclave-backed as of this change, so every return path — validation failure
// as much as graceful shutdown — has to wipe it. Without the deferred Destroy
// the secrets stayed reachable through the package-global cfg, which matters
// whenever the command is driven in-process rather than followed immediately
// by process exit.
//
// The only abort reachable before a listener opens is the missing shared
// secret, so the assertion is on the config's other protected material: an
// absent StorageService.SharedSecret must not leave those resident.
func TestRunStart_AbortedStartupWipesTheConfigSecrets(t *testing.T) {
	saved := cfg
	t.Cleanup(func() { cfg = saved })

	cfg = &config.Config{
		// StorageService.SharedSecret deliberately unset: runStart aborts here.
		CDSI: config.CDSIConfig{SharedSecret: secrets.MustNewSecureString("cdsi-secret")},
		SVR2: config.SVR2Config{SharedSecret: secrets.MustNewSecureString("svr2-secret")},
	}
	others := map[string]*secrets.SecureString{
		"CDSI.SharedSecret": cfg.CDSI.SharedSecret,
		"SVR2.SharedSecret": cfg.SVR2.SharedSecret,
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	if err := runStart(cmd, nil); err == nil {
		t.Fatal("expected runStart to abort on the missing shared secret")
	}
	for name, ss := range others {
		if !ss.IsDestroyed() {
			t.Errorf("%s survived an aborted startup", name)
		}
	}
}
