package main

import (
	"context"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestRunStart_AbortedStartupWipesTheConfigSecrets checks a missing shared secret aborts startup with the config's other secrets wiped.
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
