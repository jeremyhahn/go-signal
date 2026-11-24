package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestRunStart_AbortedStartupWipesSharedSecrets forces an early abort (data dir is a file) and checks every cfg secret is wiped.
func TestRunStart_AbortedStartupWipesSharedSecrets(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocking file: %v", err)
	}

	saved := cfg
	t.Cleanup(func() { cfg = saved })

	cfg = &config.Config{
		Server:  config.ServerConfig{Host: "127.0.0.1", HTTPPort: 0},
		Storage: config.StorageConfig{Backend: "file", File: config.FileConfig{DataDir: blocked}},
		Attachments: config.AttachmentConfig{
			TusSharedSecret: secrets.MustNewSecureString("tus-secret"),
		},
		StorageService: config.StorageServiceConfig{SharedSecret: secrets.MustNewSecureString("storage-secret")},
		CDSI:           config.CDSIConfig{SharedSecret: secrets.MustNewSecureString("cdsi-secret")},
		SVR2:           config.SVR2Config{SharedSecret: secrets.MustNewSecureString("svr2-secret")},
	}
	secretsUnderTest := map[string]*secrets.SecureString{
		"Attachments.TusSharedSecret": cfg.Attachments.TusSharedSecret,
		"StorageService.SharedSecret": cfg.StorageService.SharedSecret,
		"CDSI.SharedSecret":           cfg.CDSI.SharedSecret,
		"SVR2.SharedSecret":           cfg.SVR2.SharedSecret,
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())

	if err := runStart(cmd, nil); err == nil {
		t.Fatal("expected runStart to abort on the unusable data directory")
	}

	for name, ss := range secretsUnderTest {
		if !ss.IsDestroyed() {
			t.Errorf("%s survived an aborted startup", name)
		}
	}
}
