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

// TestRunStart_AbortedStartupWipesSharedSecrets is the regression test for the
// leak this change closes: the wipes used to live only in the ordered shutdown
// block at the end of runStart, so every early return between config load and
// that block left the process's long-lived key material resident. runStart now
// registers each wipe as a defer the moment its owner is created, and the
// shutdown block stays the normal-path owner of wipe-after-draining.
//
// The abort is forced with a data directory that is really a regular file, so
// the KV client cannot open it: startup fails immediately, binds no ports and
// starts no servers. The observable proxy is the process config — cfg is the
// package global every one of these secrets is drawn from, while the managers'
// clones are function-locals no test can reach. Driving runStart far enough to
// build those managers means standing the daemon up, which a unit test must
// not do; their wipes are covered by the Destroy tests in pkg/directory and
// pkg/securestorage plus the defer registrations here.
//
// The dev-fallback ephemeral signing key is in that same bucket, and worth
// naming because it is the one secret in runStart that cfg.Destroy() does NOT
// reach: the other two signing-key branches alias a config field, while the
// ephemeral one is owned by runStart alone. This fixture does take that branch
// (no ZKConfig is set), so its `defer ephemeral.Destroy()` does run here — but
// the key is a function-local with no handle a test can hold, so the coverage
// is the defer's registration, not an assertion.
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
			TusSharedSecret: secrets.MustNewSecureString(t.Context(), "tus-secret"),
		},
		StorageService: config.StorageServiceConfig{SharedSecret: secrets.MustNewSecureString(t.Context(), "storage-secret")},
		CDSI:           config.CDSIConfig{SharedSecret: secrets.MustNewSecureString(t.Context(), "cdsi-secret")},
		SVR2:           config.SVR2Config{SharedSecret: secrets.MustNewSecureString(t.Context(), "svr2-secret")},
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
		if !ss.IsDestroyed(t.Context()) {
			t.Errorf("%s survived an aborted startup", name)
		}
	}
}
