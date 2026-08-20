package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestConfig_Destroy_WipesHMACSharedSecrets covers the four long-lived
// credential-signing secrets added to the Destroy sweep: leaving any of them
// resident is the defect this exists to prevent.
func TestConfig_Destroy_WipesHMACSharedSecrets(t *testing.T) {
	cfg := &Config{
		Attachments:    AttachmentConfig{TusSharedSecret: secrets.MustNewSecureString("tus-secret")},
		StorageService: StorageServiceConfig{SharedSecret: secrets.MustNewSecureString("storage-secret")},
		CDSI:           CDSIConfig{SharedSecret: secrets.MustNewSecureString("cdsi-secret")},
		SVR2:           SVR2Config{SharedSecret: secrets.MustNewSecureString("svr2-secret")},
	}

	cfg.Destroy()

	for name, ss := range map[string]*secrets.SecureString{
		"Attachments.TusSharedSecret": cfg.Attachments.TusSharedSecret,
		"StorageService.SharedSecret": cfg.StorageService.SharedSecret,
		"CDSI.SharedSecret":           cfg.CDSI.SharedSecret,
		"SVR2.SharedSecret":           cfg.SVR2.SharedSecret,
	} {
		if !ss.IsDestroyed() {
			t.Errorf("expected %s to be destroyed", name)
		}
	}
}

func TestConfig_Destroy_NilHMACSharedSecrets(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{HTTPPort: 8080},
		Storage: StorageConfig{Backend: "memory"},
	}
	// The shared-secret fields are nil here; Destroy must not panic.
	cfg.Destroy()
}

// TestLoad_HMACSharedSecretsUnmarshalFromYAML pins the config file schema:
// moving these fields to *secrets.SecureString must not change the YAML a
// deployment writes.
func TestLoad_HMACSharedSecretsUnmarshalFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  httpPort: 8080
storage:
  backend: memory
attachments:
  tusSharedSecret: tus-secret
storageService:
  sharedSecret: storage-secret
cdsi:
  sharedSecret: cdsi-secret
svr2:
  sharedSecret: svr2-secret
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Destroy()

	for name, tc := range map[string]struct {
		got  *secrets.SecureString
		want string
	}{
		"attachments.tusSharedSecret": {cfg.Attachments.TusSharedSecret, "tus-secret"},
		"storageService.sharedSecret": {cfg.StorageService.SharedSecret, "storage-secret"},
		"cdsi.sharedSecret":           {cfg.CDSI.SharedSecret, "cdsi-secret"},
		"svr2.sharedSecret":           {cfg.SVR2.SharedSecret, "svr2-secret"},
	} {
		if got := tc.got.Plaintext(); got != tc.want {
			t.Errorf("%s = %q, want %q", name, got, tc.want)
		}
	}
}

// TestLoad_HMACSharedSecretsAbsentFromYAML documents the disabled-feature
// path: an omitted secret leaves an unset SecureString, which every consumer
// reads as "not configured" rather than as an empty key.
func TestLoad_HMACSharedSecretsAbsentFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
server:
  httpPort: 8080
storage:
  backend: memory
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Destroy()

	for name, ss := range map[string]*secrets.SecureString{
		"attachments.tusSharedSecret": cfg.Attachments.TusSharedSecret,
		"storageService.sharedSecret": cfg.StorageService.SharedSecret,
		"cdsi.sharedSecret":           cfg.CDSI.SharedSecret,
		"svr2.sharedSecret":           cfg.SVR2.SharedSecret,
	} {
		if !ss.IsDestroyed() {
			t.Errorf("expected %s to be unset when absent from the config file", name)
		}
	}
}

// TestConfig_Destroy_NilReceiver pins the nil-safety that lets every daemon
// register `defer cfg.Destroy()` on entry, before it has established that a
// config was loaded at all.
func TestConfig_Destroy_NilReceiver(t *testing.T) {
	var cfg *Config
	cfg.Destroy() // must not panic
}
