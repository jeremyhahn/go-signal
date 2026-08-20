package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes body to a temp file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// captureDestroy replaces the destroyConfig seam for the duration of a test
// and returns a pointer to the Config the failure path wiped, if any. Wiping a
// Config the caller never receives has no other observable effect, which is
// why the seam exists.
func captureDestroy(t *testing.T) **Config {
	t.Helper()
	var captured *Config
	original := destroyConfig
	destroyConfig = func(c *Config) {
		captured = c
		original(c)
	}
	t.Cleanup(func() { destroyConfig = original })
	return &captured
}

// TestLoad_ParseFailureDestroysAlreadyDecodedSecrets covers the leak on the
// decode path. yaml.v3 populates field by field and reports type errors only
// at the end, so a shared secret written above a malformed field is already
// sealed in protected memory by the time Unmarshal fails. Load returns nil, so
// the caller never gets a handle to wipe it.
//
// Removing the guarded cleanup from Load makes this fail.
func TestLoad_ParseFailureDestroysAlreadyDecodedSecrets(t *testing.T) {
	captured := captureDestroy(t)

	// The secret decodes first; the malformed port then fails the decode.
	path := writeConfig(t, `
cdsi:
  sharedSecret: "cdsi-shared-secret"
storageService:
  sharedSecret: "storage-shared-secret"
server:
  httpPort: "not-a-number"
`)

	cfg, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted a malformed config")
	}
	if cfg != nil {
		t.Fatal("Load returned a Config alongside an error")
	}

	c := *captured
	if c == nil {
		t.Fatal("a failed parse abandoned the Config it had already built — nothing was wiped")
	}
	for name, ss := range map[string]interface{ IsDestroyed() bool }{
		"cdsi.sharedSecret":           c.CDSI.SharedSecret,
		"storageService.sharedSecret": c.StorageService.SharedSecret,
	} {
		if ss != nil && !ss.IsDestroyed() {
			t.Errorf("%s survived a failed parse", name)
		}
	}
}

// TestLoad_ValidationFailureDestroysDecodedSecrets covers the other error
// path: the file decodes cleanly, every secret is sealed, and Validate then
// rejects it. Same consequence — the caller gets nil and cannot wipe anything.
//
// Removing the guarded cleanup from Load makes this fail.
func TestLoad_ValidationFailureDestroysDecodedSecrets(t *testing.T) {
	captured := captureDestroy(t)

	path := writeConfig(t, `
server:
  httpPort: -1
cdsi:
  sharedSecret: "cdsi-shared-secret"
`)

	cfg, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted a config that should fail validation")
	}
	if cfg != nil {
		t.Fatal("Load returned a Config alongside an error")
	}

	c := *captured
	if c == nil {
		t.Fatal("a failed validation abandoned the Config it had built — nothing was wiped")
	}
	if ss := c.CDSI.SharedSecret; ss != nil && !ss.IsDestroyed() {
		t.Error("cdsi.sharedSecret survived a failed validation")
	}
}

// TestLoad_SuccessDoesNotDestroyTheConfig is the other half of the guard: the
// cleanup must not fire on the success path, or every caller would receive a
// Config whose secrets are already wiped.
func TestLoad_SuccessDoesNotDestroyTheConfig(t *testing.T) {
	captured := captureDestroy(t)

	path := writeConfig(t, validYAML()+`
cdsi:
  sharedSecret: "cdsi-shared-secret"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer cfg.Destroy()

	if *captured != nil {
		t.Fatal("a successful load wiped the Config it returned")
	}
	if cfg.CDSI.SharedSecret.IsDestroyed() {
		t.Error("cdsi.sharedSecret was wiped on the success path")
	}
	if got := cfg.CDSI.SharedSecret.Plaintext(); got != "cdsi-shared-secret" {
		t.Errorf("cdsi.sharedSecret = %q, want %q", got, "cdsi-shared-secret")
	}
}

// TestLoad_ReadFailureWipesNothing pins the boundary: a file that cannot be
// read never reaches the decoder, so there is no Config to wipe and the
// cleanup must not run against a half-built one.
func TestLoad_ReadFailureWipesNothing(t *testing.T) {
	captured := captureDestroy(t)

	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("Load accepted a missing file")
	}
	if cfg != nil {
		t.Fatal("Load returned a Config alongside an error")
	}
	if *captured != nil {
		t.Error("cleanup ran for a file that was never decoded")
	}
}
