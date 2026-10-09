package config_test

import (
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
)

// shippedConfigPath is the development config Dockerfile.dev bakes into the
// integration image as /etc/signal-server/config.yml. Tests here assert the
// file itself, because signald seeds from it at boot and nothing else in the
// suite reads it: the in-process integration fixture builds its own stores,
// so a flag deleted from this file would go unnoticed there.
func shippedConfigPath(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "configs", "signal-server.yml")
}

func TestShippedConfig_Loads(t *testing.T) {
	if _, err := config.Load(t.Context(), shippedConfigPath(t)); err != nil {
		t.Fatalf("configs/signal-server.yml must load: %v", err)
	}
}

// The six global flags are what TestConfigV2_GetRemoteConfig expects the
// running server to serve. They are seeded from this file, so assert the
// names, the rollout, and the value the client receives.
func TestShippedConfig_SeedsGlobalRemoteConfigFlags(t *testing.T) {
	cfg, err := config.Load(t.Context(), shippedConfigPath(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	byName := make(map[string]config.RemoteConfigEntry, len(cfg.RemoteConfig.Defaults))
	for _, e := range cfg.RemoteConfig.Defaults {
		byName[e.Name] = e
	}

	for _, name := range []string{
		"global.calling",
		"global.groupsv2",
		"global.storage",
		"global.senderKey",
		"global.stories",
		"global.giftBadges",
	} {
		entry, ok := byName[name]
		if !ok {
			t.Errorf("remoteConfig.defaults is missing %q", name)
			continue
		}
		// Buckets are 0-99 and an account enrolls when its bucket is
		// strictly below the percentage, so only 100 covers everyone.
		if entry.Percentage != 100 {
			t.Errorf("%s: percentage = %d, want 100 so every account enrolls", name, entry.Percentage)
		}
		if entry.Value != "TRUE" {
			t.Errorf("%s: value = %q, want %q", name, entry.Value, "TRUE")
		}
	}
}

// The development config must stay development-only: validateProduction is
// what stops it being deployed, and this asserts that gate actually rejects
// it rather than assuming it would.
func TestShippedConfig_IsRejectedInProductionMode(t *testing.T) {
	cfg, err := config.Load(t.Context(), shippedConfigPath(t))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cfg.Mode = "production"

	if err := cfg.Validate(t.Context()); err == nil {
		t.Error("expected the development config to be rejected in production mode")
	}
}
