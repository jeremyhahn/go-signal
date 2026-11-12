package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
)

// rootAddressTestConfig writes the smallest config the root command
// loads, with every address this binary binds set in the file to fileVal.
func rootAddressTestConfig(t *testing.T, fileVal string) string {
	t.Helper()
	body := "server:\n  httpPort: 8080\nstorage:\n  backend: memory\n"
	sections := map[string]string{}
	var order []string
	for _, key := range addressKeys {
		section, field, ok := strings.Cut(string(key), ".")
		if !ok {
			t.Fatalf("key %q has no section", key)
		}
		if _, seen := sections[section]; !seen {
			order = append(order, section)
		}
		sections[section] += "  " + field + ": \"" + fileVal + "\"\n"
	}
	for _, section := range order {
		body += section + ":\n" + sections[section]
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// resolveThroughRoot runs the root command's config loading for start,
// with args parsed onto start's flags, and returns the resolved config.
func resolveThroughRoot(t *testing.T, path string, args ...string) *config.Config {
	t.Helper()
	stubSecureMemory(t, nil)
	prevPath, prevCfg := cfgPath, cfg
	t.Cleanup(func() {
		cfgPath, cfg = prevPath, prevCfg
		for _, key := range addressKeys {
			f := rootCmd.PersistentFlags().Lookup(config.FlagName(key))
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	})
	if err := startCmd.ParseFlags(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	cfgPath = path
	if err := rootCmd.PersistentPreRunE(startCmd, nil); err != nil {
		t.Fatalf("PersistentPreRunE: %v", err)
	}
	return cfg
}

// TestRoot_AddressLayers proves every address this binary binds is
// settable by file, environment and flag through the root command, with
// flag > env > file.
func TestRoot_AddressLayers(t *testing.T) {
	const (
		fileVal = "127.0.0.1:20001"
		envVal  = "127.0.0.1:20002"
		flagVal = "127.0.0.1:20003"
	)
	if len(addressKeys) == 0 {
		t.Fatal("binary registers no address keys")
	}
	path := rootAddressTestConfig(t, fileVal)
	for _, key := range addressKeys {
		t.Run(string(key), func(t *testing.T) {
			if got := resolveThroughRoot(t, path).Address(key); got != fileVal {
				t.Errorf("file only: %s = %q, want %q", key, got, fileVal)
			}
			t.Setenv(config.EnvName(key), envVal)
			if got := resolveThroughRoot(t, path).Address(key); got != envVal {
				t.Errorf("env over file: %s = %q, want %q", key, got, envVal)
			}
			got := resolveThroughRoot(t, path, "--"+config.FlagName(key)+"="+flagVal).Address(key)
			if got != flagVal {
				t.Errorf("flag over env: %s = %q, want %q", key, got, flagVal)
			}
		})
	}
}

// TestRoot_AddressFlagsRegistered verifies each address flag is on the
// root command, so every subcommand inherits it.
func TestRoot_AddressFlagsRegistered(t *testing.T) {
	for _, key := range addressKeys {
		if rootCmd.PersistentFlags().Lookup(config.FlagName(key)) == nil {
			t.Errorf("flag --%s not registered", config.FlagName(key))
		}
	}
}
