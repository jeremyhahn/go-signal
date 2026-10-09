package config

import (
	"errors"
	"strings"
	"testing"
)

// yamlFor renders a dotted two-level key (e.g. "health.listen") as a YAML
// fragment appended to validYAML.
func yamlFor(t *testing.T, key, value string) string {
	t.Helper()
	section, field, ok := strings.Cut(key, ".")
	if !ok || strings.Contains(field, ".") {
		t.Fatalf("key %q is not a two-level path", key)
	}
	entry := "  " + field + ": \"" + value + "\"\n"
	// validYAML already carries a server block; a second one would be a
	// duplicate mapping key, so the entry joins the existing block.
	if base := validYAML(); strings.Contains(base, "\n"+section+":\n") {
		return strings.Replace(base, "\n"+section+":\n", "\n"+section+":\n"+entry, 1)
	}
	return validYAML() + section + ":\n" + entry
}

// resolvedDefault is the value d resolves to when validYAML, which sets
// only the legacy server keys, is loaded: the server listen addresses fold
// the legacy host and ports in, every other address is its default.
func resolvedDefault(d addressDefault) string {
	legacy := map[AddressKey]string{
		KeyServerHTTPListen: "0.0.0.0:8080",
		KeyServerGRPCListen: "0.0.0.0:9090",
	}
	if v, ok := legacy[d.key]; ok {
		return v
	}
	return d.value
}

// TestAddressDefaults_DocumentedValues pins every documented default so a
// changed or dropped default is a deliberate edit.
func TestAddressDefaults_DocumentedValues(t *testing.T) {
	want := map[AddressKey]string{
		"health.listen":              "0.0.0.0:8099",
		"verification.grpcListen":    "0.0.0.0:8090",
		"svr2.httpListen":            "0.0.0.0:8091",
		"svr2.wsListen":              "0.0.0.0:8092",
		"cdsi.wsListen":              "0.0.0.0:8094",
		"storageService.httpListen":  "0.0.0.0:8096",
		"keyTransparency.grpcListen": "0.0.0.0:8098",
		// Optional: empty disables the listener, dialer or advertised URI.
		"server.httpListen":          "",
		"server.grpcListen":          "",
		"keyTransparency.remoteAddr": "",
		"verification.remoteAddr":    "",
		"storageService.remoteUrl":   "",
		"svr2.remoteUrl":             "",
		"attachments.tusUri":         "",
	}
	if len(addressDefaults) != len(want) {
		t.Fatalf("addressDefaults has %d keys, want %d", len(addressDefaults), len(want))
	}
	for _, d := range addressDefaults {
		if got, ok := want[d.key]; !ok || got != d.value {
			t.Errorf("default %q = %q, want %q", d.key, d.value, got)
		}
	}
}

// TestLoad_AppliesAddressDefaults verifies a file that sets no address
// resolves every listener to its defaults-layer value.
func TestLoad_AppliesAddressDefaults(t *testing.T) {
	cfg, err := Load(writeYAML(t, validYAML()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, d := range addressDefaults {
		if got, want := *d.field(cfg), resolvedDefault(d); got != want {
			t.Errorf("%s = %q, want default %q", d.key, got, want)
		}
	}
}

// TestLoad_FileOverridesAddressDefaults verifies each address is settable
// through the config file, under its existing YAML key, and that setting
// one leaves the others at their defaults.
func TestLoad_FileOverridesAddressDefaults(t *testing.T) {
	for _, d := range addressDefaults {
		t.Run(string(d.key), func(t *testing.T) {
			const override = "127.0.0.1:19999"
			cfg, err := Load(writeYAML(t, yamlFor(t, string(d.key), override)))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := *d.field(cfg); got != override {
				t.Errorf("%s = %q, want file value %q", d.key, got, override)
			}
			for _, other := range addressDefaults {
				if other.key == d.key {
					continue
				}
				if got, want := *other.field(cfg), resolvedDefault(other); got != want {
					t.Errorf("%s = %q, want default %q", other.key, got, want)
				}
			}
		})
	}
}

// TestLoad_RejectsEmptyAddress verifies a file that explicitly empties an
// address fails closed with a validation error naming the key, rather
// than binding a random port.
func TestLoad_RejectsEmptyAddress(t *testing.T) {
	for _, d := range addressDefaults {
		if d.optional {
			continue
		}
		t.Run(string(d.key), func(t *testing.T) {
			cfg, err := Load(writeYAML(t, yamlFor(t, string(d.key), "")))
			if cfg != nil {
				t.Fatal("Load returned a Config alongside an error")
			}
			var vErr *ConfigValidationError
			if !errors.As(err, &vErr) {
				t.Fatalf("err = %v, want *ConfigValidationError", err)
			}
			if vErr.Field != string(d.key) {
				t.Errorf("Field = %q, want %q", vErr.Field, d.key)
			}
		})
	}
}

// TestApplyDefaults_OverwritesEveryAddress verifies applyDefaults writes
// each address field, so no listener depends on a zero value.
func TestApplyDefaults_OverwritesEveryAddress(t *testing.T) {
	cfg := &Config{}
	for _, d := range addressDefaults {
		*d.field(cfg) = "stale"
	}
	applyDefaults(cfg)
	for _, d := range addressDefaults {
		if got := *d.field(cfg); got != d.value {
			t.Errorf("%s = %q, want %q", d.key, got, d.value)
		}
	}
}

// TestValidateAddresses_AcceptsResolvedConfig verifies the defaults layer
// alone satisfies address validation.
func TestValidateAddresses_AcceptsResolvedConfig(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	if err := validateAddresses(cfg); err != nil {
		t.Fatalf("validateAddresses: %v", err)
	}
}

// TestLoad_OptionalAddressMayBeEmpty verifies an explicitly emptied
// optional address disables its listener, dialer or advertised URI rather
// than failing the load.
func TestLoad_OptionalAddressMayBeEmpty(t *testing.T) {
	for _, d := range addressDefaults {
		if !d.optional {
			continue
		}
		t.Run(string(d.key), func(t *testing.T) {
			cfg, err := Load(writeYAML(t, yamlFor(t, string(d.key), "")))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got, want := *d.field(cfg), resolvedDefault(d); got != want {
				t.Errorf("%s = %q, want %q", d.key, got, want)
			}
		})
	}
}

// TestLoad_LegacyServerKeysFoldIntoListenAddresses verifies the legacy
// host and port keys resolve to the listen addresses, and that any
// explicit listen address, from any layer, wins over them.
func TestLoad_LegacyServerKeysFoldIntoListenAddresses(t *testing.T) {
	cfg, err := Load(writeYAML(t, validYAML()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPListen != "0.0.0.0:8080" || cfg.Server.GRPCListen != "0.0.0.0:9090" {
		t.Errorf("listen = %q, %q; want legacy keys folded in", cfg.Server.HTTPListen, cfg.Server.GRPCListen)
	}

	t.Setenv(EnvName(KeyServerHTTPListen), "127.0.0.1:10010")
	cfg, err = Load(writeYAML(t, validYAML()))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPListen != "127.0.0.1:10010" {
		t.Errorf("httpListen = %q, want env value over legacy httpPort", cfg.Server.HTTPListen)
	}
}

// TestLoad_OnlyGRPCListenSatisfiesServerValidation verifies a listen
// address alone, with no legacy port, satisfies the at-least-one-listener
// rule, and that none at all is rejected.
func TestLoad_OnlyGRPCListenSatisfiesServerValidation(t *testing.T) {
	body := "server:\n  grpcListen: \"127.0.0.1:10011\"\nstorage:\n  backend: memory\n"
	cfg, err := Load(writeYAML(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPListen != "" {
		t.Errorf("httpListen = %q, want empty", cfg.Server.HTTPListen)
	}
	var vErr *ConfigValidationError
	if _, err := Load(writeYAML(t, "storage:\n  backend: memory\n")); !errors.As(err, &vErr) || vErr.Field != "server" {
		t.Fatalf("err = %v, want *ConfigValidationError for server", err)
	}
}

// TestLoad_RejectsMalformedServerListen verifies a server listen address
// that is not host:port fails closed, naming the key.
func TestLoad_RejectsMalformedServerListen(t *testing.T) {
	for _, key := range []AddressKey{KeyServerHTTPListen, KeyServerGRPCListen} {
		t.Run(string(key), func(t *testing.T) {
			_, err := Load(writeYAML(t, yamlFor(t, string(key), "not-an-address")))
			var vErr *ConfigValidationError
			if !errors.As(err, &vErr) || vErr.Field != string(key) {
				t.Fatalf("err = %v, want *ConfigValidationError for %s", err, key)
			}
		})
	}
}
