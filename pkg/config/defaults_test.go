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
	return validYAML() + section + ":\n  " + field + ": \"" + value + "\"\n"
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
		if got := *d.field(cfg); got != d.value {
			t.Errorf("%s = %q, want default %q", d.key, got, d.value)
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
				if got := *other.field(cfg); got != other.value {
					t.Errorf("%s = %q, want default %q", other.key, got, other.value)
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
