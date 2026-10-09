package config

import (
	"errors"
	"testing"

	"github.com/spf13/pflag"
)

// TestEnvName_MechanicalRule pins the documented env name of every
// address: SIGNAL_ plus the upper-cased key with "." replaced by "_".
func TestEnvName_MechanicalRule(t *testing.T) {
	want := map[AddressKey]string{
		KeyHealthListen:              "SIGNAL_HEALTH_LISTEN",
		KeyVerificationGRPCListen:    "SIGNAL_VERIFICATION_GRPCLISTEN",
		KeySVR2HTTPListen:            "SIGNAL_SVR2_HTTPLISTEN",
		KeySVR2WSListen:              "SIGNAL_SVR2_WSLISTEN",
		KeyCDSIWSListen:              "SIGNAL_CDSI_WSLISTEN",
		KeyStorageServiceHTTPListen:  "SIGNAL_STORAGESERVICE_HTTPLISTEN",
		KeyKeyTransparencyGRPCListen: "SIGNAL_KEYTRANSPARENCY_GRPCLISTEN",
		KeyServerHTTPListen:          "SIGNAL_SERVER_HTTPLISTEN",
		KeyServerGRPCListen:          "SIGNAL_SERVER_GRPCLISTEN",
		KeyKeyTransparencyRemoteAddr: "SIGNAL_KEYTRANSPARENCY_REMOTEADDR",
		KeyVerificationRemoteAddr:    "SIGNAL_VERIFICATION_REMOTEADDR",
		KeyStorageServiceRemoteURL:   "SIGNAL_STORAGESERVICE_REMOTEURL",
		KeySVR2RemoteURL:             "SIGNAL_SVR2_REMOTEURL",
		KeyAttachmentsTusURI:         "SIGNAL_ATTACHMENTS_TUSURI",
	}
	for _, d := range addressDefaults {
		if got := EnvName(d.key); got != want[d.key] {
			t.Errorf("EnvName(%s) = %q, want %q", d.key, got, want[d.key])
		}
	}
}

// TestFlagName_KebabCase pins the documented flag name of every address.
func TestFlagName_KebabCase(t *testing.T) {
	want := map[AddressKey]string{
		KeyHealthListen:              "health-listen",
		KeyVerificationGRPCListen:    "verification-grpc-listen",
		KeySVR2HTTPListen:            "svr2-http-listen",
		KeySVR2WSListen:              "svr2-ws-listen",
		KeyCDSIWSListen:              "cdsi-ws-listen",
		KeyStorageServiceHTTPListen:  "storage-service-http-listen",
		KeyKeyTransparencyGRPCListen: "key-transparency-grpc-listen",
		KeyServerHTTPListen:          "server-http-listen",
		KeyServerGRPCListen:          "server-grpc-listen",
		KeyKeyTransparencyRemoteAddr: "key-transparency-remote-addr",
		KeyVerificationRemoteAddr:    "verification-remote-addr",
		KeyStorageServiceRemoteURL:   "storage-service-remote-url",
		KeySVR2RemoteURL:             "svr2-remote-url",
		KeyAttachmentsTusURI:         "attachments-tus-uri",
	}
	for _, d := range addressDefaults {
		if got := FlagName(d.key); got != want[d.key] {
			t.Errorf("FlagName(%s) = %q, want %q", d.key, got, want[d.key])
		}
	}
}

// addressFlags returns a flag set carrying every address flag, parsed
// from args.
func addressFlags(t *testing.T, args ...string) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	for _, d := range addressDefaults {
		AddAddressFlags(fs, d.key)
	}
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	return fs
}

// TestLoadWithFlags_Precedence proves flag > env > file > default for
// every address, one layer added at a time.
func TestLoadWithFlags_Precedence(t *testing.T) {
	const (
		fileVal = "127.0.0.1:10001"
		envVal  = "127.0.0.1:10002"
		flagVal = "127.0.0.1:10003"
	)
	for _, d := range addressDefaults {
		t.Run(string(d.key), func(t *testing.T) {
			cases := []struct {
				name string
				file bool
				env  bool
				flag bool
				want string
			}{
				{"default", false, false, false, resolvedDefault(d)},
				{"file over default", true, false, false, fileVal},
				{"env over default", false, true, false, envVal},
				{"flag over default", false, false, true, flagVal},
				{"env over file", true, true, false, envVal},
				{"flag over file", true, false, true, flagVal},
				{"flag over env", false, true, true, flagVal},
				{"flag over env over file", true, true, true, flagVal},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					body := validYAML()
					if tc.file {
						body = yamlFor(t, string(d.key), fileVal)
					}
					if tc.env {
						t.Setenv(EnvName(d.key), envVal)
					}
					var args []string
					if tc.flag {
						args = []string{"--" + FlagName(d.key) + "=" + flagVal}
					}
					cfg, err := LoadWithFlags(t.Context(), writeYAML(t, body), addressFlags(t, args...))
					if err != nil {
						t.Fatalf("LoadWithFlags: %v", err)
					}
					if got := *d.field(cfg); got != tc.want {
						t.Errorf("%s = %q, want %q", d.key, got, tc.want)
					}
				})
			}
		})
	}
}

// TestLoad_EnvOverridesWithoutFlags verifies Load, which has no flag
// layer, still resolves the environment over the file.
func TestLoad_EnvOverridesWithoutFlags(t *testing.T) {
	const envVal = "127.0.0.1:10004"
	t.Setenv(EnvName(KeyHealthListen), envVal)
	cfg, err := Load(t.Context(), writeYAML(t, yamlFor(t, string(KeyHealthListen), "127.0.0.1:10005")))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Health.Listen != envVal {
		t.Errorf("health.listen = %q, want %q", cfg.Health.Listen, envVal)
	}
}

// TestLoad_EmptyEnvIsUnset verifies an empty variable does not clear the
// address: it falls through to the file layer.
func TestLoad_EmptyEnvIsUnset(t *testing.T) {
	const fileVal = "127.0.0.1:10006"
	t.Setenv(EnvName(KeyCDSIWSListen), "")
	cfg, err := Load(t.Context(), writeYAML(t, yamlFor(t, string(KeyCDSIWSListen), fileVal)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CDSI.WSListen != fileVal {
		t.Errorf("cdsi.wsListen = %q, want %q", cfg.CDSI.WSListen, fileVal)
	}
}

// TestLoadWithFlags_UnchangedFlagKeepsLowerLayer verifies a registered
// flag the operator did not set never overrides the file, even though its
// displayed default is the defaults-layer value.
func TestLoadWithFlags_UnchangedFlagKeepsLowerLayer(t *testing.T) {
	const fileVal = "127.0.0.1:10007"
	cfg, err := LoadWithFlags(t.Context(), writeYAML(t, yamlFor(t, string(KeySVR2WSListen), fileVal)), addressFlags(t))
	if err != nil {
		t.Fatalf("LoadWithFlags: %v", err)
	}
	if cfg.SVR2.WSListen != fileVal {
		t.Errorf("svr2.wsListen = %q, want %q", cfg.SVR2.WSListen, fileVal)
	}
}

// TestLoadWithFlags_EmptyFlagRejected verifies a flag explicitly set to
// an empty address fails closed.
func TestLoadWithFlags_EmptyFlagRejected(t *testing.T) {
	fs := addressFlags(t, "--"+FlagName(KeyHealthListen)+"=")
	cfg, err := LoadWithFlags(t.Context(), writeYAML(t, validYAML()), fs)
	if cfg != nil {
		t.Fatal("LoadWithFlags returned a Config alongside an error")
	}
	var vErr *ConfigValidationError
	if !errors.As(err, &vErr) || vErr.Field != string(KeyHealthListen) {
		t.Fatalf("err = %v, want *ConfigValidationError for %s", err, KeyHealthListen)
	}
}

// TestAddAddressFlags_RegistersDefault verifies each flag is registered
// under its FlagName with the defaults-layer value as its default.
func TestAddAddressFlags_RegistersDefault(t *testing.T) {
	fs := addressFlags(t)
	for _, d := range addressDefaults {
		f := fs.Lookup(FlagName(d.key))
		if f == nil {
			t.Fatalf("flag %q not registered", FlagName(d.key))
		}
		if f.DefValue != d.value {
			t.Errorf("flag %q default = %q, want %q", f.Name, f.DefValue, d.value)
		}
	}
}

// TestAddAddressFlags_UnknownKeyPanics verifies registering a key that is
// not an address key is caught at start-up.
func TestAddAddressFlags_UnknownKeyPanics(t *testing.T) {
	defer func() {
		r := recover()
		vErr, ok := r.(*ConfigValidationError)
		if !ok || vErr.Field != "server.host" {
			t.Fatalf("recover() = %v, want *ConfigValidationError for server.host", r)
		}
	}()
	AddAddressFlags(pflag.NewFlagSet("test", pflag.ContinueOnError), AddressKey("server.host"))
}

// TestConfig_Address verifies Address reads each resolved field and
// returns "" for a key that is not an address key.
func TestConfig_Address(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	for _, d := range addressDefaults {
		if got := cfg.Address(d.key); got != d.value {
			t.Errorf("Address(%s) = %q, want %q", d.key, got, d.value)
		}
	}
	if got := cfg.Address("server.host"); got != "" {
		t.Errorf("Address(server.host) = %q, want empty", got)
	}
}

// TestApplyFlags_NilFlagSet verifies a nil flag set applies no flag layer.
func TestApplyFlags_NilFlagSet(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	applyFlags(cfg, nil)
	if cfg.Health.Listen != DefaultHealthListen {
		t.Errorf("health.listen = %q, want %q", cfg.Health.Listen, DefaultHealthListen)
	}
}
