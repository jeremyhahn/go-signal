package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validYAML() string {
	return `
server:
  host: "0.0.0.0"
  httpPort: 8080
  grpcPort: 9090
  maxDevices: 6
storage:
  backend: "memory"
`
}

func TestLoad_ValidConfig(t *testing.T) {
	path := writeYAML(t, validYAML())
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("got host %q, want %q", cfg.Server.Host, "0.0.0.0")
	}
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("got httpPort %d, want 8080", cfg.Server.HTTPPort)
	}
	if cfg.Server.GRPCPort != 9090 {
		t.Errorf("got grpcPort %d, want 9090", cfg.Server.GRPCPort)
	}
	if cfg.Storage.Backend != "memory" {
		t.Errorf("got backend %q, want %q", cfg.Storage.Backend, "memory")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	var target *ConfigLoadError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigLoadError, got %T", err)
	}
	if target.Path != "/nonexistent/path/config.yaml" {
		t.Errorf("got path %q", target.Path)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeYAML(t, "{{{{invalid yaml")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
	var target *ConfigParseError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigParseError, got %T", err)
	}
}

func TestLoad_ValidationFailure_NoPort(t *testing.T) {
	yaml := `
server:
  host: "0.0.0.0"
storage:
  backend: "memory"
`
	path := writeYAML(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "server" {
		t.Errorf("got field %q, want %q", target.Field, "server")
	}
}

func TestLoad_ValidationFailure_NoBackend(t *testing.T) {
	yaml := `
server:
  httpPort: 8080
storage:
  backend: ""
`
	path := writeYAML(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "storage.backend" {
		t.Errorf("got field %q, want %q", target.Field, "storage.backend")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	path := writeYAML(t, "")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for empty config")
	}
}

func TestLoad_HTTPPortOnly(t *testing.T) {
	yaml := `
server:
  httpPort: 8080
storage:
  backend: "memory"
`
	path := writeYAML(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.GRPCPort != 0 {
		t.Errorf("expected grpcPort 0, got %d", cfg.Server.GRPCPort)
	}
}

func TestLoad_GRPCPortOnly(t *testing.T) {
	yaml := `
server:
  grpcPort: 9090
storage:
  backend: "memory"
`
	path := writeYAML(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.HTTPPort != 0 {
		t.Errorf("expected httpPort 0, got %d", cfg.Server.HTTPPort)
	}
}

func TestLoad_DefaultMaxDevices(t *testing.T) {
	yaml := `
server:
  httpPort: 8080
storage:
  backend: "memory"
`
	path := writeYAML(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.MaxDevices != 6 {
		t.Errorf("got maxDevices %d, want 6", cfg.Server.MaxDevices)
	}
}

func TestLoad_CustomMaxDevices(t *testing.T) {
	yaml := `
server:
  httpPort: 8080
  maxDevices: 10
storage:
  backend: "memory"
`
	path := writeYAML(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.MaxDevices != 10 {
		t.Errorf("got maxDevices %d, want 10", cfg.Server.MaxDevices)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	yaml := `
server:
  host: "127.0.0.1"
  httpPort: 8080
  grpcPort: 9090
  tlsCertFile: "/certs/server.crt"
  tlsKeyFile: "/certs/server.key"
  maxDevices: 8
storage:
  backend: "postgres"
  postgres:
    host: "localhost"
    port: 5432
    database: "signal"
    user: "signal"
    password: "secret"
    sslMode: "require"
cache:
  backend: "redis"
  redis:
    url: "redis://localhost:6379"
    password: "redispass"
    db: 1
push:
  apn:
    teamId: "TEAM123"
    keyId: "KEY456"
    bundleId: "org.signal"
    privateKey: "privkey"
    sandbox: true
  fcm:
    credentials: "fcm-creds"
cdn:
  bucket: "signal-attachments"
  region: "us-east-1"
  accessKey: "AKID"
  secretKey: "SKEY"
limits:
  messages:
    bucketSize: 100
    leakRatePerMin: 50
  preKeys:
    bucketSize: 10
    leakRatePerMin: 5
  attachments:
    bucketSize: 20
    leakRatePerMin: 10
  profiles:
    bucketSize: 30
    leakRatePerMin: 15
turn:
  cloudflare:
    apiToken: "cf-token"
    endpoint: "https://cf.example.com/api"
    urls:
      - "turn:a.example.com"
      - "turn:b.example.com"
    hostname: "turn.example.com"
zkConfig:
  serverSecret: "zk-secret"
  enabled: true
payments:
  stripe:
    apiKey: "sk_test_xxx"
    webhookSecret: "whsec_xxx"
directory:
  enabled: true
`
	path := writeYAML(t, yaml)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Spot-check nested fields
	if cfg.Storage.Postgres.Host != "localhost" {
		t.Errorf("got postgres host %q", cfg.Storage.Postgres.Host)
	}
	if cfg.Cache.Redis.DB != 1 {
		t.Errorf("got redis db %d", cfg.Cache.Redis.DB)
	}
	if !cfg.Push.APN.Sandbox {
		t.Error("expected APN sandbox true")
	}
	if cfg.CDN.Bucket != "signal-attachments" {
		t.Errorf("got cdn bucket %q", cfg.CDN.Bucket)
	}
	if cfg.Limits.Messages.BucketSize != 100 {
		t.Errorf("got messages bucket size %d", cfg.Limits.Messages.BucketSize)
	}
	if len(cfg.Turn.Cloudflare.URLs) != 2 {
		t.Errorf("got %d turn URLs", len(cfg.Turn.Cloudflare.URLs))
	}
	if cfg.Turn.Cloudflare.APIToken == nil || cfg.Turn.Cloudflare.APIToken.Plaintext() != "cf-token" {
		t.Errorf("got cloudflare api token %v", cfg.Turn.Cloudflare.APIToken)
	}
	if !cfg.ZKConfig.Enabled {
		t.Error("expected zkConfig enabled")
	}
	if cfg.Payments.Stripe.APIKey == nil || cfg.Payments.Stripe.APIKey.Plaintext() != "sk_test_xxx" {
		t.Errorf("got stripe key %v", cfg.Payments.Stripe.APIKey)
	}
	if !cfg.Directory.Enabled {
		t.Error("expected directory enabled")
	}
}

func TestValidate_BothPortsZero(t *testing.T) {
	cfg := &Config{
		Storage: StorageConfig{Backend: "memory"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
}

func TestValidate_HTTPPortSet(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{HTTPPort: 8080},
		Storage: StorageConfig{Backend: "memory"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_GRPCPortSet(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{GRPCPort: 9090},
		Storage: StorageConfig{Backend: "memory"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MissingBackend(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{HTTPPort: 8080},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected validation error")
	}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *ConfigValidationError, got %T", err)
	}
	if target.Field != "storage.backend" {
		t.Errorf("got field %q, want %q", target.Field, "storage.backend")
	}
}

func TestValidate_DefaultMaxDevices(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{HTTPPort: 8080},
		Storage: StorageConfig{Backend: "memory"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.MaxDevices != 6 {
		t.Errorf("got maxDevices %d, want 6", cfg.Server.MaxDevices)
	}
}

func TestValidate_PreserveExistingMaxDevices(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{HTTPPort: 8080, MaxDevices: 12},
		Storage: StorageConfig{Backend: "memory"},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.MaxDevices != 12 {
		t.Errorf("got maxDevices %d, want 12", cfg.Server.MaxDevices)
	}
}

func TestConfigLoadError_Error(t *testing.T) {
	cause := errors.New("permission denied")
	e := &ConfigLoadError{Path: "/etc/config.yaml", Cause: cause}
	want := "failed to load config from /etc/config.yaml: permission denied"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestConfigLoadError_Unwrap(t *testing.T) {
	cause := errors.New("root")
	e := &ConfigLoadError{Path: "/x", Cause: cause}
	if e.Unwrap() != cause {
		t.Error("Unwrap should return cause")
	}
}

func TestConfigLoadError_ErrorsIs(t *testing.T) {
	cause := os.ErrNotExist
	e := &ConfigLoadError{Path: "/missing", Cause: cause}
	if !errors.Is(e, os.ErrNotExist) {
		t.Error("errors.Is should find os.ErrNotExist through chain")
	}
}

func TestConfigParseError_Error(t *testing.T) {
	cause := errors.New("yaml: unmarshal errors")
	e := &ConfigParseError{Path: "/etc/config.yaml", Cause: cause}
	want := "failed to parse config from /etc/config.yaml: yaml: unmarshal errors"
	if got := e.Error(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestConfigParseError_Unwrap(t *testing.T) {
	cause := errors.New("root")
	e := &ConfigParseError{Path: "/x", Cause: cause}
	if e.Unwrap() != cause {
		t.Error("Unwrap should return cause")
	}
}

func TestConfigValidationError_Error(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		message string
		want    string
	}{
		{
			"server_field",
			"server",
			"at least one port required",
			"config validation error: server: at least one port required",
		},
		{
			"storage_field",
			"storage.backend",
			"storage backend is required",
			"config validation error: storage.backend: storage backend is required",
		},
		{
			"empty_field",
			"",
			"generic error",
			"config validation error: : generic error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ConfigValidationError{Field: tt.field, Message: tt.message}
			if got := e.Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigValidationError_TypeAssertion(t *testing.T) {
	var err error = &ConfigValidationError{Field: "server", Message: "bad"}
	var target *ConfigValidationError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *ConfigValidationError")
	}
	if target.Field != "server" {
		t.Errorf("got field %q, want %q", target.Field, "server")
	}
}

func TestConfigLoadError_ImplementsError(t *testing.T) {
	var _ error = &ConfigLoadError{}
}

func TestConfigParseError_ImplementsError(t *testing.T) {
	var _ error = &ConfigParseError{}
}

func TestConfigValidationError_ImplementsError(t *testing.T) {
	var _ error = &ConfigValidationError{}
}

func TestConfig_Destroy(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{HTTPPort: 8080},
		Storage: StorageConfig{
			Backend: "memory",
			Postgres: PostgresConfig{
				Password: secrets.MustNewSecureString("db-password"),
			},
		},
		Cache: CacheConfig{
			Redis: RedisConfig{
				Password: secrets.MustNewSecureString("redis-password"),
			},
		},
		ZKConfig: ZKConfig{
			ServerSecret: secrets.MustNewSecureString("zk-secret"),
		},
		Captcha: CaptchaConfig{
			SecretKey: secrets.MustNewSecureString("captcha-secret"),
		},
	}

	cfg.Destroy()

	if cfg.Storage.Postgres.Password != nil && !cfg.Storage.Postgres.Password.IsDestroyed() {
		t.Error("expected Postgres.Password to be destroyed")
	}
	if cfg.Cache.Redis.Password != nil && !cfg.Cache.Redis.Password.IsDestroyed() {
		t.Error("expected Redis.Password to be destroyed")
	}
	if cfg.ZKConfig.ServerSecret != nil && !cfg.ZKConfig.ServerSecret.IsDestroyed() {
		t.Error("expected ZKConfig.ServerSecret to be destroyed")
	}
	if cfg.Captcha.SecretKey != nil && !cfg.Captcha.SecretKey.IsDestroyed() {
		t.Error("expected Captcha.SecretKey to be destroyed")
	}
}

func TestConfig_Destroy_NilFields(t *testing.T) {
	cfg := &Config{
		Server:  ServerConfig{HTTPPort: 8080},
		Storage: StorageConfig{Backend: "memory"},
	}
	// Should not panic with nil SecureString fields.
	cfg.Destroy()
}

func TestConfig_Destroy_Idempotent(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{HTTPPort: 8080},
		Storage: StorageConfig{
			Backend: "memory",
			Postgres: PostgresConfig{
				Password: secrets.MustNewSecureString("db-password"),
			},
		},
	}
	cfg.Destroy()
	cfg.Destroy() // Should not panic.
}

// validProductionConfig returns a Config that passes the production gate.
// Tests mutate one field at a time to assert each violation is detected.
func validProductionConfig() *Config {
	return &Config{
		Mode:            "production",
		Server:          ServerConfig{HTTPPort: 443, MaxDevices: 6, TLSCertFile: "/tls/c.pem", TLSKeyFile: "/tls/k.pem", AllowedOrigins: []string{"https://chat.example.com"}},
		Storage:         StorageConfig{Backend: "postgres"},
		Cache:           CacheConfig{Backend: "redis"},
		ZKConfig:        ZKConfig{Enabled: true, ServerSecret: secrets.MustNewSecureString("zk-secret")},
		CallingZKConfig: CallingZKConfig{ServerSecret: secrets.MustNewSecureString("calling-secret")},
		Verification:    VerificationConfig{Transport: "twilio"},
		Captcha:         CaptchaConfig{Provider: "hcaptcha"},
		Limits:          LimitsConfig{Messages: RateLimitConfig{BucketSize: 200, LeakRatePerMin: 60}},
	}
}

func TestValidate_ProductionConfig_Passes(t *testing.T) {
	if err := validProductionConfig().Validate(); err != nil {
		t.Fatalf("expected valid production config to pass, got: %v", err)
	}
}

func TestValidate_ProductionConfig_NonProductionModeSkipsGate(t *testing.T) {
	// A wide-open test config must pass when mode is not "production".
	cfg := &Config{
		Mode:         "development",
		Server:       ServerConfig{HTTPPort: 8081},
		Storage:      StorageConfig{Backend: "memory"},
		Cache:        CacheConfig{Backend: "memory"},
		Verification: VerificationConfig{Transport: "stub", FixedCode: "123456"},
		Captcha:      CaptchaConfig{Provider: "test"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("non-production mode should skip the gate, got: %v", err)
	}
	if cfg.IsProduction() {
		t.Fatal("IsProduction must be false for development mode")
	}
}

func TestValidate_ProductionGate_DetectsEachViolation(t *testing.T) {
	cases := map[string]struct {
		mutate     func(*Config)
		wantSubstr string
	}{
		"memory storage":        {func(c *Config) { c.Storage.Backend = "memory" }, "storage.backend"},
		"qrdb storage":          {func(c *Config) { c.Storage.Backend = "qrdb" }, "storage.backend"},
		"dynamodb storage":      {func(c *Config) { c.Storage.Backend = "dynamodb" }, "storage.backend"},
		"memory cache":          {func(c *Config) { c.Cache.Backend = "memory" }, "cache.backend"},
		"stub transport":        {func(c *Config) { c.Verification.Transport = "stub" }, "verification.transport"},
		"empty transport":       {func(c *Config) { c.Verification.Transport = "" }, "verification.transport"},
		"fixed code":            {func(c *Config) { c.Verification.FixedCode = "123456" }, "verification.fixedCode"},
		"test captcha":          {func(c *Config) { c.Captcha.Provider = "test" }, "captcha.provider"},
		"empty captcha":         {func(c *Config) { c.Captcha.Provider = "" }, "captcha.provider"},
		"zk disabled":           {func(c *Config) { c.ZKConfig.Enabled = false }, "zkConfig"},
		"zk empty secret":       {func(c *Config) { c.ZKConfig.ServerSecret = nil }, "zkConfig"},
		"calling zk empty":      {func(c *Config) { c.CallingZKConfig.ServerSecret = nil }, "callingZkConfig"},
		"calling zk test value": {func(c *Config) { c.CallingZKConfig.ServerSecret = secrets.MustNewSecureString(testCallingZKSecret) }, "well-known development secret"},
		"no tls cert":           {func(c *Config) { c.Server.TLSCertFile = "" }, "tlsCertFile"},
		"no tls key":            {func(c *Config) { c.Server.TLSKeyFile = "" }, "tlsKeyFile"},
		"wildcard origin":       {func(c *Config) { c.Server.AllowedOrigins = []string{"*"} }, "allowedOrigins"},
		"zero message bucket":   {func(c *Config) { c.Limits.Messages.BucketSize = 0 }, "limits.messages.bucketSize"},
		"insecure verification": {func(c *Config) { c.Verification.RemoteInsecure = true }, "verification.remoteInsecure"},
		"insecure kt":           {func(c *Config) { c.KeyTransparency.RemoteInsecure = true }, "keyTransparency.remoteInsecure"},
		"insecure storage svc":  {func(c *Config) { c.StorageService.RemoteInsecure = true }, "storageService.remoteInsecure"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validProductionConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected production violation for %q, got nil", name)
			}
			var pErr *ProductionValidationError
			if !errors.As(err, &pErr) {
				t.Fatalf("expected *ProductionValidationError, got %T: %v", err, err)
			}
			found := false
			for _, viol := range pErr.Violations {
				if strings.Contains(viol, tc.wantSubstr) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected a violation containing %q, got: %v", tc.wantSubstr, pErr.Violations)
			}
		})
	}
}

func TestValidate_ProductionGate_AggregatesMultiple(t *testing.T) {
	cfg := validProductionConfig()
	cfg.Storage.Backend = "memory"
	cfg.Verification.Transport = "stub"
	cfg.Captcha.Provider = "test"
	err := cfg.Validate()
	var pErr *ProductionValidationError
	if !errors.As(err, &pErr) {
		t.Fatalf("expected *ProductionValidationError, got %T", err)
	}
	if len(pErr.Violations) < 3 {
		t.Fatalf("expected at least 3 aggregated violations, got %d: %v", len(pErr.Violations), pErr.Violations)
	}
}

func TestIsProduction_CaseInsensitive(t *testing.T) {
	for _, m := range []string{"production", "Production", "PRODUCTION", " production "} {
		if !(&Config{Mode: m}).IsProduction() {
			t.Errorf("mode %q should be production", m)
		}
	}
	for _, m := range []string{"", "development", "dev", "prod"} {
		if (&Config{Mode: m}).IsProduction() {
			t.Errorf("mode %q should NOT be production", m)
		}
	}
}

func TestLoad_ProductionTemplate_PassesGate(t *testing.T) {
	// The shipped production template must always satisfy the production
	// gate; ${ENV} secret references are stored verbatim at load (resolution
	// happens later) and read as non-empty, so the presence checks pass.
	cfg, err := Load("../../configs/signal-server-prod.yml")
	if err != nil {
		t.Fatalf("production template must load and pass the gate, got: %v", err)
	}
	if !cfg.IsProduction() {
		t.Fatal("production template must set mode: production")
	}
}
