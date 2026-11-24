// Package config loads and validates the server configuration: flag > environment > file > defaults.
// Environment names are SIGNAL_ plus the upper-cased key path with "." as "_" (keyTransparency.grpcListen is SIGNAL_KEYTRANSPARENCY_GRPCLISTEN); empty is unset.
// Flag names are the key path in kebab case (--key-transparency-grpc-listen).
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// Config is the top-level server configuration.
type Config struct {
	// Mode "production" refuses to boot with development settings (see validateProduction); anything else is development.
	Mode              string                  `yaml:"mode"`
	Server            ServerConfig            `yaml:"server"`
	Storage           StorageConfig           `yaml:"storage"`
	Cache             CacheConfig             `yaml:"cache"`
	Push              PushConfig              `yaml:"push"`
	CDN               CDNConfig               `yaml:"cdn"`
	Limits            LimitsConfig            `yaml:"limits"`
	Fraud             FraudConfig             `yaml:"fraud"`
	Turn              TurnConfig              `yaml:"turn"`
	ZKConfig          ZKConfig                `yaml:"zkConfig"`
	CallingZKConfig   CallingZKConfig         `yaml:"callingZkConfig"`
	CallQualitySurvey CallQualitySurveyConfig `yaml:"callQualitySurvey"`
	Payments          PaymentsConfig          `yaml:"payments"`
	Directory         DirectoryConfig         `yaml:"directory"`
	Verification      VerificationConfig      `yaml:"verification"`
	Captcha           CaptchaConfig           `yaml:"captcha"`
	StaticResources   StaticResourcesConfig   `yaml:"staticResources"`
	Attachments       AttachmentConfig        `yaml:"attachments"`
	Frontend          FrontendConfig          `yaml:"frontend"`
	Backups           BackupsConfig           `yaml:"backups"`
	RemoteConfig      RemoteConfigBlock       `yaml:"remoteConfig"`
	SVR2              SVR2Config              `yaml:"svr2"`
	CDSI              CDSIConfig              `yaml:"cdsi"`
	StorageService    StorageServiceConfig    `yaml:"storageService"`
	KeyTransparency   KeyTransparencyConfig   `yaml:"keyTransparency"`
	Health            HealthConfig            `yaml:"health"`
}

// KeyTransparencyConfig configures the key-transparency binary and signald's gRPC client to it.
type KeyTransparencyConfig struct {
	// GRPCListen is the host:port the binary binds the
	// KeyTransparencyQueryService gRPC listener to. Defaults to
	// DefaultKeyTransparencyGRPCListen.
	GRPCListen string `yaml:"grpcListen"`

	// RemoteAddr is the gRPC endpoint signald calls for KT lookups.
	// Empty disables the remote path (monolithic deployments use the
	// in-process stub manager).
	RemoteAddr string `yaml:"remoteAddr"`

	// RemoteInsecure permits a plaintext gRPC channel from signald
	// to key-transparency. Required for development / docker-compose;
	// production must leave this false and supply mTLS dial options.
	RemoteInsecure bool `yaml:"remoteInsecure"`
}

// StorageServiceConfig configures the storage-service binary and signald's admin DELETE client.
type StorageServiceConfig struct {
	// HTTPListen is the host:port the binary binds to. Defaults to
	// DefaultStorageServiceHTTPListen.
	HTTPListen string `yaml:"httpListen"`

	// SharedSecret is the HMAC secret signald and storage-service
	// share for credential derivation. Required. Held in protected
	// memory and wiped by Config.Destroy.
	SharedSecret *secrets.SecureString `yaml:"sharedSecret"`

	// RemoteURL is the storage-service admin endpoint for account deletion; empty disables it.
	RemoteURL string `yaml:"remoteUrl"`

	// RemoteInsecure permits a plaintext HTTP channel from signald
	// to storage-service. Required for development / docker-compose;
	// production must leave this false (TLS 1.3 minimum).
	RemoteInsecure bool `yaml:"remoteInsecure"`
}

// CDSIConfig configures the cdsi binary; signald only serves the DirectoryService stream and /v2/directory/auth.
type CDSIConfig struct {
	// WSListen is the host:port the cdsi binary binds the client-
	// facing WebSocket listener to. Defaults to DefaultCDSIWSListen.
	WSListen string `yaml:"wsListen"`

	// Attestation is the attester flavour for the WebSocket Noise
	// handshake. Same options as SVR2Config.Attestation:
	// "software" (default) or "tpm".
	Attestation string `yaml:"attestation"`

	// SharedSecret is the HMAC secret shared with cdsi; clients present HMAC(sharedSecret, accountUUID). Required; wiped by Config.Destroy.
	SharedSecret *secrets.SecureString `yaml:"sharedSecret"`

	// SignaldDirectoryAddr is the gRPC endpoint cdsi calls at startup
	// to populate its local directory index from signald's
	// DirectoryService. Required.
	SignaldDirectoryAddr string `yaml:"signaldDirectoryAddr"`

	// SignaldDirectoryInsecure allows plaintext gRPC to signald, for development only; production uses mTLS.
	SignaldDirectoryInsecure bool `yaml:"signaldDirectoryInsecure"`
}

// SVR2Config configures the svr2 binary and signald's svr2 admin client.
type SVR2Config struct {
	// HTTPListen is the host:port the binary binds the admin HTTP
	// listener to (handles DELETE /v1/delete). Defaults to
	// DefaultSVR2HTTPListen.
	HTTPListen string `yaml:"httpListen"`

	// WSListen is the host:port the binary binds the
	// client-facing WebSocket listener to (Noise NKhfs over
	// WebSocket). Defaults to DefaultSVR2WSListen.
	WSListen string `yaml:"wsListen"`

	// Attestation is "software" (default, ed25519) or "tpm", which needs an injected TPM; standalone binaries use "software".
	Attestation string `yaml:"attestation"`

	// SharedSecret is the HMAC secret for SVR2 client credentials; required when Attestation is set; wiped by Config.Destroy.
	SharedSecret *secrets.SecureString `yaml:"sharedSecret"`

	// RemoteURL is the svr2 admin endpoint for account deletion; empty disables it.
	RemoteURL string `yaml:"remoteUrl"`
}

// RemoteConfigBlock configures feature flags; Defaults are upserted on boot into the store of cfg.Storage.Backend, which admin writes also use.
type RemoteConfigBlock struct {
	// Defaults is the list of feature flags loaded into the store at
	// startup.
	Defaults []RemoteConfigEntry `yaml:"defaults"`
	// RefreshInterval is how often the manager re-reads the store.
	// Zero defaults to 10 seconds.
	RefreshInterval time.Duration `yaml:"refreshInterval"`
}

// RemoteConfigEntry is the YAML shape for a single dynamic-config row.
// Mirrors Java RemoteConfig + uses a string slice for the UUID
// allowlist so YAML/JSON serialization is straightforward.
type RemoteConfigEntry struct {
	Name         string   `yaml:"name"`
	Percentage   int      `yaml:"percentage"`
	Value        string   `yaml:"value"`
	DefaultValue string   `yaml:"defaultValue"`
	HashKey      string   `yaml:"hashKey"`
	UUIDs        []string `yaml:"uuids"`
}

// BackupsConfig controls the backup subsystem, off by default; metadata uses Storage.Backend and blobs their own store.
type BackupsConfig struct {
	// Enabled gates construction of the entire backups subsystem.
	Enabled bool `yaml:"enabled"`
	// Blob picks which blob storage backend to wire under the
	// [backups.BlobStore] interface. Today the only implementation is
	// "filesystem"; S3/GCS/Azure adapters are added in future phases.
	Blob BackupsBlobConfig `yaml:"blob"`
	// ExpiryGraceHours overrides the default 30-day refresh grace for the
	// RemoveExpiredBackups worker. Zero uses the default.
	ExpiryGraceHours int `yaml:"expiryGraceHours"`
	// MaxTotalMediaSize caps the per-user paid-tier media quota in bytes.
	// Zero uses the [backups.DefaultMaxQuota] of 100 GiB.
	MaxTotalMediaSize int64 `yaml:"maxTotalMediaSize"`
}

// BackupsBlobConfig selects and configures the blob backend.
type BackupsBlobConfig struct {
	// Backend is "filesystem" today. Future values: "s3", "gcs", "azure".
	Backend string `yaml:"backend"`
	// Root is the on-disk directory used by the filesystem backend.
	Root string `yaml:"root"`
	// CDNNumber identifies which CDN this backend represents. Defaults
	// to 3 (the conventional backup-CDN number).
	CDNNumber int `yaml:"cdnNumber"`
}

// FrontendConfig serves the embedded SPA at / with client-side routing fallback when Enabled.
type FrontendConfig struct {
	// Enabled controls whether the embedded web UI is served. Defaults to
	// false so that existing deployments that run the server as a pure API
	// backend are unaffected.
	Enabled bool `yaml:"enabled"`
}

// ServerConfig holds HTTP/gRPC server settings.
type ServerConfig struct {
	// HTTPListen and GRPCListen are signald's listen addresses; empty disables a listener. Legacy Host/HTTPPort/GRPCPort fill them when unset.
	HTTPListen string `yaml:"httpListen"`
	GRPCListen string `yaml:"grpcListen"`

	// Host, HTTPPort and GRPCPort are the legacy form of the listen
	// addresses above.
	Host           string   `yaml:"host"`
	HTTPPort       int      `yaml:"httpPort"`
	GRPCPort       int      `yaml:"grpcPort"`
	TLSCertFile    string   `yaml:"tlsCertFile"`
	TLSKeyFile     string   `yaml:"tlsKeyFile"`
	MaxDevices     int      `yaml:"maxDevices"`
	TrustedProxies []string `yaml:"trustedProxies"`
	AllowedOrigins []string `yaml:"allowedOrigins"`
}

// StorageConfig holds database connection settings.
type StorageConfig struct {
	Backend  string         `yaml:"backend"` // "memory", "file", "qrdb", "dynamodb", "postgres"
	File     FileConfig     `yaml:"file"`
	DynamoDB DynamoDBConfig `yaml:"dynamodb"`
	Postgres PostgresConfig `yaml:"postgres"`
}

// FileConfig holds settings for the file-based KV storage backend.
type FileConfig struct {
	DataDir string `yaml:"dataDir"` // Root directory for data files.
}

// StaticResourcesConfig holds paths for serving static resources (emoji,
// dictionaries, release notes) that Signal clients expect.
type StaticResourcesConfig struct {
	ResourcesDir string `yaml:"resourcesDir"` // Served at /resources/{path}
	UpdatesDir   string `yaml:"updatesDir"`   // Served at /updates/{path}
}

// AttachmentConfig holds settings for attachment (CDN) storage.
type AttachmentConfig struct {
	StorageDir string `yaml:"storageDir"` // Local directory for file-based attachment storage.

	// TusURI is the external TUS server URL the v4 upload form points
	// clients at. When empty, the embedded /cdn3 TUS endpoint is used
	// (dev mode).
	TusURI string `yaml:"tusUri"`

	// TusSharedSecret is the HMAC key behind the Authorization: Basic <key>:<ts>:<hmac> header the TUS server checks.
	TusSharedSecret *secrets.SecureString `yaml:"tusSharedSecret"`
}

// DynamoDBConfig holds AWS DynamoDB settings.
type DynamoDBConfig struct {
	Region          string `yaml:"region"`
	Endpoint        string `yaml:"endpoint"`
	AccountsTable   string `yaml:"accountsTable"`
	MessagesTable   string `yaml:"messagesTable"`
	KeysTable       string `yaml:"keysTable"`
	ProfilesTable   string `yaml:"profilesTable"`
	PendingAccounts string `yaml:"pendingAccountsTable"`
}

// PostgresConfig holds PostgreSQL connection settings. URL takes precedence
// over the host/port/database/user fields when set — it is the cleanest
// way to wire a libpq-style connection string from a secret store.
type PostgresConfig struct {
	URL      *secrets.SecureString `yaml:"url"`
	Host     string                `yaml:"host"`
	Port     int                   `yaml:"port"`
	Database string                `yaml:"database"`
	User     string                `yaml:"user"`
	Password *secrets.SecureString `yaml:"password"`
	SSLMode  string                `yaml:"sslMode"`

	// Pool tuning. Zero means pgx default for that knob.
	MaxConns        int           `yaml:"maxConns"`
	MinConns        int           `yaml:"minConns"`
	MaxConnLifetime time.Duration `yaml:"maxConnLifetime"`
	MaxConnIdleTime time.Duration `yaml:"maxConnIdleTime"`
	ConnectTimeout  time.Duration `yaml:"connectTimeout"`
}

// DSN returns a libpq connection string: URL if set, else the fields; sslmode defaults to disable only when unset.
func (p PostgresConfig) DSN() string {
	if p.URL != nil {
		if u := p.URL.Plaintext(); u != "" {
			return u
		}
	}
	host := p.Host
	if host == "" {
		host = "localhost"
	}
	port := p.Port
	if port == 0 {
		port = 5432
	}
	sslMode := p.SSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	pwd := ""
	if p.Password != nil {
		pwd = p.Password.Plaintext()
	}
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		url.QueryEscape(p.User),
		url.QueryEscape(pwd),
		host, port,
		url.PathEscape(p.Database),
		sslMode,
	)
}

// CacheConfig holds Redis/cache settings.
type CacheConfig struct {
	Backend string      `yaml:"backend"` // "redis", "memory"
	Redis   RedisConfig `yaml:"redis"`
}

// RedisConfig holds Redis connection settings.
type RedisConfig struct {
	URL      string                `yaml:"url"`
	Password *secrets.SecureString `yaml:"password"`
	DB       int                   `yaml:"db"`
}

// PushConfig holds push notification service settings.
type PushConfig struct {
	APN APNConfig `yaml:"apn"`
	FCM FCMConfig `yaml:"fcm"`
}

// APNConfig holds Apple Push Notification settings.
type APNConfig struct {
	TeamID     string                `yaml:"teamId"`
	KeyID      string                `yaml:"keyId"`
	BundleID   string                `yaml:"bundleId"`
	PrivateKey *secrets.SecureString `yaml:"privateKey"`
	Sandbox    bool                  `yaml:"sandbox"`
}

// FCMConfig holds Firebase Cloud Messaging settings.
type FCMConfig struct {
	// ProjectID is the Firebase project ID. When empty, the provider
	// falls back to the project_id field embedded in the service account.
	ProjectID   string                `yaml:"projectId"`
	Credentials *secrets.SecureString `yaml:"credentials"`
}

// CDNConfig holds CDN/attachment storage settings.
type CDNConfig struct {
	Bucket    string                `yaml:"bucket"`
	Region    string                `yaml:"region"`
	AccessKey *secrets.SecureString `yaml:"accessKey"`
	SecretKey *secrets.SecureString `yaml:"secretKey"`
}

// LimitsConfig holds one token bucket per endpoint category; zero fields use limits.DefaultConfig.
type LimitsConfig struct {
	// Registration: rate limit for account registration endpoints (key: remote IP).
	Registration RateLimitConfig `yaml:"registration"`
	// Messages: rate limit for message send endpoints (key: account UUID).
	Messages RateLimitConfig `yaml:"messages"`
	// PreKeys: rate limit for pre-key fetch endpoints (key: account UUID).
	PreKeys RateLimitConfig `yaml:"preKeys"`
	// Profiles: rate limit for profile read/write endpoints (key: account UUID).
	// Replaces the deprecated "profile" key.
	Profiles RateLimitConfig `yaml:"profiles"`
	// Attachments: rate limit for attachment upload endpoints (key: account UUID).
	// Replaces the deprecated "attachment" key.
	Attachments RateLimitConfig `yaml:"attachments"`
	// Verification: rate limit for verification session endpoints (key: remote IP).
	Verification RateLimitConfig `yaml:"verification"`
	// PIN: rate limit for PIN attempt endpoints (key: account UUID).
	PIN RateLimitConfig `yaml:"pin"`
	// Usernames: rate limit for username operations (key: account UUID).
	Usernames RateLimitConfig `yaml:"usernames"`
	// Authentication: rate limit for failed authentication attempts (key: IP or UUID).
	Authentication RateLimitConfig `yaml:"authentication"`
	// AccountCheck: rate limit for account existence checks (key: remote IP).
	AccountCheck RateLimitConfig `yaml:"accountCheck"`
	// CaptchaAttempt: rate limit for captcha attempts (key: remote IP).
	CaptchaAttempt RateLimitConfig `yaml:"captchaAttempt"`
	// CaptchaSuccess: rate limit for captcha successes (key: remote IP).
	CaptchaSuccess RateLimitConfig `yaml:"captchaSuccess"`
	// DeviceAllocate: rate limit for device provisioning allocation (key: account UUID).
	DeviceAllocate RateLimitConfig `yaml:"deviceAllocate"`
	// DeviceVerify: rate limit for device provisioning verification (key: account UUID).
	DeviceVerify RateLimitConfig `yaml:"deviceVerify"`
	// InboundMessageBytes: rate limit for inbound message byte volume (key: account UUID).
	InboundMessageBytes RateLimitConfig `yaml:"inboundMessageBytes"`
}

// RateLimitConfig is a token bucket: BucketSize tokens refilled at LeakRatePerMin.
type RateLimitConfig struct {
	BucketSize     int `yaml:"bucketSize"`
	LeakRatePerMin int `yaml:"leakRatePerMin"`
}

// FraudConfig holds registration fraud detection settings.
// Zero values cause the fraud checker to use hardcoded defaults:
// MaxRegistrationsPerIP=10, MaxRegistrationsPerPrefix=50, WindowMinutes=60.
type FraudConfig struct {
	// MaxRegistrationsPerIP is the maximum number of registration attempts
	// permitted from a single IP address within the rolling window.
	// Zero uses the default of 10.
	MaxRegistrationsPerIP int `yaml:"maxRegistrationsPerIP"`
	// MaxRegistrationsPerPrefix is the maximum number of registration attempts
	// permitted for a single phone number prefix within the rolling window.
	// Zero uses the default of 50.
	MaxRegistrationsPerPrefix int `yaml:"maxRegistrationsPerPrefix"`
	// WindowMinutes is the duration of the rolling tracking window in minutes.
	// Zero uses the default of 60 minutes.
	WindowMinutes int `yaml:"windowMinutes"`
}

// TurnConfig holds TURN server credential settings.
type TurnConfig struct {
	Cloudflare CloudflareTurnConfig `yaml:"cloudflare"`
}

// CloudflareTurnConfig holds Cloudflare TURN API integration settings.
type CloudflareTurnConfig struct {
	APIToken               *secrets.SecureString `yaml:"apiToken"`
	Endpoint               string                `yaml:"endpoint"`
	URLs                   []string              `yaml:"urls"`
	URLsWithIPs            []string              `yaml:"urlsWithIps"`
	Hostname               string                `yaml:"hostname"`
	RequestedCredentialTTL string                `yaml:"requestedCredentialTtl"`
	ClientCredentialTTL    string                `yaml:"clientCredentialTtl"`
	NumHTTPClients         int                   `yaml:"numHttpClients"`
}

// ZKConfig holds zero-knowledge proof server parameters.
type ZKConfig struct {
	ServerSecret *secrets.SecureString `yaml:"serverSecret"`
	SigningKey   *secrets.SecureString `yaml:"signingKey"`
	Enabled      bool                  `yaml:"enabled"`
}

// PaymentsConfig holds payment processing settings.
type PaymentsConfig struct {
	Stripe StripeConfig `yaml:"stripe"`
}

// StripeConfig holds Stripe API settings.
type StripeConfig struct {
	APIKey        *secrets.SecureString `yaml:"apiKey"`
	WebhookSecret *secrets.SecureString `yaml:"webhookSecret"`
}

// CallingZKConfig holds zero-knowledge parameters for call link credentials.
type CallingZKConfig struct {
	ServerSecret *secrets.SecureString `yaml:"serverSecret"`
}

// CallQualitySurveyConfig holds call quality survey publishing settings.
type CallQualitySurveyConfig struct {
	Backend string       `yaml:"backend"` // "log" or "pubsub"
	PubSub  PubSubConfig `yaml:"pubSub"`
}

// PubSubConfig holds Google Cloud Pub/Sub settings.
type PubSubConfig struct {
	ProjectID string `yaml:"projectId"`
	TopicID   string `yaml:"topicId"`
}

// DirectoryConfig holds contact discovery settings.
type DirectoryConfig struct {
	Enabled bool `yaml:"enabled"`
}

// destroyConfig is Config.Destroy, a variable so tests can observe the failed-load cleanup.
var destroyConfig = (*Config).Destroy

// Load reads and parses a YAML configuration file; a failed load wipes the secrets it already sealed.
func Load(path string) (*Config, error) {
	return LoadWithFlags(path, nil)
}

// LoadWithFlags is Load with the address flags the operator set applied last; nil flags applies none.
func LoadWithFlags(path string, flags *pflag.FlagSet) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &ConfigLoadError{Path: path, Cause: err}
	}
	// Zero the raw YAML bytes after parsing to prevent secrets from
	// lingering in unprotected heap memory.
	defer func() {
		for i := range data {
			data[i] = 0
		}
	}()

	config := &Config{}
	applyDefaults(config)
	// Guarded by the success flag rather than placed on each error path, so a
	// future early return cannot forget it.
	loaded := false
	defer func() {
		if !loaded {
			destroyConfig(config)
		}
	}()

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, &ConfigParseError{Path: path, Cause: err}
	}
	applyEnv(config)
	applyFlags(config, flags)

	if err := validateAddresses(config); err != nil {
		return nil, err
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	loaded = true
	return config, nil
}

// Destroy wipes all sensitive configuration values from protected memory.
// Call this during shutdown to ensure no secret material remains resident.
func (c *Config) Destroy() {
	// Nil-safe so every daemon can register `defer cfg.Destroy()` on entry,
	// before it has established that a config was loaded at all.
	if c == nil {
		return
	}
	// Every *secrets.SecureString in Config must be listed; TestDestroy_WipesEveryProtectedFieldInTheConfigTree enforces it.
	for _, ss := range []*secrets.SecureString{
		c.Storage.Postgres.URL,
		c.Storage.Postgres.Password,
		c.Cache.Redis.Password,
		c.Push.APN.PrivateKey,
		c.Push.FCM.Credentials,
		c.CDN.AccessKey,
		c.CDN.SecretKey,
		c.Turn.Cloudflare.APIToken,
		c.ZKConfig.ServerSecret,
		c.ZKConfig.SigningKey,
		c.CallingZKConfig.ServerSecret,
		c.Payments.Stripe.APIKey,
		c.Payments.Stripe.WebhookSecret,
		c.Captcha.SecretKey,
		c.Verification.SMTP.Password,
		c.Verification.Twilio.AuthToken,
		c.Attachments.TusSharedSecret,
		c.StorageService.SharedSecret,
		c.CDSI.SharedSecret,
		c.SVR2.SharedSecret,
	} {
		if ss != nil {
			ss.Destroy()
		}
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *Config) Validate() error {
	resolveServerListeners(c)
	if c.Server.HTTPListen == "" && c.Server.GRPCListen == "" {
		return &ConfigValidationError{Field: "server", Message: "at least one of httpListen or grpcListen must be set"}
	}
	for _, d := range []struct{ key, addr string }{
		{string(KeyServerHTTPListen), c.Server.HTTPListen},
		{string(KeyServerGRPCListen), c.Server.GRPCListen},
	} {
		if d.addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(d.addr); err != nil {
			return &ConfigValidationError{Field: d.key, Message: "listen address must be host:port"}
		}
	}
	if c.Storage.Backend == "" {
		return &ConfigValidationError{Field: "storage.backend", Message: "storage backend is required"}
	}
	if c.Server.MaxDevices == 0 {
		c.Server.MaxDevices = 6 // Signal default
	}
	if c.IsProduction() {
		if err := c.validateProduction(); err != nil {
			return err
		}
	}
	return nil
}

// IsProduction reports whether Mode is "production", case-insensitively.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(strings.TrimSpace(c.Mode), "production")
}

// testCallingZKSecret is the well-known development calling-ZK secret
// shipped in configs/signal-server.yml. It must never reach production.
const testCallingZKSecret = "test-calling-zk-secret-32bytes!!"

// devCDNAccessKey and devCDNSecretKey are the development CDN placeholders, refused in production.
const (
	devCDNAccessKey = "dev-access-key"
	// #nosec G101 -- the placeholder from configs/signal-server.yml, not a credential; validateProduction rejects it by value.
	devCDNSecretKey = "dev-secret-key"
)

// validateProduction rejects every development affordance and reports all violations at once.
func (c *Config) validateProduction() error {
	var v []string

	// Durable, real storage only — memory loses data on restart, qrdb is
	// wired to an in-process fake transport, and dynamodb is unimplemented
	// (it silently falls through to memory).
	switch c.Storage.Backend {
	case "postgres", "file":
	default:
		v = append(v, "storage.backend must be 'postgres' or 'file' in production (got "+
			quoteEmpty(c.Storage.Backend)+"; memory/qrdb/dynamodb are not durable production backends)")
	}

	// Cross-instance message delivery (WebSocket wake-ups) requires a
	// shared cache. The in-memory cache cannot fan out across replicas.
	if c.Cache.Backend != "redis" {
		v = append(v, "cache.backend must be 'redis' in production (got "+
			quoteEmpty(c.Cache.Backend)+"; the memory cache breaks multi-instance delivery)")
	}

	// Verification codes must actually be delivered, and never fixed.
	if c.Verification.Transport == "" || c.Verification.Transport == "stub" {
		v = append(v, "verification.transport must be a real transport (e.g. 'twilio' or 'smtp') in production; the stub transport only logs codes")
	}
	if c.Verification.FixedCode != "" {
		v = append(v, "verification.fixedCode must be empty in production (a fixed code bypasses verification)")
	}

	// A real CAPTCHA provider is required for registration anti-abuse.
	switch c.Captcha.Provider {
	case "hcaptcha", "recaptcha":
	default:
		v = append(v, "captcha.provider must be 'hcaptcha' or 'recaptcha' in production (got "+
			quoteEmpty(c.Captcha.Provider)+"; 'test' accepts any token)")
	}

	// Profile-key / group ZK credentials must use a provisioned server
	// secret. Without it certificates.Manager issues an HMAC placeholder
	// that is not a valid zkgroup credential.
	if !c.ZKConfig.Enabled || c.ZKConfig.ServerSecret.IsEmpty() {
		v = append(v, "zkConfig must be enabled with a non-empty serverSecret in production (otherwise profile-key credentials are an insecure stub)")
	}
	if c.CallingZKConfig.ServerSecret.IsEmpty() {
		v = append(v, "callingZkConfig.serverSecret must be set in production")
	} else if c.CallingZKConfig.ServerSecret.Equals(testCallingZKSecret) {
		v = append(v, "callingZkConfig.serverSecret is the well-known development secret and must be replaced in production")
	}

	// The development CDN placeholders authenticate against nothing, so production refuses them.
	// Region is required alongside the rest: AvatarCDNConfig.Enabled() checks
	// bucket, region AND access key, so a config missing only the region
	// fails closed at runtime with a 503 on every avatar upload rather than
	// at boot where an operator would see it.
	if c.CDN.AccessKey.IsEmpty() || c.CDN.SecretKey.IsEmpty() || c.CDN.Bucket == "" || c.CDN.Region == "" {
		v = append(v, "cdn.bucket, cdn.region, cdn.accessKey and cdn.secretKey are required in production (avatar and attachment uploads are signed with them)")
	} else if c.CDN.AccessKey.Equals(devCDNAccessKey) || c.CDN.SecretKey.Equals(devCDNSecretKey) {
		v = append(v, "cdn.accessKey/cdn.secretKey are the well-known development placeholders and must be replaced in production")
	}

	// TLS is mandatory for the chat server.
	if c.Server.TLSCertFile == "" || c.Server.TLSKeyFile == "" {
		v = append(v, "server.tlsCertFile and server.tlsKeyFile are required in production")
	}

	// Wildcard CORS/WebSocket origins are never acceptable in production.
	for _, o := range c.Server.AllowedOrigins {
		if o == "*" {
			v = append(v, "server.allowedOrigins must not contain '*' in production")
			break
		}
	}

	// A zero message bucket disables the message spam check (fail-open).
	if c.Limits.Messages.BucketSize == 0 {
		v = append(v, "limits.messages.bucketSize must be > 0 in production (a zero bucket disables the message spam check)")
	}

	// Plaintext gRPC/HTTP to external services is never acceptable in
	// production, regardless of whether the corresponding remote is wired.
	if c.Verification.RemoteInsecure {
		v = append(v, "verification.remoteInsecure must be false in production")
	}
	if c.KeyTransparency.RemoteInsecure {
		v = append(v, "keyTransparency.remoteInsecure must be false in production")
	}
	if c.StorageService.RemoteInsecure {
		v = append(v, "storageService.remoteInsecure must be false in production")
	}

	if len(v) > 0 {
		return &ProductionValidationError{Violations: v}
	}
	return nil
}

// quoteEmpty renders s for error messages, making the empty string
// visible as "" rather than vanishing.
func quoteEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return "'" + s + "'"
}

// ConfigLoadError indicates a failure to load the configuration file.
type ConfigLoadError struct {
	Path  string
	Cause error
}

func (e *ConfigLoadError) Error() string {
	return "failed to load config from " + e.Path + ": " + e.Cause.Error()
}

func (e *ConfigLoadError) Unwrap() error {
	return e.Cause
}

// ConfigParseError indicates a failure to parse the configuration file.
type ConfigParseError struct {
	Path  string
	Cause error
}

func (e *ConfigParseError) Error() string {
	return "failed to parse config from " + e.Path + ": " + e.Cause.Error()
}

func (e *ConfigParseError) Unwrap() error {
	return e.Cause
}

// ConfigValidationError indicates a configuration validation failure.
type ConfigValidationError struct {
	Field   string
	Message string
}

func (e *ConfigValidationError) Error() string {
	return "config validation error: " + e.Field + ": " + e.Message
}

// ProductionValidationError aggregates every production-mode security
// violation found during validation so an operator can fix them all at
// once. It is returned only when mode is "production".
type ProductionValidationError struct {
	Violations []string
}

func (e *ProductionValidationError) Error() string {
	return "production config validation failed (" +
		strconv.Itoa(len(e.Violations)) + " violation(s)):\n  - " +
		strings.Join(e.Violations, "\n  - ")
}
