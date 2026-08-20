// Package config provides configuration loading and validation for the Signal server.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// Config is the top-level server configuration.
type Config struct {
	// Mode selects the deployment profile. "production" activates a
	// fail-closed security gate (see validateProduction) that refuses to
	// boot with development/test settings (stub verification, fixedCode,
	// test captcha, stub ZK credentials, non-durable storage, plaintext
	// transports, wildcard CORS, fail-open abuse checks). Any other value
	// (including the empty default) is treated as development.
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
}

// KeyTransparencyConfig configures the standalone key-transparency
// binary and signald's chat-server-to-KT gRPC client. signald never
// reads/writes the log directly; mobile clients hit signald's REST
// endpoints which proxy to the remote KT service.
type KeyTransparencyConfig struct {
	// GRPCListen is the host:port the binary binds the
	// KeyTransparencyQueryService gRPC listener to. Defaults to
	// 0.0.0.0:8098.
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

// StorageServiceConfig configures the standalone storage-service binary
// and signald-side wiring. Mirrors svr2 / cdsi: HMAC credentials are
// the shared-secret hinge, mobile clients connect directly to storage-
// service, and signald only calls the admin DELETE endpoint on
// account deletion.
type StorageServiceConfig struct {
	// HTTPListen is the host:port the binary binds to. Defaults to
	// 0.0.0.0:8096 when empty.
	HTTPListen string `yaml:"httpListen"`

	// SharedSecret is the HMAC secret signald and storage-service
	// share for credential derivation. Required. Held in protected
	// memory and wiped by Config.Destroy.
	SharedSecret *secrets.SecureString `yaml:"sharedSecret"`

	// RemoteURL is the storage-service admin endpoint signald calls
	// for DELETE-on-account-deletion (matches Java's
	// SecureStorageClient deleteStoredData path). Empty disables the
	// client (monolithic deployments).
	RemoteURL string `yaml:"remoteUrl"`

	// RemoteInsecure permits a plaintext HTTP channel from signald
	// to storage-service. Required for development / docker-compose;
	// production must leave this false (TLS 1.3 minimum).
	RemoteInsecure bool `yaml:"remoteInsecure"`
}

// CDSIConfig configures the standalone cdsi binary and (when needed)
// signald-side wiring. The chat-server doesn't have a CDSI HTTP
// client (mobile clients connect to cdsi directly); the chat-server
// only exposes the DirectoryService gRPC stream cdsi consumes plus
// /v2/directory/auth HMAC credential issuance.
type CDSIConfig struct {
	// WSListen is the host:port the cdsi binary binds the client-
	// facing WebSocket listener to. Defaults to 0.0.0.0:8094.
	WSListen string `yaml:"wsListen"`

	// Attestation is the attester flavour for the WebSocket Noise
	// handshake. Same options as SVR2Config.Attestation:
	// "software" (default) or "tpm".
	Attestation string `yaml:"attestation"`

	// SharedSecret is the HMAC secret signald shares with cdsi for
	// credential derivation. Mobile clients present
	// HMAC(sharedSecret, accountUUID) as the Basic auth password on
	// WebSocket upgrade. Required. Held in protected memory and wiped
	// by Config.Destroy.
	SharedSecret *secrets.SecureString `yaml:"sharedSecret"`

	// SignaldDirectoryAddr is the gRPC endpoint cdsi calls at startup
	// to populate its local directory index from signald's
	// DirectoryService. Required.
	SignaldDirectoryAddr string `yaml:"signaldDirectoryAddr"`

	// SignaldDirectoryInsecure permits a plaintext gRPC channel to
	// the signald DirectoryService. Required for development /
	// docker-compose; production deployments must leave this false
	// and supply mTLS.
	SignaldDirectoryInsecure bool `yaml:"signaldDirectoryInsecure"`
}

// SVR2Config configures the standalone svr2 binary and signald's
// chat-server-to-svr2 admin client. The binary reads HTTPListen +
// WSListen + Attestation + SharedSecret; signald only reads RemoteURL
// + SharedSecret to wire its HTTP DELETE admin client.
type SVR2Config struct {
	// HTTPListen is the host:port the binary binds the admin HTTP
	// listener to (handles DELETE /v1/delete). Defaults to
	// 0.0.0.0:8091 when empty.
	HTTPListen string `yaml:"httpListen"`

	// WSListen is the host:port the binary binds the
	// client-facing WebSocket listener to (Noise NKhfs over
	// WebSocket). Defaults to 0.0.0.0:8092 when empty.
	WSListen string `yaml:"wsListen"`

	// Attestation selects the attestation flavour:
	//   - "software" (default): ed25519 deployment-cert signing
	//   - "tpm": TPM 2.0 (requires the binary to be embedded in a
	//     host application that injects a TPM via attestation.NewTPM —
	//     go-signal does not bind a TPM transport itself; standalone
	//     cmd/svr2 + cmd/cdsi runs must use "software")
	Attestation string `yaml:"attestation"`

	// SharedSecret is the HMAC secret the chat-server uses to sign
	// SVR2 client credentials. svr2 validates inbound credentials
	// against the same secret. Required when Attestation != "" so
	// the binary knows which keyspace to trust. Held in protected
	// memory and wiped by Config.Destroy.
	SharedSecret *secrets.SecureString `yaml:"sharedSecret"`

	// RemoteURL is the chat-server-side admin endpoint used by
	// signald's SecureValueRecoveryClient for DELETE-on-account
	// -deletion. Empty disables the call entirely (development
	// monolith builds with no separate svr2 binary).
	RemoteURL string `yaml:"remoteUrl"`
}

// RemoteConfigBlock configures the dynamic feature-flag subsystem. The
// Defaults list is upserted into the configured remote-config store at
// boot. The store backend follows cfg.Storage.Backend — postgres uses
// the remote_config table, file/qrdb use a KV-backed store, memory
// mode stays in-process. Admin REST writes go through the same store,
// so live edits persist without a restart.
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

// BackupsConfig controls the message-archive (backup) subsystem. Disabled
// by default; signald only constructs the backups stack when Enabled is
// true. The metadata store reuses Storage.Backend (memory/qrdb/postgres);
// the blob store is configured separately because production blob storage
// is typically S3 / GCS, not the same engine that holds the metadata.
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

// FrontendConfig controls whether the embedded React SPA is served by the
// HTTP server. When Enabled is true, the server registers a catch-all handler
// that serves the compiled Vite output at the root path (/), with SPA
// fallback routing so that the web client's client-side router works correctly.
type FrontendConfig struct {
	// Enabled controls whether the embedded web UI is served. Defaults to
	// false so that existing deployments that run the server as a pure API
	// backend are unaffected.
	Enabled bool `yaml:"enabled"`
}

// ServerConfig holds HTTP/gRPC server settings.
type ServerConfig struct {
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

	// TusSharedSecret is the HMAC key the external TUS server validates
	// against. The server emits an `Authorization: Basic <key>:<ts>:<hmac>`
	// header; the TUS server replays the HMAC and rejects mismatches.
	// Mirrors Java TusConfiguration.userAuthenticationTokenSharedSecret.
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

// DSN builds a libpq-style connection string. URL wins if set; otherwise
// the structured fields are assembled. SSLMode defaults to "disable" only
// when both URL and SSLMode are unset — production deployments must set
// it explicitly via either the URL query parameter or sslMode field.
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

// LimitsConfig holds rate limiting settings for all Signal endpoint
// categories. Each field maps to a distinct token-bucket limiter in the
// limits.Registry. Zero-valued fields cause the corresponding limiter to fall
// back to the Signal-Server production defaults defined in limits.DefaultConfig.
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

// RateLimitConfig holds a single token-bucket rate limit configuration.
// BucketSize is the maximum number of tokens. LeakRatePerMin is the number
// of tokens refilled per minute; it is converted to a per-second RefillRate
// when building the limits.Registry.
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

// destroyConfig is Config.Destroy, indirected so the failed-load cleanup path
// can be observed by tests — a wipe of a Config the caller never receives has
// no other observable effect. Production code never reassigns it. Mirrors the
// sealSecret seam in pkg/config/secrets.
var destroyConfig = (*Config).Destroy

// Load reads and parses a YAML configuration file.
//
// A load that fails wipes whatever it had already sealed. yaml.v3 populates
// field by field and reports type errors only at the end, so a Config that
// failed to decode — or that decoded and then failed Validate — can already
// own protected allocations. Those never reach the caller, so the caller can
// never wipe them; without this they would stay resident for the life of the
// process. That matters most where a failed load is not immediately followed
// by exit: an in-process reload, or a supervisor retrying a bad file.
func Load(path string) (*Config, error) {
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
	// Every *secrets.SecureString reachable from Config must appear here.
	// The list is hand-maintained and has drifted once already
	// (Storage.Postgres.URL was missing), so
	// TestDestroy_WipesEveryProtectedFieldInTheConfigTree walks the tree by
	// reflection and fails if a field is added to Config without being added
	// here. Add the field to both, or the test will say so.
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
	if c.Server.HTTPPort == 0 && c.Server.GRPCPort == 0 {
		return &ConfigValidationError{Field: "server", Message: "at least one of httpPort or grpcPort must be set"}
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

// IsProduction reports whether the deployment profile is "production".
// The comparison is case-insensitive so "Production"/"PRODUCTION" also
// activate the gate.
func (c *Config) IsProduction() bool {
	return strings.EqualFold(strings.TrimSpace(c.Mode), "production")
}

// testCallingZKSecret is the well-known development calling-ZK secret
// shipped in configs/signal-server.yml. It must never reach production.
const testCallingZKSecret = "test-calling-zk-secret-32bytes!!"

// validateProduction enforces a fail-closed security baseline. Every
// development/test affordance that would silently weaken a real
// deployment is a hard error here; all violations are collected so an
// operator sees the full list in one boot attempt rather than fixing
// them one at a time.
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
	if !c.ZKConfig.Enabled || secretEmpty(c.ZKConfig.ServerSecret) {
		v = append(v, "zkConfig must be enabled with a non-empty serverSecret in production (otherwise profile-key credentials are an insecure stub)")
	}
	if secretEmpty(c.CallingZKConfig.ServerSecret) {
		v = append(v, "callingZkConfig.serverSecret must be set in production")
	} else if c.CallingZKConfig.ServerSecret.Plaintext() == testCallingZKSecret {
		v = append(v, "callingZkConfig.serverSecret is the well-known development secret and must be replaced in production")
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

// secretEmpty reports whether a secure string carries no usable value.
func secretEmpty(ss *secrets.SecureString) bool {
	return ss == nil || ss.IsDestroyed() || ss.Plaintext() == ""
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
