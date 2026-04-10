// Package config provides configuration loading and validation for the Signal server.
package config

import (
	"os"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"gopkg.in/yaml.v3"
)

// Config is the top-level server configuration.
type Config struct {
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
	Backend  string         `yaml:"backend"` // "memory", "file", "dynamodb", "postgres"
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

// PostgresConfig holds PostgreSQL connection settings.
type PostgresConfig struct {
	Host     string                `yaml:"host"`
	Port     int                   `yaml:"port"`
	Database string                `yaml:"database"`
	User     string                `yaml:"user"`
	Password *secrets.SecureString `yaml:"password"`
	SSLMode  string                `yaml:"sslMode"`
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

// Load reads and parses a YAML configuration file.
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
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, &ConfigParseError{Path: path, Cause: err}
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Destroy wipes all sensitive configuration values from protected memory.
// Call this during shutdown to ensure no secret material remains resident.
func (c *Config) Destroy() {
	for _, ss := range []*secrets.SecureString{
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
	return nil
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
