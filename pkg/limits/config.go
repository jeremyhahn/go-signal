// Package limits provides token-bucket rate limiting for the Signal server.
// Configurations match the Java Signal-Server leaky-bucket defaults.
package limits

import "time"

// BucketConfig defines the parameters for a single token-bucket limiter.
type BucketConfig struct {
	// BucketSize is the maximum number of tokens the bucket can hold.
	BucketSize int
	// RefillRate is the number of tokens added per second.
	RefillRate float64
	// CleanupInterval controls how often stale buckets are purged.
	// Zero uses the package default (5 minutes).
	CleanupInterval time.Duration
	// StaleAfter is the duration after which an idle bucket is considered
	// stale and eligible for removal. Zero uses the package default (10 minutes).
	StaleAfter time.Duration
}

// defaultCleanupInterval is the interval at which the cleaner goroutine runs.
const defaultCleanupInterval = 5 * time.Minute

// defaultStaleAfter is the idle duration after which a bucket is removed.
const defaultStaleAfter = 10 * time.Minute

// Config aggregates rate limit configurations for each Signal endpoint
// category, matching the Java Signal-Server defaults.
type Config struct {
	// Registration: 6 requests per 30 seconds per IP.
	Registration BucketConfig
	// Messages: 60 sends per second per account UUID.
	Messages BucketConfig
	// PreKeys: 6 fetches per 10 minutes per account UUID.
	PreKeys BucketConfig
	// Profiles: 4320 reads per 20 seconds per account UUID.
	Profiles BucketConfig
	// Attachments: 50 uploads per 1.2 seconds per account UUID.
	Attachments BucketConfig
	// Verification: 6 attempts per 30 seconds per IP.
	Verification BucketConfig
	// PIN: 10 attempts per day per account UUID.
	PIN BucketConfig
	// Usernames: 100 operations per minute per account UUID.
	Usernames BucketConfig
	// Authentication: 10 failures per minute per source key.
	Authentication BucketConfig
	// AccountCheck: 1000 checks per 4 seconds per IP.
	// Prevents account-existence enumeration attacks on HEAD /v1/accounts/account/{identifier}.
	AccountCheck BucketConfig
	// CaptchaAttempt: 10 attempts per 24 hours per IP.
	CaptchaAttempt BucketConfig
	// CaptchaSuccess: 2 successes per 24 hours per IP.
	CaptchaSuccess BucketConfig
	// DeviceAllocate: 6 allocations per 2 minutes per account UUID.
	DeviceAllocate BucketConfig
	// DeviceVerify: 6 verifications per minute per account UUID.
	DeviceVerify BucketConfig
	// InboundMessageBytes: 256 MiB per minute per account UUID.
	InboundMessageBytes BucketConfig
}

// DefaultConfig returns a Config populated with Java Signal-Server defaults.
func DefaultConfig() Config {
	return Config{
		Registration: BucketConfig{
			BucketSize: 6,
			RefillRate: float64(6) / 30.0, // 6 per 30s
		},
		Messages: BucketConfig{
			BucketSize: 60,
			RefillRate: 60.0, // 60 per second
		},
		PreKeys: BucketConfig{
			BucketSize: 6,
			RefillRate: float64(6) / 600.0, // 6 per 10 minutes
		},
		Profiles: BucketConfig{
			BucketSize: 4320,
			RefillRate: float64(4320) / 20.0, // 4320 per 20s
		},
		Attachments: BucketConfig{
			BucketSize: 50,
			RefillRate: float64(50) / 1.2, // 50 per 1.2s
		},
		Verification: BucketConfig{
			BucketSize: 6,
			RefillRate: float64(6) / 30.0, // 6 per 30s
		},
		PIN: BucketConfig{
			BucketSize: 10,
			RefillRate: float64(10) / 86400.0, // 10 per day
		},
		Usernames: BucketConfig{
			BucketSize: 100,
			RefillRate: float64(100) / 60.0, // 100 per minute
		},
		Authentication: BucketConfig{
			BucketSize: 10,
			RefillRate: float64(10) / 60.0, // 10 per minute
		},
		AccountCheck: BucketConfig{
			BucketSize: 1000,
			RefillRate: 250.0, // 250 per second (1000 per 4 seconds)
		},
		CaptchaAttempt: BucketConfig{
			BucketSize: 10,
			RefillRate: float64(10) / 86400.0, // 10 per day
		},
		CaptchaSuccess: BucketConfig{
			BucketSize: 2,
			RefillRate: float64(2) / 86400.0, // 2 per day
		},
		DeviceAllocate: BucketConfig{
			BucketSize: 6,
			RefillRate: float64(6) / 120.0, // 6 per 2 minutes
		},
		DeviceVerify: BucketConfig{
			BucketSize: 6,
			RefillRate: float64(6) / 60.0, // 6 per minute
		},
		InboundMessageBytes: BucketConfig{
			BucketSize: 256 * 1024 * 1024,             // 256 MiB
			RefillRate: float64(256*1024*1024) / 60.0, // 256 MiB per minute
		},
	}
}
