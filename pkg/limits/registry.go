package limits

// Registry holds a named set of RateLimiters, one per Signal endpoint
// category. Create it once at startup and share it across all handlers.
type Registry struct {
	registration    RateLimiter
	messages        RateLimiter
	preKeys         RateLimiter
	profiles        RateLimiter
	attachments     RateLimiter
	verification    RateLimiter
	pin             RateLimiter
	usernames       RateLimiter
	authentication  RateLimiter
	accountCheck    RateLimiter
	captchaAttempt  RateLimiter
	captchaSuccess  RateLimiter
	deviceAllocate  RateLimiter
	deviceVerify    RateLimiter
	inboundMsgBytes RateLimiter
	setBackupID     RateLimiter
	setPaidMediaID  RateLimiter
	backupAttach    RateLimiter
	createCallLink  RateLimiter
}

// NewRegistry creates a Registry using the supplied Config.  For each
// BucketConfig with a zero BucketSize or RefillRate, the corresponding
// DefaultConfig value is substituted so that callers can supply a partial
// Config and still get sane defaults.
func NewRegistry(cfg Config) *Registry {
	def := DefaultConfig()
	return &Registry{
		registration:    NewTokenBucketLimiter(mergeConfig(cfg.Registration, def.Registration)),
		messages:        NewTokenBucketLimiter(mergeConfig(cfg.Messages, def.Messages)),
		preKeys:         NewTokenBucketLimiter(mergeConfig(cfg.PreKeys, def.PreKeys)),
		profiles:        NewTokenBucketLimiter(mergeConfig(cfg.Profiles, def.Profiles)),
		attachments:     NewTokenBucketLimiter(mergeConfig(cfg.Attachments, def.Attachments)),
		verification:    NewTokenBucketLimiter(mergeConfig(cfg.Verification, def.Verification)),
		pin:             NewTokenBucketLimiter(mergeConfig(cfg.PIN, def.PIN)),
		usernames:       NewTokenBucketLimiter(mergeConfig(cfg.Usernames, def.Usernames)),
		authentication:  NewTokenBucketLimiter(mergeConfig(cfg.Authentication, def.Authentication)),
		accountCheck:    NewTokenBucketLimiter(mergeConfig(cfg.AccountCheck, def.AccountCheck)),
		captchaAttempt:  NewTokenBucketLimiter(mergeConfig(cfg.CaptchaAttempt, def.CaptchaAttempt)),
		captchaSuccess:  NewTokenBucketLimiter(mergeConfig(cfg.CaptchaSuccess, def.CaptchaSuccess)),
		deviceAllocate:  NewTokenBucketLimiter(mergeConfig(cfg.DeviceAllocate, def.DeviceAllocate)),
		deviceVerify:    NewTokenBucketLimiter(mergeConfig(cfg.DeviceVerify, def.DeviceVerify)),
		inboundMsgBytes: NewTokenBucketLimiter(mergeConfig(cfg.InboundMessageBytes, def.InboundMessageBytes)),
		setBackupID:     NewTokenBucketLimiter(mergeConfig(cfg.SetBackupID, def.SetBackupID)),
		setPaidMediaID:  NewTokenBucketLimiter(mergeConfig(cfg.SetPaidMediaBackupID, def.SetPaidMediaBackupID)),
		backupAttach:    NewTokenBucketLimiter(mergeConfig(cfg.BackupAttachment, def.BackupAttachment)),
		createCallLink:  NewTokenBucketLimiter(mergeConfig(cfg.CreateCallLink, def.CreateCallLink)),
	}
}

// NewDefaultRegistry creates a Registry using DefaultConfig.
func NewDefaultRegistry() *Registry {
	return NewRegistry(DefaultConfig())
}

// ForRegistration returns the rate limiter for account registration endpoints.
// Key: remote IP address.
func (r *Registry) ForRegistration() RateLimiter { return r.registration }

// ForMessages returns the rate limiter for message send endpoints.
// Key: authenticated account UUID.
func (r *Registry) ForMessages() RateLimiter { return r.messages }

// ForPreKeys returns the rate limiter for pre-key fetch endpoints.
// Key: authenticated account UUID.
func (r *Registry) ForPreKeys() RateLimiter { return r.preKeys }

// ForProfiles returns the rate limiter for profile read/write endpoints.
// Key: authenticated account UUID.
func (r *Registry) ForProfiles() RateLimiter { return r.profiles }

// ForAttachments returns the rate limiter for attachment upload endpoints.
// Key: authenticated account UUID.
func (r *Registry) ForAttachments() RateLimiter { return r.attachments }

// ForVerification returns the rate limiter for verification session endpoints.
// Key: remote IP address.
func (r *Registry) ForVerification() RateLimiter { return r.verification }

// ForPIN returns the rate limiter for PIN attempt endpoints.
// Key: authenticated account UUID.
func (r *Registry) ForPIN() RateLimiter { return r.pin }

// ForUsernames returns the rate limiter for username hash/link endpoints.
// Key: authenticated account UUID.
func (r *Registry) ForUsernames() RateLimiter { return r.usernames }

// ForAuthentication returns the rate limiter for failed authentication attempts.
// Key: remote IP address or account UUID.
func (r *Registry) ForAuthentication() RateLimiter { return r.authentication }

// ForAccountCheck returns the rate limiter for account existence check endpoints.
// Prevents enumeration attacks on HEAD /v1/accounts/account/{identifier}.
// Key: remote IP address.
func (r *Registry) ForAccountCheck() RateLimiter { return r.accountCheck }

// ForCaptchaAttempt returns the rate limiter for captcha attempt endpoints.
// Key: remote IP address.
func (r *Registry) ForCaptchaAttempt() RateLimiter { return r.captchaAttempt }

// ForCaptchaSuccess returns the rate limiter for captcha success tracking.
// Key: remote IP address.
func (r *Registry) ForCaptchaSuccess() RateLimiter { return r.captchaSuccess }

// ForDeviceAllocate returns the rate limiter for device provisioning allocation.
// Key: authenticated account UUID.
func (r *Registry) ForDeviceAllocate() RateLimiter { return r.deviceAllocate }

// ForDeviceVerify returns the rate limiter for device provisioning verification.
// Key: authenticated account UUID.
func (r *Registry) ForDeviceVerify() RateLimiter { return r.deviceVerify }

// ForInboundMessageBytes returns the rate limiter for inbound message byte volume.
// Key: authenticated account UUID.
func (r *Registry) ForInboundMessageBytes() RateLimiter { return r.inboundMsgBytes }

// ForSetBackupID returns the rate limiter for PUT /v1/archives/backupid
// rotations of the message backup-id slot. Key: authenticated account UUID.
func (r *Registry) ForSetBackupID() RateLimiter { return r.setBackupID }

// ForSetPaidMediaBackupID returns the rate limiter for PUT /v1/archives/backupid
// rotations of the media backup-id slot on paid accounts. Key: authenticated
// account UUID.
func (r *Registry) ForSetPaidMediaBackupID() RateLimiter { return r.setPaidMediaID }

// ForBackupAttachment returns the rate limiter for temporary-attachment
// upload-form requests against the backup CDN. Key: base64 of the hashed
// backup-id (per Java BackupManager.rateLimitKey).
func (r *Registry) ForBackupAttachment() RateLimiter { return r.backupAttach }

// ForCreateCallLink returns the rate limiter for POST /v1/call-link/create-auth.
// Mirrors Java's `createCallLink` limiter — key: authenticated account UUID.
func (r *Registry) ForCreateCallLink() RateLimiter { return r.createCallLink }

// stopper is a private interface satisfied by any limiter that exposes a
// Stop method.  Using a local interface avoids widening the public RateLimiter
// contract while still supporting type-safe dispatch.
type stopper interface{ Stop() }

// Stop halts the background goroutines of all limiter fields.
// It is safe to call Stop multiple times; each underlying TokenBucketLimiter
// uses sync.Once so subsequent calls on an already-stopped limiter are no-ops.
func (r *Registry) Stop() {
	for _, rl := range []RateLimiter{
		r.registration,
		r.messages,
		r.preKeys,
		r.profiles,
		r.attachments,
		r.verification,
		r.pin,
		r.usernames,
		r.authentication,
		r.accountCheck,
		r.captchaAttempt,
		r.captchaSuccess,
		r.deviceAllocate,
		r.deviceVerify,
		r.inboundMsgBytes,
		r.setBackupID,
		r.setPaidMediaID,
		r.backupAttach,
		r.createCallLink,
	} {
		if s, ok := rl.(stopper); ok {
			s.Stop()
		}
	}
}

// mergeConfig returns override if its BucketSize and RefillRate are both
// non-zero; otherwise falls back to fallback.  This lets callers provide
// partial configs without losing mandatory defaults.
func mergeConfig(override, fallback BucketConfig) BucketConfig {
	if override.BucketSize > 0 && override.RefillRate > 0 {
		return override
	}
	return fallback
}
