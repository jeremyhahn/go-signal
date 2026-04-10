package rest

import (
	"context"
	"crypto/tls"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/attachments"
	apiws "github.com/jeremyhahn/go-signal/pkg/api/websocket"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/service"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/directory"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securevaluerecovery"
	"github.com/jeremyhahn/go-signal/pkg/spam"
	"github.com/jeremyhahn/go-signal/pkg/stickers"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// Server implements the Signal Server REST API using the standard net/http
// package with Go 1.22+ pattern matching.
type Server struct {
	httpServer *http.Server
	// listener is the active network listener. Access is protected by
	// listenerMu to prevent data races when Start() sets the listener
	// concurrently with Addr() reading it.
	listener        net.Listener
	listenerMu      sync.RWMutex
	logger          *slog.Logger
	tlsCertFile     string
	tlsKeyFile      string
	accounts        *accounts.AccountsManager
	captcha         *captcha.CaptchaManager
	certificates    *certificates.CertificatesManager
	keys            *keys.KeysManager
	messages        *messages.MessagesManager
	profiles        *profiles.ProfilesManager
	stickers        *stickers.StickersManager
	directory       *directory.DirectoryManager
	secureStorage   *securestorage.SecureStorageManager
	svr             *securevaluerecovery.SVRManager
	calling         *calling.CallingManager
	callSignaling   service.CallSignalingService
	keyTransparency *keytransparency.KeyTransparencyManager
	usernames       *usernames.UsernamesManager
	devices         *devices.DevicesManager
	wsHandler       *apiws.Handler
	wsSessions      *signalws.SessionManager
	verification    *verification.Manager
	rateLimits      *limits.Registry
	spamChecker     spam.SpamChecker
	fraudChecker    spam.RegistrationFraudChecker
	reportStore     messages.ReportStore
	loopDetector    *messages.DeliveryLoopDetector

	// attachmentStore persists CDN attachment uploads.
	attachmentStore    attachments.Store
	staticResourcesDir string

	// frontendFS is the embedded file system for the React SPA. When non-nil
	// a catch-all handler is registered at GET / that serves the SPA with
	// SPA fallback routing and appropriate cache headers.
	frontendFS fs.FS

	// webUIHandler serves the client-facing /api/v1/* REST endpoints for the
	// web UI. When non-nil, the web UI routes are registered alongside the
	// Signal protocol routes.
	webUIHandler *WebUIHandler

	// webUIEventHub manages WebSocket connections for real-time events to
	// the web UI.
	webUIEventHub *WebUIEventHub

	// allowedOrigins holds the permitted Origin header values for WebSocket
	// upgrade requests. Used by SVR2 and delegated to the WebSocket handler.
	allowedOrigins []string

	// clientVersion holds the client version deprecation/blocking policy.
	// When nil, no version checks are applied.
	clientVersion *ClientVersionConfig

	// mux is the ServeMux used by this server. It is stored here so that
	// post-construction route registration (e.g. RegisterFIDO2) can add new
	// routes to the same mux that is already wrapped inside the middleware
	// chain.
	mux *http.ServeMux

	// routeRegistrars holds extension route registration functions added via
	// build-tagged packages (e.g., FIDO2). Each function is called at the end
	// of routes() with the mux and an auth middleware wrapper.
	routeRegistrars []func(mux *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc)

	// trustedProxies holds parsed CIDR ranges for trusted reverse proxies.
	// When non-empty, ipKey only trusts X-Forwarded-For from these sources.
	trustedProxies []*net.IPNet
}

// ServerConfig holds the configuration required to create a new Server.
type ServerConfig struct {
	Host            string
	Port            int
	TLSCertFile     string
	TLSKeyFile      string
	Logger          *slog.Logger
	Accounts        *accounts.AccountsManager
	Captcha         *captcha.CaptchaManager
	Certificates    *certificates.CertificatesManager
	Keys            *keys.KeysManager
	Messages        *messages.MessagesManager
	Profiles        *profiles.ProfilesManager
	Stickers        *stickers.StickersManager
	Directory       *directory.DirectoryManager
	SecureStorage   *securestorage.SecureStorageManager
	SVR             *securevaluerecovery.SVRManager
	Calling         *calling.CallingManager
	CallSignaling   service.CallSignalingService
	KeyTransparency *keytransparency.KeyTransparencyManager
	Usernames       *usernames.UsernamesManager
	Devices         *devices.DevicesManager
	WSSessions      *signalws.SessionManager
	Verification    *verification.Manager
	// RateLimits is the rate limiter registry applied to critical routes.
	// When nil, rate limiting is disabled. Production deployments should
	// always supply a registry; use limits.NewDefaultRegistry().
	RateLimits *limits.Registry
	// SpamChecker is the spam detection policy applied before each message
	// send. When nil, a NoOpChecker is used and all messages are allowed.
	SpamChecker spam.SpamChecker
	// FraudChecker evaluates registration requests for fraud signals.
	// When nil, a NoOpFraudChecker is used and all registrations are allowed.
	FraudChecker spam.RegistrationFraudChecker
	// ReportStore is the persistence layer for spam reports submitted via
	// POST /v1/messages/report/{source}/{messageGuid}. When nil, reports are
	// logged but not persisted.
	ReportStore messages.ReportStore
	// LoopDetector is the delivery-loop detection component. When non-nil it is
	// consulted before each message store operation. When nil, loop detection is
	// disabled.
	LoopDetector *messages.DeliveryLoopDetector
	// ReadTimeout is the maximum duration for reading the entire request,
	// including the body. Zero uses DefaultReadTimeout (30s).
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out writes of the
	// response. Zero uses DefaultWriteTimeout (60s).
	WriteTimeout time.Duration
	// IdleTimeout is the maximum amount of time to wait for the next request
	// when keep-alives are enabled. Zero uses DefaultIdleTimeout (120s).
	IdleTimeout time.Duration
	// AllowedOrigins is the list of Origin header values permitted for
	// WebSocket upgrade requests. When empty, only same-origin requests are
	// accepted (the coder/websocket library default).
	// Attachments is the storage backend for CDN attachment uploads/downloads.
	// When nil, uploads are accepted but discarded (dev mode).
	Attachments attachments.Store
	// StaticResourcesDir is the root directory for serving static resources
	// (emoji, dictionaries, release notes) at /resources/{path} and /updates/{path}.
	// When empty, these endpoints return 404.
	StaticResourcesDir string
	AllowedOrigins     []string
	// ClientVersion controls the client version deprecation and blocking
	// policy. When nil, no version checks are applied.
	ClientVersion *ClientVersionConfig
	// TrustedProxies is a list of CIDR ranges for trusted reverse proxies.
	// When set, the X-Forwarded-For header is only trusted if the request's
	// RemoteAddr falls within one of these ranges. When empty, XFF is ignored
	// and RemoteAddr is used directly.
	TrustedProxies []string
	// FrontendFS is the file system for the compiled React/Vite SPA. When
	// non-nil a catch-all GET handler is registered after all API routes that
	// serves the SPA with SPA fallback routing and appropriate cache headers.
	// Pass the value returned by internal/frontend.FS() to enable the web UI.
	// When nil the web UI is not served.
	FrontendFS fs.FS

	// WebUIHandler provides the client-facing /api/v1/* REST endpoints for
	// the web UI. When non-nil, the web UI API is available alongside the
	// Signal protocol endpoints.
	WebUIHandler *WebUIHandler

	// WebUIEventHub provides the /api/v1/events WebSocket endpoint for
	// real-time event delivery to the web UI.
	WebUIEventHub *WebUIEventHub
}

// Default HTTP server timeout values. These can be overridden via ServerConfig.
const (
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultReadTimeout       = 30 * time.Second
	DefaultWriteTimeout      = 60 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
)

// NewServer creates a new REST API Server with all routes registered.
func NewServer(cfg ServerConfig) *Server {
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = DefaultReadTimeout
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = DefaultWriteTimeout
	}
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}

	spamChecker := cfg.SpamChecker
	if spamChecker == nil {
		cfg.Logger.Warn("no spam checker configured — all messages will be allowed (fail-open)")
		spamChecker = &spam.NoOpChecker{}
	}

	fraudChecker := cfg.FraudChecker
	if fraudChecker == nil {
		cfg.Logger.Warn("no fraud checker configured — all registrations will be allowed")
		fraudChecker = spam.NoOpFraudChecker{}
	}

	// Parse trusted proxy CIDRs.
	var trustedNets []*net.IPNet
	for _, cidr := range cfg.TrustedProxies {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// Try as a single IP (add /32 or /128).
			ip := net.ParseIP(cidr)
			if ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				ipNet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
			}
		}
		if ipNet != nil {
			trustedNets = append(trustedNets, ipNet)
		}
	}

	s := &Server{
		logger:          cfg.Logger,
		tlsCertFile:     cfg.TLSCertFile,
		tlsKeyFile:      cfg.TLSKeyFile,
		accounts:        cfg.Accounts,
		captcha:         cfg.Captcha,
		certificates:    cfg.Certificates,
		keys:            cfg.Keys,
		messages:        cfg.Messages,
		profiles:        cfg.Profiles,
		stickers:        cfg.Stickers,
		directory:       cfg.Directory,
		secureStorage:   cfg.SecureStorage,
		svr:             cfg.SVR,
		calling:         cfg.Calling,
		callSignaling:   cfg.CallSignaling,
		keyTransparency: cfg.KeyTransparency,
		usernames:       cfg.Usernames,
		devices:         cfg.Devices,
		wsSessions:      cfg.WSSessions,
		verification:    cfg.Verification,
		rateLimits:      cfg.RateLimits,
		spamChecker:     spamChecker,
		fraudChecker:    fraudChecker,
		reportStore:     cfg.ReportStore,
		loopDetector:    cfg.LoopDetector,
		attachmentStore:    cfg.Attachments,
		staticResourcesDir: cfg.StaticResourcesDir,
		allowedOrigins:     cfg.AllowedOrigins,
		clientVersion:      cfg.ClientVersion,
		trustedProxies:     trustedNets,
		frontendFS:         cfg.FrontendFS,
		webUIHandler:       cfg.WebUIHandler,
		webUIEventHub:      cfg.WebUIEventHub,
	}

	mux := http.NewServeMux()
	s.mux = mux
	s.routes(mux)

	// Build the middleware chain (outermost to innermost):
	//   clientVersion -> securityHeaders -> bodyLimit -> json -> logging -> mux
	// The clientVersion middleware is applied outermost so that deprecated or
	// blocked clients are rejected before any other processing occurs.
	handler := clientVersionMiddleware(
		cfg.ClientVersion,
		securityHeadersMiddleware(
			bodyLimitMiddleware(
				jsonMiddleware(
					loggingMiddleware(cfg.Logger, mux),
				),
			),
		),
	)

	// Create WebSocket handler if sessions manager is available. The HTTP
	// handler chain is passed so that WebSocket requests can be routed to
	// the same REST handlers (like Java's WebSocketResourceProvider).
	if cfg.WSSessions != nil {
		s.wsHandler = apiws.NewHandler(cfg.Accounts, cfg.Messages, cfg.WSSessions, handler, cfg.Logger, cfg.AllowedOrigins...)
	}

	s.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	return s
}

// runSessionCleanup periodically removes expired verification sessions until
// ctx is cancelled. The sweep interval is verificationSessionCleanupInterval.

// rateLimit wraps h with rate limiting using rl and keyFn when rl is non-nil.
// When rl is nil (rate limiting disabled) the original handler is returned
// unchanged. This keeps routes() readable and avoids nil-dereferences.
func rateLimit(rl limits.RateLimiter, keyFn func(*http.Request, *accounts.Account) string, h http.Handler) http.Handler {
	if rl == nil {
		return h
	}
	return rateLimitMiddleware(rl, keyFn, h)
}

// routes registers all API routes on the given ServeMux.
func (s *Server) routes(mux *http.ServeMux) {
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return authMiddleware(s.accounts, h)
	}

	// Override ipKey to use trusted proxy awareness when configured.
	ipKey := func(r *http.Request, acct *accounts.Account) string {
		return ipKeyWithProxies(r, s.trustedProxies)
	}

	// optionalAuth wraps h with optionalAuthMiddleware, allowing both Basic
	// auth (standard authenticated sender) and the Unidentified-Access-Key
	// header (sealed sender). The destination UUID is extracted dynamically
	// from each request's path value so the correct account is looked up.
	optionalAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			dest := r.PathValue("destination")
			optionalAuthMiddleware(s.accounts, dest, h).ServeHTTP(w, r)
		}
	}

	// optionalAuthByIdentifier is like optionalAuth but reads the destination
	// account identifier from the {identifier} path variable. This is used for
	// profile GET routes where the path parameter is named "identifier" rather
	// than "destination". Callers may authenticate with Basic auth (returns the
	// authenticated sender's account in context) or via the
	// Unidentified-Access-Key header (sealed sender path). Unauthenticated
	// requests without either credential are rejected with 401.
	optionalAuthByIdentifier := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			dest := r.PathValue("identifier")
			optionalAuthMiddleware(s.accounts, dest, h).ServeHTTP(w, r)
		}
	}

	// Rate limiter aliases; nil when registry is not configured.
	var (
		rlReg       limits.RateLimiter
		rlVer       limits.RateLimiter
		rlMsg       limits.RateLimiter
		rlKeys      limits.RateLimiter
		rlProf      limits.RateLimiter
		rlAtt       limits.RateLimiter
		rlUser      limits.RateLimiter
		rlAcctCheck limits.RateLimiter
		rlDevAlloc  limits.RateLimiter
		rlDevVerify limits.RateLimiter
	)
	if s.rateLimits != nil {
		rlReg = s.rateLimits.ForRegistration()
		rlVer = s.rateLimits.ForVerification()
		rlMsg = s.rateLimits.ForMessages()
		rlKeys = s.rateLimits.ForPreKeys()
		rlProf = s.rateLimits.ForProfiles()
		rlAtt = s.rateLimits.ForAttachments()
		rlUser = s.rateLimits.ForUsernames()
		rlAcctCheck = s.rateLimits.ForAccountCheck()
		rlDevAlloc = s.rateLimits.ForDeviceAllocate()
		rlDevVerify = s.rateLimits.ForDeviceVerify()
	}

	// Registration
	mux.Handle("POST /v1/registration",
		rateLimit(rlReg, ipKey, http.HandlerFunc(s.handleRegistration)))

	// Verification sessions
	mux.Handle("POST /v1/verification/session",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleCreateVerificationSession)))
	mux.Handle("GET /v1/verification/session/{id}",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleGetVerificationSession)))
	mux.Handle("POST /v1/verification/session/{id}/code",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleRequestVerificationCode)))
	mux.Handle("PUT /v1/verification/session/{id}/code",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleSubmitVerificationCode)))

	// Accounts
	mux.HandleFunc("GET /v1/accounts/whoami", auth(s.handleWhoAmI))
	mux.HandleFunc("PUT /v1/accounts/attributes/", auth(s.handleSetAccountAttributes))
	mux.Handle("HEAD /v1/accounts/account/{identifier}",
		rateLimit(rlAcctCheck, ipKey, http.HandlerFunc(s.handleAccountExists)))
	mux.HandleFunc("DELETE /v1/accounts/me", auth(s.handleDeleteAccount))
	mux.HandleFunc("PUT /v1/accounts/gcm/", auth(s.handleRegisterGcm))
	mux.HandleFunc("DELETE /v1/accounts/gcm/", auth(s.handleUnregisterGcm))
	mux.HandleFunc("PUT /v1/accounts/apn/", auth(s.handleRegisterApn))
	mux.HandleFunc("DELETE /v1/accounts/apn/", auth(s.handleUnregisterApn))

	// Keys
	mux.HandleFunc("GET /v2/keys", auth(s.handleGetPreKeyCount))
	mux.HandleFunc("PUT /v2/keys", auth(s.handleUploadKeys))
	mux.Handle("GET /v2/keys/{identifier}/{device_id}",
		rateLimit(rlKeys, uuidKey, http.HandlerFunc(optionalAuthByIdentifier(s.handleGetPreKeys))))
	mux.Handle("POST /v2/keys/check",
		rateLimit(rlKeys, uuidKey, http.HandlerFunc(auth(s.handleCheckKeys))))

	// Messages
	// Both message-send endpoints accept either standard Basic auth (normal
	// authenticated sender) or an Unidentified-Access-Key header (sealed
	// sender / anonymous delivery). See optionalAuthMiddleware for the
	// validation logic.
	mux.Handle("PUT /v1/messages/multi_recipient",
		rateLimit(rlMsg, uuidKey, http.HandlerFunc(optionalAuth(s.handleSendMultiRecipientMessage))))
	mux.Handle("PUT /v1/messages/{destination}",
		rateLimit(rlMsg, uuidKey, http.HandlerFunc(optionalAuth(s.handleSendMessage))))
	mux.HandleFunc("GET /v1/messages", auth(s.handleGetMessages))
	mux.HandleFunc("DELETE /v1/messages/uuid/{guid}", auth(s.handleDeleteMessage))
	mux.HandleFunc("POST /v1/messages/report/{source}/{messageGuid}", auth(s.handleReportSpam))

	// Profiles
	mux.Handle("PUT /v1/profile",
		rateLimit(rlProf, uuidKey, http.HandlerFunc(auth(s.handleSetProfile))))
	mux.Handle("PUT /v1/profile/",
		rateLimit(rlProf, uuidKey, http.HandlerFunc(auth(s.handleSetProfile))))
	mux.Handle("GET /v1/profile/{identifier}/{version}/{credentialRequest}",
		rateLimit(rlProf, uuidKey, http.HandlerFunc(optionalAuthByIdentifier(s.handleGetProfileWithCredential))))
	mux.Handle("GET /v1/profile/{identifier}/{version}",
		rateLimit(rlProf, uuidKey, http.HandlerFunc(optionalAuthByIdentifier(s.handleGetVersionedProfile))))
	mux.Handle("GET /v1/profile/{identifier}",
		rateLimit(rlProf, uuidKey, http.HandlerFunc(optionalAuthByIdentifier(s.handleGetProfile))))
	mux.Handle("POST /v1/profile/identity_check/batch",
		rateLimit(rlProf, uuidKey, http.HandlerFunc(auth(s.handleBatchIdentityCheck))))

	// Devices
	mux.HandleFunc("GET /v1/devices", auth(s.handleListDevices))
	mux.HandleFunc("GET /v1/devices/", auth(s.handleListDevices))
	mux.HandleFunc("DELETE /v1/devices/{device_id}", auth(s.handleRemoveDevice))
	mux.Handle("GET /v1/devices/provisioning/code",
		rateLimit(rlDevAlloc, uuidKey, http.HandlerFunc(auth(s.handleGetProvisioningCode))))
	mux.Handle("PUT /v1/devices/link",
		rateLimit(rlDevVerify, uuidKey, http.HandlerFunc(auth(s.handleLinkDevice))))
	mux.HandleFunc("PUT /v1/devices/capabilities", auth(s.handleSetDeviceCapabilities))

	// Provisioning
	mux.HandleFunc("PUT /v1/provisioning/{destination}", auth(s.handleSendProvisioningMessage))

	// WebSocket
	mux.Handle("GET /v1/websocket/",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleWebSocket)))
	mux.Handle("GET /v1/websocket/provisioning",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleWebSocketProvisioning)))
	mux.Handle("GET /v1/websocket/provisioning/",
		rateLimit(rlVer, ipKey, http.HandlerFunc(s.handleWebSocketProvisioning)))

	// Keepalive
	mux.HandleFunc("GET /v1/keepalive", s.handleKeepalive)
	mux.HandleFunc("GET /v1/keepalive/provisioning", s.handleKeepaliveProvisioning)

	// Config
	mux.HandleFunc("GET /v1/config", s.handleGetConfig)
	mux.HandleFunc("GET /v2/config", auth(s.handleGetRemoteConfig))

	// Certificates
	mux.HandleFunc("GET /v1/certificate/delivery", auth(s.handleGetDeliveryCertificate))
	mux.HandleFunc("GET /v1/certificate/auth/group", auth(s.handleGetGroupCredentials))

	// Challenge
	mux.Handle("PUT /v1/challenge",
		rateLimit(rlReg, uuidKey, http.HandlerFunc(auth(s.handleChallengeResponse))))
	mux.Handle("POST /v1/challenge/push",
		rateLimit(rlReg, uuidKey, http.HandlerFunc(auth(s.handleRequestPushChallenge))))

	// Accounts V2
	mux.Handle("PUT /v2/accounts/number",
		rateLimit(rlReg, uuidKey, http.HandlerFunc(auth(s.handleChangeNumber))))
	mux.Handle("PUT /v2/accounts/number/",
		rateLimit(rlReg, uuidKey, http.HandlerFunc(auth(s.handleChangeNumber))))

	// Account enhancements
	mux.HandleFunc("PUT /v1/accounts/registration_lock", auth(s.handleSetRegistrationLock))
	mux.HandleFunc("DELETE /v1/accounts/registration_lock", auth(s.handleRemoveRegistrationLock))
	mux.HandleFunc("PUT /v2/accounts/phone_number_discoverability", auth(s.handleSetPhoneNumberDiscoverability))
	mux.HandleFunc("GET /v2/accounts/data_report", auth(s.handleGetDataReport))

	// Usernames
	mux.Handle("PUT /v1/accounts/username_hash/reserve",
		rateLimit(rlUser, uuidKey, http.HandlerFunc(auth(s.handleReserveUsernameHash))))
	mux.Handle("PUT /v1/accounts/username_hash/confirm",
		rateLimit(rlUser, uuidKey, http.HandlerFunc(auth(s.handleConfirmUsernameHash))))
	mux.Handle("DELETE /v1/accounts/username_hash",
		rateLimit(rlUser, uuidKey, http.HandlerFunc(auth(s.handleDeleteUsernameHash))))
	mux.Handle("GET /v1/accounts/username_hash/{usernameHash}",
		rateLimit(rlUser, ipKey, http.HandlerFunc(s.handleLookupUsernameHash)))
	mux.Handle("PUT /v1/accounts/username_link",
		rateLimit(rlUser, uuidKey, http.HandlerFunc(auth(s.handleSetUsernameLink))))
	mux.Handle("DELETE /v1/accounts/username_link",
		rateLimit(rlUser, uuidKey, http.HandlerFunc(auth(s.handleDeleteUsernameLink))))
	mux.Handle("GET /v1/accounts/username_link/{uuid}",
		rateLimit(rlUser, ipKey, http.HandlerFunc(s.handleLookupUsernameLink)))

	// Attachments & CDN
	mux.Handle("GET /v4/attachments/form/upload",
		rateLimit(rlAtt, uuidKey, http.HandlerFunc(auth(s.handleAttachmentUploadForm))))
	mux.Handle("PUT /cdn/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("POST /cdn/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("PATCH /cdn/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("HEAD /cdn/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("PUT /cdn2/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("POST /cdn2/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("PATCH /cdn2/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("HEAD /cdn2/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("PUT /cdn3/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("POST /cdn3/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("PATCH /cdn3/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	mux.Handle("HEAD /cdn3/{rest...}", rateLimit(rlAtt, ipKey, http.HandlerFunc(s.handleCDNUpload)))
	// CDN download
	mux.HandleFunc("GET /cdn/{rest...}", s.handleCDNDownload)
	mux.HandleFunc("GET /cdn2/{rest...}", s.handleCDNDownload)
	mux.HandleFunc("GET /cdn3/{rest...}", s.handleCDNDownload)

	// Static resources (emoji, dictionaries, release notes)
	if s.staticResourcesDir != "" {
		mux.HandleFunc("GET /resources/{path...}", s.handleStaticResource)
		mux.HandleFunc("GET /updates/{path...}", s.handleStaticResource)
	}

	// Stickers
	mux.HandleFunc("GET /v1/sticker/pack/form/{count}", auth(s.handleGetStickerPackForm))

	// Directory
	mux.HandleFunc("GET /v2/directory/auth", auth(s.handleGetDirectoryAuth))
	// Directory lookup uses its own service credentials (from /v2/directory/auth),
	// not account Basic Auth. Rate limiting by IP prevents enumeration.
	mux.Handle("PUT /v1/directory/lookup",
		rateLimit(rlReg, ipKey, http.HandlerFunc(s.handleDirectoryLookup)))

	// Secure Storage
	mux.HandleFunc("GET /v1/storage/auth", auth(s.handleGetStorageAuth))
	// Signal-cli appends paths to the storage base URL; after URL rewriting
	// the base is /storage. The Java server uses /v1/storage/manifest/... paths.
	mux.HandleFunc("GET /storage/v1/storage/manifest/version/{version}", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("GET /storage/v1/storage/manifest", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("GET /storage/manifest/version/{version}", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("GET /storage/manifest", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("PUT /storage/v1/storage/manifest", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("PUT /storage/manifest", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("PUT /storage/{rest...}", auth(s.handleGetStorageManifestVersion))
	mux.HandleFunc("GET /storage/{rest...}", auth(s.handleGetStorageManifestVersion))

	// SVR2 (Secure Value Recovery v2 - WebSocket)
	// Catch-all for any SVR2 request path; signal-cli's SVR2 client may use
	// various subpaths (/v1/{mrenclave}, /{enclaveId}, etc.)
	mux.HandleFunc("GET /svr2/{rest...}", s.handleSVR2WebSocket)
	mux.HandleFunc("PUT /svr2/{rest...}", s.handleSVR2WebSocket)

	// SVR (Secure Value Recovery)
	mux.HandleFunc("GET /v2/backup/auth", auth(s.handleGetSVRBackupAuth))
	mux.HandleFunc("GET /v2/svr/auth", auth(s.handleGetSVRSVRAuth))
	mux.HandleFunc("POST /v2/backup/auth/check", auth(s.handleCheckSVRBackupAuth))
	mux.HandleFunc("POST /v2/svr/auth/check", auth(s.handleCheckSVRSVRAuth))

	// Payments
	mux.HandleFunc("GET /v1/payments/auth", auth(s.handleGetPaymentsAuth))
	mux.HandleFunc("GET /v1/payments/conversions", s.handleGetPaymentsConversions)

	// Calling
	mux.HandleFunc("GET /v2/calling/relays", auth(s.handleGetCallingRelays))
	mux.HandleFunc("POST /v1/call-link/create-auth", auth(s.handleGetCallLinkAuth))
	mux.HandleFunc("PUT /v1/call_quality_survey", s.handleSubmitCallQualitySurvey)

	// Call signaling relay (1:1 audio/video)
	mux.HandleFunc("POST /v1/call/offer", auth(s.handleCallOffer))
	mux.HandleFunc("POST /v1/call/answer", auth(s.handleCallAnswer))
	mux.HandleFunc("POST /v1/call/ice", auth(s.handleCallICE))
	mux.HandleFunc("POST /v1/call/hangup", auth(s.handleCallHangup))

	// Key Transparency
	mux.HandleFunc("POST /v1/key-transparency/search", auth(s.handleKeyTransparencySearch))
	mux.HandleFunc("POST /v1/key-transparency/monitor", auth(s.handleKeyTransparencyMonitor))
	mux.HandleFunc("GET /v1/key-transparency/distinguished", s.handleGetDistinguishedKey)

	// Subscriptions
	mux.HandleFunc("GET /v1/subscription/configuration", s.handleGetSubscriptionConfig)
	mux.HandleFunc("PUT /v1/subscription/{subscriberId}", s.handleUpdateSubscriber)
	mux.HandleFunc("GET /v1/subscription/{subscriberId}", s.handleGetSubscription)
	mux.HandleFunc("DELETE /v1/subscription/{subscriberId}", s.handleDeleteSubscriber)

	// Donations
	mux.HandleFunc("POST /v1/donation/redeem-receipt", auth(s.handleRedeemDonationReceipt))

	// Archives/Backup
	mux.HandleFunc("GET /v1/archives/auth", auth(s.handleGetBackupAuth))
	mux.HandleFunc("GET /v1/archives/upload/form", auth(s.handleGetBackupUploadForm))
	mux.HandleFunc("PUT /v1/archives/backupid", auth(s.handleSetBackupId))
	mux.HandleFunc("POST /v1/archives", auth(s.handleRefreshBackup))
	mux.HandleFunc("GET /v1/archives", auth(s.handleGetBackupInfo))

	// Device Check
	mux.HandleFunc("GET /v1/devicecheck/attest", s.handleDeviceCheckAttestChallenge)
	mux.HandleFunc("PUT /v1/devicecheck/attest", auth(s.handleDeviceCheckAttest))
	mux.HandleFunc("GET /v1/devicecheck/assert", s.handleDeviceCheckAssertChallenge)
	mux.HandleFunc("POST /v1/devicecheck/assert", auth(s.handleDeviceCheckAssert))

	// Extension routes (FIDO2, etc.)
	for _, reg := range s.routeRegistrars {
		reg(mux, auth)
	}

	// Web UI client-facing API routes (/api/v1/*).
	if s.webUIHandler != nil {
		s.webUIHandler.RegisterRoutes(mux)
	}
	if s.webUIEventHub != nil {
		s.webUIEventHub.RegisterRoute(mux)
	}

	// SPA catch-all: registered last so that all API routes above take
	// priority. Only active when a frontend FS is provided.
	if s.frontendFS != nil {
		mux.Handle("/", newFrontendHandler(s.frontendFS))
	}
}

// SetAttachmentStore sets the attachment storage backend after construction.
// This allows wiring attachment storage separately from the main server config.
func (s *Server) SetAttachmentStore(store attachments.Store) {
	s.attachmentStore = store
}

// Listen binds the network listener without starting to serve requests. This
// is useful for tests that need the resolved listen address before serving
// begins. After calling Listen the Addr method returns the actual address.
// Callers must follow up with Serve to begin accepting connections.
func (s *Server) Listen() error {
	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return &ListenError{Addr: s.httpServer.Addr, Cause: err}
	}
	s.listenerMu.Lock()
	s.listener = ln
	s.listenerMu.Unlock()
	return nil
}

// Serve begins accepting connections on the previously bound listener. It
// blocks until the server is shut down and returns http.ErrServerClosed on
// graceful shutdown. Listen must be called before Serve. When TLSCertFile
// and TLSKeyFile are configured, the server serves HTTPS; otherwise HTTP.
func (s *Server) Serve() error {
	s.listenerMu.RLock()
	ln := s.listener
	s.listenerMu.RUnlock()
	if ln == nil {
		return &ListenError{Addr: s.httpServer.Addr, Cause: net.ErrClosed}
	}
	if s.tlsCertFile != "" && s.tlsKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(s.tlsCertFile, s.tlsKeyFile)
		if err != nil {
			return &TLSError{Cause: err}
		}
		s.httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			// TLS 1.3 is the minimum; TLS 1.2 and below are rejected. TLS 1.3
			// manages its own cipher suites; the CipherSuites list below only
			// applies to TLS 1.2 connections that may be negotiated if a future
			// MinVersion downgrade occurs, and is kept for defence-in-depth.
			MinVersion: tls.VersionTLS13,
			// Prefer modern ECDHE-based cipher suites with forward secrecy.
			// The ordering follows Signal's reference server preference.
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
			},
			// Prefer X25519 for key exchange; fall back to P-256 and P-384.
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			},
		}
		tlsListener := tls.NewListener(ln, s.httpServer.TLSConfig)
		s.logger.Info("REST server listening (TLS)", slog.String("addr", ln.Addr().String()))
		return s.httpServer.Serve(tlsListener)
	}
	// Warn when serving plain HTTP on a non-loopback address. This is
	// informational only — tests run without TLS and should not be blocked.
	addr := ln.Addr().String()
	host, _, _ := net.SplitHostPort(addr)
	if host != "127.0.0.1" && host != "::1" && host != "localhost" && host != "" {
		s.logger.Warn("serving plain HTTP without TLS on non-loopback address — use TLS in production",
			slog.String("addr", addr))
	}
	s.logger.Info("REST server listening", slog.String("addr", addr))
	return s.httpServer.Serve(ln)
}

// Start binds the listener and begins serving in one call. It is a convenience
// method equivalent to calling Listen followed by Serve. Returns
// http.ErrServerClosed on graceful shutdown.
func (s *Server) Start() error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve()
}

// Shutdown gracefully shuts down the server without interrupting active
// connections. It stops the verification Manager's background cleanup
// goroutine before draining HTTP connections.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("REST server shutting down")
	if s.verification != nil {
		s.verification.Shutdown()
	}
	return s.httpServer.Shutdown(ctx)
}

// Addr returns the listen address of the server. If the server has been started
// and a listener is bound, the actual address (including the resolved port) is
// returned. Otherwise, the configured address is returned.
//
// The listener's Addr() call is made while holding the read lock so that the
// underlying net.TCPAddr fields (populated during net.Listen) are not read
// concurrently with their initialisation.
func (s *Server) Addr() string {
	s.listenerMu.RLock()
	defer s.listenerMu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.httpServer.Addr
}

// ListenError indicates a failure to bind the network listener.
type ListenError struct {
	Addr  string
	Cause error
}

func (e *ListenError) Error() string {
	return "failed to listen on " + e.Addr + ": " + e.Cause.Error()
}

func (e *ListenError) Unwrap() error {
	return e.Cause
}

// TLSError indicates a failure to load TLS certificates.
type TLSError struct {
	Cause error
}

func (e *TLSError) Error() string {
	return "failed to load TLS certificates: " + e.Cause.Error()
}

func (e *TLSError) Unwrap() error {
	return e.Cause
}
