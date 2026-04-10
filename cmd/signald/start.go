package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/spf13/cobra"

	internalfrontend "github.com/jeremyhahn/go-signal/internal/frontend"
	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/api/rest"
	attachmentspkg "github.com/jeremyhahn/go-signal/pkg/attachments"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
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
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/store"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// generateEphemeralKey produces a 32-byte cryptographically random hex string
// for use as an ephemeral signing key when no key is configured. It panics
// on read failure, which indicates a broken OS random source.
func generateEphemeralKey() string {
	b := make([]byte, 32)
	if _, err := cryptorand.Read(b); err != nil {
		panic("signald: failed to read random bytes for ephemeral signing key: " + err.Error())
	}
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()
	return fmt.Sprintf("%x", b)
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the Signal server",
	Long:  "Start the Signal messaging server, listening for HTTP and gRPC connections.",
	RunE:  runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)
}

func runStart(cmd *cobra.Command, args []string) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	httpAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.HTTPPort)

	slog.InfoContext(ctx, "starting Signal server",
		slog.String("version", version),
		slog.String("commit", gitCommit),
		slog.String("http_addr", httpAddr),
		slog.String("storage_backend", cfg.Storage.Backend),
		slog.String("cache_backend", cfg.Cache.Backend),
	)

	// Resolve the certificate signing key from config. Prefer the dedicated
	// zkConfig.signingKey field; fall back to zkConfig.serverSecret if absent.
	var signingKey *secrets.SecureString
	if cfg.ZKConfig.SigningKey != nil && !cfg.ZKConfig.SigningKey.IsDestroyed() {
		signingKey = cfg.ZKConfig.SigningKey
	} else if cfg.ZKConfig.ServerSecret != nil && !cfg.ZKConfig.ServerSecret.IsDestroyed() {
		signingKey = cfg.ZKConfig.ServerSecret
	} else {
		// Fallback: generate a random ephemeral signing key for development.
		// In production, set zkConfig.signingKey in the YAML configuration.
		slog.WarnContext(ctx, "no signing key configured; generating ephemeral key — certificates will not survive restarts")
		signingKey = secrets.NewSecureString(generateEphemeralKey())
	}

	// Initialize storage backends based on config.
	var (
		accountStore  accounts.AccountStore
		keyStore      keys.PreKeyStore
		messageStore  messages.MessageStore
		profileStore  profiles.ProfileStore
		usernameStore usernames.UsernameStore
	)

	switch cfg.Storage.Backend {
	case "file":
		dataDir := cfg.Storage.File.DataDir
		if dataDir == "" {
			dataDir = "data"
		}
		kvClient, err := store.NewFileKVClient(dataDir)
		if err != nil {
			return fmt.Errorf("creating file KV client: %w", err)
		}
		slog.InfoContext(ctx, "using file storage backend", slog.String("dataDir", dataDir))

		accountStore = accounts.NewKVAccountStore(kvClient)
		keyStore = keys.NewKVPreKeyStore(kvClient)
		messageStore = messages.NewKVMessageStore(kvClient)
		profileStore = profiles.NewKVProfileStore(kvClient)
		usernameStore = memory.NewMemoryUsernameStore() // TODO: KV-backed username store

	default: // "memory"
		slog.InfoContext(ctx, "using memory storage backend")
		accountStore = memory.NewMemoryAccountStore()
		keyStore = memory.NewMemoryPreKeyStore()
		messageStore = memory.NewMemoryMessageStore()
		profileStore = memory.NewMemoryProfileStore()
		usernameStore = memory.NewMemoryUsernameStore()
	}

	// Create service managers.
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	captchaMgr := captcha.NewCaptchaManager(logger)
	// Create an independent copy of the signing key so that certificates
	// manager holds its own SecureString and cannot alias the config value.
	signingKeyCopy := secrets.NewSecureString(signingKey.Plaintext())
	certificatesMgr := certificates.NewCertificatesManager(signingKeyCopy, logger)

	// Initialize zkgroup ServerSecretParams from the ZKConfig serverSecret.
	// This enables zkgroup-native AuthCredentialWithPni group credentials and
	// ExpiringProfileKeyCredential issuance.
	if cfg.ZKConfig.ServerSecret != nil && !cfg.ZKConfig.ServerSecret.IsDestroyed() {
		serverSecretBytes := cfg.ZKConfig.ServerSecret.Bytes()
		var randomness zkgroup.RandomnessBytes
		copy(randomness[:], serverSecretBytes)
		for i := range serverSecretBytes {
			serverSecretBytes[i] = 0
		}
		authSecret, err := zkgroup.GenerateServerSecretParams(randomness)
		// Zero randomness immediately after use.
		for i := range randomness {
			randomness[i] = 0
		}
		if err != nil {
			slog.WarnContext(ctx, "failed to generate zkgroup server secret params; group credentials will use HMAC fallback",
				slog.String("error", err.Error()),
			)
		} else {
			certificatesMgr.SetAuthServerSecret(authSecret)
			slog.InfoContext(ctx, "zkgroup auth server secret configured")
		}
	} else {
		slog.WarnContext(ctx, "no zkConfig.serverSecret configured; group credentials will use HMAC-SHA256 fallback")
	}

	// Derive an Ed25519 signing key for delivery certificates from the signing
	// key material. In production, a dedicated Ed25519 key should be configured;
	// here we derive one deterministically from the signing key via SHA-256 so
	// that certificates survive restarts when the signing key is stable.
	{
		keyBytes := signingKey.Bytes()
		if len(keyBytes) > 0 {
			seed := sha256.Sum256(keyBytes)
			for i := range keyBytes {
				keyBytes[i] = 0
			}
			privKey := ed25519.NewKeyFromSeed(seed[:])
			for i := range seed {
				seed[i] = 0
			}
			// pubKeyID: first 4 bytes of the hex-encoded public key fingerprint.
			pubHex := hex.EncodeToString(privKey.Public().(ed25519.PublicKey))
			var pubKeyID uint32
			for i := 0; i < 4 && i < len(pubHex); i++ {
				pubKeyID = (pubKeyID << 8) | uint32(pubHex[i])
			}
			if err := certificatesMgr.SetEd25519SigningKey(privKey, pubKeyID); err != nil {
				slog.WarnContext(ctx, "failed to set Ed25519 signing key; delivery certificates will use HMAC-SHA256",
					slog.String("error", err.Error()),
				)
			} else {
				slog.InfoContext(ctx, "Ed25519 delivery certificate signing key configured",
					slog.Uint64("pubKeyID", uint64(pubKeyID)),
				)
			}
			// Zero the input key material; SetEd25519SigningKey makes its own copy.
			for i := range privKey {
				privKey[i] = 0
			}
		}
	}

	keysMgr := keys.NewKeysManager(keyStore)
	messagesMgr := messages.NewMessagesManager(messageStore)
	profilesMgr := profiles.NewProfilesManager(profileStore)
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, logger)
	stickersMgr := stickers.NewStickersManager(logger)
	directoryMgr := directory.NewDirectoryManager(logger)
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	keyTransparencyMgr := keytransparency.NewKeyTransparencyManager(logger)
	provisioningStore := memory.NewMemoryProvisioningStore()
	devicesMgr := devices.NewDevicesManager(provisioningStore, accountsMgr, keysMgr, logger)
	wsSessions := signalws.NewSessionManager(logger)

	// Initialize verification subsystem.
	verificationStore := verification.NewMemoryVerificationSessionStore()
	verificationTransport := verification.NewStubTransport(logger)
	verificationMgr := verification.NewManager(verificationStore, verificationTransport, verification.ManagerConfig{
		FixedCode: cfg.Verification.FixedCode,
	})
	if cfg.Verification.FixedCode != "" && cfg.Verification.Transport != "stub" {
		slog.WarnContext(ctx, "SECURITY WARNING: verification FixedCode is set with non-stub transport — this bypasses verification in production!")
	}

	// Initialize calling subsystem.
	var callingZKParams *zkgroup.GenericServerSecretParams
	if cfg.CallingZKConfig.ServerSecret != nil && !cfg.CallingZKConfig.ServerSecret.IsDestroyed() {
		serverSecretBytes := cfg.CallingZKConfig.ServerSecret.Bytes()
		var randomness zkgroup.RandomnessBytes
		copy(randomness[:], serverSecretBytes)
		// Wipe the copy immediately after use.
		for i := range serverSecretBytes {
			serverSecretBytes[i] = 0
		}
		callingZKParams = zkgroup.GenerateGenericServerSecretParams(randomness)
		// Zero randomness immediately after use.
		for i := range randomness {
			randomness[i] = 0
		}
		certificatesMgr.SetCallingZKParams(callingZKParams)
	}

	// Initialize TURN credential provider.
	var turnProvider calling.TurnCredentialProvider
	cfCfg := cfg.Turn.Cloudflare
	if cfCfg.Endpoint != "" && cfCfg.APIToken != nil && !cfCfg.APIToken.IsDestroyed() {
		reqTTL, _ := time.ParseDuration(cfCfg.RequestedCredentialTTL)
		if reqTTL == 0 {
			reqTTL = 86400 * time.Second
		}
		clientTTL, _ := time.ParseDuration(cfCfg.ClientCredentialTTL)
		if clientTTL == 0 {
			clientTTL = 43200 * time.Second
		}

		var err error
		turnProvider, err = calling.NewCloudflareTurnProvider(calling.CloudflareTurnProviderConfig{
			APIToken:               cfCfg.APIToken,
			Endpoint:               cfCfg.Endpoint,
			URLs:                   cfCfg.URLs,
			URLsWithIPs:            cfCfg.URLsWithIPs,
			Hostname:               cfCfg.Hostname,
			RequestedCredentialTTL: reqTTL,
			ClientCredentialTTL:    clientTTL,
			NumHTTPClients:         cfCfg.NumHTTPClients,
			Logger:                 logger,
		})
		if err != nil {
			return fmt.Errorf("failed to create Cloudflare TURN provider: %w", err)
		}
	} else {
		// Fallback: static TURN provider for development.
		turnProvider = &calling.StaticTurnProvider{
			URLs:     cfCfg.URLs,
			Hostname: cfCfg.Hostname,
		}
	}

	// Initialize survey publisher.
	var surveyPub calling.SurveyPublisher
	switch cfg.CallQualitySurvey.Backend {
	case "pubsub":
		// TODO: Initialize Google Pub/Sub publisher when needed.
		surveyPub = calling.NewLogSurveyPublisher(logger)
	default:
		surveyPub = calling.NewLogSurveyPublisher(logger)
	}

	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:        turnProvider,
		GenericServerSecret: callingZKParams,
		SurveyPublisher:     surveyPub,
		Logger:              logger,
	})

	// Wire real-time WebSocket delivery into the messages manager.
	messagesMgr.SetDeliveryCallback(func(uuid string, deviceID uint64, env *messages.Envelope) {
		wsSessions.DeliverMessage(uuid, deviceID, env)
	})

	// Build the spam checker. The rate-limit checker uses the messages rate
	// limit from config (BucketSize as threshold); a composite wraps it so
	// additional checkers can be added without changing the call site.
	// rateLimitCheckerStop is retained so the checker's cleanup goroutine can
	// be stopped during graceful shutdown, preventing a goroutine leak.
	var spamChecker spam.SpamChecker
	var rateLimitCheckerStop func()
	if msgLimit := cfg.Limits.Messages; msgLimit.BucketSize > 0 {
		rateLimitChecker := spam.NewRateLimitChecker(spam.RateLimitConfig{
			Threshold:      int64(msgLimit.BucketSize),
			ChallengeRatio: spam.DefaultChallengeRatio,
		})
		rateLimitCheckerStop = rateLimitChecker.Stop
		spamChecker = spam.NewCompositeChecker([]spam.SpamChecker{rateLimitChecker})
	} else {
		spamChecker = &spam.NoOpChecker{}
	}

	// Build the registration fraud checker from the YAML configuration.
	// Zero values in cfg.Fraud fall back to the DefaultFraudChecker defaults.
	fraudChecker := spam.NewDefaultFraudChecker(spam.FraudCheckerConfig{
		MaxRegistrationsPerIP:     cfg.Fraud.MaxRegistrationsPerIP,
		MaxRegistrationsPerPrefix: cfg.Fraud.MaxRegistrationsPerPrefix,
		Window:                    time.Duration(cfg.Fraud.WindowMinutes) * time.Minute,
	})

	// Create rate limiter registry from the YAML configuration. Fields that
	// are zero-valued fall back to Signal-Server production defaults via
	// limits.NewRegistry's mergeConfig logic.
	rateLimits := limits.NewRegistry(cfgToLimitsConfig(cfg.Limits))

	// Create delivery loop detector with a 5-minute window and max chain
	// length of 2 (matches Java Signal-Server defaults).
	loopDetector := messages.NewDeliveryLoopDetector(5*time.Minute, 2)

	// Resolve the frontend FS when the web UI is enabled.
	var frontendFS fs.FS
	if cfg.Frontend.Enabled {
		frontendFS = internalfrontend.FS()
		slog.InfoContext(ctx, "web UI enabled: serving embedded React SPA at /")
	}

	// Start REST API server.
	srv := rest.NewServer(rest.ServerConfig{
		Host:               cfg.Server.Host,
		Port:               cfg.Server.HTTPPort,
		TLSCertFile:        cfg.Server.TLSCertFile,
		TLSKeyFile:         cfg.Server.TLSKeyFile,
		Logger:             logger,
		Accounts:           accountsMgr,
		Captcha:            captchaMgr,
		Certificates:       certificatesMgr,
		Keys:               keysMgr,
		Messages:           messagesMgr,
		Profiles:           profilesMgr,
		Usernames:          usernamesMgr,
		Stickers:           stickersMgr,
		Directory:          directoryMgr,
		SecureStorage:      secureStorageMgr,
		SVR:                svrMgr,
		Calling:            callingMgr,
		KeyTransparency:    keyTransparencyMgr,
		Devices:            devicesMgr,
		WSSessions:         wsSessions,
		Verification:       verificationMgr,
		SpamChecker:        spamChecker,
		FraudChecker:       fraudChecker,
		RateLimits:         rateLimits,
		LoopDetector:       loopDetector,
		AllowedOrigins:     cfg.Server.AllowedOrigins,
		StaticResourcesDir: cfg.StaticResources.ResourcesDir,
		FrontendFS:         frontendFS,
	})

	// Initialize attachment storage.
	if cfg.Attachments.StorageDir != "" {
		attStore, err := attachmentspkg.NewFileStore(cfg.Attachments.StorageDir)
		if err != nil {
			return fmt.Errorf("creating attachment store: %w", err)
		}
		srv.SetAttachmentStore(attStore)
		slog.InfoContext(ctx, "attachment storage configured", slog.String("dir", cfg.Attachments.StorageDir))
	} else {
		slog.WarnContext(ctx, "no attachment storage configured — uploads will be discarded")
	}

	// Initialize FIDO2 routes if compiled with the fido2 build tag and
	// enabled in the config.
	initFIDO2(srv, cfgPath, logger)

	// Start the server and propagate fatal errors through a channel so that
	// runStart can return a non-nil error (L8).
	startErr := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			slog.ErrorContext(ctx, "REST server error", slog.String("error", err.Error()))
			startErr <- err
			cancel()
		}
	}()

	// Block until a termination signal is received.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	var serverErr error
	select {
	case sig := <-quit:
		slog.InfoContext(ctx, "received shutdown signal", slog.String("signal", sig.String()))
	case serverErr = <-startErr:
		slog.ErrorContext(ctx, "server startup failed", slog.String("error", serverErr.Error()))
	case <-ctx.Done():
		slog.InfoContext(ctx, "context canceled")
	}

	// Graceful shutdown with ordered teardown:
	// 1. Close all WebSocket sessions first (prevents new message delivery)
	// 2. Shutdown HTTP server (drains in-flight requests)
	// 3. Stop background goroutines (loop detector, rate limiters)
	// 4. Wipe sensitive key material
	slog.InfoContext(ctx, "shutting down Signal server")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// 1. Close all WebSocket sessions.
	wsSessions.CloseAll()

	// 2. Shutdown HTTP server.
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.ErrorContext(ctx, "REST server shutdown error", slog.String("error", err.Error()))
	}

	// 3. Stop background goroutines.
	loopDetector.Stop()
	if rateLimitCheckerStop != nil {
		rateLimitCheckerStop()
	}
	// Stop fraud checker's background cleanup goroutine.
	fraudChecker.Stop()
	rateLimits.Stop()

	// 4. Wipe sensitive key material from protected memory.
	certificatesMgr.Destroy()
	callingMgr.Destroy()
	cfg.Destroy()

	slog.InfoContext(ctx, "Signal server stopped")
	return serverErr
}

// cfgToLimitsConfig converts the YAML-loaded config.LimitsConfig into the
// limits.Config expected by limits.NewRegistry. Fields with a zero BucketSize
// or LeakRatePerMin are left as zero so that NewRegistry's mergeConfig falls
// back to Signal-Server production defaults for those categories.
//
// LeakRatePerMin is converted to a per-second RefillRate by dividing by 60.
func cfgToLimitsConfig(c config.LimitsConfig) limits.Config {
	toBucket := func(r config.RateLimitConfig) limits.BucketConfig {
		if r.BucketSize == 0 || r.LeakRatePerMin == 0 {
			// Zero signals "use default" to mergeConfig.
			return limits.BucketConfig{}
		}
		return limits.BucketConfig{
			BucketSize: r.BucketSize,
			RefillRate: float64(r.LeakRatePerMin) / 60.0,
		}
	}
	return limits.Config{
		Registration:        toBucket(c.Registration),
		Messages:            toBucket(c.Messages),
		PreKeys:             toBucket(c.PreKeys),
		Profiles:            toBucket(c.Profiles),
		Attachments:         toBucket(c.Attachments),
		Verification:        toBucket(c.Verification),
		PIN:                 toBucket(c.PIN),
		Usernames:           toBucket(c.Usernames),
		Authentication:      toBucket(c.Authentication),
		AccountCheck:        toBucket(c.AccountCheck),
		CaptchaAttempt:      toBucket(c.CaptchaAttempt),
		CaptchaSuccess:      toBucket(c.CaptchaSuccess),
		DeviceAllocate:      toBucket(c.DeviceAllocate),
		DeviceVerify:        toBucket(c.DeviceVerify),
		InboundMessageBytes: toBucket(c.InboundMessageBytes),
	}
}
