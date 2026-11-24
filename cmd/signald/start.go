package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	internalfrontend "github.com/jeremyhahn/go-signal/internal/frontend"
	"github.com/jeremyhahn/go-signal/pkg/accounts"
	grpcapi "github.com/jeremyhahn/go-signal/pkg/api/grpc"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
	"github.com/jeremyhahn/go-signal/pkg/api/rest"
	attachmentspkg "github.com/jeremyhahn/go-signal/pkg/attachments"
	"github.com/jeremyhahn/go-signal/pkg/audit"
	"github.com/jeremyhahn/go-signal/pkg/auth/external"
	"github.com/jeremyhahn/go-signal/pkg/backups"
	"github.com/jeremyhahn/go-signal/pkg/cache"
	cachememory "github.com/jeremyhahn/go-signal/pkg/cache/memory"
	cacheredis "github.com/jeremyhahn/go-signal/pkg/cache/redis"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/directory"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	ktextclient "github.com/jeremyhahn/go-signal/pkg/extservice/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/grpcclient"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	"github.com/jeremyhahn/go-signal/pkg/health"
	"github.com/jeremyhahn/go-signal/pkg/health/checks"
	"github.com/jeremyhahn/go-signal/pkg/jobs"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/limits"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/metrics"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/push"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
	"github.com/jeremyhahn/go-signal/pkg/registration/sessionshim"
	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securevaluerecovery"
	"github.com/jeremyhahn/go-signal/pkg/service"
	"github.com/jeremyhahn/go-signal/pkg/spam"
	"github.com/jeremyhahn/go-signal/pkg/stickers"
	"github.com/jeremyhahn/go-signal/pkg/storage/blob"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	pgstorage "github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-signal/pkg/store"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	verificationfactory "github.com/jeremyhahn/go-signal/pkg/verification/factory"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
	"github.com/jeremyhahn/go-signal/pkg/workers"
)

// nilableBackupService returns an untyped nil for a nil svc so REST's nil check works.
func nilableBackupService(svc *backups.Service) service.BackupService {
	if svc == nil {
		return nil
	}
	return service.NewBackupService(svc)
}

// stringSetToMap normalises a YAML-friendly []string allowlist into the
// map[string]struct{} shape remoteconfig.Config expects.
func stringSetToMap(in []string) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		out[s] = struct{}{}
	}
	return out
}

// buildCaptchaChecker builds the captcha dispatcher from config, or (nil, nil) when no provider is named; production accepts only hcaptcha or recaptcha.
func buildCaptchaChecker(cfg config.CaptchaConfig) (*captcha.Checker, error) {
	if cfg.Provider == "test" {
		return &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
			"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
		}}, nil
	}
	if cfg.SecretKey == nil || cfg.SecretKey.Plaintext() == "" {
		return nil, nil
	}
	allowlist := siteKeysByActionFromConfig(cfg.SiteKeysByAction)
	switch cfg.Provider {
	case "hcaptcha":
		v, err := captcha.NewHCaptchaVerifier(captcha.HCaptchaConfig{
			SecretKey:        cfg.SecretKey,
			SiteKeysByAction: allowlist,
		})
		if err != nil {
			return nil, &StartupError{Stage: "hcaptcha", Cause: err}
		}
		return &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{"hcaptcha": v}}, nil
	case "recaptcha":
		v, err := captcha.NewReCAPTCHAVerifier(captcha.ReCAPTCHAConfig{
			SecretKey:        cfg.SecretKey,
			SiteKeysByAction: allowlist,
		})
		if err != nil {
			return nil, &StartupError{Stage: "recaptcha", Cause: err}
		}
		return &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{"recaptcha": v}}, nil
	case "":
		// No provider: the REST layer answers 503 to any captcha submission.
		return nil, nil
	default:
		return nil, &UnknownBackendError{Backend: "captcha/" + cfg.Provider}
	}
}

// siteKeysByActionFromConfig converts the string-keyed config map to captcha.Action keys, dropping unknown names.
func siteKeysByActionFromConfig(in map[string][]string) map[captcha.Action][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[captcha.Action][]string, len(in))
	for k, v := range in {
		if action, ok := captcha.ParseAction(k); ok {
			out[action] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildPushManager assembles APNs and FCM legs from config; a missing leg falls back to NoOpProvider.
func buildPushManager(cfg config.PushConfig, logger *slog.Logger) (*push.PushManager, error) {
	mgrCfg := push.PushManagerConfig{Logger: logger}
	if cfg.APN.TeamID != "" && cfg.APN.KeyID != "" && cfg.APN.BundleID != "" && cfg.APN.PrivateKey != nil {
		provider, err := push.NewAPNsProvider(push.APNsConfig{
			BundleID:      cfg.APN.BundleID,
			TeamID:        cfg.APN.TeamID,
			KeyID:         cfg.APN.KeyID,
			SigningKeyPEM: []byte(cfg.APN.PrivateKey.Plaintext()),
			Sandbox:       cfg.APN.Sandbox,
		})
		if err != nil {
			return nil, &StartupError{Stage: "apns", Cause: err}
		}
		mgrCfg.APNs = provider
		logger.Info("APNs push provider configured", slog.Bool("sandbox", cfg.APN.Sandbox))
	}
	if cfg.FCM.Credentials != nil && cfg.FCM.Credentials.Plaintext() != "" {
		provider, err := push.NewFCMProvider(push.FCMConfig{
			ProjectID:          cfg.FCM.ProjectID,
			ServiceAccountJSON: []byte(cfg.FCM.Credentials.Plaintext()),
		})
		if err != nil {
			return nil, &StartupError{Stage: "fcm", Cause: err}
		}
		mgrCfg.FCM = provider
		logger.Info("FCM push provider configured")
	}
	return push.NewPushManager(mgrCfg), nil
}

// schedulePush wakes a push-only device, best-effort; an unregistered response clears the stale token.
func schedulePush(logger *slog.Logger, accountsMgr *accounts.AccountsManager, pushMgr *push.PushManager, accountUUID string, deviceID uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	acct, err := accountsMgr.Get(ctx, accountUUID)
	if err != nil {
		logger.Warn("schedulePush: account lookup failed",
			slog.String("uuid", accountUUID), slog.String("error", err.Error()))
		return
	}
	device := acct.GetDevice(deviceID)
	if device == nil || device.FetchesMessages {
		return
	}
	var (
		token   string
		devType push.DeviceType
	)
	switch {
	case device.ApnRegistrationID != "":
		token = device.ApnRegistrationID
		devType = push.DeviceTypeAPNs
	case device.GcmRegistrationID != "":
		token = device.GcmRegistrationID
		devType = push.DeviceTypeFCM
	default:
		return
	}
	res, err := pushMgr.Send(ctx, &push.PushNotification{
		AccountUUID: accountUUID,
		DeviceID:    deviceID,
		DeviceToken: token,
		DeviceType:  devType,
		Type:        push.NotificationTypeNotification,
		Urgent:      true,
	})
	if err != nil {
		logger.Warn("schedulePush: send failed",
			slog.String("uuid", accountUUID),
			slog.Uint64("deviceId", deviceID),
			slog.String("error", err.Error()))
		return
	}
	if res.Unregistered {
		logger.Info("schedulePush: device token unregistered",
			slog.String("uuid", accountUUID),
			slog.Uint64("deviceId", deviceID),
			slog.String("reason", res.RejectionReason))
		if err := clearStaleDeviceToken(ctx, accountsMgr, accountUUID, deviceID, devType); err != nil {
			logger.Warn("schedulePush: clear stale token failed",
				slog.String("uuid", accountUUID),
				slog.Uint64("deviceId", deviceID),
				slog.String("error", err.Error()))
		}
	}
}

// clearStaleDeviceToken zeroes a device's push token the provider reported invalid, re-reading the account to avoid clobbering a fresh token.
func clearStaleDeviceToken(ctx context.Context, accountsMgr *accounts.AccountsManager, accountUUID string, deviceID uint64, devType push.DeviceType) error {
	acct, err := accountsMgr.Get(ctx, accountUUID)
	if err != nil {
		return err
	}
	device := acct.GetDevice(deviceID)
	if device == nil {
		return nil
	}
	mutated := false
	switch devType {
	case push.DeviceTypeAPNs:
		if device.ApnRegistrationID != "" {
			device.ApnRegistrationID = ""
			device.VoipApnRegistrationID = ""
			mutated = true
		}
	case push.DeviceTypeFCM:
		if device.GcmRegistrationID != "" {
			device.GcmRegistrationID = ""
			mutated = true
		}
	}
	if !mutated {
		return nil
	}
	return accountsMgr.Update(ctx, acct)
}

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
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// Each owner of long-lived key material defers its wipe on creation, as a backstop to the ordered shutdown below.
	defer cfg.Destroy()

	httpAddr := cfg.Server.HTTPListen

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
		ephemeral, err := secrets.NewSecureString(generateEphemeralKey())
		if err != nil {
			return &StartupError{Stage: "signing key protection", Cause: err}
		}
		// This key is not from cfg, so cfg.Destroy does not wipe it; runStart owns it.
		defer ephemeral.Destroy()
		signingKey = ephemeral
	}

	// Initialize storage backends based on config.
	var (
		accountStore          accounts.AccountStore
		keyStore              keys.PreKeyStore
		messageStore          messages.MessageStore
		profileStore          profiles.ProfileStore
		usernameStore         usernames.UsernameStore
		recoveryPasswordStore recoverypassword.Store
		backupStore           backups.Store
		redeemedReceiptsStore backups.RedeemedReceiptsStore
		// With the postgres backend the call-quality survey publisher reuses this pool.
		pgClientForSurveys *pgstorage.Client
		// Remote config store: in-memory for memory mode, KV-backed for file and qrdb, the remote_config table for postgres.
		remoteConfigStore remoteconfig.Store
		// jobsStore is the persistence for the scheduled-jobs
		// subsystem. Same backend selection as the other domain
		// stores.
		jobsStore jobs.Store
		// manifestStore backs the embedded storage-service (contact/settings
		// sync). Wired into secureStorageMgr only when StorageService.Embedded
		// is set; otherwise the storage endpoints serve the safe 204 stub.
		manifestStore securestorage.ManifestStore
	)

	switch cfg.Storage.Backend {
	case "file":
		dataDir := cfg.Storage.File.DataDir
		if dataDir == "" {
			dataDir = "data"
		}
		kvClient, err := store.NewFileKVClient(dataDir)
		if err != nil {
			return &StartupError{Stage: "creating file KV client", Cause: err}
		}
		slog.InfoContext(ctx, "using file storage backend", slog.String("dataDir", dataDir))

		kvAdapter := qrdbstorage.NewKVClientAdapter(kvClient)

		accountStore = accounts.NewKVAccountStore(kvClient)
		keyStore = keys.NewKVPreKeyStore(kvClient)
		messageStore = messages.NewKVMessageStore(kvClient)
		profileStore = profiles.NewKVProfileStore(kvClient)
		usernameStore = qrdbstorage.NewUsernameStore(kvAdapter)
		recoveryPasswordStore = qrdbstorage.NewRecoveryPasswordStore(kvAdapter)
		if cfg.Backups.Enabled {
			backupStore = qrdbstorage.NewBackupStore(kvAdapter)
			redeemedReceiptsStore = qrdbstorage.NewRedeemedReceiptsStore(kvAdapter)
		}
		remoteConfigStore = qrdbstorage.NewRemoteConfigStore(kvAdapter)
		jobsStore = qrdbstorage.NewJobsStore(kvAdapter)
		manifestStore = qrdbstorage.NewSecureStorageStore(kvAdapter)

	case "postgres":
		slog.InfoContext(ctx, "using postgres storage backend")
		pgClient, err := pgstorage.New(ctx, pgstorage.Config{
			DSN:             cfg.Storage.Postgres.DSN(),
			MaxConns:        int32(cfg.Storage.Postgres.MaxConns),
			MinConns:        int32(cfg.Storage.Postgres.MinConns),
			MaxConnLifetime: cfg.Storage.Postgres.MaxConnLifetime,
			MaxConnIdleTime: cfg.Storage.Postgres.MaxConnIdleTime,
			ConnectTimeout:  cfg.Storage.Postgres.ConnectTimeout,
		})
		if err != nil {
			return &StartupError{Stage: "postgres connect", Cause: err}
		}
		if err := pgClient.Migrate(ctx); err != nil {
			pgClient.Close()
			return &StartupError{Stage: "postgres migrate", Cause: err}
		}
		// pgClient lives for the process and is not closed on the normal path.
		accountStore = pgstorage.NewAccountStore(pgClient.Pool())
		keyStore = pgstorage.NewPreKeyStore(pgClient.Pool())
		messageStore = pgstorage.NewMessageStore(pgClient.Pool())
		profileStore = pgstorage.NewProfileStore(pgClient.Pool())
		usernameStore = pgstorage.NewUsernameStore(pgClient)
		recoveryPasswordStore = pgstorage.NewRecoveryPasswordStore(pgClient)
		if cfg.Backups.Enabled {
			backupStore = pgstorage.NewBackupStore(pgClient)
			redeemedReceiptsStore = pgstorage.NewRedeemedReceiptsStore(pgClient)
		}
		remoteConfigStore = pgstorage.NewRemoteConfigStore(pgClient)
		jobsStore = pgstorage.NewJobsStore(pgClient)
		manifestStore = pgstorage.NewManifestStore(pgClient)
		pgClientForSurveys = pgClient

	case "qrdb":
		// qrdb domain stores over an in-process FakeKVStore until a qrdb transport is wired (ADR-0001).
		slog.InfoContext(ctx, "using qrdb storage backend (in-process fake transport)")
		qrdbKV := qrdbstorage.NewFakeKVStore()
		accountStore = qrdbstorage.NewAccountStore(qrdbKV)
		keyStore = qrdbstorage.NewPreKeyStore(qrdbKV)
		messageStore = qrdbstorage.NewMessageStore(qrdbKV)
		profileStore = qrdbstorage.NewProfileStore(qrdbKV)
		usernameStore = qrdbstorage.NewUsernameStore(qrdbKV)
		recoveryPasswordStore = qrdbstorage.NewRecoveryPasswordStore(qrdbKV)
		if cfg.Backups.Enabled {
			backupStore = qrdbstorage.NewBackupStore(qrdbKV)
			redeemedReceiptsStore = qrdbstorage.NewRedeemedReceiptsStore(qrdbKV)
		}
		manifestStore = qrdbstorage.NewSecureStorageStore(qrdbKV)
		remoteConfigStore = qrdbstorage.NewRemoteConfigStore(qrdbKV)
		jobsStore = qrdbstorage.NewJobsStore(qrdbKV)

	default: // "memory"
		slog.InfoContext(ctx, "using memory storage backend")
		accountStore = memory.NewMemoryAccountStore()
		keyStore = memory.NewMemoryPreKeyStore()
		messageStore = memory.NewMemoryMessageStore()
		profileStore = memory.NewMemoryProfileStore()
		usernameStore = memory.NewMemoryUsernameStore()
		recoveryPasswordStore = memory.NewMemoryRecoveryPasswordStore()
		if cfg.Backups.Enabled {
			backupStore = memory.NewMemoryBackupStore()
			redeemedReceiptsStore = memory.NewMemoryRedeemedReceiptsStore()
		}
		jobsStore = memory.NewMemoryJobsStore()
		manifestStore = memory.NewMemoryManifestStore()
	}

	// Shared cache client: Redis in production, memory for single-node deployments and tests.
	var cacheClient cache.Client
	switch cfg.Cache.Backend {
	case "redis":
		// The password stays in protected memory end to end: the cache
		// client takes the SecureString itself and only opens it when it
		// builds the go-redis options.
		redisClient, err := cacheredis.New(cacheredis.Config{
			URL:      cfg.Cache.Redis.URL,
			Password: cfg.Cache.Redis.Password,
			DB:       cfg.Cache.Redis.DB,
		})
		if err != nil {
			return &StartupError{Stage: "creating redis cache", Cause: err}
		}
		cacheClient = redisClient
		slog.InfoContext(ctx, "using redis cache backend", slog.String("url", cfg.Cache.Redis.URL))
	default:
		slog.InfoContext(ctx, "using memory cache backend")
		cacheClient = cachememory.New()
	}
	defer func() {
		if cerr := cacheClient.Close(); cerr != nil {
			slog.WarnContext(ctx, "cache close failed", slog.String("error", cerr.Error()))
		}
	}()

	// Health probes and /metrics on the admin port; /readyz checks the cache backend, the one dependency signald cannot route around.
	probes := health.New()
	metricsReg := metrics.NewRegistry("signald")
	probes.Add("cache", checks.Ping("cache", cacheClient))
	go func() {
		if err := health.RunSidecar(ctx, probes, metricsReg, cfg.Health.Listen); err != nil {
			logger.Error("signald health sidecar", slog.Any("error", err))
		}
	}()

	// Every accounts Create/Update/Delete fans out on the directory event bus to DirectoryService.Subscribe streams.
	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	directoryBus := accounts.NewDirectoryEventBus()
	accountsMgr.SetDirectoryEventBus(directoryBus)
	captchaChecker, err := buildCaptchaChecker(cfg.Captcha)
	if err != nil {
		return &StartupError{Stage: "captcha checker init", Cause: err}
	}
	captchaMgr := captcha.NewCaptchaManagerWithConfig(captcha.CaptchaManagerConfig{
		Checker: captchaChecker,
		Logger:  logger,
	})

	// Dynamic-configuration manager; config defaults are upserted on each boot so new flags appear in the catalog.
	if remoteConfigStore == nil {
		remoteConfigStore = remoteconfig.NewMemoryStore()
	}
	for _, c := range cfg.RemoteConfig.Defaults {
		if err := remoteConfigStore.Put(ctx, remoteconfig.Config{
			Name:         c.Name,
			Percentage:   c.Percentage,
			Value:        c.Value,
			DefaultValue: c.DefaultValue,
			HashKey:      c.HashKey,
			UUIDs:        stringSetToMap(c.UUIDs),
		}); err != nil {
			return &StartupError{Stage: fmt.Sprintf("seed remote config %q", c.Name), Cause: err}
		}
	}
	remoteConfigMgr, err := remoteconfig.NewManager(ctx, remoteconfig.ManagerConfig{
		Store:           remoteConfigStore,
		RefreshInterval: cfg.RemoteConfig.RefreshInterval,
	})
	if err != nil {
		return &StartupError{Stage: "remote config manager init", Cause: err}
	}
	defer remoteConfigMgr.Stop()

	// jobsMgr drains every non-APN job; apnJobsMgr shares the store with only the APN handler, so its throttle is independent.
	jobsMgr := jobs.NewManager(jobsStore, logger)
	apnJobsMgr := jobs.NewManager(jobsStore, logger)
	// Create an independent copy of the signing key so that certificates
	// manager holds its own SecureString and cannot alias the config value.
	signingKeyCopy, err := signingKey.Clone()
	if err != nil {
		return &StartupError{Stage: "signing key protection", Cause: err}
	}
	certificatesMgr := certificates.NewCertificatesManager(signingKeyCopy, logger)
	defer certificatesMgr.Destroy()

	// Initialize zkgroup ServerSecretParams from the ZKConfig serverSecret.
	// This enables zkgroup-native AuthCredentialWithPni group credentials and
	// ExpiringProfileKeyCredential issuance.
	var authSecret *zkgroup.ServerSecretParams
	if cfg.ZKConfig.ServerSecret != nil && !cfg.ZKConfig.ServerSecret.IsDestroyed() {
		serverSecretBytes := cfg.ZKConfig.ServerSecret.Bytes()
		var randomness zkgroup.RandomnessBytes
		copy(randomness[:], serverSecretBytes)
		for i := range serverSecretBytes {
			serverSecretBytes[i] = 0
		}
		s, err := zkgroup.GenerateServerSecretParams(randomness)
		// Zero randomness immediately after use.
		for i := range randomness {
			randomness[i] = 0
		}
		if err != nil {
			// In production a malformed ZK secret must never silently
			// downgrade to the HMAC placeholder credential.
			if cfg.IsProduction() {
				return signalerrors.Wrap(signalerrors.ErrInternal, "zkConfig.serverSecret is invalid", err)
			}
			slog.WarnContext(ctx, "failed to generate zkgroup server secret params; group credentials will use HMAC fallback",
				slog.String("error", err.Error()),
			)
		} else {
			authSecret = s
			certificatesMgr.SetAuthServerSecret(authSecret)
			slog.InfoContext(ctx, "zkgroup auth server secret configured")
		}
	} else {
		slog.WarnContext(ctx, "no zkConfig.serverSecret configured; group credentials will use HMAC-SHA256 fallback")
	}

	// Ed25519 delivery-certificate key derived from the signing key via SHA-256, stable across restarts.
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
			// ed25519.PrivateKey.Public always returns an ed25519.PublicKey.
			pubKey, _ := privKey.Public().(ed25519.PublicKey)
			pubHex := hex.EncodeToString(pubKey)
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
	// Default low-key replenishment hook: log at debug level so deployments
	// can observe the signal in logs/metrics. Production environments that
	// need to push refresh notifications wire their own callback over this.
	keysMgr.SetLowKeyCallback(func(ev keys.LowKeyEvent) {
		logger.Debug("device below pre-key replenishment threshold",
			slog.String("uuid", ev.AccountUUID),
			slog.Uint64("deviceId", ev.DeviceID),
			slog.Int("remainingEC", ev.RemainingEC),
			slog.Int("remainingKEM", ev.RemainingKEM),
			slog.Bool("lowEC", ev.LowEC),
			slog.Bool("lowKEM", ev.LowKEM),
		)
	})
	messagesMgr := messages.NewMessagesManager(messageStore)
	profilesMgr := profiles.NewProfilesManager(profileStore)
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, logger)
	recoveryPasswordsMgr := recoverypassword.NewManager(recoveryPasswordStore, 0, logger)
	cdnAccessKey := ""
	if cfg.CDN.AccessKey != nil {
		cdnAccessKey = cfg.CDN.AccessKey.Plaintext()
	}
	stickersMgr := stickers.NewStickersManager(stickers.ManagerConfig{
		Logger: logger,
		// CDN config doubles as the S3 credentials for sticker uploads —
		// Java's StickerController shares the same access key + region
		// with AttachmentController.
		S3: stickers.S3Config{
			Region:      cfg.CDN.Region,
			Bucket:      cfg.CDN.Bucket,
			AccessKeyID: cdnAccessKey,
			// The secret key is passed through in protected memory; it
			// is opened only inside the SigV4 key derivation.
			SecretAccessKey: cfg.CDN.SecretKey,
		},
	})
	directoryMgr := directory.NewDirectoryManager(logger)
	defer directoryMgr.Destroy()
	// A CDSI secret that cannot be placed in protected memory aborts startup.
	if err := directoryMgr.SetSharedSecret(cfg.CDSI.SharedSecret); err != nil {
		return &StartupError{Stage: "CDSI shared secret protection", Cause: err}
	}
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	defer secureStorageMgr.Destroy()
	if err := secureStorageMgr.SetSharedSecret(cfg.StorageService.SharedSecret); err != nil {
		return &StartupError{Stage: "storage-service shared secret protection", Cause: err}
	}
	// In-process storage service when no external one is configured; otherwise /storage stays on the 204 stub.
	if cfg.StorageService.RemoteURL == "" {
		secureStorageMgr.SetManifestStore(manifestStore)
		slog.InfoContext(ctx, "in-process storage-service enabled (monolithic mode)")
	}
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	keyTransparencyMgr := keytransparency.NewKeyTransparencyManager(logger)
	if cfg.KeyTransparency.RemoteAddr != "" {
		ktDialOpts := []grpc.DialOption{
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
		}
		if cfg.KeyTransparency.RemoteInsecure {
			ktDialOpts = []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
		}
		// Open the gRPC channel directly so we can attach a readiness
		// probe to it before handing it to the typed client. Probes
		// catch a TransientFailure state without waiting for an RPC.
		ktConn, dialErr := grpc.NewClient(cfg.KeyTransparency.RemoteAddr, ktDialOpts...)
		if dialErr != nil {
			return &StartupError{Stage: "key-transparency dial", Cause: dialErr}
		}
		ktClient, kerr := ktextclient.New(ktextclient.Config{Conn: ktConn})
		if kerr != nil {
			_ = ktConn.Close()
			return &StartupError{Stage: "key-transparency client", Cause: kerr}
		}
		keyTransparencyMgr.SetRemote(ktClient)
		probes.Add("key-transparency", checks.GRPCConn(ktConn))
		logger.Info("key-transparency: gRPC client wired",
			slog.String("endpoint", cfg.KeyTransparency.RemoteAddr))
	}
	provisioningStore := memory.NewMemoryProvisioningStore()
	devicesMgr := devices.NewDevicesManager(provisioningStore, accountsMgr, keysMgr, logger)
	// mrmCache stores each multi-recipient payload once in the cluster cache; envelopes reference it.
	mrmCache := messages.NewMRMCache(cacheClient, logger)
	// Plumb the MRM cache into MessagesManager so reads can rehydrate
	// envelopes that carry SharedMrmKey before delivery.
	messagesMgr.SetMRMCache(mrmCache)

	// wsSessions uses the cache so a message stored on any instance wakes the WebSocket wherever it is held.
	wsSessions := signalws.NewSessionManagerWithCache(logger, cacheClient,
		func(ctx context.Context, uuid string, deviceID uint64) ([]*messages.Envelope, error) {
			return messagesMgr.GetMessagesForDevice(ctx, uuid, deviceID)
		})

	// Verification: a gRPC client to a remote registration-service when RemoteAddr is set, else core.Service in-process; sessionshim.Shim adds the captcha gate.
	var (
		coreService *core.Service
		regShimCfg  sessionshim.Config
	)
	if cfg.Verification.RemoteAddr != "" {
		dialOpts := registrationServiceDialOptions(cfg.Verification)
		// Open the channel separately so we can attach a readiness
		// probe to it. Same pattern as the key-transparency wiring
		// above.
		regConn, dialErr := grpc.NewClient(cfg.Verification.RemoteAddr, dialOpts...)
		if dialErr != nil {
			return &StartupError{Stage: "registration-service dial", Cause: dialErr}
		}
		gc, gErr := grpcclient.New(grpcclient.Config{Conn: regConn})
		if gErr != nil {
			_ = regConn.Close()
			return &StartupError{Stage: "registration-service client", Cause: gErr}
		}
		probes.Add("registration-service", checks.GRPCConn(regConn))
		regShimCfg.Client = gc
		logger.Info("registration-service: gRPC client wired",
			slog.String("endpoint", cfg.Verification.RemoteAddr))
	} else {
		verificationStore := verification.NewMemoryVerificationSessionStore()
		verificationTransport, vtErr := verificationfactory.Build(cfg.Verification, logger)
		if vtErr != nil {
			return &StartupError{Stage: "verification transport", Cause: vtErr}
		}
		coreService = core.NewService(verificationStore, verificationTransport, core.Config{
			FixedCode: cfg.Verification.FixedCode,
		})
		regShimCfg.Client = inprocess.New(coreService)
		logger.Info("registration-service: in-process wiring (monolithic deployment)",
			slog.String("transport", cfg.Verification.Transport))
	}
	regShimCfg.CaptchaStore = sessionshim.NewMemoryCaptchaStore()
	regShimCfg.CaptchaChecker = captchaChecker
	verificationMgr := sessionshim.NewShim(regShimCfg)
	// In-process verification: drain core.Service's cleanup goroutine on shutdown.
	if coreService != nil {
		defer coreService.Shutdown()
	}
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
			return &StartupError{Stage: "cloudflare TURN provider", Cause: err}
		}
	} else {
		// Fallback: static TURN provider for development.
		turnProvider = &calling.StaticTurnProvider{
			URLs:     cfCfg.URLs,
			Hostname: cfCfg.Hostname,
		}
	}

	// Survey publisher: postgres when the storage backend is postgres, else log; cfg.CallQualitySurvey.Backend overrides.
	var surveyPub calling.SurveyPublisher
	switch cfg.CallQualitySurvey.Backend {
	case "postgres":
		if pgClientForSurveys == nil {
			return errors.New("call-quality-survey backend=postgres but storage backend is not postgres")
		}
		surveyPub = pgstorage.NewCallQualitySurveyPublisher(pgClientForSurveys)
	case "pubsub":
		// Google Pub/Sub publisher is intentionally not implemented —
		// the analytics path goes through Postgres in Java. Document
		// the gap explicitly rather than silently fall back.
		return errors.New("call-quality-survey backend=pubsub is not implemented")
	case "", "log":
		surveyPub = calling.NewLogSurveyPublisher(logger)
	default:
		if pgClientForSurveys != nil {
			surveyPub = pgstorage.NewCallQualitySurveyPublisher(pgClientForSurveys)
		} else {
			surveyPub = calling.NewLogSurveyPublisher(logger)
		}
	}

	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider:        turnProvider,
		GenericServerSecret: callingZKParams,
		SurveyPublisher:     surveyPub,
		Logger:              logger,
	})
	defer callingMgr.Destroy()

	// Push manager from APNs and FCM credentials; without them it is NoOpProvider and only WebSocket delivery runs.
	pushMgr, err := buildPushManager(cfg.Push, logger)
	if err != nil {
		return &StartupError{Stage: "push manager init", Cause: err}
	}

	// APN job handler: decode a JSON PushNotification (capped at 16 KiB) and send; errors go back to jobs.Manager for retry.
	const maxAPNPayloadSize = 16 * 1024
	apnJobsMgr.Register(workers.JobTypeAPNPushSend, func(ctx context.Context, job *jobs.Job) error {
		if len(job.Payload) > maxAPNPayloadSize {
			return &UsageError{Message: fmt.Sprintf("apn job payload %d bytes exceeds max %d", len(job.Payload), maxAPNPayloadSize)}
		}
		var notif push.PushNotification
		if err := json.Unmarshal(job.Payload, &notif); err != nil {
			return &StartupError{Stage: "apn job payload decode", Cause: err}
		}
		_, err := pushMgr.Send(ctx, &notif)
		return err
	})

	// Delivery order: local session, cross-instance wakeup, then push on a goroutine so the insert does not block.
	messagesMgr.SetDeliveryCallback(func(uuid string, deviceID uint64, envelope *messages.Envelope) {
		if wsSessions.DeliverMessage(uuid, deviceID, envelope) {
			return
		}
		notifyCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := wsSessions.NotifyMessageAvailable(notifyCtx, uuid, deviceID); err != nil {
			logger.Warn("websocket notify failed",
				slog.String("uuid", uuid),
				slog.Uint64("deviceId", deviceID),
				slog.String("error", err.Error()))
		}
		// Push fan-out (async). schedulePush walks the device's
		// ApnRegistrationID / GcmRegistrationID and is a no-op when neither
		// is set or the device polls via FetchesMessages=true.
		go schedulePush(logger, accountsMgr, pushMgr, uuid, deviceID)
	})

	// Spam checker: a composite around the messages rate limit; rateLimitCheckerStop stops its cleanup goroutine on shutdown.
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

	// Backups stack, when enabled and zkgroup secrets are configured; otherwise its endpoints return Unimplemented.
	var backupSvc *backups.Service
	if cfg.Backups.Enabled {
		switch {
		case backupStore == nil || redeemedReceiptsStore == nil:
			slog.WarnContext(ctx, "backups enabled but storage backend has no backup adapter; backup subsystem disabled")
		case callingZKParams == nil:
			slog.WarnContext(ctx, "backups enabled but callingZkConfig.serverSecret missing; backup subsystem disabled")
		case authSecret == nil:
			slog.WarnContext(ctx, "backups enabled but zkConfig.serverSecret missing; backup subsystem disabled (receipts cannot be verified)")
		default:
			blobBackend := cfg.Backups.Blob.Backend
			if blobBackend == "" {
				blobBackend = "filesystem"
			}
			var blobStore backups.BlobStore
			switch blobBackend {
			case "filesystem":
				root := cfg.Backups.Blob.Root
				if root == "" {
					root = "data/backups"
				}
				fs, err := blob.NewFilesystemStore(blob.FilesystemOptions{
					Root:      root,
					CDNNumber: cfg.Backups.Blob.CDNNumber,
				})
				if err != nil {
					return &StartupError{Stage: "backups: filesystem blob store", Cause: err}
				}
				blobStore = fs
				slog.InfoContext(ctx, "backups blob backend: filesystem", slog.String("root", root))
			default:
				return &UsageError{Message: fmt.Sprintf("backups: unsupported blob backend %q (only \"filesystem\" is implemented)", blobBackend)}
			}
			backupAuth := backups.NewAuthManager(backups.AuthManagerOptions{
				Accounts:                    accountsMgr,
				SetBackupIDLimiter:          rateLimits.ForSetBackupID(),
				SetPaidMediaBackupIDLimiter: rateLimits.ForSetPaidMediaBackupID(),
				ServerSecretParams:          callingZKParams,
				ReceiptServerSecretParams:   authSecret,
				RedeemedReceipts:            redeemedReceiptsStore,
			})
			backupMgr := backups.NewManager(backups.ManagerOptions{
				Store:              backupStore,
				Blob:               blobStore,
				ServerSecretParams: callingZKParams,
				AttachmentLimiter:  rateLimits.ForBackupAttachment(),
				MaxQuota:           cfg.Backups.MaxTotalMediaSize,
			})
			backupSvc = backups.NewService(backupMgr, backupAuth)
			slog.InfoContext(ctx, "backups subsystem enabled")
		}
	}

	// Resolve the frontend FS when the web UI is enabled.
	var frontendFS fs.FS
	if cfg.Frontend.Enabled {
		frontendFS = internalfrontend.FS()
		slog.InfoContext(ctx, "web UI enabled: serving embedded React SPA at /")
	}

	// Start REST API server.
	httpHost, httpPort, err := splitListen(cfg.Server.HTTPListen)
	if err != nil {
		return &StartupError{Stage: "resolving the REST listen address", Cause: err}
	}
	srv := rest.NewServer(rest.ServerConfig{
		Host:               httpHost,
		Port:               httpPort,
		IsProduction:       cfg.IsProduction(),
		TLSCertFile:        cfg.Server.TLSCertFile,
		TLSKeyFile:         cfg.Server.TLSKeyFile,
		Logger:             logger,
		Accounts:           accountsMgr,
		Captcha:            captchaMgr,
		CaptchaChecker:     captchaChecker,
		RemoteConfig:       remoteConfigMgr,
		Certificates:       certificatesMgr,
		Keys:               keysMgr,
		Messages:           messagesMgr,
		Profiles:           profilesMgr,
		Usernames:          usernamesMgr,
		RecoveryPasswords:  recoveryPasswordsMgr,
		Stickers:           stickersMgr,
		Directory:          directoryMgr,
		SecureStorage:      secureStorageMgr,
		SVR:                svrMgr,
		Calling:            callingMgr,
		KeyTransparency:    keyTransparencyMgr,
		Devices:            devicesMgr,
		WSSessions:         wsSessions,
		Verification:       verificationMgr,
		Audit:              audit.New(logger),
		SpamChecker:        spamChecker,
		FraudChecker:       fraudChecker,
		RateLimits:         rateLimits,
		LoopDetector:       loopDetector,
		MRMCache:           mrmCache,
		Backups:            nilableBackupService(backupSvc),
		AllowedOrigins:     cfg.Server.AllowedOrigins,
		StaticResourcesDir: cfg.StaticResources.ResourcesDir,
		FrontendFS:         frontendFS,
		AvatarCDN: rest.AvatarCDNConfig{
			Bucket:    cfg.CDN.Bucket,
			Region:    cfg.CDN.Region,
			AccessKey: cdnAccessKey,
			SecretKey: cfg.CDN.SecretKey,
		},
	})

	// Initialize attachment storage.
	if cfg.Attachments.StorageDir != "" {
		attStore, err := attachmentspkg.NewFileStore(cfg.Attachments.StorageDir)
		if err != nil {
			return &StartupError{Stage: "creating attachment store", Cause: err}
		}
		srv.SetAttachmentStore(attStore)
		slog.InfoContext(ctx, "attachment storage configured", slog.String("dir", cfg.Attachments.StorageDir))
	} else {
		slog.WarnContext(ctx, "no attachment storage configured — uploads will be discarded")
	}

	// External TUS upload form generator; unset tusUri or secret falls back to the embedded /cdn3 route. IsAbsent, not IsDestroyed: an unopenable secret is an error.
	var tusGenerator *external.Generator
	defer func() { tusGenerator.Destroy() }()
	if cfg.Attachments.TusURI != "" && !cfg.Attachments.TusSharedSecret.IsAbsent() {
		gen, err := external.NewGenerator(external.GeneratorConfig{
			Key: cfg.Attachments.TusSharedSecret,
		})
		if err != nil {
			return &StartupError{Stage: "attachment TUS credentials generator", Cause: err}
		}
		tusGenerator = gen
		srv.SetAttachmentTus(cfg.Attachments.TusURI, gen)
		slog.InfoContext(ctx, "external TUS attachment upload configured", slog.String("uri", cfg.Attachments.TusURI))
	}

	// Initialize FIDO2 routes if compiled with the fido2 build tag and
	// enabled in the config.
	initFIDO2(srv, cfgPath, logger)

	// SignalService aggregate: the single injection point for the gRPC services layer.
	svc := service.NewSignalService(service.ServiceConfig{
		Accounts:     accountsMgr,
		Keys:         keysMgr,
		Messages:     messagesMgr,
		Profiles:     profilesMgr,
		Usernames:    usernamesMgr,
		Calling:      callingMgr,
		WSSessions:   wsSessions,
		Devices:      devicesMgr,
		Certificates: certificatesMgr,
		Backups:      backupSvc,
		Logger:       logger,
	})

	// gRPC listener beside REST, hosting every service in pkg/api/grpc/proto.
	var grpcServer *grpcapi.Server
	if cfg.Server.GRPCListen != "" {
		grpcAddr := cfg.Server.GRPCListen
		dirSource := &directoryAccountSource{store: accountStore}
		dirEvents := &directoryEventSource{bus: directoryBus}
		grpcServer = grpcapi.New(grpcapi.Config{Listen: grpcAddr}, accountsMgr, svc, dirSource,
			dirsvc.WithEventSource(dirEvents))
		go func() {
			slog.InfoContext(ctx, "starting gRPC server", slog.String("addr", grpcAddr))
			if err := grpcServer.Serve(ctx); err != nil {
				slog.ErrorContext(ctx, "gRPC server error", slog.String("error", err.Error()))
			}
		}()
	}

	// Worker scheduler: continuous, cron and on-demand workers; leader election via a shared (redis) cache.
	workerScheduler := workers.NewScheduler(workers.Config{
		Logger: logger,
		Leaser: workers.NewCacheLeaser(cacheClient, ""),
	})
	if err := workers.RegisterDefaults(workerScheduler, svc, remoteConfigMgr, certificatesMgr, pushMgr, jobsMgr, apnJobsMgr); err != nil {
		return &StartupError{Stage: "registering default workers", Cause: err}
	}
	if err := workerScheduler.Start(ctx); err != nil {
		return &StartupError{Stage: "starting worker scheduler", Cause: err}
	}
	defer workerScheduler.Stop()

	// Start the server and propagate fatal errors through a channel so that
	// runStart can return a non-nil error (L8).
	startErr := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	// Ordered shutdown: WebSocket sessions, HTTP server, background goroutines, then key material.
	slog.InfoContext(ctx, "shutting down Signal server")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// 1. Close all WebSocket sessions.
	wsSessions.CloseAll()

	// 2. Shutdown HTTP server.
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.ErrorContext(ctx, "REST server shutdown error", slog.String("error", err.Error()))
	}

	// 2b. Stop the gRPC server (GracefulStop drains in-flight RPCs).
	if grpcServer != nil {
		grpcServer.Stop()
	}

	// 3. Stop background goroutines.
	loopDetector.Stop()
	if rateLimitCheckerStop != nil {
		rateLimitCheckerStop()
	}
	// Stop fraud checker's background cleanup goroutine.
	fraudChecker.Stop()
	rateLimits.Stop()

	// 4. Wipe sensitive key material from protected memory. Every owner of a
	// long-lived secret is destroyed here, not just the config it was drawn
	// from — each of these holds its own protected clone.
	certificatesMgr.Destroy()
	callingMgr.Destroy()
	directoryMgr.Destroy()
	secureStorageMgr.Destroy()
	tusGenerator.Destroy()
	cfg.Destroy()

	slog.InfoContext(ctx, "Signal server stopped")
	return serverErr
}

// cfgToLimitsConfig converts config.LimitsConfig to limits.Config; zero fields take the defaults and LeakRatePerMin becomes a per-second RefillRate.
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

// directoryAccountSource adapts an accounts.AccountStore to dirsvc.AccountSource for the DirectoryService snapshot.
type directoryAccountSource struct {
	store accounts.AccountStore
}

func (d *directoryAccountSource) ListAll(ctx context.Context, fn func(dirsvc.DirectoryEntry) error) error {
	return d.store.ListAll(ctx, func(a *accounts.Account) error {
		return fn(accountToDirectoryEntry(a))
	})
}

// accountToDirectoryEntry converts an account to the directory wire shape, shared by the snapshot and live-event paths.
func accountToDirectoryEntry(a *accounts.Account) dirsvc.DirectoryEntry {
	entry := dirsvc.DirectoryEntry{}
	if a == nil {
		return entry
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(a.Number, "+"), 10, 64); err == nil {
		entry.E164 = n
	}
	if a.UUID != "" {
		if id, err := uuid.Parse(a.UUID); err == nil {
			b, _ := id.MarshalBinary()
			copy(entry.ACI[:], b)
		}
	}
	if a.PNI != "" {
		if id, err := uuid.Parse(a.PNI); err == nil {
			b, _ := id.MarshalBinary()
			copy(entry.PNI[:], b)
		}
	}
	// Profile access keys are not on Account; cdsi treats zero bytes as no access key.
	return entry
}

// directoryEventSource adapts an accounts.DirectoryEventBus to dirsvc.EventSource for DirectoryService.Subscribe.
type directoryEventSource struct {
	bus *accounts.DirectoryEventBus
}

// Subscribe implements dirsvc.EventSource. The captured asOf is
// forwarded verbatim so the server can decide whether the client's
// resume token is fresh enough to skip the snapshot.
func (s *directoryEventSource) Subscribe(ctx context.Context, buffer int) (dirsvc.EventSubscription, uint64) {
	sub, asOf := s.bus.Subscribe(ctx, buffer)
	return &directoryEventSubscription{sub: sub}, asOf
}

// directoryEventSubscription converts accounts.DirectoryEvent to dirsvc.ChangeEvent on its own goroutine, off the handler path.
type directoryEventSubscription struct {
	sub *accounts.Subscription
	ch  chan dirsvc.ChangeEvent
	one sync.Once
}

func (s *directoryEventSubscription) Events() <-chan dirsvc.ChangeEvent {
	s.one.Do(func() {
		s.ch = make(chan dirsvc.ChangeEvent, cap(s.sub.Events()))
		go func() {
			defer close(s.ch)
			for e := range s.sub.Events() {
				s.ch <- accountsEventToChangeEvent(e)
			}
		}()
	})
	return s.ch
}

func (s *directoryEventSubscription) Done() <-chan struct{} { return s.sub.Done() }
func (s *directoryEventSubscription) Overflowed() bool      { return s.sub.Overflowed() }
func (s *directoryEventSubscription) Close()                { s.sub.Close() }

func accountsEventToChangeEvent(e accounts.DirectoryEvent) dirsvc.ChangeEvent {
	out := dirsvc.ChangeEvent{
		Seq:  e.Seq,
		UUID: e.UUID,
	}
	switch e.Kind {
	case accounts.DirectoryEventDeleted:
		out.Kind = dirsvc.ChangeEventDelete
	default:
		out.Kind = dirsvc.ChangeEventUpsert
	}
	out.Entry = accountToDirectoryEntry(e.Account)
	return out
}

// registrationServiceDialOptions returns plaintext dial options when cfg.RemoteInsecure is set, else TLS with system roots.
func registrationServiceDialOptions(cfg config.VerificationConfig) []grpc.DialOption {
	if cfg.RemoteInsecure {
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	}
	creds := credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	return []grpc.DialOption{grpc.WithTransportCredentials(creds)}
}

// splitListen splits a host:port listen address; an empty address yields host "" and port 0 (ephemeral).
func splitListen(addr string) (string, int, error) {
	if addr == "" {
		return "", 0, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
