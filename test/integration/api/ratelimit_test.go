//go:build integration

package api

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/api/rest"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
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
	"github.com/jeremyhahn/go-signal/pkg/stickers"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inProcessBucketSize is the bucket size used for the in-process test server.
const inProcessBucketSize = 3

// setupRateLimitedTestServer creates an in-process test REST server with a
// tightly configured rate limiter. All limiters use a bucket size of 3 to
// allow fast exhaustion. Returns nil server and the external URL when
// SIGNAL_SERVER_URL is set.
func setupRateLimitedTestServer(t *testing.T) (*rest.Server, string) {
	t.Helper()

	if externalURL := os.Getenv("SIGNAL_SERVER_URL"); externalURL != "" {
		return nil, externalURL
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	bucketSize3 := limits.BucketConfig{
		BucketSize:      inProcessBucketSize,
		RefillRate:      0.001,
		CleanupInterval: time.Hour,
		StaleAfter:      time.Hour,
	}

	rateLimitCfg := limits.Config{
		Registration:   bucketSize3,
		Messages:       bucketSize3,
		PreKeys:        bucketSize3,
		Profiles:       bucketSize3,
		Attachments:    bucketSize3,
		Verification:   bucketSize3,
		PIN:            bucketSize3,
		Usernames:      bucketSize3,
		Authentication: bucketSize3,
	}

	accountStore := memory.NewMemoryAccountStore()
	keyStore := memory.NewMemoryPreKeyStore()
	messageStore := memory.NewMemoryMessageStore()
	profileStore := memory.NewMemoryProfileStore()
	usernameStore := memory.NewMemoryUsernameStore()

	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	captchaMgr := captcha.NewCaptchaManager(logger)
	certificatesMgr := certificates.NewCertificatesManager(secrets.NewSecureString("test-signing-key-32bytes-xxxxxx"), logger)
	keysMgr := keys.NewKeysManager(keyStore)
	messagesMgr := messages.NewMessagesManager(messageStore)
	profilesMgr := profiles.NewProfilesManager(profileStore)
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, logger)
	stickersMgr := stickers.NewStickersManager(stickers.ManagerConfig{Logger: logger})
	directoryMgr := directory.NewDirectoryManager(logger)
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	keyTransparencyMgr := keytransparency.NewKeyTransparencyManager(logger)
	provisioningStore := memory.NewMemoryProvisioningStore()
	devicesMgr := devices.NewDevicesManager(provisioningStore, accountsMgr, keysMgr, logger)
	wsSessions := signalws.NewSessionManager(logger)

	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider: &calling.StaticTurnProvider{
			URLs:     []string{"turn:turn.example.com:3478"},
			Hostname: "turn.example.com",
		},
		SurveyPublisher: calling.NewLogSurveyPublisher(logger),
		Logger:          logger,
	})

	registry := limits.NewRegistry(rateLimitCfg)

	srv := rest.NewServer(rest.ServerConfig{
		Host:            "127.0.0.1",
		Port:            0,
		Logger:          logger,
		Accounts:        accountsMgr,
		Captcha:         captchaMgr,
		Certificates:    certificatesMgr,
		Keys:            keysMgr,
		Messages:        messagesMgr,
		Profiles:        profilesMgr,
		Usernames:       usernamesMgr,
		Stickers:        stickersMgr,
		Directory:       directoryMgr,
		SecureStorage:   secureStorageMgr,
		SVR:             svrMgr,
		Calling:         callingMgr,
		KeyTransparency: keyTransparencyMgr,
		Devices:         devicesMgr,
		WSSessions:      wsSessions,
		RateLimits:      registry,
	})

	require.NoError(t, srv.Listen())
	addr := srv.Addr()
	require.NotEqual(t, "127.0.0.1:0", addr)

	go func() {
		if serveErr := srv.Serve(); serveErr != nil && serveErr != http.ErrServerClosed {
			t.Logf("serve error: %v", serveErr)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	return srv, "http://" + addr
}

// isExternalServer reports whether tests are running against an external server.
func isExternalServer() bool {
	return os.Getenv("SIGNAL_SERVER_URL") != ""
}

// rateLimitHTTPClient returns an HTTP client suitable for the test environment.
func rateLimitHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// TestRateLimiting_RegistrationEndpoint_IP verifies that the registration
// endpoint enforces IP-based rate limiting. Against the in-process server
// (bucket=3), it verifies exhaustion produces 429. Against an external server
// with large buckets, it verifies a few requests are NOT rate-limited.
func TestRateLimiting_RegistrationEndpoint_IP(t *testing.T) {
	_, baseURL := setupRateLimitedTestServer(t)
	client := rateLimitHTTPClient()

	if isExternalServer() {
		// External server has large bucket (10000). Just verify 3 requests
		// are not rate-limited.
		for i := range 3 {
			req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/registration", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.NotEqual(t, http.StatusTooManyRequests, resp.StatusCode,
				"request %d should not be rate-limited with large bucket", i)
		}
		return
	}

	// In-process server with bucket=3. Exhaust the bucket.
	for i := range inProcessBucketSize {
		req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/registration", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d should not be rate-limited yet (bucket size %d)", i, inProcessBucketSize)
		}
	}

	// The (bucketSize+1)-th request must return 429.
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/registration", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, "4th request should be rate-limited")

	retryAfter := resp.Header.Get("Retry-After")
	assert.NotEmpty(t, retryAfter, "Retry-After header must be set on 429")

	val, parseErr := strconv.ParseInt(retryAfter, 10, 64)
	require.NoError(t, parseErr, "Retry-After must be an integer")
	assert.Greater(t, val, int64(0), "Retry-After must be positive")
}

// TestRateLimiting_VerificationEndpoint_IP verifies the verification session
// endpoint is rate-limited by remote IP.
func TestRateLimiting_VerificationEndpoint_IP(t *testing.T) {
	_, baseURL := setupRateLimitedTestServer(t)
	client := rateLimitHTTPClient()

	if isExternalServer() {
		// External server has large bucket. Verify a few requests are accepted.
		for i := range 3 {
			req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/verification/session", http.NoBody)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.NotEqual(t, http.StatusTooManyRequests, resp.StatusCode,
				"verification request %d should not be rate-limited", i)
		}
		return
	}

	// In-process server with bucket=3.
	for i := range inProcessBucketSize {
		req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/verification/session", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("verification request %d should not be rate-limited yet", i)
		}
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/verification/session", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"verification endpoint should be rate-limited after bucket exhaustion")
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}

// TestRateLimiting_NoLimiter_AllowsAllRequests verifies that a server
// configured without a rate limiter passes all requests through normally.
// Against an external server (which always has a limiter), this test verifies
// that 10 requests are accepted without 429 given the large bucket.
func TestRateLimiting_NoLimiter_AllowsAllRequests(t *testing.T) {
	var baseURL string
	if externalURL := os.Getenv("SIGNAL_SERVER_URL"); externalURL != "" {
		baseURL = externalURL
	} else {
		env := setupTestEnv(t)
		baseURL = env.baseURL
	}

	client := rateLimitHTTPClient()

	// Send 10 consecutive requests; none should be rate-limited.
	for i := range 10 {
		req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/registration", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			t.Errorf("request %d: unexpected 429", i)
		}
	}
}
