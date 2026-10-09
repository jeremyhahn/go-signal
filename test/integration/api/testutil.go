//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/api/rest"
	"github.com/jeremyhahn/go-signal/pkg/calling"
	"github.com/jeremyhahn/go-signal/pkg/captcha"
	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/devices"
	"github.com/jeremyhahn/go-signal/pkg/directory"
	"github.com/jeremyhahn/go-signal/pkg/extservice/registration/inprocess"
	"github.com/jeremyhahn/go-signal/pkg/keys"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
	"github.com/jeremyhahn/go-signal/pkg/messages"
	"github.com/jeremyhahn/go-signal/pkg/profiles"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/registration/sessionshim"
	"github.com/jeremyhahn/go-signal/pkg/remoteconfig"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	"github.com/jeremyhahn/go-signal/pkg/securevaluerecovery"
	"github.com/jeremyhahn/go-signal/pkg/stickers"
	"github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/usernames"
	"github.com/jeremyhahn/go-signal/pkg/verification"
	signalws "github.com/jeremyhahn/go-signal/pkg/websocket"
)

// phoneRunBase is a per-process random base offset for phone number generation.
// It is initialised once at package load time from a cryptographically secure
// random source so that successive integration test runs against a persistent
// external server never reuse phone numbers from a previous run. The upper
// four digits of the seven-digit suffix encode the run base (0000–9999); the
// lower three digits encode the per-test counter (001–999).
var phoneRunBase int64

func init() {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-derived value; still avoids sequential collisions.
		phoneRunBase = (time.Now().UnixNano() / 1e6) % 10000
		return
	}
	phoneRunBase = int64(binary.BigEndian.Uint16(b[:])) % 10000
}

// phoneCounter is an atomic counter used to generate unique phone numbers
// within a single test run, preventing collisions across concurrently running
// tests. It is combined with phoneRunBase to produce run-unique numbers.
var phoneCounter int64

// uniquePhoneNumber generates a unique phone number for each test invocation.
// The format is "+1555RRRRPPP" where RRRR is the four-digit per-run base and
// PPP is a zero-padded three-digit per-test counter (001–999). This scheme
// supports up to 999 tests per run and ensures different runs against a shared
// persistent server never collide on the same phone number.
func uniquePhoneNumber() string {
	n := atomic.AddInt64(&phoneCounter, 1)
	// Clamp to 3-digit range; integration tests never need more than 999 numbers.
	return fmt.Sprintf("+1555%04d%03d", phoneRunBase, n%1000)
}

// testEnv holds the test server and HTTP client for integration tests.
// When SIGNAL_SERVER_URL is set (devcontainer mode), tests connect to
// the external containerized server. Otherwise, an in-process server
// is started for local development.
type testEnv struct {
	server  *rest.Server // nil when using external server
	baseURL string
	client  *http.Client
}

// caCertPath returns the CA that issued the devcontainer server's certificate.
// SIGNAL_CA_CERT lets the environment point elsewhere, matching what the CLI
// harness already reads.
func caCertPath() string {
	if path := os.Getenv("SIGNAL_CA_CERT"); path != "" {
		return path
	}
	return "../../tls/ca-cert.pem"
}

// remoteTLSConfig verifies the server against the test CA instead of trusting
// whatever certificate it presents.
//
// This used to be InsecureSkipVerify with a comment asserting the target was a
// local devcontainer. SIGNAL_SERVER_URL is read verbatim and constrained to
// nothing, so that assertion was not the code's to make: pointed at any other
// host, the suite would accept any certificate while sending registration
// passwords, authorization headers and generated key material to it. The test
// CA is in the repo and its certificate covers signal-server, localhost and
// 127.0.0.1, so there is nothing to give up by verifying properly.
//
// Failing to load the CA fails the test. A fallback to skipping verification
// would restore the same hole for anyone whose environment is slightly wrong.
func remoteTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	path := caCertPath()
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read test CA %s: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("test CA %s contains no usable certificate", path)
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// setupTestEnv creates a test environment. If the SIGNAL_SERVER_URL
// environment variable is set, the tests connect to that external server
// (the devcontainer docker-compose signal-server service). Otherwise, an
// in-process server with in-memory stores is started on a random port.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	if serverURL := os.Getenv("SIGNAL_SERVER_URL"); serverURL != "" {
		return &testEnv{
			baseURL: serverURL,
			client: &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: remoteTLSConfig(t),
				},
			},
		}
	}

	// Local mode: start an in-process server with in-memory stores.
	accountStore := memory.NewMemoryAccountStore()
	messageStore := memory.NewMemoryMessageStore()
	keyStore := memory.NewMemoryPreKeyStore()
	profileStore := memory.NewMemoryProfileStore()
	usernameStore := memory.NewMemoryUsernameStore()

	accountsMgr := accounts.NewAccountsManager(accountStore, 6)
	// Mirror the daemon's wiring (cmd/signald buildCaptchaChecker): a Checker
	// holding the test provider, not the bare legacy verifier. Both modes of
	// this fixture must accept the same submission format, or a test that
	// passes against the live server fails in local mode for a reason that
	// has nothing to do with the server.
	captchaMgr := captcha.NewCaptchaManagerWithConfig(captcha.CaptchaManagerConfig{
		Checker: &captcha.Checker{Providers: map[string]captcha.CaptchaVerifier{
			"test": captcha.NewTestVerifier(captcha.TestVerifierConfig{}),
		}},
		Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	certificatesMgr := certificates.NewCertificatesManager(secrets.MustNewSecureString(t.Context(), "test-signing-key"), slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	keysMgr := keys.NewKeysManager(keyStore)
	messagesMgr := messages.NewMessagesManager(messageStore)
	profilesMgr := profiles.NewProfilesManager(profileStore)
	usernamesMgr := usernames.NewUsernamesManager(usernameStore, slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	stickersMgr := stickers.NewStickersManager(t.Context(), stickers.ManagerConfig{Logger: logger})
	directoryMgr := directory.NewDirectoryManager(logger)
	secureStorageMgr := securestorage.NewSecureStorageManager(logger)
	svrMgr := securevaluerecovery.NewSVRManager(logger)
	// Generate a deterministic server secret for call link credential issuance.
	// Use a fixed 32-byte seed so tests are reproducible.
	var callingZKRandomness zkgroup.RandomnessBytes
	copy(callingZKRandomness[:], []byte("test-calling-zk-secret-32bytes!!"))
	callingZKParams := zkgroup.GenerateGenericServerSecretParams(callingZKRandomness)

	callingMgr := calling.NewCallingManager(calling.CallingConfig{
		TurnProvider: &calling.StaticTurnProvider{
			URLs:     []string{"turn:localhost:3478"},
			Hostname: "localhost",
		},
		GenericServerSecret: callingZKParams,
		Logger:              logger,
	})
	keyTransparencyMgr := keytransparency.NewKeyTransparencyManager(logger)
	provisioningStore := memory.NewMemoryProvisioningStore()
	devicesMgr := devices.NewDevicesManager(provisioningStore, accountsMgr, keysMgr, logger)
	wsSessions := signalws.NewSessionManager(logger)
	verificationStore := verification.NewMemoryVerificationSessionStore()
	verificationTransport := verification.NewStubTransport(logger)
	coreSvc := core.NewService(verificationStore, verificationTransport, core.Config{
		// FixedCode enables deterministic verification in tests:
		// registerTestAccount always submits "123456" and the stub
		// transport will match it.
		FixedCode: "123456",
	})
	t.Cleanup(coreSvc.Shutdown)
	verificationMgr := sessionshim.NewShim(sessionshim.Config{
		Client:       inprocess.New(coreSvc),
		CaptchaStore: sessionshim.NewMemoryCaptchaStore(),
	})

	// Wire real-time WebSocket delivery.
	messagesMgr.SetDeliveryCallback(func(uuid string, deviceID uint64, env *messages.Envelope) {
		wsSessions.DeliverMessage(uuid, deviceID, env)
	})

	// Seed remote (dynamic) configuration so GET /v2/config exercises the
	// real evaluation pipeline. The global.* flags ship to every platform
	// at 100% so every account receives value "TRUE".
	rcStore := remoteconfig.NewMemoryStore()
	for _, name := range []string{
		"global.calling", "global.groupsv2", "global.storage",
		"global.senderKey", "global.stories", "global.giftBadges",
	} {
		require.NoError(t, rcStore.Put(context.Background(), remoteconfig.Config{
			Name:       name,
			Percentage: 100,
			Value:      "TRUE",
		}))
	}
	remoteConfigMgr, err := remoteconfig.NewManager(context.Background(), remoteconfig.ManagerConfig{Store: rcStore})
	require.NoError(t, err)
	t.Cleanup(remoteConfigMgr.Stop)

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
		Verification:    verificationMgr,
		RemoteConfig:    remoteConfigMgr,
	})

	err = srv.Listen()
	require.NoError(t, err)

	addr := srv.Addr()
	require.NotEqual(t, "127.0.0.1:0", addr, "server did not bind")

	go func() {
		if err := srv.Serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("server serve error: %v", err)
		}
	}()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Logf("server shutdown: %v", err)
		}
	})

	return &testEnv{
		server:  srv,
		baseURL: "http://" + addr,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// doRequest executes an HTTP request and returns the response.
func (e *testEnv) doRequest(t *testing.T, method, path string, body any, headers map[string]string) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, e.baseURL+path, bodyReader)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	require.NoError(t, err)
	return resp
}

// doAuthRequest executes an HTTP request with Basic auth credentials in the
// format "uuid.1:password".
func (e *testEnv) doAuthRequest(t *testing.T, method, path string, body any, uuid, password string) *http.Response {
	t.Helper()
	creds := base64.StdEncoding.EncodeToString([]byte(uuid + ".1:" + password))
	return e.doRequest(t, method, path, body, map[string]string{
		"Authorization": "Basic " + creds,
	})
}

// decodeJSON decodes a JSON response body into v and closes the body.
func decodeJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	err := json.NewDecoder(resp.Body).Decode(v)
	require.NoError(t, err)
}

// testKeyMaterial holds a generated identity key pair and signed pre-key
// material for use in registration requests.
type testKeyMaterial struct {
	// identityKeyPair is the Curve25519 key pair used as the account identity key.
	identityKeyPair *ecc.ECKeyPair
	// identityKeyB64 is the base64-encoded serialized public identity key (33 bytes:
	// DJB type byte 0x05 followed by 32 key bytes).
	identityKeyB64 string
}

// generateTestKeyMaterial creates a fresh Curve25519 key pair for use as an
// account identity key in integration test registrations.
func generateTestKeyMaterial(t *testing.T) *testKeyMaterial {
	t.Helper()

	kp, err := ecc.GenerateKeyPair()
	require.NoError(t, err, "failed to generate test identity key pair")

	pub := kp.PublicKey().Serialize() // 33 bytes: 0x05 + 32 raw bytes
	return &testKeyMaterial{
		identityKeyPair: kp,
		identityKeyB64:  base64.StdEncoding.EncodeToString(pub),
	}
}

// signedPreKeyFor generates a valid Curve25519 signed pre-key entry signed
// with the given identity private key, suitable for API registration requests.
func signedPreKeyFor(t *testing.T, keyID uint64, identityKey *ecc.ECKeyPair) map[string]any {
	t.Helper()

	spkPair, err := ecc.GenerateKeyPair()
	require.NoError(t, err, "failed to generate signed pre-key pair")

	// The message being signed is the serialized public key (33 bytes).
	msg := spkPair.PublicKey().Serialize()

	sig, err := ecc.CalculateSignature(identityKey.PrivateKey(), msg)
	require.NoError(t, err, "failed to sign pre-key")

	return map[string]any{
		"keyId":     keyID,
		"publicKey": base64.StdEncoding.EncodeToString(spkPair.PublicKey().Serialize()),
		"signature": base64.StdEncoding.EncodeToString(sig[:]),
	}
}

// kemPreKeyFor generates a valid KEM pre-key entry. The KEM public key is
// random bytes; the signature covers those bytes using the identity private key.
func kemPreKeyFor(t *testing.T, keyID uint64, identityKey *ecc.ECKeyPair) map[string]any {
	t.Helper()

	// Use a Curve25519 key pair's raw 32-byte public key as a stand-in
	// KEM public key. The validation only checks that the signature over the
	// raw bytes is valid; it does not enforce a specific KEM key format.
	kemPair, err := ecc.GenerateKeyPair()
	require.NoError(t, err, "failed to generate KEM key pair")

	rawPub := kemPair.PublicKey().Serialize()[1:] // strip DJB type byte → 32 raw bytes

	sig, err := ecc.CalculateSignature(identityKey.PrivateKey(), rawPub)
	require.NoError(t, err, "failed to sign KEM pre-key")

	return map[string]any{
		"keyId":     keyID,
		"publicKey": base64.StdEncoding.EncodeToString(rawPub),
		"signature": base64.StdEncoding.EncodeToString(sig[:]),
	}
}

// testSignedPreKey returns a test signed pre-key entity. The signature is not
// valid against any identity key; use signedPreKeyFor when a real signature is
// required (e.g., in registration requests).
func testSignedPreKey(keyID uint64) map[string]any {
	kp, _ := ecc.GenerateKeyPair()
	if kp == nil {
		// Fallback to static bytes if key generation fails (should not happen).
		return map[string]any{
			"keyId":     keyID,
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 33)),
			"signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}
	}
	pub := kp.PublicKey().Serialize()
	return map[string]any{
		"keyId":     keyID,
		"publicKey": base64.StdEncoding.EncodeToString(pub),
		"signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
}

// testKEMPreKey returns a test KEM pre-key entity. The signature is not valid;
// use kemPreKeyFor when a real signature is required.
func testKEMPreKey(keyID uint64) map[string]any {
	kp, _ := ecc.GenerateKeyPair()
	if kp == nil {
		return map[string]any{
			"keyId":     keyID,
			"publicKey": base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}
	}
	rawPub := kp.PublicKey().Serialize()[1:]
	return map[string]any{
		"keyId":     keyID,
		"publicKey": base64.StdEncoding.EncodeToString(rawPub),
		"signature": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
}

// registeredAccount holds the result of a successful test account registration,
// including server-assigned identifiers and the cryptographic key material used.
// Tests that need to upload signed pre-keys after registration should use
// registerTestAccountFull so they can sign new keys with the ACI identity key.
type registeredAccount struct {
	UUID    string
	PNI     string
	ACIKeys *testKeyMaterial
	PNIKeys *testKeyMaterial
}

// registerTestAccount creates a test account via the full registration flow:
// 1. Creates a verification session for the phone number.
// 2. Requests a verification code (stub transport accepts any request).
// 3. Submits code "123456" which the stub transport auto-verifies.
// 4. Posts the registration request with the verified session ID.
//
// It returns the UUID and PNI assigned by the server.
func registerTestAccount(t *testing.T, env *testEnv, number, password string) (uuid string, pni string) {
	t.Helper()
	acct := registerTestAccountFull(t, env, number, password)
	return acct.UUID, acct.PNI
}

// registerTestAccountFull performs the same registration flow as
// registerTestAccount but returns the full registeredAccount including the
// ACI and PNI key pairs. Use this when subsequent test steps need to produce
// new signed pre-keys for the same account (e.g. PUT /v2/keys).
func registerTestAccountFull(t *testing.T, env *testEnv, number, password string) *registeredAccount {
	t.Helper()

	// Step 1: Create a verification session.
	sessionResp := env.doRequest(t, "POST", "/v1/verification/session", map[string]any{
		"number":    number,
		"transport": "sms",
	}, nil)
	require.Equal(t, http.StatusOK, sessionResp.StatusCode,
		"verification session creation failed for number %s", number)

	var session map[string]any
	decodeJSON(t, sessionResp, &session)
	sessionID, ok := session["id"].(string)
	require.True(t, ok, "verification session response missing id field")
	require.NotEmpty(t, sessionID)

	// Step 2: Request a verification code (stub transport accepts all requests).
	codeResp := env.doRequest(t, "POST", "/v1/verification/session/"+sessionID+"/code", nil, nil)
	require.Equal(t, http.StatusOK, codeResp.StatusCode, "verification code request failed")
	_ = codeResp.Body.Close()

	// Step 3: Submit the verification code. The stub transport auto-verifies "123456".
	verifyResp := env.doRequest(t, "PUT", "/v1/verification/session/"+sessionID+"/code",
		map[string]any{"code": "123456"}, nil)
	require.Equal(t, http.StatusOK, verifyResp.StatusCode, "verification code submission failed")
	_ = verifyResp.Body.Close()

	// Step 4: Generate valid cryptographic key material for the registration request.
	aciKeys := generateTestKeyMaterial(t)
	pniKeys := generateTestKeyMaterial(t)

	// Register the account with the verified session ID and valid signed pre-keys.
	regReq := map[string]any{
		"sessionId": sessionID,
		"accountAttributes": map[string]any{
			"fetchesMessages":   true,
			"registrationId":    1234,
			"pniRegistrationId": 5678,
			"name":              base64.StdEncoding.EncodeToString([]byte("Test User")),
			"capabilities":      map[string]bool{"storage": true},
		},
		"aciIdentityKey":        aciKeys.identityKeyB64,
		"pniIdentityKey":        pniKeys.identityKeyB64,
		"aciSignedPreKey":       signedPreKeyFor(t, 1, aciKeys.identityKeyPair),
		"pniSignedPreKey":       signedPreKeyFor(t, 2, pniKeys.identityKeyPair),
		"aciPqLastResortPreKey": kemPreKeyFor(t, 3, aciKeys.identityKeyPair),
		"pniPqLastResortPreKey": kemPreKeyFor(t, 4, pniKeys.identityKeyPair),
	}

	creds := base64.StdEncoding.EncodeToString([]byte(number + ":" + password))
	resp := env.doRequest(t, "POST", "/v1/registration", regReq, map[string]string{
		"Authorization": "Basic " + creds,
	})
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"registration failed for number %s", number)

	var result map[string]any
	decodeJSON(t, resp, &result)

	uuidVal, ok := result["uuid"].(string)
	require.True(t, ok, "registration response missing uuid field")
	pniVal, ok := result["pni"].(string)
	require.True(t, ok, "registration response missing pni field")

	return &registeredAccount{
		UUID:    uuidVal,
		PNI:     pniVal,
		ACIKeys: aciKeys,
		PNIKeys: pniKeys,
	}
}
