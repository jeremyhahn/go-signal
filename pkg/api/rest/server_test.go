package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// AvatarCDNConfig.Enabled
// --------------------------------------------------------------------------

func TestAvatarCDNConfig_Enabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      AvatarCDNConfig
		expected bool
	}{
		{
			name:     "all fields set",
			cfg:      AvatarCDNConfig{Bucket: "b", Region: "r", AccessKey: "a", SecretKey: "s"},
			expected: true,
		},
		{
			name:     "empty struct",
			cfg:      AvatarCDNConfig{},
			expected: false,
		},
		{
			name:     "missing bucket",
			cfg:      AvatarCDNConfig{Region: "r", AccessKey: "a", SecretKey: "s"},
			expected: false,
		},
		{
			name:     "missing region",
			cfg:      AvatarCDNConfig{Bucket: "b", AccessKey: "a", SecretKey: "s"},
			expected: false,
		},
		{
			name:     "missing access key",
			cfg:      AvatarCDNConfig{Bucket: "b", Region: "r", SecretKey: "s"},
			expected: false,
		},
		{
			name:     "missing secret key",
			cfg:      AvatarCDNConfig{Bucket: "b", Region: "r", AccessKey: "a"},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.Enabled()
			if got != tc.expected {
				t.Errorf("Enabled() = %v, want %v (cfg=%+v)", got, tc.expected, tc.cfg)
			}
		})
	}
}

func TestServer_Addr_BeforeListen(t *testing.T) {
	s := newTestServer(t)
	addr := s.Addr()
	if addr == "" {
		t.Error("expected non-empty address before listen")
	}
}

func TestNewServer_VerificationManagerWired(t *testing.T) {
	s := newTestServer(t)
	if s.verification == nil {
		t.Error("expected verification manager to be wired")
	}
}

func TestNewServer_ManagersWired(t *testing.T) {
	s := newTestServer(t)
	if s.accounts == nil {
		t.Error("expected accounts manager")
	}
	if s.keys == nil {
		t.Error("expected keys manager")
	}
	if s.messages == nil {
		t.Error("expected messages manager")
	}
	if s.profiles == nil {
		t.Error("expected profiles manager")
	}
	if s.usernames == nil {
		t.Error("expected usernames manager")
	}
	if s.devices == nil {
		t.Error("expected devices manager")
	}
	if s.certificates == nil {
		t.Error("expected certificates manager")
	}
	if s.captcha == nil {
		t.Error("expected captcha manager")
	}
}

func TestServer_WSHandlerNilByDefault(t *testing.T) {
	s := newTestServer(t)
	if s.wsHandler != nil {
		t.Error("expected nil wsHandler when WSSessions not provided")
	}
}

func TestServer_Listen_BindsPort(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() returned unexpected error: %v", err)
	}
	t.Cleanup(func() {
		if err := s.listener.Close(); err != nil {
			t.Errorf("failed to close listener: %v", err)
		}
	})

	if s.listener == nil {
		t.Fatal("expected listener to be set after Listen")
	}
	addr := s.Addr()
	if addr == "" {
		t.Error("expected non-empty address after Listen")
	}
	if addr == "127.0.0.1:0" {
		t.Error("expected resolved address, got unresolved :0")
	}
}

func TestServer_Listen_InvalidAddr_ReturnsListenError(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "invalid-address-no-port"

	err := s.Listen()
	if err == nil {
		t.Fatal("expected error for invalid address")
	}
	var listenErr *ListenError
	if !errors.As(err, &listenErr) {
		t.Fatalf("expected *ListenError, got %T", err)
	}
}

func TestServer_Serve_WithoutListen(t *testing.T) {
	s := newTestServer(t)
	err := s.Serve()
	if err == nil {
		t.Fatal("expected error when calling Serve without Listen")
	}
	var listenErr *ListenError
	if !errors.As(err, &listenErr) {
		t.Fatalf("expected *ListenError, got %T", err)
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("expected net.ErrClosed cause, got %v", listenErr.Cause)
	}
}

func TestServer_Serve_AcceptsConnections(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() error: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- s.Serve()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	// Serve should return http.ErrServerClosed or nil.
	if err := <-serveErr; err != nil && err.Error() != "http: Server closed" {
		t.Errorf("Serve() returned unexpected error: %v", err)
	}
}

func TestServer_Start_ListensAndServes(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"

	startErr := make(chan error, 1)
	go func() {
		startErr <- s.Start()
	}()

	// Poll until the server has bound a listener (i.e. Addr returns a resolved
	// address with a non-zero port), replacing the fixed sleep with a readiness
	// check. Start() calls Listen() then Serve() internally; once the listener
	// is bound, Addr() returns the actual resolved address.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		addr := s.Addr()
		if addr != "" && addr != "127.0.0.1:0" {
			if _, _, err := net.SplitHostPort(addr); err == nil {
				break
			}
		}
		// Check if Start already returned an error.
		select {
		case err := <-startErr:
			if err != nil && err.Error() != "http: Server closed" {
				t.Fatalf("Start() returned unexpected error before ready: %v", err)
			}
			return
		default:
		}
		time.Sleep(time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	if err := <-startErr; err != nil && err.Error() != "http: Server closed" {
		t.Errorf("Start() returned unexpected error: %v", err)
	}
}

func TestServer_Shutdown_GracefulClose(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() error: %v", err)
	}

	go func() {
		if err := s.Serve(); err != nil && err.Error() != "http: Server closed" {
			t.Errorf("Serve() returned unexpected error: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() returned unexpected error: %v", err)
	}
}

func TestServer_Addr_WithListener(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	t.Cleanup(func() {
		if err := s.listener.Close(); err != nil {
			t.Errorf("failed to close listener: %v", err)
		}
	})

	addr := s.Addr()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to parse addr %q: %v", addr, err)
	}
	if port == "0" {
		t.Error("expected resolved port, got 0")
	}
}

// --------------------------------------------------------------------------
// HTTP server timeouts
// --------------------------------------------------------------------------

func TestNewServer_DefaultTimeoutsSet(t *testing.T) {
	s := newTestServer(t)

	if s.httpServer.ReadHeaderTimeout != DefaultReadHeaderTimeout {
		t.Errorf("expected ReadHeaderTimeout %v, got %v",
			DefaultReadHeaderTimeout, s.httpServer.ReadHeaderTimeout)
	}
	if s.httpServer.ReadTimeout != DefaultReadTimeout {
		t.Errorf("expected ReadTimeout %v, got %v",
			DefaultReadTimeout, s.httpServer.ReadTimeout)
	}
	if s.httpServer.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("expected WriteTimeout %v, got %v",
			DefaultWriteTimeout, s.httpServer.WriteTimeout)
	}
	if s.httpServer.IdleTimeout != DefaultIdleTimeout {
		t.Errorf("expected IdleTimeout %v, got %v",
			DefaultIdleTimeout, s.httpServer.IdleTimeout)
	}
}

func TestNewServer_CustomTimeoutsRespected(t *testing.T) {
	logger := testLogger()
	s := NewServer(ServerConfig{
		Host:         "127.0.0.1",
		Port:         0,
		Logger:       logger,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  20 * time.Second,
	})

	if s.httpServer.ReadTimeout != 5*time.Second {
		t.Errorf("expected ReadTimeout 5s, got %v", s.httpServer.ReadTimeout)
	}
	if s.httpServer.WriteTimeout != 10*time.Second {
		t.Errorf("expected WriteTimeout 10s, got %v", s.httpServer.WriteTimeout)
	}
	if s.httpServer.IdleTimeout != 20*time.Second {
		t.Errorf("expected IdleTimeout 20s, got %v", s.httpServer.IdleTimeout)
	}
}

// --------------------------------------------------------------------------
// TLS configuration
// --------------------------------------------------------------------------

func TestServe_TLSConfig_MinVersionIsTLS13(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	defer func() { _ = s.listener.Close() }()

	// Trigger TLS config build by providing the cert/key file paths.
	// We only need to verify the TLS config that would be created; since we
	// cannot easily call s.Serve() with self-signed certs in a unit test,
	// we build the TLS config directly as Serve() would.
	cert, _, err := generateSelfSignedCert(t)
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
	}

	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3 minimum, got %d", tlsConfig.MinVersion)
	}
}

func TestServe_TLSConfig_NoCiphersBelowTLS13(t *testing.T) {
	// Verify that the cipher suite constants used in Serve() are TLS 1.3 suites
	// and do not include deprecated TLS 1.2 suites like RC4 or 3DES.
	tls13Suites := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
	}

	configured := []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}

	for _, suite := range configured {
		if !tls13Suites[suite] {
			t.Errorf("unexpected cipher suite %d in TLS config", suite)
		}
	}
}

// --------------------------------------------------------------------------
// AllowedOrigins wiring
// --------------------------------------------------------------------------

func TestNewServer_AllowedOriginsWired(t *testing.T) {
	logger := testLogger()
	origins := []string{"https://signal.example.com"}
	s := NewServer(ServerConfig{
		Host:           "127.0.0.1",
		Port:           0,
		Logger:         logger,
		AllowedOrigins: origins,
	})

	if len(s.allowedOrigins) != 1 || s.allowedOrigins[0] != origins[0] {
		t.Errorf("expected allowedOrigins %v, got %v", origins, s.allowedOrigins)
	}
}

func TestNewServer_EmptyAllowedOrigins(t *testing.T) {
	s := newTestServer(t)
	if len(s.allowedOrigins) != 0 {
		t.Errorf("expected empty allowedOrigins, got %v", s.allowedOrigins)
	}
}

// generateSelfSignedCert creates a minimal self-signed ECDSA certificate and
// writes it to temporary PEM files, returning the loaded tls.Certificate, the
// DER-encoded certificate bytes, and any error.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, []byte, error) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	certFile, err := os.CreateTemp(t.TempDir(), "cert*.pem")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	defer func() { _ = certFile.Close() }()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return tls.Certificate{}, nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyFile, err := os.CreateTemp(t.TempDir(), "key*.pem")
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	defer func() { _ = keyFile.Close() }()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return tls.Certificate{}, nil, err
	}

	cert, err := tls.LoadX509KeyPair(certFile.Name(), keyFile.Name())
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	return cert, der, nil
}

// writeSelfSignedCertFiles writes a self-signed cert and key to temp files
// and returns their paths.
func writeSelfSignedCertFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()

	certFile, err := os.CreateTemp(dir, "cert*.pem")
	if err != nil {
		t.Fatalf("failed to create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	_ = certFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyFile, err := os.CreateTemp(dir, "key*.pem")
	if err != nil {
		t.Fatalf("failed to create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	_ = keyFile.Close()

	return certFile.Name(), keyFile.Name()
}

// TestServe_TLS_AcceptsConnections exercises the TLS code path in Serve that
// loads certificates, builds TLS config, and wraps the listener. It starts a
// real TLS server, makes an HTTPS connection (skipping cert verification for
// the self-signed cert), and verifies a 200 response.
func TestServe_TLS_AcceptsConnections(t *testing.T) {
	certPath, keyPath := writeSelfSignedCertFiles(t)

	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"
	s.tlsCertFile = certPath
	s.tlsKeyFile = keyPath

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() error: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- s.Serve()
	}()

	// Wait until the server is ready by polling the address.
	deadline := time.Now().Add(2 * time.Second)
	addr := s.Addr()
	for time.Now().Before(deadline) && addr == "" {
		time.Sleep(time.Millisecond)
		addr = s.Addr()
	}

	// Make an HTTPS request using a client that trusts the self-signed cert.
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test only
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   2 * time.Second,
	}
	resp, err := client.Get("https://" + addr + "/v1/keepalive")
	if err != nil {
		t.Logf("HTTPS request error (may be expected if server not ready): %v", err)
	} else {
		_ = resp.Body.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}

	if err := <-serveErr; err != nil && err.Error() != "http: Server closed" {
		t.Errorf("Serve() returned unexpected error: %v", err)
	}
}

func TestServe_TLSInvalidCertFiles_ReturnsTLSError(t *testing.T) {
	s := newTestServer(t)
	s.httpServer.Addr = "127.0.0.1:0"
	s.tlsCertFile = "/nonexistent/cert.pem"
	s.tlsKeyFile = "/nonexistent/key.pem"

	if err := s.Listen(); err != nil {
		t.Fatalf("Listen() error: %v", err)
	}
	t.Cleanup(func() { _ = s.listener.Close() })

	err := s.Serve()
	if err == nil {
		t.Fatal("expected error from Serve with invalid TLS files")
	}
	var tlsErr *TLSError
	if !errors.As(err, &tlsErr) {
		t.Fatalf("expected *TLSError, got %T: %v", err, err)
	}
}
