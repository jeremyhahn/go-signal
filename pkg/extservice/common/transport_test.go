package common

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestTLSConfig_InsecureDoesNotRequireCertMaterial(t *testing.T) {
	c := TLSConfig{Insecure: true}
	tr, err := c.HTTPTransport()
	if err != nil {
		t.Fatalf("HTTPTransport: %v", err)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true on insecure transport")
	}
	_, err = c.GRPCDialOption()
	if err != nil {
		t.Errorf("GRPCDialOption insecure: %v", err)
	}
}

func TestTLSConfig_MinVersionDefaultsToTLS12(t *testing.T) {
	c := TLSConfig{}
	cfg, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
}

func TestTLSConfig_RejectsMissingMTLSHalf(t *testing.T) {
	if _, err := (TLSConfig{ClientCertFile: "cert.pem"}).buildTLSConfig(); err == nil {
		t.Error("missing key should error")
	}
	if _, err := (TLSConfig{ClientKeyFile: "key.pem"}).buildTLSConfig(); err == nil {
		t.Error("missing cert should error")
	}
}

func TestTLSConfig_RejectsBadCABundle(t *testing.T) {
	dir := t.TempDir()
	ca := writeFile(t, dir, "ca.pem", []byte("not-a-real-pem"))
	if _, err := (TLSConfig{CAFile: ca}).buildTLSConfig(); err == nil {
		t.Error("invalid CA PEM should error")
	}
}

func TestDefaultDeadlines(t *testing.T) {
	connect, rpc := DefaultDeadlines()
	if connect == 0 || rpc == 0 {
		t.Error("default deadlines must be non-zero")
	}
	if rpc <= connect {
		t.Errorf("rpc deadline (%v) should be > connect deadline (%v)", rpc, connect)
	}
}

func TestTLSConfig_SecurePath_HTTPTransport(t *testing.T) {
	// No certs, no CA → builds a valid TLS 1.2 transport with system roots.
	c := TLSConfig{}
	tr, err := c.HTTPTransport()
	if err != nil {
		t.Fatalf("HTTPTransport secure: %v", err)
	}
	if tr == nil {
		t.Fatal("transport is nil")
	}
	if tr.TLSClientConfig == nil {
		t.Error("TLSClientConfig should be set")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false on secure transport")
	}
}

func TestTLSConfig_SecurePath_GRPCDialOption(t *testing.T) {
	c := TLSConfig{}
	opt, err := c.GRPCDialOption()
	if err != nil {
		t.Fatalf("GRPCDialOption secure: %v", err)
	}
	if opt == nil {
		t.Error("DialOption should not be nil")
	}
}

func TestTLSConfig_MinVersionExplicit(t *testing.T) {
	c := TLSConfig{MinVersion: tls.VersionTLS13}
	cfg, err := c.buildTLSConfig()
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want TLS 1.3", cfg.MinVersion)
	}
}
