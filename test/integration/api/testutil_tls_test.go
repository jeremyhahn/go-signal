//go:build integration

package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// shippedServerCert parses the certificate the devcontainer stack serves.
func shippedServerCert(t *testing.T) *x509.Certificate {
	t.Helper()

	serverPEM, err := os.ReadFile("../../tls/server-cert.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(serverPEM)
	require.NotNil(t, block, "server certificate is not PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

// TestRemoteTLSConfig_VerifiesTheDevcontainerCertificate proves the harness can
// authenticate the server it talks to, rather than accepting whatever
// certificate arrives.
//
// The remote path only runs when SIGNAL_SERVER_URL is set, so a wrong CA path
// or an unusable pool would otherwise surface for the first time inside the
// devcontainer — as a connection failure with no obvious cause. This runs
// everywhere and needs no server.
//
// It is skipped when SIGNAL_CA_CERT is set. That override exists so the suite
// can be pointed at another environment, whose CA has no reason to have issued
// the certificate shipped in this repository; asserting the shipped one
// regardless would break the very path the override is for.
func TestRemoteTLSConfig_VerifiesTheDevcontainerCertificate(t *testing.T) {
	if path := os.Getenv("SIGNAL_CA_CERT"); path != "" {
		t.Skipf("SIGNAL_CA_CERT=%s selects another environment's CA; the shipped certificate is not expected to chain to it", path)
	}

	cfg := remoteTLSConfig(t)
	require.NotNil(t, cfg.RootCAs, "no CA pool: the harness would have nothing to verify against")
	require.False(t, cfg.InsecureSkipVerify, "TLS verification is disabled")

	cert := shippedServerCert(t)
	// Both names the compose file and the local default point at.
	for _, host := range []string{"signal-server", "localhost"} {
		_, err := cert.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: host})
		require.NoErrorf(t, err, "the harness could not verify the server certificate for %s", host)
	}
}

// TestRemoteTLSConfig_HonoursTheCACertOverride covers the path the test above
// steps out of the way for: an external environment supplying its own CA.
//
// A generated CA rather than a fixture, because the assertion is that the
// configured pool trusts what SIGNAL_CA_CERT points at — which is only
// meaningful if that CA has nothing to do with this repository.
func TestRemoteTLSConfig_HonoursTheCACertOverride(t *testing.T) {
	const host = "override.example"
	caPEM, leaf := newTestCAAndLeaf(t, host)

	path := filepath.Join(t.TempDir(), "override-ca.pem")
	require.NoError(t, os.WriteFile(path, caPEM, 0o600))
	t.Setenv("SIGNAL_CA_CERT", path)

	cfg := remoteTLSConfig(t)
	require.NotNil(t, cfg.RootCAs)

	_, err := leaf.Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: host})
	require.NoError(t, err, "SIGNAL_CA_CERT was ignored: the pool does not trust the supplied CA")

	// The override must REPLACE the default, not sit alongside it. A pool that
	// also trusted the shipped CA would pass the assertion above while quietly
	// trusting more than the operator asked for.
	_, err = shippedServerCert(t).Verify(x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: "signal-server"})
	require.Error(t, err, "the pool still trusts the repository CA despite the override")
}

// newTestCAAndLeaf mints a throwaway CA and a server certificate it issued.
// Nothing here is written outside the test's own temporary directory, and the
// key material lives only for the test.
func newTestCAAndLeaf(t *testing.T, dnsName string) (caPEM []byte, leaf *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Override Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), leaf
}
