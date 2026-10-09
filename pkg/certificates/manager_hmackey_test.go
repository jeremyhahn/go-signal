package certificates

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

func newHMACManager(t *testing.T, key *secrets.SecureString) *CertificatesManager {
	t.Helper()
	m := NewCertificatesManager(key, slog.New(slog.DiscardHandler))
	t.Cleanup(m.Destroy)
	return m
}

// hmacKeyRefusals are the ways opening the legacy HMAC key can fail. Each must
// reach the caller as an error: a refused open used to yield a nil key, and
// HMAC-SHA256 under a nil key is a valid-looking credential anyone can
// recompute.
func hmacKeyRefusals(t *testing.T) map[string]struct {
	manager *CertificatesManager
	ctx     context.Context
} {
	t.Helper()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	return map[string]struct {
		manager *CertificatesManager
		ctx     context.Context
	}{
		"canceled context": {newHMACManager(t, secrets.MustNewSecureString(t.Context(), "hmac-key")), canceled},
		"no key":           {newHMACManager(t, nil), t.Context()},
	}
}

func TestGetDeliveryCertificate_HMACKeyOpenFailureIsAnError(t *testing.T) {
	for name, tc := range hmacKeyRefusals(t) {
		t.Run(name, func(t *testing.T) {
			got, err := tc.manager.GetDeliveryCertificate(tc.ctx, "uuid", "+15550100", 1, []byte("ik"), true)
			var keyErr *HMACKeyError
			if !errors.As(err, &keyErr) {
				t.Fatalf("err = %T (%v), want it to wrap *HMACKeyError", err, err)
			}
			if got != nil {
				t.Error("a certificate was issued despite the failure")
			}
		})
	}
}

func TestGetGroupCredentials_HMACKeyOpenFailureIsAnError(t *testing.T) {
	for name, tc := range hmacKeyRefusals(t) {
		t.Run(name, func(t *testing.T) {
			got, err := tc.manager.GetGroupCredentials(tc.ctx, "uuid", "pni", 0, 0)
			var keyErr *HMACKeyError
			if !errors.As(err, &keyErr) {
				t.Fatalf("err = %T (%v), want it to wrap *HMACKeyError", err, err)
			}
			if got != nil {
				t.Error("credentials were issued despite the failure")
			}
		})
	}
}

func TestGetExpiringProfileKeyCredentialStub_HMACKeyOpenFailureIsAnError(t *testing.T) {
	for name, tc := range hmacKeyRefusals(t) {
		t.Run(name, func(t *testing.T) {
			got, err := tc.manager.GetExpiringProfileKeyCredentialStub(tc.ctx, "aci", zkgroup.Timestamp{})
			var keyErr *HMACKeyError
			if !errors.As(err, &keyErr) {
				t.Fatalf("err = %T (%v), want it to wrap *HMACKeyError", err, err)
			}
			if got != nil {
				t.Error("a credential was issued despite the failure")
			}
		})
	}
}
