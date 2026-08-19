package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/certificates"
	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
)

// TestNewCertificateService_InterfaceSatisfaction verifies the concrete type
// satisfies the CertificateService interface at compile time.
func TestNewCertificateService_InterfaceSatisfaction(t *testing.T) {
	var _ CertificateService = (*certificateService)(nil)
}

// newTestCertificateService builds a CertificateService with a deterministic
// 32-byte signing key suitable for unit tests.
func newTestCertificateService() CertificateService {
	signingKey := secrets.MustNewSecureString("01234567890123456789012345678901")
	mgr := certificates.NewCertificatesManager(signingKey, slog.Default())
	return NewCertificateService(mgr)
}

func TestCertificateService_GetDeliveryCertificate_WithE164(t *testing.T) {
	svc := newTestCertificateService()

	cert, err := svc.GetDeliveryCertificate(
		context.Background(),
		"uuid-c01",
		"+14155550001",
		1,
		[]byte("testidentitykey"),
		true,
	)
	if err != nil {
		t.Fatalf("GetDeliveryCertificate: unexpected error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("GetDeliveryCertificate: expected non-empty certificate bytes")
	}
	if cert.CertificateExpiry == 0 {
		t.Error("GetDeliveryCertificate: expected non-zero expiry")
	}
}

func TestCertificateService_GetDeliveryCertificate_WithoutE164(t *testing.T) {
	svc := newTestCertificateService()

	cert, err := svc.GetDeliveryCertificate(
		context.Background(),
		"uuid-c02",
		"+14155550002",
		1,
		[]byte("identitykey"),
		false,
	)
	if err != nil {
		t.Fatalf("GetDeliveryCertificate: unexpected error: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Error("GetDeliveryCertificate: expected certificate bytes even without E164")
	}
}

func TestCertificateService_GetDeliveryCertificate_DifferentDevices(t *testing.T) {
	svc := newTestCertificateService()

	cert1, err := svc.GetDeliveryCertificate(context.Background(), "uuid-c03", "+14155550003", 1, []byte("ik"), true)
	if err != nil {
		t.Fatalf("GetDeliveryCertificate device 1: %v", err)
	}
	cert2, err := svc.GetDeliveryCertificate(context.Background(), "uuid-c03", "+14155550003", 2, []byte("ik"), true)
	if err != nil {
		t.Fatalf("GetDeliveryCertificate device 2: %v", err)
	}

	// Each device certificate should be unique.
	if string(cert1.Certificate) == string(cert2.Certificate) {
		t.Error("GetDeliveryCertificate: expected distinct certificates for different devices")
	}
}

func TestCertificateService_GetGroupCredentials_Success(t *testing.T) {
	svc := newTestCertificateService()

	// Use a window of exactly one day.
	startSeconds := int64(1_700_000_000)
	endSeconds := startSeconds + 86399

	creds, err := svc.GetGroupCredentials(context.Background(), "uuid-c04", "pni-c04", startSeconds, endSeconds)
	if err != nil {
		t.Fatalf("GetGroupCredentials: unexpected error: %v", err)
	}
	if len(creds.Credentials) == 0 {
		t.Error("GetGroupCredentials: expected at least one credential")
	}
	if creds.PNI != "pni-c04" {
		t.Errorf("GetGroupCredentials: PNI mismatch, got %q", creds.PNI)
	}
}

func TestCertificateService_GetGroupCredentials_MultiDay(t *testing.T) {
	svc := newTestCertificateService()

	// Use a day-aligned start and span exactly 3 whole days so we stay well
	// within the 7-day maximum while validating that multi-day ranges work.
	// 1_700_006_400 == day boundary: 1_700_006_400 / 86400 * 86400 == 1_700_006_400
	startSeconds := int64(1_700_006_400) // day-aligned (19676 * 86400)
	endSeconds := startSeconds + 3*86400 - 1

	creds, err := svc.GetGroupCredentials(context.Background(), "uuid-c05", "pni-c05", startSeconds, endSeconds)
	if err != nil {
		t.Fatalf("GetGroupCredentials: unexpected error: %v", err)
	}
	if len(creds.Credentials) < 2 {
		t.Errorf("GetGroupCredentials: expected multi-day credentials, got %d", len(creds.Credentials))
	}
}

func TestCertificateService_GetGroupCredentials_StartAfterEnd(t *testing.T) {
	svc := newTestCertificateService()

	_, err := svc.GetGroupCredentials(context.Background(), "uuid-c06", "pni-c06", 1_700_086_400, 1_700_000_000)
	if err == nil {
		t.Fatal("GetGroupCredentials: expected error when start > end")
	}
}

func TestCertificateService_GetGroupCredentials_RangeTooLarge(t *testing.T) {
	svc := newTestCertificateService()

	// Use a day-aligned start and span 8 whole days — exceeds the 7-day maximum.
	startSeconds := int64(1_700_006_400) // day-aligned
	endSeconds := startSeconds + 8*86400

	_, err := svc.GetGroupCredentials(context.Background(), "uuid-c07", "pni-c07", startSeconds, endSeconds)
	if err == nil {
		t.Fatal("GetGroupCredentials: expected error for range exceeding 7 days")
	}
}

// TestNewCertificateService_Roundtrip verifies NewCertificateService returns
// a usable implementation without panicking.
func TestNewCertificateService_Roundtrip(t *testing.T) {
	signingKey := secrets.MustNewSecureString("abcdefghijklmnopqrstuvwxyz012345")
	mgr := certificates.NewCertificatesManager(signingKey, slog.Default())
	svc := NewCertificateService(mgr)

	if svc == nil {
		t.Fatal("NewCertificateService: returned nil")
	}
}
