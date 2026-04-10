package certificates

import (
	"encoding/json"
	"testing"
)

func TestDeliveryCertificate_JSONRoundTrip(t *testing.T) {
	cert := DeliveryCertificate{
		Certificate:       []byte("test-cert-data"),
		CertificateExpiry: 1700000000000,
	}

	data, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded DeliveryCertificate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if string(decoded.Certificate) != string(cert.Certificate) {
		t.Errorf("Certificate mismatch: got %q, want %q", decoded.Certificate, cert.Certificate)
	}
	if decoded.CertificateExpiry != cert.CertificateExpiry {
		t.Errorf("CertificateExpiry = %d, want %d", decoded.CertificateExpiry, cert.CertificateExpiry)
	}
}

func TestDeliveryCertificate_EmptyFields(t *testing.T) {
	cert := DeliveryCertificate{}

	if cert.Certificate != nil {
		t.Errorf("expected nil Certificate, got %v", cert.Certificate)
	}
	if cert.CertificateExpiry != 0 {
		t.Errorf("expected zero CertificateExpiry, got %d", cert.CertificateExpiry)
	}
}

func TestSenderCertificate_JSONRoundTrip(t *testing.T) {
	sc := SenderCertificate{
		SenderUUID:     "test-uuid",
		SenderE164:     "+15551234567",
		SenderDeviceID: 2,
		Expiration:     1700000000000,
		IdentityKey:    []byte{1, 2, 3, 4},
		Signer:         []byte{5, 6, 7, 8},
	}

	data, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded SenderCertificate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.SenderUUID != sc.SenderUUID {
		t.Errorf("SenderUUID = %q, want %q", decoded.SenderUUID, sc.SenderUUID)
	}
	if decoded.SenderE164 != sc.SenderE164 {
		t.Errorf("SenderE164 = %q, want %q", decoded.SenderE164, sc.SenderE164)
	}
	if decoded.SenderDeviceID != sc.SenderDeviceID {
		t.Errorf("SenderDeviceID = %d, want %d", decoded.SenderDeviceID, sc.SenderDeviceID)
	}
}

func TestSenderCertificate_OmitEmptyE164(t *testing.T) {
	sc := SenderCertificate{
		SenderUUID:     "uuid-1",
		SenderDeviceID: 1,
		Expiration:     123456789,
		IdentityKey:    []byte{1},
		Signer:         []byte{2},
	}

	data, err := json.Marshal(sc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if _, exists := raw["senderE164"]; exists {
		t.Errorf("expected senderE164 to be omitted when empty")
	}
}

func TestGroupCredentials_JSONRoundTrip(t *testing.T) {
	gc := GroupCredentials{
		Credentials: []GroupCredential{
			{Credential: []byte{10, 20}, RedemptionTime: 100},
			{Credential: []byte{30, 40}, RedemptionTime: 200},
		},
		PNI: "pni-value",
	}

	data, err := json.Marshal(gc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded GroupCredentials
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.PNI != gc.PNI {
		t.Errorf("PNI = %q, want %q", decoded.PNI, gc.PNI)
	}
	if len(decoded.Credentials) != 2 {
		t.Fatalf("Credentials length = %d, want 2", len(decoded.Credentials))
	}
	if decoded.Credentials[0].RedemptionTime != 100 {
		t.Errorf("RedemptionTime[0] = %d, want 100", decoded.Credentials[0].RedemptionTime)
	}
}

func TestGroupCredentials_EmptyCredentials(t *testing.T) {
	gc := GroupCredentials{PNI: "pni-1"}
	if gc.Credentials != nil {
		t.Errorf("expected nil Credentials, got %v", gc.Credentials)
	}
}

func TestGroupCredential_JSONRoundTrip(t *testing.T) {
	gc := GroupCredential{
		Credential:     []byte{0xAA, 0xBB},
		RedemptionTime: 86400,
	}

	data, err := json.Marshal(gc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded GroupCredential
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.RedemptionTime != gc.RedemptionTime {
		t.Errorf("RedemptionTime = %d, want %d", decoded.RedemptionTime, gc.RedemptionTime)
	}
}

func TestGroupCredential_ZeroValues(t *testing.T) {
	gc := GroupCredential{}
	if gc.Credential != nil {
		t.Errorf("expected nil Credential, got %v", gc.Credential)
	}
	if gc.RedemptionTime != 0 {
		t.Errorf("expected zero RedemptionTime, got %d", gc.RedemptionTime)
	}
}

func TestCallLinkAuthCredential_JSONRoundTrip(t *testing.T) {
	cred := CallLinkAuthCredential{
		Credential:     []byte{0x01, 0x02, 0x03},
		RedemptionTime: 86400,
	}

	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded CallLinkAuthCredential
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.RedemptionTime != cred.RedemptionTime {
		t.Errorf("RedemptionTime = %d, want %d", decoded.RedemptionTime, cred.RedemptionTime)
	}
	if len(decoded.Credential) != len(cred.Credential) {
		t.Errorf("Credential length = %d, want %d", len(decoded.Credential), len(cred.Credential))
	}
}

func TestCallLinkAuthCredential_ZeroValues(t *testing.T) {
	cred := CallLinkAuthCredential{}
	if cred.Credential != nil {
		t.Errorf("expected nil Credential, got %v", cred.Credential)
	}
	if cred.RedemptionTime != 0 {
		t.Errorf("expected zero RedemptionTime, got %d", cred.RedemptionTime)
	}
}

func TestGroupCredentials_WithCallLinkAuthCredentials(t *testing.T) {
	gc := GroupCredentials{
		Credentials: []GroupCredential{
			{Credential: []byte{1}, RedemptionTime: 100},
		},
		CallLinkAuthCredentials: []CallLinkAuthCredential{
			{Credential: []byte{2}, RedemptionTime: 200},
		},
		PNI: "pni-val",
	}

	data, err := json.Marshal(gc)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded GroupCredentials
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(decoded.CallLinkAuthCredentials) != 1 {
		t.Fatalf("CallLinkAuthCredentials length = %d, want 1", len(decoded.CallLinkAuthCredentials))
	}
	if decoded.CallLinkAuthCredentials[0].RedemptionTime != 200 {
		t.Errorf("RedemptionTime = %d, want 200", decoded.CallLinkAuthCredentials[0].RedemptionTime)
	}
}
