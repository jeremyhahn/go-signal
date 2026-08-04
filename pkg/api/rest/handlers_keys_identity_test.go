package rest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// testAccountPNI is the bare PNI UUID used by identity-aware tests. The
// project's invariant is that Account.PNI is stored bare; the "PNI:" prefix
// is added only at wire boundaries via accounts.ServiceIdentifierString.
const testAccountPNI = "22222222-2222-4222-8222-222222222222"

// seedAccountWithBothIdentities pre-populates a test account whose ACI and
// PNI both have valid identity keys, distinct registration IDs, and a real
// ACI signed pre-key. Returns the live account so callers can drive
// identity-routed handlers.
func seedAccountWithBothIdentities(t *testing.T) (*Server, *accounts.Account, *signalKeyMaterial) {
	t.Helper()
	s, _, km := newTestServerWithRealKeys(t)

	acct, err := s.accounts.Get(context.Background(), testAccountUUID)
	if err != nil {
		t.Fatalf("get seeded account: %v", err)
	}
	acct.PNI = testAccountPNI
	acct.Devices[0].PhoneNumberIdentityRegistrationID = 99999
	if err := s.accounts.Update(context.Background(), acct); err != nil {
		t.Fatalf("update seeded account: %v", err)
	}
	return s, acct, km
}

func TestParseServiceIdentifier_AcceptsAllForms(t *testing.T) {
	cases := []struct {
		in   string
		want accounts.IdentityType
	}{
		{"11111111-1111-4111-8111-111111111111", accounts.IdentityTypeACI},
		{"ACI:11111111-1111-4111-8111-111111111111", accounts.IdentityTypeACI},
		{"PNI:22222222-2222-4222-8222-222222222222", accounts.IdentityTypePNI},
		{"+15555550100", accounts.IdentityTypeACI},
	}
	for _, c := range cases {
		got, _, err := parseServiceIdentifier(c.in)
		if err != nil {
			t.Errorf("parseServiceIdentifier(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseServiceIdentifier(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestParseServiceIdentifier_RejectsGarbage(t *testing.T) {
	cases := []string{
		"not-a-uuid",
		"ACI:not-a-uuid",
		"PNI:not-a-uuid",
		"WHATEVER:11111111-1111-4111-8111-111111111111",
	}
	for _, in := range cases {
		if _, _, err := parseServiceIdentifier(in); err == nil {
			t.Errorf("parseServiceIdentifier(%q): expected error", in)
		}
	}
}

func TestParseIdentityQueryParam(t *testing.T) {
	cases := []struct {
		raw     string
		want    accounts.IdentityType
		wantErr bool
	}{
		{"", accounts.IdentityTypeACI, false},
		{"aci", accounts.IdentityTypeACI, false},
		{"ACI", accounts.IdentityTypeACI, false},
		{"pni", accounts.IdentityTypePNI, false},
		{"PNI", accounts.IdentityTypePNI, false},
		{"bogus", 0, true},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/v2/keys?identity="+c.raw, nil)
		got, err := parseIdentityQueryParam(req)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseIdentityQueryParam(%q): expected error", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseIdentityQueryParam(%q): %v", c.raw, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseIdentityQueryParam(%q) = %v; want %v", c.raw, got, c.want)
		}
	}
}

func TestIdentityKeyForType_ReturnsCorrectField(t *testing.T) {
	acct := &accounts.Account{
		IdentityKey:            []byte("aci-id"),
		PhoneNumberIdentityKey: []byte("pni-id"),
	}
	if got := identityKeyForType(acct, accounts.IdentityTypeACI); string(got) != "aci-id" {
		t.Errorf("ACI: got %q", got)
	}
	if got := identityKeyForType(acct, accounts.IdentityTypePNI); string(got) != "pni-id" {
		t.Errorf("PNI: got %q", got)
	}
	if got := identityKeyForType(nil, accounts.IdentityTypeACI); got != nil {
		t.Errorf("nil account: got %v", got)
	}
}

// TestGetPreKeyCount_IdentityRoutesToDifferentNamespaces verifies that
// counts queried for ACI and PNI come from independent storage namespaces.
func TestGetPreKeyCount_IdentityRoutesToDifferentNamespaces(t *testing.T) {
	s, acct, _ := seedAccountWithBothIdentities(t)
	ctx := context.Background()

	// Upload 5 KEM keys against ACI directly via the manager (bypassing the
	// signature check, which is exercised elsewhere). The PNI namespace
	// receives zero keys.
	if err := s.keys.StoreKEMPreKeysForIdentity(ctx, acct, accounts.IdentityTypeACI,
		accounts.PrimaryDeviceID, makeSyntheticKEMKeys(5)); err != nil {
		t.Fatalf("StoreKEMPreKeysForIdentity ACI: %v", err)
	}

	aciResp := doGetPreKeyCount(t, s, "aci")
	pniResp := doGetPreKeyCount(t, s, "pni")

	if aciResp.PqCount != 5 {
		t.Errorf("ACI PqCount = %d; want 5", aciResp.PqCount)
	}
	if pniResp.PqCount != 0 {
		t.Errorf("PNI PqCount = %d; want 0 (no PNI keys uploaded)", pniResp.PqCount)
	}
}

// TestUploadKeys_IdentityRoutesToPNI proves that an upload with
// ?identity=pni lands in the PNI namespace and does NOT overwrite ACI.
func TestUploadKeys_IdentityRoutesToPNI(t *testing.T) {
	s, acct, km := seedAccountWithBothIdentities(t)
	ctx := context.Background()

	body := makePNISignedPreKeyUploadBody(km)

	req := httptest.NewRequest(http.MethodPut, "/v2/keys?identity=pni", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT /v2/keys?identity=pni: expected 204, got %d: %s", rr.Code, rr.Body.String())
	}

	pniSPK, err := s.keys.GetSignedPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID)
	if err != nil {
		t.Fatalf("PNI signed pre-key: %v", err)
	}
	if pniSPK.KeyID != 200 {
		t.Errorf("PNI signed pre-key keyId = %d; want 200", pniSPK.KeyID)
	}

	aciSPK, err := s.keys.GetSignedPreKeyForIdentity(ctx, acct, accounts.IdentityTypeACI, accounts.PrimaryDeviceID)
	if err != nil {
		t.Fatalf("ACI signed pre-key: %v", err)
	}
	if aciSPK.KeyID != 1 {
		t.Errorf("ACI signed pre-key keyId = %d; want 1 (seeded value should not have been overwritten)", aciSPK.KeyID)
	}
}

// TestGetPreKeyBundle_RoutesByServiceIdentifier verifies a PNI:<uuid> bundle
// GET returns the PNI identity key and the PNI registrationId, NOT ACI.
func TestGetPreKeyBundle_RoutesByServiceIdentifier(t *testing.T) {
	s, acct, km := seedAccountWithBothIdentities(t)
	ctx := context.Background()

	// Seed a PNI signed pre-key so the bundle GET succeeds.
	if err := s.keys.StoreSignedPreKeyForIdentity(ctx, acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID,
		&keys.SignedPreKey{KeyID: 7, PublicKey: km.PNISignedPreKeyPub, Signature: km.PNISignedPreKeySig}); err != nil {
		t.Fatalf("seed PNI signed pre-key: %v", err)
	}

	url := "/v2/keys/PNI:" + acct.PNI + "/" + fmt.Sprint(accounts.PrimaryDeviceID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d: %s", url, rr.Code, rr.Body.String())
	}

	var resp PreKeyResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wantIdentity := base64.StdEncoding.EncodeToString(km.PNIIdentityKey)
	if resp.IdentityKey != wantIdentity {
		t.Errorf("identityKey: got %q; want PNI identity key", resp.IdentityKey)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("expected 1 device entry, got %d", len(resp.Devices))
	}
	if resp.Devices[0].RegistrationId != 99999 {
		t.Errorf("registrationId = %d; want 99999 (PNI registrationId)", resp.Devices[0].RegistrationId)
	}
}

// TestGetPreKeyBundle_BareUUID_DefaultsToACI ensures legacy clients that
// don't send the "ACI:" prefix continue to get the ACI bundle.
func TestGetPreKeyBundle_BareUUID_DefaultsToACI(t *testing.T) {
	s, acct, km := seedAccountWithBothIdentities(t)

	url := "/v2/keys/" + acct.UUID + "/" + fmt.Sprint(accounts.PrimaryDeviceID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: expected 200, got %d: %s", url, rr.Code, rr.Body.String())
	}

	var resp PreKeyResponseEntity
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.IdentityKey != base64.StdEncoding.EncodeToString(km.ACIIdentityKey) {
		t.Errorf("bare UUID should default to ACI identity key")
	}
}

func TestGetPreKeyBundle_InvalidServiceIdentifier(t *testing.T) {
	s, _, _ := seedAccountWithBothIdentities(t)

	url := "/v2/keys/WHATEVER:not-a-uuid/" + fmt.Sprint(accounts.PrimaryDeviceID)
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid identifier, got %d", rr.Code)
	}
}

// --- helpers --------------------------------------------------------------

// doGetPreKeyCount issues a GET /v2/keys?identity=<v> request as the seeded
// test account and returns the parsed PreKeyCountResponse.
func doGetPreKeyCount(t *testing.T, s *Server, identity string) PreKeyCountResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v2/keys?identity="+identity, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v2/keys?identity=%s: %d: %s", identity, rr.Code, rr.Body.String())
	}
	var out PreKeyCountResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// makeSyntheticKEMKeys returns n KEMSignedPreKey values with predictable IDs.
// Signatures and public keys are NOT real — only safe with store-side helpers
// that skip ValidateAllSignedKeys (e.g. StoreKEMPreKeysForIdentity).
func makeSyntheticKEMKeys(n int) []*keys.KEMSignedPreKey {
	out := make([]*keys.KEMSignedPreKey, n)
	for i := range out {
		out[i] = &keys.KEMSignedPreKey{
			KeyID:     uint64(100 + i),
			PublicKey: []byte{byte(i)},
			Signature: []byte{0xAA},
		}
	}
	return out
}

// makePNISignedPreKeyUploadBody builds an upload body that contains a PNI
// signed pre-key (KeyID 200) with a signature that validates against the
// PNI identity key. No EC pre-keys or KEM keys are included so the test
// stays focused on signed-pre-key routing.
func makePNISignedPreKeyUploadBody(km *signalKeyMaterial) string {
	return `{
		"signedPreKey": {
			"keyId": 200,
			"publicKey": "` + km.PNISignedPreKeyPubB64 + `",
			"signature": "` + km.PNISignedPreKeySigB64 + `"
		}
	}`
}
