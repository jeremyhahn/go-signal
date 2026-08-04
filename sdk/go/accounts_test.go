package signal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
)

// --- Verification session ---

func TestClient_CreateVerificationSession_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/verification/session" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1", AllowedToRequestCode: true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	sess, err := c.CreateVerificationSession(context.Background(), "+15550000001")
	if err != nil {
		t.Fatalf("CreateVerificationSession: %v", err)
	}
	if sess.ID != "sess-1" {
		t.Errorf("ID = %q", sess.ID)
	}
}

func TestClient_CreateVerificationSession_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.CreateVerificationSession(context.Background(), "+15550000001")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_RequestVerificationCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/v1/verification/session/sess-1/code"
		if r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	sess, err := c.RequestVerificationCode(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("RequestVerificationCode: %v", err)
	}
	if sess.ID != "sess-1" {
		t.Errorf("ID = %q", sess.ID)
	}
}

func TestClient_RequestVerificationCode_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.RequestVerificationCode(context.Background(), "bad-sess")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SubmitVerificationCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1", Verified: true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	sess, err := c.SubmitVerificationCode(context.Background(), "sess-1", "123456")
	if err != nil {
		t.Fatalf("SubmitVerificationCode: %v", err)
	}
	if !sess.Verified {
		t.Error("expected Verified=true")
	}
}

func TestClient_SubmitVerificationCode_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "wrong code", http.StatusForbidden)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.SubmitVerificationCode(context.Background(), "sess-1", "000000")
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- Register ---

func TestClient_Register_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/registration" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _, ok := r.BasicAuth()
		if !ok {
			t.Error("expected Basic Auth")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RegistrationResult{
			UUID: "aci-uuid-123",
			PNI:  "pni-uuid-456",
		})
	}))
	defer srv.Close()

	ms := &mockStore{}
	c := newTestClient(t, srv.URL, ms)
	result, err := c.Register(context.Background(), "+15550000001", "sess-1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if result.UUID != "aci-uuid-123" {
		t.Errorf("UUID = %q", result.UUID)
	}
	if result.PNI != "pni-uuid-456" {
		t.Errorf("PNI = %q", result.PNI)
	}
	if ms.credentials == nil {
		t.Fatal("credentials not saved")
	}
	if ms.credentials.UUID != "aci-uuid-123" {
		t.Errorf("saved UUID = %q", ms.credentials.UUID)
	}
}

func TestClient_Register_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "conflict", http.StatusConflict)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.Register(context.Background(), "+15550000001", "sess-1")
	if err == nil {
		t.Fatal("expected error for server error")
	}
}

func TestClient_Register_SaveCredentialsFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RegistrationResult{UUID: "u", PNI: "p"})
	}))
	defer srv.Close()

	ms := &mockStore{saveCredErr: errors.New("disk full")}
	c := newTestClient(t, srv.URL, ms)
	_, err := c.Register(context.Background(), "+15550000001", "sess-1")
	if err == nil {
		t.Fatal("expected error when SaveCredentials fails")
	}
}

// --- Unregister ---

func TestClient_Unregister_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/accounts/me" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.Unregister(context.Background()); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
}

func TestClient_Unregister_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.Unregister(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

// --- ReplenishPreKeys ---

func TestClient_ReplenishPreKeys_AboveThreshold(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %q", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"count": 50, "pqCount": 5, "hasLastResort": true})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.ReplenishPreKeys(context.Background()); err != nil {
		t.Fatalf("ReplenishPreKeys: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 GET, got %d", calls)
	}
}

func TestClient_ReplenishPreKeys_BelowThreshold(t *testing.T) {
	var putCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 3, "pqCount": 0, "hasLastResort": false})
			return
		}
		if r.Method == http.MethodPut {
			putCalled = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	creds := &Credentials{UUID: "user-uuid", DeviceID: 1}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, srv.URL, ms)
	if err := c.ReplenishPreKeys(context.Background()); err != nil {
		t.Fatalf("ReplenishPreKeys: %v", err)
	}
	if !putCalled {
		t.Error("expected PUT /v2/keys to be called")
	}
}

func TestClient_ReplenishPreKeys_GetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.ReplenishPreKeys(context.Background()); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ReplenishPreKeys_NoCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 0})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// stubStore returns nil credentials.
	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.ReplenishPreKeys(context.Background()); err == nil {
		t.Fatal("expected error when no credentials")
	}
}

// --- SetPin / RemovePin / UpdateAccountSettings ---

func TestClient_SetPin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !strings.Contains(r.URL.Path, "registration_lock") {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SetPin(context.Background(), "123456"); err != nil {
		t.Fatalf("SetPin: %v", err)
	}
}

func TestClient_SetPin_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SetPin(context.Background(), "000000"); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_RemovePin_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.RemovePin(context.Background()); err != nil {
		t.Fatalf("RemovePin: %v", err)
	}
}

func TestClient_UpdateAccountSettings_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %q", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	err := c.UpdateAccountSettings(context.Background(), map[string]any{"fetchesMessages": true})
	if err != nil {
		t.Fatalf("UpdateAccountSettings: %v", err)
	}
}

// --- SetPhoneNumberDiscoverability / SubmitChallenge ---

func TestClient_SetPhoneNumberDiscoverability_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SetPhoneNumberDiscoverability(context.Background(), true); err != nil {
		t.Fatalf("SetPhoneNumberDiscoverability: %v", err)
	}
}

func TestClient_SetPhoneNumberDiscoverability_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SetPhoneNumberDiscoverability(context.Background(), false); err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_SubmitChallenge_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/challenge" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SubmitChallenge(context.Background(), "token123", "captcha456"); err != nil {
		t.Fatalf("SubmitChallenge: %v", err)
	}
}

func TestClient_SubmitChallenge_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	if err := c.SubmitChallenge(context.Background(), "t", "c"); err == nil {
		t.Fatal("expected error")
	}
}

// --- WhoAmI / ListAccounts ---

func TestClient_WhoAmI_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/accounts/whoami" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Account{UUID: "my-uuid", Number: "+15550000001"})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	acct, err := c.WhoAmI(context.Background())
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if acct.UUID != "my-uuid" {
		t.Errorf("UUID = %q", acct.UUID)
	}
}

func TestClient_WhoAmI_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &stubStore{})
	_, err := c.WhoAmI(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ListAccounts_WithCredentials(t *testing.T) {
	creds := &Credentials{
		Number:   "+15550000001",
		UUID:     "my-uuid",
		DeviceID: 1,
	}
	ms := &mockStore{credentials: creds}
	c := newTestClient(t, "http://localhost", ms)
	accounts, err := c.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %d", len(accounts))
	}
	if accounts[0].UUID != "my-uuid" {
		t.Errorf("UUID = %q", accounts[0].UUID)
	}
}

func TestClient_ListAccounts_NoCredentials(t *testing.T) {
	c := newTestClient(t, "http://localhost", &stubStore{})
	accounts, err := c.ListAccounts()
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("expected 0 accounts, got %d", len(accounts))
	}
}

// --- Verify ---

func TestClient_Verify_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/verification/session":
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/code"):
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1"})
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/code"):
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1", Verified: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/registration":
			_ = json.NewEncoder(w).Encode(RegistrationResult{UUID: "aci-uuid", PNI: "pni-uuid"})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{})
	result, err := c.Verify(context.Background(), "+15550000001", "123456")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.UUID != "aci-uuid" {
		t.Errorf("UUID = %q", result.UUID)
	}
}

func TestClient_Verify_SessionNotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/verification/session":
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/code"):
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1"})
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/code"):
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-1", Verified: false})
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{})
	_, err := c.Verify(context.Background(), "+15550000001", "wrongcode")
	if err == nil {
		t.Fatal("expected error when verification fails")
	}
}

func TestClient_Verify_CreateSessionError(t *testing.T) {
	// Server returns an error on the first call (CreateVerificationSession).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{})
	_, err := c.Verify(context.Background(), "+15550000001", "123456")
	if err == nil {
		t.Fatal("expected error when CreateVerificationSession fails")
	}
}

func TestClient_Verify_RequestCodeError(t *testing.T) {
	// CreateVerificationSession succeeds but RequestVerificationCode fails.
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		if callCount == 1 && r.Method == http.MethodPost && r.URL.Path == "/v1/verification/session" {
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-x"})
			return
		}
		// All subsequent calls fail.
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{})
	_, err := c.Verify(context.Background(), "+15550000001", "123456")
	if err == nil {
		t.Fatal("expected error when RequestVerificationCode fails")
	}
}

func TestClient_Verify_SubmitCodeError(t *testing.T) {
	// CreateVerificationSession and RequestVerificationCode succeed; SubmitVerificationCode fails.
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/verification/session":
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-y"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/code"):
			_ = json.NewEncoder(w).Encode(VerificationSession{ID: "sess-y"})
		default:
			http.Error(w, "submit failed", http.StatusUnprocessableEntity)
		}
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, &mockStore{})
	_, err := c.Verify(context.Background(), "+15550000001", "wrong")
	if err == nil {
		t.Fatal("expected error when SubmitVerificationCode fails")
	}
}

// --- Private helpers ---

func TestGenerateSignedPreKey_Success(t *testing.T) {
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("ecc.GenerateKeyPair: %v", err)
	}
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	spk, err := generateSignedPreKey(idKP, 42)
	if err != nil {
		t.Fatalf("generateSignedPreKey: %v", err)
	}
	if spk.KeyID != 42 {
		t.Errorf("KeyID = %d", spk.KeyID)
	}
	if spk.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if spk.Signature == "" {
		t.Error("Signature is empty")
	}
}

func TestGenerateSignedPreKey_DifferentIDs(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	spk1, err1 := generateSignedPreKey(idKP, 1)
	spk2, err2 := generateSignedPreKey(idKP, 2)
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v %v", err1, err2)
	}
	if spk1.KeyID == spk2.KeyID {
		t.Error("KeyIDs should differ")
	}
}

func TestGenerateDummyPQPreKey_NonNil(t *testing.T) {
	kp, _ := ecc.GenerateKeyPair()
	pubKey := identity.NewKey(kp.PublicKey())
	idKP := identity.NewKeyPair(pubKey, kp.PrivateKey())

	pq := generateDummyPQPreKey(idKP)
	if pq == nil {
		t.Fatal("expected non-nil result")
	}
	if pq.PublicKey == "" {
		t.Error("PublicKey is empty")
	}
	if pq.Signature == "" {
		t.Error("Signature is empty")
	}
}

func TestRandomRegistrationID_Range(t *testing.T) {
	for i := 0; i < 20; i++ {
		id := randomRegistrationID()
		if id > 0x3FFF {
			t.Errorf("id %d exceeds 14-bit max", id)
		}
	}
}

func TestRandomRegistrationID_IsRandom(t *testing.T) {
	a, b, c2 := randomRegistrationID(), randomRegistrationID(), randomRegistrationID()
	if a == b && b == c2 {
		t.Error("registration IDs appear non-random (got same value 3 times)")
	}
}

func TestGeneratePassword_NonEmpty(t *testing.T) {
	pw := generatePassword()
	if len(pw) == 0 {
		t.Error("expected non-empty password")
	}
}

func TestGeneratePassword_IsRandom(t *testing.T) {
	a, b := generatePassword(), generatePassword()
	if a == b {
		t.Error("passwords should be unique")
	}
}
