package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// handleGetSVRBackupAuth
// --------------------------------------------------------------------------

func TestHandleGetSVRBackupAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/backup/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetSVRBackupAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/backup/auth", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetSVRSVRAuth
// --------------------------------------------------------------------------

func TestHandleGetSVRSVRAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/svr/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetSVRSVRAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/svr/auth", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleCheckSVRBackupAuth
// --------------------------------------------------------------------------

func TestHandleCheckSVRBackupAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"passwords":["pass1","pass2"]}`
	req := httptest.NewRequest(http.MethodPost, "/v2/backup/auth/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCheckSVRBackupAuth_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v2/backup/auth/check", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCheckSVRBackupAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v2/backup/auth/check", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleCheckSVRSVRAuth
// --------------------------------------------------------------------------

func TestHandleCheckSVRSVRAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"passwords":["pass1"]}`
	req := httptest.NewRequest(http.MethodPost, "/v2/svr/auth/check", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleCheckSVRSVRAuth_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPost, "/v2/svr/auth/check", strings.NewReader("bad"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCheckSVRSVRAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v2/svr/auth/check", strings.NewReader("{}"))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// Same guard as the directory-auth body test: the SVR credential must reach
// the client as usable plaintext even though it is held in protected memory
// server-side.
func TestHandleGetSVRSVRAuth_BodyCarriesUsableCredential(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/svr/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, rr.Body.String())
	}
	if resp.Username != testAccountUUID {
		t.Errorf("username = %q, want %q", resp.Username, testAccountUUID)
	}
	if resp.Password == "" {
		t.Error("password must not be empty")
	}
	if resp.Password == "[REDACTED]" {
		t.Error("password must not be redacted on the wire")
	}
}

// The SVRB archive credential goes out through a dedicated response DTO;
// assert that path too, since it reads Plaintext() explicitly.
func TestHandleGetSVRBackupAuth_BodyCarriesUsableCredential(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/backup/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, rr.Body.String())
	}
	if resp.Password == "" || resp.Password == "[REDACTED]" {
		t.Errorf("password not usable on the wire: %q", resp.Password)
	}
}
