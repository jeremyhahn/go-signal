package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config/secrets"
	"github.com/jeremyhahn/go-signal/pkg/directory"
)

func TestHandleGetDirectoryAuth_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetDirectoryAuth_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleDirectoryLookup
// --------------------------------------------------------------------------

func TestHandleDirectoryLookup_RegisteredNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":["+15551234567"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []struct {
			E164 string `json:"e164"`
			UUID string `json:"uuid"`
		} `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(resp.Contacts))
	}
	if resp.Contacts[0].E164 != "+15551234567" {
		t.Errorf("expected E164 +15551234567, got %q", resp.Contacts[0].E164)
	}
	if resp.Contacts[0].UUID != testAccountUUID {
		t.Errorf("expected UUID %s, got %q", testAccountUUID, resp.Contacts[0].UUID)
	}
}

func TestHandleDirectoryLookup_UnknownNumber(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":["+15559999999"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []json.RawMessage `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 0 {
		t.Errorf("expected 0 contacts for unknown number, got %d", len(resp.Contacts))
	}
}

func TestHandleDirectoryLookup_AcceptsUnauthenticated(t *testing.T) {
	s := newTestServer(t)

	// Directory lookup uses its own service credentials, not account auth.
	// Unauthenticated requests are accepted (rate limited by IP).
	body := `{"numbers":["+15559999999"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDirectoryLookup_InvalidBody(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader("not json"))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleDirectoryLookup_EmptyNumbers(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":[]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []json.RawMessage `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 0 {
		t.Errorf("expected 0 contacts for empty numbers, got %d", len(resp.Contacts))
	}
}

func TestHandleDirectoryLookup_MixedKnownAndUnknown(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	body := `{"numbers":["+15551234567","+15559999999"]}`
	req := httptest.NewRequest(http.MethodPut, "/v1/directory/lookup", strings.NewReader(body))
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		Contacts []struct {
			E164 string `json:"e164"`
			UUID string `json:"uuid"`
		} `json:"contacts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(resp.Contacts) != 1 {
		t.Fatalf("expected 1 contact (only registered), got %d", len(resp.Contacts))
	}
	if resp.Contacts[0].E164 != "+15551234567" {
		t.Errorf("expected registered number, got %q", resp.Contacts[0].E164)
	}
}

// The CDS credential is now held in protected memory up to the response
// writer. This asserts the wire body still carries a usable plaintext
// password under the Java field names — a redacted or empty password here
// would hand clients an unusable credential while every status check
// still passed.
func TestHandleGetDirectoryAuth_BodyCarriesUsableCredential(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
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

// capturingDirectoryService hands out a credential the test keeps a handle on
// so the handler's post-serialization wipe is observable.
type capturingDirectoryService struct {
	issued *directory.DirectoryCredentials
}

func (d *capturingDirectoryService) GetAuthToken(
	ctx context.Context,
	accountUUID string,
) (*directory.DirectoryCredentials, error) {
	password, err := secrets.NewSecureString(ctx, "cds-password")
	if err != nil {
		return nil, err
	}
	d.issued = &directory.DirectoryCredentials{Username: accountUUID, Password: password}
	return d.issued, nil
}

// The issued credential must not outlive the request: the handler serializes
// it and then wipes the protected copy.
func TestHandleGetDirectoryAuth_DestroysCredentialAfterResponse(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	svc := &capturingDirectoryService{}
	s.directory = svc

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Password string `json:"password"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v (body %s)", err, rr.Body.String())
	}
	// The password reached the client...
	if resp.Password != "cds-password" {
		t.Errorf("password on the wire = %q, want %q", resp.Password, "cds-password")
	}
	// ...and the server-side protected copy is gone.
	if svc.issued == nil {
		t.Fatal("handler did not request a credential")
	}
	if !svc.issued.Password.IsDestroyed(t.Context()) {
		t.Error("credential must be wiped once the response is written")
	}
}

// A credential that cannot be placed in protected memory must fail closed
// rather than serialize an empty password with a 200.
type failingDirectoryService struct{}

func (failingDirectoryService) GetAuthToken(
	context.Context,
	string,
) (*directory.DirectoryCredentials, error) {
	return nil, &secrets.EmptySecretError{}
}

func TestHandleGetDirectoryAuth_SealFailureIsNotIssued(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.directory = failingDirectoryService{}

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "password") {
		t.Errorf("error response must not carry a credential: %s", rr.Body.String())
	}
}

// wipedDirectoryService issues a credential whose protected password is
// already gone — serializing it as an empty password with a 200 would tell
// the client the credential is good.
type wipedDirectoryService struct{}

func (wipedDirectoryService) GetAuthToken(
	ctx context.Context,
	accountUUID string,
) (*directory.DirectoryCredentials, error) {
	password, err := secrets.NewSecureString(ctx, "cds-password")
	if err != nil {
		return nil, err
	}
	creds := &directory.DirectoryCredentials{Username: accountUUID, Password: password}
	creds.Destroy()
	return creds, nil
}

func TestHandleGetDirectoryAuth_UnavailablePasswordFailsClosed(t *testing.T) {
	s, _ := newTestServerWithAccount(t)
	s.directory = wipedDirectoryService{}

	req := httptest.NewRequest(http.MethodGet, "/v2/directory/auth", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), `"password"`) {
		t.Errorf("error response must not carry a credential: %s", rr.Body.String())
	}
}
