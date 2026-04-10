package rest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// --------------------------------------------------------------------------
// handleGetDeliveryCertificate
// --------------------------------------------------------------------------

func TestHandleGetDeliveryCertificate_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/delivery", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp DeliveryCertificateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if resp.Certificate == "" {
		t.Error("expected non-empty certificate")
	}
	if resp.CertificateExpiry <= 0 {
		t.Error("expected positive certificate expiry")
	}
}

func TestHandleGetDeliveryCertificate_WithIncludeE164(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/delivery?includeE164=false", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetDeliveryCertificate_InvalidIncludeE164(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/delivery?includeE164=notabool", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetDeliveryCertificate_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/delivery", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// --------------------------------------------------------------------------
// handleGetGroupCredentials
// --------------------------------------------------------------------------

func TestHandleGetGroupCredentials_Success(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group?redemptionStartSeconds=1700000000&redemptionEndSeconds=1700086400", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetGroupCredentials_MissingParams(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetGroupCredentials_InvalidStartSeconds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group?redemptionStartSeconds=abc&redemptionEndSeconds=1700086400", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetGroupCredentials_InvalidEndSeconds(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group?redemptionStartSeconds=1700000000&redemptionEndSeconds=abc", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleGetGroupCredentials_Unauthenticated(t *testing.T) {
	s := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group?redemptionStartSeconds=1&redemptionEndSeconds=2", nil)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestHandleGetGroupCredentials_InvertedRange(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// startTime > endTime should be rejected with 400.
	req := httptest.NewRequest(http.MethodGet, "/v1/certificate/auth/group?redemptionStartSeconds=1700086400&redemptionEndSeconds=1700000000", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for inverted range (start > end), got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetGroupCredentials_ExactMaxRange(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// Exactly 7 days apart (aligned to day boundaries) should succeed.
	// Use a range of exactly 7 days aligned to midnight: day 0 through day 6 inclusive.
	const secondsPerDay = 86400
	startDay := int64(1700000000 / secondsPerDay)
	startSeconds := startDay * secondsPerDay
	endSeconds := startSeconds + (7-1)*secondsPerDay // 7 days inclusive: day 0..6

	url := "/v1/certificate/auth/group?redemptionStartSeconds=" +
		strconv.FormatInt(startSeconds, 10) +
		"&redemptionEndSeconds=" +
		strconv.FormatInt(endSeconds, 10)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for exactly 7-day range, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetGroupCredentials_ExceedsMaxRange(t *testing.T) {
	s, _ := newTestServerWithAccount(t)

	// 8 days span (spanning 8 distinct day buckets) should be rejected with 400.
	const secondsPerDay = 86400
	startDay := int64(1700000000 / secondsPerDay)
	startSeconds := startDay * secondsPerDay
	endSeconds := startSeconds + 7*secondsPerDay // 8 days inclusive: day 0..7

	url := "/v1/certificate/auth/group?redemptionStartSeconds=" +
		strconv.FormatInt(startSeconds, 10) +
		"&redemptionEndSeconds=" +
		strconv.FormatInt(endSeconds, 10)

	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for 8-day range exceeding maximum, got %d: %s", rr.Code, rr.Body.String())
	}
}
