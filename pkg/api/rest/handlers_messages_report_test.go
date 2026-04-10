package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// --------------------------------------------------------------------------
// memTestReportStore — in-process test double for messages.ReportStore
// --------------------------------------------------------------------------

type memTestReportStore struct {
	mu       sync.Mutex
	reports  []*messages.SpamReport
	storeErr error
}

func (s *memTestReportStore) Store(_ context.Context, report *messages.SpamReport) error {
	if s.storeErr != nil {
		return s.storeErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report.ID = "test-id"
	clone := *report
	s.reports = append(s.reports, &clone)
	return nil
}

func (s *memTestReportStore) GetByReporter(_ context.Context, reporterUUID string) ([]*messages.SpamReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*messages.SpamReport
	for _, r := range s.reports {
		if r.ReporterUUID == reporterUUID {
			clone := *r
			result = append(result, &clone)
		}
	}
	if result == nil {
		result = []*messages.SpamReport{}
	}
	return result, nil
}

// newTestServerWithReportStore creates a test server wired with the provided
// ReportStore so spam-report handler tests can control store behaviour.
func newTestServerWithReportStore(t *testing.T, rs messages.ReportStore) *Server {
	t.Helper()
	s, _ := newTestServerWithVerification(t)
	s.reportStore = rs
	return s
}

// --------------------------------------------------------------------------
// handleReportSpam – ReportStore integration
// --------------------------------------------------------------------------

func TestHandleReportSpam_StoresReport(t *testing.T) {
	rs := &memTestReportStore{}
	s := newTestServerWithReportStore(t, rs)

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("create account: %v", err)
	}

	const testSourceUUID = "99999999-9999-9999-9999-999999999999"
	const testMsgGUID = "88888888-8888-8888-8888-888888888888"

	req := httptest.NewRequest(http.MethodPost, "/v1/messages/report/"+testSourceUUID+"/"+testMsgGUID, nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	if len(rs.reports) != 1 {
		t.Fatalf("expected 1 stored report, got %d", len(rs.reports))
	}
	r := rs.reports[0]
	if r.ReporterUUID != testAccountUUID {
		t.Errorf("ReporterUUID: got %q, want %q", r.ReporterUUID, testAccountUUID)
	}
	if r.SourceUUID != testSourceUUID {
		t.Errorf("SourceUUID: got %q, want %q", r.SourceUUID, testSourceUUID)
	}
	if r.MessageGUID != testMsgGUID {
		t.Errorf("MessageGUID: got %q, want %q", r.MessageGUID, testMsgGUID)
	}
}

func TestHandleReportSpam_NilReportStore_StillReturns200(t *testing.T) {
	// When no ReportStore is configured the handler must still succeed (just logs).
	s, _ := newTestServerWithAccount(t)
	// s.reportStore is nil by default.

	req := httptest.NewRequest(http.MethodPost, "/v1/messages/report/99999999-9999-9999-9999-999999999999/88888888-8888-8888-8888-888888888888", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with nil report store, got %d", rr.Code)
	}
}

func TestHandleReportSpam_StoreError_Returns500(t *testing.T) {
	rs := &memTestReportStore{
		storeErr: &messages.InvalidArgumentError{Field: "test", Message: "simulated store failure"},
	}
	s := newTestServerWithReportStore(t, rs)

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("create account: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/messages/report/99999999-9999-9999-9999-999999999999/88888888-8888-8888-8888-888888888888", nil)
	req.SetBasicAuth(testAccountUUID, testAuthToken)
	rr := httptest.NewRecorder()
	s.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 on store error, got %d", rr.Code)
	}
}

func TestHandleReportSpam_ConcurrentReports(t *testing.T) {
	rs := &memTestReportStore{}
	s := newTestServerWithReportStore(t, rs)

	acct := testAccount()
	if err := s.accounts.Create(context.Background(), acct); err != nil {
		t.Fatalf("create account: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	for range n {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/messages/report/99999999-9999-9999-9999-999999999999/88888888-8888-8888-8888-888888888888", nil)
			req.SetBasicAuth(testAccountUUID, testAuthToken)
			rr := httptest.NewRecorder()
			s.httpServer.Handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("expected 200, got %d", rr.Code)
			}
		}()
	}
	wg.Wait()

	rs.mu.Lock()
	defer rs.mu.Unlock()

	if len(rs.reports) != n {
		t.Errorf("expected %d reports after concurrent submissions, got %d", n, len(rs.reports))
	}
}
