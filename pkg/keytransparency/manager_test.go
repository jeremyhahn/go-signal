package keytransparency

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	ktpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/keytransparencyservice"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestNewKeyTransparencyManager_NotNil(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	if m == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewKeyTransparencyManager_StoresLogger(t *testing.T) {
	logger := testLogger()
	m := NewKeyTransparencyManager(logger)
	if m.logger != logger {
		t.Error("logger not stored correctly")
	}
}

func TestSearch_ReturnsResponse(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	req := &SearchRequest{Token: []byte("search-token")}
	resp, err := m.Search(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if resp.Token == nil {
		t.Fatal("expected non-nil token in response")
	}
}

func TestSearch_EmptyToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	req := &SearchRequest{Token: []byte{}}
	resp, err := m.Search(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestSearch_NilToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	req := &SearchRequest{Token: nil}
	resp, err := m.Search(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestSearch_CancelledContext(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := m.Search(ctx, &SearchRequest{Token: []byte("tok")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestMonitor_ReturnsResponse(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	req := &MonitorRequest{Token: []byte("monitor-token")}
	resp, err := m.Monitor(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if resp.Token == nil {
		t.Fatal("expected non-nil token in response")
	}
}

func TestMonitor_EmptyToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	req := &MonitorRequest{Token: []byte{}}
	resp, err := m.Monitor(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestMonitor_NilToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	req := &MonitorRequest{Token: nil}
	resp, err := m.Monitor(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestMonitor_CancelledContext(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := m.Monitor(ctx, &MonitorRequest{Token: []byte("tok")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestGetDistinguishedKey_ReturnsResponse(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	resp, err := m.GetDistinguishedKey(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
		return
	}
	if resp.Key == nil {
		t.Fatal("expected non-nil key in response")
	}
}

func TestGetDistinguishedKey_CancelledContext(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resp, err := m.GetDistinguishedKey(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestGetDistinguishedKey_EmptyKeySlice(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	resp, err := m.GetDistinguishedKey(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Key) != 0 {
		t.Errorf("expected empty key slice, got len %d", len(resp.Key))
	}
}

func TestSearch_ReturnsEmptyTokenSlice(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	resp, err := m.Search(context.Background(), &SearchRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Token) != 0 {
		t.Errorf("expected empty token slice, got len %d", len(resp.Token))
	}
}

func TestMonitor_ReturnsEmptyTokenSlice(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	resp, err := m.Monitor(context.Background(), &MonitorRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Token) != 0 {
		t.Errorf("expected empty token slice, got len %d", len(resp.Token))
	}
}

// ---- stub RemoteClient -------------------------------------------------------

// stubRemote is a test double for RemoteClient. All fields are set per test.
type stubRemote struct {
	searchResp        *ktpb.SearchResponse
	searchErr         error
	monitorResp       *ktpb.MonitorResponse
	monitorErr        error
	distinguishedResp *ktpb.DistinguishedResponse
	distinguishedErr  error
}

func (s *stubRemote) Search(_ context.Context, _ *ktpb.SearchRequest) (*ktpb.SearchResponse, error) {
	return s.searchResp, s.searchErr
}

func (s *stubRemote) Monitor(_ context.Context, _ *ktpb.MonitorRequest) (*ktpb.MonitorResponse, error) {
	return s.monitorResp, s.monitorErr
}

func (s *stubRemote) Distinguished(_ context.Context, _ *ktpb.DistinguishedRequest) (*ktpb.DistinguishedResponse, error) {
	return s.distinguishedResp, s.distinguishedErr
}

// ---- SetRemote --------------------------------------------------------------

func TestSetRemote_StoresClient(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	stub := &stubRemote{}
	m.SetRemote(stub)
	if m.remote != stub {
		t.Error("SetRemote did not store the provided client")
	}
}

func TestSetRemote_NilResetsToStubMode(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	m.SetRemote(&stubRemote{})
	m.SetRemote(nil)
	// Stub mode: Search must succeed without calling the remote.
	resp, err := m.Search(context.Background(), &SearchRequest{})
	if err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil stub response")
	}
}

// ---- Search with remote -----------------------------------------------------

func TestSearch_Remote_NilTreeHead_ReturnsEmptyToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	// SearchResponse with nil TreeHead → extractToken(nil) → []byte{}
	m.SetRemote(&stubRemote{searchResp: &ktpb.SearchResponse{}})
	resp, err := m.Search(context.Background(), &SearchRequest{Token: []byte("tok")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Token) != 0 {
		t.Errorf("expected empty token, got len %d", len(resp.Token))
	}
}

func TestSearch_Remote_NoSignatures_ReturnsEmptyToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	// FullTreeHead present but no signatures → extractToken path 2
	m.SetRemote(&stubRemote{
		searchResp: &ktpb.SearchResponse{
			TreeHead: &ktpb.FullTreeHead{
				TreeHead: &ktpb.TreeHead{},
			},
		},
	})
	resp, err := m.Search(context.Background(), &SearchRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Token) != 0 {
		t.Errorf("expected empty token, got len %d", len(resp.Token))
	}
}

func TestSearch_Remote_WithSignature_ReturnsToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	wantSig := []byte("sig-bytes-abc")
	m.SetRemote(&stubRemote{
		searchResp: &ktpb.SearchResponse{
			TreeHead: &ktpb.FullTreeHead{
				TreeHead: &ktpb.TreeHead{
					Signatures: []*ktpb.Signature{
						{AuditorPublicKey: []byte("pub"), Signature: wantSig},
					},
				},
			},
		},
	})
	resp, err := m.Search(context.Background(), &SearchRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Token) != string(wantSig) {
		t.Errorf("token = %q, want %q", resp.Token, wantSig)
	}
}

func TestSearch_Remote_ErrorPropagates(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	wantErr := errors.New("remote search failure")
	m.SetRemote(&stubRemote{searchErr: wantErr})
	_, err := m.Search(context.Background(), &SearchRequest{})
	if !errors.Is(err, wantErr) {
		t.Errorf("expected error %v, got %v", wantErr, err)
	}
}

// ---- Monitor with remote ----------------------------------------------------

func TestMonitor_Remote_NilTreeHead_ReturnsEmptyToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	m.SetRemote(&stubRemote{monitorResp: &ktpb.MonitorResponse{}})
	resp, err := m.Monitor(context.Background(), &MonitorRequest{Token: []byte("tok")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Token) != 0 {
		t.Errorf("expected empty token, got len %d", len(resp.Token))
	}
}

func TestMonitor_Remote_WithSignature_ReturnsToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	wantSig := []byte("monitor-sig")
	m.SetRemote(&stubRemote{
		monitorResp: &ktpb.MonitorResponse{
			TreeHead: &ktpb.FullTreeHead{
				TreeHead: &ktpb.TreeHead{
					Signatures: []*ktpb.Signature{
						{Signature: wantSig},
					},
				},
			},
		},
	})
	resp, err := m.Monitor(context.Background(), &MonitorRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Token) != string(wantSig) {
		t.Errorf("token = %q, want %q", resp.Token, wantSig)
	}
}

func TestMonitor_Remote_NoSignatures_ReturnsEmptyToken(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	m.SetRemote(&stubRemote{
		monitorResp: &ktpb.MonitorResponse{
			TreeHead: &ktpb.FullTreeHead{
				TreeHead: &ktpb.TreeHead{},
			},
		},
	})
	resp, err := m.Monitor(context.Background(), &MonitorRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Token) != 0 {
		t.Errorf("expected empty token, got len %d", len(resp.Token))
	}
}

func TestMonitor_Remote_ErrorPropagates(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	wantErr := errors.New("remote monitor failure")
	m.SetRemote(&stubRemote{monitorErr: wantErr})
	_, err := m.Monitor(context.Background(), &MonitorRequest{})
	if !errors.Is(err, wantErr) {
		t.Errorf("expected error %v, got %v", wantErr, err)
	}
}

// ---- GetDistinguishedKey with remote ----------------------------------------

func TestGetDistinguishedKey_Remote_NilTreeHead_ReturnsEmptyKey(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	m.SetRemote(&stubRemote{distinguishedResp: &ktpb.DistinguishedResponse{}})
	resp, err := m.GetDistinguishedKey(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Key) != 0 {
		t.Errorf("expected empty key, got len %d", len(resp.Key))
	}
}

func TestGetDistinguishedKey_Remote_WithSignature_ReturnsKey(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	wantSig := []byte("distinguished-sig")
	m.SetRemote(&stubRemote{
		distinguishedResp: &ktpb.DistinguishedResponse{
			TreeHead: &ktpb.FullTreeHead{
				TreeHead: &ktpb.TreeHead{
					Signatures: []*ktpb.Signature{
						{Signature: wantSig},
					},
				},
			},
		},
	})
	resp, err := m.GetDistinguishedKey(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(resp.Key) != string(wantSig) {
		t.Errorf("key = %q, want %q", resp.Key, wantSig)
	}
}

func TestGetDistinguishedKey_Remote_NoSignatures_ReturnsEmptyKey(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	m.SetRemote(&stubRemote{
		distinguishedResp: &ktpb.DistinguishedResponse{
			TreeHead: &ktpb.FullTreeHead{
				TreeHead: &ktpb.TreeHead{},
			},
		},
	})
	resp, err := m.GetDistinguishedKey(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Key) != 0 {
		t.Errorf("expected empty key, got len %d", len(resp.Key))
	}
}

func TestGetDistinguishedKey_Remote_ErrorPropagates(t *testing.T) {
	m := NewKeyTransparencyManager(testLogger())
	wantErr := errors.New("remote distinguished failure")
	m.SetRemote(&stubRemote{distinguishedErr: wantErr})
	_, err := m.GetDistinguishedKey(context.Background())
	if !errors.Is(err, wantErr) {
		t.Errorf("expected error %v, got %v", wantErr, err)
	}
}
