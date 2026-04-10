package keytransparency

import (
	"context"
	"log/slog"
	"testing"
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
