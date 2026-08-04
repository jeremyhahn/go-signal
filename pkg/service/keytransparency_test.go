package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/keytransparency"
)

func TestNewKeyTransparencyService_InterfaceSatisfaction(t *testing.T) {
	var _ KeyTransparencyService = (*keyTransparencyService)(nil)
}

func newTestKeyTransparencyService() KeyTransparencyService {
	mgr := keytransparency.NewKeyTransparencyManager(slog.Default())
	return NewKeyTransparencyService(mgr)
}

func TestKeyTransparencyService_Search_ReturnsStub(t *testing.T) {
	svc := newTestKeyTransparencyService()
	resp, err := svc.Search(context.Background(), &keytransparency.SearchRequest{})
	if err != nil {
		t.Fatalf("Search: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Search: expected non-nil stub response")
	}
}

func TestKeyTransparencyService_Monitor_ReturnsStub(t *testing.T) {
	svc := newTestKeyTransparencyService()
	resp, err := svc.Monitor(context.Background(), &keytransparency.MonitorRequest{})
	if err != nil {
		t.Fatalf("Monitor: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("Monitor: expected non-nil stub response")
	}
}

func TestKeyTransparencyService_GetDistinguishedKey_ReturnsStub(t *testing.T) {
	svc := newTestKeyTransparencyService()
	resp, err := svc.GetDistinguishedKey(context.Background())
	if err != nil {
		t.Fatalf("GetDistinguishedKey: unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("GetDistinguishedKey: expected non-nil stub response")
	}
}
