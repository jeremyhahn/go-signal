package service

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/stickers"
)

func TestNewStickersService_InterfaceSatisfaction(t *testing.T) {
	var _ StickersService = (*stickersService)(nil)
}

func newTestStickersService() StickersService {
	mgr := stickers.NewStickersManager(context.Background(), stickers.ManagerConfig{})
	return NewStickersService(mgr)
}

func TestStickersService_GetUploadForm_Success(t *testing.T) {
	svc := newTestStickersService()
	form, err := svc.GetUploadForm(context.Background(), "uuid-s01", 5)
	if err != nil {
		t.Fatalf("GetUploadForm: unexpected error: %v", err)
	}
	if form == nil {
		t.Fatal("GetUploadForm: expected non-nil form")
	}
}

func TestStickersService_GetUploadForm_ZeroStickers(t *testing.T) {
	svc := newTestStickersService()
	// Zero stickers should not panic; error handling is up to the manager.
	_, _ = svc.GetUploadForm(context.Background(), "uuid-s02", 0)
}
