package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/directory"
)

func TestNewDirectoryService_InterfaceSatisfaction(t *testing.T) {
	var _ DirectoryService = (*directoryService)(nil)
}

func newTestDirectoryService() DirectoryService {
	mgr := directory.NewDirectoryManager(slog.Default())
	return NewDirectoryService(mgr)
}

func TestDirectoryService_GetAuthToken_ReturnsCredentials(t *testing.T) {
	svc := newTestDirectoryService()
	creds, err := svc.GetAuthToken(context.Background(), "dir-uuid-01")
	if err != nil {
		t.Fatalf("GetAuthToken: unexpected error: %v", err)
	}
	if creds == nil {
		t.Fatal("GetAuthToken: expected non-nil credentials")
	}
}

func TestDirectoryService_GetAuthToken_EmptyUUID(t *testing.T) {
	svc := newTestDirectoryService()
	// Empty UUID is forwarded to the manager; no panic expected.
	_, _ = svc.GetAuthToken(context.Background(), "")
}
