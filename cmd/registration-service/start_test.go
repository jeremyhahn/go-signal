package main

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

func TestBuildSessionStore_Memory(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: ""}
	store, err := buildSessionStore(context.Background(), cfg, newDiscardLogger())
	if err != nil {
		t.Fatalf("buildSessionStore(memory): unexpected error: %v", err)
	}
	if _, ok := store.(*verification.MemoryVerificationSessionStore); !ok {
		t.Fatalf("buildSessionStore(memory): want *verification.MemoryVerificationSessionStore, got %T", store)
	}
}

func TestBuildSessionStore_UnknownBackendDefaultsToMemory(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: "unknown"}
	store, err := buildSessionStore(context.Background(), cfg, newDiscardLogger())
	if err != nil {
		t.Fatalf("buildSessionStore(unknown): unexpected error: %v", err)
	}
	if _, ok := store.(*verification.MemoryVerificationSessionStore); !ok {
		t.Fatalf("buildSessionStore(unknown): want *verification.MemoryVerificationSessionStore, got %T", store)
	}
}

func TestBuildSessionStore_Qrdb(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: "qrdb"}
	store, err := buildSessionStore(context.Background(), cfg, newDiscardLogger())
	if err != nil {
		t.Fatalf("buildSessionStore(qrdb): unexpected error: %v", err)
	}
	if _, ok := store.(*qrdbstorage.VerificationSessionStore); !ok {
		t.Fatalf("buildSessionStore(qrdb): want *qrdbstorage.VerificationSessionStore, got %T", store)
	}
}
