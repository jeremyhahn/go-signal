package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestBuildManifestStore_Memory(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: ""}
	store, err := buildManifestStore(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("buildManifestStore(memory): unexpected error: %v", err)
	}
	if _, ok := store.(*memstorage.MemoryManifestStore); !ok {
		t.Fatalf("buildManifestStore(memory): want *memstorage.MemoryManifestStore, got %T", store)
	}
}

func TestBuildManifestStore_UnknownBackendDefaultsToMemory(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: "unknown"}
	store, err := buildManifestStore(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("buildManifestStore(unknown): unexpected error: %v", err)
	}
	if _, ok := store.(*memstorage.MemoryManifestStore); !ok {
		t.Fatalf("buildManifestStore(unknown): want *memstorage.MemoryManifestStore, got %T", store)
	}
}

func TestBuildManifestStore_Qrdb(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: "qrdb"}
	store, err := buildManifestStore(context.Background(), cfg, discardLogger())
	if err != nil {
		t.Fatalf("buildManifestStore(qrdb): unexpected error: %v", err)
	}
	if _, ok := store.(*qrdbstorage.SecureStorageStore); !ok {
		t.Fatalf("buildManifestStore(qrdb): want *qrdbstorage.SecureStorageStore, got %T", store)
	}
}
