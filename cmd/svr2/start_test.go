package main

import (
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/config"
	"github.com/jeremyhahn/go-signal/pkg/svr2"
)

func TestBuildStorage_Memory(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: ""}
	store, err := buildStorage(cfg)
	if err != nil {
		t.Fatalf("buildStorage(memory): unexpected error: %v", err)
	}
	if _, ok := store.(*svr2.MemoryStorage); !ok {
		t.Fatalf("buildStorage(memory): want *svr2.MemoryStorage, got %T", store)
	}
}

func TestBuildStorage_UnknownBackendDefaultsToMemory(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: "unknown"}
	store, err := buildStorage(cfg)
	if err != nil {
		t.Fatalf("buildStorage(unknown): unexpected error: %v", err)
	}
	if _, ok := store.(*svr2.MemoryStorage); !ok {
		t.Fatalf("buildStorage(unknown): want *svr2.MemoryStorage, got %T", store)
	}
}

func TestBuildStorage_Qrdb(t *testing.T) {
	t.Parallel()
	cfg := config.StorageConfig{Backend: "qrdb"}
	store, err := buildStorage(cfg)
	if err != nil {
		t.Fatalf("buildStorage(qrdb): unexpected error: %v", err)
	}
	if _, ok := store.(*svr2.QrdbStorage); !ok {
		t.Fatalf("buildStorage(qrdb): want *svr2.QrdbStorage, got %T", store)
	}
}
