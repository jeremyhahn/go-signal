package securestorage

import (
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// StorageManifest
// --------------------------------------------------------------------------

func TestStorageManifest_ZeroValue(t *testing.T) {
	var m StorageManifest
	if m.Version != 0 {
		t.Errorf("expected zero Version, got %d", m.Version)
	}
	if m.Value != nil {
		t.Error("expected nil Value on zero StorageManifest")
	}
}

func TestStorageManifest_Fields(t *testing.T) {
	m := StorageManifest{
		Version: 42,
		Value:   []byte("encrypted-blob"),
	}
	if m.Version != 42 {
		t.Errorf("got %d, want 42", m.Version)
	}
	if string(m.Value) != "encrypted-blob" {
		t.Errorf("got %q, want %q", m.Value, "encrypted-blob")
	}
}

// --------------------------------------------------------------------------
// StorageItem
// --------------------------------------------------------------------------

func TestStorageItem_ZeroValue(t *testing.T) {
	var item StorageItem
	if item.Key != nil {
		t.Error("expected nil Key on zero StorageItem")
	}
	if item.Value != nil {
		t.Error("expected nil Value on zero StorageItem")
	}
}

func TestStorageItem_Fields(t *testing.T) {
	item := StorageItem{
		Key:   []byte{0x01, 0x02},
		Value: []byte("item-value"),
	}
	if len(item.Key) != 2 {
		t.Errorf("got key len %d, want 2", len(item.Key))
	}
	if string(item.Value) != "item-value" {
		t.Errorf("got %q, want %q", item.Value, "item-value")
	}
}

// --------------------------------------------------------------------------
// ManifestNotFoundError
// --------------------------------------------------------------------------

func TestManifestNotFoundError_ContainsAccountUUID(t *testing.T) {
	err := &ManifestNotFoundError{AccountUUID: "account-abc"}
	if !strings.Contains(err.Error(), "account-abc") {
		t.Errorf("expected error to contain account UUID, got: %s", err.Error())
	}
}

func TestManifestNotFoundError_ContainsNotFound(t *testing.T) {
	err := &ManifestNotFoundError{AccountUUID: "x"}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %s", err.Error())
	}
}

// --------------------------------------------------------------------------
// ManifestVersionConflictError
// --------------------------------------------------------------------------

func TestManifestVersionConflictError_ContainsAccountUUID(t *testing.T) {
	err := &ManifestVersionConflictError{
		AccountUUID:      "acct-1",
		StoredVersion:    3,
		SubmittedVersion: 2,
	}
	if !strings.Contains(err.Error(), "acct-1") {
		t.Errorf("expected error to contain account UUID, got: %s", err.Error())
	}
}

func TestManifestVersionConflictError_ContainsVersions(t *testing.T) {
	err := &ManifestVersionConflictError{
		AccountUUID:      "acct-1",
		StoredVersion:    5,
		SubmittedVersion: 3,
	}
	msg := err.Error()
	if !strings.Contains(msg, "5") {
		t.Errorf("expected stored version 5 in error, got: %s", msg)
	}
	if !strings.Contains(msg, "3") {
		t.Errorf("expected submitted version 3 in error, got: %s", msg)
	}
}

// --------------------------------------------------------------------------
// StorageItemNotFoundError
// --------------------------------------------------------------------------

func TestStorageItemNotFoundError_ContainsAccountUUID(t *testing.T) {
	err := &StorageItemNotFoundError{AccountUUID: "acct-2", Key: []byte{0xAB, 0xCD}}
	if !strings.Contains(err.Error(), "acct-2") {
		t.Errorf("expected error to contain account UUID, got: %s", err.Error())
	}
}

func TestStorageItemNotFoundError_ContainsKey(t *testing.T) {
	err := &StorageItemNotFoundError{AccountUUID: "acct-2", Key: []byte{0xAB, 0xCD}}
	// The key is hex-encoded in the error message.
	if !strings.Contains(err.Error(), "abcd") {
		t.Errorf("expected hex key in error, got: %s", err.Error())
	}
}

func TestStorageItemNotFoundError_NilKey(t *testing.T) {
	err := &StorageItemNotFoundError{AccountUUID: "acct-3", Key: nil}
	// Should not panic for nil key.
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
}
