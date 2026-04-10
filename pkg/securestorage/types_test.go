package securestorage

import (
	"testing"
)

func TestStorageCredentials_ZeroValue(t *testing.T) {
	var creds StorageCredentials
	if creds.Username != "" {
		t.Errorf("expected empty username, got %q", creds.Username)
	}
	if creds.Password != "" {
		t.Errorf("expected empty password, got %q", creds.Password)
	}
}

func TestStorageCredentials_Fields(t *testing.T) {
	creds := StorageCredentials{
		Username: "storage-user",
		Password: "storage-pass",
	}
	if creds.Username != "storage-user" {
		t.Errorf("got %q, want %q", creds.Username, "storage-user")
	}
	if creds.Password != "storage-pass" {
		t.Errorf("got %q, want %q", creds.Password, "storage-pass")
	}
}
