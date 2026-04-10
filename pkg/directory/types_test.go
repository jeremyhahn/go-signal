package directory

import (
	"testing"
)

func TestDirectoryCredentials_ZeroValue(t *testing.T) {
	var creds DirectoryCredentials
	if creds.Username != "" {
		t.Errorf("expected empty username, got %q", creds.Username)
	}
	if creds.Password != "" {
		t.Errorf("expected empty password, got %q", creds.Password)
	}
}

func TestDirectoryCredentials_Fields(t *testing.T) {
	creds := DirectoryCredentials{
		Username: "alice",
		Password: "secret-pw",
	}
	if creds.Username != "alice" {
		t.Errorf("got %q, want %q", creds.Username, "alice")
	}
	if creds.Password != "secret-pw" {
		t.Errorf("got %q, want %q", creds.Password, "secret-pw")
	}
}
