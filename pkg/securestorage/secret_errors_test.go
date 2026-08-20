package securestorage

import (
	"errors"
	"strings"
	"testing"
)

func TestSharedSecretUnavailableError_NamesTheAccount(t *testing.T) {
	err := &SharedSecretUnavailableError{AccountUUID: "acct-1"}
	got := err.Error()
	if got == "" {
		t.Fatal("Error() returned an empty string")
	}
	if want := "acct-1"; !strings.Contains(got, want) {
		t.Errorf("Error() = %q, want it to name %q", got, want)
	}
}

func TestSharedSecretUnavailableError_IsMatchableByType(t *testing.T) {
	var wrapped error = &SharedSecretUnavailableError{AccountUUID: "acct-2"}
	wrapped = errors.Join(errors.New("outer"), wrapped)

	var target *SharedSecretUnavailableError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As did not match the wrapped error")
	}
	if target.AccountUUID != "acct-2" {
		t.Errorf("AccountUUID = %q, want %q", target.AccountUUID, "acct-2")
	}
}
