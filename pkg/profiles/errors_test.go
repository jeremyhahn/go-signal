package profiles

import (
	"errors"
	"testing"
)

// --- InvalidArgumentError tests ---

func TestInvalidArgumentError_Error(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		message string
		want    string
	}{
		{
			name:    "typical fields",
			field:   "uuid",
			message: "must not be empty",
			want:    "invalid argument: uuid: must not be empty",
		},
		{
			name:    "empty field and message",
			field:   "",
			message: "",
			want:    "invalid argument: : ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidArgumentError{Field: tt.field, Message: tt.message}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalidArgumentError_TypeAssertion(t *testing.T) {
	var err error = &InvalidArgumentError{Field: "name", Message: "required"}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidArgumentError")
	}
	if target.Field != "name" {
		t.Errorf("Field = %q, want %q", target.Field, "name")
	}
	if target.Message != "required" {
		t.Errorf("Message = %q, want %q", target.Message, "required")
	}
}

func TestInvalidArgumentError_ImplementsError(t *testing.T) {
	var _ error = &InvalidArgumentError{}
}

// --- ProfileNotFoundError tests ---

func TestProfileNotFoundError_ErrorWithVersion(t *testing.T) {
	e := &ProfileNotFoundError{UUID: "test-uuid", Version: "v1"}
	want := "profile not found: test-uuid version v1"
	got := e.Error()
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestProfileNotFoundError_ErrorWithoutVersion(t *testing.T) {
	e := &ProfileNotFoundError{UUID: "test-uuid"}
	want := "profile not found: test-uuid"
	got := e.Error()
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestProfileNotFoundError_EmptyFields(t *testing.T) {
	e := &ProfileNotFoundError{}
	want := "profile not found: "
	got := e.Error()
	if got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestProfileNotFoundError_TypeAssertion(t *testing.T) {
	var err error = &ProfileNotFoundError{UUID: "uuid-ta", Version: "v2"}
	var target *ProfileNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *ProfileNotFoundError")
	}
	if target.UUID != "uuid-ta" {
		t.Errorf("UUID = %q, want %q", target.UUID, "uuid-ta")
	}
	if target.Version != "v2" {
		t.Errorf("Version = %q, want %q", target.Version, "v2")
	}
}

func TestProfileNotFoundError_ImplementsError(t *testing.T) {
	var _ error = &ProfileNotFoundError{}
}
