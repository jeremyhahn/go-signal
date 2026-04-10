package usernames

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestUsernameHashConflictError_Error(t *testing.T) {
	tests := []struct {
		name string
		hash []byte
		want string
	}{
		{
			name: "non-empty hash",
			hash: []byte{0xDE, 0xAD, 0xBE, 0xEF},
			want: "username hash already taken: " + hex.EncodeToString([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		},
		{
			name: "empty hash",
			hash: []byte{},
			want: "username hash already taken: ",
		},
		{
			name: "nil hash",
			hash: nil,
			want: "username hash already taken: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &UsernameHashConflictError{Hash: tt.hash}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUsernameHashConflictError_TypeAssertion(t *testing.T) {
	var err error = &UsernameHashConflictError{Hash: []byte{1, 2, 3}}
	var target *UsernameHashConflictError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *UsernameHashConflictError")
	}
	if len(target.Hash) != 3 {
		t.Errorf("Hash length = %d, want 3", len(target.Hash))
	}
}

func TestUsernameNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name string
		hash []byte
		want string
	}{
		{
			name: "non-empty hash",
			hash: []byte{0xCA, 0xFE},
			want: "username hash not found: " + hex.EncodeToString([]byte{0xCA, 0xFE}),
		},
		{
			name: "empty hash",
			hash: []byte{},
			want: "username hash not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &UsernameNotFoundError{Hash: tt.hash}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUsernameNotFoundError_TypeAssertion(t *testing.T) {
	var err error = &UsernameNotFoundError{Hash: []byte{0xFF}}
	var target *UsernameNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *UsernameNotFoundError")
	}
}

func TestInvalidReservationTokenError_Error(t *testing.T) {
	tests := []struct {
		name string
		uuid string
		want string
	}{
		{
			name: "with uuid",
			uuid: "test-uuid-123",
			want: "invalid reservation token for account test-uuid-123",
		},
		{
			name: "empty uuid",
			uuid: "",
			want: "invalid reservation token for account ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidReservationTokenError{UUID: tt.uuid}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalidReservationTokenError_TypeAssertion(t *testing.T) {
	var err error = &InvalidReservationTokenError{UUID: "uuid-1"}
	var target *InvalidReservationTokenError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidReservationTokenError")
	}
	if target.UUID != "uuid-1" {
		t.Errorf("UUID = %q, want %q", target.UUID, "uuid-1")
	}
}

func TestUsernameLinkNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name   string
		handle string
		want   string
	}{
		{
			name:   "with handle",
			handle: "handle-abc",
			want:   "username link not found: handle-abc",
		},
		{
			name:   "empty handle",
			handle: "",
			want:   "username link not found: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &UsernameLinkNotFoundError{Handle: tt.handle}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUsernameLinkNotFoundError_TypeAssertion(t *testing.T) {
	var err error = &UsernameLinkNotFoundError{Handle: "handle-xyz"}
	var target *UsernameLinkNotFoundError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *UsernameLinkNotFoundError")
	}
}

func TestInvalidArgumentError_Error(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		message string
		want    string
	}{
		{
			name:    "uuid field",
			field:   "uuid",
			message: "must not be empty",
			want:    "invalid argument: uuid: must not be empty",
		},
		{
			name:    "hash field",
			field:   "hash",
			message: "must not be empty",
			want:    "invalid argument: hash: must not be empty",
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
	var err error = &InvalidArgumentError{Field: "token", Message: "required"}
	var target *InvalidArgumentError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidArgumentError")
	}
	if target.Field != "token" {
		t.Errorf("Field = %q, want %q", target.Field, "token")
	}
	if target.Message != "required" {
		t.Errorf("Message = %q, want %q", target.Message, "required")
	}
}
