package messages

import (
	"testing"
)

func TestInvalidArgumentError_Error(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		message  string
		expected string
	}{
		{
			name:     "basic error",
			field:    "envelope",
			message:  "must not be nil",
			expected: "invalid argument: envelope: must not be nil",
		},
		{
			name:     "empty field",
			field:    "",
			message:  "missing",
			expected: "invalid argument: : missing",
		},
		{
			name:     "empty message",
			field:    "id",
			message:  "",
			expected: "invalid argument: id: ",
		},
		{
			name:     "both empty",
			field:    "",
			message:  "",
			expected: "invalid argument: : ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &InvalidArgumentError{Field: tc.field, Message: tc.message}
			got := err.Error()
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestInvalidArgumentError_ImplementsError(t *testing.T) {
	var err error = &InvalidArgumentError{Field: "test", Message: "msg"}
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

func TestMessageNotFoundError_Error(t *testing.T) {
	tests := []struct {
		name       string
		serverGUID string
		expected   string
	}{
		{
			name:       "with guid",
			serverGUID: "abc-123-def",
			expected:   "message not found: abc-123-def",
		},
		{
			name:       "empty guid",
			serverGUID: "",
			expected:   "message not found: ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := &MessageNotFoundError{ServerGUID: tc.serverGUID}
			got := err.Error()
			if got != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, got)
			}
		})
	}
}

func TestMessageNotFoundError_ImplementsError(t *testing.T) {
	var err error = &MessageNotFoundError{ServerGUID: "guid-1"}
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

func TestInvalidArgumentError_TypeAssertion(t *testing.T) {
	var err error = &InvalidArgumentError{Field: "f", Message: "m"}
	iae, ok := err.(*InvalidArgumentError)
	if !ok {
		t.Fatal("expected type assertion to succeed")
	}
	if iae.Field != "f" {
		t.Errorf("expected Field 'f', got %q", iae.Field)
	}
	if iae.Message != "m" {
		t.Errorf("expected Message 'm', got %q", iae.Message)
	}
}

func TestMessageNotFoundError_TypeAssertion(t *testing.T) {
	var err error = &MessageNotFoundError{ServerGUID: "guid-x"}
	mnf, ok := err.(*MessageNotFoundError)
	if !ok {
		t.Fatal("expected type assertion to succeed")
	}
	if mnf.ServerGUID != "guid-x" {
		t.Errorf("expected ServerGUID 'guid-x', got %q", mnf.ServerGUID)
	}
}
