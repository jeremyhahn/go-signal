package signal

import (
	"errors"
	"strings"
	"testing"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
		wantSubstr string
	}{
		{"standard", 404, "not found", "404"},
		{"server error", 500, "internal", "500"},
		{"empty message", 400, "", "400"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &APIError{StatusCode: tt.statusCode, Message: tt.message}
			got := e.Error()
			if !strings.Contains(got, tt.wantSubstr) {
				t.Errorf("Error() = %q, want substr %q", got, tt.wantSubstr)
			}
		})
	}
}

func TestAPIError_ImplementsError(t *testing.T) {
	var err error = &APIError{StatusCode: 422, Message: "unprocessable"}
	if err == nil {
		t.Fatal("expected non-nil error interface")
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("error string missing status code: %q", err.Error())
	}
}

func TestNotRegisteredError_Error(t *testing.T) {
	tests := []struct {
		name   string
		number string
	}{
		{"with number", "+15551234567"},
		{"empty number", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &NotRegisteredError{Number: tt.number}
			got := e.Error()
			if got == "" {
				t.Error("Error() returned empty string")
			}
			if tt.number != "" && !strings.Contains(got, tt.number) {
				t.Errorf("Error() = %q, want to contain %q", got, tt.number)
			}
		})
	}
}

func TestSessionError_Error(t *testing.T) {
	cause := errors.New("session broken")
	e := &SessionError{Recipient: "+15550000001", Cause: cause}
	got := e.Error()
	if got == "" {
		t.Error("Error() returned empty string")
	}
	if !strings.Contains(got, "+15550000001") {
		t.Errorf("Error() missing recipient: %q", got)
	}
}

func TestSessionError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := &SessionError{Recipient: "alice", Cause: cause}
	if !errors.Is(e, cause) {
		t.Error("errors.Is should find cause via Unwrap")
	}
	if e.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}
