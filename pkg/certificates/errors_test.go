package certificates

import (
	"errors"
	"testing"
)

func TestCertificateGenerationError_Error(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		cause     error
		want      string
	}{
		{
			name:      "sign operation failure",
			operation: "sign",
			cause:     errors.New("key too short"),
			want:      "certificate generation failed: sign: key too short",
		},
		{
			name:      "marshal operation failure",
			operation: "marshal",
			cause:     errors.New("invalid json"),
			want:      "certificate generation failed: marshal: invalid json",
		},
		{
			name:      "empty operation string",
			operation: "",
			cause:     errors.New("unknown"),
			want:      "certificate generation failed: : unknown",
		},
		{
			name:      "group-credential operation",
			operation: "group-credential",
			cause:     errors.New("hmac failure"),
			want:      "certificate generation failed: group-credential: hmac failure",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &CertificateGenerationError{Operation: tt.operation, Cause: tt.cause}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCertificateGenerationError_Unwrap(t *testing.T) {
	t.Run("returns wrapped cause", func(t *testing.T) {
		cause := errors.New("root cause")
		e := &CertificateGenerationError{Operation: "sign", Cause: cause}
		if e.Unwrap() != cause {
			t.Errorf("Unwrap() did not return the original cause")
		}
	})

	t.Run("errors.Is matches cause", func(t *testing.T) {
		sentinel := errors.New("sentinel")
		e := &CertificateGenerationError{Operation: "sign", Cause: sentinel}
		if !errors.Is(e, sentinel) {
			t.Errorf("errors.Is should match the wrapped sentinel error")
		}
	})
}

func TestInvalidTimeRangeError_Error(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{
			name:    "start after end",
			message: "start must not be after end",
			want:    "invalid time range: start must not be after end",
		},
		{
			name:    "range too large",
			message: "range exceeds maximum of 7 days",
			want:    "invalid time range: range exceeds maximum of 7 days",
		},
		{
			name:    "empty message",
			message: "",
			want:    "invalid time range: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidTimeRangeError{Message: tt.message}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCertificateGenerationError_TypeAssertion(t *testing.T) {
	var err error = &CertificateGenerationError{
		Operation: "sign",
		Cause:     errors.New("test"),
	}

	var target *CertificateGenerationError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *CertificateGenerationError")
	}
	if target.Operation != "sign" {
		t.Errorf("Operation = %q, want %q", target.Operation, "sign")
	}
}

func TestInvalidTimeRangeError_TypeAssertion(t *testing.T) {
	var err error = &InvalidTimeRangeError{Message: "bad range"}

	var target *InvalidTimeRangeError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidTimeRangeError")
	}
	if target.Message != "bad range" {
		t.Errorf("Message = %q, want %q", target.Message, "bad range")
	}
}
