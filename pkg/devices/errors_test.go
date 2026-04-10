package devices

import (
	"errors"
	"testing"
)

func TestProvisioningCodeExpiredError_Error(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "non-empty code",
			code: "abc-123",
			want: "provisioning code expired: abc-123",
		},
		{
			name: "empty code",
			code: "",
			want: "provisioning code expired: ",
		},
		{
			name: "uuid-style code",
			code: "550e8400-e29b-41d4-a716-446655440000",
			want: "provisioning code expired: 550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ProvisioningCodeExpiredError{Code: tt.code}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProvisioningCodeExpiredError_TypeAssertion(t *testing.T) {
	var err error = &ProvisioningCodeExpiredError{Code: "test-code"}
	var target *ProvisioningCodeExpiredError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *ProvisioningCodeExpiredError")
	}
	if target.Code != "test-code" {
		t.Errorf("Code = %q, want %q", target.Code, "test-code")
	}
}

func TestInvalidProvisioningCodeError_Error(t *testing.T) {
	tests := []struct {
		name string
		code string
		want string
	}{
		{
			name: "non-empty code",
			code: "xyz-789",
			want: "invalid provisioning code: xyz-789",
		},
		{
			name: "empty code",
			code: "",
			want: "invalid provisioning code: ",
		},
		{
			name: "uuid-style code",
			code: "550e8400-e29b-41d4-a716-446655440000",
			want: "invalid provisioning code: 550e8400-e29b-41d4-a716-446655440000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &InvalidProvisioningCodeError{Code: tt.code}
			got := e.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInvalidProvisioningCodeError_TypeAssertion(t *testing.T) {
	var err error = &InvalidProvisioningCodeError{Code: "bad-code"}
	var target *InvalidProvisioningCodeError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *InvalidProvisioningCodeError")
	}
	if target.Code != "bad-code" {
		t.Errorf("Code = %q, want %q", target.Code, "bad-code")
	}
}

func TestProvisioningCodeExpiredError_ImplementsError(t *testing.T) {
	var _ error = &ProvisioningCodeExpiredError{}
}

func TestInvalidProvisioningCodeError_ImplementsError(t *testing.T) {
	var _ error = &InvalidProvisioningCodeError{}
}
