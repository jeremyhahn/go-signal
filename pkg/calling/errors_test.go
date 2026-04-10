package calling

import (
	"errors"
	"testing"
)

func TestCloudflareRequestError_WithCause(t *testing.T) {
	cause := errors.New("connection timeout")
	err := &CloudflareRequestError{Cause: cause}
	expected := "cloudflare API request failed: connection timeout"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestCloudflareRequestError_WithoutCause(t *testing.T) {
	err := &CloudflareRequestError{}
	expected := "cloudflare API request failed"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestCloudflareRequestError_Unwrap_WithCause(t *testing.T) {
	cause := errors.New("underlying error")
	err := &CloudflareRequestError{Cause: cause}
	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap returned %v, want %v", unwrapped, cause)
	}
}

func TestCloudflareRequestError_Unwrap_NilCause(t *testing.T) {
	err := &CloudflareRequestError{}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap returned %v, want nil", err.Unwrap())
	}
}

func TestCloudflareRequestError_ErrorsAs(t *testing.T) {
	err := &CloudflareRequestError{Cause: errors.New("test")}
	var target *CloudflareRequestError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for CloudflareRequestError")
	}
}

func TestCloudflareRequestError_ErrorsIs(t *testing.T) {
	cause := errors.New("root cause")
	err := &CloudflareRequestError{Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should find wrapped cause")
	}
}

func TestCloudflareDNSError_WithCause(t *testing.T) {
	cause := errors.New("no such host")
	err := &CloudflareDNSError{Hostname: "relay.example.com", Cause: cause}
	expected := "DNS resolution failed for TURN hostname: relay.example.com: no such host"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestCloudflareDNSError_WithoutCause(t *testing.T) {
	err := &CloudflareDNSError{Hostname: "relay.example.com"}
	expected := "DNS resolution failed for TURN hostname: relay.example.com"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestCloudflareDNSError_Unwrap_WithCause(t *testing.T) {
	cause := errors.New("DNS failure")
	err := &CloudflareDNSError{Hostname: "test.com", Cause: cause}
	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap returned %v, want %v", unwrapped, cause)
	}
}

func TestCloudflareDNSError_Unwrap_NilCause(t *testing.T) {
	err := &CloudflareDNSError{Hostname: "test.com"}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap returned %v, want nil", err.Unwrap())
	}
}

func TestCloudflareDNSError_ErrorsAs(t *testing.T) {
	err := &CloudflareDNSError{Hostname: "h.com", Cause: errors.New("fail")}
	var target *CloudflareDNSError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for CloudflareDNSError")
	}
	if target.Hostname != "h.com" {
		t.Errorf("got hostname %q, want %q", target.Hostname, "h.com")
	}
}

func TestCloudflareDNSError_ErrorsIs(t *testing.T) {
	cause := errors.New("root")
	err := &CloudflareDNSError{Hostname: "h.com", Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should find wrapped cause")
	}
}

func TestInvalidCredentialRequestError_Message(t *testing.T) {
	err := &InvalidCredentialRequestError{Message: "bad request data"}
	expected := "invalid call link credential request: bad request data"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestInvalidCredentialRequestError_EmptyMessage(t *testing.T) {
	err := &InvalidCredentialRequestError{}
	expected := "invalid call link credential request: "
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestInvalidCredentialRequestError_ErrorsAs(t *testing.T) {
	err := &InvalidCredentialRequestError{Message: "test"}
	var target *InvalidCredentialRequestError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for InvalidCredentialRequestError")
	}
	if target.Message != "test" {
		t.Errorf("got message %q, want %q", target.Message, "test")
	}
}

func TestSurveyValidationError_WithField(t *testing.T) {
	err := &SurveyValidationError{Field: "startTimestamp"}
	expected := "call quality survey missing required field: startTimestamp"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestSurveyValidationError_EmptyField(t *testing.T) {
	err := &SurveyValidationError{}
	expected := "call quality survey missing required field: "
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestSurveyValidationError_ErrorsAs(t *testing.T) {
	err := &SurveyValidationError{Field: "callType"}
	var target *SurveyValidationError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for SurveyValidationError")
	}
	if target.Field != "callType" {
		t.Errorf("got field %q, want %q", target.Field, "callType")
	}
}

func TestSurveyPublishError_WithCause(t *testing.T) {
	cause := errors.New("publish timeout")
	err := &SurveyPublishError{Cause: cause}
	expected := "failed to publish call quality survey: publish timeout"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestSurveyPublishError_WithoutCause(t *testing.T) {
	err := &SurveyPublishError{}
	expected := "failed to publish call quality survey"
	if err.Error() != expected {
		t.Errorf("got %q, want %q", err.Error(), expected)
	}
}

func TestSurveyPublishError_Unwrap_WithCause(t *testing.T) {
	cause := errors.New("transport failure")
	err := &SurveyPublishError{Cause: cause}
	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap returned %v, want %v", unwrapped, cause)
	}
}

func TestSurveyPublishError_Unwrap_NilCause(t *testing.T) {
	err := &SurveyPublishError{}
	if err.Unwrap() != nil {
		t.Errorf("Unwrap returned %v, want nil", err.Unwrap())
	}
}

func TestSurveyPublishError_ErrorsAs(t *testing.T) {
	err := &SurveyPublishError{Cause: errors.New("fail")}
	var target *SurveyPublishError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for SurveyPublishError")
	}
}

func TestSurveyPublishError_ErrorsIs(t *testing.T) {
	cause := errors.New("root cause")
	err := &SurveyPublishError{Cause: cause}
	if !errors.Is(err, cause) {
		t.Error("errors.Is should find wrapped cause")
	}
}
