package messages

import (
	"errors"
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

// --- QueueError ---

func TestQueueError_Error_WithKey(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		key      string
		cause    string
		expected string
	}{
		{
			name:     "with key",
			op:       "hget",
			key:      "guid-abc",
			cause:    "connection refused",
			expected: "messages/queue: hget guid-abc: connection refused",
		},
		{
			name:     "without key",
			op:       "zadd",
			key:      "",
			cause:    "timeout",
			expected: "messages/queue: zadd: timeout",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &QueueError{Op: tc.op, Key: tc.key, Cause: errors.New(tc.cause)}
			got := e.Error()
			if got != tc.expected {
				t.Errorf("QueueError.Error() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestQueueError_Unwrap(t *testing.T) {
	cause := errors.New("root cause")
	e := &QueueError{Op: "zrange", Cause: cause}
	if e.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), cause)
	}
}

func TestQueueError_ImplementsError(t *testing.T) {
	var err error = &QueueError{Op: "op", Cause: errors.New("err")}
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

// --- MRMCacheError ---

func TestMRMCacheError_Error(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		cause    string
		expected string
	}{
		{
			name:     "insert op",
			op:       "insert",
			cause:    "redis unavailable",
			expected: "mrm insert: redis unavailable",
		},
		{
			name:     "remove op",
			op:       "remove",
			cause:    "timeout",
			expected: "mrm remove: timeout",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &MRMCacheError{Op: tc.op, Cause: errors.New(tc.cause)}
			got := e.Error()
			if got != tc.expected {
				t.Errorf("MRMCacheError.Error() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestMRMCacheError_Unwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	e := &MRMCacheError{Op: "get", Cause: cause}
	if e.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), cause)
	}
}

func TestMRMCacheError_ImplementsError(t *testing.T) {
	var err error = &MRMCacheError{Op: "op", Cause: errors.New("err")}
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

// --- MRMUnexpectedResultTypeError ---

func TestMRMUnexpectedResultTypeError_Error(t *testing.T) {
	tests := []struct {
		name   string
		result interface{}
	}{
		{name: "string result", result: "unexpected"},
		{name: "bool result", result: true},
		{name: "nil result", result: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &MRMUnexpectedResultTypeError{Result: tc.result}
			got := e.Error()
			if got == "" {
				t.Error("expected non-empty error string")
			}
			if len(got) < 10 {
				t.Errorf("error string suspiciously short: %q", got)
			}
		})
	}
}

func TestMRMUnexpectedResultTypeError_ImplementsError(t *testing.T) {
	var err error = &MRMUnexpectedResultTypeError{Result: 42}
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}

// --- MRMSendError ---

func TestMRMSendError_Error(t *testing.T) {
	tests := []struct {
		name     string
		e        MRMSendError
		expected string
	}{
		{
			name:     "with UUID and device",
			e:        MRMSendError{Op: "send", UUID: "uuid-1", Device: 3, Cause: errors.New("failed")},
			expected: "mrm: send uuid-1/3: failed",
		},
		{
			name:     "with UUID only",
			e:        MRMSendError{Op: "send", UUID: "uuid-2", Device: 0, Cause: errors.New("failed")},
			expected: "mrm: send uuid-2: failed",
		},
		{
			name:     "no UUID no device",
			e:        MRMSendError{Op: "encode", UUID: "", Device: 0, Cause: errors.New("err")},
			expected: "mrm: encode: err",
		},
		{
			name:     "nil cause",
			e:        MRMSendError{Op: "op", UUID: "u", Device: 1, Cause: nil},
			expected: "mrm: op u/1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.e.Error()
			if got != tc.expected {
				t.Errorf("MRMSendError.Error() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestMRMSendError_Unwrap(t *testing.T) {
	cause := errors.New("send cause")
	e := &MRMSendError{Op: "send", Cause: cause}
	if e.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), cause)
	}
}

func TestMRMSendError_UnwrapNil(t *testing.T) {
	e := &MRMSendError{Op: "send", Cause: nil}
	if e.Unwrap() != nil {
		t.Errorf("Unwrap() should be nil, got %v", e.Unwrap())
	}
}

// --- PersisterError ---

func TestPersisterError_Error(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		key      string
		cause    string
		expected string
	}{
		{
			name:     "with key",
			op:       "drain",
			key:      "guid-xyz",
			cause:    "store error",
			expected: "drain guid-xyz: store error",
		},
		{
			name:     "without key",
			op:       "flush",
			key:      "",
			cause:    "timeout",
			expected: "flush: timeout",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &PersisterError{Op: tc.op, Key: tc.key, Cause: errors.New(tc.cause)}
			got := e.Error()
			if got != tc.expected {
				t.Errorf("PersisterError.Error() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestPersisterError_Unwrap(t *testing.T) {
	cause := errors.New("persister cause")
	e := &PersisterError{Op: "drain", Cause: cause}
	if e.Unwrap() != cause {
		t.Errorf("Unwrap() = %v, want %v", e.Unwrap(), cause)
	}
}

func TestPersisterError_ImplementsError(t *testing.T) {
	var err error = &PersisterError{Op: "op", Cause: errors.New("err")}
	if err.Error() == "" {
		t.Error("expected non-empty error string")
	}
}
