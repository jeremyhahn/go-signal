package calling

// CloudflareRequestError indicates a Cloudflare API call failed.
type CloudflareRequestError struct {
	Cause error
}

func (e *CloudflareRequestError) Error() string {
	msg := "cloudflare API request failed"
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause of the Cloudflare request error.
func (e *CloudflareRequestError) Unwrap() error {
	return e.Cause
}

// CloudflareDNSError indicates DNS resolution for a TURN hostname failed.
type CloudflareDNSError struct {
	Hostname string
	Cause    error
}

func (e *CloudflareDNSError) Error() string {
	msg := "DNS resolution failed for TURN hostname: " + e.Hostname
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause of the DNS resolution error.
func (e *CloudflareDNSError) Unwrap() error {
	return e.Cause
}

// InvalidCredentialRequestError indicates a malformed call link credential request.
type InvalidCredentialRequestError struct {
	Message string
}

func (e *InvalidCredentialRequestError) Error() string {
	return "invalid call link credential request: " + e.Message
}

// SurveyValidationError indicates a call quality survey is missing required fields.
type SurveyValidationError struct {
	Field string
}

func (e *SurveyValidationError) Error() string {
	return "call quality survey missing required field: " + e.Field
}

// SurveyPublishError indicates a failure to publish a call quality survey.
type SurveyPublishError struct {
	Cause error
}

func (e *SurveyPublishError) Error() string {
	msg := "failed to publish call quality survey"
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying cause of the survey publish error.
func (e *SurveyPublishError) Unwrap() error {
	return e.Cause
}

// PeerNotConnectedError indicates that the target peer has no active WebSocket
// session and therefore cannot receive a call signal.
type PeerNotConnectedError struct {
	UUID string
}

func (e *PeerNotConnectedError) Error() string {
	return "peer not connected: " + e.UUID
}

// Unwrap returns nil; PeerNotConnectedError has no causal chain.
func (e *PeerNotConnectedError) Unwrap() error { return nil }

// CallNotFoundError indicates that the referenced callID does not correspond
// to any active or pending call.
type CallNotFoundError struct {
	CallID string
}

func (e *CallNotFoundError) Error() string {
	return "call not found: " + e.CallID
}

// Unwrap returns nil; CallNotFoundError has no causal chain.
func (e *CallNotFoundError) Unwrap() error { return nil }

// CallAlreadyActiveError indicates that the user is already participating in
// a call and cannot accept or initiate another.
type CallAlreadyActiveError struct {
	UUID string
}

func (e *CallAlreadyActiveError) Error() string {
	return "call already active for user: " + e.UUID
}

// Unwrap returns nil; CallAlreadyActiveError has no causal chain.
func (e *CallAlreadyActiveError) Unwrap() error { return nil }

// InvalidCallSignalError indicates that a call signal message is malformed or
// contains unrecognized fields.
type InvalidCallSignalError struct {
	Message string
}

func (e *InvalidCallSignalError) Error() string {
	return "invalid call signal: " + e.Message
}

// Unwrap returns nil; InvalidCallSignalError has no causal chain.
func (e *InvalidCallSignalError) Unwrap() error { return nil }
