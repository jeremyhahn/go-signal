package certificates

// CertificateGenerationError indicates a failure during certificate or
// credential generation.
type CertificateGenerationError struct {
	Operation string
	Cause     error
}

// Error returns a human-readable description of the certificate generation
// failure including the operation that failed.
func (e *CertificateGenerationError) Error() string {
	return "certificate generation failed: " + e.Operation + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause of the certificate generation error.
func (e *CertificateGenerationError) Unwrap() error {
	return e.Cause
}

// InvalidTimeRangeError indicates that a requested time range for credential
// generation is invalid (e.g. start after end, or range too large).
type InvalidTimeRangeError struct {
	Message string
}

// Error returns a human-readable description of the invalid time range.
func (e *InvalidTimeRangeError) Error() string {
	return "invalid time range: " + e.Message
}

// Ed25519KeyError indicates a failure involving an Ed25519 signing key, such
// as an invalid key size or a failed key-generation attempt.
type Ed25519KeyError struct {
	Cause error
}

// Error returns a human-readable description of the Ed25519 key error.
func (e *Ed25519KeyError) Error() string {
	return "ed25519 key error: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *Ed25519KeyError) Unwrap() error {
	return e.Cause
}

// InvalidUUIDError indicates that a UUID string could not be parsed.
type InvalidUUIDError struct {
	Value string
	Cause error
}

// Error returns a human-readable description of the UUID parse failure.
func (e *InvalidUUIDError) Error() string {
	return "invalid uuid " + e.Value + ": " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *InvalidUUIDError) Unwrap() error {
	return e.Cause
}

// ZKGroupError wraps a zkgroup operation failure with contextual information.
type ZKGroupError struct {
	Operation string
	Cause     error
}

// Error returns a human-readable description of the zkgroup operation failure.
func (e *ZKGroupError) Error() string {
	return "zkgroup " + e.Operation + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ZKGroupError) Unwrap() error {
	return e.Cause
}
