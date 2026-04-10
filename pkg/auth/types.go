// Package auth provides authentication primitives for the Signal server,
// including salted+hashed token storage using HKDF-SHA256.
package auth

// InvalidTokenError indicates that an authentication token failed validation
// (e.g., it is empty or malformed before hashing).
type InvalidTokenError struct {
	Reason string
}

func (e *InvalidTokenError) Error() string {
	return "invalid auth token: " + e.Reason
}

// TokenHashError indicates a failure during token hash derivation, typically
// caused by a failure in the underlying cryptographic primitives.
type TokenHashError struct {
	Cause error
}

func (e *TokenHashError) Error() string {
	return "auth token hash error: " + e.Cause.Error()
}

func (e *TokenHashError) Unwrap() error {
	return e.Cause
}
