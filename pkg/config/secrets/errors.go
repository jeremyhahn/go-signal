// Package secrets provides secret resolution for configuration values using
// pluggable resolvers that support kms:// URIs, auto-generation, and
// environment variable expansion.
package secrets

// ResolverNotFoundError indicates no resolver is registered for the given scheme.
type ResolverNotFoundError struct {
	Scheme string
}

func (e *ResolverNotFoundError) Error() string {
	return "secrets: no resolver registered for scheme: " + e.Scheme
}

// ResolutionError indicates a failure to resolve a secret value.
type ResolutionError struct {
	URI   string
	Cause error
}

func (e *ResolutionError) Error() string {
	return "secrets: failed to resolve " + e.URI + ": " + e.Cause.Error()
}

func (e *ResolutionError) Unwrap() error {
	return e.Cause
}

// ProcessingError indicates a failure during config struct processing.
type ProcessingError struct {
	Field string
	Cause error
}

func (e *ProcessingError) Error() string {
	return "secrets: failed to process field " + e.Field + ": " + e.Cause.Error()
}

func (e *ProcessingError) Unwrap() error {
	return e.Cause
}

// InvalidURIError indicates a malformed secret URI.
type InvalidURIError struct {
	URI     string
	Message string
}

func (e *InvalidURIError) Error() string {
	return "secrets: invalid URI " + e.URI + ": " + e.Message
}

// EnvVarNotSetError indicates a referenced environment variable is not set.
type EnvVarNotSetError struct {
	VarName string
}

func (e *EnvVarNotSetError) Error() string {
	return "secrets: environment variable not set: " + e.VarName
}

// EmptySecretError indicates an attempt to seal an empty value into
// protected memory via NewSecureString. Credential and key material is never
// legitimately empty, so this is reported rather than silently producing an
// unset SecureString that a handler would go on to issue as a credential.
// Configuration values whose absence is legitimate use
// NewOptionalSecureString, which accepts an empty value.
type EmptySecretError struct{}

func (e *EmptySecretError) Error() string {
	return "secrets: cannot seal an empty value into protected memory"
}

// UnavailableSecretError indicates a secret could not be read back out of
// protected memory: it was never set, has been destroyed, or the enclave
// could not be opened. Boundaries that put a secret on the wire report this
// rather than serialising an empty value the peer would accept as a
// credential.
type UnavailableSecretError struct {
	Cause error
}

func (e *UnavailableSecretError) Error() string {
	if e.Cause != nil {
		return "secrets: secret is unavailable: " + e.Cause.Error()
	}
	return "secrets: secret is unavailable: unset or destroyed"
}

func (e *UnavailableSecretError) Unwrap() error {
	return e.Cause
}

// SealError indicates the protected-memory allocation for a secret could not
// be obtained. The value is wiped and no SecureString is produced, so callers
// must abort the operation rather than continue with unprotected material.
type SealError struct {
	Cause error
}

func (e *SealError) Error() string {
	return "secrets: failed to seal value into protected memory: " + e.Cause.Error()
}

func (e *SealError) Unwrap() error {
	return e.Cause
}

// AbsentSecretError indicates a secret was never configured, as distinct from
// one that was configured and is no longer readable. Only this error means
// "not configured": a call site that selects a legacy or stub mode must do so
// on this and nothing else, or an unopenable enclave silently downgrades a
// deployment that does have a key installed.
type AbsentSecretError struct{}

func (e *AbsentSecretError) Error() string {
	return "secrets: secret was never configured"
}
