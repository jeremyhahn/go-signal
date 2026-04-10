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
