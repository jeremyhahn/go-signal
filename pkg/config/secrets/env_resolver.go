package secrets

import (
	"context"
	"os"
	"strings"
)

// EnvResolver resolves environment variable references in the form ${VAR_NAME}.
// This is the standalone-mode resolver for secrets that are stored in
// environment variables rather than a KMS.
type EnvResolver struct{}

// NewEnvResolver creates a new EnvResolver.
func NewEnvResolver() *EnvResolver {
	return &EnvResolver{}
}

// Scheme returns "env". This resolver handles "${VAR}" syntax rather than
// URI schemes, so it is invoked directly by the ConfigProcessor for values
// matching the ${...} pattern.
func (r *EnvResolver) Scheme() string {
	return "env"
}

// Resolve expands environment variable references in the value. A value of
// "${VAR_NAME}" resolves to the value of the VAR_NAME environment variable
// wrapped in a SecureString. If the variable is not set, an EnvVarNotSetError
// is returned. Values that are not env var references are wrapped unchanged.
func (r *EnvResolver) Resolve(ctx context.Context, value string) (*SecureString, error) {
	varName, ok := parseEnvVar(value)
	if !ok {
		return NewOptionalSecureString(ctx, value)
	}

	envValue, exists := os.LookupEnv(varName)
	if !exists {
		return nil, &EnvVarNotSetError{VarName: varName}
	}

	// An exported-but-empty variable is a legitimate configuration state;
	// it is the unset variable above that is an error.
	return NewOptionalSecureString(ctx, envValue)
}

// IsEnvVar reports whether the value is an environment variable reference.
func IsEnvVar(value string) bool {
	_, ok := parseEnvVar(value)
	return ok
}

// parseEnvVar extracts the variable name from a "${VAR_NAME}" string.
// Returns the variable name and true if the value matches the pattern.
func parseEnvVar(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "${") || !strings.HasSuffix(trimmed, "}") {
		return "", false
	}
	varName := trimmed[2 : len(trimmed)-1]
	if varName == "" {
		return "", false
	}
	return varName, true
}
