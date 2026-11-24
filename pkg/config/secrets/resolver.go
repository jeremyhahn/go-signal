package secrets

import (
	"context"
	"strings"
)

// SecretResolver resolves a secret URI to a SecureString the caller must Destroy.
type SecretResolver interface {
	// Scheme returns the URI scheme this resolver handles (e.g., "kms", "env").
	Scheme() string

	// Resolve resolves the given URI to its plaintext value wrapped in a
	// SecureString. The caller owns the returned SecureString and must call
	// Destroy when done.
	Resolve(ctx context.Context, uri string) (*SecureString, error)
}

// ResolverRegistry holds registered resolvers keyed by URI scheme.
type ResolverRegistry struct {
	resolvers map[string]SecretResolver
}

// NewResolverRegistry creates an empty ResolverRegistry.
func NewResolverRegistry() *ResolverRegistry {
	return &ResolverRegistry{
		resolvers: make(map[string]SecretResolver),
	}
}

// Register adds a resolver for the given scheme. If a resolver is already
// registered for the scheme, it is replaced.
func (r *ResolverRegistry) Register(resolver SecretResolver) {
	r.resolvers[resolver.Scheme()] = resolver
}

// Resolve dispatches a URI with a registered scheme to its resolver, wraps any other value, and returns nil for empty input.
func (r *ResolverRegistry) Resolve(ctx context.Context, value string) (*SecureString, error) {
	if value == "" {
		return NewOptionalSecureString(value)
	}

	scheme, _, ok := parseScheme(value)
	if !ok {
		return NewOptionalSecureString(value)
	}

	resolver, exists := r.resolvers[scheme]
	if !exists {
		return nil, &ResolverNotFoundError{Scheme: scheme}
	}

	resolved, err := resolver.Resolve(ctx, value)
	if err != nil {
		return nil, &ResolutionError{URI: value, Cause: err}
	}

	return resolved, nil
}

// HasResolver reports whether a resolver is registered for the given scheme.
func (r *ResolverRegistry) HasResolver(scheme string) bool {
	_, ok := r.resolvers[scheme]
	return ok
}

// parseScheme extracts the scheme from a URI string. Returns the scheme,
// the remainder after "://", and whether a scheme was found.
func parseScheme(value string) (scheme, rest string, ok bool) {
	idx := strings.Index(value, "://")
	if idx <= 0 {
		return "", "", false
	}
	return value[:idx], value[idx+3:], true
}
