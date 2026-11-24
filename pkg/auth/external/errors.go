package external

// MissingKeyError indicates no signing key was configured for the generator.
// It means "this deployment did not ask for external upload authorization",
// which a caller may legitimately treat as a reason to select a local mode.
type MissingKeyError struct{}

func (e *MissingKeyError) Error() string {
	return "external: Key is required"
}

// UnusableKeyError means a key is configured but unreadable; callers must fail, not fall back to unauthenticated.
type UnusableKeyError struct {
	Cause error
}

func (e *UnusableKeyError) Error() string {
	if e.Cause != nil {
		return "external: configured signing key is unusable: " + e.Cause.Error()
	}
	return "external: configured signing key is unusable"
}

func (e *UnusableKeyError) Unwrap() error { return e.Cause }
