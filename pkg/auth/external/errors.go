package external

// MissingKeyError indicates no signing key was configured for the generator.
// It means "this deployment did not ask for external upload authorization",
// which a caller may legitimately treat as a reason to select a local mode.
type MissingKeyError struct{}

func (e *MissingKeyError) Error() string {
	return "external: Key is required"
}

// UnusableKeyError indicates a key WAS configured but could not be read out
// of protected memory. It is deliberately distinct from MissingKeyError: a
// caller must not respond to this by falling back to an unauthenticated mode,
// because the deployment does have a key installed and the correct action is
// to fail rather than to silently downgrade.
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
