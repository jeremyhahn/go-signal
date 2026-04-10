package auth

// HashingError indicates a failure during Argon2id key derivation, typically
// caused by an OS entropy source failure when generating salt.
type HashingError struct {
	Cause error
}

func (e *HashingError) Error() string {
	if e.Cause != nil {
		return "registration lock hashing failed: " + e.Cause.Error()
	}
	return "registration lock hashing failed"
}

func (e *HashingError) Unwrap() error {
	return e.Cause
}
