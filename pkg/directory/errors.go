package directory

// SharedSecretUnavailableError indicates the manager was configured with a
// CDS HMAC shared secret that can no longer be revealed from protected
// memory — it has been destroyed, or its enclave failed to open.
//
// Credential issuance fails closed with this error rather than falling back
// to the random-UUID stub: once HMAC mode is configured, a random password is
// a placeholder that cdsi would reject, and returning one would disguise the
// loss of the key as a successful credential grant.
type SharedSecretUnavailableError struct {
	AccountUUID string
}

func (e *SharedSecretUnavailableError) Error() string {
	return "directory: CDS shared secret is unavailable; cannot mint credentials for account " + e.AccountUUID
}
