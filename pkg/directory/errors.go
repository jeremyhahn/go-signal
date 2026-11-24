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

// ManagerDestroyedError indicates SetSharedSecret was called on a manager that
// has already been destroyed, or lost a race with a concurrent Destroy.
//
// The secret is not installed and the clone the call had made is wiped, so the
// manager stays terminal. Startup treats this as fatal; a shutdown path
// racing configuration means the process is going away regardless, and
// installing a key into a manager nothing will wipe is the outcome this
// prevents.
type ManagerDestroyedError struct{}

func (e *ManagerDestroyedError) Error() string {
	return "directory: manager has been destroyed; the shared secret was not installed"
}
