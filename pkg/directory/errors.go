package directory

// SharedSecretUnavailableError means the configured CDS shared secret can no longer be revealed; issuance fails rather than falling back to the stub.
type SharedSecretUnavailableError struct {
	AccountUUID string
}

func (e *SharedSecretUnavailableError) Error() string {
	return "directory: CDS shared secret is unavailable; cannot mint credentials for account " + e.AccountUUID
}

// ManagerDestroyedError means SetSharedSecret ran on a destroyed manager; the secret is not installed and its clone is wiped.
type ManagerDestroyedError struct{}

func (e *ManagerDestroyedError) Error() string {
	return "directory: manager has been destroyed; the shared secret was not installed"
}
