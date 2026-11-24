package securestorage

// SharedSecretUnavailableError means the configured HMAC secret can no longer be revealed; issuance fails rather than using the stub.
type SharedSecretUnavailableError struct {
	AccountUUID string
}

func (e *SharedSecretUnavailableError) Error() string {
	return "securestorage: storage-service shared secret is unavailable; cannot mint credentials for account " + e.AccountUUID
}

// ManagerDestroyedError means SetSharedSecret ran on a destroyed manager; the clone is wiped and nothing is installed.
type ManagerDestroyedError struct{}

func (e *ManagerDestroyedError) Error() string {
	return "securestorage: manager has been destroyed; the shared secret was not installed"
}
