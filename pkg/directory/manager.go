package directory

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"

	"github.com/google/uuid"
)

// DirectoryManager manages contact discovery (CDSI) credentials. The
// credential format is HMAC-SHA256(sharedSecret, accountUUID) hex —
// the same scheme svr2 and registration-service use. cmd/cdsi
// validates inbound credentials against the same shared secret.
type DirectoryManager struct {
	logger       *slog.Logger
	sharedSecret []byte
}

// NewDirectoryManager creates a new DirectoryManager. When secret is
// empty the manager falls back to random UUIDs so non-CDSI deployments
// can keep using the legacy /v2/directory/auth stub.
func NewDirectoryManager(logger *slog.Logger) *DirectoryManager {
	return &DirectoryManager{logger: logger}
}

// SetSharedSecret installs the HMAC secret used to mint credentials.
// Called by cmd/signald at startup with cfg.CDSI.SharedSecret.
func (m *DirectoryManager) SetSharedSecret(secret string) {
	if secret == "" {
		m.sharedSecret = nil
		return
	}
	m.sharedSecret = []byte(secret)
}

// GetAuthToken returns CDSI credentials for the given account. With a
// configured shared secret, the password is the HMAC-SHA256 of the
// account UUID under that secret. Otherwise a random UUID is returned
// (matches the legacy stub behaviour).
func (m *DirectoryManager) GetAuthToken(_ context.Context, accountUUID string) (*DirectoryCredentials, error) {
	if len(m.sharedSecret) == 0 {
		return &DirectoryCredentials{
			Username: accountUUID,
			Password: uuid.NewString(),
		}, nil
	}
	mac := hmac.New(sha256.New, m.sharedSecret)
	mac.Write([]byte(accountUUID))
	return &DirectoryCredentials{
		Username: accountUUID,
		Password: hex.EncodeToString(mac.Sum(nil)),
	}, nil
}
