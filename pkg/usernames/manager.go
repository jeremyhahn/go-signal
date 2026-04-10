package usernames

import (
	"context"
	"log/slog"
)

// UsernamesManager coordinates username operations, delegating persistence to
// a UsernameStore and enforcing business rules.
type UsernamesManager struct {
	store  UsernameStore
	logger *slog.Logger
}

// NewUsernamesManager creates a new UsernamesManager backed by the given store.
func NewUsernamesManager(store UsernameStore, logger *slog.Logger) *UsernamesManager {
	return &UsernamesManager{
		store:  store,
		logger: logger,
	}
}

// ReserveHash attempts to reserve one of the provided username hashes for the
// given account. Returns the selected hash and a reservation token.
func (m *UsernamesManager) ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	if uuid == "" {
		return nil, "", &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if len(hashes) == 0 {
		return nil, "", &InvalidArgumentError{Field: "hashes", Message: "must not be empty"}
	}
	for i, h := range hashes {
		if len(h) == 0 {
			m.logger.Warn("empty hash in reservation request",
				slog.String("uuid", uuid),
				slog.Int("index", i))
			return nil, "", &InvalidArgumentError{Field: "hashes", Message: "hash must not be empty"}
		}
	}

	hash, token, err := m.store.ReserveHash(ctx, uuid, hashes)
	if err != nil {
		return nil, "", err
	}

	m.logger.Debug("username hash reserved",
		slog.String("uuid", uuid))

	return hash, token, nil
}

// ConfirmHash confirms a previously reserved username hash using the
// reservation token.
func (m *UsernamesManager) ConfirmHash(ctx context.Context, uuid string, hash []byte, token string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if len(hash) == 0 {
		return &InvalidArgumentError{Field: "hash", Message: "must not be empty"}
	}
	if token == "" {
		return &InvalidArgumentError{Field: "token", Message: "must not be empty"}
	}

	if err := m.store.ConfirmHash(ctx, uuid, hash, token); err != nil {
		return err
	}

	m.logger.Debug("username hash confirmed",
		slog.String("uuid", uuid))

	return nil
}

// LookupByHash returns the account UUID associated with a confirmed username
// hash.
func (m *UsernamesManager) LookupByHash(ctx context.Context, hash []byte) (string, error) {
	if len(hash) == 0 {
		return "", &InvalidArgumentError{Field: "hash", Message: "must not be empty"}
	}

	return m.store.LookupByHash(ctx, hash)
}

// DeleteHash removes the confirmed username hash for the given account UUID.
func (m *UsernamesManager) DeleteHash(ctx context.Context, uuid string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	if err := m.store.DeleteHash(ctx, uuid); err != nil {
		return err
	}

	m.logger.Debug("username hash deleted",
		slog.String("uuid", uuid))

	return nil
}

// SetLink stores or replaces the username link for the given account.
func (m *UsernamesManager) SetLink(ctx context.Context, link *UsernameLink) error {
	if link == nil {
		return &InvalidArgumentError{Field: "link", Message: "must not be nil"}
	}
	if link.UUID == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}
	if link.UsernameLinkHandle == "" {
		return &InvalidArgumentError{Field: "usernameLinkHandle", Message: "must not be empty"}
	}
	if len(link.EncryptedUsername) == 0 {
		return &InvalidArgumentError{Field: "encryptedUsername", Message: "must not be empty"}
	}

	if err := m.store.SetLink(ctx, link); err != nil {
		return err
	}

	m.logger.Debug("username link set",
		slog.String("uuid", link.UUID),
		slog.String("handle", link.UsernameLinkHandle))

	return nil
}

// GetLink retrieves a username link by its handle UUID.
func (m *UsernamesManager) GetLink(ctx context.Context, handle string) (*UsernameLink, error) {
	if handle == "" {
		return nil, &InvalidArgumentError{Field: "handle", Message: "must not be empty"}
	}

	return m.store.GetLink(ctx, handle)
}

// DeleteLink removes the username link for the given account UUID.
func (m *UsernamesManager) DeleteLink(ctx context.Context, uuid string) error {
	if uuid == "" {
		return &InvalidArgumentError{Field: "uuid", Message: "must not be empty"}
	}

	if err := m.store.DeleteLink(ctx, uuid); err != nil {
		return err
	}

	m.logger.Debug("username link deleted",
		slog.String("uuid", uuid))

	return nil
}
