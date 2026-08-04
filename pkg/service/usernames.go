package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/usernames"
)

// UsernameService defines the username operations exposed to protocol handlers.
type UsernameService interface {
	// ReserveHash attempts to reserve one of the provided username hashes
	// for the given account, returning the selected hash and a token.
	ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error)

	// ConfirmHash confirms a previously reserved username hash using the
	// reservation token. The caller supplies a zero-knowledge proof that is
	// verified server-side via go-libsignal/usernames.VerifyProof.
	ConfirmHash(ctx context.Context, uuid string, hash []byte, token string, zkProof []byte) error

	// LookupByHash returns the account UUID associated with a confirmed hash.
	LookupByHash(ctx context.Context, hash []byte) (string, error)

	// DeleteHash removes the confirmed username hash for the given account.
	DeleteHash(ctx context.Context, uuid string) error

	// SetLink stores or replaces the username link for the given account.
	SetLink(ctx context.Context, link *usernames.UsernameLink) error

	// GetLink retrieves a username link by its handle.
	GetLink(ctx context.Context, handle string) (*usernames.UsernameLink, error)

	// DeleteLink removes the username link for the given account UUID.
	DeleteLink(ctx context.Context, uuid string) error

	// DeleteExpiredReservations sweeps expired username-hash holds.
	// Used by the remove-expired-username-holds worker; safe to call
	// from any node — the underlying store handles concurrency.
	DeleteExpiredReservations(ctx context.Context) (int, error)

	// ExistingLinkHandle returns the handle of the account's currently-published
	// username link, or *UsernameLinkNotFoundError when none exists. Used by the
	// REST handler to honour keepLinkHandle=true.
	ExistingLinkHandle(ctx context.Context, uuid string) (string, error)
}

// Compile-time assertion: UsernamesManager must satisfy UsernameService.
var _ UsernameService = (*usernames.UsernamesManager)(nil)

// usernameService is the default UsernameService backed by a UsernamesManager.
type usernameService struct {
	manager *usernames.UsernamesManager
}

// NewUsernameService returns a UsernameService that delegates to the given
// UsernamesManager. The manager must not be nil.
func NewUsernameService(manager *usernames.UsernamesManager) UsernameService {
	return &usernameService{manager: manager}
}

func (s *usernameService) ReserveHash(ctx context.Context, uuid string, hashes [][]byte) ([]byte, string, error) {
	return s.manager.ReserveHash(ctx, uuid, hashes)
}

func (s *usernameService) ConfirmHash(ctx context.Context, uuid string, hash []byte, token string, zkProof []byte) error {
	return s.manager.ConfirmHash(ctx, uuid, hash, token, zkProof)
}

func (s *usernameService) LookupByHash(ctx context.Context, hash []byte) (string, error) {
	return s.manager.LookupByHash(ctx, hash)
}

func (s *usernameService) DeleteHash(ctx context.Context, uuid string) error {
	return s.manager.DeleteHash(ctx, uuid)
}

func (s *usernameService) SetLink(ctx context.Context, link *usernames.UsernameLink) error {
	return s.manager.SetLink(ctx, link)
}

func (s *usernameService) GetLink(ctx context.Context, handle string) (*usernames.UsernameLink, error) {
	return s.manager.GetLink(ctx, handle)
}

func (s *usernameService) DeleteLink(ctx context.Context, uuid string) error {
	return s.manager.DeleteLink(ctx, uuid)
}

func (s *usernameService) DeleteExpiredReservations(ctx context.Context) (int, error) {
	return s.manager.DeleteExpiredReservations(ctx)
}

func (s *usernameService) ExistingLinkHandle(ctx context.Context, uuid string) (string, error) {
	return s.manager.ExistingLinkHandle(ctx, uuid)
}
