package qrdb

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jeremyhahn/go-signal/pkg/devices"
	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
)

// Key layout: provisioning:{code} → JSON-serialized ProvisioningSession.
const provisioningKeyPrefix = "provisioning:"

// Compile-time interface satisfaction check.
var _ devices.ProvisioningStore = (*ProvisioningStore)(nil)

// ProvisioningStore is a qrdb-backed implementation of
// devices.ProvisioningStore. Sessions are keyed by verification code.
type ProvisioningStore struct {
	kv KVStore
}

// NewProvisioningStore returns a ProvisioningStore that persists to kv.
func NewProvisioningStore(kv KVStore) *ProvisioningStore {
	return &ProvisioningStore{kv: kv}
}

func provisioningKey(code string) string { return provisioningKeyPrefix + code }

// StoreSession persists a provisioning session, overwriting any prior session
// stored under the same code. This matches the memory-backed store's
// semantics; callers that require create-only behavior should check existence
// first.
func (s *ProvisioningStore) StoreSession(ctx context.Context, session *devices.ProvisioningSession) error {
	if session == nil {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb provisioning: nil session")
	}
	if session.Code == "" {
		return signalerrors.New(signalerrors.ErrInvalidArgument, "qrdb provisioning: empty code")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb provisioning: marshal", err)
	}
	if err := s.kv.Put(ctx, provisioningKey(session.Code), data); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb provisioning: put", err)
	}
	return nil
}

// GetSession retrieves a provisioning session by verification code. Returns
// an InvalidProvisioningCodeError when the code is absent.
func (s *ProvisioningStore) GetSession(ctx context.Context, code string) (*devices.ProvisioningSession, error) {
	data, err := getOrNotFound(ctx, s.kv, provisioningKey(code))
	if errors.Is(err, ErrNotFound) {
		return nil, &devices.InvalidProvisioningCodeError{Code: code}
	}
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb provisioning: get", err)
	}

	var sess devices.ProvisioningSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "qrdb provisioning: unmarshal", err)
	}
	return &sess, nil
}

// DeleteSession removes a session. The operation is idempotent: deleting a
// missing session does not return an error.
func (s *ProvisioningStore) DeleteSession(ctx context.Context, code string) error {
	if err := s.kv.Delete(ctx, provisioningKey(code)); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "qrdb provisioning: delete", err)
	}
	return nil
}
