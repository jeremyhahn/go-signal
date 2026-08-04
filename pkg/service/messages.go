package service

import (
	"context"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// MessageService defines the message operations exposed to protocol handlers.
type MessageService interface {
	// Insert stores a message envelope for delivery to the specified device.
	Insert(ctx context.Context, destinationUUID string, destinationDeviceID uint64, envelope *messages.Envelope) error

	// GetMessagesForDevice retrieves pending envelopes for a device.
	GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) ([]*messages.Envelope, error)

	// HasMessagesForDevice reports whether the device has at least
	// one pending envelope. Cheaper than GetMessagesForDevice
	// because no envelope payloads are materialised.
	HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) (bool, error)

	// Delete removes a specific envelope by its server-assigned GUID.
	Delete(ctx context.Context, destinationUUID string, serverGUID string) error

	// DeleteForDevice removes all pending envelopes for a device.
	DeleteForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) error

	// DeleteForAccount removes all pending envelopes for an account.
	DeleteForAccount(ctx context.Context, uuid string) error

	// SetDeliveryCallback registers a callback invoked after each Insert for
	// real-time WebSocket delivery.
	SetDeliveryCallback(fn messages.DeliveryCallback)

	// SendMRMBinary processes a SealedSender v2 multi-recipient ciphertext:
	// stores the shared payload in the MRM cache and enqueues per-recipient
	// envelopes referencing it. Returns the list of recipient UUIDs that
	// could not be resolved by the supplied lookup. Callers must wire an
	// MRM cache via the underlying MessagesManager (SetMRMCache) before
	// calling, otherwise ErrMRMNoCache is returned.
	SendMRMBinary(ctx context.Context, req messages.MRMSendRequest) (*messages.MRMSendResult, error)

	// SetMRMCache wires the multi-recipient message shared-payload cache. When
	// nil, the binary multi-recipient send path returns ErrMRMNoCache.
	SetMRMCache(c *messages.MRMCache)

	// RemoveExpired sweeps envelopes whose per-row expires_at is strictly
	// before the supplied cutoff. Returns the number of rows removed.
	// Used by the periodic RemoveExpiredMessagesWorker.
	RemoveExpired(ctx context.Context, before time.Time) (int64, error)
}

// Compile-time assertion: MessagesManager must satisfy MessageService.
var _ MessageService = (*messages.MessagesManager)(nil)

// messageService is the default MessageService backed by a MessagesManager.
type messageService struct {
	manager *messages.MessagesManager
}

// NewMessageService returns a MessageService that delegates to the given
// MessagesManager. The manager must not be nil.
func NewMessageService(manager *messages.MessagesManager) MessageService {
	return &messageService{manager: manager}
}

func (s *messageService) Insert(ctx context.Context, destinationUUID string, destinationDeviceID uint64, envelope *messages.Envelope) error {
	return s.manager.Insert(ctx, destinationUUID, destinationDeviceID, envelope)
}

func (s *messageService) GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) ([]*messages.Envelope, error) {
	return s.manager.GetMessagesForDevice(ctx, destinationUUID, destinationDeviceID)
}

func (s *messageService) HasMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) (bool, error) {
	return s.manager.HasMessagesForDevice(ctx, destinationUUID, destinationDeviceID)
}

func (s *messageService) Delete(ctx context.Context, destinationUUID string, serverGUID string) error {
	return s.manager.Delete(ctx, destinationUUID, serverGUID)
}

func (s *messageService) DeleteForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) error {
	return s.manager.DeleteForDevice(ctx, destinationUUID, destinationDeviceID)
}

func (s *messageService) DeleteForAccount(ctx context.Context, uuid string) error {
	return s.manager.DeleteForAccount(ctx, uuid)
}

func (s *messageService) SetDeliveryCallback(fn messages.DeliveryCallback) {
	s.manager.SetDeliveryCallback(fn)
}

func (s *messageService) SendMRMBinary(ctx context.Context, req messages.MRMSendRequest) (*messages.MRMSendResult, error) {
	return s.manager.SendMRMBinary(ctx, req)
}

func (s *messageService) SetMRMCache(c *messages.MRMCache) {
	s.manager.SetMRMCache(c)
}

func (s *messageService) RemoveExpired(ctx context.Context, before time.Time) (int64, error) {
	return s.manager.RemoveExpired(ctx, before)
}
