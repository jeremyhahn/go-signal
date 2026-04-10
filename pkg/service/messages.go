package service

import (
	"context"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// MessageService defines the message operations exposed to protocol handlers.
type MessageService interface {
	// Insert stores a message envelope for delivery to the specified device.
	Insert(ctx context.Context, destinationUUID string, destinationDeviceID uint64, envelope *messages.Envelope) error

	// GetMessagesForDevice retrieves pending envelopes for a device.
	GetMessagesForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) ([]*messages.Envelope, error)

	// Delete removes a specific envelope by its server-assigned GUID.
	Delete(ctx context.Context, destinationUUID string, serverGUID string) error

	// DeleteForDevice removes all pending envelopes for a device.
	DeleteForDevice(ctx context.Context, destinationUUID string, destinationDeviceID uint64) error

	// DeleteForAccount removes all pending envelopes for an account.
	DeleteForAccount(ctx context.Context, uuid string) error

	// SetDeliveryCallback registers a callback invoked after each Insert for
	// real-time WebSocket delivery.
	SetDeliveryCallback(fn messages.DeliveryCallback)
}

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
