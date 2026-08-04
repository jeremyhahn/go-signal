package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// deviceKey uniquely identifies a device within an account.
type deviceKey struct {
	uuid     string
	deviceID uint64
}

// Compile-time interface satisfaction check.
var _ messages.MessageStore = (*MemoryMessageStore)(nil)

// MemoryMessageStore implements messages.MessageStore with in-memory storage.
type MemoryMessageStore struct {
	mu        sync.RWMutex
	byDevice  map[deviceKey][]*messages.Envelope
	byGUID    map[string]*guidIndex // serverGUID -> index info
	idCounter atomic.Uint64
}

// guidIndex tracks the location of a message for efficient deletion by GUID.
type guidIndex struct {
	destinationUUID string
	deviceID        uint64
}

// NewMemoryMessageStore creates a new in-memory message store.
func NewMemoryMessageStore() *MemoryMessageStore {
	return &MemoryMessageStore{
		byDevice: make(map[deviceKey][]*messages.Envelope),
		byGUID:   make(map[string]*guidIndex),
	}
}

// Insert persists a new message envelope for delivery.
func (s *MemoryMessageStore) Insert(_ context.Context, destinationUUID string, destinationDevice uint64, envelope *messages.Envelope) (uint64, error) {
	if envelope == nil {
		return 0, &messages.InvalidArgumentError{Field: "envelope", Message: "nil envelope"}
	}
	if envelope.ServerGUID == "" {
		return 0, &messages.InvalidArgumentError{Field: "serverGuid", Message: "empty server GUID"}
	}

	id := s.idCounter.Add(1)

	stored := cloneEnvelope(envelope)
	stored.ID = id
	stored.DestinationUUID = destinationUUID
	stored.DestinationDevice = destinationDevice

	key := deviceKey{uuid: destinationUUID, deviceID: destinationDevice}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.byDevice[key] = append(s.byDevice[key], stored)

	if stored.ServerGUID != "" {
		s.byGUID[stored.ServerGUID] = &guidIndex{
			destinationUUID: destinationUUID,
			deviceID:        destinationDevice,
		}
	}

	return id, nil
}

// GetMessagesForDevice retrieves all pending messages for a specific device.
func (s *MemoryMessageStore) GetMessagesForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) ([]*messages.Envelope, error) {
	key := deviceKey{uuid: destinationUUID, deviceID: destinationDevice}

	s.mu.RLock()
	defer s.mu.RUnlock()

	envelopes := s.byDevice[key]
	result := make([]*messages.Envelope, len(envelopes))
	for i, env := range envelopes {
		result[i] = cloneEnvelope(env)
	}

	return result, nil
}

// HasMessagesForDevice reports whether the device has at least one
// pending envelope without materialising the envelope set.
func (s *MemoryMessageStore) HasMessagesForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) (bool, error) {
	key := deviceKey{uuid: destinationUUID, deviceID: destinationDevice}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byDevice[key]) > 0, nil
}

// Delete removes a specific message by destination UUID and server GUID.
func (s *MemoryMessageStore) Delete(_ context.Context, destinationUUID string, serverGUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx, exists := s.byGUID[serverGUID]
	if !exists {
		return &messages.MessageNotFoundError{ServerGUID: serverGUID}
	}

	if idx.destinationUUID != destinationUUID {
		return &messages.MessageNotFoundError{ServerGUID: serverGUID}
	}

	key := deviceKey{uuid: idx.destinationUUID, deviceID: idx.deviceID}
	envelopes := s.byDevice[key]

	for i, env := range envelopes {
		if env.ServerGUID == serverGUID {
			// Build a new slice to avoid mutating the backing array, which
			// would corrupt any concurrent reader holding a reference to the
			// original slice header.
			newSlice := make([]*messages.Envelope, 0, len(envelopes)-1)
			newSlice = append(newSlice, envelopes[:i]...)
			newSlice = append(newSlice, envelopes[i+1:]...)
			s.byDevice[key] = newSlice
			delete(s.byGUID, serverGUID)
			return nil
		}
	}

	delete(s.byGUID, serverGUID)
	return &messages.MessageNotFoundError{ServerGUID: serverGUID}
}

// DeleteForDevice removes all messages for a specific device.
func (s *MemoryMessageStore) DeleteForDevice(_ context.Context, destinationUUID string, destinationDevice uint64) error {
	key := deviceKey{uuid: destinationUUID, deviceID: destinationDevice}

	s.mu.Lock()
	defer s.mu.Unlock()

	envelopes := s.byDevice[key]
	for _, env := range envelopes {
		if env.ServerGUID != "" {
			delete(s.byGUID, env.ServerGUID)
		}
	}
	delete(s.byDevice, key)

	return nil
}

// RemoveExpired is a no-op for the memory backend: envelopes carry no
// expires_at field today, so there is nothing to sweep. The method exists to
// satisfy [messages.MessageStore] and lets the sweep worker run uniformly
// against every backend.
func (s *MemoryMessageStore) RemoveExpired(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

// DeleteForAccount removes all messages for an entire account.
func (s *MemoryMessageStore) DeleteForAccount(_ context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, envelopes := range s.byDevice {
		if key.uuid == uuid {
			for _, env := range envelopes {
				if env.ServerGUID != "" {
					delete(s.byGUID, env.ServerGUID)
				}
			}
			delete(s.byDevice, key)
		}
	}

	return nil
}

// cloneEnvelope returns a deep copy of an envelope.
func cloneEnvelope(e *messages.Envelope) *messages.Envelope {
	clone := *e
	clone.Content = cloneBytes(e.Content)
	clone.ReportSpamToken = cloneBytes(e.ReportSpamToken)
	return &clone
}
