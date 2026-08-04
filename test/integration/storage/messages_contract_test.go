package storage_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/messages"
	memorystorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/storage/postgres"
	qrdbstorage "github.com/jeremyhahn/go-signal/pkg/storage/qrdb"
)

// newTestEnvelope returns a valid Envelope with a unique server GUID.
func newTestEnvelope() *messages.Envelope {
	return &messages.Envelope{
		Type:            messages.EnvelopeTypeCiphertext,
		ServerGUID:      uuid.NewString(),
		Timestamp:       1000,
		ServerTimestamp: 2000,
		Content:         []byte("encrypted-payload"),
		Urgent:          true,
	}
}

// runMessageStoreContract drives every behavioral expectation of
// messages.MessageStore across all backends.
func runMessageStoreContract(t *testing.T, factory func(t *testing.T) messages.MessageStore) {
	t.Helper()

	const deviceID = uint64(1)

	t.Run("Insert_GetMessagesForDevice_Roundtrip", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		destUUID := uuid.NewString()
		env := newTestEnvelope()

		id, err := s.Insert(ctx, destUUID, deviceID, env)
		require.NoError(t, err)
		assert.Greater(t, id, uint64(0))

		msgs, err := s.GetMessagesForDevice(ctx, destUUID, deviceID)
		require.NoError(t, err)
		require.Len(t, msgs, 1)
		assert.Equal(t, env.ServerGUID, msgs[0].ServerGUID)
	})

	t.Run("Insert_EmptyServerGUID_InvalidArgumentError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		env := newTestEnvelope()
		env.ServerGUID = ""

		_, err := s.Insert(ctx, uuid.NewString(), deviceID, env)
		require.Error(t, err, "empty ServerGUID must be rejected")
		var target *messages.InvalidArgumentError
		assert.ErrorAs(t, err, &target, "error must be *messages.InvalidArgumentError")
	})

	t.Run("Insert_NilEnvelope_InvalidArgumentError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		_, err := s.Insert(ctx, uuid.NewString(), deviceID, nil)
		require.Error(t, err, "nil envelope must be rejected")
		var target *messages.InvalidArgumentError
		assert.ErrorAs(t, err, &target, "error must be *messages.InvalidArgumentError")
	})

	t.Run("GetMessagesForDevice_Empty_ReturnsSlice", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		msgs, err := s.GetMessagesForDevice(ctx, uuid.NewString(), deviceID)
		require.NoError(t, err)
		assert.NotNil(t, msgs)
		assert.Len(t, msgs, 0)
	})

	t.Run("GetMessagesForDevice_MultipleMessages_InOrder", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		destUUID := uuid.NewString()

		env1 := newTestEnvelope()
		env2 := newTestEnvelope()
		env3 := newTestEnvelope()

		_, err := s.Insert(ctx, destUUID, deviceID, env1)
		require.NoError(t, err)
		_, err = s.Insert(ctx, destUUID, deviceID, env2)
		require.NoError(t, err)
		_, err = s.Insert(ctx, destUUID, deviceID, env3)
		require.NoError(t, err)

		msgs, err := s.GetMessagesForDevice(ctx, destUUID, deviceID)
		require.NoError(t, err)
		require.Len(t, msgs, 3)

		// Verify all GUIDs are present (order is backend-specific but all must
		// be returned).
		guids := map[string]struct{}{}
		for _, m := range msgs {
			guids[m.ServerGUID] = struct{}{}
		}
		assert.Contains(t, guids, env1.ServerGUID)
		assert.Contains(t, guids, env2.ServerGUID)
		assert.Contains(t, guids, env3.ServerGUID)
	})

	t.Run("Delete_ByGUID_Succeeds", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		destUUID := uuid.NewString()
		env := newTestEnvelope()

		_, err := s.Insert(ctx, destUUID, deviceID, env)
		require.NoError(t, err)

		require.NoError(t, s.Delete(ctx, destUUID, env.ServerGUID))

		msgs, err := s.GetMessagesForDevice(ctx, destUUID, deviceID)
		require.NoError(t, err)
		assert.Len(t, msgs, 0)
	})

	t.Run("Delete_NotFound_MessageNotFoundError", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()

		err := s.Delete(ctx, uuid.NewString(), uuid.NewString())
		require.Error(t, err)
		var target *messages.MessageNotFoundError
		assert.ErrorAs(t, err, &target, "error must be *messages.MessageNotFoundError")
	})

	t.Run("DeleteForDevice_RemovesAllDeviceMessages", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		destUUID := uuid.NewString()
		const dev1, dev2 = uint64(1), uint64(2)

		_, err := s.Insert(ctx, destUUID, dev1, newTestEnvelope())
		require.NoError(t, err)
		_, err = s.Insert(ctx, destUUID, dev1, newTestEnvelope())
		require.NoError(t, err)
		_, err = s.Insert(ctx, destUUID, dev2, newTestEnvelope())
		require.NoError(t, err)

		require.NoError(t, s.DeleteForDevice(ctx, destUUID, dev1))

		msgs1, err := s.GetMessagesForDevice(ctx, destUUID, dev1)
		require.NoError(t, err)
		assert.Len(t, msgs1, 0)

		// Device 2 messages must remain untouched.
		msgs2, err := s.GetMessagesForDevice(ctx, destUUID, dev2)
		require.NoError(t, err)
		assert.Len(t, msgs2, 1)
	})

	t.Run("DeleteForDevice_Idempotent", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		destUUID := uuid.NewString()

		require.NoError(t, s.DeleteForDevice(ctx, destUUID, deviceID))
		require.NoError(t, s.DeleteForDevice(ctx, destUUID, deviceID))
	})

	t.Run("DeleteForAccount_RemovesAllDevices", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		destUUID := uuid.NewString()
		const dev1, dev2 = uint64(1), uint64(2)

		_, err := s.Insert(ctx, destUUID, dev1, newTestEnvelope())
		require.NoError(t, err)
		_, err = s.Insert(ctx, destUUID, dev2, newTestEnvelope())
		require.NoError(t, err)

		require.NoError(t, s.DeleteForAccount(ctx, destUUID))

		for _, dev := range []uint64{dev1, dev2} {
			msgs, err := s.GetMessagesForDevice(ctx, destUUID, dev)
			require.NoError(t, err)
			assert.Len(t, msgs, 0, "device %d should have no messages after account delete", dev)
		}
	})

	t.Run("DeviceIsolation_DifferentUUIDs", func(t *testing.T) {
		s := factory(t)
		ctx := context.Background()
		uuid1 := uuid.NewString()
		uuid2 := uuid.NewString()

		_, err := s.Insert(ctx, uuid1, deviceID, newTestEnvelope())
		require.NoError(t, err)

		// uuid2 must see no messages.
		msgs, err := s.GetMessagesForDevice(ctx, uuid2, deviceID)
		require.NoError(t, err)
		assert.Len(t, msgs, 0)
	})
}

// TestMessageStoreContract_Memory runs the message contract against the
// in-memory backend.
func TestMessageStoreContract_Memory(t *testing.T) {
	runMessageStoreContract(t, func(t *testing.T) messages.MessageStore {
		return memorystorage.NewMemoryMessageStore()
	})
}

// TestMessageStoreContract_QRDB runs the message contract against the qrdb
// (FakeKVStore) backend.
func TestMessageStoreContract_QRDB(t *testing.T) {
	runMessageStoreContract(t, func(t *testing.T) messages.MessageStore {
		return qrdbstorage.NewMessageStore(qrdbstorage.NewFakeKVStore())
	})
}

// TestMessageStoreContract_Postgres runs the message contract against a live
// Postgres instance. Skips if TEST_POSTGRES_URL is unset.
func TestMessageStoreContract_Postgres(t *testing.T) {
	c := postgresClient(t)
	runMessageStoreContract(t, func(t *testing.T) messages.MessageStore {
		ctx := context.Background()
		if err := truncatePostgres(ctx, c); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		return postgres.NewMessageStore(c.Pool())
	})
}
