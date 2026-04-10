package messages

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

func newTestMessageStore() (*KVMessageStore, store.KVClient) {
	kv := store.NewMemoryKVClient()
	return NewKVMessageStore(kv), kv
}

func testEnvelope(serverGUID string) *Envelope {
	return &Envelope{
		Type:              EnvelopeTypeCiphertext,
		SourceUUID:        "sender-uuid",
		SourceDevice:      1,
		DestinationUUID:   "dest-uuid",
		DestinationDevice: 1,
		Timestamp:         1000,
		ServerTimestamp:   1001,
		Content:           []byte("encrypted-content"),
		ServerGUID:        serverGUID,
		Urgent:            true,
	}
}

// --- NewKVMessageStore tests ---

func TestNewKVMessageStore(t *testing.T) {
	s, _ := newTestMessageStore()
	require.NotNil(t, s)
}

func TestNewKVMessageStore_KVAssigned(t *testing.T) {
	kv := store.NewMemoryKVClient()
	s := NewKVMessageStore(kv)
	assert.NotNil(t, s.kv)
}

// --- Insert tests ---

func TestKVMessageStore_Insert_Success(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	env := testEnvelope("guid-1")
	id, err := s.Insert(ctx, "dest-uuid", 1, env)
	require.NoError(t, err)
	assert.NotZero(t, id)
	assert.Equal(t, id, env.ID)
}

func TestKVMessageStore_Insert_IncrementsID(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	id1, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)

	id2, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-2"))
	require.NoError(t, err)

	assert.Greater(t, id2, id1)
}

func TestKVMessageStore_Insert_MultipleDevices(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)

	_, err = s.Insert(ctx, "dest-uuid", 2, testEnvelope("guid-2"))
	require.NoError(t, err)

	msgs1, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	assert.Len(t, msgs1, 1)

	msgs2, err := s.GetMessagesForDevice(ctx, "dest-uuid", 2)
	require.NoError(t, err)
	assert.Len(t, msgs2, 1)
}

// --- GetMessagesForDevice tests ---

func TestKVMessageStore_GetMessagesForDevice_Success(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-2"))
	require.NoError(t, err)

	msgs, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	assert.Len(t, msgs, 2)
}

func TestKVMessageStore_GetMessagesForDevice_Empty(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	msgs, err := s.GetMessagesForDevice(ctx, "nonexistent", 1)
	require.NoError(t, err)
	assert.Empty(t, msgs)
}

func TestKVMessageStore_GetMessagesForDevice_PreservesFields(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	env := testEnvelope("guid-1")
	env.Story = true
	env.ReportSpamToken = []byte("spam-token")
	_, err := s.Insert(ctx, "dest-uuid", 1, env)
	require.NoError(t, err)

	msgs, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "guid-1", msgs[0].ServerGUID)
	assert.Equal(t, EnvelopeTypeCiphertext, msgs[0].Type)
	assert.True(t, msgs[0].Urgent)
	assert.True(t, msgs[0].Story)
	assert.Equal(t, []byte("spam-token"), msgs[0].ReportSpamToken)
	assert.Equal(t, []byte("encrypted-content"), msgs[0].Content)
}

func TestKVMessageStore_GetMessagesForDevice_IsolatedByAccount(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "uuid-1", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "uuid-2", 1, testEnvelope("guid-2"))
	require.NoError(t, err)

	msgs, err := s.GetMessagesForDevice(ctx, "uuid-1", 1)
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
	assert.Equal(t, "guid-1", msgs[0].ServerGUID)
}

// --- Delete tests ---

func TestKVMessageStore_Delete_Success(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)

	err = s.Delete(ctx, "dest-uuid", "guid-1")
	require.NoError(t, err)

	msgs, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	assert.Empty(t, msgs)
}

func TestKVMessageStore_Delete_NotFound(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	err := s.Delete(ctx, "dest-uuid", "nonexistent")
	require.Error(t, err)

	var target *MessageNotFoundError
	require.True(t, errors.As(err, &target))
	assert.Equal(t, "nonexistent", target.ServerGUID)
}

func TestKVMessageStore_Delete_DoesNotAffectOtherMessages(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-2"))
	require.NoError(t, err)

	require.NoError(t, s.Delete(ctx, "dest-uuid", "guid-1"))

	msgs, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "guid-2", msgs[0].ServerGUID)
}

// --- DeleteForDevice tests ---

func TestKVMessageStore_DeleteForDevice_Success(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-2"))
	require.NoError(t, err)

	err = s.DeleteForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)

	msgs, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	assert.Empty(t, msgs)
}

func TestKVMessageStore_DeleteForDevice_DoesNotAffectOtherDevices(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "dest-uuid", 2, testEnvelope("guid-2"))
	require.NoError(t, err)

	require.NoError(t, s.DeleteForDevice(ctx, "dest-uuid", 1))

	msgs, err := s.GetMessagesForDevice(ctx, "dest-uuid", 2)
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
}

func TestKVMessageStore_DeleteForDevice_EmptyDevice(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	err := s.DeleteForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
}

// --- DeleteForAccount tests ---

func TestKVMessageStore_DeleteForAccount_Success(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "dest-uuid", 2, testEnvelope("guid-2"))
	require.NoError(t, err)

	err = s.DeleteForAccount(ctx, "dest-uuid")
	require.NoError(t, err)

	msgs1, err := s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.NoError(t, err)
	assert.Empty(t, msgs1)

	msgs2, err := s.GetMessagesForDevice(ctx, "dest-uuid", 2)
	require.NoError(t, err)
	assert.Empty(t, msgs2)
}

func TestKVMessageStore_DeleteForAccount_DoesNotAffectOtherAccounts(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	_, err := s.Insert(ctx, "uuid-1", 1, testEnvelope("guid-1"))
	require.NoError(t, err)
	_, err = s.Insert(ctx, "uuid-2", 1, testEnvelope("guid-2"))
	require.NoError(t, err)

	require.NoError(t, s.DeleteForAccount(ctx, "uuid-1"))

	msgs, err := s.GetMessagesForDevice(ctx, "uuid-2", 1)
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
}

func TestKVMessageStore_DeleteForAccount_EmptyAccount(t *testing.T) {
	s, _ := newTestMessageStore()
	ctx := context.Background()

	err := s.DeleteForAccount(ctx, "nonexistent")
	require.NoError(t, err)
}

// --- Error injection tests ---

func TestKVMessageStore_Insert_PutError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.PutErr = errors.New("put failure")
	s := NewKVMessageStore(fkv)

	_, err := s.Insert(context.Background(), "dest-uuid", 1, testEnvelope("guid-1"))
	require.Error(t, err)
	assert.Equal(t, "put failure", err.Error())
}

func TestKVMessageStore_GetMessagesForDevice_ListError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.ListErr = errors.New("list failure")
	s := NewKVMessageStore(fkv)

	_, err := s.GetMessagesForDevice(context.Background(), "dest-uuid", 1)
	require.Error(t, err)
	assert.Equal(t, "list failure", err.Error())
}

func TestKVMessageStore_GetMessagesForDevice_GetError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVMessageStore(fkv)
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)

	fkv.GetErr = errors.New("get failure")
	_, err = s.GetMessagesForDevice(ctx, "dest-uuid", 1)
	require.Error(t, err)
	assert.Equal(t, "get failure", err.Error())
}

func TestKVMessageStore_Delete_ScanError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.ScanErr = errors.New("scan failure")
	s := NewKVMessageStore(fkv)

	err := s.Delete(context.Background(), "dest-uuid", "guid-1")
	require.Error(t, err)
	assert.Equal(t, "scan failure", err.Error())
}

func TestKVMessageStore_DeleteForDevice_ListError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.ListErr = errors.New("list failure")
	s := NewKVMessageStore(fkv)

	err := s.DeleteForDevice(context.Background(), "dest-uuid", 1)
	require.Error(t, err)
	assert.Equal(t, "list failure", err.Error())
}

func TestKVMessageStore_DeleteForAccount_ListError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	fkv.ListErr = errors.New("list failure")
	s := NewKVMessageStore(fkv)

	err := s.DeleteForAccount(context.Background(), "uuid-1")
	require.Error(t, err)
	assert.Equal(t, "list failure", err.Error())
}

func TestKVMessageStore_DeleteByPrefix_NonKNFDeleteError(t *testing.T) {
	fkv := store.NewFailingKVClient()
	s := NewKVMessageStore(fkv)
	ctx := context.Background()

	_, err := s.Insert(ctx, "dest-uuid", 1, testEnvelope("guid-1"))
	require.NoError(t, err)

	fkv.DeleteErr = errors.New("delete failure")
	err = s.DeleteForDevice(ctx, "dest-uuid", 1)
	require.Error(t, err)
	assert.Equal(t, "delete failure", err.Error())
}

// --- Interface compliance ---

func TestKVMessageStore_ImplementsMessageStore(t *testing.T) {
	var _ MessageStore = &KVMessageStore{}
}
