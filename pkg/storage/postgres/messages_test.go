package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/messages"
)

// newEnvelope builds a minimal valid Envelope for tests.
func newEnvelope(destinationUUID string, destinationDevice uint64) *messages.Envelope {
	return &messages.Envelope{
		Type:              messages.EnvelopeTypeCiphertext,
		ServerGUID:        uuid.NewString(),
		DestinationUUID:   destinationUUID,
		DestinationDevice: destinationDevice,
		Timestamp:         1_000_000,
		ServerTimestamp:   2_000_000,
		Content:           []byte("payload"),
	}
}

func TestMessages_Insert_GetMessagesForDevice_OrderPreserved(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	const device = uint64(1)

	want := make([]string, 3)
	for i := range want {
		env := newEnvelope(acct, device)
		want[i] = env.ServerGUID
		if _, err := s.Insert(ctx, acct, device, env); err != nil {
			t.Fatalf("Insert[%d]: %v", i, err)
		}
	}

	got, err := s.GetMessagesForDevice(ctx, acct, device)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d messages, got %d", len(want), len(got))
	}
	for i, env := range got {
		if env.ServerGUID != want[i] {
			t.Errorf("message[%d]: got GUID %q, want %q", i, env.ServerGUID, want[i])
		}
	}
}

func TestMessages_Insert_AssignsSeqToEnvelope(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	env := newEnvelope(acct, 1)

	seq, err := s.Insert(ctx, acct, 1, env)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if seq == 0 {
		t.Fatal("expected non-zero seq from Insert")
	}
	// The seq must have been written back to the struct.
	if env.ID != seq {
		t.Fatalf("envelope.ID = %d, want %d", env.ID, seq)
	}
}

func TestMessages_Insert_TwoDevices_IsolatedQueues(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	env1 := newEnvelope(acct, 1)
	env2 := newEnvelope(acct, 2)

	if _, err := s.Insert(ctx, acct, 1, env1); err != nil {
		t.Fatalf("Insert device 1: %v", err)
	}
	if _, err := s.Insert(ctx, acct, 2, env2); err != nil {
		t.Fatalf("Insert device 2: %v", err)
	}

	got1, err := s.GetMessagesForDevice(ctx, acct, 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice device 1: %v", err)
	}
	if len(got1) != 1 || got1[0].ServerGUID != env1.ServerGUID {
		t.Fatalf("device 1 returned unexpected messages: %v", got1)
	}

	got2, err := s.GetMessagesForDevice(ctx, acct, 2)
	if err != nil {
		t.Fatalf("GetMessagesForDevice device 2: %v", err)
	}
	if len(got2) != 1 || got2[0].ServerGUID != env2.ServerGUID {
		t.Fatalf("device 2 returned unexpected messages: %v", got2)
	}
}

func TestMessages_GetMessagesForDevice_Empty(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	got, err := s.GetMessagesForDevice(ctx, uuid.NewString(), 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice on empty queue: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty slice, got %d messages", len(got))
	}
}

func TestMessages_Delete_ByGUID_Works(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	env := newEnvelope(acct, 1)
	if _, err := s.Insert(ctx, acct, 1, env); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	if err := s.Delete(ctx, acct, env.ServerGUID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	got, err := s.GetMessagesForDevice(ctx, acct, 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 messages after delete, got %d", len(got))
	}
}

func TestMessages_Delete_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	err := s.Delete(ctx, uuid.NewString(), uuid.NewString())
	var nfe *messages.MessageNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected MessageNotFoundError, got %T: %v", err, err)
	}
}

func TestMessages_Delete_OnlyRemovesTargetMessage(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	env1 := newEnvelope(acct, 1)
	env2 := newEnvelope(acct, 1)

	for i, env := range []*messages.Envelope{env1, env2} {
		if _, err := s.Insert(ctx, acct, 1, env); err != nil {
			t.Fatalf("Insert[%d]: %v", i, err)
		}
	}

	if err := s.Delete(ctx, acct, env1.ServerGUID); err != nil {
		t.Fatalf("Delete env1: %v", err)
	}

	got, err := s.GetMessagesForDevice(ctx, acct, 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 1 || got[0].ServerGUID != env2.ServerGUID {
		t.Fatalf("expected only env2 to remain, got %+v", got)
	}
}

func TestMessages_DeleteForDevice_ClearsQueue(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	for i := 0; i < 3; i++ {
		if _, err := s.Insert(ctx, acct, 1, newEnvelope(acct, 1)); err != nil {
			t.Fatalf("Insert[%d]: %v", i, err)
		}
	}

	if err := s.DeleteForDevice(ctx, acct, 1); err != nil {
		t.Fatalf("DeleteForDevice: %v", err)
	}

	got, err := s.GetMessagesForDevice(ctx, acct, 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 messages after DeleteForDevice, got %d", len(got))
	}
}

func TestMessages_DeleteForDevice_DoesNotAffectOtherDevices(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	env1 := newEnvelope(acct, 1)
	env2 := newEnvelope(acct, 2)

	if _, err := s.Insert(ctx, acct, 1, env1); err != nil {
		t.Fatalf("Insert device 1: %v", err)
	}
	if _, err := s.Insert(ctx, acct, 2, env2); err != nil {
		t.Fatalf("Insert device 2: %v", err)
	}

	if err := s.DeleteForDevice(ctx, acct, 1); err != nil {
		t.Fatalf("DeleteForDevice device 1: %v", err)
	}

	// Device 2 must still have its message.
	got, err := s.GetMessagesForDevice(ctx, acct, 2)
	if err != nil {
		t.Fatalf("GetMessagesForDevice device 2: %v", err)
	}
	if len(got) != 1 || got[0].ServerGUID != env2.ServerGUID {
		t.Fatalf("expected device 2 message to survive, got %v", got)
	}
}

func TestMessages_DeleteForAccount_ClearsAllDevices(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct := uuid.NewString()
	for _, device := range []uint64{1, 2, 3} {
		if _, err := s.Insert(ctx, acct, device, newEnvelope(acct, device)); err != nil {
			t.Fatalf("Insert device %d: %v", device, err)
		}
	}

	if err := s.DeleteForAccount(ctx, acct); err != nil {
		t.Fatalf("DeleteForAccount: %v", err)
	}

	for _, device := range []uint64{1, 2, 3} {
		got, err := s.GetMessagesForDevice(ctx, acct, device)
		if err != nil {
			t.Fatalf("GetMessagesForDevice device %d: %v", device, err)
		}
		if len(got) != 0 {
			t.Fatalf("device %d: expected 0 messages, got %d", device, len(got))
		}
	}
}

func TestMessages_DeleteForAccount_DoesNotAffectOtherAccounts(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	acct1 := uuid.NewString()
	acct2 := uuid.NewString()
	env1 := newEnvelope(acct1, 1)
	env2 := newEnvelope(acct2, 1)

	if _, err := s.Insert(ctx, acct1, 1, env1); err != nil {
		t.Fatalf("Insert acct1: %v", err)
	}
	if _, err := s.Insert(ctx, acct2, 1, env2); err != nil {
		t.Fatalf("Insert acct2: %v", err)
	}

	if err := s.DeleteForAccount(ctx, acct1); err != nil {
		t.Fatalf("DeleteForAccount acct1: %v", err)
	}

	got, err := s.GetMessagesForDevice(ctx, acct2, 1)
	if err != nil {
		t.Fatalf("GetMessagesForDevice acct2: %v", err)
	}
	if len(got) != 1 || got[0].ServerGUID != env2.ServerGUID {
		t.Fatalf("acct2 message should survive deletion of acct1, got %v", got)
	}
}

func TestMessages_Insert_NilEnvelope_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())

	_, err := s.Insert(context.Background(), uuid.NewString(), 1, nil)
	var iae *messages.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// TestMessages_DeleteForDevice_NoRows verifies DeleteForDevice on an empty
// queue returns nil (idempotent — no error for zero rows affected).
func TestMessages_DeleteForDevice_NoRows_Succeeds(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())

	if err := s.DeleteForDevice(context.Background(), uuid.NewString(), 1); err != nil {
		t.Fatalf("DeleteForDevice on empty queue: %v", err)
	}
}

func TestMessages_Delete_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	c.Close()

	err := s.Delete(context.Background(), uuid.NewString(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *messages.MessageNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not MessageNotFoundError")
	}
}

func TestMessages_Insert_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	c.Close()

	env := newEnvelope(uuid.NewString(), 1)
	_, err := s.Insert(context.Background(), uuid.NewString(), 1, env)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestMessages_DeleteForDevice_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	c.Close()

	err := s.DeleteForDevice(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

// TestMessages_DeleteForAccount_NoRows verifies DeleteForAccount on an account
// with no messages returns nil (idempotent).
func TestMessages_DeleteForAccount_NoRows_Succeeds(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())

	if err := s.DeleteForAccount(context.Background(), uuid.NewString()); err != nil {
		t.Fatalf("DeleteForAccount on empty account: %v", err)
	}
}

func TestMessages_DeleteForAccount_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	c.Close()

	err := s.DeleteForAccount(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestMessages_GetMessagesForDevice_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	c.Close()

	_, err := s.GetMessagesForDevice(context.Background(), uuid.NewString(), 1)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

func TestMessages_Insert_EmptyServerGUID_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	env := newEnvelope(uuid.NewString(), 1)
	env.ServerGUID = ""

	_, err := s.Insert(ctx, uuid.NewString(), 1, env)
	var iae *messages.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

// TestMessages_GetMessagesForDevice_CorruptedData_UnmarshalError exercises the
// json.Unmarshal error branch in GetMessagesForDevice (messages.go:93-95).
// A row is inserted via raw SQL whose envelope column contains valid JSONB but
// with a "content" field set to an invalid base64 string (Envelope.Content is
// []byte, encoded as base64 in JSON), so json.Unmarshal fails even though the
// row exists and is scanned successfully.
func TestMessages_GetMessagesForDevice_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	accountUUID := uuid.NewString()
	deviceID := uint64(1)
	serverGUID := uuid.NewString()

	// The messages table has no FK on account_uuid so no seed is needed.
	_, err := c.Pool().Exec(ctx,
		`INSERT INTO messages (account_uuid, device_id, server_guid, envelope)
		 VALUES ($1, $2, $3, $4::jsonb)`,
		accountUUID,
		deviceID,
		serverGUID,
		`{"content":"!!! not valid base64 !!!","serverGuid":"`+serverGUID+`"}`,
	)
	if err != nil {
		t.Fatalf("raw insert corrupted message: %v", err)
	}

	_, err = s.GetMessagesForDevice(ctx, accountUUID, deviceID)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
}

// TestMessages_RemoveExpired_DeletesPastCutoffOnly seeds rows with
// expires_at in the past and future, runs RemoveExpired, and verifies that
// only the past rows are deleted. The Insert path doesn't currently set
// expires_at, so we write rows directly via the pool to exercise the sweep.
func TestMessages_RemoveExpired_DeletesPastCutoffOnly(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	accountUUID := uuid.NewString()
	deviceID := uint64(1)

	// Insert three rows: one well-past, one just-past, one in the future.
	now := time.Now().UTC()
	rows := []struct {
		guid      string
		expiresAt time.Time
	}{
		{uuid.NewString(), now.Add(-2 * time.Hour)},
		{uuid.NewString(), now.Add(-1 * time.Minute)},
		{uuid.NewString(), now.Add(1 * time.Hour)},
	}
	for _, r := range rows {
		if _, err := c.Pool().Exec(ctx,
			`INSERT INTO messages (account_uuid, device_id, server_guid, envelope, expires_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			accountUUID, deviceID, r.guid, []byte(`{}`), r.expiresAt,
		); err != nil {
			t.Fatalf("seed insert: %v", err)
		}
	}

	n, err := s.RemoveExpired(ctx, now)
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if n != 2 {
		t.Errorf("removed = %d; want 2", n)
	}

	// The future-dated row must remain.
	var remaining int
	if err := c.Pool().QueryRow(ctx,
		`SELECT count(*) FROM messages WHERE account_uuid = $1`, accountUUID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining rows = %d; want 1", remaining)
	}
}

// TestMessages_RemoveExpired_NullExpiresAtIgnored documents that rows
// without an expires_at (the current default for envelope inserts) are
// never swept regardless of the cutoff.
func TestMessages_RemoveExpired_NullExpiresAtIgnored(t *testing.T) {
	c := newTestClient(t)
	s := NewMessageStore(c.Pool())
	ctx := context.Background()

	accountUUID := uuid.NewString()
	if _, err := s.Insert(ctx, accountUUID, 1, newEnvelope(accountUUID, 1)); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	n, err := s.RemoveExpired(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("RemoveExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("removed = %d; want 0 (NULL expires_at must be retained)", n)
	}
}
