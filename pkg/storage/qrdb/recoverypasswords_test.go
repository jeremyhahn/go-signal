package qrdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/registration/recoverypassword"
)

func TestRecoveryPasswordStore_PutGetRoundTrip(t *testing.T) {
	s := NewRecoveryPasswordStore(NewFakeKVStore())
	ctx := context.Background()

	hash := &recoverypassword.SaltedTokenHash{Hash: "2.deadbeef", Salt: "abcdef"}
	if err := s.Put(ctx, "pni-1", hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "pni-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Hash != hash.Hash || got.Salt != hash.Salt {
		t.Fatalf("Get returned %+v; want %+v", got, hash)
	}
}

func TestRecoveryPasswordStore_GetNotFound(t *testing.T) {
	s := NewRecoveryPasswordStore(NewFakeKVStore())
	_, err := s.Get(context.Background(), "missing")
	var nf *recoverypassword.NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("expected *NotFoundError, got %T", err)
	}
}

func TestRecoveryPasswordStore_GetExpiredEvicts(t *testing.T) {
	kv := NewFakeKVStore()
	s := NewRecoveryPasswordStore(kv)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })

	hash := &recoverypassword.SaltedTokenHash{Hash: "2.x", Salt: "y"}
	if err := s.Put(ctx, "pni-e", hash, now.Add(time.Minute)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	s.SetClock(func() time.Time { return now.Add(time.Hour) })
	if _, err := s.Get(ctx, "pni-e"); err == nil {
		t.Fatal("expected NotFoundError for expired entry")
	}

	// The expired row was deleted on read. Verify directly via the KV.
	exists, err := kv.Exists(ctx, recoveryPasswordKeyPrefix+"pni-e")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected expired row to be removed by Get")
	}
}

func TestRecoveryPasswordStore_PutNilRejected(t *testing.T) {
	s := NewRecoveryPasswordStore(NewFakeKVStore())
	if err := s.Put(context.Background(), "pni", nil, time.Now()); err == nil {
		t.Fatal("expected error for nil hash")
	}
}

func TestRecoveryPasswordStore_Delete(t *testing.T) {
	s := NewRecoveryPasswordStore(NewFakeKVStore())
	ctx := context.Background()

	if err := s.Delete(ctx, "ghost"); err != nil {
		t.Fatalf("Delete on missing: %v", err)
	}

	if err := s.Put(ctx, "pni-d", &recoverypassword.SaltedTokenHash{Hash: "2.d", Salt: "s"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(ctx, "pni-d"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "pni-d"); err == nil {
		t.Fatal("expected NotFoundError after Delete")
	}
}

// TestRecoveryPasswordStore_GetCorruptJSON verifies that an unparseable
// stored value bubbles up as a wrapped error rather than NotFound.
func TestRecoveryPasswordStore_GetCorruptJSON(t *testing.T) {
	kv := NewFakeKVStore()
	if err := kv.Put(context.Background(), recoveryPasswordKeyPrefix+"pni-c", []byte("not-json")); err != nil {
		t.Fatalf("seed bad value: %v", err)
	}
	s := NewRecoveryPasswordStore(kv)

	_, err := s.Get(context.Background(), "pni-c")
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
	var nf *recoverypassword.NotFoundError
	if errors.As(err, &nf) {
		t.Fatal("expected non-NotFoundError for corrupt JSON")
	}
}

// TestRecoveryPasswordStore_PutKVError ensures Put surfaces underlying KV
// failures rather than swallowing them.
func TestRecoveryPasswordStore_PutKVError(t *testing.T) {
	kv := &errKV{putErr: errors.New("kv-down")}
	s := NewRecoveryPasswordStore(kv)
	if err := s.Put(context.Background(), "pni",
		&recoverypassword.SaltedTokenHash{Hash: "2.x", Salt: "s"},
		time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected Put to surface KV error")
	}
}

func TestRecoveryPasswordStore_GetKVError(t *testing.T) {
	kv := &errKV{getErr: errors.New("kv-down")}
	s := NewRecoveryPasswordStore(kv)
	if _, err := s.Get(context.Background(), "pni"); err == nil {
		t.Fatal("expected Get to surface KV error")
	}
}

func TestRecoveryPasswordStore_DeleteKVError(t *testing.T) {
	kv := &errKV{delErr: errors.New("kv-down")}
	s := NewRecoveryPasswordStore(kv)
	if err := s.Delete(context.Background(), "pni"); err == nil {
		t.Fatal("expected Delete to surface KV error")
	}
}

func TestRecoveryPasswordStore_SetClockNil_NoOp(t *testing.T) {
	s := NewRecoveryPasswordStore(NewFakeKVStore())
	s.SetClock(nil)
	if s.now == nil {
		t.Fatal("expected default clock to remain after SetClock(nil)")
	}
}

// errKV is a KVStore that returns canned errors for the tested operations.
// It only implements the methods the recovery-password store calls; other
// methods return nil/empty so the type satisfies the interface.
type errKV struct {
	getErr error
	putErr error
	delErr error
}

func (k *errKV) Put(_ context.Context, _ string, _ []byte) error    { return k.putErr }
func (k *errKV) Get(_ context.Context, _ string) ([]byte, error)    { return nil, k.getErr }
func (k *errKV) Delete(_ context.Context, _ string) error           { return k.delErr }
func (k *errKV) Exists(_ context.Context, _ string) (bool, error)   { return false, nil }
func (k *errKV) List(_ context.Context, _ string) ([]string, error) { return nil, nil }
func (k *errKV) Scan(_ context.Context, _ string, _ func(string, []byte) error) error {
	return nil
}
