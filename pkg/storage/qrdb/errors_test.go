package qrdb

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/devices"
)

// faultyKV is a KVStore that returns injected errors on targeted operations.
// A zero-valued faultyKV forwards everything to an embedded FakeKVStore.
type faultyKV struct {
	*FakeKVStore
	putErr    error
	getErr    error
	deleteErr error
	existsErr error
}

func (f *faultyKV) Put(ctx context.Context, key string, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.FakeKVStore.Put(ctx, key, value)
}

func (f *faultyKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.FakeKVStore.Get(ctx, key)
}

func (f *faultyKV) Delete(ctx context.Context, key string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	return f.FakeKVStore.Delete(ctx, key)
}

func (f *faultyKV) Exists(ctx context.Context, key string) (bool, error) {
	if f.existsErr != nil {
		return false, f.existsErr
	}
	return f.FakeKVStore.Exists(ctx, key)
}

// ---- AccountStore error propagation ----

func TestAccountStore_Create_ExistsError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("backend down")
	s := NewAccountStore(&faultyKV{FakeKVStore: NewFakeKVStore(), existsErr: boom})

	err := s.Create(context.Background(), newAccount("u1", "+15551111111"))
	if err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("expected wrapped exists error, got %v", err)
	}
}

func TestAccountStore_Create_PutPrimaryError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("write failure")
	s := NewAccountStore(&faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom})

	err := s.Create(context.Background(), newAccount("u1", "+15551111111"))
	if err == nil || !strings.Contains(err.Error(), "put primary") {
		t.Fatalf("expected wrapped put error, got %v", err)
	}
}

func TestAccountStore_Get_BackendError_Propagated(t *testing.T) {
	t.Parallel()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewAccountStore(kv)

	// Write a valid record through the underlying fake.
	if err := s.Create(context.Background(), newAccount("u1", "+15551111111")); err != nil {
		t.Fatal(err)
	}

	// Now arm the fault.
	kv.getErr = errors.New("read failure")

	_, err := s.Get(context.Background(), "u1")
	if err == nil || !strings.Contains(err.Error(), "get") {
		t.Fatalf("expected wrapped get error, got %v", err)
	}
}

func TestAccountStore_Get_CorruptJSON_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()

	// Seed the raw store with non-JSON bytes at a valid key.
	_ = kv.Put(ctx, accountKey("u1"), []byte("not json"))

	s := NewAccountStore(kv)
	_, err := s.Get(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestAccountStore_Update_DeleteOldMirrorFails_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewAccountStore(kv)

	acct := newAccount("u1", "+15551111111")
	if err := s.Create(ctx, acct); err != nil {
		t.Fatal(err)
	}

	// Arm the fault so Delete on the mirror will fail during number change.
	kv.deleteErr = errors.New("delete failure")

	updated := *acct
	updated.Version = 1
	updated.Number = "+15552222222"
	err := s.Update(ctx, &updated)
	if err == nil || !strings.Contains(err.Error(), "delete old mirror") {
		t.Fatalf("expected wrapped delete-mirror error, got %v", err)
	}
}

func TestAccountStore_Delete_MirrorDeleteFails_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := &faultyKV{FakeKVStore: NewFakeKVStore()}
	s := NewAccountStore(kv)

	if err := s.Create(ctx, newAccount("u1", "+15551111111")); err != nil {
		t.Fatal(err)
	}
	kv.deleteErr = errors.New("delete failure")

	err := s.Delete(ctx, "u1")
	if err == nil || !strings.Contains(err.Error(), "delete mirror") {
		t.Fatalf("expected wrapped delete-mirror error, got %v", err)
	}
}

// ---- ProvisioningStore error propagation ----

func TestProvisioningStore_Store_BackendError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("backend down")
	s := NewProvisioningStore(&faultyKV{FakeKVStore: NewFakeKVStore(), putErr: boom})

	err := s.StoreSession(context.Background(), newSession("ABC"))
	if err == nil || !strings.Contains(err.Error(), "put") {
		t.Fatalf("expected wrapped put error, got %v", err)
	}
}

func TestProvisioningStore_Get_BackendError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("read failure")
	s := NewProvisioningStore(&faultyKV{FakeKVStore: NewFakeKVStore(), getErr: boom})

	_, err := s.GetSession(context.Background(), "ABC")
	if err == nil || !strings.Contains(err.Error(), "get") {
		t.Fatalf("expected wrapped get error, got %v", err)
	}
}

func TestProvisioningStore_Get_CorruptJSON_Propagated(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kv := NewFakeKVStore()
	_ = kv.Put(ctx, provisioningKey("ABC"), []byte("not json"))

	s := NewProvisioningStore(kv)
	_, err := s.GetSession(ctx, "ABC")
	if err == nil || !strings.Contains(err.Error(), "unmarshal") {
		t.Fatalf("expected unmarshal error, got %v", err)
	}
}

func TestProvisioningStore_Delete_BackendError_Propagated(t *testing.T) {
	t.Parallel()
	boom := errors.New("delete failure")
	s := NewProvisioningStore(&faultyKV{FakeKVStore: NewFakeKVStore(), deleteErr: boom})

	err := s.DeleteSession(context.Background(), "ABC")
	if err == nil || !strings.Contains(err.Error(), "delete") {
		t.Fatalf("expected wrapped delete error, got %v", err)
	}
}

// ---- AccountStore sanity: make sure the fault-injection helper interacts
// with domain error types correctly (no accidental wrapping). ----

func TestAccountStore_Update_DoesNotWrapConflictError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551111111")); err != nil {
		t.Fatal(err)
	}

	stale := newAccount("u1", "+15551111111")
	stale.Version = 99
	err := s.Update(ctx, stale)
	var vce *accounts.VersionConflictError
	if !errors.As(err, &vce) {
		t.Fatalf("expected raw VersionConflictError (not wrapped), got %T: %v", err, err)
	}
}

func TestProvisioningStore_Get_DoesNotWrapInvalidProvisioningCodeError(t *testing.T) {
	t.Parallel()
	s := NewProvisioningStore(NewFakeKVStore())

	_, err := s.GetSession(context.Background(), "absent")
	var ipce *devices.InvalidProvisioningCodeError
	if !errors.As(err, &ipce) {
		t.Fatalf("expected raw InvalidProvisioningCodeError, got %T: %v", err, err)
	}
}
