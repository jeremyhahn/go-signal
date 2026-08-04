package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/store"
)

func TestKVClientAdapter_GetMissingReturnsNilNil(t *testing.T) {
	a := NewKVClientAdapter(store.NewMemoryKVClient())
	v, err := a.Get(context.Background(), "absent")
	if err != nil {
		t.Fatalf("want nil err on missing key, got %v", err)
	}
	if v != nil {
		t.Fatalf("want nil value on missing key, got %x", v)
	}
}

func TestKVClientAdapter_GetPropagatesOtherErrors(t *testing.T) {
	want := errors.New("boom")
	a := NewKVClientAdapter(&adapterErrKV{err: want})
	if _, err := a.Get(context.Background(), "k"); !errors.Is(err, want) {
		t.Fatalf("error not propagated: %v", err)
	}
}

func TestKVClientAdapter_PutGetRoundTrip(t *testing.T) {
	a := NewKVClientAdapter(store.NewMemoryKVClient())
	ctx := context.Background()
	if err := a.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, err := a.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(v) != "v" {
		t.Errorf("got %q want %q", v, "v")
	}
}

func TestKVClientAdapter_DeleteMissingIsNotError(t *testing.T) {
	a := NewKVClientAdapter(store.NewMemoryKVClient())
	if err := a.Delete(context.Background(), "absent"); err != nil {
		t.Errorf("Delete of missing key returned %v, want nil", err)
	}
}

func TestKVClientAdapter_DeletePropagatesOtherErrors(t *testing.T) {
	want := errors.New("boom")
	a := NewKVClientAdapter(&adapterErrKV{err: want})
	if err := a.Delete(context.Background(), "k"); !errors.Is(err, want) {
		t.Fatalf("error not propagated: %v", err)
	}
}

func TestKVClientAdapter_ScanListExists(t *testing.T) {
	kv := store.NewMemoryKVClient()
	a := NewKVClientAdapter(kv)
	ctx := context.Background()
	_ = a.Put(ctx, "p:a", []byte("1"))
	_ = a.Put(ctx, "p:b", []byte("2"))
	_ = a.Put(ctx, "q:c", []byte("3"))

	keys, err := a.List(ctx, "p:")
	if err != nil || len(keys) != 2 {
		t.Errorf("List: keys=%v err=%v", keys, err)
	}

	count := 0
	if err := a.Scan(ctx, "p:", func(k string, v []byte) error { count++; return nil }); err != nil {
		t.Errorf("Scan: %v", err)
	}
	if count != 2 {
		t.Errorf("Scan count = %d, want 2", count)
	}

	exists, err := a.Exists(ctx, "p:a")
	if err != nil || !exists {
		t.Errorf("Exists p:a: %v %v", exists, err)
	}
	exists, err = a.Exists(ctx, "absent")
	if err != nil || exists {
		t.Errorf("Exists absent: %v %v", exists, err)
	}
}

// adapterErrKV is a store.KVClient stub that returns the configured error
// from every method — used to verify the adapter propagates non-not-found
// errors. Distinct from errKV in recoverypasswords_test.go which satisfies
// the qrdb KVStore interface; this one satisfies store.KVClient.
type adapterErrKV struct{ err error }

func (e *adapterErrKV) Put(context.Context, string, []byte) error             { return e.err }
func (e *adapterErrKV) Get(context.Context, string) ([]byte, error)           { return nil, e.err }
func (e *adapterErrKV) Delete(context.Context, string) error                  { return e.err }
func (e *adapterErrKV) DeleteIfPresent(context.Context, string) (bool, error) { return false, e.err }
func (e *adapterErrKV) List(context.Context, string) ([]string, error)        { return nil, e.err }
func (e *adapterErrKV) Exists(context.Context, string) (bool, error)          { return false, e.err }
func (e *adapterErrKV) Scan(context.Context, string, func(string, []byte) error) error {
	return e.err
}
