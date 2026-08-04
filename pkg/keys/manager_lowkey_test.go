package keys

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// noopStore implements just enough of PreKeyStore to drive the manager's
// consuming GetPreKeys path. ECCount/KEMCount returned by GetPreKeyCount are
// controllable via the embedded atomics so tests can assert threshold logic
// without standing up a full backend.
type lowKeyStubStore struct {
	signedKey *SignedPreKey

	ec  atomic.Int32 // remaining one-time EC keys reported by GetPreKeyCount
	kem atomic.Int32 // remaining one-time KEM keys reported by GetPreKeyCount

	takeECCalled  atomic.Int32
	takeKEMCalled atomic.Int32
}

func (s *lowKeyStubStore) StoreECPreKeys(context.Context, string, uint64, []*PreKey) error {
	return nil
}
func (s *lowKeyStubStore) StoreKEMPreKeys(context.Context, string, uint64, []*KEMSignedPreKey) error {
	return nil
}
func (s *lowKeyStubStore) StoreKEMLastResortPreKey(context.Context, string, uint64, *KEMSignedPreKey) error {
	return nil
}
func (s *lowKeyStubStore) StoreSignedPreKey(context.Context, string, uint64, *SignedPreKey) error {
	return nil
}
func (s *lowKeyStubStore) StoreECSignedPreKey(context.Context, string, uint64, *SignedPreKey) error {
	return nil
}
func (s *lowKeyStubStore) GetSignedPreKey(_ context.Context, _ string, _ uint64) (*SignedPreKey, error) {
	if s.signedKey != nil {
		return s.signedKey, nil
	}
	return &SignedPreKey{KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig")}, nil
}
func (s *lowKeyStubStore) TakeEC(context.Context, string, uint64) (*PreKey, error) {
	s.takeECCalled.Add(1)
	return &PreKey{KeyID: 10, PublicKey: []byte("ec")}, nil
}
func (s *lowKeyStubStore) TakeKEM(context.Context, string, uint64) (*KEMSignedPreKey, error) {
	s.takeKEMCalled.Add(1)
	return &KEMSignedPreKey{KeyID: 20, PublicKey: []byte("kem"), Signature: []byte("sig")}, nil
}
func (s *lowKeyStubStore) GetKEMLastResortPreKey(context.Context, string, uint64) (*KEMSignedPreKey, error) {
	return nil, nil
}
func (s *lowKeyStubStore) GetPreKeyCount(_ context.Context, _ string, _ uint64) (*PreKeyState, error) {
	return &PreKeyState{
		ECCount:       int(s.ec.Load()),
		KEMCount:      int(s.kem.Load()),
		HasLastResort: false,
	}, nil
}
func (s *lowKeyStubStore) DeleteAllForDevice(context.Context, string, uint64) error {
	return nil
}
func (s *lowKeyStubStore) DeleteAllForAccount(context.Context, string) error { return nil }
func (s *lowKeyStubStore) ListAccountUUIDs(context.Context) ([]string, error) {
	return nil, nil
}

// Compile-time interface check.
var _ PreKeyStore = (*lowKeyStubStore)(nil)

func TestLowKeyCallback_FiresOnLowEC(t *testing.T) {
	store := &lowKeyStubStore{}
	store.ec.Store(10) // below default threshold (25)
	store.kem.Store(100)
	mgr := NewKeysManager(store)

	var got LowKeyEvent
	mgr.SetLowKeyCallback(func(ev LowKeyEvent) { got = ev })

	if _, err := mgr.GetPreKeys(context.Background(), "acct-1", accounts.PrimaryDeviceID); err != nil {
		t.Fatalf("GetPreKeys: %v", err)
	}

	if got.AccountUUID != "acct-1" {
		t.Errorf("AccountUUID = %q; want acct-1", got.AccountUUID)
	}
	if !got.LowEC {
		t.Error("expected LowEC to be true")
	}
	if got.LowKEM {
		t.Error("expected LowKEM to be false")
	}
	if got.RemainingEC != 10 || got.RemainingKEM != 100 {
		t.Errorf("remaining counts wrong: %+v", got)
	}
}

func TestLowKeyCallback_FiresOnLowKEM(t *testing.T) {
	store := &lowKeyStubStore{}
	store.ec.Store(500)
	store.kem.Store(5)
	mgr := NewKeysManager(store)

	var fired atomic.Bool
	mgr.SetLowKeyCallback(func(ev LowKeyEvent) {
		fired.Store(true)
		if !ev.LowKEM {
			t.Error("expected LowKEM to be true")
		}
		if ev.LowEC {
			t.Error("expected LowEC to be false")
		}
	})

	if _, err := mgr.GetPreKeys(context.Background(), "acct-2", accounts.PrimaryDeviceID); err != nil {
		t.Fatalf("GetPreKeys: %v", err)
	}
	if !fired.Load() {
		t.Fatal("callback did not fire")
	}
}

func TestLowKeyCallback_NoFireAboveThreshold(t *testing.T) {
	store := &lowKeyStubStore{}
	store.ec.Store(100)
	store.kem.Store(100)
	mgr := NewKeysManager(store)

	var fired atomic.Bool
	mgr.SetLowKeyCallback(func(LowKeyEvent) { fired.Store(true) })

	if _, err := mgr.GetPreKeys(context.Background(), "acct-3", accounts.PrimaryDeviceID); err != nil {
		t.Fatalf("GetPreKeys: %v", err)
	}
	if fired.Load() {
		t.Fatal("callback should not have fired")
	}
}

func TestLowKeyCallback_DisableViaNil(t *testing.T) {
	store := &lowKeyStubStore{}
	store.ec.Store(0)
	store.kem.Store(0)
	mgr := NewKeysManager(store)

	var fired atomic.Bool
	mgr.SetLowKeyCallback(func(LowKeyEvent) { fired.Store(true) })
	mgr.SetLowKeyCallback(nil)

	if _, err := mgr.GetPreKeys(context.Background(), "acct-4", accounts.PrimaryDeviceID); err != nil {
		t.Fatalf("GetPreKeys: %v", err)
	}
	if fired.Load() {
		t.Fatal("callback should be disabled")
	}
}

func TestLowKeyCallback_CustomThreshold(t *testing.T) {
	store := &lowKeyStubStore{}
	store.ec.Store(50) // above default 25
	store.kem.Store(50)
	mgr := NewKeysManager(store)

	mgr.SetLowKeyThreshold(100) // raise threshold so 50 is now below

	var fired atomic.Bool
	mgr.SetLowKeyCallback(func(ev LowKeyEvent) {
		fired.Store(true)
		if !ev.LowEC || !ev.LowKEM {
			t.Errorf("both should be flagged low at threshold 100: %+v", ev)
		}
	})

	if _, err := mgr.GetPreKeys(context.Background(), "acct-5", accounts.PrimaryDeviceID); err != nil {
		t.Fatalf("GetPreKeys: %v", err)
	}
	if !fired.Load() {
		t.Fatal("expected callback to fire at custom threshold")
	}
}

func TestLowKeyCallback_NegativeThresholdResetsToDefault(t *testing.T) {
	store := &lowKeyStubStore{}
	store.ec.Store(100)
	store.kem.Store(100)
	mgr := NewKeysManager(store)

	mgr.SetLowKeyThreshold(0)  // should reset to default
	mgr.SetLowKeyThreshold(-1) // same

	var fired atomic.Bool
	mgr.SetLowKeyCallback(func(LowKeyEvent) { fired.Store(true) })
	if _, err := mgr.GetPreKeys(context.Background(), "acct-6", accounts.PrimaryDeviceID); err != nil {
		t.Fatalf("GetPreKeys: %v", err)
	}
	if fired.Load() {
		t.Fatal("100 counts should not trigger below default threshold of 25")
	}
}
