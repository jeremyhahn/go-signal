package accounts

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// drainOne reads one event or fails the test.
func drainOne(t *testing.T, sub *Subscription) DirectoryEvent {
	t.Helper()
	select {
	case e := <-sub.Events():
		return e
	case <-time.After(time.Second):
		t.Fatal("expected event was not delivered")
		return DirectoryEvent{}
	}
}

// expectNothing asserts the subscription receives no event within a
// short window. Used to confirm internal-only updates do not leak as
// directory mutations (they currently do, since every Update emits;
// kept for future filtering work).
func expectNothing(t *testing.T, sub *Subscription, label string) {
	t.Helper()
	select {
	case e := <-sub.Events():
		t.Errorf("%s: unexpected event %+v", label, e)
	case <-time.After(50 * time.Millisecond):
	}
}

func newManagerWithBus(t *testing.T) (*AccountsManager, *DirectoryEventBus) {
	t.Helper()
	m := NewAccountsManager(newMemoryStore(), 0)
	bus := NewDirectoryEventBus()
	m.SetDirectoryEventBus(bus)
	return m, bus
}

func directoryEventAccount(uuidStr, number string) *Account {
	return &Account{
		UUID:        uuidStr,
		Number:      number,
		IdentityKey: []byte{0x01},
		Devices: []Device{{
			ID:           PrimaryDeviceID,
			AuthToken:    "token-" + uuidStr,
			SignedPreKey: &SignedPreKey{KeyID: 1, PublicKey: []byte{0x02}, Signature: []byte{0x03}},
		}},
	}
}

func TestAccountsManager_CreatePublishesCreated(t *testing.T) {
	m, bus := newManagerWithBus(t)
	sub, _ := bus.Subscribe(context.Background(), 4)
	defer sub.Close()

	if err := m.Create(context.Background(), directoryEventAccount("uuid-a", "+15550001")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	e := drainOne(t, sub)
	if e.Kind != DirectoryEventCreated || e.UUID != "uuid-a" {
		t.Errorf("got %+v", e)
	}
	if e.Account == nil || e.Account.Number != "+15550001" {
		t.Errorf("account snapshot lost: %+v", e.Account)
	}
}

func TestAccountsManager_UpdatePublishesUpdated(t *testing.T) {
	m, bus := newManagerWithBus(t)
	a := directoryEventAccount("uuid-a", "+15550001")
	if err := m.Create(context.Background(), a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	sub, _ := bus.Subscribe(context.Background(), 4)
	defer sub.Close()

	if err := m.Update(context.Background(), a); err != nil {
		t.Fatalf("Update: %v", err)
	}
	e := drainOne(t, sub)
	if e.Kind != DirectoryEventUpdated || e.UUID != "uuid-a" {
		t.Errorf("got %+v", e)
	}
}

func TestAccountsManager_DeletePublishesDeleted(t *testing.T) {
	m, bus := newManagerWithBus(t)
	a := directoryEventAccount("uuid-a", "+15550001")
	_ = m.Create(context.Background(), a)
	sub, _ := bus.Subscribe(context.Background(), 4)
	defer sub.Close()

	if err := m.Delete(context.Background(), "uuid-a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	e := drainOne(t, sub)
	if e.Kind != DirectoryEventDeleted || e.UUID != "uuid-a" {
		t.Errorf("got %+v", e)
	}
	if e.Account == nil || e.Account.Number != "+15550001" {
		t.Errorf("delete event must carry pre-delete snapshot: %+v", e.Account)
	}
}

func TestAccountsManager_FailedStoreOpDoesNotPublish(t *testing.T) {
	store := &failingStore{}
	m := NewAccountsManager(store, 0)
	bus := NewDirectoryEventBus()
	m.SetDirectoryEventBus(bus)
	sub, _ := bus.Subscribe(context.Background(), 4)
	defer sub.Close()

	if err := m.Create(context.Background(), directoryEventAccount("uuid-a", "+15550001")); err == nil {
		t.Fatal("Create expected to fail")
	}
	expectNothing(t, sub, "Create failure")

	if err := m.Delete(context.Background(), "uuid-a"); err == nil {
		t.Fatal("Delete expected to fail")
	}
	expectNothing(t, sub, "Delete failure")
}

func TestAccountsManager_NoBusNoCrash(t *testing.T) {
	m := NewAccountsManager(newMemoryStore(), 0)
	// No SetDirectoryEventBus call.
	if err := m.Create(context.Background(), directoryEventAccount("uuid-a", "+15550001")); err != nil {
		t.Fatalf("Create with nil bus: %v", err)
	}
	if err := m.Delete(context.Background(), "uuid-a"); err != nil {
		t.Fatalf("Delete with nil bus: %v", err)
	}
}

func TestAccountsManager_ChangeNumberPublishesDisplaceAndUpdate(t *testing.T) {
	m, bus := newManagerWithBus(t)
	holder := directoryEventAccount(uuid.NewString(), "+15550100")
	mover := directoryEventAccount(uuid.NewString(), "+15550200")
	_ = m.Create(context.Background(), holder)
	_ = m.Create(context.Background(), mover)

	sub, _ := bus.Subscribe(context.Background(), 8)
	defer sub.Close()

	if _, err := m.ChangeNumber(context.Background(), mover.UUID, "+15550100", nil); err != nil {
		t.Fatalf("ChangeNumber: %v", err)
	}
	// Expect 2 events: Deleted (displaced holder) then Updated (mover).
	e1 := drainOne(t, sub)
	e2 := drainOne(t, sub)
	gotDeleted := (e1.Kind == DirectoryEventDeleted && e1.UUID == holder.UUID) ||
		(e2.Kind == DirectoryEventDeleted && e2.UUID == holder.UUID)
	gotUpdated := (e1.Kind == DirectoryEventUpdated && e1.UUID == mover.UUID) ||
		(e2.Kind == DirectoryEventUpdated && e2.UUID == mover.UUID)
	if !gotDeleted || !gotUpdated {
		t.Errorf("missing events: e1=%+v e2=%+v", e1, e2)
	}
}

// failingStore returns errors from every method — used to verify
// publish gating on store success.
type failingStore struct{}

func (f *failingStore) Create(context.Context, *Account) error { return &InvalidArgumentError{} }
func (f *failingStore) Get(context.Context, string) (*Account, error) {
	return nil, &InvalidArgumentError{}
}
func (f *failingStore) GetByNumber(context.Context, string) (*Account, error) {
	return nil, &InvalidArgumentError{}
}
func (f *failingStore) GetByPNI(context.Context, string) (*Account, error) {
	return nil, &InvalidArgumentError{}
}
func (f *failingStore) Update(context.Context, *Account) error { return &InvalidArgumentError{} }
func (f *failingStore) Delete(context.Context, string) error   { return &InvalidArgumentError{} }
func (f *failingStore) ListAll(context.Context, func(*Account) error) error {
	return &InvalidArgumentError{}
}
