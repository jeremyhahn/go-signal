package cdsi

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	dirpb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/directory"
	dirsvc "github.com/jeremyhahn/go-signal/pkg/api/grpc/services/directory"
)

// memoryAccountStore is a slimmed-down store for replication tests.
// The mutex is intentional: the directory server's Subscribe handler
// runs ListAll on its goroutine while the test's Create runs on the
// test goroutine — without locking, the race detector flags the
// concurrent map access. Production stores (memory/qrdb/postgres) all
// have their own synchronization.
type memoryAccountStore struct {
	mu   sync.Mutex
	data map[string]*accounts.Account
}

func newMemoryAccountStore() *memoryAccountStore {
	return &memoryAccountStore{data: make(map[string]*accounts.Account)}
}

func (s *memoryAccountStore) Create(_ context.Context, a *accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[a.UUID] = a
	return nil
}
func (s *memoryAccountStore) Get(_ context.Context, u string) (*accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.data[u]; ok {
		return a, nil
	}
	return nil, &accounts.InvalidArgumentError{Field: "uuid", Message: "not found"}
}
func (s *memoryAccountStore) GetByNumber(_ context.Context, n string) (*accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.data {
		if a.Number == n {
			return a, nil
		}
	}
	return nil, &accounts.InvalidArgumentError{Field: "number", Message: "not found"}
}
func (s *memoryAccountStore) GetByPNI(_ context.Context, p string) (*accounts.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.data {
		if a.PNI == p {
			return a, nil
		}
	}
	return nil, &accounts.InvalidArgumentError{Field: "pni", Message: "not found"}
}
func (s *memoryAccountStore) Update(_ context.Context, a *accounts.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[a.UUID]; !ok {
		return &accounts.InvalidArgumentError{Field: "uuid", Message: "not found"}
	}
	s.data[a.UUID] = a
	return nil
}
func (s *memoryAccountStore) Delete(_ context.Context, u string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[u]; !ok {
		return &accounts.InvalidArgumentError{Field: "uuid", Message: "not found"}
	}
	delete(s.data, u)
	return nil
}
func (s *memoryAccountStore) ListAll(_ context.Context, fn func(*accounts.Account) error) error {
	s.mu.Lock()
	snapshot := make([]*accounts.Account, 0, len(s.data))
	for _, a := range s.data {
		snapshot = append(snapshot, a)
	}
	s.mu.Unlock()
	for _, a := range snapshot {
		if err := fn(a); err != nil {
			return err
		}
	}
	return nil
}

// directoryEventSourceForTest mirrors the adapter in cmd/signald,
// translating accounts.DirectoryEvent into dirsvc.ChangeEvent. Kept
// local to this test so the replication path can be exercised
// end-to-end without depending on cmd/signald wiring code.
type directoryEventSourceForTest struct {
	bus *accounts.DirectoryEventBus
}

func (s *directoryEventSourceForTest) Subscribe(ctx context.Context, buffer int) (dirsvc.EventSubscription, uint64) {
	sub, asOf := s.bus.Subscribe(ctx, buffer)
	wrap := &replSub{sub: sub, out: make(chan dirsvc.ChangeEvent, buffer)}
	go func() {
		defer close(wrap.out)
		for e := range sub.Events() {
			wrap.out <- accountsToChange(e)
		}
	}()
	return wrap, asOf
}

type replSub struct {
	sub *accounts.Subscription
	out chan dirsvc.ChangeEvent
}

func (s *replSub) Events() <-chan dirsvc.ChangeEvent { return s.out }
func (s *replSub) Done() <-chan struct{}             { return s.sub.Done() }
func (s *replSub) Overflowed() bool                  { return s.sub.Overflowed() }
func (s *replSub) Close()                            { s.sub.Close() }

func accountsToChange(e accounts.DirectoryEvent) dirsvc.ChangeEvent {
	out := dirsvc.ChangeEvent{Seq: e.Seq, UUID: e.UUID}
	if e.Kind == accounts.DirectoryEventDeleted {
		out.Kind = dirsvc.ChangeEventDelete
	} else {
		out.Kind = dirsvc.ChangeEventUpsert
	}
	if e.Account != nil {
		if n, err := strconv.ParseUint(strings.TrimPrefix(e.Account.Number, "+"), 10, 64); err == nil {
			out.Entry.E164 = n
		}
		if id, err := uuid.Parse(e.Account.UUID); err == nil {
			b, _ := id.MarshalBinary()
			copy(out.Entry.ACI[:], b)
		}
		if id, err := uuid.Parse(e.Account.PNI); err == nil {
			b, _ := id.MarshalBinary()
			copy(out.Entry.PNI[:], b)
		}
	}
	return out
}

// accountSourceForTest is a dirsvc.AccountSource over a memoryAccountStore.
type accountSourceForTest struct{ store *memoryAccountStore }

func (a *accountSourceForTest) ListAll(ctx context.Context, fn func(dirsvc.DirectoryEntry) error) error {
	return a.store.ListAll(ctx, func(acc *accounts.Account) error {
		entry := dirsvc.DirectoryEntry{}
		if n, err := strconv.ParseUint(strings.TrimPrefix(acc.Number, "+"), 10, 64); err == nil {
			entry.E164 = n
		}
		if id, err := uuid.Parse(acc.UUID); err == nil {
			b, _ := id.MarshalBinary()
			copy(entry.ACI[:], b)
		}
		if id, err := uuid.Parse(acc.PNI); err == nil {
			b, _ := id.MarshalBinary()
			copy(entry.PNI[:], b)
		}
		return fn(entry)
	})
}

func TestReplication_EndToEnd_NewAccountReachesCdsi(t *testing.T) {
	// --- signald side ---
	store := newMemoryAccountStore()
	bus := accounts.NewDirectoryEventBus()
	mgr := accounts.NewAccountsManager(store, 0)
	mgr.SetDirectoryEventBus(bus)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	dirpb.RegisterDirectoryServiceServer(gs,
		dirsvc.NewServer(&accountSourceForTest{store: store},
			dirsvc.WithEventSource(&directoryEventSourceForTest{bus: bus})))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := dirpb.NewDirectoryServiceClient(conn)

	// --- cdsi side ---
	dir := NewMemoryDirectory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	loopErr := make(chan error, 1)
	go func() {
		loopErr <- SubscribeAndApply(ctx, SubscribeConfig{
			Client:     client,
			Directory:  dir,
			TokenStore: NewMemoryResumeTokenStore(),
			MinBackoff: 5 * time.Millisecond,
			MaxBackoff: 20 * time.Millisecond,
		})
	}()

	// Give the subscribe stream a moment to settle (snapshot frame + initial resume token).
	time.Sleep(50 * time.Millisecond)

	// Now create an account on signald — the bus delivers the event,
	// the server forwards it, the cdsi loop applies it.
	acc := &accounts.Account{
		UUID:        uuid.NewString(),
		Number:      "+15551234567",
		IdentityKey: []byte{0x01},
		Devices: []accounts.Device{{
			ID:           accounts.PrimaryDeviceID,
			AuthToken:    "tok",
			SignedPreKey: &accounts.SignedPreKey{KeyID: 1, PublicKey: []byte{1}, Signature: []byte{2}},
		}},
	}
	if err := mgr.Create(ctx, acc); err != nil {
		t.Fatalf("Create: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := dir.Lookup(15551234567); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := dir.Lookup(15551234567); !ok {
		t.Fatalf("cdsi never observed new account; entries=%d", dir.Count())
	}

	// Now delete the account → cdsi should drop the entry.
	if err := mgr.Delete(ctx, acc.UUID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := dir.Lookup(15551234567); !ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := dir.Lookup(15551234567); ok {
		t.Errorf("cdsi did not observe deletion")
	}
}
