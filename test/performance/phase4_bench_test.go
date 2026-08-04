package performance

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/attest"
	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"

	cdsipb "github.com/jeremyhahn/go-signal/pkg/api/grpc/genproto/cdsi"
	"github.com/jeremyhahn/go-signal/pkg/cdsi"
	"github.com/jeremyhahn/go-signal/pkg/keytransparency/server"
	"github.com/jeremyhahn/go-signal/pkg/registration/core"
	"github.com/jeremyhahn/go-signal/pkg/securestorage"
	memstorage "github.com/jeremyhahn/go-signal/pkg/storage/memory"
	"github.com/jeremyhahn/go-signal/pkg/svr2"
	"github.com/jeremyhahn/go-signal/pkg/verification"
)

// BenchmarkNKhfsServerHandshake measures one full server-side
// NKhfs handshake (the hot path on every new svr2 / cdsi WebSocket
// connection). One iteration = build initiator message-1, run
// server-side ProcessMessage1, return message-2 + cipher pair.
func BenchmarkNKhfsServerHandshake(b *testing.B) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		b.Fatalf("rand: %v", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		b.Fatalf("derive pub: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		uv, err := attest.NewNKhfsInitiator(pub)
		if err != nil {
			b.Fatalf("initiator: %v", err)
		}
		msg1 := uv.SkipRaftValidation().InitialRequest()
		responder, _ := attest.NewNKhfsResponder(priv, pub)
		if _, _, _, _, err := responder.ProcessMessage1(msg1); err != nil {
			b.Fatalf("ProcessMessage1: %v", err)
		}
	}
}

// BenchmarkCDSIDispatch_SmallLookup measures one CDSI ClientRequest
// → ClientResponse round-trip with a single E.164 lookup. Hot path
// for every contact-discovery call.
func BenchmarkCDSIDispatch_SmallLookup(b *testing.B) {
	dir := cdsi.NewMemoryDirectory()
	var aci, pni [16]byte
	aci[0] = 0xAB
	pni[1] = 0xCD
	dir.Upsert(cdsi.Entry{E164: 15551112222, ACI: aci, PNI: pni})
	d := cdsi.NewDispatcher(dir)
	req := &cdsipb.ClientRequest{E164SBytes: packE164(15551112222)}
	frame, _ := proto.Marshal(req)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := d.Handle(ctx, frame); err != nil {
			b.Fatalf("Handle: %v", err)
		}
	}
}

// BenchmarkCDSIDispatch_HundredLookups measures the cost-per-lookup
// for batched requests typical of a contact-sync flow.
func BenchmarkCDSIDispatch_HundredLookups(b *testing.B) {
	dir := cdsi.NewMemoryDirectory()
	const N = 100
	for i := uint64(0); i < N; i++ {
		var aci, pni [16]byte
		aci[0] = byte(i)
		pni[1] = byte(i)
		dir.Upsert(cdsi.Entry{E164: 15550000000 + i, ACI: aci, PNI: pni})
	}
	d := cdsi.NewDispatcher(dir)
	nums := make([]uint64, 0, N)
	for i := uint64(0); i < N; i++ {
		nums = append(nums, 15550000000+i)
	}
	req := &cdsipb.ClientRequest{E164SBytes: packE164(nums...)}
	frame, _ := proto.Marshal(req)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := d.Handle(ctx, frame); err != nil {
			b.Fatalf("Handle: %v", err)
		}
	}
}

// BenchmarkKTLogAppend measures the cost of one append to the
// in-memory key-transparency log including the sha256-hashed snapshot
// commitment update. The hot path on every chat-server-driven account
// update (key rotation, link/unlink).
func BenchmarkKTLogAppend(b *testing.B) {
	log := server.NewMemoryLog()
	key := make([]byte, 16)
	value := []byte("identity-key-value")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		key[0] = byte(i)
		if _, err := log.Append(key, value); err != nil {
			b.Fatalf("Append: %v", err)
		}
	}
}

// BenchmarkKTSignTreeHead measures the ed25519 signing cost of the
// FullTreeHead generation that runs on every Search / Monitor /
// Distinguished RPC. The RootHash() call is included.
func BenchmarkKTSignTreeHead(b *testing.B) {
	log := server.NewMemoryLog()
	for i := uint64(0); i < 100; i++ {
		key := []byte{byte(i)}
		_, _ = log.Append(key, []byte("value"))
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		root := log.RootHash()
		_ = server.SignTreeHead(priv, log.Size(), root, timeFixed)
	}
}

// BenchmarkSVR2DispatchCreate measures one SVR4 Create round-trip
// against the in-memory MemoryStorage backend. Hot path for every
// new backup registration.
func BenchmarkSVR2DispatchCreate(b *testing.B) {
	store := svr2.NewMemoryStorage()
	d := svr2.NewDispatcher(store)
	req, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Create_{
		Create: &svrpb.Request4_Create{
			Version:               1,
			MaxTries:              5,
			OprfSecretshare:       []byte{1, 2, 3, 4},
			AuthCommitment:        []byte{5, 6, 7, 8},
			EncryptionSecretshare: []byte{9, 10, 11, 12},
			ZeroSecretshare:       []byte{13, 14, 15, 16},
		},
	}})
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		identity := identityFor(i)
		if _, err := d.Handle(ctx, identity, req); err != nil {
			b.Fatalf("Handle: %v", err)
		}
	}
}

// BenchmarkStorageManifest_PutGet measures one round-trip for the
// storage-service manifest hot path: PUT manifest → GET manifest
// against the in-memory ManifestStore.
func BenchmarkStorageManifest_PutGet(b *testing.B) {
	store := memstorage.NewMemoryManifestStore()
	ctx := context.Background()
	manifest := &securestorage.StorageManifest{
		Version: 1,
		Value:   make([]byte, 256), // representative manifest size
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		identity := identityFor(i)
		manifest.Version = uint64(i + 1)
		if err := store.PutManifest(ctx, identity, manifest); err != nil {
			b.Fatalf("PutManifest: %v", err)
		}
		if _, err := store.GetManifest(ctx, identity); err != nil {
			b.Fatalf("GetManifest: %v", err)
		}
	}
}

// BenchmarkRegistrationSessionLifecycle measures the in-process
// registration-service round-trip: CreateSession → SendCode →
// SubmitCode against the FixedCode-stub transport.
func BenchmarkRegistrationSessionLifecycle(b *testing.B) {
	store := verification.NewMemoryVerificationSessionStore()
	tr := benchStubTransport{}
	svc := core.NewService(store, tr, core.Config{FixedCode: "424242"})
	defer svc.Shutdown()
	ctx := context.Background()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		sess, err := svc.CreateSession(ctx, "+15551234567")
		if err != nil {
			b.Fatalf("CreateSession: %v", err)
		}
		if _, err := svc.SendCode(ctx, sess.ID); err != nil {
			b.Fatalf("SendCode: %v", err)
		}
		if _, err := svc.SubmitCode(ctx, sess.ID, "424242"); err != nil {
			b.Fatalf("SubmitCode: %v", err)
		}
	}
}

// --- helpers ---------------------------------------------------------

// packE164 returns the packed big-endian E.164 byte slice the CDSI
// dispatcher expects.
func packE164(nums ...uint64) []byte {
	out := make([]byte, len(nums)*8)
	for i, n := range nums {
		binary.BigEndian.PutUint64(out[i*8:], n)
	}
	return out
}

// identityFor produces a per-iteration identity string so benchmarks
// don't degenerate to single-key contention.
func identityFor(i int) string {
	const set = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for j := range b {
		b[j] = set[(i+j)%len(set)]
	}
	return string(b)
}

// benchStubTransport satisfies verification.VerificationTransport with
// zero overhead — the benchmark measures the manager, not the
// transport.
type benchStubTransport struct{}

func (benchStubTransport) SendCode(_ context.Context, _, _ string, _ ...verification.SendOption) error {
	return nil
}
func (benchStubTransport) Name() string { return "bench-stub" }

// timeFixed is a stable timestamp for BenchmarkKTSignTreeHead so
// signature input bytes don't drift across benchmark iterations.
var timeFixed = time.Unix(1_700_000_000, 0).UTC()
