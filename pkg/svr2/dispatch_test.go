package svr2

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// errStorage always returns errors for every Storage operation.
type errStorage struct{}

func (errStorage) Get(_ context.Context, _ string) (*Record, error) {
	return nil, errors.New("svr2: store error")
}
func (errStorage) Put(_ context.Context, _ string, _ *Record) error {
	return errors.New("svr2: store error")
}
func (errStorage) Delete(_ context.Context, _ string) error {
	return errors.New("svr2: store error")
}
func (errStorage) Count(_ context.Context) (int, error) {
	return 0, errors.New("svr2: store error")
}

// controlledStorage wraps MemoryStorage and injects a Put error on demand.
type controlledStorage struct {
	base        *MemoryStorage
	failNextPut bool
}

func (c *controlledStorage) Get(ctx context.Context, id string) (*Record, error) {
	return c.base.Get(ctx, id)
}
func (c *controlledStorage) Put(ctx context.Context, id string, r *Record) error {
	if c.failNextPut {
		return errors.New("svr2: injected put error")
	}
	return c.base.Put(ctx, id, r)
}
func (c *controlledStorage) Delete(ctx context.Context, id string) error {
	return c.base.Delete(ctx, id)
}
func (c *controlledStorage) Count(ctx context.Context) (int, error) {
	return c.base.Count(ctx)
}

func newCreateReq(version uint32, maxTries uint32) []byte {
	req := &svrpb.Request4{Inner: &svrpb.Request4_Create_{
		Create: &svrpb.Request4_Create{
			Version:               version,
			MaxTries:              maxTries,
			OprfSecretshare:       []byte{1, 2, 3, 4},
			AuthCommitment:        []byte{5, 6, 7, 8},
			EncryptionSecretshare: []byte{9, 10, 11, 12},
			ZeroSecretshare:       []byte{13, 14, 15, 16},
		},
	}}
	b, _ := proto.Marshal(req)
	return b
}

func decodeResponse(t *testing.T, b []byte) *svrpb.Response4 {
	t.Helper()
	var resp svrpb.Response4
	if err := proto.Unmarshal(b, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &resp
}

func TestDispatch_CreateThenQuery(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()

	out, err := d.Handle(ctx, "alice", newCreateReq(1, 5))
	if err != nil {
		t.Fatalf("Handle Create: %v", err)
	}
	resp := decodeResponse(t, out)
	created := resp.GetCreate()
	if created == nil {
		t.Fatalf("expected Create response; got %v", resp.GetInner())
	}
	if created.Status != svrpb.Response4_OK {
		t.Errorf("Create status = %v", created.Status)
	}
	if created.TriesRemaining != 5 {
		t.Errorf("Create tries_remaining = %d", created.TriesRemaining)
	}

	// Query reports the same state.
	queryReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Query_{Query: &svrpb.Request4_Query{}}})
	out, err = d.Handle(ctx, "alice", queryReq)
	if err != nil {
		t.Fatalf("Handle Query: %v", err)
	}
	q := decodeResponse(t, out).GetQuery()
	if q.Status != svrpb.Response4_OK {
		t.Errorf("Query status = %v", q.Status)
	}
	if q.Version != 1 || q.TriesRemaining != 5 {
		t.Errorf("Query Version=%d TriesRemaining=%d", q.Version, q.TriesRemaining)
	}
}

func TestDispatch_Restore1Decrements(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	if _, err := d.Handle(ctx, "alice", newCreateReq(1, 2)); err != nil {
		t.Fatalf("Handle Create: %v", err)
	}
	r1Req, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Restore1_{
		Restore1: &svrpb.Request4_Restore1{Blinded: []byte("blinded")},
	}})
	out, _ := d.Handle(ctx, "alice", r1Req)
	r := decodeResponse(t, out).GetRestore1()
	if r.Status != svrpb.Response4_OK {
		t.Errorf("Restore1 status = %v", r.Status)
	}
	if r.TriesRemaining != 1 {
		t.Errorf("first Restore1 tries_remaining = %d", r.TriesRemaining)
	}
	if len(r.Auth) != 1 || r.Auth[0].Version != 1 {
		t.Errorf("Restore1 auth = %+v", r.Auth)
	}

	// Second Restore1 → tries_remaining=0.
	out, _ = d.Handle(ctx, "alice", r1Req)
	r = decodeResponse(t, out).GetRestore1()
	if r.TriesRemaining != 0 {
		t.Errorf("second Restore1 tries_remaining = %d", r.TriesRemaining)
	}

	// Third Restore1 → MISSING (record deleted).
	out, _ = d.Handle(ctx, "alice", r1Req)
	r = decodeResponse(t, out).GetRestore1()
	if r.Status != svrpb.Response4_MISSING {
		t.Errorf("third Restore1 status = %v", r.Status)
	}
}

func TestDispatch_Restore2VersionMismatch(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	if _, err := d.Handle(ctx, "alice", newCreateReq(1, 5)); err != nil {
		t.Fatalf("Handle Create: %v", err)
	}
	r2Req, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Restore2_{
		Restore2: &svrpb.Request4_Restore2{Version: 99, AuthPoint: []byte{1}, AuthScalar: []byte{2}},
	}})
	out, _ := d.Handle(ctx, "alice", r2Req)
	r := decodeResponse(t, out).GetRestore2()
	if r.Status != svrpb.Response4_VERSION_MISMATCH {
		t.Errorf("expected VERSION_MISMATCH, got %v", r.Status)
	}
}

func TestDispatch_RemoveIdempotent(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	if _, err := d.Handle(ctx, "alice", newCreateReq(1, 5)); err != nil {
		t.Fatalf("Handle Create: %v", err)
	}
	rmReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Remove_{Remove: &svrpb.Request4_Remove{}}})
	if _, err := d.Handle(ctx, "alice", rmReq); err != nil {
		t.Fatalf("Handle Remove: %v", err)
	}
	// Remove on missing record must also succeed.
	if _, err := d.Handle(ctx, "alice", rmReq); err != nil {
		t.Fatalf("Handle Remove again: %v", err)
	}
}

func TestDispatch_RotateStartCommitRollback(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	if _, err := d.Handle(ctx, "alice", newCreateReq(1, 5)); err != nil {
		t.Fatalf("Handle Create: %v", err)
	}

	// Start a rotation to version=2.
	rsReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{
			Version:                    2,
			OprfSecretshareDelta:       []byte{0x10, 0x20, 0x30, 0x40},
			EncryptionSecretshareDelta: []byte{0x50, 0x60, 0x70, 0x80},
		},
	}})
	out, _ := d.Handle(ctx, "alice", rsReq)
	r := decodeResponse(t, out).GetRotateStart()
	if r.Status != svrpb.Response4_OK {
		t.Errorf("RotateStart status = %v", r.Status)
	}

	// Duplicate RotateStart returns DUPLICATE_VERSION (same version) or ALREADY_ROTATING.
	out, _ = d.Handle(ctx, "alice", rsReq)
	r = decodeResponse(t, out).GetRotateStart()
	if r.Status != svrpb.Response4_DUPLICATE_VERSION {
		t.Errorf("duplicate RotateStart status = %v", r.Status)
	}

	// Commit the rotation.
	commitReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateCommit_{
		RotateCommit: &svrpb.Request4_RotateCommit{Version: 2},
	}})
	out, _ = d.Handle(ctx, "alice", commitReq)
	c := decodeResponse(t, out).GetRotateCommit()
	if c.Status != svrpb.Response4_OK {
		t.Errorf("RotateCommit status = %v", c.Status)
	}

	// Now Rollback after commit returns NOT_ROTATING.
	rbReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateRollback_{
		RotateRollback: &svrpb.Request4_RotateRollback{Version: 2},
	}})
	out, _ = d.Handle(ctx, "alice", rbReq)
	rb := decodeResponse(t, out).GetRotateRollback()
	if rb.Status != svrpb.Response4_NOT_ROTATING {
		t.Errorf("RotateRollback after Commit status = %v", rb.Status)
	}
}

func TestDispatch_QueryMissingRecord(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	qReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Query_{Query: &svrpb.Request4_Query{}}})
	out, _ := d.Handle(ctx, "bob", qReq)
	q := decodeResponse(t, out).GetQuery()
	if q.Status != svrpb.Response4_MISSING {
		t.Errorf("expected MISSING, got %v", q.Status)
	}
}

func TestDispatch_BadFrame(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	if _, err := d.Handle(context.Background(), "alice", []byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("expected error on garbage frame")
	}
}

func TestNewDispatcher_PanicsWithoutStorage(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when storage is nil")
		}
	}()
	NewDispatcher(nil)
}

func TestMemoryStorage_CountAndDelete(t *testing.T) {
	s := NewMemoryStorage()
	ctx := context.Background()
	n, _ := s.Count(ctx)
	if n != 0 {
		t.Errorf("initial count = %d", n)
	}
	_ = s.Put(ctx, "a", &Record{Version: 1})
	_ = s.Put(ctx, "b", &Record{Version: 2})
	n, _ = s.Count(ctx)
	if n != 2 {
		t.Errorf("count after puts = %d", n)
	}
	_ = s.Delete(ctx, "a")
	n, _ = s.Count(ctx)
	if n != 1 {
		t.Errorf("count after delete = %d", n)
	}
	if _, err := s.Get(ctx, "a"); err != ErrRecordNotFound {
		t.Errorf("expected ErrRecordNotFound, got %v", err)
	}
}

// --------------------------------------------------------------------------
// Handle: nil inner (default case)
// --------------------------------------------------------------------------

func TestDispatch_Handle_NilInner_ReturnsInvalidRequest(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	emptyReq, _ := proto.Marshal(&svrpb.Request4{}) // nil Inner hits default case
	out, err := d.Handle(context.Background(), "alice", emptyReq)
	if err != nil {
		t.Fatalf("Handle nil inner: %v", err)
	}
	c := decodeResponse(t, out).GetCreate()
	if c == nil || c.Status != svrpb.Response4_INVALID_REQUEST {
		t.Errorf("expected INVALID_REQUEST for nil inner, got %v", c)
	}
}

// --------------------------------------------------------------------------
// handleCreate: validation and storage error paths
// --------------------------------------------------------------------------

func TestDispatch_HandleCreate_MissingFields_ReturnsInvalidRequest(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	req, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Create_{
		Create: &svrpb.Request4_Create{
			// OprfSecretshare deliberately empty — must return INVALID_REQUEST.
			AuthCommitment:        []byte{1},
			EncryptionSecretshare: []byte{2},
		},
	}})
	out, _ := d.Handle(context.Background(), "alice", req)
	if got := decodeResponse(t, out).GetCreate().Status; got != svrpb.Response4_INVALID_REQUEST {
		t.Errorf("expected INVALID_REQUEST on missing fields, got %v", got)
	}
}

func TestDispatch_HandleCreate_StorageError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	out, _ := d.Handle(context.Background(), "alice", newCreateReq(1, 3))
	if got := decodeResponse(t, out).GetCreate().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR from storage, got %v", got)
	}
}

// --------------------------------------------------------------------------
// handleRestore1: storage error paths
// --------------------------------------------------------------------------

func TestDispatch_HandleRestore1_GetError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	r1, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Restore1_{
		Restore1: &svrpb.Request4_Restore1{Blinded: []byte("x")},
	}})
	out, _ := d.Handle(context.Background(), "alice", r1)
	if got := decodeResponse(t, out).GetRestore1().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR, got %v", got)
	}
}

func TestDispatch_HandleRestore1_PutError_ReturnsError(t *testing.T) {
	base := NewMemoryStorage()
	ctx := context.Background()
	_ = base.Put(ctx, "alice", &Record{
		Version: 1, MaxTries: 3, TriesRemaining: 3,
		OPRFSecretShare: []byte{1}, AuthCommitment: []byte{2},
		EncryptionSecretShare: []byte{3}, ZeroSecretShare: []byte{4},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	cs := &controlledStorage{base: base, failNextPut: true}
	d := NewDispatcher(cs)
	r1, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Restore1_{
		Restore1: &svrpb.Request4_Restore1{Blinded: []byte("x")},
	}})
	out, _ := d.Handle(ctx, "alice", r1)
	if got := decodeResponse(t, out).GetRestore1().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR from put failure, got %v", got)
	}
}

// --------------------------------------------------------------------------
// handleRestore2: storage error path
// --------------------------------------------------------------------------

func TestDispatch_HandleRestore2_GetError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	r2, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Restore2_{
		Restore2: &svrpb.Request4_Restore2{Version: 1},
	}})
	out, _ := d.Handle(context.Background(), "alice", r2)
	if got := decodeResponse(t, out).GetRestore2().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR, got %v", got)
	}
}

// --------------------------------------------------------------------------
// handleQuery: storage error path and pending-rotation branch
// --------------------------------------------------------------------------

func TestDispatch_HandleQuery_GetError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	q, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Query_{Query: &svrpb.Request4_Query{}}})
	out, _ := d.Handle(context.Background(), "alice", q)
	if got := decodeResponse(t, out).GetQuery().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR, got %v", got)
	}
}

func TestDispatch_HandleQuery_WithPendingRotation_PopulatesNewVersion(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	_, _ = d.Handle(ctx, "alice", newCreateReq(1, 5))
	start, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 2, OprfSecretshareDelta: []byte{0x01}},
	}})
	_, _ = d.Handle(ctx, "alice", start)
	qReq, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_Query_{Query: &svrpb.Request4_Query{}}})
	out, _ := d.Handle(ctx, "alice", qReq)
	q := decodeResponse(t, out).GetQuery()
	if q.NewVersion != 2 {
		t.Errorf("expected NewVersion=2 in query with pending rotation, got %d", q.NewVersion)
	}
}

// --------------------------------------------------------------------------
// handleRotateStart: all uncovered branches
// --------------------------------------------------------------------------

func TestDispatch_HandleRotateStart_GetError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	rs, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 2},
	}})
	out, _ := d.Handle(context.Background(), "alice", rs)
	if got := decodeResponse(t, out).GetRotateStart().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR, got %v", got)
	}
}

func TestDispatch_HandleRotateStart_AlreadyRotating_DifferentVersion(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	_, _ = d.Handle(ctx, "alice", newCreateReq(1, 5))
	// Start version-2 rotation.
	start2, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 2, OprfSecretshareDelta: []byte{0x01}},
	}})
	_, _ = d.Handle(ctx, "alice", start2)
	// Attempt version-3 rotation while version-2 is in-flight → ALREADY_ROTATING.
	start3, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 3, OprfSecretshareDelta: []byte{0x02}},
	}})
	out, _ := d.Handle(ctx, "alice", start3)
	if got := decodeResponse(t, out).GetRotateStart().Status; got != svrpb.Response4_ALREADY_ROTATING {
		t.Errorf("expected ALREADY_ROTATING, got %v", got)
	}
}

func TestDispatch_HandleRotateStart_VersionNotAdvanced_ReturnsDuplicateVersion(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	_, _ = d.Handle(ctx, "alice", newCreateReq(2, 5)) // record.Version = 2
	// req.Version(1) <= rec.Version(2) → DUPLICATE_VERSION via the version-guard branch.
	start1, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 1},
	}})
	out, _ := d.Handle(ctx, "alice", start1)
	if got := decodeResponse(t, out).GetRotateStart().Status; got != svrpb.Response4_DUPLICATE_VERSION {
		t.Errorf("expected DUPLICATE_VERSION for non-advancing version, got %v", got)
	}
}

func TestDispatch_HandleRotateStart_PutError_ReturnsError(t *testing.T) {
	base := NewMemoryStorage()
	ctx := context.Background()
	_ = base.Put(ctx, "alice", &Record{
		Version: 1, MaxTries: 3, TriesRemaining: 3,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	cs := &controlledStorage{base: base, failNextPut: true}
	d := NewDispatcher(cs)
	rs, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 2, OprfSecretshareDelta: []byte{0x01}},
	}})
	out, _ := d.Handle(ctx, "alice", rs)
	if got := decodeResponse(t, out).GetRotateStart().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR from put failure, got %v", got)
	}
}

// --------------------------------------------------------------------------
// handleRotateCommit: storage error paths
// --------------------------------------------------------------------------

func TestDispatch_HandleRotateCommit_GetError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	rc, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateCommit_{
		RotateCommit: &svrpb.Request4_RotateCommit{Version: 1},
	}})
	out, _ := d.Handle(context.Background(), "alice", rc)
	if got := decodeResponse(t, out).GetRotateCommit().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR, got %v", got)
	}
}

func TestDispatch_HandleRotateCommit_PutError_ReturnsError(t *testing.T) {
	base := NewMemoryStorage()
	ctx := context.Background()
	_ = base.Put(ctx, "alice", &Record{
		Version: 1, MaxTries: 3, TriesRemaining: 3,
		OPRFSecretShare:       []byte{0xAA},
		EncryptionSecretShare: []byte{0xBB},
		PendingRotation: &PendingRotation{
			NewVersion:                 2,
			OPRFSecretShareDelta:       []byte{0x01},
			EncryptionSecretShareDelta: []byte{0x01},
		},
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	cs := &controlledStorage{base: base, failNextPut: true}
	d := NewDispatcher(cs)
	rc, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateCommit_{
		RotateCommit: &svrpb.Request4_RotateCommit{Version: 2},
	}})
	out, _ := d.Handle(ctx, "alice", rc)
	if got := decodeResponse(t, out).GetRotateCommit().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR from put failure, got %v", got)
	}
}

// --------------------------------------------------------------------------
// handleRotateRollback: all paths including success
// --------------------------------------------------------------------------

func TestDispatch_HandleRotateRollback_GetError_ReturnsError(t *testing.T) {
	d := NewDispatcher(errStorage{})
	rb, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateRollback_{
		RotateRollback: &svrpb.Request4_RotateRollback{Version: 1},
	}})
	out, _ := d.Handle(context.Background(), "alice", rb)
	if got := decodeResponse(t, out).GetRotateRollback().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR, got %v", got)
	}
}

func TestDispatch_HandleRotateRollback_Success(t *testing.T) {
	d := NewDispatcher(NewMemoryStorage())
	ctx := context.Background()
	_, _ = d.Handle(ctx, "alice", newCreateReq(1, 5))
	start, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateStart_{
		RotateStart: &svrpb.Request4_RotateStart{Version: 2, OprfSecretshareDelta: []byte{0x01}},
	}})
	_, _ = d.Handle(ctx, "alice", start)
	rb, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateRollback_{
		RotateRollback: &svrpb.Request4_RotateRollback{Version: 2},
	}})
	out, _ := d.Handle(ctx, "alice", rb)
	if got := decodeResponse(t, out).GetRotateRollback().Status; got != svrpb.Response4_OK {
		t.Errorf("expected OK from rollback, got %v", got)
	}
}

func TestDispatch_HandleRotateRollback_PutError_ReturnsError(t *testing.T) {
	base := NewMemoryStorage()
	ctx := context.Background()
	_ = base.Put(ctx, "alice", &Record{
		Version: 1, MaxTries: 3, TriesRemaining: 3,
		PendingRotation: &PendingRotation{NewVersion: 2},
		CreatedAt:       time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	cs := &controlledStorage{base: base, failNextPut: true}
	d := NewDispatcher(cs)
	rb, _ := proto.Marshal(&svrpb.Request4{Inner: &svrpb.Request4_RotateRollback_{
		RotateRollback: &svrpb.Request4_RotateRollback{Version: 2},
	}})
	out, _ := d.Handle(ctx, "alice", rb)
	if got := decodeResponse(t, out).GetRotateRollback().Status; got != svrpb.Response4_ERROR {
		t.Errorf("expected ERROR from put failure, got %v", got)
	}
}

// --------------------------------------------------------------------------
// applyDelta: short delta (len(delta) < len(target))
// --------------------------------------------------------------------------

func TestApplyDelta_ShorterDelta_XORsOnlyOverlap(t *testing.T) {
	target := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	delta := []byte{0x01, 0x02} // shorter than target
	applyDelta(target, delta)
	if target[0] != 0xFE {
		t.Errorf("target[0] = 0x%X, want 0xFE", target[0])
	}
	if target[1] != 0xFD {
		t.Errorf("target[1] = 0x%X, want 0xFD", target[1])
	}
	// Non-overlap bytes must be unchanged.
	if target[2] != 0xFF || target[3] != 0xFF {
		t.Errorf("non-overlap bytes modified: %v", target[2:])
	}
}

func TestApplyDelta_EmptyDelta_TargetUnchanged(t *testing.T) {
	target := []byte{0xAA, 0xBB}
	applyDelta(target, nil)
	if target[0] != 0xAA || target[1] != 0xBB {
		t.Errorf("target changed with empty delta: %v", target)
	}
}
