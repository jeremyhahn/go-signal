package svr2

import (
	"context"
	"errors"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-libsignal/pkg/svr/svrpb"
)

// Dispatcher routes encrypted SVR4 frames (Request4 protobuf bytes)
// onto Storage operations and returns Response4 protobuf bytes. One
// Dispatcher instance is shared by all sessions; per-session state
// lives in the WebSocket handler.
//
// The dispatcher does NOT speak Noise — encrypted-transport framing
// is the WebSocket handler's responsibility. Dispatcher consumes and
// produces plaintext Request4/Response4 wire bytes.
type Dispatcher struct {
	storage Storage
}

// NewDispatcher constructs a Dispatcher backed by storage.
func NewDispatcher(storage Storage) *Dispatcher {
	if storage == nil {
		panic("svr2: storage is required")
	}
	return &Dispatcher{storage: storage}
}

// Handle decodes a Request4 frame, dispatches it against the
// identity's record, persists any mutation, and returns the
// Response4 encoded bytes. identity is the authenticated principal
// (HMAC-derived from the chat-server credential).
func (d *Dispatcher) Handle(ctx context.Context, identity string, frame []byte) ([]byte, error) {
	var req svrpb.Request4
	if err := proto.Unmarshal(frame, &req); err != nil {
		return nil, err
	}

	var resp svrpb.Response4
	switch inner := req.Inner.(type) {
	case *svrpb.Request4_Create_:
		resp.Inner = d.handleCreate(ctx, identity, inner.Create)
	case *svrpb.Request4_Restore1_:
		resp.Inner = d.handleRestore1(ctx, identity, inner.Restore1)
	case *svrpb.Request4_Restore2_:
		resp.Inner = d.handleRestore2(ctx, identity, inner.Restore2)
	case *svrpb.Request4_Remove_:
		resp.Inner = d.handleRemove(ctx, identity)
	case *svrpb.Request4_Query_:
		resp.Inner = d.handleQuery(ctx, identity)
	case *svrpb.Request4_RotateStart_:
		resp.Inner = d.handleRotateStart(ctx, identity, inner.RotateStart)
	case *svrpb.Request4_RotateCommit_:
		resp.Inner = d.handleRotateCommit(ctx, identity, inner.RotateCommit)
	case *svrpb.Request4_RotateRollback_:
		resp.Inner = d.handleRotateRollback(ctx, identity, inner.RotateRollback)
	default:
		resp.Inner = &svrpb.Response4_Create_{Create: &svrpb.Response4_Create{Status: svrpb.Response4_INVALID_REQUEST}}
	}
	return proto.Marshal(&resp)
}

func (d *Dispatcher) handleCreate(ctx context.Context, identity string, req *svrpb.Request4_Create) *svrpb.Response4_Create_ { //nolint:dupl
	if len(req.OprfSecretshare) == 0 || len(req.EncryptionSecretshare) == 0 || len(req.AuthCommitment) == 0 {
		return &svrpb.Response4_Create_{Create: &svrpb.Response4_Create{Status: svrpb.Response4_INVALID_REQUEST}}
	}
	now := time.Now().UTC()
	rec := &Record{
		Version:               req.Version,
		MaxTries:              req.MaxTries,
		TriesRemaining:        req.MaxTries,
		OPRFSecretShare:       cloneBytes(req.OprfSecretshare),
		AuthCommitment:        cloneBytes(req.AuthCommitment),
		EncryptionSecretShare: cloneBytes(req.EncryptionSecretshare),
		ZeroSecretShare:       cloneBytes(req.ZeroSecretshare),
		CreatedAt:             now,
		UpdatedAt:             now,
	}
	if err := d.storage.Put(ctx, identity, rec); err != nil {
		return &svrpb.Response4_Create_{Create: &svrpb.Response4_Create{Status: svrpb.Response4_ERROR}}
	}
	return &svrpb.Response4_Create_{Create: &svrpb.Response4_Create{
		Status:         svrpb.Response4_OK,
		TriesRemaining: rec.TriesRemaining,
	}}
}

func (d *Dispatcher) handleRestore1(ctx context.Context, identity string, _ *svrpb.Request4_Restore1) *svrpb.Response4_Restore1_ {
	rec, err := d.storage.Get(ctx, identity)
	if errors.Is(err, ErrRecordNotFound) {
		return &svrpb.Response4_Restore1_{Restore1: &svrpb.Response4_Restore1{Status: svrpb.Response4_MISSING}}
	}
	if err != nil {
		return &svrpb.Response4_Restore1_{Restore1: &svrpb.Response4_Restore1{Status: svrpb.Response4_ERROR}}
	}
	if rec.TriesRemaining == 0 {
		// Out of tries; remove the record per SVR4 semantics.
		_ = d.storage.Delete(ctx, identity)
		return &svrpb.Response4_Restore1_{Restore1: &svrpb.Response4_Restore1{Status: svrpb.Response4_MISSING}}
	}
	rec.TriesRemaining--
	rec.UpdatedAt = time.Now().UTC()
	if err := d.storage.Put(ctx, identity, rec); err != nil {
		return &svrpb.Response4_Restore1_{Restore1: &svrpb.Response4_Restore1{Status: svrpb.Response4_ERROR}}
	}
	auth := &svrpb.Response4_Restore1_Auth{
		Element: cloneBytes(rec.OPRFSecretShare),
		Version: rec.Version,
	}
	return &svrpb.Response4_Restore1_{Restore1: &svrpb.Response4_Restore1{
		Status:         svrpb.Response4_OK,
		Auth:           []*svrpb.Response4_Restore1_Auth{auth},
		TriesRemaining: rec.TriesRemaining,
	}}
}

func (d *Dispatcher) handleRestore2(ctx context.Context, identity string, req *svrpb.Request4_Restore2) *svrpb.Response4_Restore2_ {
	rec, err := d.storage.Get(ctx, identity)
	if errors.Is(err, ErrRecordNotFound) {
		return &svrpb.Response4_Restore2_{Restore2: &svrpb.Response4_Restore2{Status: svrpb.Response4_RESTORE1_MISSING}}
	}
	if err != nil {
		return &svrpb.Response4_Restore2_{Restore2: &svrpb.Response4_Restore2{Status: svrpb.Response4_ERROR}}
	}
	if req.Version != rec.Version {
		return &svrpb.Response4_Restore2_{Restore2: &svrpb.Response4_Restore2{Status: svrpb.Response4_VERSION_MISMATCH}}
	}
	return &svrpb.Response4_Restore2_{Restore2: &svrpb.Response4_Restore2{
		Status:                svrpb.Response4_OK,
		EncryptionSecretshare: cloneBytes(rec.EncryptionSecretShare),
	}}
}

func (d *Dispatcher) handleRemove(ctx context.Context, identity string) *svrpb.Response4_Remove_ {
	_ = d.storage.Delete(ctx, identity)
	return &svrpb.Response4_Remove_{Remove: &svrpb.Response4_Remove{}}
}

func (d *Dispatcher) handleQuery(ctx context.Context, identity string) *svrpb.Response4_Query_ {
	rec, err := d.storage.Get(ctx, identity)
	if errors.Is(err, ErrRecordNotFound) {
		return &svrpb.Response4_Query_{Query: &svrpb.Response4_Query{Status: svrpb.Response4_MISSING}}
	}
	if err != nil {
		return &svrpb.Response4_Query_{Query: &svrpb.Response4_Query{Status: svrpb.Response4_ERROR}}
	}
	q := &svrpb.Response4_Query{
		Status:         svrpb.Response4_OK,
		TriesRemaining: rec.TriesRemaining,
		Version:        rec.Version,
	}
	if rec.PendingRotation != nil {
		q.NewVersion = rec.PendingRotation.NewVersion
	}
	return &svrpb.Response4_Query_{Query: q}
}

func (d *Dispatcher) handleRotateStart(ctx context.Context, identity string, req *svrpb.Request4_RotateStart) *svrpb.Response4_RotateStart_ {
	rec, err := d.storage.Get(ctx, identity)
	if errors.Is(err, ErrRecordNotFound) {
		return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_MISSING}}
	}
	if err != nil {
		return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_ERROR}}
	}
	if rec.PendingRotation != nil {
		// Another rotation is already in flight.
		if rec.PendingRotation.NewVersion == req.Version {
			return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_DUPLICATE_VERSION}}
		}
		return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_ALREADY_ROTATING}}
	}
	if req.Version <= rec.Version {
		return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_DUPLICATE_VERSION}}
	}
	rec.PendingRotation = &PendingRotation{
		NewVersion:                 req.Version,
		OPRFSecretShareDelta:       cloneBytes(req.OprfSecretshareDelta),
		EncryptionSecretShareDelta: cloneBytes(req.EncryptionSecretshareDelta),
	}
	rec.UpdatedAt = time.Now().UTC()
	if err := d.storage.Put(ctx, identity, rec); err != nil {
		return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_ERROR}}
	}
	return &svrpb.Response4_RotateStart_{RotateStart: &svrpb.Response4_RotateStart{Status: svrpb.Response4_OK}}
}

func (d *Dispatcher) handleRotateCommit(ctx context.Context, identity string, req *svrpb.Request4_RotateCommit) *svrpb.Response4_RotateCommit_ {
	rec, err := d.storage.Get(ctx, identity)
	if errors.Is(err, ErrRecordNotFound) {
		return &svrpb.Response4_RotateCommit_{RotateCommit: &svrpb.Response4_RotateCommit{Status: svrpb.Response4_MISSING}}
	}
	if err != nil {
		return &svrpb.Response4_RotateCommit_{RotateCommit: &svrpb.Response4_RotateCommit{Status: svrpb.Response4_ERROR}}
	}
	if rec.PendingRotation == nil || rec.PendingRotation.NewVersion != req.Version {
		return &svrpb.Response4_RotateCommit_{RotateCommit: &svrpb.Response4_RotateCommit{Status: svrpb.Response4_NOT_ROTATING}}
	}
	applyDelta(rec.OPRFSecretShare, rec.PendingRotation.OPRFSecretShareDelta)
	applyDelta(rec.EncryptionSecretShare, rec.PendingRotation.EncryptionSecretShareDelta)
	rec.Version = rec.PendingRotation.NewVersion
	rec.PendingRotation = nil
	rec.UpdatedAt = time.Now().UTC()
	if err := d.storage.Put(ctx, identity, rec); err != nil {
		return &svrpb.Response4_RotateCommit_{RotateCommit: &svrpb.Response4_RotateCommit{Status: svrpb.Response4_ERROR}}
	}
	return &svrpb.Response4_RotateCommit_{RotateCommit: &svrpb.Response4_RotateCommit{Status: svrpb.Response4_OK}}
}

func (d *Dispatcher) handleRotateRollback(ctx context.Context, identity string, req *svrpb.Request4_RotateRollback) *svrpb.Response4_RotateRollback_ {
	rec, err := d.storage.Get(ctx, identity)
	if errors.Is(err, ErrRecordNotFound) {
		return &svrpb.Response4_RotateRollback_{RotateRollback: &svrpb.Response4_RotateRollback{Status: svrpb.Response4_MISSING}}
	}
	if err != nil {
		return &svrpb.Response4_RotateRollback_{RotateRollback: &svrpb.Response4_RotateRollback{Status: svrpb.Response4_ERROR}}
	}
	if rec.PendingRotation == nil || rec.PendingRotation.NewVersion != req.Version {
		return &svrpb.Response4_RotateRollback_{RotateRollback: &svrpb.Response4_RotateRollback{Status: svrpb.Response4_NOT_ROTATING}}
	}
	rec.PendingRotation = nil
	rec.UpdatedAt = time.Now().UTC()
	if err := d.storage.Put(ctx, identity, rec); err != nil {
		return &svrpb.Response4_RotateRollback_{RotateRollback: &svrpb.Response4_RotateRollback{Status: svrpb.Response4_ERROR}}
	}
	return &svrpb.Response4_RotateRollback_{RotateRollback: &svrpb.Response4_RotateRollback{Status: svrpb.Response4_OK}}
}

// applyDelta xors delta into target in place. When delta is shorter
// or longer than target, the overlap region is updated; this mirrors
// the SVR4 reference's byte-wise additive-share update semantics
// (the deltas come pre-sized by the client).
func applyDelta(target, delta []byte) {
	n := len(target)
	if len(delta) < n {
		n = len(delta)
	}
	for i := 0; i < n; i++ {
		target[i] ^= delta[i]
	}
}
