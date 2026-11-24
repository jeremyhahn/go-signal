// Package svr2 is the SVR4 server engine: Request4/Response4 dispatch and one persistent Record per identity.
package svr2

import (
	"time"
)

// Record is an identity's SVR4 state, created by Request4.Create: secret shares and Merkle commitment metadata.
type Record struct {
	// Version is the OPRF key version, set by Create and rotated by RotateCommit.
	Version uint32

	// MaxTries is the operator-fixed cap on Restore1 attempts before
	// the record auto-deletes itself. Set by Create.
	MaxTries uint32

	// TriesRemaining decrements on every Restore1 call. When it hits
	// zero the record is removed by the server.
	TriesRemaining uint32

	// OPRFSecretShare is the server's OPRF key share.
	OPRFSecretShare []byte

	// AuthCommitment is sha256-style commitment used by Restore2 to
	// confirm the client's auth scalar matches the value that bound
	// the secret at Create time.
	AuthCommitment []byte

	// EncryptionSecretShare is the server's share of the secret-
	// derived encryption key returned in Restore2.
	EncryptionSecretShare []byte

	// ZeroSecretShare is the additive-zero share for blind verification.
	ZeroSecretShare []byte

	// CreatedAt is when the record was first stored.
	CreatedAt time.Time

	// UpdatedAt is the most recent mutation. Storage backends that
	// implement TTL semantics expire on (UpdatedAt + RecordTTL).
	UpdatedAt time.Time

	// PendingRotation holds the deltas of an uncommitted RotateStart, persisted so a restart cannot corrupt the record.
	PendingRotation *PendingRotation
}

// PendingRotation captures an in-flight OPRF-key rotation.
type PendingRotation struct {
	NewVersion                 uint32
	OPRFSecretShareDelta       []byte
	EncryptionSecretShareDelta []byte
}

// Clone returns a deep copy so callers can mutate without affecting
// the underlying store. All slices are reallocated.
func (r *Record) Clone() *Record {
	if r == nil {
		return nil
	}
	out := *r
	out.OPRFSecretShare = cloneBytes(r.OPRFSecretShare)
	out.AuthCommitment = cloneBytes(r.AuthCommitment)
	out.EncryptionSecretShare = cloneBytes(r.EncryptionSecretShare)
	out.ZeroSecretShare = cloneBytes(r.ZeroSecretShare)
	if r.PendingRotation != nil {
		pr := *r.PendingRotation
		pr.OPRFSecretShareDelta = cloneBytes(r.PendingRotation.OPRFSecretShareDelta)
		pr.EncryptionSecretShareDelta = cloneBytes(r.PendingRotation.EncryptionSecretShareDelta)
		out.PendingRotation = &pr
	}
	return &out
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
