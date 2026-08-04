// Package svr2 is the server-side state engine for SVR4 backup
// operations. cmd/svr2 wires it behind a Noise-attested WebSocket
// endpoint; this package owns the protocol-level Request4/Response4
// dispatch + the persistent Record state.
//
// One Record per authenticated identity, identified by the
// HMAC-derived auth token the chat-server hands out via
// SVRManager.GetAuth. SVR2's threat model is "the operator does not
// see the secret"; in our software-attestation profile that holds
// only against passive operators. TPM/TDX deployments raise the bar
// to active operators inside the supply chain.
package svr2

import (
	"time"
)

// Record is the per-identity SVR4 state persisted by Storage. It is
// produced by Request4.Create and mutated by Restore1/Restore2/Remove/
// Rotate*. The structure mirrors what an SVR2 enclave keeps in memory
// per session — secret shares plus metadata for the Merkle commitment
// used by the OPRF/PPSS protocol.
type Record struct {
	// Version is the OPRF key version the record currently uses. It
	// is set by Create and rotated by RotateCommit.
	Version uint32

	// MaxTries is the operator-fixed cap on Restore1 attempts before
	// the record auto-deletes itself. Set by Create.
	MaxTries uint32

	// TriesRemaining decrements on every Restore1 call. When it hits
	// zero the record is removed by the server.
	TriesRemaining uint32

	// OPRFSecretShare is the server's share of the OPRF key. Sealed
	// at rest by Storage implementations that support envelope
	// encryption (qrdb backend).
	OPRFSecretShare []byte

	// AuthCommitment is sha256-style commitment used by Restore2 to
	// confirm the client's auth scalar matches the value that bound
	// the secret at Create time.
	AuthCommitment []byte

	// EncryptionSecretShare is the server's share of the secret-
	// derived encryption key returned in Restore2.
	EncryptionSecretShare []byte

	// ZeroSecretShare is the additive-zero share used by the OPRF
	// PPSS variant for blind verification.
	ZeroSecretShare []byte

	// CreatedAt is when the record was first stored.
	CreatedAt time.Time

	// UpdatedAt is the most recent mutation. Storage backends that
	// implement TTL semantics expire on (UpdatedAt + RecordTTL).
	UpdatedAt time.Time

	// PendingRotation, when non-nil, contains the secret-share deltas
	// for an in-flight RotateStart that has not yet been Committed or
	// Rolled-Back. The Java reference's enclave keeps these in memory
	// only; we persist them so a process restart mid-rotation does
	// not corrupt the record.
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
