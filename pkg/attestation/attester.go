// Package attestation provides pluggable enclave attestation for
// long-lived service binaries (cmd/svr2 today, cmd/cdsi in Phase 4.3,
// any future TEE-backed service).
//
// The Attester interface returns the wire-format bytes a Signal client
// expects to see in a Noise handshake's "evidence" + "endorsement"
// fields (see go-libsignal/pkg/attest). What the bytes actually
// attest to depends on the implementation:
//
//   - software.Attester signs the server's static Noise public key
//     (and a small, well-defined payload) with a deployment-time
//     ed25519 key. The operator's PKI rooted at that key is the trust
//     anchor; clients pin the operator cert. Honest about being
//     non-hardware-backed.
//
//   - tpm.Attester uses the platform TPM 2.0 to produce a
//     PCR-bound Quote over the server's static Noise public key. The
//     EK certificate (vendor-signed) anchors the trust chain. This
//     is the future-proof confidential-computing path — modern x86
//     platforms (Intel TDX, AMD SEV-SNP) layer on top of TPM
//     attestation for measurement.
//
// Both impls satisfy the same interface so cmd/svr2 picks one at
// startup via config; future deployments can substitute a TDX or
// SEV-SNP impl without touching the wire surface.
package attestation

import (
	"context"
	"errors"
)

// Evidence is the wire-format payload returned to the client during
// the SVR2 / CDSI client handshake start (see Java protobuf:
// org.signal.svr2.ClientHandshakeStart with fields evidence + endorsement).
//
// Both fields are opaque to the chat-server protocol layer; the client
// parses them per the attestation type negotiated at deployment time.
type Evidence struct {
	// Evidence carries the quote / attestation signature bytes.
	Evidence []byte
	// Endorsement carries the trust-chain bytes the client uses to
	// validate Evidence (EK cert chain for TPM; operator cert chain
	// for software attestation).
	Endorsement []byte
}

// Attester produces fresh Evidence for the supplied bound data. The
// boundData binds the attestation to a specific session — typically
// the server's static Noise public key plus a session nonce — so that
// replayed quotes from a previous server lifetime do not authenticate
// a new connection.
//
// Implementations MUST be safe for concurrent use; cmd/svr2 calls
// Attest from each inbound WebSocket goroutine.
type Attester interface {
	// Attest produces fresh evidence binding to boundData.
	Attest(ctx context.Context, boundData []byte) (*Evidence, error)

	// PublicKey returns the static Noise X25519 public key the
	// attester is committing to. cmd/svr2 also uses this directly as
	// the server static key in NKhfsResponder.
	PublicKey() []byte

	// Type identifies the attestation flavour for diagnostics +
	// metrics labels (e.g. "software", "tpm").
	Type() string
}

// ErrAttestUnavailable is returned by an Attester whose backing
// security primitive is not present on the host. tpm.Attester returns
// this when /dev/tpm0 is missing.
var ErrAttestUnavailable = errors.New("attestation: backing primitive unavailable on this host")

// AttestUnavailableError wraps ErrAttestUnavailable with an
// implementation-specific detail message while preserving errors.Is
// matching on the sentinel.
type AttestUnavailableError struct {
	Detail string
}

// Error implements the error interface.
func (e *AttestUnavailableError) Error() string {
	return ErrAttestUnavailable.Error() + ": " + e.Detail
}

// Unwrap returns ErrAttestUnavailable so errors.Is matches the sentinel.
func (e *AttestUnavailableError) Unwrap() error {
	return ErrAttestUnavailable
}
