// Package attestation provides pluggable enclave attestation (software ed25519 or TPM 2.0 quote) for Noise handshake evidence and endorsement.
package attestation

import (
	"context"
	"errors"
)

// Evidence is the opaque evidence and endorsement pair of the SVR2/CDSI ClientHandshakeStart.
type Evidence struct {
	// Evidence carries the quote / attestation signature bytes.
	Evidence []byte
	// Endorsement carries the trust-chain bytes the client uses to
	// validate Evidence (EK cert chain for TPM; operator cert chain
	// for software attestation).
	Endorsement []byte
}

// Attester produces Evidence bound to boundData (static key plus session nonce); implementations must be safe for concurrent use.
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
