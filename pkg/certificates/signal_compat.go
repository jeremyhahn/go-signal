package certificates

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
)

// SignalSenderCertificateInput collects the fields needed to build a
// byte-wire-compatible Signal SenderCertificate. The Identity, ServerCert
// signing keypair, and TrustRoot are EC-on-Curve25519 keys produced by the
// go-libsignal/pkg/ecc package; the certificate signature scheme is XEdDSA
// over Curve25519 to match Rust libsignal::SenderCertificate exactly.
//
// Mirrors the inputs Rust libsignal_protocol::SenderCertificate::new
// expects — see rust/protocol/src/sealed_sender.rs in the upstream tree
// at the commit pinned by the go-libsignal RUST_REV file.
type SignalSenderCertificateInput struct {
	// SenderUUID is the sender's account UUID (ACI), as a string.
	SenderUUID string

	// SenderE164 is the sender's optional phone number. When empty, the
	// resulting certificate omits the field, supporting anonymous
	// sealed-sender delivery.
	SenderE164 string

	// SenderDevice is the device ID of the sender (1+).
	SenderDevice uint32

	// IdentityKeyBytes is the sender's wire-encoded identity public key
	// (33 bytes: 1 type byte + 32 Curve25519 X coordinate, as produced by
	// go-libsignal/pkg/ecc.ECPublicKey.Serialize).
	IdentityKeyBytes []byte

	// Expiration is the certificate expiry, expressed as a Unix
	// millisecond timestamp.
	Expiration uint64

	// ServerCertKeyID is the opaque key identifier embedded in the
	// ServerCertificate so clients can pick the correct trust-root anchor.
	ServerCertKeyID uint32

	// ServerCertPublic is the public half of the server-cert signing key.
	// Embedded inside the ServerCertificate; used by clients to verify the
	// sender certificate's XEdDSA signature.
	ServerCertPublic ecc.ECPublicKeyable

	// ServerCertPrivate is the private half of the server-cert signing
	// key. Used to XEdDSA-sign the inner SenderCertificate body.
	ServerCertPrivate ecc.ECPrivateKeyable

	// TrustRoot is the long-lived private key whose public half is shipped
	// with clients. Used to XEdDSA-sign the ServerCertificate.
	TrustRoot ecc.ECPrivateKeyable
}

// BuildSignalSenderCertificate assembles a byte-wire-compatible
// libsignal SenderCertificate (protobuf-encoded, XEdDSA-signed) by
// delegating wholly to go-libsignal/pkg/sealed.
//
// This is the canonical, Rust-aligned construction path. The legacy
// CertificatesManager.GetDeliveryCertificate produces a JSON-encoded
// envelope that is NOT byte-wire compatible with Rust libsignal or the
// Java Signal-Server reference; new code must call this helper instead.
//
// The returned bytes are exactly what
// rust/protocol/src/sealed_sender.rs::SenderCertificate::serialize emits
// for the same inputs, modulo random salt; clients verify via
// SenderCertificate::deserialize + Validate(trustRoot, validationTime).
//
// Layering: this helper imports go-libsignal/pkg/sealed and delegates;
// it adds no crypto in this repository. All signing happens inside
// go-libsignal.
func BuildSignalSenderCertificate(in SignalSenderCertificateInput) ([]byte, error) {
	identity, err := ecc.DecodePoint(in.IdentityKeyBytes, 0)
	if err != nil {
		return nil, err
	}

	serverCert, err := sealed.NewServerCertificate(
		in.ServerCertKeyID,
		in.ServerCertPublic,
		in.TrustRoot,
	)
	if err != nil {
		return nil, err
	}

	var e164Ptr *string
	if in.SenderE164 != "" {
		e164 := in.SenderE164
		e164Ptr = &e164
	}

	senderCert, err := sealed.NewSenderCertificate(
		in.SenderUUID,
		e164Ptr,
		identity,
		in.SenderDevice,
		in.Expiration,
		serverCert,
		in.ServerCertPrivate,
	)
	if err != nil {
		return nil, err
	}

	return senderCert.Serialize(), nil
}
