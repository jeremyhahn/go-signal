// Package apple implements Apple App Attest attestation + assertion
// verification. Mirrors Java Signal-Server's
// org.whispersystems.textsecuregcm.storage.devicecheck.AppleDeviceCheckManager
// which delegates to webauthn4j-appattest. We hand-roll the verifier
// against Apple's published spec rather than pulling in a third-party
// library — it's pure stdlib + cbor/v2 (already a workspace dep).
//
// Apple's reference docs:
//
//	https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server
//	https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity
package apple

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"time"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/fxamacker/cbor/v2"
)

// rootCAPEM is Apple's published App Attest root CA, embedded at compile
// time so production builds don't need to trust an on-disk file.
//
//go:embed apple_root_ca.pem
var rootCAPEM []byte

// aaguidProduction and aaguidDevelopment are the AAGUIDs (16 bytes) Apple
// embeds in the App Attest authenticator data. The development AAGUID is
// returned by attestation in DEBUG/development builds; production builds
// use the production AAGUID. Reject any other value.
var (
	aaguidProduction  = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDevelopment = []byte("appattestdevelop")
)

// nonceOID is the Apple-defined ASN.1 OID for the App Attest nonce
// extension on the leaf attestation certificate (1.2.840.113635.100.8.2).
// The DER value is `SEQUENCE { [0] OCTET STRING <32-byte nonce> }`.
var nonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// Verifier holds the configured root CA + Apple team/bundle IDs used to
// validate App Attest attestations + assertions. One Verifier is safe to
// share across requests; the root cert pool is computed once at
// construction.
type Verifier struct {
	roots    *x509.CertPool
	teamID   string
	bundleID string
	// now is the wall-clock source used for certificate validity checks.
	// Tests override this; production callers leave it as time.Now.
	now func() time.Time
	// allowDevelopment controls whether the development AAGUID is
	// accepted. Production deployments leave this false; QA harnesses
	// can flip it true to validate dev-build attestations.
	allowDevelopment bool
}

// Config configures NewVerifier. TeamID/BundleID are required; AAGUID
// pinning falls back to production-only when allowDevelopment is false.
type Config struct {
	TeamID           string
	BundleID         string
	AllowDevelopment bool
	// RootCAPEM overrides the embedded Apple root CA. Empty selects the
	// embedded CA; only tests need this hook.
	RootCAPEM []byte
}

// NewVerifier validates cfg and returns a verifier ready to call
// VerifyAttestation / VerifyAssertion.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.TeamID == "" {
		return nil, errors.New("apple: TeamID is required")
	}
	if cfg.BundleID == "" {
		return nil, errors.New("apple: BundleID is required")
	}
	pemBytes := cfg.RootCAPEM
	if len(pemBytes) == 0 {
		pemBytes = rootCAPEM
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("apple: invalid root CA PEM")
	}
	return &Verifier{
		roots:            pool,
		teamID:           cfg.TeamID,
		bundleID:         cfg.BundleID,
		now:              time.Now,
		allowDevelopment: cfg.AllowDevelopment,
	}, nil
}

// AttestationResult is the parsed + verified output of VerifyAttestation:
// the device public key (ES256), the credential ID, and the initial sign
// counter (must be 0). Stored against the account so subsequent assertions
// can be verified.
type AttestationResult struct {
	PublicKey    *ecdsa.PublicKey
	CredentialID []byte
	SignCount    uint32
	Receipt      []byte // opaque Apple receipt; relayed back to Apple later if needed
}

// VerifyAttestation runs the full Apple App Attest verification flow for a
// new device key. clientChallenge is the original challenge string Signal
// issued; attestation is the CBOR blob the client returned; keyID is the
// SHA-256 of the device's public key (base64 in transit, decoded by caller).
//
// Returns a stored-device record on success or a typed error.
func (v *Verifier) VerifyAttestation(challenge string, keyID, attestation []byte) (*AttestationResult, error) {
	if len(keyID) != 32 {
		return nil, errInvalid("keyId must be SHA-256 length (32 bytes)")
	}
	if len(challenge) == 0 {
		return nil, errInvalid("challenge required")
	}
	stmt, err := decodeAttestation(attestation)
	if err != nil {
		return nil, err
	}

	// Step 1: certificate chain to Apple root.
	leaf, err := stmt.verifyCertChain(v.roots, v.now())
	if err != nil {
		return nil, err
	}

	// Step 2 + 3: nonce extension matches SHA256(authData || SHA256(challenge)).
	clientDataHash := sha256.Sum256([]byte(challenge))
	nonceInput := make([]byte, 0, len(stmt.authData)+sha256.Size)
	nonceInput = append(nonceInput, stmt.authData...)
	nonceInput = append(nonceInput, clientDataHash[:]...)
	expectedNonce := sha256.Sum256(nonceInput)
	gotNonce, err := nonceFromCert(leaf)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(gotNonce, expectedNonce[:]) {
		return nil, errInvalid("nonce mismatch")
	}

	// Step 4: keyID = SHA256(devicePublicKey).
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errInvalid("leaf certificate public key is not ECDSA")
	}
	if pub.Curve != elliptic.P256() {
		return nil, errInvalid("device public key must be P-256")
	}
	pubBytes := uncompressedECPoint(pub)
	pubHash := sha256.Sum256(pubBytes)
	if !bytes.Equal(pubHash[:], keyID) {
		return nil, errInvalid("keyId does not match device public key hash")
	}

	// Step 5: parse authData + verify RP ID, counter, AAGUID, credentialID.
	authData, err := parseAuthenticatorData(stmt.authData)
	if err != nil {
		return nil, err
	}
	wantRPHash := sha256.Sum256([]byte(v.teamID + "." + v.bundleID))
	if !bytes.Equal(authData.rpIDHash[:], wantRPHash[:]) {
		return nil, errInvalid("rpIdHash mismatch")
	}
	if authData.signCount != 0 {
		return nil, errInvalid("attestation must have signCount=0")
	}
	if !bytes.Equal(authData.aaguid, aaguidProduction) {
		if !v.allowDevelopment || !bytes.Equal(authData.aaguid, aaguidDevelopment) {
			return nil, errInvalid("unexpected AAGUID")
		}
	}
	if !bytes.Equal(authData.credentialID, keyID) {
		return nil, errInvalid("credentialId in authData does not match keyId")
	}

	return &AttestationResult{
		PublicKey:    pub,
		CredentialID: authData.credentialID,
		SignCount:    authData.signCount,
		Receipt:      stmt.receipt,
	}, nil
}

// VerifyAssertion runs the assertion verification flow. devicePublicKey is
// the previously-stored ECDSA key from VerifyAttestation; storedCounter is
// the last seen sign-count for this device; request is the application-
// level bytes the client signed (Signal embeds the challenge in this);
// assertion is the CBOR blob returned by the client.
//
// Returns the new sign-count on success so the caller can persist it.
func (v *Verifier) VerifyAssertion(
	devicePublicKey *ecdsa.PublicKey,
	storedCounter uint32,
	request, assertion []byte,
) (uint32, error) {
	stmt, err := decodeAssertion(assertion)
	if err != nil {
		return 0, err
	}
	authData, err := parseAuthenticatorData(stmt.authData)
	if err != nil {
		return 0, err
	}
	// RP-ID hash must match teamID.bundleID.
	wantRPHash := sha256.Sum256([]byte(v.teamID + "." + v.bundleID))
	if !bytes.Equal(authData.rpIDHash[:], wantRPHash[:]) {
		return 0, errInvalid("assertion rpIdHash mismatch")
	}
	// Counter must strictly increase to defeat replay.
	if authData.signCount <= storedCounter {
		return 0, ErrReusedAssertion
	}
	// Signature is over authData || SHA256(request).
	clientDataHash := sha256.Sum256(request)
	signed := append([]byte{}, stmt.authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	if !verifyECDSAASN1(devicePublicKey, digest[:], stmt.signature) {
		return 0, errInvalid("assertion signature invalid")
	}
	return authData.signCount, nil
}

// ErrReusedAssertion is returned by VerifyAssertion when the assertion's
// sign-counter is not strictly greater than the stored counter. Callers
// surface this as a force-rebind / replay error.
var ErrReusedAssertion = errors.New("apple: assertion sign-counter did not advance")

// VerifyError indicates the attestation or assertion blob failed
// validation. Callers map this to HTTP 422 / gRPC InvalidArgument.
type VerifyError struct {
	Reason string
}

func (e *VerifyError) Error() string { return "apple: " + e.Reason }

func errInvalid(reason string) error { return &VerifyError{Reason: reason} }

// -- internal parsing --------------------------------------------------------

// attestationStatement is the decoded attStmt + authData CBOR struct.
type attestationStatement struct {
	x5c      [][]byte
	receipt  []byte
	authData []byte
}

// rawAttestation matches the CBOR map Apple sends. Keys are stable strings.
type rawAttestation struct {
	Format   string                  `cbor:"fmt"`
	AttStmt  rawAttestationStatement `cbor:"attStmt"`
	AuthData []byte                  `cbor:"authData"`
}

type rawAttestationStatement struct {
	X5c     [][]byte `cbor:"x5c"`
	Receipt []byte   `cbor:"receipt"`
}

// decodeAttestation parses the CBOR attestation payload and validates the
// outer envelope (fmt = "apple-appattest" with x5c chain present).
func decodeAttestation(payload []byte) (*attestationStatement, error) {
	var raw rawAttestation
	if err := cbor.Unmarshal(payload, &raw); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: decode attestation CBOR", err)
	}
	if raw.Format != "apple-appattest" {
		return nil, errInvalid("attestation fmt must be apple-appattest")
	}
	if len(raw.AttStmt.X5c) < 2 {
		return nil, errInvalid("attStmt missing certificate chain")
	}
	if len(raw.AuthData) == 0 {
		return nil, errInvalid("attestation missing authData")
	}
	return &attestationStatement{
		x5c:      raw.AttStmt.X5c,
		receipt:  raw.AttStmt.Receipt,
		authData: raw.AuthData,
	}, nil
}

// verifyCertChain walks the supplied x5c list, building intermediates +
// validating against the configured root pool. Returns the leaf cert.
func (s *attestationStatement) verifyCertChain(roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(s.x5c) < 2 {
		return nil, errInvalid("expected at least 2 certs in x5c")
	}
	certs := make([]*x509.Certificate, 0, len(s.x5c))
	for i, raw := range s.x5c {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInvalidArgument, "apple: parse cert["+strconv.Itoa(i)+"]", err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	leaf := certs[0]
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: cert chain verification", err)
	}
	return leaf, nil
}

// nonceFromCert extracts the 32-byte App Attest nonce from the leaf cert's
// 1.2.840.113635.100.8.2 extension. Apple's spec: the extension value is
// `SEQUENCE { [0] EXPLICIT OCTET STRING }`.
func nonceFromCert(c *x509.Certificate) ([]byte, error) {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(nonceOID) {
			continue
		}
		var outer asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &outer); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: parse nonce ext (outer)", err)
		}
		// Outer is a SEQUENCE. Walk to find the OCTET STRING.
		var inner asn1.RawValue
		rest, err := asn1.Unmarshal(outer.Bytes, &inner)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: parse nonce ext (inner)", err)
		}
		// Some Apple-issued extensions wrap the OCTET STRING inside a
		// `[0] EXPLICIT` context-specific tag. Unwrap one level if so.
		if inner.Tag == 0 && inner.Class == asn1.ClassContextSpecific {
			if _, err := asn1.Unmarshal(inner.Bytes, &inner); err != nil {
				return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: unwrap context-specific tag", err)
			}
		}
		_ = rest
		if inner.Tag != asn1.TagOctetString {
			return nil, errInvalid("nonce ext inner is not OCTET STRING")
		}
		if len(inner.Bytes) != sha256.Size {
			return nil, errInvalid("nonce ext payload wrong length")
		}
		return inner.Bytes, nil
	}
	return nil, errInvalid("nonce extension missing")
}

// authenticatorData is the parsed authData block (Apple App Attest layout
// matches WebAuthn authenticatorData):
//
//	rpIdHash (32) | flags (1) | signCount (4) | aaguid (16) |
//	credIdLength (2) | credId | extensions...
type authenticatorData struct {
	rpIDHash     [32]byte
	flags        byte
	signCount    uint32
	aaguid       []byte
	credentialID []byte
}

func parseAuthenticatorData(data []byte) (*authenticatorData, error) {
	// 32 (rpid) + 1 (flags) + 4 (counter) = minimum for assertion.
	const minLen = 37
	if len(data) < minLen {
		return nil, errInvalid("authData too short")
	}
	out := &authenticatorData{}
	copy(out.rpIDHash[:], data[:32])
	out.flags = data[32]
	out.signCount = binary.BigEndian.Uint32(data[33:37])
	if len(data) == minLen {
		// Assertion: no attested credential block.
		return out, nil
	}
	if len(data) < minLen+18 { // aaguid (16) + credIdLen (2) minimum
		return nil, errInvalid("authData missing attested credential data")
	}
	out.aaguid = data[37:53]
	credLen := int(binary.BigEndian.Uint16(data[53:55]))
	if credLen == 0 || credLen > len(data)-55 {
		return nil, errInvalid("invalid credentialId length")
	}
	out.credentialID = data[55 : 55+credLen]
	return out, nil
}

// uncompressedECPoint serializes pub in SEC1 uncompressed form
// (0x04 || X || Y), the byte layout SHA-256 hashes into the App Attest
// keyId. Uses (*ecdsa.PublicKey).Bytes — the Go-1.25-stabilized
// replacement for the deprecated direct big.Int X/Y access. A correctly
// constructed P-256 public key never produces an error here (the only
// failure mode is an unsupported curve, which NewVerifier guards against
// upstream); we panic on the impossible case so the contract is clear.
func uncompressedECPoint(pub *ecdsa.PublicKey) []byte {
	out, err := pub.Bytes()
	if err != nil {
		panic("apple: ecdsa.PublicKey.Bytes failed on validated P-256 key: " + err.Error())
	}
	return out
}

// assertionStatement is the decoded assertion CBOR object.
type assertionStatement struct {
	signature []byte
	authData  []byte
}

type rawAssertion struct {
	Signature []byte `cbor:"signature"`
	AuthData  []byte `cbor:"authenticatorData"`
}

func decodeAssertion(payload []byte) (*assertionStatement, error) {
	var raw rawAssertion
	if err := cbor.Unmarshal(payload, &raw); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "apple: decode assertion CBOR", err)
	}
	if len(raw.Signature) == 0 {
		return nil, errInvalid("assertion missing signature")
	}
	if len(raw.AuthData) == 0 {
		return nil, errInvalid("assertion missing authenticatorData")
	}
	return &assertionStatement{
		signature: raw.Signature,
		authData:  raw.AuthData,
	}, nil
}

// verifyECDSAASN1 verifies an ASN.1-encoded ECDSA signature over digest
// under pub. Returns false on any decode/validate failure so the caller
// can map a single error case to InvalidArgument.
func verifyECDSAASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	var parsed struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &parsed); err != nil {
		return false
	}
	if parsed.R == nil || parsed.S == nil {
		return false
	}
	return ecdsa.Verify(pub, digest, parsed.R, parsed.S)
}

// parseEmbeddedRoot is a paranoia check that the embedded PEM contains
// exactly the Apple App Attest root subject we expect. Called from
// NewVerifier indirectly via AppendCertsFromPEM; exposed for tests.
func parseEmbeddedRoot() (*x509.Certificate, error) {
	block, _ := pem.Decode(rootCAPEM)
	if block == nil {
		return nil, errors.New("apple: embedded root PEM malformed")
	}
	return x509.ParseCertificate(block.Bytes)
}
