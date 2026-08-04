package apple

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// fakeAppAttest builds a self-signed Apple-style attestation fixture so we
// can exercise the full VerifyAttestation / VerifyAssertion happy paths
// without an iOS device. The fixture issues its own root CA so the
// Verifier can be configured with it via Config.RootCAPEM.
//
// The fixture produces:
//   - root CA cert
//   - intermediate cert (signed by root)
//   - leaf cert (signed by intermediate) with the App Attest nonce
//     extension over the constructed authData + clientDataHash
//   - authData with rpIdHash(teamID+"."+bundleID), counter, AAGUID,
//     credentialID = SHA256(devicePubBytes)
//   - top-level CBOR attestation map (fmt=apple-appattest)
//
// The fixture also exposes the leaf's private key so the test can sign
// assertion blobs to drive VerifyAssertion.
type fakeAppAttest struct {
	teamID, bundleID string
	rootPEM          []byte
	leafKey          *ecdsa.PrivateKey
	keyID            []byte
}

func newFakeAppAttest(t *testing.T) *fakeAppAttest {
	t.Helper()
	return &fakeAppAttest{teamID: "TEAMID", bundleID: "org.signal.test"}
}

// buildAttestation constructs an attestation CBOR blob over `challenge`
// and returns the raw bytes, the embedded keyID, and the fixture's PEM
// root for Verifier wiring.
func (f *fakeAppAttest) buildAttestation(t *testing.T, challenge string) []byte {
	t.Helper()
	// 1. Root CA (self-signed).
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("root keygen: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Apple App Attest Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("root sign: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	f.rootPEM = []byte("-----BEGIN CERTIFICATE-----\n" + base64Wrap(rootDER) + "-----END CERTIFICATE-----\n")

	// 2. Intermediate.
	intKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Apple App Attest Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTpl, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("int sign: %v", err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	// 3. Device key + computed credentialID.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafPubBytes, err := leafKey.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("PublicKey.Bytes: %v", err)
	}
	keyHash := sha256.Sum256(leafPubBytes)
	f.keyID = keyHash[:]
	f.leafKey = leafKey

	// 4. authData layout: rpid(32) | flags(1) | counter(4) | aaguid(16) |
	//    credLen(2) | credID(32) | empty COSE block (skipped — parser
	//    ignores trailing bytes).
	rpIDHash := sha256.Sum256([]byte(f.teamID + "." + f.bundleID))
	authData := make([]byte, 0, 32+1+4+16+2+32)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x40) // flags: AT (attested credential data included)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, 0)
	authData = append(authData, counter...)
	authData = append(authData, aaguidProduction...)
	credLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(credLenBytes, uint16(len(f.keyID)))
	authData = append(authData, credLenBytes...)
	authData = append(authData, f.keyID...)

	// 5. Leaf cert with nonce extension over authData||SHA256(challenge).
	clientDataHash := sha256.Sum256([]byte(challenge))
	nonceInput := make([]byte, 0, len(authData)+sha256.Size)
	nonceInput = append(nonceInput, authData...)
	nonceInput = append(nonceInput, clientDataHash[:]...)
	nonce := sha256.Sum256(nonceInput)
	// Wrap the nonce in `SEQUENCE { [0] EXPLICIT OCTET STRING <32 bytes> }`
	// matching Apple's actual production extension format.
	nonceOctets, err := asn1.Marshal(nonce[:])
	if err != nil {
		t.Fatalf("marshal nonce octets: %v", err)
	}
	contextWrapped, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: nonceOctets,
	})
	if err != nil {
		t.Fatalf("marshal context tag: %v", err)
	}
	nonceExtVal, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: contextWrapped,
	})
	if err != nil {
		t.Fatalf("marshal SEQUENCE wrapper: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Apple App Attest Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:    nonceOID,
			Value: nonceExtVal,
		}},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, intCert, &leafKey.PublicKey, intKey)
	if err != nil {
		t.Fatalf("leaf sign: %v", err)
	}

	// 6. CBOR encode the attestation.
	att := rawAttestation{
		Format:   "apple-appattest",
		AuthData: authData,
		AttStmt: rawAttestationStatement{
			X5c:     [][]byte{leafDER, intDER},
			Receipt: []byte("test-receipt-bytes"),
		},
	}
	encoded, err := cbor.Marshal(att)
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	return encoded
}

// buildAssertion produces a valid assertion CBOR blob for the supplied
// request bytes + sign counter. Returns the encoded assertion.
func (f *fakeAppAttest) buildAssertion(t *testing.T, request []byte, signCount uint32) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(f.teamID + "." + f.bundleID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x00) // flags
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, signCount)
	authData = append(authData, counter...)

	clientDataHash := sha256.Sum256(request)
	signed := append([]byte{}, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, f.leafKey, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	out, err := cbor.Marshal(rawAssertion{Signature: sig, AuthData: authData})
	if err != nil {
		t.Fatalf("cbor.Marshal assertion: %v", err)
	}
	return out
}

// base64Wrap returns DER bytes as 64-column PEM body lines.
func base64Wrap(der []byte) string {
	const lineLen = 64
	enc := base64StdEncoding(der)
	var out []byte
	for i := 0; i < len(enc); i += lineLen {
		end := i + lineLen
		if end > len(enc) {
			end = len(enc)
		}
		out = append(out, enc[i:end]...)
		out = append(out, '\n')
	}
	return string(out)
}

// base64StdEncoding wraps the stdlib base64 encode to avoid an extra
// import in this test-only file.
func base64StdEncoding(b []byte) []byte {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	pad := (3 - len(b)%3) % 3
	out := make([]byte, 0, ((len(b)+2)/3)*4)
	for i := 0; i+3 <= len(b); i += 3 {
		v := uint32(b[i])<<16 | uint32(b[i+1])<<8 | uint32(b[i+2])
		out = append(out, tbl[(v>>18)&0x3f], tbl[(v>>12)&0x3f], tbl[(v>>6)&0x3f], tbl[v&0x3f])
	}
	if pad > 0 {
		remaining := len(b) - (len(b)/3)*3
		var v uint32
		for i := 0; i < remaining; i++ {
			v |= uint32(b[len(b)-remaining+i]) << uint(16-i*8)
		}
		out = append(out, tbl[(v>>18)&0x3f], tbl[(v>>12)&0x3f])
		if remaining == 2 {
			out = append(out, tbl[(v>>6)&0x3f])
		} else {
			out = append(out, '=')
		}
		out = append(out, '=')
	}
	return out
}
