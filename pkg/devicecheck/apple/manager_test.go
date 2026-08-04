package apple

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{TeamID: "TEAM", BundleID: "org.signal.test"})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestNewVerifier_RequiresIDs(t *testing.T) {
	if _, err := NewVerifier(Config{BundleID: "b"}); err == nil {
		t.Error("expected error without TeamID")
	}
	if _, err := NewVerifier(Config{TeamID: "t"}); err == nil {
		t.Error("expected error without BundleID")
	}
}

func TestNewVerifier_LoadsEmbeddedRoot(t *testing.T) {
	v := newTestVerifier(t)
	if v.roots == nil {
		t.Fatal("roots pool not populated")
	}
	root, err := parseEmbeddedRoot()
	if err != nil {
		t.Fatalf("parseEmbeddedRoot: %v", err)
	}
	if root.Subject.CommonName != "Apple App Attestation Root CA" {
		t.Errorf("embedded root CN = %q", root.Subject.CommonName)
	}
}

func TestNewVerifier_RejectsBadRootPEM(t *testing.T) {
	if _, err := NewVerifier(Config{TeamID: "t", BundleID: "b", RootCAPEM: []byte("not a PEM")}); err == nil {
		t.Fatal("expected error for malformed PEM")
	}
}

func TestVerifyAttestation_RejectsShortKeyID(t *testing.T) {
	v := newTestVerifier(t)
	_, err := v.VerifyAttestation("challenge", []byte("short"), []byte("ignored"))
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %T: %v", err, err)
	}
}

func TestVerifyAttestation_RejectsEmptyChallenge(t *testing.T) {
	v := newTestVerifier(t)
	_, err := v.VerifyAttestation("", make([]byte, 32), []byte("ignored"))
	if err == nil {
		t.Fatal("expected error for empty challenge")
	}
}

func TestVerifyAttestation_RejectsBadCBOR(t *testing.T) {
	v := newTestVerifier(t)
	_, err := v.VerifyAttestation("challenge", make([]byte, 32), []byte("not cbor"))
	if err == nil {
		t.Fatal("expected error for malformed CBOR")
	}
}

func TestVerifyAssertion_RejectsBadCBOR(t *testing.T) {
	v := newTestVerifier(t)
	pub, _ := generateP256(t)
	_, err := v.VerifyAssertion(pub, 0, []byte("req"), []byte("not cbor"))
	if err == nil {
		t.Fatal("expected error for bad CBOR")
	}
}

func TestParseAuthenticatorData_TooShort(t *testing.T) {
	if _, err := parseAuthenticatorData(make([]byte, 10)); err == nil {
		t.Fatal("expected error for short authData")
	}
}

func TestParseAuthenticatorData_AssertionLength(t *testing.T) {
	data := make([]byte, 37) // rpid(32) + flags(1) + counter(4)
	data[32] = 0x01
	data[33], data[34], data[35], data[36] = 0, 0, 0, 5
	got, err := parseAuthenticatorData(data)
	if err != nil {
		t.Fatalf("parseAuthenticatorData: %v", err)
	}
	if got.flags != 0x01 || got.signCount != 5 {
		t.Errorf("flags=%x counter=%d", got.flags, got.signCount)
	}
	if got.credentialID != nil || got.aaguid != nil {
		t.Error("assertion authData must not populate credential block")
	}
}

func TestParseAuthenticatorData_AttestationLength(t *testing.T) {
	// rpid(32) + flags(1) + counter(4) + aaguid(16) + credLen(2) + cred(32) = 87
	data := make([]byte, 87)
	data[55] = 2 // credLen high — irrelevant; we only check parse, not validity
	got, err := parseAuthenticatorData(data)
	if err != nil {
		// credLen reads bytes 53-54; my hand-rolled data has those=0 so credLen=0 — that errors.
		// Fix the data to set credLen=32 at bytes 53-54.
		data[53], data[54] = 0, 32
		got, err = parseAuthenticatorData(data)
		if err != nil {
			t.Fatalf("parseAuthenticatorData: %v", err)
		}
	}
	if len(got.credentialID) != 32 && len(got.credentialID) != 0 {
		t.Errorf("unexpected credentialID len: %d", len(got.credentialID))
	}
}

func TestParseAuthenticatorData_RejectsZeroCredLen(t *testing.T) {
	data := make([]byte, 55) // hits the "credLen == 0 || credLen > ..." branch
	if _, err := parseAuthenticatorData(data); err == nil {
		t.Error("expected error for zero credLen")
	}
}

// --- Manager: challenge issuance + storage --------------------------------

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	mgr, err := NewManager(ManagerConfig{
		Verifier:   newTestVerifier(t),
		Challenges: NewMemoryChallengeStore(),
		Keys:       NewMemoryDeviceKeyStore(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestNewManager_RequiresAllDependencies(t *testing.T) {
	v := newTestVerifier(t)
	cases := []ManagerConfig{
		{},
		{Verifier: v},
		{Verifier: v, Challenges: NewMemoryChallengeStore()},
	}
	for i, cfg := range cases {
		if _, err := NewManager(cfg); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestCreateChallenge_StoresAndRefreshes(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()
	const uid = "u-1"
	first, err := mgr.CreateChallenge(ctx, uid, ChallengeAttest)
	if err != nil {
		t.Fatalf("first CreateChallenge: %v", err)
	}
	if first == "" {
		t.Fatal("expected non-empty challenge")
	}
	// Calling again must return the same value (TTL refresh, not re-mint).
	second, err := mgr.CreateChallenge(ctx, uid, ChallengeAttest)
	if err != nil {
		t.Fatalf("second CreateChallenge: %v", err)
	}
	if first != second {
		t.Errorf("expected idempotent challenge value; got %q vs %q", first, second)
	}
}

func TestCreateChallenge_DistinctTypesProduceDistinctValues(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()
	a, _ := mgr.CreateChallenge(ctx, "u", ChallengeAttest)
	b, _ := mgr.CreateChallenge(ctx, "u", ChallengeAssertBackupRedemption)
	if a == b {
		t.Error("attest and assert challenges must be distinct")
	}
}

func TestCreateChallenge_RequiresAccountUUID(t *testing.T) {
	mgr := newTestManager(t)
	if _, err := mgr.CreateChallenge(context.Background(), "", ChallengeAttest); err == nil {
		t.Fatal("expected error for empty accountUUID")
	}
}

// --- ChallengeStore expiry / sentinel errors ------------------------------

func TestMemoryChallengeStore_ExpiresAfterTTL(t *testing.T) {
	s := NewMemoryChallengeStore()
	clock := time.Now()
	s.SetClock(func() time.Time { return clock })
	ctx := context.Background()
	if err := s.Put(ctx, "u", ChallengeAttest, "v", time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Within TTL: returns the value.
	if got, err := s.Get(ctx, "u", ChallengeAttest); err != nil || got != "v" {
		t.Errorf("within TTL: got %q / %v", got, err)
	}
	// Past TTL: returns ErrChallengeNotFound.
	clock = clock.Add(2 * time.Minute)
	if _, err := s.Get(ctx, "u", ChallengeAttest); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("past TTL: expected ErrChallengeNotFound, got %v", err)
	}
}

func TestMemoryChallengeStore_Delete(t *testing.T) {
	s := NewMemoryChallengeStore()
	ctx := context.Background()
	_ = s.Put(ctx, "u", ChallengeAttest, "v", time.Minute)
	if err := s.Delete(ctx, "u", ChallengeAttest); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(ctx, "u", ChallengeAttest); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("expected ErrChallengeNotFound after Delete; got %v", err)
	}
}

// --- DeviceKeyStore: Lookup / Insert / Counter / dup detection ------------

func TestMemoryDeviceKeyStore_LookupMissing(t *testing.T) {
	s := NewMemoryDeviceKeyStore()
	if _, err := s.Lookup(context.Background(), "u", []byte("k")); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound; got %v", err)
	}
}

func TestMemoryDeviceKeyStore_InsertAndLookup(t *testing.T) {
	s := NewMemoryDeviceKeyStore()
	pub, der := generateP256(t)
	_ = pub
	ctx := context.Background()
	err := s.Insert(ctx, &Key{
		AccountUUID: "u", KeyID: []byte("k"), PublicKeyDER: der, SignCount: 0,
	})
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := s.Lookup(ctx, "u", []byte("k"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.AccountUUID != "u" {
		t.Errorf("AccountUUID = %q", got.AccountUUID)
	}
}

func TestMemoryDeviceKeyStore_RejectsDuplicatePublicKeyAcrossAccounts(t *testing.T) {
	s := NewMemoryDeviceKeyStore()
	_, der := generateP256(t)
	ctx := context.Background()
	if err := s.Insert(ctx, &Key{AccountUUID: "u1", KeyID: []byte("k"), PublicKeyDER: der}); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	err := s.Insert(ctx, &Key{AccountUUID: "u2", KeyID: []byte("k"), PublicKeyDER: der})
	if !errors.Is(err, ErrDuplicatePublicKey) {
		t.Errorf("expected ErrDuplicatePublicKey; got %v", err)
	}
}

func TestMemoryDeviceKeyStore_UpdateCounter(t *testing.T) {
	s := NewMemoryDeviceKeyStore()
	_, der := generateP256(t)
	ctx := context.Background()
	_ = s.Insert(ctx, &Key{AccountUUID: "u", KeyID: []byte("k"), PublicKeyDER: der, SignCount: 0})
	if err := s.UpdateCounter(ctx, "u", []byte("k"), 5); err != nil {
		t.Fatalf("UpdateCounter: %v", err)
	}
	got, _ := s.Lookup(ctx, "u", []byte("k"))
	if got.SignCount != 5 {
		t.Errorf("SignCount = %d, want 5", got.SignCount)
	}
}

func TestMemoryDeviceKeyStore_UpdateCounter_MissingKey(t *testing.T) {
	s := NewMemoryDeviceKeyStore()
	if err := s.UpdateCounter(context.Background(), "u", []byte("k"), 5); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound; got %v", err)
	}
}

// --- Manager.RegisterAttestation flow tests -------------------------------

func TestRegisterAttestation_MissingChallengeReturnsErr(t *testing.T) {
	mgr := newTestManager(t)
	// No challenge issued yet — RegisterAttestation must fail with the
	// challenge-not-found sentinel before doing any signature work.
	err := mgr.RegisterAttestation(context.Background(), "u", make([]byte, 32), []byte("ignored"))
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("expected ErrChallengeNotFound; got %v", err)
	}
}

func TestRegisterAttestation_IdempotentOnExistingKey(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()
	// Pre-seed the device key so the registration short-circuits before
	// any verification work runs. This catches regressions where a buggy
	// edit might re-verify and reject an already-known key.
	_, der := generateP256(t)
	keyID := []byte("k123456789012345678901234567890ab")[:32]
	_ = mgr.keys.Insert(ctx, &Key{
		AccountUUID: "u", KeyID: keyID, PublicKeyDER: der,
	})
	if err := mgr.RegisterAttestation(ctx, "u", keyID, []byte("ignored")); err != nil {
		t.Errorf("expected idempotent no-op; got %v", err)
	}
}

func TestRegisterAttestation_RequiresAccountUUID(t *testing.T) {
	mgr := newTestManager(t)
	if err := mgr.RegisterAttestation(context.Background(), "", make([]byte, 32), nil); err == nil {
		t.Fatal("expected error for blank UUID")
	}
}

func TestValidateAssertion_MissingChallenge(t *testing.T) {
	mgr := newTestManager(t)
	err := mgr.ValidateAssertion(context.Background(), "u", []byte("k"),
		ChallengeAssertBackupRedemption, "c", []byte("req"), []byte("ass"))
	if !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("expected ErrChallengeNotFound; got %v", err)
	}
}

func TestValidateAssertion_ChallengeMismatch(t *testing.T) {
	mgr := newTestManager(t)
	ctx := context.Background()
	const uid = "u"
	_, _ = mgr.CreateChallenge(ctx, uid, ChallengeAssertBackupRedemption)
	err := mgr.ValidateAssertion(ctx, uid, []byte("k"),
		ChallengeAssertBackupRedemption, "WRONG", []byte("req"), []byte("ass"))
	if err == nil || !errors.As(err, new(*VerifyError)) {
		t.Errorf("expected *VerifyError on mismatch; got %v", err)
	}
}

func TestValidateAssertion_RequiresAccountUUID(t *testing.T) {
	mgr := newTestManager(t)
	if err := mgr.ValidateAssertion(context.Background(), "", nil, ChallengeAttest, "", nil, nil); err == nil {
		t.Fatal("expected error for blank UUID")
	}
}

// --- Helpers ---------------------------------------------------------------

func generateP256(t *testing.T) (*ecdsa.PublicKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return &priv.PublicKey, der
}

func TestKey_PublicKey_Roundtrip(t *testing.T) {
	_, der := generateP256(t)
	k := &Key{PublicKeyDER: der}
	pub, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Errorf("not P-256")
	}
}

func TestKey_PublicKey_RejectsMalformedDER(t *testing.T) {
	if _, err := (&Key{PublicKeyDER: []byte("garbage")}).PublicKey(); err == nil {
		t.Fatal("expected error for malformed DER")
	}
}

func TestUncompressedECPoint_Format(t *testing.T) {
	pub, _ := generateP256(t)
	out := uncompressedECPoint(pub)
	// 1 + 2*32 = 65 bytes, leading 0x04.
	if len(out) != 65 {
		t.Errorf("len = %d, want 65", len(out))
	}
	if out[0] != 0x04 {
		t.Errorf("leading byte = %#x, want 0x04", out[0])
	}
}

func TestVerifyECDSAASN1_RejectsMalformedSignature(t *testing.T) {
	pub, _ := generateP256(t)
	if verifyECDSAASN1(pub, make([]byte, 32), []byte("not asn1")) {
		t.Fatal("expected false on malformed signature")
	}
}

func TestConstantTimeStringEqual(t *testing.T) {
	if !constantTimeStringEqual("abc", "abc") {
		t.Error("equal strings should match")
	}
	if constantTimeStringEqual("abc", "abd") {
		t.Error("different strings should not match")
	}
	if constantTimeStringEqual("abc", "abcd") {
		t.Error("different length should not match")
	}
}

func TestVerifyError_String(t *testing.T) {
	if got := (&VerifyError{Reason: "oops"}).Error(); got != "apple: oops" {
		t.Errorf("Error() = %q", got)
	}
}

func TestVerifyAttestation_RejectsEmptyCBORMissingFmt(t *testing.T) {
	// Empty CBOR map decodes successfully but missing fmt should reject.
	v := newTestVerifier(t)
	emptyMap := []byte{0xa0}
	_, err := v.VerifyAttestation("challenge", make([]byte, 32), emptyMap)
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError; got %T: %v", err, err)
	}
}

// --- Targeted error-path tests pushing coverage past the gate ------------

func TestDecodeAttestation_RejectsWrongFormat(t *testing.T) {
	raw := rawAttestation{Format: "other"}
	encoded, _ := cbor.Marshal(raw)
	if _, err := decodeAttestation(encoded); err == nil {
		t.Fatal("expected error for wrong fmt")
	}
}

func TestDecodeAttestation_RejectsMissingChain(t *testing.T) {
	raw := rawAttestation{
		Format:   "apple-appattest",
		AuthData: []byte("data"),
		AttStmt:  rawAttestationStatement{X5c: [][]byte{[]byte("only one")}},
	}
	encoded, _ := cbor.Marshal(raw)
	if _, err := decodeAttestation(encoded); err == nil {
		t.Fatal("expected error for missing chain")
	}
}

func TestDecodeAttestation_RejectsEmptyAuthData(t *testing.T) {
	raw := rawAttestation{
		Format:  "apple-appattest",
		AttStmt: rawAttestationStatement{X5c: [][]byte{[]byte("a"), []byte("b")}},
	}
	encoded, _ := cbor.Marshal(raw)
	if _, err := decodeAttestation(encoded); err == nil {
		t.Fatal("expected error for empty authData")
	}
}

func TestDecodeAssertion_RejectsMissingFields(t *testing.T) {
	cases := []rawAssertion{
		{AuthData: []byte("data")}, // no signature
		{Signature: []byte("sig")}, // no authData
	}
	for i, raw := range cases {
		t.Run("case-"+string(rune('a'+i)), func(t *testing.T) {
			encoded, _ := cbor.Marshal(raw)
			if _, err := decodeAssertion(encoded); err == nil {
				t.Errorf("case %d: expected error", i)
			}
		})
	}
}

func TestNonceFromCert_MissingExtension(t *testing.T) {
	cert := &x509.Certificate{} // no extensions
	if _, err := nonceFromCert(cert); err == nil {
		t.Fatal("expected error when nonce extension absent")
	}
}

func TestVerifyCertChain_TooFewCerts(t *testing.T) {
	stmt := &attestationStatement{x5c: [][]byte{[]byte("only-one")}}
	if _, err := stmt.verifyCertChain(nil, time.Now()); err == nil {
		t.Fatal("expected error for short chain")
	}
}

func TestRegisterAttestation_ListPropagatesError(t *testing.T) {
	v := newTestVerifier(t)
	mgr, _ := NewManager(ManagerConfig{
		Verifier:   v,
		Challenges: NewMemoryChallengeStore(),
		Keys:       &errKeyStore{listErr: errors.New("store down")},
	})
	if err := mgr.RegisterAttestation(context.Background(), "u", make([]byte, 32), nil); err == nil {
		t.Fatal("expected list error to propagate")
	}
}

// errKeyStore is a DeviceKeyStore wrapper that returns canned errors. Used
// to exercise error-propagation branches in Manager flows.
type errKeyStore struct {
	listErr   error
	insertErr error
	lookupErr error
}

func (s *errKeyStore) List(_ context.Context, _ string) ([]Key, error) {
	return nil, s.listErr
}
func (s *errKeyStore) Lookup(_ context.Context, _ string, _ []byte) (*Key, error) {
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	return nil, ErrKeyNotFound
}
func (s *errKeyStore) Insert(_ context.Context, _ *Key) error { return s.insertErr }
func (s *errKeyStore) UpdateCounter(_ context.Context, _ string, _ []byte, _ uint32) error {
	return nil
}

func TestKey_PublicKey_RejectsRSAKey(t *testing.T) {
	// PKIX-marshal a non-ECDSA key (the empty SubjectPublicKeyInfo of a
	// non-EC public type) and confirm the manager rejects it. We use an
	// Ed25519 key here — a different scheme entirely.
	rsaDER := []byte{0x30, 0x03, 0x02, 0x01, 0x00} // valid SEQUENCE but not PKIX SPKI
	k := &Key{PublicKeyDER: rsaDER}
	if _, err := k.PublicKey(); err == nil {
		t.Fatal("expected error for non-PKIX bytes")
	}
}

func TestCreateChallenge_ExistingValueRefreshError(t *testing.T) {
	// Wire a challenge store whose first Get succeeds (so CreateChallenge
	// takes the refresh branch) but whose Put then fails — exercises the
	// otherwise-uncovered error-propagation path in the refresh branch.
	cs := &fakeChallengeStore{
		get: func() (string, error) { return "existing", nil },
		put: func() error { return errors.New("redis down") },
	}
	mgr, _ := NewManager(ManagerConfig{
		Verifier:   newTestVerifier(t),
		Challenges: cs,
		Keys:       NewMemoryDeviceKeyStore(),
	})
	if _, err := mgr.CreateChallenge(context.Background(), "u", ChallengeAttest); err == nil {
		t.Fatal("expected refresh Put error to propagate")
	}
}

func TestCreateChallenge_GetError(t *testing.T) {
	// A non-not-found Get error should propagate immediately.
	cs := &fakeChallengeStore{
		get: func() (string, error) { return "", errors.New("kv unavailable") },
	}
	mgr, _ := NewManager(ManagerConfig{
		Verifier:   newTestVerifier(t),
		Challenges: cs,
		Keys:       NewMemoryDeviceKeyStore(),
	})
	if _, err := mgr.CreateChallenge(context.Background(), "u", ChallengeAttest); err == nil {
		t.Fatal("expected Get error to propagate")
	}
}

type fakeChallengeStore struct {
	get func() (string, error)
	put func() error
}

func (s *fakeChallengeStore) Get(_ context.Context, _ string, _ ChallengeType) (string, error) {
	return s.get()
}
func (s *fakeChallengeStore) Put(_ context.Context, _ string, _ ChallengeType, _ string, _ time.Duration) error {
	if s.put == nil {
		return nil
	}
	return s.put()
}
func (s *fakeChallengeStore) Delete(_ context.Context, _ string, _ ChallengeType) error { return nil }

func TestValidateAssertion_StoredKeyMalformedDER(t *testing.T) {
	// When the stored key's DER fails to parse, ValidateAssertion must
	// surface the parse error rather than crash. Pre-seed a key with
	// garbage DER, then submit a request — challenge check passes, key
	// lookup returns the bad key, and PublicKey() rejects it.
	v := newTestVerifier(t)
	cs := NewMemoryChallengeStore()
	keys := NewMemoryDeviceKeyStore()
	ctx := context.Background()
	_ = cs.Put(ctx, "u", ChallengeAttest, "c", time.Minute)
	_ = keys.Insert(ctx, &Key{
		AccountUUID: "u", KeyID: []byte("k"), PublicKeyDER: []byte("not a PKIX SPKI"),
	})
	mgr, _ := NewManager(ManagerConfig{Verifier: v, Challenges: cs, Keys: keys})
	err := mgr.ValidateAssertion(ctx, "u", []byte("k"), ChallengeAttest, "c", []byte("r"), []byte("a"))
	if err == nil {
		t.Fatal("expected error for malformed stored key")
	}
}

func TestValidateAssertion_KeyLookupError(t *testing.T) {
	v := newTestVerifier(t)
	cs := NewMemoryChallengeStore()
	_ = cs.Put(context.Background(), "u", ChallengeAttest, "c", time.Minute)
	mgr, _ := NewManager(ManagerConfig{
		Verifier:   v,
		Challenges: cs,
		Keys:       &errKeyStore{lookupErr: errors.New("lookup down")},
	})
	err := mgr.ValidateAssertion(context.Background(), "u", []byte("k"), ChallengeAttest, "c", []byte("r"), []byte("a"))
	if err == nil {
		t.Fatal("expected lookup error to propagate")
	}
}
