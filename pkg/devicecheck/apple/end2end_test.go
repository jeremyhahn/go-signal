package apple

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
)

// x509MarshalPKIX is a thin wrapper so the end2end test can produce PKIX
// DER without importing crypto/x509 at the call site.
func x509MarshalPKIX(pub any) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}

// fixtureVerifier wires a Verifier whose root pool trusts the test
// fixture's self-signed CA so VerifyAttestation can complete the chain
// validation against a deterministic in-test trust anchor.
func fixtureVerifier(t *testing.T, f *fakeAppAttest) *Verifier {
	t.Helper()
	v, err := NewVerifier(Config{TeamID: f.teamID, BundleID: f.bundleID, RootCAPEM: f.rootPEM})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestVerifyAttestation_HappyPathEnd2End(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "challenge-value")
	v := fixtureVerifier(t, f)

	got, err := v.VerifyAttestation("challenge-value", f.keyID, att)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}
	if got.PublicKey == nil {
		t.Error("expected PublicKey populated")
	}
	if !bytes.Equal(got.CredentialID, f.keyID) {
		t.Error("CredentialID mismatch")
	}
	if got.SignCount != 0 {
		t.Errorf("SignCount = %d, want 0", got.SignCount)
	}
	if string(got.Receipt) != "test-receipt-bytes" {
		t.Errorf("Receipt = %q", got.Receipt)
	}
}

func TestVerifyAttestation_ChallengeMismatchRejected(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "real-challenge")
	v := fixtureVerifier(t, f)

	_, err := v.VerifyAttestation("wrong-challenge", f.keyID, att)
	if err == nil {
		t.Fatal("expected error on challenge mismatch")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *VerifyError, got %T: %v", err, err)
	}
}

func TestVerifyAttestation_RPIDMismatchRejected(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "c")
	// Verifier configured with a DIFFERENT bundle ID must reject the
	// fixture's RP-ID hash.
	v, err := NewVerifier(Config{TeamID: f.teamID, BundleID: "WRONG", RootCAPEM: f.rootPEM})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.VerifyAttestation("c", f.keyID, att); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestVerifyAttestation_KeyIDMismatchRejected(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "c")
	v := fixtureVerifier(t, f)
	wrongKeyID := make([]byte, 32)
	if _, err := v.VerifyAttestation("c", wrongKeyID, att); err == nil {
		t.Fatal("expected rejection")
	}
}

func TestVerifyAssertion_HappyPathAdvancesCounter(t *testing.T) {
	f := newFakeAppAttest(t)
	// First run the attestation flow so we have a registered public key.
	att := f.buildAttestation(t, "c")
	v := fixtureVerifier(t, f)
	attRes, err := v.VerifyAttestation("c", f.keyID, att)
	if err != nil {
		t.Fatalf("VerifyAttestation: %v", err)
	}

	// Build an assertion at counter=5; current stored counter is 0.
	assertion := f.buildAssertion(t, []byte("application-bytes"), 5)
	newCounter, err := v.VerifyAssertion(attRes.PublicKey, 0, []byte("application-bytes"), assertion)
	if err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
	if newCounter != 5 {
		t.Errorf("newCounter = %d, want 5", newCounter)
	}
}

func TestVerifyAssertion_ReplayRejected(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "c")
	v := fixtureVerifier(t, f)
	attRes, _ := v.VerifyAttestation("c", f.keyID, att)

	assertion := f.buildAssertion(t, []byte("req"), 5)
	// First call accepts counter=5.
	if _, err := v.VerifyAssertion(attRes.PublicKey, 0, []byte("req"), assertion); err != nil {
		t.Fatalf("first VerifyAssertion: %v", err)
	}
	// Replay with the same blob — stored counter is now 5; assertion
	// also reports 5; must be rejected.
	_, err := v.VerifyAssertion(attRes.PublicKey, 5, []byte("req"), assertion)
	if !errors.Is(err, ErrReusedAssertion) {
		t.Errorf("expected ErrReusedAssertion, got %v", err)
	}
}

func TestVerifyAssertion_TamperedRequestRejected(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "c")
	v := fixtureVerifier(t, f)
	attRes, _ := v.VerifyAttestation("c", f.keyID, att)
	assertion := f.buildAssertion(t, []byte("original-request"), 1)
	_, err := v.VerifyAssertion(attRes.PublicKey, 0, []byte("modified-request"), assertion)
	if err == nil {
		t.Fatal("expected signature mismatch")
	}
}

func TestVerifyAssertion_RPIDMismatch(t *testing.T) {
	f := newFakeAppAttest(t)
	att := f.buildAttestation(t, "c")
	v := fixtureVerifier(t, f)
	attRes, _ := v.VerifyAttestation("c", f.keyID, att)
	assertion := f.buildAssertion(t, []byte("req"), 1)
	// Different bundle => RP-ID hash mismatch.
	v2, _ := NewVerifier(Config{TeamID: f.teamID, BundleID: "WRONG", RootCAPEM: f.rootPEM})
	if _, err := v2.VerifyAssertion(attRes.PublicKey, 0, []byte("req"), assertion); err == nil {
		t.Fatal("expected RP-ID mismatch error")
	}
}

// End-to-end Manager flow with the fixture.

func TestManager_FullAttestationFlow(t *testing.T) {
	f := newFakeAppAttest(t)
	const challenge = "deterministic-challenge"
	// Build the attestation FIRST so f.rootPEM is populated before the
	// verifier is constructed against it. fixtureVerifier reads rootPEM
	// during NewVerifier; ordering matters.
	att := f.buildAttestation(t, challenge)

	v := fixtureVerifier(t, f)
	mgr, err := NewManager(ManagerConfig{
		Verifier:   v,
		Challenges: NewMemoryChallengeStore(),
		Keys:       NewMemoryDeviceKeyStore(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	const uid = "11111111-1111-1111-1111-111111111111"
	// Inject the fixture's challenge so VerifyAttestation matches the
	// nonce extension baked into the leaf cert.
	ctx := context.Background()
	if err := mgr.challenges.Put(ctx, uid, ChallengeAttest, challenge, DefaultChallengeTTL); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	if err := mgr.RegisterAttestation(ctx, uid, f.keyID, att); err != nil {
		t.Fatalf("RegisterAttestation: %v", err)
	}

	// Re-running with the same keyID must be idempotent.
	if err := mgr.RegisterAttestation(ctx, uid, f.keyID, att); err != nil {
		t.Errorf("idempotent re-registration: %v", err)
	}

	// Now exercise an assertion flow.
	const reqBytes = "signed-request"
	if err := mgr.challenges.Put(ctx, uid, ChallengeAssertBackupRedemption, "assert-challenge", DefaultChallengeTTL); err != nil {
		t.Fatalf("seed assert challenge: %v", err)
	}
	assertion := f.buildAssertion(t, []byte(reqBytes), 7)
	if err := mgr.ValidateAssertion(ctx, uid, f.keyID, ChallengeAssertBackupRedemption, "assert-challenge",
		[]byte(reqBytes), assertion); err != nil {
		t.Fatalf("ValidateAssertion: %v", err)
	}

	got, err := mgr.keys.Lookup(ctx, uid, f.keyID)
	if err != nil {
		t.Fatalf("Lookup after assertion: %v", err)
	}
	if got.SignCount != 7 {
		t.Errorf("SignCount = %d, want 7", got.SignCount)
	}
}

func TestManager_DuplicatePublicKeyAcrossAccountsRejected(t *testing.T) {
	f := newFakeAppAttest(t)
	const challenge = "dup-challenge"
	att := f.buildAttestation(t, challenge)
	v := fixtureVerifier(t, f)
	keysStore := NewMemoryDeviceKeyStore()
	mgr, _ := NewManager(ManagerConfig{
		Verifier:   v,
		Challenges: NewMemoryChallengeStore(),
		Keys:       keysStore,
	})
	ctx := context.Background()
	// Seed the fixture's public key DER under a DIFFERENT account so
	// the second account's registration trips ErrDuplicatePublicKey.
	pubDER, err := f.leafKey.PublicKey.Bytes()
	if err == nil {
		// PublicKey.Bytes returns SEC1 bytes; we need PKIX DER for the
		// store. Fall back via MarshalPKIXPublicKey.
		_ = pubDER
	}
	pubDER2, err := pubKeyDER(&f.leafKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	other := "00000000-0000-0000-0000-000000000002"
	_ = keysStore.Insert(ctx, &Key{
		AccountUUID: other, KeyID: []byte("seeded-key"), PublicKeyDER: pubDER2,
	})

	const uid = "00000000-0000-0000-0000-000000000001"
	_ = mgr.challenges.Put(ctx, uid, ChallengeAttest, challenge, DefaultChallengeTTL)
	err = mgr.RegisterAttestation(ctx, uid, f.keyID, att)
	if !errors.Is(err, ErrDuplicatePublicKey) {
		t.Errorf("expected ErrDuplicatePublicKey, got %v", err)
	}
}

// pubKeyDER marshals an ECDSA public key in PKIX SubjectPublicKeyInfo
// form. Wraps x509.MarshalPKIXPublicKey for the test-only fixture.
func pubKeyDER(pub interface{}) ([]byte, error) {
	return x509MarshalPKIX(pub)
}

func TestManager_TooManyKeys(t *testing.T) {
	v := newTestVerifier(t)
	keysStore := NewMemoryDeviceKeyStore()
	mgr, _ := NewManager(ManagerConfig{
		Verifier:   v,
		Challenges: NewMemoryChallengeStore(),
		Keys:       keysStore,
	})
	const uid = "user"
	_, der := generateP256(t)
	for i := 0; i < MaxDeviceKeys; i++ {
		key := make([]byte, 32)
		// Stamp a unique non-zero suffix so the slot we use as the
		// "new" attestation key below doesn't accidentally match a
		// pre-seeded one and trip the idempotent-no-op branch.
		key[31] = 0xAA
		key[0] = byte(i + 1)
		key[1] = byte((i + 1) >> 8)
		if err := keysStore.Insert(context.Background(), &Key{
			AccountUUID: uid, KeyID: key, PublicKeyDER: der,
		}); err != nil {
			t.Fatalf("seed key %d: %v", i, err)
		}
		_, der = generateP256(t)
	}
	// Use an all-zero keyID — guaranteed distinct from the seeded set.
	if err := mgr.RegisterAttestation(context.Background(), uid, make([]byte, 32), nil); !errors.Is(err, ErrTooManyKeys) {
		t.Errorf("expected ErrTooManyKeys, got %v", err)
	}
}
