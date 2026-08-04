package keys

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// TestGetSignedPreKeyForIdentity_RoundTrip exercises the identity-routed
// signed-pre-key getter against both ACI and PNI partitions.
func TestGetSignedPreKeyForIdentity_RoundTrip(t *testing.T) {
	store := &lowKeyStubStore{}
	mgr := NewKeysManager(store)
	acct := &accounts.Account{UUID: "aci-uuid", PNI: "pni-uuid"}

	if _, err := mgr.GetSignedPreKeyForIdentity(context.Background(), acct, accounts.IdentityTypeACI, accounts.PrimaryDeviceID); err != nil {
		t.Errorf("ACI: %v", err)
	}
	if _, err := mgr.GetSignedPreKeyForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID); err != nil {
		t.Errorf("PNI: %v", err)
	}
}

// TestGetSignedPreKeyForIdentity_MissingIdentity ensures an account with no
// PNI returns ErrIdentityNotSet rather than silently routing to an empty UUID.
func TestGetSignedPreKeyForIdentity_MissingIdentity(t *testing.T) {
	mgr := NewKeysManager(&lowKeyStubStore{})
	acct := &accounts.Account{UUID: "aci-uuid"} // no PNI

	_, err := mgr.GetSignedPreKeyForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID)
	if !errors.Is(err, ErrIdentityNotSet) {
		t.Fatalf("expected ErrIdentityNotSet, got %v", err)
	}
}

// TestForIdentity_AllMethodsRejectMissingPNI consolidates a "no PNI set"
// check across every *ForIdentity helper that wraps resolveIdentityUUID.
// Catches any future variant that forgets the guard.
func TestForIdentity_AllMethodsRejectMissingPNI(t *testing.T) {
	mgr := NewKeysManager(&lowKeyStubStore{})
	acct := &accounts.Account{UUID: "aci"} // no PNI

	cases := []struct {
		name string
		fn   func() error
	}{
		{"StoreKeys", func() error {
			return mgr.StoreKeysForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID, &SetKeysRequest{})
		}},
		{"GetPreKeys", func() error {
			_, err := mgr.GetPreKeysForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID)
			return err
		}},
		{"GetPreKeyCount", func() error {
			_, err := mgr.GetPreKeyCountForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID)
			return err
		}},
		{"StoreSignedPreKey", func() error {
			return mgr.StoreSignedPreKeyForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID, &SignedPreKey{KeyID: 1, PublicKey: []byte("p"), Signature: []byte("s")})
		}},
		{"StoreKEMPreKeys", func() error {
			return mgr.StoreKEMPreKeysForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID, []*KEMSignedPreKey{{KeyID: 1, PublicKey: []byte("p"), Signature: []byte("s")}})
		}},
		{"StoreKEMLastResort", func() error {
			return mgr.StoreKEMLastResortPreKeyForIdentity(context.Background(), acct, accounts.IdentityTypePNI, accounts.PrimaryDeviceID, &KEMSignedPreKey{KeyID: 1, PublicKey: []byte("p"), Signature: []byte("s")})
		}},
	}

	for _, c := range cases {
		if err := c.fn(); !errors.Is(err, ErrIdentityNotSet) {
			t.Errorf("%s: expected ErrIdentityNotSet, got %v", c.name, err)
		}
	}
}
