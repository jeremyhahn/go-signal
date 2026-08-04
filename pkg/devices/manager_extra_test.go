package devices

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
	"github.com/jeremyhahn/go-signal/pkg/keys"
)

// setupLinkDeviceTestWithPNI creates a DevicesManager with an account that has
// both an ACI UUID and a PNI UUID, so storeDevicePreKeys can cover the PNI
// pre-key paths.
func setupLinkDeviceTestWithPNI(t *testing.T) (*DevicesManager, *mockProvisioningStore, *mockAccountStore, string) {
	t.Helper()

	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	// Account with both ACI UUID and PNI UUID so identity routing succeeds.
	acctStore.accounts["aci-uuid"] = &accounts.Account{
		UUID:        "aci-uuid",
		PNI:         "pni-uuid",
		Number:      "+15559876543",
		IdentityKey: []byte("identity-key"),
		Devices: []accounts.Device{
			{
				ID:        accounts.PrimaryDeviceID,
				AuthToken: "primary-token",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     1,
					PublicKey: []byte("pub"),
					Signature: []byte("sig"),
				},
			},
		},
	}

	code, err := mgr.CreateProvisioningCode(context.Background(), "aci-uuid")
	if err != nil {
		t.Fatalf("failed to create provisioning code: %v", err)
	}

	return mgr, provStore, acctStore, code.VerificationCode
}

// validKEMPreKeyEntity builds a KEMSignedPreKeyEntity with valid base64 values.
func validKEMPreKeyEntity() KEMSignedPreKeyEntity {
	return KEMSignedPreKeyEntity{
		KeyId:     42,
		PublicKey: base64.StdEncoding.EncodeToString([]byte("kem-public-key")),
		Signature: base64.StdEncoding.EncodeToString([]byte("kem-signature")),
	}
}

// --------------------------------------------------------------------------
// LinkDeviceForAccount
// --------------------------------------------------------------------------

func TestLinkDeviceForAccount_Success(t *testing.T) {
	mgr, provStore, _, code := setupLinkDeviceTest(t)

	// The provisioning session was created for "test-uuid". Linking with the
	// same accountUUID must succeed.
	_ = provStore // already set up by setupLinkDeviceTest
	req := validLinkDeviceRequest(code)
	resp, err := mgr.LinkDeviceForAccount(context.Background(), "test-uuid", code, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.DeviceId == 0 {
		t.Error("expected non-zero device ID")
	}
}

func TestLinkDeviceForAccount_InvalidCode(t *testing.T) {
	mgr, _, _, _ := setupLinkDeviceTest(t)

	req := validLinkDeviceRequest("no-such-code")
	_, err := mgr.LinkDeviceForAccount(context.Background(), "test-uuid", "no-such-code", req)
	if err == nil {
		t.Fatal("expected error for non-existent provisioning code")
	}
	if !isInvalidProvisioningCodeError(err) {
		t.Errorf("expected *InvalidProvisioningCodeError, got %T", err)
	}
}

func TestLinkDeviceForAccount_WrongOwner(t *testing.T) {
	mgr, _, _, code := setupLinkDeviceTest(t)

	// The provisioning code was created for "test-uuid" but we pass a different
	// accountUUID — this must be rejected as an ownership mismatch.
	req := validLinkDeviceRequest(code)
	_, err := mgr.LinkDeviceForAccount(context.Background(), "other-uuid", code, req)
	if err == nil {
		t.Fatal("expected error when session owner does not match accountUUID")
	}
	if !isInvalidProvisioningCodeError(err) {
		t.Errorf("expected *InvalidProvisioningCodeError for ownership mismatch, got %T", err)
	}
}

// isInvalidProvisioningCodeError reports whether err is an *InvalidProvisioningCodeError.
func isInvalidProvisioningCodeError(err error) bool {
	_, ok := err.(*InvalidProvisioningCodeError)
	return ok
}

// --------------------------------------------------------------------------
// decodeKEMPreKeyForStore — signature decode error
// --------------------------------------------------------------------------

func TestDecodeKEMPreKeyForStore_InvalidSignature(t *testing.T) {
	entity := &KEMSignedPreKeyEntity{
		KeyId:     1,
		PublicKey: base64.StdEncoding.EncodeToString([]byte("pub")),
		Signature: "!!!invalid-base64!!!",
	}

	_, err := decodeKEMPreKeyForStore(entity)
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestDecodeKEMPreKeyForStore_InvalidPublicKey(t *testing.T) {
	entity := &KEMSignedPreKeyEntity{
		KeyId:     1,
		PublicKey: "!!!invalid-base64!!!",
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}

	_, err := decodeKEMPreKeyForStore(entity)
	if err == nil {
		t.Fatal("expected error for invalid base64 public key")
	}
}

func TestDecodeKEMPreKeyForStore_Success(t *testing.T) {
	entity := validKEMPreKeyEntity()
	k, err := decodeKEMPreKeyForStore(&entity)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.KeyID != 42 {
		t.Errorf("expected KeyID 42, got %d", k.KeyID)
	}
}

// --------------------------------------------------------------------------
// storeDevicePreKeys — success path with PNI-enabled account
// --------------------------------------------------------------------------

func TestStoreDevicePreKeys_SuccessWithPNI(t *testing.T) {
	mgr, _, _, code := setupLinkDeviceTestWithPNI(t)

	// Build a request with KEM pre-keys set so all decode branches are hit.
	kemKey := validKEMPreKeyEntity()
	req := &LinkDeviceRequest{
		VerificationCode: code,
		AccountAttributes: DeviceAccountAttributes{
			FetchesMessages:   true,
			RegistrationId:    100,
			PniRegistrationId: 200,
			Name:              "pni-device",
		},
		AciSignedPreKey:       validSignedPreKeyEntity(),
		PniSignedPreKey:       validSignedPreKeyEntity(),
		AciPqLastResortPreKey: kemKey,
		PniPqLastResortPreKey: kemKey,
	}

	resp, err := mgr.LinkDevice(context.Background(), code, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.DeviceId == 0 {
		t.Error("expected non-zero device ID")
	}
}

// --------------------------------------------------------------------------
// storeDevicePreKeys — decode error paths
// --------------------------------------------------------------------------

func newDevicesMgrForPreKeyTest(t *testing.T) (*DevicesManager, *accounts.Account) {
	t.Helper()
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	acct := &accounts.Account{
		UUID:        "spk-test-uuid",
		PNI:         "spk-pni-uuid",
		Number:      "+15550000000",
		IdentityKey: []byte("key"),
		Devices: []accounts.Device{
			{ID: accounts.PrimaryDeviceID, AuthToken: "tok"},
		},
	}
	return mgr, acct
}

func TestStoreDevicePreKeys_AciSignedDecodeError(t *testing.T) {
	mgr, acct := newDevicesMgrForPreKeyTest(t)
	req := &LinkDeviceRequest{
		AciSignedPreKey: SignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "!!!not-base64!!!",
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	err := mgr.storeDevicePreKeys(context.Background(), acct, accounts.PrimaryDeviceID, req)
	if err == nil {
		t.Fatal("expected error for invalid ACI signed pre-key public key")
	}
}

func TestStoreDevicePreKeys_AciKEMDecodeError(t *testing.T) {
	mgr, acct := newDevicesMgrForPreKeyTest(t)
	req := &LinkDeviceRequest{
		AciSignedPreKey: validSignedPreKeyEntity(),
		AciPqLastResortPreKey: KEMSignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "!!!not-base64!!!",
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	err := mgr.storeDevicePreKeys(context.Background(), acct, accounts.PrimaryDeviceID, req)
	if err == nil {
		t.Fatal("expected error for invalid ACI KEM public key")
	}
}

func TestStoreDevicePreKeys_PniSignedDecodeError(t *testing.T) {
	mgr, acct := newDevicesMgrForPreKeyTest(t)
	req := &LinkDeviceRequest{
		AciSignedPreKey:       validSignedPreKeyEntity(),
		AciPqLastResortPreKey: validKEMPreKeyEntity(),
		PniSignedPreKey: SignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "!!!not-base64!!!",
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	err := mgr.storeDevicePreKeys(context.Background(), acct, accounts.PrimaryDeviceID, req)
	if err == nil {
		t.Fatal("expected error for invalid PNI signed pre-key public key")
	}
}

func TestStoreDevicePreKeys_PniKEMDecodeError(t *testing.T) {
	mgr, acct := newDevicesMgrForPreKeyTest(t)
	req := &LinkDeviceRequest{
		AciSignedPreKey:       validSignedPreKeyEntity(),
		AciPqLastResortPreKey: validKEMPreKeyEntity(),
		PniSignedPreKey:       validSignedPreKeyEntity(),
		PniPqLastResortPreKey: KEMSignedPreKeyEntity{
			KeyId:     1,
			PublicKey: "!!!not-base64!!!",
			Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
		},
	}
	err := mgr.storeDevicePreKeys(context.Background(), acct, accounts.PrimaryDeviceID, req)
	if err == nil {
		t.Fatal("expected error for invalid PNI KEM public key")
	}
}

// --------------------------------------------------------------------------
// LinkDeviceForAccount — expired code (coverage)
// --------------------------------------------------------------------------

func TestLinkDeviceForAccount_ExpiredCode(t *testing.T) {
	provStore := newMockProvisioningStore()
	acctStore := newMockAccountStore()
	acctMgr := accounts.NewAccountsManager(acctStore, 0)
	keysMgr := keys.NewKeysManager(newMockPreKeyStore())
	mgr := NewDevicesManager(provStore, acctMgr, keysMgr, testLogger())

	// Store an already-expired session.
	provStore.sessions["exp-code"] = &ProvisioningSession{
		Code:      "exp-code",
		UUID:      "test-uuid",
		ExpiresAt: time.Now().Add(-time.Minute),
	}

	req := validLinkDeviceRequest("exp-code")
	_, err := mgr.LinkDeviceForAccount(context.Background(), "test-uuid", "exp-code", req)
	if err == nil {
		t.Fatal("expected error for expired code")
	}
}
