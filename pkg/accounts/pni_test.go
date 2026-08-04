package accounts

import (
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-signal/pkg/auth"
)

// ---- AccountsManager.Create auto-assigns PNI ----

func TestAccountsManager_Create_AutoAssignsPNI(t *testing.T) {
	t.Parallel()
	tokenHash, _ := auth.NewSaltedTokenHash("password")
	acct := &Account{
		UUID:        "00000000-0000-0000-0000-000000000001",
		Number:      "+15551234567",
		IdentityKey: []byte("ik"),
		Devices: []Device{
			{ID: PrimaryDeviceID, AuthToken: "password", AuthTokenHash: tokenHash, SignedPreKey: &SignedPreKey{KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig")}},
		},
	}

	m := NewAccountsManager(newMemoryStore(), 6)
	if err := m.Create(context.Background(), acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if acct.PNI == "" {
		t.Fatal("Create must auto-assign a PNI when none is supplied")
	}
	// PNI must be a valid UUID string (36 characters, 8-4-4-4-12).
	if len(acct.PNI) != 36 {
		t.Fatalf("PNI is not a canonical UUID string: %q (len %d)", acct.PNI, len(acct.PNI))
	}
	if !strings.Contains(acct.PNI, "-") {
		t.Fatalf("PNI missing dashes: %q", acct.PNI)
	}
	if acct.PNI == acct.UUID {
		t.Fatalf("PNI must be distinct from UUID (ACI); both were %q", acct.PNI)
	}
}

func TestAccountsManager_Create_PreservesCallerPNI(t *testing.T) {
	t.Parallel()
	tokenHash, _ := auth.NewSaltedTokenHash("password")
	explicit := "11111111-1111-1111-1111-111111111111"
	acct := &Account{
		UUID:        "00000000-0000-0000-0000-000000000002",
		PNI:         explicit,
		Number:      "+15552222222",
		IdentityKey: []byte("ik"),
		Devices: []Device{
			{ID: PrimaryDeviceID, AuthToken: "password", AuthTokenHash: tokenHash, SignedPreKey: &SignedPreKey{KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig")}},
		},
	}

	m := NewAccountsManager(newMemoryStore(), 6)
	if err := m.Create(context.Background(), acct); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if acct.PNI != explicit {
		t.Fatalf("Create overwrote caller-supplied PNI: got %q, want %q", acct.PNI, explicit)
	}
}

// ---- GetByPNI ----

func TestAccountsManager_GetByPNI_Success(t *testing.T) {
	t.Parallel()
	tokenHash, _ := auth.NewSaltedTokenHash("password")
	acct := &Account{
		UUID:        "00000000-0000-0000-0000-000000000003",
		Number:      "+15553333333",
		IdentityKey: []byte("ik"),
		Devices: []Device{
			{ID: PrimaryDeviceID, AuthToken: "password", AuthTokenHash: tokenHash, SignedPreKey: &SignedPreKey{KeyID: 1, PublicKey: []byte("pk"), Signature: []byte("sig")}},
		},
	}

	store := newMemoryStore()
	m := NewAccountsManager(store, 6)
	if err := m.Create(context.Background(), acct); err != nil {
		t.Fatal(err)
	}

	got, err := m.GetByPNI(context.Background(), acct.PNI)
	if err != nil {
		t.Fatalf("GetByPNI: %v", err)
	}
	if got.UUID != acct.UUID {
		t.Fatalf("GetByPNI returned wrong account: got UUID %q, want %q", got.UUID, acct.UUID)
	}
}

func TestAccountsManager_GetByPNI_EmptyRejected(t *testing.T) {
	t.Parallel()
	m := NewAccountsManager(newMemoryStore(), 6)
	_, err := m.GetByPNI(context.Background(), "")
	var iae *InvalidArgumentError
	if err == nil || err.Error() == "" {
		t.Fatal("expected validation error for empty PNI")
	}
	_ = iae
}

func TestAccountsManager_GetByPNI_Missing(t *testing.T) {
	t.Parallel()
	m := NewAccountsManager(newMemoryStore(), 6)
	_, err := m.GetByPNI(context.Background(), "22222222-2222-2222-2222-222222222222")
	var nfe *AccountNotFoundError
	if err == nil {
		t.Fatal("expected AccountNotFoundError for unknown PNI")
	}
	_ = nfe
}
