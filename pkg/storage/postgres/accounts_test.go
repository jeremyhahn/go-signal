package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// newAccount builds a deterministic Account for tests. UUID and PNI are
// generated as real UUID strings so they pass Postgres UUID type validation;
// pass empty for fields the test does not care about.
func newAccount(aci, pni, number string) *accounts.Account {
	return &accounts.Account{
		UUID:      aci,
		PNI:       pni,
		Number:    number,
		CreatedAt: time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
		Version:   0,
	}
}

func TestAccounts_Create_Get_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	pni := uuid.NewString()
	want := newAccount(aci, pni, "+15551234567")
	if err := s.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, aci)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UUID != aci || got.PNI != pni || got.Number != "+15551234567" {
		t.Fatalf("Get returned unexpected account: %+v", got)
	}
}

func TestAccounts_Create_NilAccount_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())

	err := s.Create(context.Background(), nil)
	var iae *accounts.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAccounts_Create_DuplicateUUID_ReturnsAlreadyExists(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	if err := s.Create(ctx, newAccount(aci, uuid.NewString(), "+15551111111")); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	err := s.Create(ctx, newAccount(aci, uuid.NewString(), "+15552222222"))
	var aee *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccounts_Create_DuplicateNumber_ReturnsAlreadyExists(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	if err := s.Create(context.Background(),
		newAccount(uuid.NewString(), uuid.NewString(), "+15551234567")); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	err := s.Create(ctx,
		newAccount(uuid.NewString(), uuid.NewString(), "+15551234567"))
	var aee *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccounts_Create_DuplicatePNI_ReturnsAlreadyExists(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	pni := uuid.NewString()
	if err := s.Create(ctx,
		newAccount(uuid.NewString(), pni, "+15551111111")); err != nil {
		t.Fatalf("Create #1: %v", err)
	}
	err := s.Create(ctx,
		newAccount(uuid.NewString(), pni, "+15552222222"))
	var aee *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccounts_GetByNumber_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	if err := s.Create(ctx, newAccount(aci, uuid.NewString(), "+15551234567")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.GetByNumber(ctx, "+15551234567")
	if err != nil {
		t.Fatalf("GetByNumber: %v", err)
	}
	if got.UUID != aci {
		t.Fatalf("GetByNumber: got UUID %q, want %q", got.UUID, aci)
	}
}

func TestAccounts_GetByPNI_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	pni := uuid.NewString()
	if err := s.Create(ctx, newAccount(aci, pni, "+15551234567")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := s.GetByPNI(ctx, pni)
	if err != nil {
		t.Fatalf("GetByPNI: %v", err)
	}
	if got.UUID != aci {
		t.Fatalf("GetByPNI: got UUID %q, want %q", got.UUID, aci)
	}
}

func TestAccounts_Get_Missing_ReturnsNotFound(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())

	_, err := s.Get(context.Background(), uuid.NewString())
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccounts_Update_VersionMonotonic(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	a := newAccount(aci, uuid.NewString(), "+15551234567")
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	a.Version = 1
	a.Number = "+15559999999"
	if err := s.Update(ctx, a); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, aci)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Version != 1 || got.Number != "+15559999999" {
		t.Fatalf("Update did not persist: %+v", got)
	}
}

func TestAccounts_Update_VersionConflict(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	a := newAccount(aci, uuid.NewString(), "+15551234567")
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}

	a.Version = 5 // skip ahead
	err := s.Update(ctx, a)
	var vc *accounts.VersionConflictError
	if !errors.As(err, &vc) {
		t.Fatalf("expected VersionConflictError, got %T: %v", err, err)
	}
}

func TestAccounts_Update_NumberCollision_AcrossAccounts(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	a1 := newAccount(uuid.NewString(), uuid.NewString(), "+15551111111")
	a2 := newAccount(uuid.NewString(), uuid.NewString(), "+15552222222")
	for _, a := range []*accounts.Account{a1, a2} {
		if err := s.Create(ctx, a); err != nil {
			t.Fatalf("Create %s: %v", a.UUID, err)
		}
	}
	a2.Version = 1
	a2.Number = a1.Number
	err := s.Update(ctx, a2)
	var aee *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccounts_Delete_Idempotent_OnMissing(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())

	err := s.Delete(context.Background(), uuid.NewString())
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccounts_Create_EmptyUUID_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())

	err := s.Create(context.Background(), &accounts.Account{UUID: "", Number: "+15551234567"})
	var iae *accounts.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError for empty UUID, got %T: %v", err, err)
	}
}

func TestAccounts_Update_NilAccount_Rejected(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())

	err := s.Update(context.Background(), nil)
	var iae *accounts.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError for nil account, got %T: %v", err, err)
	}
}

// TestAccounts_Update_AccountNotFound exercises the branch where Update
// finds zero rows and Get returns AccountNotFoundError (account was deleted
// between insert and update attempt).
func TestAccounts_Update_AccountNotFound_AfterDelete(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	a := newAccount(aci, uuid.NewString(), "+15551234567")
	if err := s.Create(ctx, a); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, aci); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Update must surface AccountNotFoundError because the row is gone.
	a.Version = 1
	err := s.Update(ctx, a)
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError after delete, got %T: %v", err, err)
	}
}

// TestAccounts_Create_DuplicateUsernameHash exercises the accounts_username_hash_key
// constraint branch inside identifyConflict.
func TestAccounts_Create_DuplicateUsernameHash_ReturnsAlreadyExists(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	hash := []byte("shared-username-hash")
	a1 := newAccount(uuid.NewString(), uuid.NewString(), "+15551110001")
	a1.UsernameHash = hash
	if err := s.Create(ctx, a1); err != nil {
		t.Fatalf("Create #1: %v", err)
	}

	a2 := newAccount(uuid.NewString(), uuid.NewString(), "+15551110002")
	a2.UsernameHash = hash
	err := s.Create(ctx, a2)
	var aee *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected AccountAlreadyExistsError for dup hash, got %T: %v", err, err)
	}
}

// TestAccounts_Create_DuplicateUsernameLinkHandle exercises the
// accounts_username_link_handle_key constraint branch inside identifyConflict.
func TestAccounts_Create_DuplicateUsernameLinkHandle_ReturnsAlreadyExists(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	sharedHandle := "shared-link-handle"
	a1 := newAccount(uuid.NewString(), uuid.NewString(), "+15551120001")
	a1.Username = sharedHandle
	if err := s.Create(ctx, a1); err != nil {
		t.Fatalf("Create #1: %v", err)
	}

	a2 := newAccount(uuid.NewString(), uuid.NewString(), "+15551120002")
	a2.Username = sharedHandle
	err := s.Create(ctx, a2)
	var aee *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aee) {
		t.Fatalf("expected AccountAlreadyExistsError for dup handle, got %T: %v", err, err)
	}
}

// TestAccounts_nullableUUID_BothBranches exercises both branches of nullableUUID.
func TestAccounts_nullableUUID_BothBranches(t *testing.T) {
	if got := nullableUUID(""); got != nil {
		t.Fatalf("expected nil for empty UUID, got %v", got)
	}
	got := nullableUUID("some-uuid")
	if got == nil {
		t.Fatal("expected non-nil for non-empty UUID")
	}
	if got.(string) != "some-uuid" {
		t.Fatalf("expected %q, got %v", "some-uuid", got)
	}
}

// TestAccounts_nullableBytes_BothBranches exercises both branches of nullableBytes.
func TestAccounts_nullableBytes_BothBranches(t *testing.T) {
	if got := nullableBytes(nil); got != nil {
		t.Fatalf("expected nil for nil bytes, got %v", got)
	}
	if got := nullableBytes([]byte{}); got != nil {
		t.Fatalf("expected nil for empty bytes, got %v", got)
	}
	b := []byte{0x01, 0x02}
	got := nullableBytes(b)
	if got == nil {
		t.Fatal("expected non-nil for non-empty bytes")
	}
}

func TestAccounts_Delete_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	c.Close()

	err := s.Delete(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	var nfe *accounts.AccountNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not AccountNotFoundError")
	}
}

func TestAccounts_Create_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	c.Close()

	err := s.Create(context.Background(), newAccount(uuid.NewString(), uuid.NewString(), "+15551239999"))
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
}

// TestAccounts_scanOne_PoolClosed exercises the query error branch in scanOne.
func TestAccounts_scanOne_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	c.Close()

	_, err := s.Get(context.Background(), uuid.NewString())
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	// Must NOT be AccountNotFoundError — that's reserved for pgx.ErrNoRows.
	var nfe *accounts.AccountNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected a pool error, got AccountNotFoundError")
	}
}

func TestAccounts_Update_PoolClosed_ReturnsError(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	c.Close()

	acct := newAccount(uuid.NewString(), uuid.NewString(), "+15559990001")
	acct.Version = 1
	err := s.Update(context.Background(), acct)
	if err == nil {
		t.Fatal("expected error from closed pool")
	}
	// Must not be a typed domain error — it's a pool-level failure.
	var vc *accounts.VersionConflictError
	if errors.As(err, &vc) {
		t.Fatal("expected pool error, not VersionConflictError")
	}
	var nfe *accounts.AccountNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected pool error, not AccountNotFoundError")
	}
}

func TestAccounts_Delete_Roundtrip(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	if err := s.Create(ctx, newAccount(aci, uuid.NewString(), "+15551234567")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Delete(ctx, aci); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(ctx, aci)
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected NotFound after delete, got %T: %v", err, err)
	}
}

// TestAccounts_Get_CorruptedData_UnmarshalError exercises the json.Unmarshal
// error branch in scanOne (accounts.go:175-177). A row is inserted via raw SQL
// with a data value whose "CreatedAt" field is not a valid RFC3339 time string,
// causing json.Unmarshal to fail even though the row exists and is found.
func TestAccounts_Get_CorruptedData_UnmarshalError(t *testing.T) {
	c := newTestClient(t)
	s := NewAccountStore(c.Pool())
	ctx := context.Background()

	aci := uuid.NewString()
	pni := uuid.NewString()

	_, err := c.Pool().Exec(ctx,
		`INSERT INTO accounts (aci, pni, e164, version, data)
		 VALUES ($1, $2, '+15559876543', 0, '{"CreatedAt":"NOT-A-TIME"}'::jsonb)`,
		aci, pni,
	)
	if err != nil {
		t.Fatalf("raw insert corrupted account: %v", err)
	}

	_, err = s.Get(ctx, aci)
	if err == nil {
		t.Fatal("expected unmarshal error, got nil")
	}
	var nfe *accounts.AccountNotFoundError
	if errors.As(err, &nfe) {
		t.Fatal("expected unmarshal error, not AccountNotFoundError")
	}
}
