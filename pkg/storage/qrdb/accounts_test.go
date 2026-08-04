package qrdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

// newAccount is a small factory that produces a deterministic Account
// fixture with sensible defaults. Callers may override any field after.
func newAccount(uuid, number string) *accounts.Account {
	return &accounts.Account{
		UUID:      uuid,
		Number:    number,
		CreatedAt: time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC),
		Version:   0,
	}
}

func TestAccountStore_Create_Success(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551234567")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(ctx, "u1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.UUID != "u1" || got.Number != "+15551234567" {
		t.Fatalf("Get returned unexpected account: %+v", got)
	}
}

func TestAccountStore_Create_NilAccount_RejectedAsInvalidArgument(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	err := s.Create(context.Background(), nil)
	var iae *accounts.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAccountStore_Create_EmptyUUID_RejectedAsInvalidArgument(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	err := s.Create(context.Background(), &accounts.Account{})
	var iae *accounts.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAccountStore_Create_DuplicateUUID_RejectedAsAlreadyExists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551234567")); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	err := s.Create(ctx, newAccount("u1", "+15559999999"))
	var aae *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aae) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccountStore_Create_DuplicateNumber_RejectedAsAlreadyExists(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551234567")); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	err := s.Create(ctx, newAccount("u2", "+15551234567"))
	var aae *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aae) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccountStore_Create_EmptyNumberAllowed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	// Phone-number-less accounts (e.g., pre-verification) are allowed.
	if err := s.Create(ctx, newAccount("u1", "")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := s.Create(ctx, newAccount("u2", "")); err != nil {
		t.Fatalf("second Create should not conflict on empty number: %v", err)
	}
}

func TestAccountStore_Get_Missing_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	_, err := s.Get(context.Background(), "missing")
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccountStore_GetByNumber_Missing_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	_, err := s.GetByNumber(context.Background(), "+10000000000")
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccountStore_GetByNumber_Existing_ReturnsAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	acct := newAccount("u1", "+15551234567")
	if err := s.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.GetByNumber(ctx, "+15551234567")
	if err != nil {
		t.Fatalf("GetByNumber: %v", err)
	}
	if got.UUID != "u1" {
		t.Fatalf("GetByNumber returned wrong UUID: %s", got.UUID)
	}
}

func TestAccountStore_Update_Success_BumpsVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	acct := newAccount("u1", "+15551234567")
	if err := s.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated := *acct
	updated.Version = 1
	updated.DiscoverableByPhoneNumber = true
	if err := s.Update(ctx, &updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := s.Get(ctx, "u1")
	if err != nil {
		t.Fatalf("Get after Update: %v", err)
	}
	if got.Version != 1 || !got.DiscoverableByPhoneNumber {
		t.Fatalf("Update did not persist: %+v", got)
	}
}

func TestAccountStore_Update_WrongVersion_RejectedAsConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	acct := newAccount("u1", "+15551234567")
	if err := s.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stale := *acct
	stale.Version = 5 // expected 1; caller missed several updates
	err := s.Update(ctx, &stale)
	var vce *accounts.VersionConflictError
	if !errors.As(err, &vce) {
		t.Fatalf("expected VersionConflictError, got %T: %v", err, err)
	}
	if vce.ExpectedVersion != 1 || vce.ActualVersion != 5 {
		t.Fatalf("conflict versions wrong: %+v", vce)
	}
}

func TestAccountStore_Update_MissingAccount_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	err := s.Update(context.Background(), &accounts.Account{UUID: "missing", Version: 1})
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccountStore_Update_NilAccount_Rejected(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	err := s.Update(context.Background(), nil)
	var iae *accounts.InvalidArgumentError
	if !errors.As(err, &iae) {
		t.Fatalf("expected InvalidArgumentError, got %T: %v", err, err)
	}
}

func TestAccountStore_Update_NumberChange_UpdatesMirror(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	acct := newAccount("u1", "+15551234567")
	if err := s.Create(ctx, acct); err != nil {
		t.Fatalf("Create: %v", err)
	}

	updated := *acct
	updated.Version = 1
	updated.Number = "+15559999999"
	if err := s.Update(ctx, &updated); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Old number should no longer resolve.
	if _, err := s.GetByNumber(ctx, "+15551234567"); err == nil {
		t.Fatal("expected old number to be unreachable after change")
	}

	// New number should resolve to the account.
	got, err := s.GetByNumber(ctx, "+15559999999")
	if err != nil {
		t.Fatalf("GetByNumber(new): %v", err)
	}
	if got.UUID != "u1" {
		t.Fatalf("GetByNumber returned wrong UUID: %s", got.UUID)
	}
}

func TestAccountStore_Update_NumberChange_ConflictRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551111111")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, newAccount("u2", "+15552222222")); err != nil {
		t.Fatal(err)
	}

	stealer := newAccount("u1", "+15552222222")
	stealer.Version = 1
	err := s.Update(ctx, stealer)
	var aae *accounts.AccountAlreadyExistsError
	if !errors.As(err, &aae) {
		t.Fatalf("expected AccountAlreadyExistsError, got %T: %v", err, err)
	}
}

func TestAccountStore_Delete_Success_RemovesBothKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551234567")); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Delete(ctx, "u1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := s.Get(ctx, "u1"); err == nil {
		t.Fatal("expected Get after Delete to return NotFound")
	}
	if _, err := s.GetByNumber(ctx, "+15551234567"); err == nil {
		t.Fatal("expected GetByNumber after Delete to return NotFound")
	}
}

func TestAccountStore_Delete_Missing_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())

	err := s.Delete(context.Background(), "missing")
	var nfe *accounts.AccountNotFoundError
	if !errors.As(err, &nfe) {
		t.Fatalf("expected AccountNotFoundError, got %T: %v", err, err)
	}
}

func TestAccountStore_Delete_PreservesOtherAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("u1", "+15551111111")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, newAccount("u2", "+15552222222")); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(ctx, "u1"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.Get(ctx, "u2"); err != nil {
		t.Fatalf("Delete(u1) should not have affected u2: %v", err)
	}
}

func TestAccountStore_ListAll_Empty(t *testing.T) {
	t.Parallel()
	s := NewAccountStore(NewFakeKVStore())
	var visited []*accounts.Account
	err := s.ListAll(context.Background(), func(a *accounts.Account) error {
		visited = append(visited, a)
		return nil
	})
	if err != nil {
		t.Fatalf("ListAll empty: %v", err)
	}
	if len(visited) != 0 {
		t.Errorf("ListAll: expected 0 accounts, got %d", len(visited))
	}
}

func TestAccountStore_ListAll_IteratesAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	for i := 0; i < 3; i++ {
		num := "+1555000000" + string(rune('0'+i))
		uuid := "list-uuid-" + string(rune('a'+i))
		if err := s.Create(ctx, newAccount(uuid, num)); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	var uuids []string
	if err := s.ListAll(ctx, func(a *accounts.Account) error {
		uuids = append(uuids, a.UUID)
		return nil
	}); err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(uuids) != 3 {
		t.Errorf("ListAll: expected 3, got %d", len(uuids))
	}
}

func TestAccountStore_ListAll_FnErrorStopsIteration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewAccountStore(NewFakeKVStore())

	if err := s.Create(ctx, newAccount("stop-u1", "+15550021001")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, newAccount("stop-u2", "+15550021002")); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("stop")
	count := 0
	err := s.ListAll(ctx, func(_ *accounts.Account) error {
		count++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("ListAll: expected sentinel error, got %v", err)
	}
	if count != 1 {
		t.Errorf("ListAll: fn called %d times; expected 1", count)
	}
}
