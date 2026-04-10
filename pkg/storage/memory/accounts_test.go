package memory

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-signal/pkg/accounts"
)

func testAccount(uuid, number string) *accounts.Account {
	return &accounts.Account{
		UUID:                   uuid,
		Number:                 number,
		IdentityKey:            []byte("identity-key-" + uuid),
		PhoneNumberIdentityKey: []byte("pni-key-" + uuid),
		UnidentifiedAccessKey:  []byte("uak-" + uuid),
		UsernameHash:           []byte("hash-" + uuid),
		Devices: []accounts.Device{
			{
				ID:        1,
				Name:      "primary",
				AuthToken: "token-1",
				SignedPreKey: &accounts.SignedPreKey{
					KeyID:     100,
					PublicKey: []byte("spk-pub"),
					Signature: []byte("spk-sig"),
				},
				KyberPreKey: &accounts.KyberPreKey{
					KeyID:     200,
					PublicKey: []byte("kpk-pub"),
					Signature: []byte("kpk-sig"),
				},
			},
		},
		CreatedAt: time.Now(),
	}
}

func TestNewMemoryAccountStore(t *testing.T) {
	store := NewMemoryAccountStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.byUUID == nil {
		t.Fatal("expected byUUID map to be initialized")
	}
	if store.byNumber == nil {
		t.Fatal("expected byNumber map to be initialized")
	}
}

func TestNewMemoryAccountStoreEmptyMaps(t *testing.T) {
	store := NewMemoryAccountStore()
	if len(store.byUUID) != 0 {
		t.Fatalf("expected empty byUUID map, got %d entries", len(store.byUUID))
	}
	if len(store.byNumber) != 0 {
		t.Fatalf("expected empty byNumber map, got %d entries", len(store.byNumber))
	}
}

func TestCreate(t *testing.T) {
	tests := []struct {
		name    string
		account *accounts.Account
	}{
		{
			name:    "account with number",
			account: testAccount("uuid-1", "+15551234567"),
		},
		{
			name:    "account without number",
			account: testAccount("uuid-2", ""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMemoryAccountStore()
			err := store.Create(context.Background(), tt.account)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			got, err := store.Get(context.Background(), tt.account.UUID)
			if err != nil {
				t.Fatalf("unexpected error on Get: %v", err)
			}
			if got.UUID != tt.account.UUID {
				t.Fatalf("expected UUID %q, got %q", tt.account.UUID, got.UUID)
			}
		})
	}
}

func TestCreateDuplicateUUID(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-dup", "+15551111111")

	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err := store.Create(context.Background(), acct)
	if err == nil {
		t.Fatal("expected error for duplicate UUID")
	}

	var alreadyExists *accounts.AccountAlreadyExistsError
	if ae, ok := err.(*accounts.AccountAlreadyExistsError); !ok {
		t.Fatalf("expected *AccountAlreadyExistsError, got %T", err)
	} else {
		alreadyExists = ae
	}
	if alreadyExists.Identifier != "uuid-dup" {
		t.Fatalf("expected identifier %q, got %q", "uuid-dup", alreadyExists.Identifier)
	}
}

func TestCreateDuplicateNumber(t *testing.T) {
	store := NewMemoryAccountStore()

	acct1 := testAccount("uuid-a", "+15559999999")
	if err := store.Create(context.Background(), acct1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	acct2 := testAccount("uuid-b", "+15559999999")
	err := store.Create(context.Background(), acct2)
	if err == nil {
		t.Fatal("expected error for duplicate number")
	}

	if _, ok := err.(*accounts.AccountAlreadyExistsError); !ok {
		t.Fatalf("expected *AccountAlreadyExistsError, got %T", err)
	}
}

func TestCreateDeepCopy(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-dc", "+15550000000")

	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the original.
	acct.IdentityKey[0] = 0xFF
	acct.Number = "+changed"

	got, err := store.Get(context.Background(), "uuid-dc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got.IdentityKey[0] == 0xFF {
		t.Fatal("mutation of original affected stored data")
	}
	if got.Number == "+changed" {
		t.Fatal("mutation of original affected stored number")
	}
}

func TestGet(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-get", "+15551000000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(context.Background(), "uuid-get")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-get" {
		t.Fatalf("expected UUID %q, got %q", "uuid-get", got.UUID)
	}
	if got.Number != "+15551000000" {
		t.Fatalf("expected Number %q, got %q", "+15551000000", got.Number)
	}
}

func TestGetNotFound(t *testing.T) {
	store := NewMemoryAccountStore()
	_, err := store.Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}

	nf, ok := err.(*accounts.AccountNotFoundError)
	if !ok {
		t.Fatalf("expected *AccountNotFoundError, got %T", err)
	}
	if nf.Identifier != "nonexistent" {
		t.Fatalf("expected identifier %q, got %q", "nonexistent", nf.Identifier)
	}
}

func TestGetDeepCopy(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-gdc", "+15552000000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(context.Background(), "uuid-gdc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the returned value.
	got.IdentityKey[0] = 0xAA
	got.Devices[0].SignedPreKey.PublicKey[0] = 0xBB

	got2, err := store.Get(context.Background(), "uuid-gdc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got2.IdentityKey[0] == 0xAA {
		t.Fatal("mutation of returned value affected stored data")
	}
	if got2.Devices[0].SignedPreKey.PublicKey[0] == 0xBB {
		t.Fatal("mutation of returned device data affected stored data")
	}
}

func TestGetByNumber(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-gbn", "+15553000000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.GetByNumber(context.Background(), "+15553000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-gbn" {
		t.Fatalf("expected UUID %q, got %q", "uuid-gbn", got.UUID)
	}
}

func TestGetByNumberNotFound(t *testing.T) {
	store := NewMemoryAccountStore()

	_, err := store.GetByNumber(context.Background(), "+15550000001")
	if err == nil {
		t.Fatal("expected error for nonexistent number")
	}

	if _, ok := err.(*accounts.AccountNotFoundError); !ok {
		t.Fatalf("expected *AccountNotFoundError, got %T", err)
	}
}

func TestGetByNumberOrphanedIndex(t *testing.T) {
	// Simulate an orphaned byNumber entry (number maps to UUID not in byUUID).
	store := NewMemoryAccountStore()
	store.byNumber["+orphan"] = "uuid-orphan"

	_, err := store.GetByNumber(context.Background(), "+orphan")
	if err == nil {
		t.Fatal("expected error for orphaned number index")
	}

	nf, ok := err.(*accounts.AccountNotFoundError)
	if !ok {
		t.Fatalf("expected *AccountNotFoundError, got %T", err)
	}
	if nf.Identifier != "uuid-orphan" {
		t.Fatalf("expected identifier %q, got %q", "uuid-orphan", nf.Identifier)
	}
}

func TestUpdate(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-upd", "+15554000000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated := testAccount("uuid-upd", "+15554000000")
	updated.IdentityKey = []byte("new-identity-key")
	updated.Version = acct.Version + 1 // satisfy optimistic lock: stored version is acct.Version
	if err := store.Update(context.Background(), updated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := store.Get(context.Background(), "uuid-upd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.IdentityKey) != "new-identity-key" {
		t.Fatalf("expected updated identity key, got %q", string(got.IdentityKey))
	}
}

func TestUpdateNotFound(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-missing", "+15555000000")

	err := store.Update(context.Background(), acct)
	if err == nil {
		t.Fatal("expected error for updating nonexistent account")
	}

	if _, ok := err.(*accounts.AccountNotFoundError); !ok {
		t.Fatalf("expected *AccountNotFoundError, got %T", err)
	}
}

func TestUpdateChangeNumber(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-cn", "+15556000000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated := testAccount("uuid-cn", "+15557000000")
	updated.Version = acct.Version + 1 // satisfy optimistic lock
	if err := store.Update(context.Background(), updated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old number should no longer work.
	_, err := store.GetByNumber(context.Background(), "+15556000000")
	if err == nil {
		t.Fatal("expected error for old number after update")
	}

	// New number should work.
	got, err := store.GetByNumber(context.Background(), "+15557000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.UUID != "uuid-cn" {
		t.Fatalf("expected UUID %q, got %q", "uuid-cn", got.UUID)
	}
}

func TestUpdateChangeNumberConflict(t *testing.T) {
	store := NewMemoryAccountStore()

	acct1 := testAccount("uuid-c1", "+15558000000")
	if err := store.Create(context.Background(), acct1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	acct2 := testAccount("uuid-c2", "+15559000000")
	if err := store.Create(context.Background(), acct2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to change acct2's number to acct1's number.
	updated := testAccount("uuid-c2", "+15558000000")
	updated.Version = acct2.Version + 1 // satisfy optimistic lock so we reach the number-conflict check
	err := store.Update(context.Background(), updated)
	if err == nil {
		t.Fatal("expected error for number conflict on update")
	}

	if _, ok := err.(*accounts.AccountAlreadyExistsError); !ok {
		t.Fatalf("expected *AccountAlreadyExistsError, got %T", err)
	}
}

func TestUpdateClearNumber(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-clr", "+15550100000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated := testAccount("uuid-clr", "")
	updated.Version = acct.Version + 1 // satisfy optimistic lock
	if err := store.Update(context.Background(), updated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Old number should no longer work.
	_, err := store.GetByNumber(context.Background(), "+15550100000")
	if err == nil {
		t.Fatal("expected error for cleared number")
	}
}

func TestUpdateDeepCopy(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-udc", "+15550200000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated := testAccount("uuid-udc", "+15550200000")
	updated.IdentityKey = []byte("updated-key")
	updated.Version = acct.Version + 1 // satisfy optimistic lock
	if err := store.Update(context.Background(), updated); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutate the updated struct after Update.
	updated.IdentityKey[0] = 0xFF

	got, err := store.Get(context.Background(), "uuid-udc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.IdentityKey[0] == 0xFF {
		t.Fatal("mutation of updated struct affected stored data")
	}
}

func TestDelete(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-del", "+15550300000")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(context.Background(), "uuid-del"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := store.Get(context.Background(), "uuid-del")
	if err == nil {
		t.Fatal("expected error after delete")
	}

	// Number index should also be cleaned up.
	_, err = store.GetByNumber(context.Background(), "+15550300000")
	if err == nil {
		t.Fatal("expected error for number after account deletion")
	}
}

func TestDeleteNotFound(t *testing.T) {
	store := NewMemoryAccountStore()
	err := store.Delete(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for deleting nonexistent account")
	}

	if _, ok := err.(*accounts.AccountNotFoundError); !ok {
		t.Fatalf("expected *AccountNotFoundError, got %T", err)
	}
}

func TestDeleteNoNumber(t *testing.T) {
	store := NewMemoryAccountStore()
	acct := testAccount("uuid-dnn", "")
	if err := store.Create(context.Background(), acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := store.Delete(context.Background(), "uuid-dnn"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err := store.Get(context.Background(), "uuid-dnn")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestCloneAccount(t *testing.T) {
	original := testAccount("uuid-clone", "+15550400000")
	clone := cloneAccount(original)

	if clone.UUID != original.UUID {
		t.Fatalf("expected UUID %q, got %q", original.UUID, clone.UUID)
	}

	// Mutate clone, ensure original is unaffected.
	clone.IdentityKey[0] = 0xFF
	if original.IdentityKey[0] == 0xFF {
		t.Fatal("clone mutation affected original IdentityKey")
	}

	clone.PhoneNumberIdentityKey[0] = 0xAA
	if original.PhoneNumberIdentityKey[0] == 0xAA {
		t.Fatal("clone mutation affected original PhoneNumberIdentityKey")
	}

	clone.UnidentifiedAccessKey[0] = 0xBB
	if original.UnidentifiedAccessKey[0] == 0xBB {
		t.Fatal("clone mutation affected original UnidentifiedAccessKey")
	}

	clone.UsernameHash[0] = 0xCC
	if original.UsernameHash[0] == 0xCC {
		t.Fatal("clone mutation affected original UsernameHash")
	}
}

func TestCloneAccountNilDevices(t *testing.T) {
	original := &accounts.Account{
		UUID:        "uuid-nd",
		IdentityKey: []byte("key"),
		Devices:     nil,
	}
	clone := cloneAccount(original)
	if clone.Devices != nil {
		t.Fatal("expected nil devices on clone")
	}
}

func TestCloneDevice(t *testing.T) {
	original := &accounts.Device{
		ID:   1,
		Name: "test",
		SignedPreKey: &accounts.SignedPreKey{
			KeyID:     10,
			PublicKey: []byte("pub"),
			Signature: []byte("sig"),
		},
		KyberPreKey: &accounts.KyberPreKey{
			KeyID:     20,
			PublicKey: []byte("kpub"),
			Signature: []byte("ksig"),
		},
	}

	clone := cloneDevice(original)
	clone.SignedPreKey.PublicKey[0] = 0xFF
	if original.SignedPreKey.PublicKey[0] == 0xFF {
		t.Fatal("clone mutation affected original SignedPreKey.PublicKey")
	}

	clone.KyberPreKey.PublicKey[0] = 0xAA
	if original.KyberPreKey.PublicKey[0] == 0xAA {
		t.Fatal("clone mutation affected original KyberPreKey.PublicKey")
	}
}

func TestCloneDeviceNilKeys(t *testing.T) {
	original := &accounts.Device{
		ID:           2,
		SignedPreKey: nil,
		KyberPreKey:  nil,
	}
	clone := cloneDevice(original)
	if clone.SignedPreKey != nil {
		t.Fatal("expected nil SignedPreKey on clone")
	}
	if clone.KyberPreKey != nil {
		t.Fatal("expected nil KyberPreKey on clone")
	}
}

func TestCloneBytes(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"nil input", nil},
		{"empty slice", []byte{}},
		{"normal data", []byte("hello")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cloneBytes(tt.input)
			if tt.input == nil {
				if result != nil {
					t.Fatal("expected nil result for nil input")
				}
				return
			}
			if len(result) != len(tt.input) {
				t.Fatalf("expected len %d, got %d", len(tt.input), len(result))
			}
			// Mutate and verify independence.
			if len(result) > 0 {
				result[0] = 0xFF
				if tt.input[0] == 0xFF {
					t.Fatal("clone mutation affected original")
				}
			}
		})
	}
}

func TestCloneBytesIndependence(t *testing.T) {
	original := []byte{1, 2, 3, 4, 5}
	clone := cloneBytes(original)
	clone[2] = 99
	if original[2] == 99 {
		t.Fatal("clone mutation affected original")
	}
}

func TestAccountStoreConcurrency(t *testing.T) {
	store := NewMemoryAccountStore()
	ctx := context.Background()

	var wg sync.WaitGroup
	const numGoroutines = 50

	// Concurrent creates.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			uuid := "uuid-conc-" + string(rune('A'+idx))
			number := "+1555" + string(rune('0'+idx%10)) + "000" + string(rune('0'+idx/10))
			acct := &accounts.Account{
				UUID:        uuid,
				Number:      number,
				IdentityKey: []byte("key-" + uuid),
			}
			_ = store.Create(ctx, acct)
		}(i)
	}
	wg.Wait()

	// Concurrent reads.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			uuid := "uuid-conc-" + string(rune('A'+idx))
			_, _ = store.Get(ctx, uuid)
		}(i)
	}
	wg.Wait()

	// Concurrent deletes.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			uuid := "uuid-conc-" + string(rune('A'+idx))
			_ = store.Delete(ctx, uuid)
		}(i)
	}
	wg.Wait()
}

// TestUpdateVersionConflict verifies that submitting a stale version returns
// *accounts.VersionConflictError and does not overwrite the stored account.
func TestUpdateVersionConflict(t *testing.T) {
	store := NewMemoryAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-vc", "+15550600000")
	if err := store.Create(ctx, acct); err != nil {
		t.Fatalf("unexpected error creating account: %v", err)
	}

	// First update succeeds: version 0 -> 1.
	first := testAccount("uuid-vc", "+15550600000")
	first.IdentityKey = []byte("key-v1")
	first.Version = 1
	if err := store.Update(ctx, first); err != nil {
		t.Fatalf("unexpected error on first update: %v", err)
	}

	// Second update re-uses the original stale version (1 again, not 2).
	stale := testAccount("uuid-vc", "+15550600000")
	stale.IdentityKey = []byte("key-stale")
	stale.Version = 1 // stale — stored is now 1, expects 2
	err := store.Update(ctx, stale)
	if err == nil {
		t.Fatal("expected VersionConflictError for stale version, got nil")
	}
	if _, ok := err.(*accounts.VersionConflictError); !ok {
		t.Fatalf("expected *accounts.VersionConflictError, got %T: %v", err, err)
	}

	// Stored account must still reflect the first successful update.
	got, err := store.Get(ctx, "uuid-vc")
	if err != nil {
		t.Fatalf("unexpected error getting account: %v", err)
	}
	if string(got.IdentityKey) != "key-v1" {
		t.Errorf("stored identity key = %q, want %q", string(got.IdentityKey), "key-v1")
	}
}

// TestUpdateVersionConflict_ConcurrentWriters verifies that when multiple
// goroutines concurrently attempt to update the same account exactly one
// succeeds and the rest receive VersionConflictError.
func TestUpdateVersionConflict_ConcurrentWriters(t *testing.T) {
	store := NewMemoryAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-cvc", "+15550700000")
	if err := store.Create(ctx, acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	const goroutines = 20
	var successCount atomic.Int64
	var conflictCount atomic.Int64

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			// All goroutines read version 0 and try to write version 1.
			updated := testAccount("uuid-cvc", "+15550700000")
			updated.Version = 1
			err := store.Update(ctx, updated)
			if err == nil {
				successCount.Add(1)
			} else if _, ok := err.(*accounts.VersionConflictError); ok {
				conflictCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := successCount.Load(); got != 1 {
		t.Errorf("expected exactly 1 successful update, got %d", got)
	}
	if got := conflictCount.Load(); got != goroutines-1 {
		t.Errorf("expected %d conflict errors, got %d", goroutines-1, got)
	}
}

func TestAccountStoreConcurrentReadWrite(t *testing.T) {
	store := NewMemoryAccountStore()
	ctx := context.Background()

	acct := testAccount("uuid-crw", "+15550500000")
	if err := store.Create(ctx, acct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = store.Get(ctx, "uuid-crw")
		}()
		go func() {
			defer wg.Done()
			// Read the current version before updating to satisfy the
			// optimistic lock. Errors are intentionally ignored because
			// concurrent callers will race on the version and many will
			// get VersionConflictError — the goal is only to verify
			// absence of data races under the race detector.
			current, err := store.Get(ctx, "uuid-crw")
			if err != nil {
				return
			}
			updated := testAccount("uuid-crw", "+15550500000")
			updated.Version = current.Version + 1
			_ = store.Update(ctx, updated)
		}()
	}
	wg.Wait()
}
