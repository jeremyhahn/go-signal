package securestorage

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// stubStore is a ManifestStore whose behaviour is fully controlled by injected
// functions. All fields default to nil; a nil function panics if called, which
// makes missing expectations loud rather than silent.
type stubStore struct {
	getManifestFn func(ctx context.Context, accountUUID string) (*StorageManifest, error)
	putManifestFn func(ctx context.Context, accountUUID string, manifest *StorageManifest) error
	getItemFn     func(ctx context.Context, accountUUID string, key []byte) (*StorageItem, error)
	putItemFn     func(ctx context.Context, accountUUID string, item *StorageItem) error
	deleteItemFn  func(ctx context.Context, accountUUID string, key []byte) error
	deleteAllFn   func(ctx context.Context, accountUUID string) error
}

func (s *stubStore) GetManifest(ctx context.Context, accountUUID string) (*StorageManifest, error) {
	return s.getManifestFn(ctx, accountUUID)
}

func (s *stubStore) PutManifest(ctx context.Context, accountUUID string, manifest *StorageManifest) error {
	return s.putManifestFn(ctx, accountUUID, manifest)
}

func (s *stubStore) GetItem(ctx context.Context, accountUUID string, key []byte) (*StorageItem, error) {
	return s.getItemFn(ctx, accountUUID, key)
}

func (s *stubStore) PutItem(ctx context.Context, accountUUID string, item *StorageItem) error {
	return s.putItemFn(ctx, accountUUID, item)
}

func (s *stubStore) DeleteItem(ctx context.Context, accountUUID string, key []byte) error {
	return s.deleteItemFn(ctx, accountUUID, key)
}

func (s *stubStore) DeleteAll(ctx context.Context, accountUUID string) error {
	return s.deleteAllFn(ctx, accountUUID)
}

// errStoreOp is a sentinel error used in stub store error-path tests.
var errStoreOp = errors.New("store operation failed")

// --------------------------------------------------------------------------
// SetSharedSecret
// --------------------------------------------------------------------------

func TestSetSharedSecret_EmptyStringClearsSecret(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetSharedSecret("some-secret")
	m.SetSharedSecret("")
	if m.sharedSecret != nil {
		t.Error("expected nil sharedSecret after setting empty string")
	}
}

func TestSetSharedSecret_NonEmptySetsSecret(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetSharedSecret("my-secret")
	if len(m.sharedSecret) == 0 {
		t.Error("expected non-empty sharedSecret after setting non-empty string")
	}
}

// --------------------------------------------------------------------------
// StorageEnabled
// --------------------------------------------------------------------------

func TestStorageEnabled_FalseWhenNoStore(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	if m.StorageEnabled() {
		t.Error("expected StorageEnabled to return false when no store is configured")
	}
}

func TestStorageEnabled_TrueWhenStoreConfigured(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{})
	if !m.StorageEnabled() {
		t.Error("expected StorageEnabled to return true when store is configured")
	}
}

// --------------------------------------------------------------------------
// GetAuth — HMAC branch
// --------------------------------------------------------------------------

func TestGetAuth_HMACBranchWithSharedSecret(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetSharedSecret("test-secret")

	creds, err := m.GetAuth(context.Background(), "user-uuid-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if creds.Username != "user-uuid-1" {
		t.Errorf("got username %q, want %q", creds.Username, "user-uuid-1")
	}
	// Password should be a hex-encoded HMAC-SHA256 (64 hex chars = 32 bytes).
	if len(creds.Password) != 64 {
		t.Errorf("expected 64-char hex HMAC password, got len %d: %q", len(creds.Password), creds.Password)
	}
	if _, err := hex.DecodeString(creds.Password); err != nil {
		t.Errorf("password is not valid hex: %v", err)
	}
}

func TestGetAuth_HMACIsDeterministic(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetSharedSecret("deterministic-secret")

	c1, _ := m.GetAuth(context.Background(), "uuid-A")
	c2, _ := m.GetAuth(context.Background(), "uuid-A")
	if c1.Password != c2.Password {
		t.Error("HMAC password must be deterministic for the same UUID and secret")
	}
}

func TestGetAuth_HMACAcrossUUIDs(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetSharedSecret("shared-secret")

	c1, _ := m.GetAuth(context.Background(), "uuid-1")
	c2, _ := m.GetAuth(context.Background(), "uuid-2")
	if c1.Password == c2.Password {
		t.Error("expected different HMAC passwords for different UUIDs")
	}
}

// --------------------------------------------------------------------------
// GetManifest — store error path
// --------------------------------------------------------------------------

func TestGetManifest_StoreErrorPropagated(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, errStoreOp
		},
	})

	_, err := m.GetManifest(context.Background(), "acct")
	if err == nil {
		t.Fatal("expected error from store, got nil")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

// --------------------------------------------------------------------------
// Write — error paths
// --------------------------------------------------------------------------

func TestWrite_GetManifestErrorPropagated(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, errStoreOp
		},
	})

	_, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, nil, false)
	if err == nil {
		t.Fatal("expected Write to propagate GetManifest error")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

func TestWrite_ClearAllDeleteAllError(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, &ManifestNotFoundError{AccountUUID: "acct"}
		},
		deleteAllFn: func(_ context.Context, _ string) error {
			return errStoreOp
		},
	})

	_, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, nil, true)
	if err == nil {
		t.Fatal("expected Write to propagate DeleteAll error")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

func TestWrite_DeleteItemNonNotFoundErrorPropagated(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, &ManifestNotFoundError{AccountUUID: "acct"}
		},
		deleteItemFn: func(_ context.Context, _ string, _ []byte) error {
			return errStoreOp
		},
	})

	_, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, [][]byte{[]byte("key-x")}, false)
	if err == nil {
		t.Fatal("expected Write to propagate non-NotFound DeleteItem error")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

func TestWrite_DeleteItemNotFoundErrorIsIgnored(t *testing.T) {
	// Deleting a key that doesn't exist must not fail the write operation.
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, &ManifestNotFoundError{AccountUUID: "acct"}
		},
		deleteItemFn: func(_ context.Context, accountUUID string, key []byte) error {
			return &StorageItemNotFoundError{AccountUUID: accountUUID, Key: key}
		},
		putItemFn: func(_ context.Context, _ string, _ *StorageItem) error {
			return nil
		},
		putManifestFn: func(_ context.Context, _ string, _ *StorageManifest) error {
			return nil
		},
	})

	conflict, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, [][]byte{[]byte("missing-key")}, false)
	if err != nil {
		t.Fatalf("expected no error for not-found delete, got: %v", err)
	}
	if conflict != nil {
		t.Errorf("expected no conflict, got %+v", conflict)
	}
}

func TestWrite_PutItemErrorPropagated(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, &ManifestNotFoundError{AccountUUID: "acct"}
		},
		putItemFn: func(_ context.Context, _ string, _ *StorageItem) error {
			return errStoreOp
		},
	})

	_, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1},
		[]*StorageItem{{Key: []byte("k"), Value: []byte("v")}},
		nil, false)
	if err == nil {
		t.Fatal("expected Write to propagate PutItem error")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

func TestWrite_PutManifestGenericErrorPropagated(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, _ string) (*StorageManifest, error) {
			return nil, &ManifestNotFoundError{AccountUUID: "acct"}
		},
		putManifestFn: func(_ context.Context, _ string, _ *StorageManifest) error {
			return errStoreOp
		},
	})

	_, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, nil, false)
	if err == nil {
		t.Fatal("expected Write to propagate PutManifest generic error")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

func TestWrite_PutManifestRaceReturnsCurrentManifest(t *testing.T) {
	// Simulate a race: the pre-check sees no existing manifest, but PutManifest
	// returns ManifestVersionConflictError (another writer won the race).
	// Write must recover by fetching the now-current manifest and returning it
	// as the conflict.
	raceManifest := &StorageManifest{Version: 99, Value: []byte("winner")}

	getCallCount := 0
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, accountUUID string) (*StorageManifest, error) {
			getCallCount++
			if getCallCount == 1 {
				// First call: no existing manifest → pre-check passes.
				return nil, &ManifestNotFoundError{AccountUUID: accountUUID}
			}
			// Second call (race recovery): return the winner's manifest.
			return raceManifest, nil
		},
		putManifestFn: func(_ context.Context, accountUUID string, _ *StorageManifest) error {
			return &ManifestVersionConflictError{
				AccountUUID:      accountUUID,
				StoredVersion:    99,
				SubmittedVersion: 1,
			}
		},
	})

	conflict, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, nil, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conflict == nil {
		t.Fatal("expected conflict manifest to be returned after race")
	}
	if conflict.Version != 99 {
		t.Errorf("expected conflict version 99, got %d", conflict.Version)
	}
}

func TestWrite_PutManifestRaceRecoveryGetManifestError(t *testing.T) {
	// When the race recovery GetManifest also fails, the error must propagate.
	getCallCount := 0
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getManifestFn: func(_ context.Context, accountUUID string) (*StorageManifest, error) {
			getCallCount++
			if getCallCount == 1 {
				return nil, &ManifestNotFoundError{AccountUUID: accountUUID}
			}
			// Second call during race recovery: the store is also broken.
			return nil, errStoreOp
		},
		putManifestFn: func(_ context.Context, accountUUID string, _ *StorageManifest) error {
			return &ManifestVersionConflictError{
				AccountUUID:      accountUUID,
				StoredVersion:    99,
				SubmittedVersion: 1,
			}
		},
	})

	_, err := m.Write(context.Background(), "acct",
		&StorageManifest{Version: 1}, nil, nil, false)
	if err == nil {
		t.Fatal("expected error from race-recovery GetManifest, got nil")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

// --------------------------------------------------------------------------
// Read — store error path
// --------------------------------------------------------------------------

func TestRead_StoreErrorPropagated(t *testing.T) {
	m := NewSecureStorageManager(testLogger())
	m.SetManifestStore(&stubStore{
		getItemFn: func(_ context.Context, _ string, _ []byte) (*StorageItem, error) {
			return nil, errStoreOp
		},
	})

	_, err := m.Read(context.Background(), "acct", [][]byte{[]byte("key")})
	if err == nil {
		t.Fatal("expected Read to propagate store error")
	}
	if !errors.Is(err, errStoreOp) {
		t.Errorf("expected errStoreOp, got %v", err)
	}
}

// --------------------------------------------------------------------------
// InvalidStorageRequestError
// --------------------------------------------------------------------------

func TestInvalidStorageRequestError_ContainsReason(t *testing.T) {
	err := &InvalidStorageRequestError{Reason: "write operation requires a manifest"}
	msg := err.Error()
	if !strings.Contains(msg, "write operation requires a manifest") {
		t.Errorf("expected reason in error message, got: %s", msg)
	}
}

func TestInvalidStorageRequestError_ContainsInvalidStorageRequest(t *testing.T) {
	err := &InvalidStorageRequestError{Reason: "test reason"}
	msg := err.Error()
	if !strings.Contains(msg, "invalid storage request") {
		t.Errorf("expected 'invalid storage request' prefix in error, got: %s", msg)
	}
}
