package recoverypassword

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakeStore is a tiny in-test Store implementation. It avoids a dependency on
// the memory backend so manager tests stay isolated.
type fakeStore struct {
	mu   sync.Mutex
	rows map[string]fakeRow

	getErr error
	putErr error
	delErr error
}

type fakeRow struct {
	hash      *SaltedTokenHash
	expiresAt time.Time
}

func newFakeStore() *fakeStore {
	return &fakeStore{rows: make(map[string]fakeRow)}
}

func (s *fakeStore) Get(_ context.Context, pni string) (*SaltedTokenHash, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getErr != nil {
		return nil, s.getErr
	}
	row, ok := s.rows[pni]
	if !ok {
		return nil, &NotFoundError{PNI: pni}
	}
	clone := *row.hash
	return &clone, nil
}

func (s *fakeStore) Put(_ context.Context, pni string, hash *SaltedTokenHash, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	clone := *hash
	s.rows[pni] = fakeRow{hash: &clone, expiresAt: expiresAt}
	return nil
}

func (s *fakeStore) Delete(_ context.Context, pni string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.rows, pni)
	return nil
}

// TestNewManager_DefaultsAndOverrides covers both the zero/nil default branch
// and the explicit-override branch in a single fixture-driven test.
func TestNewManager_DefaultsAndOverrides(t *testing.T) {
	s := newFakeStore()

	defaults := NewManager(s, 0, nil)
	if defaults.expiration != DefaultExpiration {
		t.Fatalf("expected default expiration; got %s", defaults.expiration)
	}
	if defaults.logger == nil {
		t.Fatal("expected default logger to be set")
	}

	custom := NewManager(s, 1*time.Hour, slog.Default())
	if custom.expiration != 1*time.Hour {
		t.Fatalf("expected 1h expiration; got %s", custom.expiration)
	}
}

func TestManager_Verify_Success(t *testing.T) {
	s := newFakeStore()
	m := NewManager(s, 1*time.Hour, slog.Default())

	pni := "11111111-1111-4111-8111-111111111111"
	pwd := []byte{0x01, 0x02, 0x03}
	if err := m.Store(context.Background(), pni, pwd); err != nil {
		t.Fatalf("Store: %v", err)
	}

	ok, err := m.Verify(context.Background(), pni, pwd)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("expected Verify to accept the original password")
	}
}

func TestManager_Verify_WrongPassword(t *testing.T) {
	s := newFakeStore()
	m := NewManager(s, 1*time.Hour, slog.Default())

	pni := "22222222-2222-4222-8222-222222222222"
	if err := m.Store(context.Background(), pni, []byte("right")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	ok, err := m.Verify(context.Background(), pni, []byte("wrong"))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("expected Verify to reject the wrong password")
	}
}

func TestManager_Verify_NotFoundReturnsFalseNoError(t *testing.T) {
	m := NewManager(newFakeStore(), 1*time.Hour, slog.Default())
	ok, err := m.Verify(context.Background(), "missing", []byte("any"))
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected Verify to return false for missing entry")
	}
}

func TestManager_Verify_StoreError(t *testing.T) {
	s := newFakeStore()
	s.getErr = errors.New("boom")
	m := NewManager(s, 1*time.Hour, slog.Default())

	if _, err := m.Verify(context.Background(), "pni", []byte("p")); err == nil {
		t.Fatal("expected error when store fails")
	}
}

func TestManager_Verify_RejectsEmptyArgs(t *testing.T) {
	m := NewManager(newFakeStore(), 1*time.Hour, slog.Default())

	if _, err := m.Verify(context.Background(), "", []byte("p")); err == nil {
		t.Fatal("expected error for empty PNI")
	}
	if _, err := m.Verify(context.Background(), "pni", nil); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestManager_Store_RejectsEmptyArgs(t *testing.T) {
	m := NewManager(newFakeStore(), 1*time.Hour, slog.Default())

	if err := m.Store(context.Background(), "", []byte("p")); err == nil {
		t.Fatal("expected error for empty PNI")
	}
	if err := m.Store(context.Background(), "pni", nil); err == nil {
		t.Fatal("expected error for empty password")
	}
}

func TestManager_Store_StoreError(t *testing.T) {
	s := newFakeStore()
	s.putErr = errors.New("boom")
	m := NewManager(s, 1*time.Hour, slog.Default())

	if err := m.Store(context.Background(), "pni", []byte("p")); err == nil {
		t.Fatal("expected error when store fails")
	}
}

// TestManager_Store_AppliesExpiration verifies that a fixed clock plus the
// configured expiration produces the deadline the Manager passes to Put.
func TestManager_Store_AppliesExpiration(t *testing.T) {
	s := newFakeStore()
	m := NewManager(s, 5*time.Minute, slog.Default())

	fixed := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	m.SetClock(func() time.Time { return fixed })
	// Setting a nil clock function must be a no-op.
	m.SetClock(nil)

	if err := m.Store(context.Background(), "pni-x", []byte("p")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	row, ok := s.rows["pni-x"]
	if !ok {
		t.Fatal("expected row to be persisted")
	}
	expected := fixed.Add(5 * time.Minute)
	if !row.expiresAt.Equal(expected) {
		t.Fatalf("expected expiry %s, got %s", expected, row.expiresAt)
	}
}

func TestManager_Remove_Success(t *testing.T) {
	s := newFakeStore()
	m := NewManager(s, 1*time.Hour, slog.Default())

	if err := m.Store(context.Background(), "pni-r", []byte("p")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := m.Remove(context.Background(), "pni-r"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := s.rows["pni-r"]; ok {
		t.Fatal("expected row to be deleted")
	}
}

func TestManager_Remove_RejectsEmptyPNI(t *testing.T) {
	m := NewManager(newFakeStore(), 1*time.Hour, slog.Default())
	if err := m.Remove(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty PNI")
	}
}

func TestManager_Remove_StoreError(t *testing.T) {
	s := newFakeStore()
	s.delErr = errors.New("boom")
	m := NewManager(s, 1*time.Hour, slog.Default())

	if err := m.Remove(context.Background(), "pni"); err == nil {
		t.Fatal("expected error when store fails")
	}
}

// TestErrors_Messages exercises the error-formatting branches so coverage
// counts the Error() string-builders.
func TestErrors_Messages(t *testing.T) {
	if got := (&InvalidArgumentError{Field: "x", Message: "y"}).Error(); got == "" {
		t.Fatal("expected non-empty InvalidArgumentError message")
	}
	if got := (&NotFoundError{PNI: "abc"}).Error(); got == "" {
		t.Fatal("expected non-empty NotFoundError message")
	}
}
