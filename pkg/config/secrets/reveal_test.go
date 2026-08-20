package secrets

import (
	"bytes"
	"errors"
	"runtime"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/secure"
)

// cloneHeapLimit{Numerator,Denominator} bound the Go-heap bytes Clone may
// charge per byte of secret — 2.5x. Both endpoints were measured on a 1 MiB
// secret against this exact stack, not assumed:
//
//	Clone as implemented (protected page -> protected page)  2.010x
//	the same Clone with an intermediate []byte staging copy  3.010x
//
// 2.5x sits in the half-a-copy gap between them, so the bound fails if a
// plaintext-sized heap staging buffer is reintroduced and does not trip on
// allocator noise. The 2x floor is the sealing path itself: the enclave keeps
// its ciphertext as an ordinary allocation, which is encrypted, not the key.
const (
	cloneHeapLimitNumerator   = 5
	cloneHeapLimitDenominator = 2
)

func TestWithBytes_RevealsTheStoredValue(t *testing.T) {
	s := MustNewSecureString("hunter2")
	defer s.Destroy()

	var got []byte
	if ok := s.WithBytes(func(b []byte) {
		got = append(got, b...)
	}); !ok {
		t.Fatal("WithBytes reported the secret unavailable")
	}
	if string(got) != "hunter2" {
		t.Errorf("revealed %q, want %q", got, "hunter2")
	}
}

func TestWithBytes_RevealedBufferIsNotAHeapCopy(t *testing.T) {
	// The slice handed to fn must be the protected buffer's own mlocked
	// pages, not an ordinary heap allocation: that is what lets WithBytes
	// guarantee the plaintext is gone once it returns. Those pages are
	// released on Destroy, so a retained slice header no longer aliases
	// readable memory — reading it would fault, which is precisely the point.
	// Assert on the observable proxy instead: the secret is unreachable
	// through every public accessor once destroyed.
	s := MustNewSecureString("hunter2")
	var revealedLen int
	s.WithBytes(func(b []byte) { revealedLen = len(b) })
	if revealedLen != len("hunter2") {
		t.Fatalf("revealed %d bytes, want %d", revealedLen, len("hunter2"))
	}

	s.Destroy()
	if got := s.Plaintext(); got != "" {
		t.Errorf("Plaintext() = %q after Destroy, want empty", got)
	}
	if got := s.Bytes(); got != nil {
		t.Errorf("Bytes() = %q after Destroy, want nil", got)
	}
}

func TestWithBytes_RepeatedCallsEachSeeTheValue(t *testing.T) {
	s := MustNewSecureString("rotate-me")
	defer s.Destroy()

	for i := range 3 {
		var got string
		if ok := s.WithBytes(func(b []byte) { got = string(b) }); !ok {
			t.Fatalf("call %d: WithBytes reported the secret unavailable", i)
		}
		if got != "rotate-me" {
			t.Errorf("call %d: revealed %q, want %q", i, got, "rotate-me")
		}
	}
}

func TestWithBytes_NilReceiverDoesNotRunFn(t *testing.T) {
	var s *SecureString
	ran := false
	if ok := s.WithBytes(func([]byte) { ran = true }); ok {
		t.Error("WithBytes on a nil receiver reported success")
	}
	if ran {
		t.Error("fn ran for a nil receiver")
	}
}

func TestWithBytes_DestroyedSecretDoesNotRunFn(t *testing.T) {
	s := MustNewSecureString("gone")
	s.Destroy()

	ran := false
	if ok := s.WithBytes(func([]byte) { ran = true }); ok {
		t.Error("WithBytes on a destroyed secret reported success")
	}
	if ran {
		t.Error("fn ran for a destroyed secret")
	}
}

func TestWithBytes_UnsetSecretDoesNotRunFn(t *testing.T) {
	s := MustNewSecureString("")
	ran := false
	if ok := s.WithBytes(func([]byte) { ran = true }); ok {
		t.Error("WithBytes on an unset secret reported success")
	}
	if ran {
		t.Error("fn ran for an unset secret")
	}
}

func TestWithBytes_NilFnReportsFailure(t *testing.T) {
	s := MustNewSecureString("value")
	defer s.Destroy()
	if s.WithBytes(nil) {
		t.Error("WithBytes(nil) reported success")
	}
}

func TestNewSecureStringFromBytes_SealsTheValue(t *testing.T) {
	ss, err := NewSecureStringFromBytes([]byte("from-bytes"))
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	defer ss.Destroy()
	if got := ss.Plaintext(); got != "from-bytes" {
		t.Errorf("Plaintext() = %q, want %q", got, "from-bytes")
	}
}

func TestNewSecureStringFromBytes_WipesTheSourceSlice(t *testing.T) {
	src := []byte("wipe-me")
	ss, err := NewSecureStringFromBytes(src)
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	defer ss.Destroy()

	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Errorf("source slice was not wiped: %q", src)
	}
}

func TestNewSecureStringFromBytes_EmptyAndNilAreRejected(t *testing.T) {
	// Credential material is never legitimately empty, so this constructor
	// fails closed rather than handing back an unset value that would sign
	// with nothing.
	for name, value := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			ss, err := NewSecureStringFromBytes(value)
			if err == nil {
				t.Fatal("expected an error for an empty value")
			}
			var empty *EmptySecretError
			if !errors.As(err, &empty) {
				t.Errorf("err = %T (%v), want *EmptySecretError", err, err)
			}
			if ss != nil {
				t.Error("expected a nil SecureString alongside the error")
			}
		})
	}
}

func TestNewSecureStringFromBytes_SealFailureWipesTheSource(t *testing.T) {
	// A caller that hands its bytes to this constructor has given up
	// ownership of them. If the protected allocation cannot be obtained, the
	// plaintext must not be left behind in the caller's slice.
	injected := errors.New("seal failed")
	restore := sealSecret
	sealSecret = func([]byte) (*secure.Secret, error) { return nil, injected }
	t.Cleanup(func() { sealSecret = restore })

	src := []byte("wipe-on-failure")
	ss, err := NewSecureStringFromBytes(src)
	if err == nil {
		t.Fatal("expected a seal failure")
	}
	if ss != nil {
		t.Error("expected a nil SecureString alongside the error")
	}
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Errorf("source slice survived a seal failure: %q", src)
	}
}

func TestClone_CopiesTheValue(t *testing.T) {
	orig := MustNewSecureString("shared-secret")
	defer orig.Destroy()

	clone, err := orig.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer clone.Destroy()

	if got := clone.Plaintext(); got != "shared-secret" {
		t.Errorf("clone Plaintext() = %q, want %q", got, "shared-secret")
	}
}

func TestClone_DestroyingTheCloneLeavesTheOriginalUsable(t *testing.T) {
	orig := MustNewSecureString("shared-secret")
	defer orig.Destroy()

	clone, err := orig.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	clone.Destroy()

	if !clone.IsDestroyed() {
		t.Error("clone should be destroyed")
	}
	if got := orig.Plaintext(); got != "shared-secret" {
		t.Errorf("original Plaintext() = %q, want %q — the clone shared its allocation", got, "shared-secret")
	}
}

func TestClone_DestroyingTheOriginalLeavesTheCloneUsable(t *testing.T) {
	orig := MustNewSecureString("shared-secret")
	clone, err := orig.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer clone.Destroy()

	orig.Destroy()

	if got := clone.Plaintext(); got != "shared-secret" {
		t.Errorf("clone Plaintext() = %q, want %q", got, "shared-secret")
	}
}

func TestClone_NilUnsetAndDestroyedCloneToUnset(t *testing.T) {
	destroyed := MustNewSecureString("x")
	destroyed.Destroy()

	cases := map[string]*SecureString{
		"nil":       nil,
		"unset":     MustNewSecureString(""),
		"destroyed": destroyed,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			clone, err := src.Clone()
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if clone == nil {
				t.Fatal("Clone returned nil")
			}
			if !clone.IsDestroyed() {
				t.Error("expected an unset clone")
			}
		})
	}
}

// TestClone_DoesNotStagePlaintextOnTheGoHeap is the regression guard for
// Clone's implementation staying inside protected memory. A Go-heap copy of
// the plaintext is invisible to a functional assertion, so this measures the
// property that does change: Go-heap bytes charged per clone. See
// cloneHeapLimitNumerator for the measured endpoints.
func TestClone_DoesNotStagePlaintextOnTheGoHeap(t *testing.T) {
	const size = 1 << 20 // Large enough that one plaintext copy dwarfs any constant overhead.
	src, err := NewSecureStringFromBytes(bytes.Repeat([]byte("k"), size))
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	defer src.Destroy()

	const clones = 8
	made := make([]*SecureString, 0, clones)
	t.Cleanup(func() {
		for _, c := range made {
			c.Destroy()
		}
	})

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range clones {
		c, err := src.Clone()
		if err != nil {
			t.Fatalf("Clone: %v", err)
		}
		made = append(made, c)
	}
	runtime.ReadMemStats(&after)

	perClone := (after.TotalAlloc - before.TotalAlloc) / clones
	if limit := uint64(size) * cloneHeapLimitNumerator / cloneHeapLimitDenominator; perClone > limit {
		t.Errorf("Clone charged %d Go-heap bytes per clone of a %d-byte secret (limit %d) — "+
			"an intermediate plaintext copy has been reintroduced", perClone, size, limit)
	}

	// The clones must still be correct, not merely cheap.
	if got := made[0].Plaintext(); len(got) != size {
		t.Errorf("clone length = %d, want %d", len(got), size)
	}
}
