package secrets

import (
	"bytes"
	"context"
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

// revealHeapLimitNumerator/Denominator bound the Go-heap bytes WithBytes may
// charge per reveal, as a multiple of the plaintext size. Measured endpoints
// on a 1 MiB secret: 1.001x when fn receives the protected buffer directly,
// 2.001x when a plaintext-sized heap copy is staged for it. 1.5x sits between
// them with room for allocator noise on either side.
//
// The 1x floor is Open itself — the enclave decrypts into a fresh buffer,
// which is what fn then borrows. What this bounds is a SECOND copy on top of
// that, which is the shape the defect would take.
const (
	revealHeapLimitNumerator   = 3
	revealHeapLimitDenominator = 2
)

func TestWithBytes_RevealsTheStoredValue(t *testing.T) {
	s := MustNewSecureString(t.Context(), "hunter2")
	defer s.Destroy()

	var got []byte
	if ok := s.WithBytes(t.Context(), func(b []byte) {
		got = append(got, b...)
	}); !ok {
		t.Fatal("WithBytes reported the secret unavailable")
	}
	if string(got) != "hunter2" {
		t.Errorf("revealed %q, want %q", got, "hunter2")
	}
}

// TestWithBytes_RevealedBufferIsNotAHeapCopy measures the property that
// actually changes if fn is handed a heap copy instead of the protected
// buffer's own pages. The accessor checks below are necessary but not
// sufficient — they stay green whether or not a copy was staged, which the
// previous version of this test conceded in its own comment. See
// revealHeapLimitNumerator for the measured endpoints.
func TestWithBytes_RevealedBufferIsNotAHeapCopy(t *testing.T) {
	const size = 1 << 20 // Large enough that one plaintext copy dwarfs constant overhead.
	big, err := NewSecureStringFromBytes(t.Context(), bytes.Repeat([]byte("k"), size))
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	defer big.Destroy()

	const reveals = 8
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range reveals {
		if ok := big.WithBytes(t.Context(), func(b []byte) {
			if len(b) != size {
				t.Errorf("revealed %d bytes, want %d", len(b), size)
			}
		}); !ok {
			t.Fatal("WithBytes reported the secret unavailable")
		}
	}
	runtime.ReadMemStats(&after)

	perReveal := (after.TotalAlloc - before.TotalAlloc) / reveals
	if limit := uint64(size) * revealHeapLimitNumerator / revealHeapLimitDenominator; perReveal > limit {
		t.Errorf("WithBytes charged %d Go-heap bytes per reveal (%.3fx the secret), limit %d (%.1fx): "+
			"fn is being handed a heap copy rather than the protected buffer",
			perReveal, float64(perReveal)/float64(size), limit,
			float64(revealHeapLimitNumerator)/float64(revealHeapLimitDenominator))
	}

	// The plaintext is also unreachable through every public accessor once
	// destroyed — necessary, but on its own it would not have caught a copy.
	s := MustNewSecureString(t.Context(), "hunter2")
	var revealedLen int
	s.WithBytes(t.Context(), func(b []byte) { revealedLen = len(b) })
	if revealedLen != len("hunter2") {
		t.Fatalf("revealed %d bytes, want %d", revealedLen, len("hunter2"))
	}

	s.Destroy()
	if got := s.Plaintext(t.Context()); got != "" {
		t.Errorf("Plaintext() = %q after Destroy, want empty", got)
	}
	if got := s.Bytes(t.Context()); got != nil {
		t.Errorf("Bytes() = %q after Destroy, want nil", got)
	}
}

func TestWithBytes_RepeatedCallsEachSeeTheValue(t *testing.T) {
	s := MustNewSecureString(t.Context(), "rotate-me")
	defer s.Destroy()

	for i := range 3 {
		var got string
		if ok := s.WithBytes(t.Context(), func(b []byte) { got = string(b) }); !ok {
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
	if ok := s.WithBytes(t.Context(), func([]byte) { ran = true }); ok {
		t.Error("WithBytes on a nil receiver reported success")
	}
	if ran {
		t.Error("fn ran for a nil receiver")
	}
}

func TestWithBytes_DestroyedSecretDoesNotRunFn(t *testing.T) {
	s := MustNewSecureString(t.Context(), "gone")
	s.Destroy()

	ran := false
	if ok := s.WithBytes(t.Context(), func([]byte) { ran = true }); ok {
		t.Error("WithBytes on a destroyed secret reported success")
	}
	if ran {
		t.Error("fn ran for a destroyed secret")
	}
}

func TestWithBytes_UnsetSecretDoesNotRunFn(t *testing.T) {
	s := MustNewSecureString(t.Context(), "")
	ran := false
	if ok := s.WithBytes(t.Context(), func([]byte) { ran = true }); ok {
		t.Error("WithBytes on an unset secret reported success")
	}
	if ran {
		t.Error("fn ran for an unset secret")
	}
}

func TestWithBytes_NilFnReportsFailure(t *testing.T) {
	s := MustNewSecureString(t.Context(), "value")
	defer s.Destroy()
	if s.WithBytes(t.Context(), nil) {
		t.Error("WithBytes(nil) reported success")
	}
}

func TestNewSecureStringFromBytes_SealsTheValue(t *testing.T) {
	ss, err := NewSecureStringFromBytes(t.Context(), []byte("from-bytes"))
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	defer ss.Destroy()
	if got := ss.Plaintext(t.Context()); got != "from-bytes" {
		t.Errorf("Plaintext() = %q, want %q", got, "from-bytes")
	}
}

func TestNewSecureStringFromBytes_WipesTheSourceSlice(t *testing.T) {
	src := []byte("wipe-me")
	ss, err := NewSecureStringFromBytes(t.Context(), src)
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
			ss, err := NewSecureStringFromBytes(t.Context(), value)
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
	sealSecret = func(context.Context, []byte) (*secure.Secret, error) { return nil, injected }
	t.Cleanup(func() { sealSecret = restore })

	src := []byte("wipe-on-failure")
	ss, err := NewSecureStringFromBytes(t.Context(), src)
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
	orig := MustNewSecureString(t.Context(), "shared-secret")
	defer orig.Destroy()

	clone, err := orig.Clone(t.Context())
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer clone.Destroy()

	if got := clone.Plaintext(t.Context()); got != "shared-secret" {
		t.Errorf("clone Plaintext() = %q, want %q", got, "shared-secret")
	}
}

func TestClone_DestroyingTheCloneLeavesTheOriginalUsable(t *testing.T) {
	orig := MustNewSecureString(t.Context(), "shared-secret")
	defer orig.Destroy()

	clone, err := orig.Clone(t.Context())
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	clone.Destroy()

	if !clone.IsDestroyed(t.Context()) {
		t.Error("clone should be destroyed")
	}
	if got := orig.Plaintext(t.Context()); got != "shared-secret" {
		t.Errorf("original Plaintext() = %q, want %q — the clone shared its allocation", got, "shared-secret")
	}
}

func TestClone_DestroyingTheOriginalLeavesTheCloneUsable(t *testing.T) {
	orig := MustNewSecureString(t.Context(), "shared-secret")
	clone, err := orig.Clone(t.Context())
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	defer clone.Destroy()

	orig.Destroy()

	if got := clone.Plaintext(t.Context()); got != "shared-secret" {
		t.Errorf("clone Plaintext() = %q, want %q", got, "shared-secret")
	}
}

func TestClone_NilUnsetAndDestroyedCloneToUnset(t *testing.T) {
	destroyed := MustNewSecureString(t.Context(), "x")
	destroyed.Destroy()

	cases := map[string]*SecureString{
		"nil":       nil,
		"unset":     MustNewSecureString(t.Context(), ""),
		"destroyed": destroyed,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			clone, err := src.Clone(t.Context())
			if err != nil {
				t.Fatalf("Clone: %v", err)
			}
			if clone == nil {
				t.Fatal("Clone returned nil")
			}
			if !clone.IsDestroyed(t.Context()) {
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
	src, err := NewSecureStringFromBytes(t.Context(), bytes.Repeat([]byte("k"), size))
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
		c, err := src.Clone(t.Context())
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
	if got := made[0].Plaintext(t.Context()); len(got) != size {
		t.Errorf("clone length = %d, want %d", len(got), size)
	}
}

// --- Equals / IsEmpty -------------------------------------------------------

func TestEquals_MatchesAndMismatches(t *testing.T) {
	s := MustNewSecureString(t.Context(), "dev-secret-key")
	defer s.Destroy()

	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{"exact match", "dev-secret-key", true},
		{"same length, one byte different", "dev-secret-kex", false},
		{"prefix of the value", "dev-secret", false},
		{"value plus a suffix", "dev-secret-key!", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Equals(t.Context(), tt.want); got != tt.ok {
				t.Errorf("Equals(%q) = %v, want %v", tt.want, got, tt.ok)
			}
		})
	}
}

// An unreadable secret is not a matching secret. Every one of these states
// reaches the same branch — WithBytes reporting that fn did not run — which is
// also how an enclave that cannot be opened is reported, so that case needs no
// production seam of its own to be covered.
func TestEquals_UnreadableSecretsDoNotMatch(t *testing.T) {
	destroyed := MustNewSecureString(t.Context(), "dev-secret-key")
	destroyed.Destroy()

	absent, err := NewOptionalSecureString(t.Context(), "")
	if err != nil {
		t.Fatalf("NewOptionalSecureString: %v", err)
	}

	var nilSecret *SecureString

	for name, s := range map[string]*SecureString{
		"nil receiver": nilSecret,
		"destroyed":    destroyed,
		"absent":       absent,
	} {
		t.Run(name, func(t *testing.T) {
			if s.Equals(t.Context(), "dev-secret-key") {
				t.Error("an unreadable secret reported a match")
			}
			if s.Equals(t.Context(), "") {
				t.Error("an unreadable secret matched the empty string")
			}
			if !s.IsEmpty(t.Context()) {
				t.Error("an unreadable secret did not report itself empty")
			}
		})
	}
}

func TestIsEmpty_ReportsThePresenceOfAValue(t *testing.T) {
	set := MustNewSecureString(t.Context(), "x")
	defer set.Destroy()
	if set.IsEmpty(t.Context()) {
		t.Error("a secret holding a value reported itself empty")
	}
}

// TestEqualsAndIsEmpty_DoNotStagePlaintextOnTheGoHeap measures the property
// that actually changes if either is written as `Plaintext() == want`: the
// whole secret lands on the Go heap as an immutable string that can never be
// wiped. The behavioural tests above stay green either way — this is the one
// that does not.
//
// want is deliberately SHORT while the secret is large, so the two
// implementations separate: comparing inside the borrow window charges one
// plaintext (the enclave's own Open) plus a few bytes, while revealing to a
// string charges a second. The bound is revealHeapLimit, whose endpoints were
// measured on this same stack for WithBytes.
func TestEqualsAndIsEmpty_DoNotStagePlaintextOnTheGoHeap(t *testing.T) {
	const size = 1 << 20 // Large enough that one plaintext copy dwarfs constant overhead.
	big, err := NewSecureStringFromBytes(t.Context(), bytes.Repeat([]byte("k"), size))
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	defer big.Destroy()

	const calls = 8
	for _, tc := range []struct {
		name string
		fn   func() bool
	}{
		// Each returns whether the call gave the RIGHT answer, so a
		// measurement can never be taken from a call that misbehaved.
		{"Equals", func() bool { return !big.Equals(t.Context(), "not-the-secret") }},
		{"IsEmpty", func() bool { return !big.IsEmpty(t.Context()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range calls {
				if !tc.fn() {
					t.Fatal("the call under measurement returned the wrong answer")
				}
			}
			runtime.ReadMemStats(&after)

			perCall := (after.TotalAlloc - before.TotalAlloc) / calls
			limit := uint64(size) * revealHeapLimitNumerator / revealHeapLimitDenominator
			if perCall > limit {
				t.Errorf("%s charged %d Go-heap bytes per call (%.3fx the secret), limit %d (%.1fx): "+
					"the plaintext is being staged as a Go string rather than compared in the borrow window",
					tc.name, perCall, float64(perCall)/float64(size), limit,
					float64(revealHeapLimitNumerator)/float64(revealHeapLimitDenominator))
			}
		})
	}
}
