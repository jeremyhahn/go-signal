package secrets

import (
	"errors"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

// IsAbsent must answer "was a value ever configured here", which is a
// different question from IsDestroyed's "is a value readable here". The two
// diverge exactly where the fail-open lived: a configured secret that has
// been destroyed reports destroyed but NOT absent.
func TestIsAbsent_SeparatesNeverSetFromNoLongerReadable(t *testing.T) {
	destroyed := MustNewSecureString("x")
	destroyed.Destroy()

	cases := map[string]struct {
		s             *SecureString
		wantAbsent    bool
		wantDestroyed bool
	}{
		"nil":            {nil, true, true},
		"unset":          {MustNewSecureString(""), true, true},
		"live":           {MustNewSecureString("x"), false, false},
		"destroyed":      {destroyed, false, true},
		"from bytes":     {mustFromBytes(t, "y"), false, false},
		"clone of live":  {mustClone(t, MustNewSecureString("z")), false, false},
		"clone of unset": {mustClone(t, MustNewSecureString("")), true, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.s.IsAbsent(); got != tc.wantAbsent {
				t.Errorf("IsAbsent() = %v, want %v", got, tc.wantAbsent)
			}
			if got := tc.s.IsDestroyed(); got != tc.wantDestroyed {
				t.Errorf("IsDestroyed() = %v, want %v", got, tc.wantDestroyed)
			}
		})
	}
}

// Destroy must not make a configured secret look unconfigured — that is the
// whole point of tracking it separately.
func TestIsAbsent_StaysFalseAcrossDestroy(t *testing.T) {
	s := MustNewSecureString("x")
	if s.IsAbsent() {
		t.Fatal("a live secret must not be absent")
	}
	s.Destroy()
	if s.IsAbsent() {
		t.Error("Destroy must not turn a configured secret into an absent one")
	}
	s.Destroy() // idempotent
	if s.IsAbsent() {
		t.Error("a second Destroy must not change the answer either")
	}
}

func TestTryWithBytes_RunsAndReportsNoError(t *testing.T) {
	s := MustNewSecureString("hunter2")
	defer s.Destroy()

	var seen string
	if err := s.TryWithBytes(func(b []byte) { seen = string(b) }); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seen != "hunter2" {
		t.Errorf("fn saw %q, want %q", seen, "hunter2")
	}
}

func TestTryWithBytes_DistinguishesAbsentFromUnavailable(t *testing.T) {
	destroyed := MustNewSecureString("x")
	destroyed.Destroy()

	t.Run("never set", func(t *testing.T) {
		err := MustNewSecureString("").TryWithBytes(func([]byte) {})
		var absent *AbsentSecretError
		if !errors.As(err, &absent) {
			t.Fatalf("expected *AbsentSecretError, got %#v", err)
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var s *SecureString
		var absent *AbsentSecretError
		if err := s.TryWithBytes(func([]byte) {}); !errors.As(err, &absent) {
			t.Fatalf("expected *AbsentSecretError, got %#v", err)
		}
	})

	t.Run("configured then destroyed", func(t *testing.T) {
		err := destroyed.TryWithBytes(func([]byte) {})
		var unavailable *UnavailableSecretError
		if !errors.As(err, &unavailable) {
			t.Fatalf("expected *UnavailableSecretError, got %#v", err)
		}
		var absent *AbsentSecretError
		if errors.As(err, &absent) {
			t.Error("a destroyed secret must not be reported as absent")
		}
	})
}

// fn must not run when the secret cannot be revealed — a caller that ignored
// the error would otherwise compute over whatever the zero value gives it.
func TestTryWithBytes_DoesNotRunFnWhenUnavailable(t *testing.T) {
	destroyed := MustNewSecureString("x")
	destroyed.Destroy()

	ran := false
	if err := destroyed.TryWithBytes(func([]byte) { ran = true }); err == nil {
		t.Fatal("expected an error for a destroyed secret")
	}
	if ran {
		t.Error("fn ran for a secret that could not be revealed")
	}
}

func mustFromBytes(t *testing.T, v string) *SecureString {
	t.Helper()
	s, err := NewSecureStringFromBytes([]byte(v))
	if err != nil {
		t.Fatalf("NewSecureStringFromBytes: %v", err)
	}
	return s
}

func mustClone(t *testing.T, src *SecureString) *SecureString {
	t.Helper()
	c, err := src.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	return c
}

// --------------------------------------------------------------------------
// YAML decoding
// --------------------------------------------------------------------------

// TestUnmarshalYAML_CarriesConfigured is the regression test for the defect
// Codex found on #33.
//
// UnmarshalYAML installed the decoded enclave but left `configured` false, so
// EVERY secret loaded from a config file reported IsAbsent() == true. A call
// site that selects a legacy or stub mode on absence would have taken that
// branch for a fully configured deployment — the exact fail-open IsAbsent was
// added to prevent, reintroduced through the loading path.
func TestUnmarshalYAML_CarriesConfigured(t *testing.T) {
	cases := map[string]struct {
		yaml       string
		wantAbsent bool
		wantValue  string
	}{
		"non-empty value":    {"secret: hunter2\n", false, "hunter2"},
		"empty value":        {"secret: \"\"\n", true, ""},
		"absent key":         {"other: x\n", true, ""},
		"whitespace is real": {"secret: \" \"\n", false, " "},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var doc struct {
				Secret *SecureString `yaml:"secret"`
			}
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatalf("yaml.Unmarshal: %v", err)
			}
			if got := doc.Secret.IsAbsent(); got != tc.wantAbsent {
				t.Errorf("IsAbsent() = %v, want %v", got, tc.wantAbsent)
			}
			if got := doc.Secret.Plaintext(); got != tc.wantValue {
				t.Errorf("Plaintext() = %q, want %q", got, tc.wantValue)
			}
		})
	}
}

// Decoding an empty node over a previously configured value must leave the
// SecureString genuinely unset: carrying `configured` forward would report a
// key that is no longer there.
func TestUnmarshalYAML_EmptyValueClearsConfigured(t *testing.T) {
	var doc struct {
		Secret *SecureString `yaml:"secret"`
	}
	if err := yaml.Unmarshal([]byte("secret: first\n"), &doc); err != nil {
		t.Fatalf("first decode: %v", err)
	}
	if doc.Secret.IsAbsent() {
		t.Fatal("a decoded non-empty secret must not be absent")
	}

	if err := yaml.Unmarshal([]byte("secret: \"\"\n"), &doc); err != nil {
		t.Fatalf("second decode: %v", err)
	}
	if !doc.Secret.IsAbsent() {
		t.Error("decoding an empty value must leave the secret absent")
	}
}

// --------------------------------------------------------------------------
// Atomic presence + clone
// --------------------------------------------------------------------------

// TestCloneWithPresence_IsASingleSnapshot stresses the race Codex found on
// #33: asking IsAbsent() and then Clone() are two separate reveals, so a
// secret installed between them yields absent=true beside a clone holding a
// real value, and a caller choosing a stub on absence publishes stub mode
// over a key that exists.
//
// Honest about what this is: a STRESS test, not a proof. The window between
// two adjacent reads is small enough that a deliberately split implementation
// still passed this in measurement, so a green run here is not evidence the
// snapshot is atomic. The guarantee is structural — CloneWithPresence reads
// the presence bit and performs the copy under one RLock, which is verifiable
// by reading it — and this covers the case where that structure is broken
// badly enough to widen the window.
//
// It also exercises CloneWithPresence under -race against a concurrent
// writer, which is worth having on its own.
func TestCloneWithPresence_IsASingleSnapshot(t *testing.T) {
	const readers = 16

	for range 50 {
		s := MustNewSecureString("")

		var wg sync.WaitGroup
		start := make(chan struct{})

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			// The absent-to-configured transition, through the same public
			// path a config reload uses.
			_ = s.UnmarshalYAML(func(v any) error {
				*(v.(*string)) = "installed"
				return nil
			})
		}()

		for range readers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				clone, configured, err := s.CloneWithPresence()
				if err != nil {
					t.Errorf("CloneWithPresence: %v", err)
					return
				}
				defer clone.Destroy()

				hasValue := clone.Plaintext() != ""
				if hasValue && !configured {
					t.Error("clone holds a value while presence reports never-configured: " +
						"the two came from different snapshots")
				}
			}()
		}

		close(start)
		wg.Wait()
		s.Destroy()
	}
}

// The presence bit describes the SOURCE, not the clone. A configured secret
// that cannot be revealed yields an empty clone AND configured=true, so the
// caller can tell it apart from a genuinely unset one.
func TestCloneWithPresence_ConfiguredButUnreadable(t *testing.T) {
	s := MustNewSecureString("x")
	s.Destroy()

	clone, configured, err := s.CloneWithPresence()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer clone.Destroy()

	if !configured {
		t.Error("a configured-then-destroyed secret must report configured=true")
	}
	if !clone.IsAbsent() {
		t.Error("the clone of an unreadable secret holds nothing, so it is absent")
	}
}

func TestCloneWithPresence_NeverConfigured(t *testing.T) {
	clone, configured, err := MustNewSecureString("").CloneWithPresence()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer clone.Destroy()
	if configured {
		t.Error("an unset secret must report configured=false")
	}
}
