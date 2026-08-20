package external

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestGenerator_CredentialNeverStagedInAGoString guards the property this
// package cannot express any other way.
//
// Generate and Validate handle a complete bearer password. Building or reading
// one through a Go string leaves the credential in memory that cannot be
// wiped and that the runtime may copy, so destroying the SecureString does not
// remove it. The fix was to assemble, parse and compare in byte buffers.
//
// There is no runtime-observable difference between the two implementations —
// same wire bytes, same errors, same timings — and the credential is far too
// small for an allocation bound to separate them from noise the way
// TestClone_DoesNotStagePlaintextOnTheGoHeap can at 1 MiB. So this asserts on
// the source, which is the only instrument that actually discriminates. It is
// a narrow, deterministic check: the two call shapes that reintroduce the
// defect, in the one file that must not contain them.
//
// Reintroducing `Password.Plaintext()` or `hex.EncodeToString` in
// generator.go makes this fail.
func TestGenerator_CredentialNeverStagedInAGoString(t *testing.T) {
	src, err := os.ReadFile("generator.go")
	if err != nil {
		t.Fatalf("read generator.go: %v", err)
	}
	// Strip comments so the prose above (and the doc comments in generator.go
	// that name these very calls) cannot trip the check.
	code := regexp.MustCompile(`(?m)^\s*//.*$|/\*(?s:.*?)\*/`).ReplaceAll(src, nil)

	banned := map[string]string{
		".Plaintext()": "reveals the whole credential into an unwipeable Go string; " +
			"parse and compare inside Password.WithBytes instead",
		"hex.EncodeToString": "produces the signature as an unwipeable Go string; " +
			"use hex.Encode into a byte buffer and wipe it",
	}
	for call, why := range banned {
		if strings.Contains(string(code), call) {
			t.Errorf("generator.go uses %s — %s", call, why)
		}
	}
}
