package external

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestGenerator_CredentialNeverStagedInAGoString checks generator.go never calls Password.Plaintext() or hex.EncodeToString on the credential.
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
