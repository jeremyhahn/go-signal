//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// FIDO2 Security Keys
// Commands: fido2 capabilities, fido2 list, fido2 delete, fido2 rename
// =============================================================================

func TestCLI_FIDO2_Capabilities(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			result := execCLI(t, bin, "fido2", "capabilities")
			require.Equal(t, 0, result.ExitCode, "fido2 capabilities should succeed: %s", result.Stderr)

			data := parseJSON(t, result)
			assert.Equal(t, true, data["enabled"], "FIDO2 should be enabled")
			assert.NotEmpty(t, data["rpId"], "rpId should be set")
			assert.NotEmpty(t, data["rpName"], "rpName should be set")
		})
	}
}

func TestCLI_FIDO2_ListCredentials_Empty(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "fido2", "list")
			assert.Equal(t, 0, result.ExitCode, "fido2 list should succeed: %s", result.Stderr)
		})
	}
}

func TestCLI_FIDO2_DeleteCredential_NotFound(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			// Delete a non-existent credential — should fail with 404
			result := execCLIAccount(t, bin, number, "fido2", "delete", "nonexistent-id")
			t.Logf("fido2 delete exit=%d stderr=%s", result.ExitCode, result.Stderr)
			// Expect non-zero exit (credential not found)
			assert.NotEqual(t, 0, result.ExitCode, "delete of nonexistent credential should fail")
		})
	}
}

func TestCLI_FIDO2_RenameCredential_NotFound(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "fido2", "rename", "nonexistent-id", "NewName")
			t.Logf("fido2 rename exit=%d stderr=%s", result.ExitCode, result.Stderr)
			assert.NotEqual(t, 0, result.ExitCode, "rename of nonexistent credential should fail")
		})
	}
}
