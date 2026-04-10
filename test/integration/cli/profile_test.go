//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Profiles
// Commands: updateProfile, getUserStatus
// =============================================================================

func TestCLI_UpdateProfile(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"updateProfile",
				"--given-name", "Test",
				"--family-name", "User",
				"--about", "Integration test",
			)
			t.Logf("updateProfile exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

func TestCLI_GetUserStatus(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			other := uniqueNumber()
			registerAndVerify(t, withName(bin, "other"), other)

			result := execCLIAccount(t, bin, number, "getUserStatus", other)
			assert.Equal(t, 0, result.ExitCode, "getUserStatus should succeed: %s", result.Stderr)
		})
	}
}
