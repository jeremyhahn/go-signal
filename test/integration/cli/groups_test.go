//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Groups
// Commands: listGroups, updateGroup, quitGroup, joinGroup
// =============================================================================

func TestCLI_ListGroups(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue // signal-cli groups require full e2e encryption
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "listGroups")
			assert.Equal(t, 0, result.ExitCode, "listGroups should succeed")
		})
	}
}

func TestCLI_UpdateGroup_Create(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"updateGroup", "--name", "Test Group",
			)
			t.Logf("updateGroup exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_QuitGroup(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"quitGroup", "--group-id", "nonexistent",
			)
			t.Logf("quitGroup exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_JoinGroup(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number,
				"joinGroup", "--uri", "https://signal.group/#nonexistent",
			)
			t.Logf("joinGroup exit=%d", result.ExitCode)
		})
	}
}
