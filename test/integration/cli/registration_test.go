//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Account Registration, Verification & Lifecycle
// Commands: register, verify, listAccounts, whoami, version,
//           unregister, deleteLocalAccountData, updateAccount
// =============================================================================

func TestCLI_Register(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)
		})
	}
}

func TestCLI_ListAccounts(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLI(t, bin, "listAccounts")
			assert.Equal(t, 0, result.ExitCode, "listAccounts should succeed")
			assert.Contains(t, result.Stdout, number)
		})
	}
}

func TestCLI_WhoAmI(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue // signal-cli doesn't have whoami
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "whoami")
			require.Equal(t, 0, result.ExitCode, "whoami should succeed")
			data := parseJSON(t, result)
			assert.NotEmpty(t, data["uuid"])
			assert.Equal(t, number, data["number"])
		})
	}
}

func TestCLI_Version(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			result := execCLI(t, bin, "version")
			assert.Equal(t, 0, result.ExitCode, "version should succeed")
			assert.NotEmpty(t, result.Stdout)
		})
	}
}

func TestCLI_Unregister(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "unregister")
			t.Logf("unregister exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

func TestCLI_DeleteLocalAccountData(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "deleteLocalAccountData")
			assert.Equal(t, 0, result.ExitCode, "deleteLocalAccountData should succeed")
		})
	}
}

func TestCLI_UpdateAccount(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "updateAccount")
			t.Logf("updateAccount exit=%d", result.ExitCode)
		})
	}
}
