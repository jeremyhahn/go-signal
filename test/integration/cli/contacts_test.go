//go:build integration

package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Contacts & Identity
// Commands: listContacts, updateContact, removeContact, block, unblock,
//           listIdentities, trust
// =============================================================================

func TestCLI_ListContacts(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "listContacts")
			assert.Equal(t, 0, result.ExitCode, "listContacts should succeed")
		})
	}
}

func TestCLI_UpdateContact(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			contact := uniqueNumber()
			result := execCLIAccount(t, bin, number,
				"updateContact", contact,
				"--given-name", "Alice",
				"--family-name", "Smith",
			)
			assert.Equal(t, 0, result.ExitCode, "updateContact should succeed")

			// Verify it shows up in list
			result = execCLIAccount(t, bin, number, "listContacts")
			assert.Contains(t, result.Stdout, contact)
		})
	}
}

func TestCLI_RemoveContact(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			contact := uniqueNumber()
			execCLIAccount(t, bin, number, "updateContact", contact, "--given-name", "ToDelete")

			result := execCLIAccount(t, bin, number, "removeContact", contact)
			assert.Equal(t, 0, result.ExitCode, "removeContact should succeed")
		})
	}
}

func TestCLI_BlockAndUnblock(t *testing.T) {
	for _, bin := range binaries(t) {
		if bin.Name == "signal-cli" {
			continue
		}
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			target := uniqueNumber()

			result := execCLIAccount(t, bin, number, "block", target)
			assert.Equal(t, 0, result.ExitCode, "block should succeed")

			result = execCLIAccount(t, bin, number, "unblock", target)
			assert.Equal(t, 0, result.ExitCode, "unblock should succeed")
		})
	}
}

func TestCLI_ListIdentities(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "listIdentities")
			assert.Equal(t, 0, result.ExitCode, "listIdentities should succeed")
		})
	}
}

func TestCLI_Trust(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			target := uniqueNumber()
			registerAndVerify(t, withName(bin, "target"), target)

			result := execCLIAccount(t, bin, number, "trust", target)
			t.Logf("trust exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}
