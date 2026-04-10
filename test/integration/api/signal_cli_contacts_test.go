//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Contacts & Identity (signal-cli: listContacts, updateContact, removeContact,
// listIdentities, trust, block, unblock)
// =============================================================================

func TestSignalCLI_ListContacts(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listContacts")
	assert.Equal(t, 0, result.ExitCode, "listContacts should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListContacts_AllRecipients(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listContacts", "--all-recipients")
	assert.Equal(t, 0, result.ExitCode, "listContacts --all-recipients should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListContacts_Blocked(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listContacts", "--blocked=true")
	assert.Equal(t, 0, result.ExitCode, "listContacts --blocked should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateContact(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "updateContact",
		"--given-name", "Bob",
		"--family-name", "Jones",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "updateContact should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateContact_WithExpiration(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "updateContact",
		"--given-name", "Carol",
		"--expiration", "3600",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "updateContact with expiration should succeed: %s", result.Stderr)
}

func TestSignalCLI_RemoveContact(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Add contact first
	result := signalCLIExecAccount(t, numberA, "updateContact", "--given-name", "ToRemove", numberB)
	assert.Equal(t, 0, result.ExitCode)

	// Remove it
	result = signalCLIExecAccount(t, numberA, "removeContact", "--forget", numberB)
	assert.Equal(t, 0, result.ExitCode, "removeContact should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListIdentities(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listIdentities")
	assert.Equal(t, 0, result.ExitCode, "listIdentities should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListIdentities_ForNumber(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "listIdentities", "--number", numberB)
	assert.Equal(t, 0, result.ExitCode, "listIdentities --number should succeed: %s", result.Stderr)
}

func TestSignalCLI_Trust(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// The trust command requires that the target's identity key is already
	// known. Sending a message first establishes the identity relationship.
	result := signalCLIExecAccount(t, numberA, "send", "-m", "hello", numberB)
	assert.Equal(t, 0, result.ExitCode, "send should succeed to establish identity: %s", result.Stderr)

	result = signalCLIExecAccount(t, numberA, "trust", "--trust-all-known-keys", numberB)
	assert.Equal(t, 0, result.ExitCode, "trust should succeed: %s", result.Stderr)
}

func TestSignalCLI_Block(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "block", numberB)
	assert.Equal(t, 0, result.ExitCode, "block should succeed: %s", result.Stderr)
}

func TestSignalCLI_Unblock(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Block then unblock
	result := signalCLIExecAccount(t, numberA, "block", numberB)
	assert.Equal(t, 0, result.ExitCode)

	result = signalCLIExecAccount(t, numberA, "unblock", numberB)
	assert.Equal(t, 0, result.ExitCode, "unblock should succeed: %s", result.Stderr)
}

func TestSignalCLI_Block_Group(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group first
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Block Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	result = signalCLIExecAccount(t, numberA, "block", "--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "block group should succeed: %s", result.Stderr)
}

func TestSignalCLI_Unblock_Group(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create and block a group first
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Unblock Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	result = signalCLIExecAccount(t, numberA, "block", "--group-id", groupID)
	require.Equal(t, 0, result.ExitCode, "block group should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, numberA, "unblock", "--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "unblock group should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListContacts_Name(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Add a contact with a name
	result := signalCLIExecAccount(t, numberA, "updateContact", "--given-name", "FilterTest", numberB)
	assert.Equal(t, 0, result.ExitCode, "updateContact should succeed: %s", result.Stderr)

	// List contacts - should include the named contact
	result = signalCLIExecAccount(t, numberA, "listContacts")
	assert.Equal(t, 0, result.ExitCode, "listContacts should succeed: %s", result.Stderr)
	assert.Contains(t, result.Stdout, "FilterTest",
		"listContacts output should include the added contact name")
}

func TestSignalCLI_Trust_VerifiedSafetyNumber(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Establish identity by sending a message
	result := signalCLIExecAccount(t, numberA, "send", "-m", "hello", numberB)
	assert.Equal(t, 0, result.ExitCode, "send should succeed: %s", result.Stderr)

	// Trust with --verified-safety-number using a dummy safety number.
	// This will likely fail because the safety number won't match, but it
	// should not crash the server.
	result = signalCLIExecAccount(t, numberA, "trust",
		"--verified-safety-number", "00000 11111 22222 33333 44444 55555 66666 77777 88888 99999 00000 11111",
		numberB)
	t.Logf("trust --verified-safety-number: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}
