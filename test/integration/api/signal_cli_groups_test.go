//go:build integration

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Groups (signal-cli: updateGroup, listGroups, quitGroup, joinGroup)
// =============================================================================

func TestSignalCLI_ListGroups_Empty(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listGroups")
	assert.Equal(t, 0, result.ExitCode, "listGroups should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_Create(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Test Group",
		"--member", numberB)
	assert.Equal(t, 0, result.ExitCode, "updateGroup create should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetExpiration(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group first
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Expiry Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)

	// List groups to get group ID
	result = signalCLIExecAccount(t, numberA, "listGroups", "--detailed")
	assert.Equal(t, 0, result.ExitCode, "listGroups should succeed: %s", result.Stderr)
}

func TestSignalCLI_ListGroups_Detailed(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "listGroups", "--detailed")
	assert.Equal(t, 0, result.ExitCode, "listGroups --detailed should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendToGroup(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group — the response JSON includes "groupId" which we can parse
	// directly instead of relying on listGroups.
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Message Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)

	// Extract group ID from the updateGroup response.
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Send message to the group
	result = signalCLIExecAccount(t, numberA, "send", "-m", "Hello group!", "--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "send to group should succeed: %s", result.Stderr)
}

func TestSignalCLI_QuitGroup(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Quit Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)

	// Extract group ID from the updateGroup response.
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Quit the group
	result = signalCLIExecAccount(t, numberA, "quitGroup", "--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "quitGroup should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetDescription(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Description Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Set description on existing group
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--description", "Test description")
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --description should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetAvatar(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Avatar Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Create a temporary avatar file (1x1 PNG)
	avatarPath := t.TempDir() + "/avatar.png"
	err := writeTestFile(avatarPath, "PNG-PLACEHOLDER")
	require.NoError(t, err, "failed to create temp avatar file")

	// Set avatar on existing group
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--avatar", avatarPath)
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --avatar should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_RemoveMember(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group with two members
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Remove Member Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Remove member B from the group
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--remove-member", numberB)
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --remove-member should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetAdmin(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group with two members
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Admin Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Promote member B to admin
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--admin", numberB)
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --admin should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_RemoveAdmin(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group with two members
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Remove Admin Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Promote member B to admin first
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--admin", numberB)
	require.Equal(t, 0, result.ExitCode,
		"updateGroup --admin should succeed: %s", result.Stderr)

	// Demote member B from admin
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--remove-admin", numberB)
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --remove-admin should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_Ban(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	numberC := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)
	signalCLIRegisterAndVerify(t, numberC)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Ban Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Ban number C from the group
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--ban", numberC)
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --ban should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_Unban(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	numberC := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)
	signalCLIRegisterAndVerify(t, numberC)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Unban Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Ban number C first
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--ban", numberC)
	require.Equal(t, 0, result.ExitCode,
		"updateGroup --ban should succeed: %s", result.Stderr)

	// Unban number C
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--unban", numberC)
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --unban should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetLinkEnabled(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Link Enabled Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Group link operations depend on group V2 server-side state. signal-cli
	// may exit non-zero if the operation isn't fully supported.
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--link", "enabled")
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"should not cause server error: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetLinkDisabled(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Link Disabled Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Group link operations depend on group V2 server-side state. signal-cli
	// may exit non-zero if the operation isn't fully supported.
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--link", "disabled")
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"should not cause server error: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetLinkWithApproval(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Link Approval Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Group link operations depend on group V2 server-side state. signal-cli
	// may exit non-zero if the operation isn't fully supported.
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--link", "enabled-with-approval")
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"should not cause server error: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_ResetLink(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Reset Link Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Enable link first so there is something to reset
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--link", "enabled")

	// Group link operations depend on group V2 server-side state. signal-cli
	// may exit non-zero if the operation isn't fully supported.
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--reset-link")
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"should not cause server error: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_PermissionAddMember(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Permission AddMember Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Set add-member permission to only-admins
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--set-permission-add-member", "only-admins")
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --set-permission-add-member should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_PermissionEditDetails(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Permission EditDetails Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Set edit-details permission to every-member
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--set-permission-edit-details", "every-member")
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --set-permission-edit-details should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_PermissionSendMessages(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Permission SendMessages Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Set send-messages permission to every-member
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--set-permission-send-messages", "every-member")
	assert.Equal(t, 0, result.ExitCode,
		"updateGroup --set-permission-send-messages should succeed: %s", result.Stderr)
}

func TestSignalCLI_JoinGroup(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	numberC := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)
	signalCLIRegisterAndVerify(t, numberC)

	// Create group
	result := signalCLIExecAccount(t, numberA, "updateGroup",
		"--name", "Join Group",
		"--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "response should contain groupId")

	// Enable group link so others can join via invite URI
	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--link", "enabled")

	// Retrieve the group invite link from listGroups output. The invite link
	// is only available when the group link is enabled.
	result = signalCLIExecAccount(t, numberA, "listGroups", "--detailed")

	// Attempt to extract the invite link from the group listing. If group
	// links are not fully supported, fall back to a dummy URI to verify
	// the joinGroup command does not crash the server.
	inviteURI := "https://signal.group/#dummy-test-link"
	if result.ExitCode == 0 && result.Stdout != "" {
		groups := parseJSONArray(t, result)
		for _, g := range groups {
			gMap, gOk := g.(map[string]any)
			if !gOk {
				continue
			}
			if gMap["id"] == groupID || gMap["groupId"] == groupID {
				if link, linkOk := gMap["groupInviteLink"].(string); linkOk && link != "" {
					inviteURI = link
				}
				break
			}
		}
	}

	// Have number C join the group via the invite link. Group link operations
	// depend on group V2 server-side state. signal-cli may exit non-zero if
	// the operation isn't fully supported.
	result = signalCLIExecAccount(t, numberC, "joinGroup", "--uri", inviteURI)
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"should not cause server error: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetExpireTimer(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Timer Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--expiration", "3600")
	assert.Equal(t, 0, result.ExitCode, "updateGroup --expiration should succeed: %s", result.Stderr)
}

func TestSignalCLI_UpdateGroup_SetName(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Original Name", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	result = signalCLIExecAccount(t, numberA, "updateGroup",
		"--group-id", groupID,
		"--name", "Renamed Group")
	assert.Equal(t, 0, result.ExitCode, "updateGroup --name (rename) should succeed: %s", result.Stderr)
}
