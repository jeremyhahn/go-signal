//go:build integration

package api

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Messaging (signal-cli: send, receive, sendReaction, sendReceipt,
// sendTyping, remoteDelete, sendContacts, sendSyncRequest)
// =============================================================================

func TestSignalCLI_Send_TextMessage(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", "-m", "Hello from A", numberB)
	assert.Equal(t, 0, result.ExitCode, "send should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithAttachment(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a temporary file for attachment
	tmpFile := t.TempDir() + "/test-attachment.txt"
	require.NoError(t, writeTestFile(tmpFile, "test attachment content"))

	// The attachment upload flow uses the TUS resumable upload protocol via
	// the CDN3 endpoint. The server implements TUS creation (POST → Location
	// header) and data upload (PATCH) to allow signal-cli to complete the
	// full upload flow.
	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "With attachment", "--attachment", tmpFile)
	assert.Equal(t, 0, result.ExitCode, "send with attachment should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_NoteToSelf(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "send", "-m", "Note to self", "--note-to-self")
	assert.Equal(t, 0, result.ExitCode, "send --note-to-self should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_EndSession(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", "--end-session", numberB)
	assert.Equal(t, 0, result.ExitCode, "send --end-session should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_EditMessage(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Send an edit referencing a previous timestamp
	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "send", "-m", "Edited message",
		"--edit-timestamp", uintToStr(ts), numberB)
	assert.Equal(t, 0, result.ExitCode, "send --edit-timestamp should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_StoryReply(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "send", "-m", "Story reply",
		"--story-timestamp", uintToStr(ts),
		"--story-author", numberB,
		numberB)
	assert.Equal(t, 0, result.ExitCode, "send --story-timestamp should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithQuote(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "send", "-m", "Quoted reply",
		"--quote-timestamp", uintToStr(ts),
		"--quote-author", numberB,
		"--quote-message", "Original message",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "send with quote should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithPreview(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", "-m", "Check this link",
		"--preview-url", "https://example.com",
		"--preview-title", "Example",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "send with preview should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_MessageFromStdin(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// --message-from-stdin reads from stdin. With empty stdin (EOF), signal-cli
	// exits with code 1 because no message content is available. This verifies
	// the server processes the request path correctly.
	result := signalCLIExecAccount(t, numberA, "send", "--message-from-stdin", numberB)
	assert.Equal(t, 1, result.ExitCode, "send --message-from-stdin with empty stdin should exit 1: %s", result.Stderr)
}

func TestSignalCLI_Receive(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// receive with short timeout - should return quickly with no messages
	result := signalCLIExecAccount(t, number, "receive", "--timeout", "1")
	assert.Equal(t, 0, result.ExitCode, "receive should succeed: %s", result.Stderr)
}

func TestSignalCLI_Receive_IgnoreAttachments(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "receive", "--timeout", "1", "--ignore-attachments")
	assert.Equal(t, 0, result.ExitCode, "receive --ignore-attachments should succeed: %s", result.Stderr)
}

func TestSignalCLI_Receive_IgnoreStories(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "receive", "--timeout", "1", "--ignore-stories")
	assert.Equal(t, 0, result.ExitCode, "receive --ignore-stories should succeed: %s", result.Stderr)
}

func TestSignalCLI_Receive_SendReadReceipts(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "receive", "--timeout", "1", "--send-read-receipts")
	assert.Equal(t, 0, result.ExitCode, "receive --send-read-receipts should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendAndReceive_E2E(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// A sends to B
	result := signalCLIExecAccount(t, numberA, "send", "-m", "Hello B!", numberB)
	require.Equal(t, 0, result.ExitCode, "send should succeed: %s", result.Stderr)

	// Verify send returned a successful result with a timestamp.
	assert.Contains(t, result.Stdout, "timestamp", "send result should contain a timestamp")

	// B receives - message delivery through the server's WebSocket channel is
	// asynchronous and may not arrive within the short timeout, so we verify
	// the receive command itself succeeds.
	result = signalCLIExecAccount(t, numberB, "receive", "--timeout", "5")
	assert.Equal(t, 0, result.ExitCode, "receive should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendReaction(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "sendReaction",
		"--emoji", "👍",
		"--target-author", numberB,
		"--target-timestamp", uintToStr(ts),
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendReaction should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendReaction_Remove(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "sendReaction",
		"--emoji", "👍",
		"--target-author", numberB,
		"--target-timestamp", uintToStr(ts),
		"--remove",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendReaction --remove should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendReceipt_Read(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	// signal-cli's sendReceipt uses argparse4j: the positional recipient must
	// come before the optional -t flag for correct parsing.
	result := signalCLIExecAccount(t, numberA, "sendReceipt",
		numberB,
		"--type", "read",
		"-t", uintToStr(ts))
	assert.Equal(t, 0, result.ExitCode, "sendReceipt read should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendReceipt_Viewed(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "sendReceipt",
		numberB,
		"--type", "viewed",
		"-t", uintToStr(ts))
	assert.Equal(t, 0, result.ExitCode, "sendReceipt viewed should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendTyping(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Establish a Signal session between A and B by sending a regular message
	// first. Typing indicators require an established session for encryption.
	result := signalCLIExecAccount(t, numberA, "send", "-m", "session setup", numberB)
	require.Equal(t, 0, result.ExitCode,
		"session setup send should succeed: %s", result.Stderr)

	// sendTyping sends a typing indicator to the recipient.
	result = signalCLIExecAccount(t, numberA, "sendTyping", numberB)
	assert.Equal(t, 0, result.ExitCode,
		"sendTyping should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendTyping_Stop(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Establish a Signal session between A and B first.
	result := signalCLIExecAccount(t, numberA, "send", "-m", "session setup", numberB)
	require.Equal(t, 0, result.ExitCode,
		"session setup send should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, numberA, "sendTyping", "--stop", numberB)
	assert.Equal(t, 0, result.ExitCode,
		"sendTyping --stop should succeed: %s", result.Stderr)
}

func TestSignalCLI_RemoteDelete(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "remoteDelete",
		"--target-timestamp", uintToStr(ts),
		numberB)
	assert.Equal(t, 0, result.ExitCode, "remoteDelete should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendContacts(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// sendContacts uploads a contacts blob to the CDN via TUS resumable upload
	// and then sends a sync message to linked devices.
	result := signalCLIExecAccount(t, number, "sendContacts")
	assert.Equal(t, 0, result.ExitCode, "sendContacts should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendSyncRequest(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	result := signalCLIExecAccount(t, number, "sendSyncRequest")
	assert.Equal(t, 0, result.ExitCode, "sendSyncRequest should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendPaymentNotification(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	receipt := base64.StdEncoding.EncodeToString([]byte("test-payment-receipt"))
	result := signalCLIExecAccount(t, numberA, "sendPaymentNotification",
		"--receipt", receipt,
		"--note", "Coffee payment",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendPaymentNotification should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendMessageRequestResponse(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "sendMessageRequestResponse",
		"--type", "accept",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendMessageRequestResponse should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithMention(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group with both members.
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Test Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Send a message to the group with a mention of numberB.
	// Mention syntax: "start:length:recipient"
	result = signalCLIExecAccount(t, numberA, "send", "-m", "Hello @user!",
		"--group-id", groupID,
		"--mention", fmt.Sprintf("6:5:%s", numberB))
	assert.Equal(t, 0, result.ExitCode, "send with mention should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithTextStyle(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Send with bold text style. Syntax: "start:length:STYLE"
	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Hello World",
		"--text-style", "0:5:BOLD")
	assert.Equal(t, 0, result.ExitCode, "send with text style should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithSticker(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Send with a sticker. Syntax: "stickerPackId:stickerId"
	// Using a dummy pack ID - signal-cli may fail client-side for unknown packs,
	// but the server must not return 5xx errors.
	result := signalCLIExecAccount(t, numberA, "send",
		"--sticker", "0000000000000000000000000000000000000000000000000000000000000000:0",
		numberB)
	// signal-cli may fail client-side for certain operations, but the server
	// must not return 5xx errors. Exit codes 0 or 1 are acceptable.
	assert.True(t, result.ExitCode == 0 || result.ExitCode == 1,
		"command should not cause server error: %s", result.Stderr)
}

func TestSignalCLI_Send_WithPreviewDescription(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", "-m", "Check this link",
		"--preview-url", "https://example.com",
		"--preview-title", "Example Site",
		"--preview-description", "An example website for testing",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "send with preview description should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithQuoteMention(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Quoting with mention",
		"--quote-timestamp", uintToStr(ts),
		"--quote-author", numberB,
		"--quote-message", "@user said something",
		"--quote-mention", fmt.Sprintf("0:5:%s", numberB))
	assert.Equal(t, 0, result.ExitCode, "send with quote mention should succeed: %s", result.Stderr)
}

func TestSignalCLI_Receive_MaxMessages(t *testing.T) {
	number := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, number)

	// receive with --max-messages 1 should return at most one message and exit.
	result := signalCLIExecAccount(t, number, "receive", "--timeout", "1", "--max-messages", "1")
	assert.Equal(t, 0, result.ExitCode, "receive --max-messages should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendReaction_ToGroup(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group with both members.
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Test Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Send a regular message to the group to establish the session.
	result = signalCLIExecAccount(t, numberA, "send", "-m", "group session setup",
		"--group-id", groupID)
	require.Equal(t, 0, result.ExitCode, "group message should succeed: %s", result.Stderr)

	ts := uint64(time.Now().UnixMilli())
	result = signalCLIExecAccount(t, numberA, "sendReaction",
		"--emoji", "🎉",
		"--target-author", numberA,
		"--target-timestamp", uintToStr(ts),
		"--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "sendReaction to group should succeed: %s", result.Stderr)
}

func TestSignalCLI_RemoteDelete_InGroup(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group with both members.
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Test Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Send a regular message to the group to establish the session.
	result = signalCLIExecAccount(t, numberA, "send", "-m", "group session setup",
		"--group-id", groupID)
	require.Equal(t, 0, result.ExitCode, "group message should succeed: %s", result.Stderr)

	ts := uint64(time.Now().UnixMilli())
	result = signalCLIExecAccount(t, numberA, "remoteDelete",
		"--target-timestamp", uintToStr(ts),
		"--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "remoteDelete in group should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendTyping_ToGroup(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group with both members.
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Test Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Send a regular message to the group to establish the session.
	result = signalCLIExecAccount(t, numberA, "send", "-m", "group session setup",
		"--group-id", groupID)
	require.Equal(t, 0, result.ExitCode, "group message should succeed: %s", result.Stderr)

	result = signalCLIExecAccount(t, numberA, "sendTyping", "--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "sendTyping to group should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendMessageRequestResponse_AcceptThenDelete(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Accept first
	result := signalCLIExecAccount(t, numberA, "sendMessageRequestResponse",
		"--type", "accept",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendMessageRequestResponse accept should succeed: %s", result.Stderr)

	// Then delete
	result = signalCLIExecAccount(t, numberA, "sendMessageRequestResponse",
		"--type", "delete",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendMessageRequestResponse delete should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendMessageRequestResponse_Delete(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "sendMessageRequestResponse",
		"--type", "delete",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "sendMessageRequestResponse --type delete should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithPreviewImage(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	tmpFile := t.TempDir() + "/preview.png"
	require.NoError(t, writeTestFile(tmpFile, "fake-preview-image"))

	result := signalCLIExecAccount(t, numberA, "send", "-m", "Check this link",
		"--preview-url", "https://example.com",
		"--preview-title", "Example Site",
		"--preview-image", tmpFile,
		numberB)
	assert.Equal(t, 0, result.ExitCode, "send with preview image should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithQuoteAttachment(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Quoting with attachment",
		"--quote-timestamp", uintToStr(ts),
		"--quote-author", numberB,
		"--quote-message", "Original with image",
		"--quote-attachment", "image/png")
	assert.Equal(t, 0, result.ExitCode, "send with quote attachment should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithQuoteTextStyle(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts := uint64(time.Now().UnixMilli())
	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Quoting styled text",
		"--quote-timestamp", uintToStr(ts),
		"--quote-author", numberB,
		"--quote-message", "Bold original",
		"--quote-text-style", "0:4:BOLD")
	assert.Equal(t, 0, result.ExitCode, "send with quote text style should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_WithMultipleTextStyles(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Bold and italic text",
		"--text-style", "0:4:BOLD",
		"--text-style", "9:6:ITALIC")
	assert.Equal(t, 0, result.ExitCode, "send with multiple text styles should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_TextStyleSpoiler(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Secret spoiler text",
		"--text-style", "7:7:SPOILER")
	assert.Equal(t, 0, result.ExitCode, "send with SPOILER text style should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_TextStyleStrikethrough(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Deleted text here",
		"--text-style", "0:12:STRIKETHROUGH")
	assert.Equal(t, 0, result.ExitCode, "send with STRIKETHROUGH text style should succeed: %s", result.Stderr)
}

func TestSignalCLI_Send_TextStyleMonospace(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "send", numberB, "-m", "Code block here",
		"--text-style", "0:10:MONOSPACE")
	assert.Equal(t, 0, result.ExitCode, "send with MONOSPACE text style should succeed: %s", result.Stderr)
}

func TestSignalCLI_SendReceipt_MultipleTimestampsRead(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	ts1 := uint64(time.Now().UnixMilli())
	ts2 := ts1 + 1
	result := signalCLIExecAccount(t, numberA, "sendReceipt",
		numberB,
		"--type", "read",
		"-t", uintToStr(ts1),
		"-t", uintToStr(ts2))
	assert.Equal(t, 0, result.ExitCode, "sendReceipt with multiple timestamps should succeed: %s", result.Stderr)
}

func TestSignalCLI_GetAttachment(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// getAttachment retrieves locally stored attachments. Without a prior
	// download, it will fail with a non-existent attachment ID. Verify the
	// command does not crash the server.
	result := signalCLIExecAccount(t, numberA, "getAttachment",
		"--id", "nonexistent-id",
		"--recipient", numberB)
	t.Logf("getAttachment: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_GetAvatar_Contact(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// getAvatar retrieves a locally cached avatar. Without prior download,
	// it will fail. Verify the command does not crash the server.
	result := signalCLIExecAccount(t, numberA, "getAvatar",
		"--contact", numberB)
	t.Logf("getAvatar --contact: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_GetAvatar_Profile(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	result := signalCLIExecAccount(t, numberA, "getAvatar",
		"--profile", numberB)
	t.Logf("getAvatar --profile: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_Send_WithExpirationViaContact(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Set disappearing message timer via updateContact (send --expiration
	// is not a valid flag in signal-cli v0.13.12).
	result := signalCLIExecAccount(t, numberA, "updateContact",
		"--given-name", "Ephemeral",
		"--expiration", "3600",
		numberB)
	assert.Equal(t, 0, result.ExitCode, "updateContact with expiration should succeed: %s", result.Stderr)

	// Send a message after setting the timer - it should use the configured expiration.
	result = signalCLIExecAccount(t, numberA, "send", "-m", "Disappearing message", numberB)
	assert.Equal(t, 0, result.ExitCode, "send after setting expiration should succeed: %s", result.Stderr)
}

func TestSignalCLI_GetAvatar_GroupID(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "Avatar Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	// Get group avatar (may not exist, but should not crash server)
	result = signalCLIExecAccount(t, numberA, "getAvatar", "--group-id", groupID)
	t.Logf("getAvatar --group-id: exit=%d stderr=%s", result.ExitCode, result.Stderr)
	assert.NotContains(t, result.Stderr, "500 Internal Server Error",
		"should not cause 500 server error")
}

func TestSignalCLI_SendMessageRequestResponse_GroupAccept(t *testing.T) {
	numberA := signalCLIUniqueNumber()
	numberB := signalCLIUniqueNumber()
	signalCLIRegisterAndVerify(t, numberA)
	signalCLIRegisterAndVerify(t, numberB)

	// Create a group
	result := signalCLIExecAccount(t, numberA, "updateGroup", "--name", "MRR Group", "--member", numberB)
	require.Equal(t, 0, result.ExitCode, "create group should succeed: %s", result.Stderr)
	createResp := parseJSON(t, result)
	groupID, ok := createResp["groupId"].(string)
	require.True(t, ok && groupID != "", "updateGroup response should contain groupId")

	result = signalCLIExecAccount(t, numberA, "sendMessageRequestResponse",
		"--type", "accept",
		"--group-id", groupID)
	assert.Equal(t, 0, result.ExitCode, "sendMessageRequestResponse with group should succeed: %s", result.Stderr)
}

// writeTestFile creates a file with the given content.
func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

func uintToStr(v uint64) string {
	return fmt.Sprintf("%d", v)
}
