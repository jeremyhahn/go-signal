package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// setGlobals configures CLI global variables and the cobra command's context
// for a single test. A fresh temp directory is created for configDir so each
// test gets an isolated, empty local store.
func setGlobals(t *testing.T, cmd *cobra.Command, srvURL string) {
	t.Helper()
	serverURL = srvURL
	configDir = t.TempDir()
	account = ""
	outputFmt = "text"
	verbose = false
	cmd.SetContext(context.Background())
}

// --- updateGroup ---

func TestUpdateGroupCmd_MissingName_Create(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, updateGroupCmd, srv.URL)

	updateGroupCmd.ResetFlags()
	updateGroupCmd.Flags().String("name", "", "group name")
	updateGroupCmd.Flags().String("group-id", "", "existing group ID")
	updateGroupCmd.Flags().String("description", "", "group description")
	updateGroupCmd.Flags().StringSlice("member", nil, "add member")

	err := updateGroupCmd.RunE(updateGroupCmd, []string{})
	if err == nil {
		t.Fatal("expected UsageError for missing name")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestUpdateGroupCmd_CreateGroup_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, updateGroupCmd, srv.URL)

	buf := &bytes.Buffer{}
	updateGroupCmd.SetOut(buf)
	updateGroupCmd.ResetFlags()
	updateGroupCmd.Flags().String("name", "", "group name")
	updateGroupCmd.Flags().String("group-id", "", "existing group ID")
	updateGroupCmd.Flags().String("description", "", "group description")
	updateGroupCmd.Flags().StringSlice("member", nil, "add member")
	_ = updateGroupCmd.Flags().Set("name", "TestGroup")

	if err := updateGroupCmd.RunE(updateGroupCmd, []string{}); err != nil {
		t.Fatalf("updateGroup create: %v", err)
	}
	if !strings.Contains(buf.String(), "Group created") {
		t.Errorf("output = %q, want 'Group created'", buf.String())
	}
}

func TestUpdateGroupCmd_UpdateNonExistentGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, updateGroupCmd, srv.URL)

	updateGroupCmd.ResetFlags()
	updateGroupCmd.Flags().String("name", "", "group name")
	updateGroupCmd.Flags().String("group-id", "", "existing group ID")
	updateGroupCmd.Flags().String("description", "", "group description")
	updateGroupCmd.Flags().StringSlice("member", nil, "add member")
	_ = updateGroupCmd.Flags().Set("group-id", "g-nonexistent")
	_ = updateGroupCmd.Flags().Set("name", "New Name")

	// Local DAOStore is empty: UpdateGroup returns "group not found" → CLIError.
	err := updateGroupCmd.RunE(updateGroupCmd, []string{})
	if err == nil {
		t.Fatal("expected error for non-existent group")
	}
	if _, ok := err.(*CLIError); !ok {
		t.Errorf("expected *CLIError, got %T: %v", err, err)
	}
}

// --- quitGroup ---

func TestQuitGroupCmd_MissingGroupID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, quitGroupCmd, srv.URL)

	quitGroupCmd.ResetFlags()
	quitGroupCmd.Flags().String("group-id", "", "group ID to leave")

	err := quitGroupCmd.RunE(quitGroupCmd, []string{})
	if err == nil {
		t.Fatal("expected UsageError for missing group-id")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestQuitGroupCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, quitGroupCmd, srv.URL)

	buf := &bytes.Buffer{}
	quitGroupCmd.SetOut(buf)
	quitGroupCmd.ResetFlags()
	quitGroupCmd.Flags().String("group-id", "", "group ID to leave")
	_ = quitGroupCmd.Flags().Set("group-id", "group-abc")

	if err := quitGroupCmd.RunE(quitGroupCmd, []string{}); err != nil {
		t.Fatalf("quitGroup: %v", err)
	}
	if !strings.Contains(buf.String(), "Left group") {
		t.Errorf("output = %q, want 'Left group'", buf.String())
	}
}

// --- joinGroup ---

func TestJoinGroupCmd_MissingURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, joinGroupCmd, srv.URL)

	joinGroupCmd.ResetFlags()
	joinGroupCmd.Flags().String("uri", "", "group invite URI")

	err := joinGroupCmd.RunE(joinGroupCmd, []string{})
	if err == nil {
		t.Fatal("expected UsageError for missing URI")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestJoinGroupCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, joinGroupCmd, srv.URL)

	buf := &bytes.Buffer{}
	joinGroupCmd.SetOut(buf)
	joinGroupCmd.ResetFlags()
	joinGroupCmd.Flags().String("uri", "", "group invite URI")
	_ = joinGroupCmd.Flags().Set("uri", "https://signal.group/#abc")

	if err := joinGroupCmd.RunE(joinGroupCmd, []string{}); err != nil {
		t.Fatalf("joinGroup: %v", err)
	}
	if !strings.Contains(buf.String(), "Joined group") {
		t.Errorf("output = %q, want 'Joined group'", buf.String())
	}
}

// --- addDevice ---

func TestAddDeviceCmd_MissingURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, addDeviceCmd, srv.URL)

	addDeviceCmd.ResetFlags()
	addDeviceCmd.Flags().String("uri", "", "provisioning URI")

	err := addDeviceCmd.RunE(addDeviceCmd, []string{})
	if err == nil {
		t.Fatal("expected UsageError for missing URI")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestAddDeviceCmd_Success(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, addDeviceCmd, srv.URL)

	buf := &bytes.Buffer{}
	addDeviceCmd.SetOut(buf)
	addDeviceCmd.ResetFlags()
	addDeviceCmd.Flags().String("uri", "", "provisioning URI")
	_ = addDeviceCmd.Flags().Set("uri", "provision-token-abc")

	if err := addDeviceCmd.RunE(addDeviceCmd, []string{}); err != nil {
		t.Fatalf("addDevice: %v", err)
	}
	if !strings.HasSuffix(gotPath, "provision-token-abc") {
		t.Errorf("path = %q, expected suffix 'provision-token-abc'", gotPath)
	}
	if !strings.Contains(buf.String(), "Device linked") {
		t.Errorf("output = %q, want 'Device linked'", buf.String())
	}
}

func TestAddDeviceCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	setGlobals(t, addDeviceCmd, srv.URL)

	addDeviceCmd.ResetFlags()
	addDeviceCmd.Flags().String("uri", "", "provisioning URI")
	_ = addDeviceCmd.Flags().Set("uri", "bad-token")

	err := addDeviceCmd.RunE(addDeviceCmd, []string{})
	if err == nil {
		t.Fatal("expected error on server 403")
	}
	if _, ok := err.(*CLIError); !ok {
		t.Errorf("expected *CLIError, got %T: %v", err, err)
	}
}

// --- sendReaction ---

func TestSendReactionCmd_MissingEmoji(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, sendReactionCmd, srv.URL)

	sendReactionCmd.ResetFlags()
	sendReactionCmd.Flags().String("emoji", "", "emoji character")
	sendReactionCmd.Flags().String("target-author", "", "message author")
	sendReactionCmd.Flags().String("target-timestamp", "", "message timestamp")
	sendReactionCmd.Flags().Bool("remove", false, "remove reaction")

	err := sendReactionCmd.RunE(sendReactionCmd, []string{"recipient"})
	if err == nil {
		t.Fatal("expected UsageError for missing emoji")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestSendReactionCmd_InvalidTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, sendReactionCmd, srv.URL)

	sendReactionCmd.ResetFlags()
	sendReactionCmd.Flags().String("emoji", "", "emoji character")
	sendReactionCmd.Flags().String("target-author", "", "message author")
	sendReactionCmd.Flags().String("target-timestamp", "", "message timestamp")
	sendReactionCmd.Flags().Bool("remove", false, "remove reaction")
	_ = sendReactionCmd.Flags().Set("emoji", "👍")
	_ = sendReactionCmd.Flags().Set("target-timestamp", "not-a-number")

	err := sendReactionCmd.RunE(sendReactionCmd, []string{"recipient"})
	if err == nil {
		t.Fatal("expected UsageError for invalid timestamp")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestSendReactionCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, sendReactionCmd, srv.URL)

	buf := &bytes.Buffer{}
	sendReactionCmd.SetOut(buf)
	sendReactionCmd.ResetFlags()
	sendReactionCmd.Flags().String("emoji", "", "emoji character")
	sendReactionCmd.Flags().String("target-author", "", "message author")
	sendReactionCmd.Flags().String("target-timestamp", "", "message timestamp")
	sendReactionCmd.Flags().Bool("remove", false, "remove reaction")
	_ = sendReactionCmd.Flags().Set("emoji", "👍")
	_ = sendReactionCmd.Flags().Set("target-author", "author-uuid")
	_ = sendReactionCmd.Flags().Set("target-timestamp", "1234567890")

	if err := sendReactionCmd.RunE(sendReactionCmd, []string{"recipient-uuid"}); err != nil {
		t.Fatalf("sendReaction: %v", err)
	}
	if !strings.Contains(buf.String(), "Reaction sent") {
		t.Errorf("output = %q, want 'Reaction sent'", buf.String())
	}
}

// --- sendReceipt ---

func TestSendReceiptCmd_MissingTimestamps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, sendReceiptCmd, srv.URL)

	sendReceiptCmd.ResetFlags()
	sendReceiptCmd.Flags().String("type", "read", "receipt type")
	sendReceiptCmd.Flags().StringSliceP("timestamps", "t", nil, "message timestamps")

	err := sendReceiptCmd.RunE(sendReceiptCmd, []string{"recipient"})
	if err == nil {
		t.Fatal("expected UsageError for missing timestamps")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestSendReceiptCmd_InvalidTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, sendReceiptCmd, srv.URL)

	sendReceiptCmd.ResetFlags()
	sendReceiptCmd.Flags().String("type", "read", "receipt type")
	sendReceiptCmd.Flags().StringSliceP("timestamps", "t", nil, "message timestamps")
	_ = sendReceiptCmd.Flags().Set("timestamps", "not-a-number")

	err := sendReceiptCmd.RunE(sendReceiptCmd, []string{"recipient"})
	if err == nil {
		t.Fatal("expected UsageError for invalid timestamp")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestSendReceiptCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, sendReceiptCmd, srv.URL)

	buf := &bytes.Buffer{}
	sendReceiptCmd.SetOut(buf)
	sendReceiptCmd.ResetFlags()
	sendReceiptCmd.Flags().String("type", "read", "receipt type")
	sendReceiptCmd.Flags().StringSliceP("timestamps", "t", nil, "message timestamps")
	_ = sendReceiptCmd.Flags().Set("timestamps", "1234567890,9876543210")

	if err := sendReceiptCmd.RunE(sendReceiptCmd, []string{"recipient-uuid"}); err != nil {
		t.Fatalf("sendReceipt: %v", err)
	}
	if !strings.Contains(buf.String(), "Receipt sent") {
		t.Errorf("output = %q, want 'Receipt sent'", buf.String())
	}
}

// --- sendTyping ---

func TestSendTypingCmd_Start(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, sendTypingCmd, srv.URL)

	sendTypingCmd.ResetFlags()
	sendTypingCmd.Flags().Bool("stop", false, "stop typing indicator")

	if err := sendTypingCmd.RunE(sendTypingCmd, []string{"recipient"}); err != nil {
		t.Fatalf("sendTyping start: %v", err)
	}
}

func TestSendTypingCmd_Stop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, sendTypingCmd, srv.URL)

	sendTypingCmd.ResetFlags()
	sendTypingCmd.Flags().Bool("stop", false, "stop typing indicator")
	_ = sendTypingCmd.Flags().Set("stop", "true")

	if err := sendTypingCmd.RunE(sendTypingCmd, []string{"recipient"}); err != nil {
		t.Fatalf("sendTyping stop: %v", err)
	}
}

// --- remoteDelete ---

func TestRemoteDeleteCmd_MissingTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, remoteDeleteCmd, srv.URL)

	remoteDeleteCmd.ResetFlags()
	remoteDeleteCmd.Flags().String("target-timestamp", "", "timestamp of message to delete")

	err := remoteDeleteCmd.RunE(remoteDeleteCmd, []string{"recipient"})
	if err == nil {
		t.Fatal("expected UsageError for missing timestamp")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestRemoteDeleteCmd_InvalidTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, remoteDeleteCmd, srv.URL)

	remoteDeleteCmd.ResetFlags()
	remoteDeleteCmd.Flags().String("target-timestamp", "", "timestamp of message to delete")
	_ = remoteDeleteCmd.Flags().Set("target-timestamp", "not-a-number")

	err := remoteDeleteCmd.RunE(remoteDeleteCmd, []string{"recipient"})
	if err == nil {
		t.Fatal("expected UsageError for invalid timestamp")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestRemoteDeleteCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setGlobals(t, remoteDeleteCmd, srv.URL)

	buf := &bytes.Buffer{}
	remoteDeleteCmd.SetOut(buf)
	remoteDeleteCmd.ResetFlags()
	remoteDeleteCmd.Flags().String("target-timestamp", "", "timestamp of message to delete")
	_ = remoteDeleteCmd.Flags().Set("target-timestamp", "1234567890")

	if err := remoteDeleteCmd.RunE(remoteDeleteCmd, []string{"recipient-uuid"}); err != nil {
		t.Fatalf("remoteDelete: %v", err)
	}
	if !strings.Contains(buf.String(), "Message deleted") {
		t.Errorf("output = %q, want 'Message deleted'", buf.String())
	}
}

// --- sendContacts ---

// TestSendContactsCmd_NoCredentials verifies the command returns a CLIError
// wrapping NotRegisteredError when no account credentials exist in the local store.
func TestSendContactsCmd_NoCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	// Empty configDir: DAOStore returns nil credentials.
	setGlobals(t, sendContactsCmd, srv.URL)

	err := sendContactsCmd.RunE(sendContactsCmd, []string{})
	if err == nil {
		t.Fatal("expected error when no credentials")
	}
	if _, ok := err.(*CLIError); !ok {
		t.Errorf("expected *CLIError, got %T: %v", err, err)
	}
}

// TestSendContactsCmd_ErrorContainsOp verifies the CLIError Op field is set
// to "send contacts" so CLI output identifies which operation failed.
func TestSendContactsCmd_ErrorContainsOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, sendContactsCmd, srv.URL)

	err := sendContactsCmd.RunE(sendContactsCmd, []string{})
	if err == nil {
		t.Fatal("expected error")
	}
	var cliErr *CLIError
	if !errors.As(err, &cliErr) {
		t.Fatalf("error does not wrap CLIError: %T %v", err, err)
	}
	if cliErr.Op != "send contacts" {
		t.Errorf("Op = %q, want 'send contacts'", cliErr.Op)
	}
}

// --- updateConfiguration ---

func TestUpdateConfigurationCmd_NoFlagsSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, updateConfigurationCmd, srv.URL)

	updateConfigurationCmd.ResetFlags()
	updateConfigurationCmd.Flags().String("read-receipts", "", "true or false")
	updateConfigurationCmd.Flags().String("typing-indicators", "", "true or false")
	updateConfigurationCmd.Flags().String("link-previews", "", "true or false")

	err := updateConfigurationCmd.RunE(updateConfigurationCmd, []string{})
	if err == nil {
		t.Fatal("expected UsageError when no flags set")
	}
	if _, ok := err.(*UsageError); !ok {
		t.Errorf("expected *UsageError, got %T: %v", err, err)
	}
}

func TestUpdateConfigurationCmd_ReadReceiptsTrue(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	setGlobals(t, updateConfigurationCmd, srv.URL)

	buf := &bytes.Buffer{}
	updateConfigurationCmd.SetOut(buf)
	updateConfigurationCmd.ResetFlags()
	updateConfigurationCmd.Flags().String("read-receipts", "", "true or false")
	updateConfigurationCmd.Flags().String("typing-indicators", "", "true or false")
	updateConfigurationCmd.Flags().String("link-previews", "", "true or false")
	_ = updateConfigurationCmd.Flags().Set("read-receipts", "true")

	if err := updateConfigurationCmd.RunE(updateConfigurationCmd, []string{}); err != nil {
		t.Fatalf("updateConfiguration: %v", err)
	}
	if !strings.Contains(buf.String(), "Configuration updated") {
		t.Errorf("output = %q, want 'Configuration updated'", buf.String())
	}
	if gotBody["readReceipts"] != true {
		t.Errorf("readReceipts = %v, want true", gotBody["readReceipts"])
	}
}

func TestUpdateConfigurationCmd_MultipleFields(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	setGlobals(t, updateConfigurationCmd, srv.URL)

	updateConfigurationCmd.ResetFlags()
	updateConfigurationCmd.Flags().String("read-receipts", "", "true or false")
	updateConfigurationCmd.Flags().String("typing-indicators", "", "true or false")
	updateConfigurationCmd.Flags().String("link-previews", "", "true or false")
	_ = updateConfigurationCmd.Flags().Set("read-receipts", "false")
	_ = updateConfigurationCmd.Flags().Set("typing-indicators", "true")
	_ = updateConfigurationCmd.Flags().Set("link-previews", "false")

	if err := updateConfigurationCmd.RunE(updateConfigurationCmd, []string{}); err != nil {
		t.Fatalf("updateConfiguration multi-field: %v", err)
	}
	if gotBody["readReceipts"] != false {
		t.Errorf("readReceipts = %v, want false", gotBody["readReceipts"])
	}
	if gotBody["typingIndicators"] != true {
		t.Errorf("typingIndicators = %v, want true", gotBody["typingIndicators"])
	}
}

func TestUpdateConfigurationCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer srv.Close()
	setGlobals(t, updateConfigurationCmd, srv.URL)

	updateConfigurationCmd.ResetFlags()
	updateConfigurationCmd.Flags().String("read-receipts", "", "true or false")
	updateConfigurationCmd.Flags().String("typing-indicators", "", "true or false")
	updateConfigurationCmd.Flags().String("link-previews", "", "true or false")
	_ = updateConfigurationCmd.Flags().Set("typing-indicators", "false")

	err := updateConfigurationCmd.RunE(updateConfigurationCmd, []string{})
	if err == nil {
		t.Fatal("expected error on server failure")
	}
	if _, ok := err.(*CLIError); !ok {
		t.Errorf("expected *CLIError, got %T: %v", err, err)
	}
}

// --- deleteLocalAccountData ---

func TestDeleteLocalDataCmd_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	setGlobals(t, deleteLocalDataCmd, srv.URL)

	buf := &bytes.Buffer{}
	deleteLocalDataCmd.SetOut(buf)

	if err := deleteLocalDataCmd.RunE(deleteLocalDataCmd, []string{}); err != nil {
		t.Fatalf("deleteLocalAccountData: %v", err)
	}
	if !strings.Contains(buf.String(), "Local account data deleted") {
		t.Errorf("output = %q, want 'Local account data deleted'", buf.String())
	}
}

func TestDeleteLocalDataCmd_AlreadyAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	// Point configDir at a path that does not exist yet.
	// os.RemoveAll is a no-op for missing paths and returns nil.
	serverURL = srv.URL
	configDir = filepath.Join(t.TempDir(), "nonexistent-subdir")
	outputFmt = "text"
	deleteLocalDataCmd.SetContext(context.Background())

	buf := &bytes.Buffer{}
	deleteLocalDataCmd.SetOut(buf)

	if err := deleteLocalDataCmd.RunE(deleteLocalDataCmd, []string{}); err != nil {
		t.Fatalf("deleteLocalAccountData with absent dir: %v", err)
	}
	if !strings.Contains(buf.String(), "Local account data deleted") {
		t.Errorf("output = %q, want 'Local account data deleted'", buf.String())
	}
}
