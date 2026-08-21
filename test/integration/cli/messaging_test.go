//go:build integration

package cli

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Messaging
// Commands: send, receive, sendReaction, sendReceipt, sendTyping,
//           remoteDelete, sendContacts
// =============================================================================

func TestCLI_SendAndReceive(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			sender := uniqueNumber()
			receiver := uniqueNumber()

			registerAndVerify(t, bin, sender)
			receiverBin := withName(bin, "receiver")
			registerAndVerify(t, receiverBin, receiver)

			recipientID := getAccountUUID(t, receiverBin, receiver)

			sendResult := execCLIAccount(t, bin, sender, "send", "-m", "hello parity test", recipientID)
			assert.Equal(t, 0, sendResult.ExitCode, "send should succeed: %s", sendResult.Stderr)

			recvResult := execCLIAccount(t, receiverBin, receiver, "receive", "--timeout", "3")
			assert.Equal(t, 0, recvResult.ExitCode, "receive should succeed")

			encoded := base64.StdEncoding.EncodeToString([]byte("hello parity test"))
			found := strings.Contains(recvResult.Stdout, "hello parity test") ||
				strings.Contains(recvResult.Stdout, encoded)
			assert.True(t, found, "should contain message content")
		})
	}
}

func TestCLI_SendReaction(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)
			target := uniqueNumber()
			registerAndVerify(t, withName(bin, "target"), target)

			targetUUID := getAccountUUID(t, withName(bin, "target"), target)

			result := execCLIAccount(t, bin, number,
				"sendReaction", "--emoji", "\U0001f44d",
				"--target-author", targetUUID,
				"--target-timestamp", "1000000000000",
				targetUUID,
			)
			t.Logf("sendReaction exit=%d stderr=%s", result.ExitCode, result.Stderr)
		})
	}
}

func TestCLI_SendReceipt(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)
			target := uniqueNumber()
			registerAndVerify(t, withName(bin, "target"), target)

			targetUUID := getAccountUUID(t, withName(bin, "target"), target)

			result := execCLIAccount(t, bin, number,
				"sendReceipt", "--type", "read",
				"-t", "1000000000000",
				targetUUID,
			)
			t.Logf("sendReceipt exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_SendTyping(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)
			target := uniqueNumber()
			registerAndVerify(t, withName(bin, "target"), target)

			targetUUID := getAccountUUID(t, withName(bin, "target"), target)

			result := execCLIAccount(t, bin, number, "sendTyping", targetUUID)
			t.Logf("sendTyping exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_RemoteDelete(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)
			target := uniqueNumber()
			registerAndVerify(t, withName(bin, "target"), target)

			targetUUID := getAccountUUID(t, withName(bin, "target"), target)

			result := execCLIAccount(t, bin, number,
				"remoteDelete", "--target-timestamp", "1000000000000",
				targetUUID,
			)
			t.Logf("remoteDelete exit=%d", result.ExitCode)
		})
	}
}

func TestCLI_SendContacts(t *testing.T) {
	for _, bin := range binaries(t) {
		t.Run(bin.Name, func(t *testing.T) {
			number := uniqueNumber()
			registerAndVerify(t, bin, number)

			result := execCLIAccount(t, bin, number, "sendContacts")
			t.Logf("sendContacts exit=%d", result.ExitCode)
		})
	}
}

// --- helpers ---

func getAccountUUID(t *testing.T, bin CLIBinary, number string) string {
	t.Helper()
	if bin.Kind == KindSignalGo {
		result := execCLIAccount(t, bin, number, "whoami")
		require.Equal(t, 0, result.ExitCode)
		data := parseJSON(t, result)
		return data["uuid"].(string)
	}
	return number
}

// withName derives a binary for a second account in the same test: the
// suffixed Name gives it its own data directory and labels it distinctly in
// the log. Kind is copied unchanged, so the derived binary still builds
// commands for the implementation it actually drives.
func withName(bin CLIBinary, suffix string) CLIBinary {
	b := bin
	b.Name = bin.Name + "-" + suffix
	return b
}
