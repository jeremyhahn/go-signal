//go:build integration

package api

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// signalCLIPhoneRunBase is a random per-run prefix that ensures phone numbers
// don't collide with numbers from prior test runs against a persistent server.
var signalCLIPhoneRunBase int64

func init() {
	var buf [2]byte
	if _, err := cryptorand.Read(buf[:]); err == nil {
		signalCLIPhoneRunBase = int64(binary.BigEndian.Uint16(buf[:])) % 9000
	}
}

// signalCLIPhoneCounter generates unique phone numbers for signal-cli tests.
var signalCLIPhoneCounter int64

// signalCLIUniqueNumber generates a unique phone number for signal-cli tests.
// The format is +1555RRRRNNN where RRRR is a random 4-digit per-run prefix
// and NNN is a sequential counter, ensuring uniqueness across runs.
func signalCLIUniqueNumber() string {
	n := atomic.AddInt64(&signalCLIPhoneCounter, 1)
	return fmt.Sprintf("+1555%04d%03d", signalCLIPhoneRunBase, n)
}

// signalCLIBin returns the path to the signal-cli binary.
func signalCLIBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("SIGNAL_CLI_BIN")
	if bin == "" {
		bin = "signal-cli"
	}
	_, err := exec.LookPath(bin)
	require.NoError(t, err, "signal-cli binary not found at %q; set SIGNAL_CLI_BIN or ensure it is in PATH", bin)
	return bin
}

// signalCLITestDirs caches one temp directory per test. The key is t.Name()
// and the value is an absolute path created by t.TempDir(). Using a sync.Map
// ensures that all signal-cli invocations within a single test share the same
// data directory even when helper functions are called from different
// goroutines, while completely isolating concurrent tests from each other and
// eliminating the SQLite lock contention caused by the shared global volume.
var signalCLITestDirs sync.Map // map[string]string

// signalCLITestDataDir returns a per-test isolated data directory for
// signal-cli. The directory is created once per test via t.TempDir() and
// cached for all subsequent calls within the same test, so that register,
// verify, and subsequent commands all operate on the same local account store.
func signalCLITestDataDir(t *testing.T) string {
	t.Helper()
	dir, _ := signalCLITestDirs.LoadOrStore(t.Name(), t.TempDir())
	return dir.(string)
}

// signalCLIResult holds the output of a signal-cli command execution.
type signalCLIResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// signalCLIExecVerbose runs a signal-cli command with --verbose for full
// debug-level logging, useful for diagnosing failures.
func signalCLIExecVerbose(t *testing.T, args ...string) signalCLIResult {
	t.Helper()
	bin := signalCLIBin(t)
	dataDir := signalCLITestDataDir(t)

	fullArgs := []string{"--config", dataDir, "--output", "json", "--verbose"}
	fullArgs = append(fullArgs, args...)

	t.Logf("signal-cli (verbose) %s", strings.Join(fullArgs, " "))

	cmd := exec.Command(bin, fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		exitCode = -1
	}

	result := signalCLIResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}

	t.Logf("exit=%d stdout=%s stderr=%s", exitCode, result.Stdout, result.Stderr)
	return result
}

// signalCLIExecAccountVerbose runs a signal-cli command with the -a (account)
// flag and --verbose for debug-level logging.
func signalCLIExecAccountVerbose(t *testing.T, account string, args ...string) signalCLIResult {
	t.Helper()
	fullArgs := []string{"-a", account}
	fullArgs = append(fullArgs, args...)
	return signalCLIExecVerbose(t, fullArgs...)
}

// signalCLIExec runs a signal-cli command and returns the result.
// The command is run with --output json for machine-readable output.
// Each test gets its own isolated data directory via signalCLITestDataDir so
// that concurrent tests do not contend on a shared SQLite database.
func signalCLIExec(t *testing.T, args ...string) signalCLIResult {
	t.Helper()
	bin := signalCLIBin(t)
	dataDir := signalCLITestDataDir(t)

	fullArgs := []string{"--config", dataDir, "--output", "json"}
	fullArgs = append(fullArgs, args...)

	t.Logf("signal-cli %s", strings.Join(fullArgs, " "))

	cmd := exec.Command(bin, fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		exitCode = -1
	}

	result := signalCLIResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}

	t.Logf("exit=%d stdout=%s stderr=%s", exitCode, result.Stdout, result.Stderr)
	return result
}

// signalCLIExecAccount runs a signal-cli command with the -a (account) flag.
func signalCLIExecAccount(t *testing.T, account string, args ...string) signalCLIResult {
	t.Helper()
	fullArgs := []string{"-a", account}
	fullArgs = append(fullArgs, args...)
	return signalCLIExec(t, fullArgs...)
}

// signalCLIExecSuccess runs a signal-cli command and asserts it succeeds.
func signalCLIExecSuccess(t *testing.T, args ...string) signalCLIResult {
	t.Helper()
	result := signalCLIExec(t, args...)
	require.NoError(t, result.Err, "signal-cli command failed: stderr=%s", result.Stderr)
	return result
}

// signalCLIExecAccountSuccess runs a signal-cli command with account and asserts it succeeds.
func signalCLIExecAccountSuccess(t *testing.T, account string, args ...string) signalCLIResult {
	t.Helper()
	result := signalCLIExecAccount(t, account, args...)
	require.NoError(t, result.Err, "signal-cli command failed: stderr=%s", result.Stderr)
	return result
}

// extractJSON finds the first JSON object or array in the output, skipping
// any non-JSON prefix lines (e.g. "TestTrustStore:" debug output from the
// patched signal-cli build).
func extractJSON(output string) string {
	for i, ch := range output {
		if ch == '{' || ch == '[' {
			return output[i:]
		}
	}
	return output
}

// parseJSON parses the stdout of a signal-cli result as JSON.
func parseJSON(t *testing.T, result signalCLIResult) map[string]any {
	t.Helper()
	var data map[string]any
	jsonStr := extractJSON(result.Stdout)
	err := json.Unmarshal([]byte(jsonStr), &data)
	require.NoError(t, err, "failed to parse signal-cli JSON output: %s", result.Stdout)
	return data
}

// parseJSONArray parses the stdout of a signal-cli result as a JSON array.
func parseJSONArray(t *testing.T, result signalCLIResult) []any {
	t.Helper()
	var data []any
	jsonStr := extractJSON(result.Stdout)
	err := json.Unmarshal([]byte(jsonStr), &data)
	require.NoError(t, err, "failed to parse signal-cli JSON array: %s", result.Stdout)
	return data
}

// signalCLIRegisterAndVerify registers a phone number using signal-cli and
// verifies it against the integration test server. Each invocation uses the
// test-scoped isolated data directory so that concurrent tests never share a
// SQLite database.
//
// The function is tolerant of several benign conditions:
//   - "Account is already registered": stale local state from a prior Docker
//     volume; the account is already usable.
//   - "verify is not necessary" / "Reregistered existing account": signal-cli
//     detected that the number was previously registered locally.
//   - "Invalid verification method": the server returned a transport or
//     session state that signal-cli considers unsupported; treated as a
//     non-fatal warning so that the remaining test can proceed if the account
//     was actually created.
//
// Returns the phone number that was registered.
func signalCLIRegisterAndVerify(t *testing.T, number string) string {
	t.Helper()

	// Step 1: Register (requests verification code via POST /v1/verification/session
	// then POST /v1/verification/session/{id}/code).
	result := signalCLIExecAccount(t, number, "register")
	combined := result.Stdout + result.Stderr

	// Stale local state from a prior Docker volume: account already usable.
	if result.ExitCode != 0 &&
		strings.Contains(combined, "Account is already registered") {
		return number
	}

	// signal-cli recognised the number as previously registered locally.
	if strings.Contains(combined, "verify is not necessary") ||
		strings.Contains(combined, "Reregistered existing account") {
		return number
	}

	// "Invalid verification method" means signal-cli received a transport or
	// session-state response it did not recognise (e.g. the server returned
	// allowedToRequestCode:false immediately after session creation). Log the
	// condition and continue: the registration endpoint will still accept the
	// verify step because the server's FixedCode stub matches "123456".
	if result.ExitCode != 0 &&
		strings.Contains(combined, "Invalid verification method") {
		t.Logf("register: server returned an unrecognised verification method; "+
			"attempting verify anyway (number=%s stderr=%s)", number, result.Stderr)
	} else {
		require.NoError(t, result.Err, "register failed: stderr=%s", result.Stderr)
	}

	// Step 2: Verify with the fixed code (our server accepts "123456" in test
	// mode via the FixedCode stub transport).
	result = signalCLIExecAccount(t, number, "verify", "123456")

	// Stale Docker volume state: account already fully registered.
	if result.ExitCode != 0 &&
		strings.Contains(result.Stderr, "Account is already registered") {
		return number
	}

	// If the number has a registration lock from a previous test run (the
	// server container may persist state), re-register with the PIN to create
	// a fresh verification session and complete verification in one step.
	if result.ExitCode != 0 &&
		strings.Contains(result.Stderr, "locked with a pin") {
		t.Logf("number %s has a registration lock; re-registering with --pin", number)
		// Re-register: creates a new verification session
		reregResult := signalCLIExecAccount(t, number, "register")
		if reregResult.ExitCode != 0 &&
			strings.Contains(reregResult.Stdout+reregResult.Stderr, "Account is already registered") {
			return number
		}
		// Verify with the PIN
		result = signalCLIExecAccount(t, number, "verify", "--pin", "12345678", "123456")
		if result.ExitCode != 0 &&
			strings.Contains(result.Stderr, "Account is already registered") {
			return number
		}
	}
	require.NoError(t, result.Err, "verify failed: stderr=%s", result.Stderr)

	return number
}
