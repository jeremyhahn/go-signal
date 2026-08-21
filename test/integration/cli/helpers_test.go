//go:build integration

// Package cli provides table-driven integration tests that run the same
// command sequences against both signal-cli (Java) and our signal (Go)
// binary to verify parity.
package cli

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

// CLIKind identifies which implementation a CLIBinary drives. It selects
// command syntax; Name only labels the process and keys its data directory.
// The two are distinct because withName derives a second account's binary by
// suffixing Name, which must not change how commands are built.
type CLIKind string

const (
	// KindSignalGo is our Go signal binary.
	KindSignalGo CLIKind = "signal-go"
	// KindSignalCLI is the Java signal-cli reference client.
	KindSignalCLI CLIKind = "signal-cli"
)

// CLIBinary represents a Signal CLI binary to test against.
type CLIBinary struct {
	// Name labels the process in test output and keys its data directory.
	// Derived binaries (see withName) carry a suffix, so never switch on it.
	Name string
	// Kind is the implementation, and the only thing command construction
	// may branch on.
	Kind CLIKind
	Bin  string
	// ExtraArgs holds binary-specific arguments prepended to every command
	// (e.g., signal-cli needs different flag names or defaults).
	ExtraArgs []string
}

// cliResult holds the output of a CLI command execution.
type cliResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Err      error
}

// binaries returns the list of CLI binaries to test. Both must be available
// for the full parity test to run. If only one is available, tests run
// against that binary alone.
func binaries(t *testing.T) []CLIBinary {
	t.Helper()
	var bins []CLIBinary

	// Go signal binary
	signalBin := os.Getenv("SIGNAL_GO_BIN")
	if signalBin == "" {
		signalBin = "../../../build/bin/signal"
	}
	if _, err := os.Stat(signalBin); err == nil {
		bins = append(bins, CLIBinary{
			Name: string(KindSignalGo),
			Kind: KindSignalGo,
			Bin:  signalBin,
			ExtraArgs: []string{
				"--server", serverURL(),
				"--ca-cert", caCertPath(),
			},
		})
	}

	// Java signal-cli binary
	signalCLIBin := os.Getenv("SIGNAL_CLI_BIN")
	if signalCLIBin == "" {
		signalCLIBin = "signal-cli"
	}
	if _, err := exec.LookPath(signalCLIBin); err == nil {
		bins = append(bins, CLIBinary{
			Name:      string(KindSignalCLI),
			Kind:      KindSignalCLI,
			Bin:       signalCLIBin,
			ExtraArgs: nil, // signal-cli connects to server configured at build time
		})
	}

	if len(bins) == 0 {
		t.Skip("no CLI binaries available; set SIGNAL_GO_BIN or SIGNAL_CLI_BIN")
	}
	return bins
}

func serverURL() string {
	url := os.Getenv("SIGNAL_SERVER_URL")
	if url == "" {
		url = "https://localhost:8081"
	}
	return url
}

func caCertPath() string {
	path := os.Getenv("SIGNAL_CA_CERT")
	if path == "" {
		path = "../../../test/tls/ca-cert.pem"
	}
	return path
}

// Phone number generation — unique per run.
var phoneRunBase int64
var phoneCounter int64

func init() {
	var buf [2]byte
	if _, err := cryptorand.Read(buf[:]); err == nil {
		phoneRunBase = int64(binary.BigEndian.Uint16(buf[:])) % 9000
	}
}

func uniqueNumber() string {
	n := atomic.AddInt64(&phoneCounter, 1)
	return fmt.Sprintf("+1555%04d%03d", phoneRunBase, n)
}

// Per-test data directory cache.
var testDirs sync.Map

func testDataDir(t *testing.T, binName string) string {
	t.Helper()
	key := t.Name() + "/" + binName
	dir, _ := testDirs.LoadOrStore(key, t.TempDir())
	return dir.(string)
}

// execCLI runs a CLI command and returns the result.
func execCLI(t *testing.T, bin CLIBinary, args ...string) cliResult {
	t.Helper()
	dataDir := testDataDir(t, bin.Name)

	fullArgs := []string{"--config", dataDir, "--output", "json"}
	fullArgs = append(fullArgs, bin.ExtraArgs...)
	fullArgs = append(fullArgs, args...)

	t.Logf("[%s] %s %s", bin.Name, bin.Bin, strings.Join(fullArgs, " "))

	cmd := exec.Command(bin.Bin, fullArgs...)
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

	result := cliResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Err:      err,
	}

	t.Logf("[%s] exit=%d stdout=%s stderr=%s", bin.Name, exitCode, result.Stdout, result.Stderr)
	return result
}

// execCLIAccount runs a CLI command with the -a account flag.
func execCLIAccount(t *testing.T, bin CLIBinary, account string, args ...string) cliResult {
	t.Helper()
	fullArgs := []string{"-a", account}
	fullArgs = append(fullArgs, args...)
	return execCLI(t, bin, fullArgs...)
}

// execCLISuccess runs a CLI command and asserts it succeeds.
func execCLISuccess(t *testing.T, bin CLIBinary, args ...string) cliResult {
	t.Helper()
	result := execCLI(t, bin, args...)
	require.NoError(t, result.Err, "[%s] command failed: stderr=%s", bin.Name, result.Stderr)
	return result
}

// registerAndVerify registers and verifies an account using the given binary.
func registerAndVerify(t *testing.T, bin CLIBinary, number string) {
	t.Helper()
	if bin.Kind == KindSignalCLI {
		// signal-cli selects the account with -a: register, then verify CODE.
		result := execCLIAccount(t, bin, number, "register")
		combined := result.Stdout + result.Stderr
		alreadyRegistered := strings.Contains(combined, "already registered") ||
			strings.Contains(combined, "verify is not necessary")
		if !alreadyRegistered {
			require.Equal(t, 0, result.ExitCode, "register should succeed")
			result = execCLIAccount(t, bin, number, "verify", "123456")
			require.Equal(t, 0, result.ExitCode, "verify should succeed")
		}
	} else {
		// Our Go signal binary: verify does the full flow
		result := execCLI(t, bin, "verify", number, "123456")
		require.Equal(t, 0, result.ExitCode, "verify should succeed: %s", result.Stderr)
	}
}

// extractJSON finds the first JSON object or array in the output.
func extractJSON(output string) string {
	for i, ch := range output {
		if ch == '{' || ch == '[' {
			return output[i:]
		}
	}
	return output
}

// parseJSON parses CLI JSON output into a map.
func parseJSON(t *testing.T, result cliResult) map[string]any {
	t.Helper()
	var data map[string]any
	jsonStr := extractJSON(result.Stdout)
	err := json.Unmarshal([]byte(jsonStr), &data)
	require.NoError(t, err, "failed to parse JSON: %s", result.Stdout)
	return data
}
