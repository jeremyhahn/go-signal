package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// errMemlockTooSmall stands in for the secure-memory lifecycle refusing a
// host whose RLIMIT_MEMLOCK is too small to budget.
var errMemlockTooSmall = errors.New("root_securemem_test: memlock too small")

// executeRoot runs the root command on args through Execute, with a start
// that fails as a host too small to budget would, and returns the command's
// output, the number of starts and its error.
func executeRoot(t *testing.T, args ...string) (string, int, error) {
	t.Helper()
	prevStart := startSecureMemory
	t.Cleanup(func() {
		startSecureMemory = prevStart
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		if f := rootCmd.Flags().Lookup("help"); f != nil {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	})
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	starts := 0
	err := Execute(func() error {
		starts++
		return errMemlockTooSmall
	})
	return out.String(), starts, err
}

// TestExecute_SecretFreeCommandsRunWithoutSecureMemory proves version and
// help run on a host whose memlock limit the lifecycle would refuse: they
// never start it.
func TestExecute_SecretFreeCommandsRunWithoutSecureMemory(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		"version":      {args: []string{"version"}, want: "signal " + Version},
		"help command": {args: []string{"help"}, want: "Usage:"},
		"help flag":    {args: []string{"--help"}, want: "Usage:"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			out, starts, err := executeRoot(t, tc.args...)
			if err != nil {
				t.Fatalf("Execute(%v): %v", tc.args, err)
			}
			if starts != 0 {
				t.Errorf("Execute(%v) started secure memory %d times, want none", tc.args, starts)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("Execute(%v) output = %q, want it to contain %q", tc.args, out, tc.want)
			}
		})
	}
}

// TestExecute_AccountCommandsStartSecureMemoryFirst proves a command that
// opens an account's store starts the lifecycle before its own work: a
// refusal is the command's error, reached before any client is built.
func TestExecute_AccountCommandsStartSecureMemoryFirst(t *testing.T) {
	for _, args := range [][]string{{"whoami"}, {"receive"}} {
		t.Run(args[0], func(t *testing.T) {
			_, starts, err := executeRoot(t, args...)
			if !errors.Is(err, errMemlockTooSmall) {
				t.Fatalf("Execute(%v) error = %v, want the lifecycle's refusal", args, err)
			}
			if starts != 1 {
				t.Errorf("Execute(%v) started secure memory %d times, want 1", args, starts)
			}
		})
	}
}
