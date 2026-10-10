package main

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
)

// errMemlockTooSmall stands in for the secure-memory lifecycle refusing a
// host whose RLIMIT_MEMLOCK is too small to budget.
var errMemlockTooSmall = errors.New("root_securemem_test: memlock too small")

// stubSecureMemory replaces startSecureMemory for the duration of t with a
// start that returns err, and returns the number of times it was called.
func stubSecureMemory(t *testing.T, err error) *int {
	t.Helper()
	prev := startSecureMemory
	t.Cleanup(func() { startSecureMemory = prev })
	calls := new(int)
	startSecureMemory = func() error {
		*calls++
		return err
	}
	return calls
}

// executeRoot runs the root command on args through Execute, with a start
// that fails as a host too small to budget would, and returns the command's
// output, the number of starts and its error.
func executeRoot(t *testing.T, args ...string) (string, int, error) {
	t.Helper()
	prevLogger, prevStart, prevPath, prevCfg := logger, startSecureMemory, cfgPath, cfg
	t.Cleanup(func() {
		logger, startSecureMemory, cfgPath, cfg = prevLogger, prevStart, prevPath, prevCfg
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		if f := rootCmd.Flags().Lookup("help"); f != nil {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	})
	cfg = nil
	cfgPath = filepath.Join(t.TempDir(), "absent.yml")
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	starts := 0
	err := Execute(slog.New(slog.NewTextHandler(io.Discard, nil)), func() error {
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
		"version":      {args: []string{"version"}, want: rootCmd.Use + " "},
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

// TestExecute_StartRefusesBeforeConfigLoads proves the start command runs
// the lifecycle before configuration loading: a refusal is the command's
// error and no configuration was loaded.
func TestExecute_StartRefusesBeforeConfigLoads(t *testing.T) {
	_, starts, err := executeRoot(t, "start")
	if !errors.Is(err, errMemlockTooSmall) {
		t.Fatalf("Execute(start) error = %v, want the lifecycle's refusal", err)
	}
	if starts != 1 {
		t.Errorf("Execute(start) started secure memory %d times, want 1", starts)
	}
	if cfg != nil {
		t.Error("configuration loaded although the lifecycle refused")
	}
}

// TestRoot_StartsSecureMemoryBeforeLoadingConfig proves a successful start
// precedes configuration loading, which then proceeds.
func TestRoot_StartsSecureMemoryBeforeLoadingConfig(t *testing.T) {
	prevPath, prevCfg, prevStart := cfgPath, cfg, startSecureMemory
	t.Cleanup(func() { cfgPath, cfg, startSecureMemory = prevPath, prevCfg, prevStart })
	cfg = nil
	cfgPath = rootAddressTestConfig(t, "127.0.0.1:20001")
	loadedAtStart := true
	startSecureMemory = func() error {
		loadedAtStart = cfg != nil
		return nil
	}
	if err := rootCmd.PersistentPreRunE(startCmd, nil); err != nil {
		t.Fatalf("PersistentPreRunE: %v", err)
	}
	if loadedAtStart {
		t.Error("configuration loaded before secure memory started")
	}
	if cfg == nil {
		t.Error("configuration not loaded after secure memory started")
	}
}
