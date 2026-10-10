// Package main is the entry point for the Signal client. It runs as a CLI
// when subcommands are given, or launches a Wails GUI when run without
// subcommands and a display is detected.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/jeremyhahn/go-signal/cmd/signal/cmd"
	"github.com/jeremyhahn/go-signal/pkg/securemem"
)

func main() {
	args := os.Args[1:]
	forceGUI := hasFlag(args, "--gui")
	forceCLI := hasFlag(args, "--no-gui") || hasFlag(args, "--help") || hasFlag(args, "-h")

	// If the user provided subcommand arguments, treat as CLI intent
	// unless --gui was explicitly passed.
	if !forceGUI && hasSubcommand(args) {
		forceCLI = true
	}

	// CLI mode by default.
	run, label := cmd.Execute, "Error"
	if !forceCLI && (forceGUI || hasGUIEnvironment()) {
		// GUI mode — delegates to runGUI which is build-tagged:
		// desktop build: launches Wails app
		// non-desktop build: prints error and exits
		serverURL := extractFlag(args, "--server")
		dataDir := extractFlag(args, "--config")
		run = func() error { return runGUI(serverURL, dataDir) }
		label = "GUI error"
	} else {
		os.Args = stripFlags(os.Args, "--no-gui", "--gui")
	}

	// The secure-memory lifecycle wraps whichever mode runs, so neither the
	// desktop app's embedded store nor any CLI path can allocate protected
	// memory before the process is hardened and budgeted.
	if err := securemem.Run(run); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", label, err)
		os.Exit(1)
	}
}

// stripFlags removes the specified flags from the argument list.
func stripFlags(args []string, flags ...string) []string {
	remove := make(map[string]struct{}, len(flags))
	for _, f := range flags {
		remove[f] = struct{}{}
	}
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if _, ok := remove[a]; !ok {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// hasSubcommand returns true if the argument list contains a positional
// subcommand, skipping known global flags and their values.
func hasSubcommand(args []string) bool {
	metaFlags := map[string]struct{}{
		"--gui": {}, "--no-gui": {}, "--help": {}, "-h": {},
	}
	valueTakingFlags := map[string]struct{}{
		"--config": {}, "--server": {}, "--account": {}, "-a": {},
		"--output": {}, "--log-level": {},
	}

	skipNext := false
	for _, a := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if _, ok := metaFlags[a]; ok {
			continue
		}
		if _, ok := valueTakingFlags[a]; ok {
			skipNext = true
			continue
		}
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		return true
	}
	return false
}

// hasGUIEnvironment returns true if a graphical display is available.
func hasGUIEnvironment() bool {
	switch runtime.GOOS {
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "darwin", "windows":
		return true
	default:
		return false
	}
}

// extractFlag extracts the value following a flag in the argument list.
// Returns empty string if the flag is not found or has no value.
func extractFlag(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
