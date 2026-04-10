//go:build !desktop

package main

import (
	"fmt"
	"os"
)

// runGUI is the stub for non-desktop builds.
func runGUI(_, _ string) error {
	fmt.Fprintln(os.Stderr, "GUI mode not available. Build with -tags desktop.")
	fmt.Fprintln(os.Stderr, "Run 'signal --help' for available commands.")
	os.Exit(1)
	return nil
}
