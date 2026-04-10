//go:build desktop

package main

import "github.com/jeremyhahn/go-signal/pkg/desktop"

// runGUI launches the Wails desktop application.
func runGUI(serverURL, dataDir string) error {
	return desktop.Run(serverURL, dataDir)
}
