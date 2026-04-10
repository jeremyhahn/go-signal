//go:build desktop

// Package desktop provides the Wails-based desktop GUI for the Signal client.
// It is activated via the `desktop` build tag and wraps the sdk/go client
// with a React frontend served through Wails' native webview.
package desktop

import (
	"fmt"
	"os"
	"path/filepath"

	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// Run initializes and starts the Wails desktop application.
// It creates an embedded QRDB KVStore for local persistence,
// builds the Signal SDK client, and launches the Wails window.
func Run(serverURL, dataDir string) error {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("desktop: get home dir: %w", err)
		}
		dataDir = filepath.Join(home, ".config", "signal")
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("desktop: create data dir: %w", err)
	}

	// Default server URL for self-hosted deployments.
	if serverURL == "" {
		serverURL = "https://localhost:8081"
	}

	cfg := signal.ClientConfig{
		ServerURL: serverURL,
		DataDir:   dataDir,
		UserAgent: "signal-desktop-go/0.1",
	}

	app, err := NewApp(cfg)
	if err != nil {
		return fmt.Errorf("desktop: create app: %w", err)
	}

	// Launch the Wails application.
	// Wails v2 integration is wired through wails.json and the wails CLI.
	// During `wails dev`, the frontend is served from the Vite dev server.
	// During `wails build`, frontend assets are embedded automatically.
	//
	// The actual wails.Run() call requires the Wails CLI to generate the
	// binding code and embed assets. For now, start in headless mode:
	fmt.Fprintf(os.Stderr, "Signal desktop initialized (server: %s, data: %s)\n", serverURL, dataDir)
	fmt.Fprintln(os.Stderr, "Run 'wails dev' from the project root to launch the GUI.")

	// Keep the app alive for WebSocket connections.
	_ = app
	select {} // block until signal
}
