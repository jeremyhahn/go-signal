//go:build desktop

// Package desktop provides the Wails-based desktop GUI for the Signal client.
// It is activated via the `desktop` build tag and wraps the sdk/go client
// with a React frontend served through Wails' native webview.
package desktop

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"
	signal "github.com/jeremyhahn/go-signal/sdk/go"
)

// newApp is a test seam for RunContext's shutdown-error path; production never reassigns it.
var newApp = NewApp

// Run starts the Wails app until the process exits; prefer RunContext where it must stop.
func Run(serverURL, dataDir string) error {
	return RunContext(context.Background(), serverURL, dataDir)
}

// RunContext starts the Wails app, runs until ctx is cancelled, then closes the client and its store; initialization always completes.
func RunContext(ctx context.Context, serverURL, dataDir string) (err error) {
	if dataDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "desktop: get home dir", err)
		}
		dataDir = filepath.Join(home, ".config", "signal")
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "desktop: create data dir", err)
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

	app, err := newApp(cfg)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "desktop: create app", err)
	}
	// Report a store close failure, unless an earlier error is already being returned.
	defer func() {
		if cerr := app.Close(); cerr != nil && err == nil {
			err = signalerrors.Wrap(signalerrors.ErrInternal, "desktop: close app", cerr)
		}
	}()

	// wails.Run needs the Wails CLI to generate bindings and embed assets; run headless here.
	fmt.Fprintf(os.Stderr, "Signal desktop initialized (server: %s, data: %s)\n", serverURL, dataDir)
	fmt.Fprintln(os.Stderr, "Run 'wails dev' from the project root to launch the GUI.")

	// Keep the app alive for WebSocket connections until the caller stops us.
	<-ctx.Done()
	return nil
}
