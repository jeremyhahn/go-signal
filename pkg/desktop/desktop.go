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

// newApp is NewApp, indirected so RunContext's shutdown-error path can be
// exercised. A store whose Close fails cannot be provoked through RunContext's
// own arguments — it builds its own config — and that path is precisely the
// one that used to swallow a persistence failure. Production code never
// reassigns it; same seam as cloneSecret in pkg/directory.
var newApp = NewApp

// Run initializes and starts the Wails desktop application, running until the
// process is killed. It is RunContext with a background context — the shape a
// main function wants.
//
// Prefer RunContext anywhere the caller needs the application to stop: this
// one cannot be stopped, so the embedded store it opens is only released by
// process exit.
func Run(serverURL, dataDir string) error {
	return RunContext(context.Background(), serverURL, dataDir)
}

// RunContext initializes and starts the Wails desktop application and runs
// until ctx is cancelled, then closes the client and the embedded store it
// opened before returning.
//
// The context is the whole point. Without one there was no way to stop the
// application at all, so the PebbleDB it opens outlived every caller — which
// in a test meant a live database writing into a t.TempDir() that had already
// been deleted, failing the package after every test had passed (#55).
//
// Initialization always completes: an already-cancelled context skips the
// waiting, not the setup, so a caller that cancels immediately still gets
// either a real initialization error or a cleanly closed store.
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

	// Setup runs detached from cancellation, per the contract above: a
	// cancelled ctx must not leave saved credentials unloaded.
	app, err := newApp(context.WithoutCancel(ctx), cfg)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "desktop: create app", err)
	}
	// NewApp opened the store and nothing else holds it, so closing it is this
	// function's job — and reporting a failure to close is part of that. A
	// database that will not flush is a persistence failure, and returning nil
	// over it would tell the caller the shutdown succeeded.
	//
	// An error already on its way out wins: it is the cause, and the close
	// failure is likely its consequence.
	defer func() {
		if cerr := app.Close(); cerr != nil && err == nil {
			err = signalerrors.Wrap(signalerrors.ErrInternal, "desktop: close app", cerr)
		}
	}()

	// Launch the Wails application.
	// Wails v2 integration is wired through wails.json and the wails CLI.
	// During `wails dev`, the frontend is served from the Vite dev server.
	// During `wails build`, frontend assets are embedded automatically.
	//
	// The actual wails.Run() call requires the Wails CLI to generate the
	// binding code and embed assets. For now, start in headless mode:
	fmt.Fprintf(os.Stderr, "Signal desktop initialized (server: %s, data: %s)\n", serverURL, dataDir)
	fmt.Fprintln(os.Stderr, "Run 'wails dev' from the project root to launch the GUI.")

	// Keep the app alive for WebSocket connections until the caller stops us.
	<-ctx.Done()
	return nil
}
