// Package frontend embeds the compiled React/Vite SPA build output so that
// the signald binary can serve the web UI without any external file system
// dependency.
//
// The embedded files live in the dist/ subdirectory of this package, which is
// populated by `make build-frontend` as part of the server build process.
// Run that target before building the signald binary.
package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var staticFiles embed.FS

// FS returns the embedded file system rooted at the Vite output directory.
// All files (assets, index.html, etc.) are accessible without any prefix.
func FS() fs.FS {
	sub, err := fs.Sub(staticFiles, "dist")
	if err != nil {
		// fs.Sub fails only when the subdirectory does not exist inside the
		// embed, which is a programming error caught at compile time.
		panic("frontend: dist not found in embedded FS: " + err.Error())
	}
	return sub
}
