//go:build tools

// Package tools pins the gosec build used by `make gosec`.
package tools

import (
	_ "github.com/securego/gosec/v2/cmd/gosec"
	_ "golang.org/x/tools/go/packages"
)
