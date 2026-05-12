// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build bindings

// This file is the xkey module's main package for the Wails bindings
// generator. When wails builds the bindings extractor binary it runs
// `go build -tags bindings ...` from the project root (the directory
// holding wails.json) with the `dev`, `desktop`, `production`, and
// `debug` tags explicitly stripped (see wails/v2/pkg/commands/bindings).
// Without a main package guarded by `//go:build bindings`, the build
// fails with "build constraints exclude all Go files". Production and
// CLI builds use ./cmd/xkey as their entry point and do not include
// this file because the `bindings` tag is only injected by wails when
// generating TypeScript bindings.
//
// The `bindings` tag also swaps wails.Run() for the binding-extraction
// implementation in wails/v2/internal/app/app_bindings.go, which
// reflects on options.App.Bind to emit the TS types and exits without
// starting the GUI, so this entry point is safe to call gui.Run()
// directly.
package main

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/jeremyhahn/go-xkms/xkey/cmd/xkey/cmd"
	"github.com/jeremyhahn/go-xkms/xkey/frontend"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui"
)

func main() {
	subFS, err := fs.Sub(frontend.Assets, "dist")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load frontend assets: %v\n", err)
		os.Exit(1)
	}
	gui.Assets = subFS
	gui.FirmwareVersion = gui.ParseFirmwareVersion(cmd.Version)

	if err := gui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "GUI error: %v\n", err)
		os.Exit(1)
	}
}
