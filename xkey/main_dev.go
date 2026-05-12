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

//go:build dev

// This file is the xkey module's main package for wails dev mode.
// Wails v2's CLI hard-codes `go build` in the project root (the directory
// holding wails.json), so a main package must live here for `wails dev` to
// succeed. Production and CLI builds use ./cmd/xkey as their entry point
// (see cmd/xkey/main.go) and do not include this file because the `dev`
// build tag is only injected by wails when OutputType == "dev".
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
