// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !desktop

package main

import "log/slog"

// runGUI is the no-GUI stub used when the binary is built without the
// "desktop" tag (no cgo/WebKit). The connection logic still runs, so this
// build is useful for headless verification and CI compile checks.
func runGUI(_ Connection, _ *slog.Logger) error {
	return &GUIUnavailableError{}
}
