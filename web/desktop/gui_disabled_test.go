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

import (
	"log/slog"
	"testing"
)

// TestRunGUI_DisabledBuildReturnsError proves the stub in gui_disabled.go
// reports GUI support as absent rather than silently succeeding. It carries
// the same "!desktop" constraint as gui_disabled.go: with the "desktop" tag,
// runGUI is gui_enabled.go, which opens a real Wails/WebKit window and is a
// GUI smoke test outside a unit test's remit, not this stub's contract.
func TestRunGUI_DisabledBuildReturnsError(t *testing.T) {
	err := runGUI(Connection{Mode: ModeRemote, BaseURL: "https://x:8443"}, slog.Default())
	var gu *GUIUnavailableError
	if !errorsAs(err, &gu) {
		t.Fatalf("expected GUIUnavailableError, got %T", err)
	}
}

// errorsAs is a tiny local errors.As to avoid an import solely for one call.
func errorsAs(err error, target **GUIUnavailableError) bool {
	if e, ok := err.(*GUIUnavailableError); ok {
		*target = e
		return true
	}
	return false
}
