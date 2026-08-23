// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

//go:build !gui

package main

// Tests for the no-GUI stubs in gui_nogui.go.
//
// They live in their own !gui-tagged file because they reference symbols that
// exist ONLY in that build -- ErrGUINotAvailable, and the stub hasDisplay and
// runGUI. While they sat in the untagged acme_client_test.go, that whole file
// was implicitly a !gui file: `go vet -tags gui ./cmd/acme-client/` failed on
// "undefined: ErrGUINotAvailable" and `go test -tags gui` could not build the
// package at all, which took every OTHER test in it down too.
//
// That is the same shape as #48 itself -- a build tag nobody evaluates, hiding
// code that no longer compiles -- one directory over, so it is fixed here
// rather than left for the next person to trip on.

import (
	"errors"
	"strings"
	"testing"
)

func TestErrGUINotAvailable_Error(t *testing.T) {
	err := ErrGUINotAvailable{}
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}
	if !strings.Contains(msg, "GUI not available") {
		t.Errorf("expected 'GUI not available' in message: %q", msg)
	}
}

func TestHasDisplay_ReturnsFalse(t *testing.T) {
	if hasDisplay() {
		t.Error("hasDisplay should return false in no-gui build")
	}
}

func TestRunGUI_ReturnsError(t *testing.T) {
	err := runGUI()
	if err == nil {
		t.Error("runGUI should return error in no-gui build")
	}
	var e ErrGUINotAvailable
	if !errors.As(err, &e) {
		t.Errorf("expected ErrGUINotAvailable, got %T: %v", err, err)
	}
}
