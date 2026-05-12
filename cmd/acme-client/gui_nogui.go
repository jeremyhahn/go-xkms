// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-ca.
//
// go-trusted-ca is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !gui

package main

// ErrGUINotAvailable is returned when the binary was built without GUI support.
type ErrGUINotAvailable struct{}

// Error returns the error message.
func (e ErrGUINotAvailable) Error() string {
	return "GUI not available: build with -tags gui to enable desktop mode"
}

// hasDisplay returns false when built without the gui tag.
func hasDisplay() bool {
	return false
}

// runGUI returns an error when built without the gui tag.
func runGUI() error {
	return ErrGUINotAvailable{}
}
