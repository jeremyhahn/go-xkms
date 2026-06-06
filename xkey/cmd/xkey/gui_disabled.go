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

//go:build !production && !dev && !bindings

package main

// guiBuildTagPresent is false when the binary was built without any Wails
// build tag. In this state the Wails library compiles a stub CreateApp that
// returns "Wails applications will not build without the correct build tags."
// at runtime — confusing for end users. main.go consults this constant to
// substitute a clear, actionable error message before invoking Wails.
const guiBuildTagPresent = false
