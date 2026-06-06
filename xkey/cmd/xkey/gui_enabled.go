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

//go:build production || dev || bindings

package main

// guiBuildTagPresent is true when the binary was built with one of the Wails
// build tags (`production`, `dev`, or `bindings`). It is false otherwise.
// main.go consults this to give a clear error before invoking Wails when the
// binary was compiled without GUI support.
const guiBuildTagPresent = true
