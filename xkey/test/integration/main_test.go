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

//go:build integration && linux

package xkey

import (
	"os"
	"testing"
)

// TestMain sets up package-level resources that must outlive individual tests,
// such as the compiled xkey binary used by the CLI integration tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "xkey-integration-bin-*")
	if err != nil {
		panic("failed to create package-level temp dir: " + err.Error())
	}
	pkgTempDir = dir

	code := m.Run()

	os.RemoveAll(pkgTempDir)
	os.Exit(code)
}
