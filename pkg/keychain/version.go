// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package keychain

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Version returns the library version string.
// The version is read from the VERSION file in the project root.
// If the VERSION file cannot be read or is empty, returns "unknown".
func Version() string {
	// Get the path to this source file
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "unknown"
	}

	// Navigate to project root (up from pkg/keychain/)
	projectRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	versionFile := filepath.Join(projectRoot, "VERSION")

	// Read the VERSION file
	// #nosec G304 - Reading fixed VERSION file from project root
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "unknown"
	}

	version := strings.TrimSpace(string(data))
	if version == "" {
		return "unknown"
	}

	return version
}
