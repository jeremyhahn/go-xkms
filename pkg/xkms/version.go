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

package xkms

import (
	"runtime/debug"
	"strings"
)

// buildVersion is the library version, set at link time by the Makefile
// LDFLAGS (-X github.com/jeremyhahn/go-xkms/pkg/xkms.buildVersion=$(VERSION)).
// Builds run with -trimpath (#2309), so the package cannot locate the
// VERSION file through its own source path.
var buildVersion string

// Version returns the library version string: the linker-set buildVersion,
// else the main module version recorded in the build info, else "unknown".
func Version() string {
	if v := strings.TrimSpace(buildVersion); v != "" {
		return v
	}
	if v := moduleVersion(); v != "" {
		return v
	}
	return "unknown"
}

// moduleVersion is the main module version from the build info, or "" when
// there is none or it is the "(devel)" placeholder of a local build.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "(devel)" {
		return ""
	}
	return info.Main.Version
}
