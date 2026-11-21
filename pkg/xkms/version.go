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
// else the go-xkms module version recorded in the build info, else "unknown".
func Version() string {
	if v := strings.TrimSpace(buildVersion); v != "" {
		return v
	}
	info, _ := debug.ReadBuildInfo()
	return libraryVersion(info)
}

// modulePath is the go-xkms module path looked up in the build info.
const modulePath = "github.com/jeremyhahn/go-xkms"

// libraryVersion is the go-xkms module version recorded in info: the main
// module version when go-xkms is the main module, else the version of the
// go-xkms dependency (its replacement's when replaced). When another
// application imports go-xkms, info.Main is that application, so its version
// is never used. It returns "unknown" when no usable version is recorded.
func libraryVersion(info *debug.BuildInfo) string {
	const unknown = "unknown"
	if info == nil {
		return unknown
	}
	usable := func(v string) string {
		if v == "" || v == "(devel)" {
			return unknown
		}
		return v
	}
	if info.Main.Path == modulePath {
		return usable(info.Main.Version)
	}
	for _, dep := range info.Deps {
		if dep == nil || dep.Path != modulePath {
			continue
		}
		if dep.Replace != nil {
			return usable(dep.Replace.Version)
		}
		return usable(dep.Version)
	}
	return unknown
}
