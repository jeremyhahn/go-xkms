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

// Package manager is the SDK re-export of the PKCS#11 module/token manager
// (pkg/pkcs11/manager). Client binaries import this package instead of
// pkg/pkcs11/manager.
package manager

import pkgmanager "github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"

// Re-exported types.
type (
	Manager     = pkgmanager.Manager
	Option      = pkgmanager.Option
	ModuleProbe = pkgmanager.ModuleProbe
)

// Re-exported constructors and helpers.
var (
	New                   = pkgmanager.New
	ProbeModulesWithNames = pkgmanager.ProbeModulesWithNames
)
