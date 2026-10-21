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

//go:build !pkcs11

package gui

import (
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// registerPKCS11PIVStore registers no on-token PIV certificate storage when
// PKCS#11 support is not compiled in; it logs why instead.
func (a *App) registerPKCS11PIVStore(moduleID string, _ *xkms.PKCS11Connection, _, _ string) {
	a.log.Debug("PKCS#11 PIV cert storage not available", "module_id", moduleID,
		"error", xkms.NewPIVStorageTypeError("registerPKCS11PIVStore", xkms.PIVStorageTypePKCS11, xkms.ErrPIVPKCS11NotAvailable))
}
