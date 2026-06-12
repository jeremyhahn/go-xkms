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

// newPKCS11PIVCertStorageFromConnection returns an error when PKCS#11 support is not compiled in.
func newPKCS11PIVCertStorageFromConnection(conn *xkms.PKCS11Connection, soPin, userPin string) (xkms.PIVCertificateStorage, error) {
	return nil, xkms.NewPIVStorageTypeError("newPKCS11PIVCertStorageFromConnection", xkms.PIVStorageTypePKCS11, xkms.ErrPIVPKCS11NotAvailable)
}
