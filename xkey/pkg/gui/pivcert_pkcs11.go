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

//go:build pkcs11

package gui

import (
	"github.com/miekg/pkcs11"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// newPKCS11PIVCertStorageFromConnection creates a PKCS#11 PIV cert storage
// that reuses the already-initialized context and session from the PKCS#11
// module manager. This avoids CKR_CRYPTOKI_ALREADY_INITIALIZED errors and
// never touches token initialization.
//
// When soPin is non-empty (e.g., YubiKey PIV management key), the storage
// uses SO session elevation for write/delete operations to avoid
// CKR_USER_TYPE_INVALID errors on tokens that reject those ops under CKU_USER.
func newPKCS11PIVCertStorageFromConnection(conn *xkms.PKCS11Connection, soPin, userPin string) (xkms.PIVCertificateStorage, error) {
	if conn == nil || conn.P11Ctx == nil {
		return nil, xkms.NewPIVStorageTypeError("newPKCS11PIVCertStorageFromConnection",
			xkms.PIVStorageTypePKCS11, xkms.ErrPIVPKCS11NotAvailable)
	}

	p11ctx, ok := conn.P11Ctx.(*pkcs11.Ctx)
	if !ok {
		return nil, xkms.NewPIVStorageTypeError("newPKCS11PIVCertStorageFromConnection",
			xkms.PIVStorageTypePKCS11, xkms.ErrPIVPKCS11NotAvailable)
	}

	if soPin != "" {
		return xkms.NewPIVPKCS11BackendFromSessionWithSO(p11ctx, pkcs11.SessionHandle(conn.SessionHandle), conn.SlotID, soPin, userPin)
	}
	return xkms.NewPIVPKCS11BackendFromSession(p11ctx, pkcs11.SessionHandle(conn.SessionHandle), conn.SlotID)
}
