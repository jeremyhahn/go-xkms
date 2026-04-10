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

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivpkcs11 "github.com/jeremyhahn/go-xkms/pkg/pivcert/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
)

// newPKCS11PIVCertStorage creates a PKCS#11-backed PIV certificate storage.
// This stores certificates directly on the PKCS#11 token, compliant with
// NIST SP 800-73-5.
func newPKCS11PIVCertStorage(config *pivcert.PKCS11StorageConfig) (pivcert.PIVCertificateStorage, error) {
	return pivpkcs11.New(config)
}

// newPKCS11PIVCertStorageFromConnection creates a PKCS#11 PIV cert storage
// that reuses the already-initialized context and session from the PKCS#11
// module manager. This avoids CKR_CRYPTOKI_ALREADY_INITIALIZED errors and
// never touches token initialization.
func newPKCS11PIVCertStorageFromConnection(conn *manager.Connection) (pivcert.PIVCertificateStorage, error) {
	if conn == nil || conn.P11Ctx == nil {
		return nil, pivcert.NewStorageTypeError("newPKCS11PIVCertStorageFromConnection",
			pivcert.StorageTypePKCS11, pivcert.ErrPKCS11NotAvailable)
	}

	p11ctx, ok := conn.P11Ctx.(*pkcs11.Ctx)
	if !ok {
		return nil, pivcert.NewStorageTypeError("newPKCS11PIVCertStorageFromConnection",
			pivcert.StorageTypePKCS11, pivcert.ErrPKCS11NotAvailable)
	}

	return pivpkcs11.NewFromSession(p11ctx, pkcs11.SessionHandle(conn.SessionHandle), conn.SlotID)
}
