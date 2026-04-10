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

package pkcs11

import (
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// PKCS11CertStorage is a placeholder when PKCS#11 support is not compiled in.
type PKCS11CertStorage struct{}

// New returns an error when PKCS#11 support is not compiled in.
// Build with -tags pkcs11 to enable PKCS#11 PIV certificate storage.
func New(config *pivcert.PKCS11StorageConfig) (*PKCS11CertStorage, error) {
	return nil, pivcert.NewStorageTypeError("New", pivcert.StorageTypePKCS11, pivcert.ErrPKCS11NotAvailable)
}
