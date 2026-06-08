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

package cmd

import (
	"errors"
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ErrPIVPKCS11BuildTagRequired indicates that the binary was not compiled with
// the pkcs11 build tag, which is required for PKCS#11 PIV operations.
var ErrPIVPKCS11BuildTagRequired = errors.New("piv: PKCS#11 support requires the pkcs11 build tag")

// createPKCS11PIVStorage returns an error because PKCS#11 support is not
// compiled into this binary.
func createPKCS11PIVStorage(_ *PIVConfig, _ *slog.Logger) (xkms.PIVCertificateStorage, error) {
	return nil, ErrPIVPKCS11BuildTagRequired
}

// ensurePKCS11Backend returns an error because PKCS#11 support is not
// compiled into this binary.
func ensurePKCS11Backend(_ *PIVConfig, _ *slog.Logger) error {
	return ErrPIVPKCS11BuildTagRequired
}
