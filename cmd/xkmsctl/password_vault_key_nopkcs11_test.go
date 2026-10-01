// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestKeyFactorVault_PKCS11NeedsAPKCS11Build proves the CGO-free xkmsctl
// refuses a PKCS#11 key source with a typed error instead of failing later.
func TestKeyFactorVault_PKCS11NeedsAPKCS11Build(t *testing.T) {
	setFlags(t, passwordVaultEnrollCmd, map[string]string{
		keyFactorFlag: "piv", pkcs11LibraryFlag: "/usr/lib/softhsm/libsofthsm2.so", keyPINFlag: "1234",
	})
	_, _, err := resolveVaultKeySource(passwordVaultEnrollCmd, "", vaultNewFactor)
	assert.ErrorIs(t, err, ErrVaultPKCS11Unavailable)
}
