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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestNewPKCS11PIVCertStorageFromConnection_NotAvailable verifies the
// non-pkcs11 build's stub fails closed with a typed error rather than
// returning a usable (nil) storage silently, when PKCS#11 support was not
// compiled in.
func TestNewPKCS11PIVCertStorageFromConnection_NotAvailable(t *testing.T) {
	storage, err := newPKCS11PIVCertStorageFromConnection(nil, "so-pin", "user-pin")
	assert.Nil(t, storage)
	require.Error(t, err)
	assert.ErrorIs(t, err, xkms.ErrPIVPKCS11NotAvailable)
}
