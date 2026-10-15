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

package uhid

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticatorDeviceNameValue(t *testing.T) {
	assert.Equal(t, "xKey OTP+FIDO+CCID", AuthenticatorDeviceName)
}

func TestDefaultCreateConfigUsesConstant(t *testing.T) {
	cfg := DefaultCreateConfig()
	assert.Equal(t, AuthenticatorDeviceName, cfg.Name)
}

func TestDefaultCreateConfigPhys(t *testing.T) {
	cfg := DefaultCreateConfig()
	assert.Equal(t, "xkey-authenticator", cfg.Phys)
}

func TestDefaultCreateConfigUniq(t *testing.T) {
	cfg := DefaultCreateConfig()
	assert.Equal(t, "XKEY001", cfg.Uniq)
}

func TestDefaultCreateConfigVendorProduct(t *testing.T) {
	cfg := DefaultCreateConfig()
	assert.Equal(t, VendorIDVirtualFIDO, cfg.VendorID)
	assert.Equal(t, ProductIDVirtualFIDO, cfg.ProductID)
}
