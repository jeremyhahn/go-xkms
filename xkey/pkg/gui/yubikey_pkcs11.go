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
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/yubikey"
)

func init() {
	wrapYubiKeyProvider = func(inner xkms.KeyProvider) xkms.KeyProvider {
		p11b, ok := inner.(*xkms.PKCS11Backend)
		if !ok {
			return nil
		}
		return yubikey.NewProvider(p11b)
	}
}
