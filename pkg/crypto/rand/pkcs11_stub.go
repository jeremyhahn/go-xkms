// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !pkcs11

package rand

import "fmt"

// newPKCS11Resolver is a stub when PKCS#11 support is not compiled.
func newPKCS11Resolver(config *PKCS11Config) (Resolver, error) {
	return nil, fmt.Errorf("PKCS#11 support not compiled")
}

// pkcs11Available returns false when PKCS#11 is not available.
func pkcs11Available() bool {
	return false
}
