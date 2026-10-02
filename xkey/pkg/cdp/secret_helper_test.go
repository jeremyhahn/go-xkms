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

package cdp

import secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

// withPrivateKey stores key on cred and returns cred, preserving the shape
// of the composite-literal tests written when PrivateKey was an exported
// string field. It panics on a protected-memory failure, which in a test
// is a legitimate abort.
func withPrivateKey(cred StoredCredential, key string) StoredCredential {
	if err := cred.SetPrivateKey([]byte(key)); err != nil {
		panic(err)
	}
	return cred
}

// privateKeyText returns the credential's private key as a string for
// assertions, or "" when none is set. It panics on a protected-memory failure.
func privateKeyText(cred *StoredCredential) string {
	b, err := cred.PrivateKey()
	if err != nil {
		panic(err)
	}
	defer secure.Wipe(b)
	return string(b)
}
