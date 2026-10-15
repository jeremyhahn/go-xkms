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

package authenticator

// withPrivateKey stores key on cred and returns cred, preserving the shape
// of the composite-literal tests written when PrivateKey was an exported
// []byte field. It panics on a protected-memory failure, which in a test is
// a legitimate abort.
func withPrivateKey(cred *StoredCredential, key []byte) *StoredCredential {
	if err := cred.SetPrivateKey(key); err != nil {
		panic(err)
	}
	return cred
}
