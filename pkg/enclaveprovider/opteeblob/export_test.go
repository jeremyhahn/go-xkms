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

package opteeblob

import (
	"crypto/aes"
	"crypto/cipher"
)

// ProtectedHeader, KDFInfo and Enc0AAD expose the fixed inputs the test
// vectors publish.
var (
	ProtectedHeader = protectedHeader
	KDFInfo         = kdfInfo
	Enc0AAD         = enc0AAD
)

// SealWithNonce is Seal with a caller-chosen nonce. It exists only to
// recompute the published test vectors: Seal never takes a nonce.
func SealWithNonce(key []byte, ta TAUUID, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return encode(nonce, aead.Seal(nil, nonce, plaintext, enc0AAD(ta)))
}
