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

package symmetric

import (
	"crypto/fips140"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// requireEncrypt runs enc.Encrypt for a test that needs the ciphertext to
// exercise further behavior (decryption, tamper detection, and so on), and
// reports whether the caller can continue using it.
//
// Two families of calls in this package's test suite fail only under
// GODEBUG=fips140=only, both deliberately supported outside that mode:
//
//   - ChaCha20-Poly1305 and XChaCha20-Poly1305 (types.SymmetricChaCha20Poly1305,
//     types.SymmetricXChaCha20Poly1305) go through
//     golang.org/x/crypto/chacha20poly1305, which is outside the Go
//     Cryptographic Module boundary -- see pkg/crypto/chacha20poly1305's own
//     requireCipher and docs/fips/README.md.
//   - AES-GCM over an explicit, caller- or fixture-supplied nonce
//     (types.EncryptOptions.Nonce) or a truncated tag
//     (types.EncryptOptions.TagSize != 0 and != 16) requires the
//     arbitrary-IV cipher.NewGCM/NewGCMWithTagSize construction, which
//     GODEBUG=fips140=only refuses outright -- see docs/fips/README.md
//     "AEAD construction" and pkg/crypto/aead.NewGCMForFreshEncrypt, which
//     this package's default (no explicit nonce, full tag) Encrypt path
//     already routes through instead.
func requireEncrypt(t *testing.T, enc types.SymmetricEncrypter, plaintext []byte, opts *types.EncryptOptions) (*types.EncryptedData, bool) {
	t.Helper()
	encrypted, err := enc.Encrypt(plaintext, opts)
	if err != nil {
		if fips140.Enforced() {
			require.Error(t, err, "encryption must be refused under GODEBUG=fips140=only")
			return nil, false
		}
		require.NoError(t, err)
		return nil, false
	}
	return encrypted, true
}
