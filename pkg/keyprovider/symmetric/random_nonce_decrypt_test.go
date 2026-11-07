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
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// sealRandomNonce seals plaintext the way a FIPS 140-only process does:
// cipher.NewGCMWithRandomNonce, split into the EncryptedData fields.
func sealRandomNonce(t *testing.T, key, plaintext, aad []byte) *types.EncryptedData {
	t.Helper()
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)
	nonce, ciphertext, tag, err := aead.SplitGCMWithRandomNonce(gcm.Seal(nil, nil, plaintext, aad))
	require.NoError(t, err)
	return &types.EncryptedData{
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		Tag:          tag,
		Algorithm:    string(types.SymmetricAES256GCM),
		GCMNonceMode: types.GCMNonceModeRandom,
	}
}

// TestDecrypt_RandomNonceGCM proves a ciphertext sealed in random-nonce GCM
// framing opens with the key and AAD it was sealed under, in any process.
func TestDecrypt_RandomNonceGCM(t *testing.T) {
	enc, key := newTagSizeFixture(t, types.SymmetricAES256GCM)
	plaintext := []byte("sealed by a FIPS 140-only peer")
	aad := []byte("context")

	got, err := enc.Decrypt(sealRandomNonce(t, key, plaintext, aad), &types.DecryptOptions{AdditionalData: aad})
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestDecrypt_RandomNonceGCM_Refusals proves each malformed or forged
// random-nonce ciphertext is refused with no plaintext.
func TestDecrypt_RandomNonceGCM_Refusals(t *testing.T) {
	enc, key := newTagSizeFixture(t, types.SymmetricAES256GCM)
	aad := []byte("context")

	tests := []struct {
		name    string
		mutate  func(d *types.EncryptedData)
		opts    *types.DecryptOptions
		wantIs  error
		wantMsg string
	}{
		{
			name:   "truncated tag length requested",
			mutate: func(*types.EncryptedData) {},
			opts:   &types.DecryptOptions{AdditionalData: aad, TagSize: 12},
			wantIs: ErrInvalidTagSize,
		},
		{
			name:    "short tag",
			mutate:  func(d *types.EncryptedData) { d.Tag = d.Tag[:12] },
			opts:    &types.DecryptOptions{AdditionalData: aad},
			wantMsg: "symmetric: authentication tag is 12 bytes, want 16",
		},
		{
			name:    "short nonce",
			mutate:  func(d *types.EncryptedData) { d.Nonce = d.Nonce[:8] },
			opts:    &types.DecryptOptions{AdditionalData: aad},
			wantMsg: "symmetric: nonce is 8 bytes, want 12",
		},
		{
			name:    "tampered ciphertext",
			mutate:  func(d *types.EncryptedData) { d.Ciphertext[0] ^= 0xFF },
			opts:    &types.DecryptOptions{AdditionalData: aad},
			wantMsg: "decryption failed (authentication error)",
		},
		{
			name:    "different additional data",
			mutate:  func(*types.EncryptedData) {},
			opts:    &types.DecryptOptions{AdditionalData: []byte("other")},
			wantMsg: "decryption failed (authentication error)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := sealRandomNonce(t, key, []byte("plaintext"), aad)
			tt.mutate(data)
			got, err := enc.Decrypt(data, tt.opts)
			require.Error(t, err)
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
			assert.Nil(t, got)
		})
	}
}
