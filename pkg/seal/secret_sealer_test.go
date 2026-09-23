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

package seal

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretSealer_RoundTrip(t *testing.T) {
	sealer, err := NewSecretSealer([]byte("a-strong-node-protection-secret"))
	require.NoError(t, err)
	require.True(t, sealer.CanSeal())

	plaintext := []byte("PKCS#8 private key bytes")
	sealed, err := sealer.Seal(context.Background(), plaintext, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sealed.Ciphertext)
	require.NotEmpty(t, sealed.Nonce)
	// Ciphertext must not contain the plaintext.
	assert.NotContains(t, string(sealed.Ciphertext), string(plaintext))

	got, err := sealer.Unseal(context.Background(), sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

func TestSecretSealer_EmptySecretRejected(t *testing.T) {
	_, err := NewSecretSealer(nil)
	require.ErrorIs(t, err, ErrSecretSealerEmptySecret)
	_, err = NewSecretSealer([]byte{})
	require.ErrorIs(t, err, ErrSecretSealerEmptySecret)
}

func TestSecretSealer_WrongSecretFailsToUnseal(t *testing.T) {
	// 24+ bytes: crypto/hkdf refuses any HKDF input keying material under
	// 112 bits (14 bytes) under GODEBUG=fips140=only.
	a, err := NewSecretSealer([]byte("node-protection-secret-a"))
	require.NoError(t, err)
	b, err := NewSecretSealer([]byte("node-protection-secret-b"))
	require.NoError(t, err)

	sealed, err := a.Seal(context.Background(), []byte("data"), nil)
	require.NoError(t, err)

	_, err = b.Unseal(context.Background(), sealed, nil)
	require.Error(t, err) // GCM auth tag mismatch under a different derived key
}

func TestSecretSealer_DeterministicKeyDerivation(t *testing.T) {
	// The same secret always derives the same data key, so a restart can
	// unseal what a prior boot sealed. 16+ bytes: see
	// TestSecretSealer_WrongSecretFailsToUnseal for the HKDF floor.
	a, err := NewSecretSealer([]byte("a-stable-node-secret"))
	require.NoError(t, err)
	sealed, err := a.Seal(context.Background(), []byte("persisted"), nil)
	require.NoError(t, err)

	b, err := NewSecretSealer([]byte("a-stable-node-secret"))
	require.NoError(t, err)
	got, err := b.Unseal(context.Background(), sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("persisted"), got)
}

// TestSecretSealer_Unseal_WrongNonceLength verifies that Unseal returns an
// error instead of panicking when the sealed data carries a nonce that is
// not exactly the GCM nonce size. crypto/cipher.AEAD.Open panics on a
// mismatched nonce length, so a corrupted or tampered sealed blob must be
// rejected before it reaches Open.
func TestSecretSealer_Unseal_WrongNonceLength(t *testing.T) {
	sealer, err := NewSecretSealer([]byte("a-strong-node-protection-secret"))
	require.NoError(t, err)

	sealed, err := sealer.Seal(context.Background(), []byte("data"), nil)
	require.NoError(t, err)

	tests := []struct {
		name      string
		nonceSize int
	}{
		{name: "16-byte AES-CBC-style IV", nonceSize: 16},
		{name: "empty nonce", nonceSize: 0},
		{name: "single byte nonce", nonceSize: 1},
		{name: "oversized nonce", nonceSize: 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tampered := *sealed
			tampered.Nonce = make([]byte, tt.nonceSize)
			_, err := sealer.Unseal(context.Background(), &tampered, nil)
			require.Error(t, err, "unseal should reject a wrong-length nonce, not panic")
		})
	}
}

// TestSecretSealer_Unseal_NilSealedData verifies that Unseal rejects nil
// SealedData with an error instead of a nil-pointer panic.
func TestSecretSealer_Unseal_NilSealedData(t *testing.T) {
	sealer, err := NewSecretSealer([]byte("a-strong-node-protection-secret"))
	require.NoError(t, err)

	_, err = sealer.Unseal(context.Background(), nil, nil)
	require.Error(t, err)
}
