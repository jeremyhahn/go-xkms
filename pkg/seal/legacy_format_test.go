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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Golden SealedData produced by the PRE-CHANGE SecretSealer.Seal: a hand-rolled
// 12-byte nonce passed to cipher.NewGCM's Seal, with the nonce kept in its own
// field. Fixed bytes captured from that implementation, under the data key
// HKDF-SHA256 derives from the secret below. The current code cannot regenerate
// them, which is what makes this a real compatibility check rather than a round
// trip that agrees with itself.
const (
	legacySealSecret     = "a-strong-node-protection-secret"
	legacySealNonceHex   = "a0a1a2a3a4a5a6a7a8a9aaab"
	legacySealCipherHex  = "b54a97d6f24b8915fc32591a0fa00fa5c401186461c784cc686d3346f217fe990d054f84"
	legacySealPlaintext  = "legacy sealed secret"
	legacySealBackendKey = types.BackendTypeSoftware
)

// TestSecretSealer_UnsealsLegacySealedData asserts a blob sealed before AES-GCM
// nonce generation moved inside the module boundary still unseals.
func TestSecretSealer_UnsealsLegacySealedData(t *testing.T) {
	sealer, err := NewSecretSealer([]byte(legacySealSecret))
	require.NoError(t, err)

	nonce, err := hex.DecodeString(legacySealNonceHex)
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString(legacySealCipherHex)
	require.NoError(t, err)

	got, err := sealer.Unseal(context.Background(), &types.SealedData{
		Backend:    legacySealBackendKey,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, legacySealPlaintext, string(got))
}

// TestSecretSealer_SealStillSplitsTheNonceOut asserts the other direction: a
// blob sealed now keeps the two separate fields an older build reads, with the
// nonce at its documented length rather than folded into the ciphertext.
func TestSecretSealer_SealStillSplitsTheNonceOut(t *testing.T) {
	sealer, err := NewSecretSealer([]byte(legacySealSecret))
	require.NoError(t, err)

	sealed, err := sealer.Seal(context.Background(), []byte(legacySealPlaintext), nil)
	require.NoError(t, err)

	assert.Len(t, sealed.Nonce, gcmNonceSize)
	// GCM adds only the 16-byte tag to the ciphertext; the nonce is not in it.
	assert.Len(t, sealed.Ciphertext, len(legacySealPlaintext)+16)
}
