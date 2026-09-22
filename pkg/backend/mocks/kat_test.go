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

package mocks

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Golden EncryptedData produced by the PRE-CHANGE MockSymmetricEncrypter: a
// hand-rolled 12-byte nonce passed to cipher.NewGCM's Seal, split into the
// Nonce/Ciphertext/Tag fields. Fixed bytes captured from that implementation.
const (
	legacyMockKeyHex    = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	legacyMockNonceHex  = "a0a1a2a3a4a5a6a7a8a9aaab"
	legacyMockCipherHex = "c5aa58971d563c7eb36e60f7fa69e2d20253860414"
	legacyMockTagHex    = "f12e4050dc6971773f5e33e74e4e4004"
	legacyMockPlaintext = "legacy mock plaintext"
	legacyMockAAD       = "mock-aad"
)

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestMockSymmetricEncrypter_DecryptsKnownAnswerEncryptedData keeps the mock
// honest about the format it stands in for: it must read what the real
// backends wrote before AES-GCM nonce generation moved inside the module
// boundary.
func TestMockSymmetricEncrypter_DecryptsKnownAnswerEncryptedData(t *testing.T) {
	enc, err := NewMockSymmetricEncrypter(mustHexBytes(t, legacyMockKeyHex), "")
	require.NoError(t, err)

	got, err := enc.Decrypt(&types.EncryptedData{
		Nonce:      mustHexBytes(t, legacyMockNonceHex),
		Ciphertext: mustHexBytes(t, legacyMockCipherHex),
		Tag:        mustHexBytes(t, legacyMockTagHex),
	}, &types.DecryptOptions{AdditionalData: []byte(legacyMockAAD)})
	require.NoError(t, err)
	assert.Equal(t, legacyMockPlaintext, string(got))
}
