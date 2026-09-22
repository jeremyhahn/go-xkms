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

package quantum

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden blob produced by the PRE-CHANGE encryptWithAESGCM: a hand-rolled
// 12-byte nonce passed to cipher.NewGCM's Seal, with the nonce prepended and
// the AAD authenticated. Fixed bytes captured from that implementation, which
// the current code cannot regenerate.
const (
	legacyQuantumKeyHex  = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	legacyQuantumBlobHex = "a0a1a2a3a4a5a6a7a8a9aaabc5aa58971d563c62a96c65a3ff68a3cb00468a1214b57df43a84db560ebcd767ea67d1a71c6f028e"
	legacyQuantumPayload = "legacy quantum plaintext"
	legacyQuantumAAD     = "quantum-aad"
)

// TestDecryptWithAESGCM_ReadsKnownAnswerCiphertext is a known-answer test:
// a fixed ciphertext captured from the format produced before AES-GCM nonce
// generation moved inside the module boundary still decrypts.
func TestDecryptWithAESGCM_ReadsKnownAnswerCiphertext(t *testing.T) {
	key, err := hex.DecodeString(legacyQuantumKeyHex)
	require.NoError(t, err)
	blob, err := hex.DecodeString(legacyQuantumBlobHex)
	require.NoError(t, err)

	got, err := decryptWithAESGCM(blob, key, []byte(legacyQuantumAAD))
	require.NoError(t, err)
	assert.Equal(t, legacyQuantumPayload, string(got))
}
