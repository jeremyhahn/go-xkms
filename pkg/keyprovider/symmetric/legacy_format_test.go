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
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden blob produced by the PRE-CHANGE encryptWithPassword in the
// [salt:32][nonce:12][ciphertext+tag] layout, with the salt as AAD and the key
// derived by argon2.IDKey(password, salt, 1, 64*1024, 4, 32). Fixed bytes
// captured from that implementation, which the current code cannot regenerate.
const (
	legacyPwBlobHex  = "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6fa0a1a2a3a4a5a6a7a8a9aaab8f77348b02bb5e0040fad601b8d03449f42d424aa1f8ddabeed57e408228eef09c36d25afc85ca03792f3c49c49dc79e"
	legacyPwPassword = "legacy-export-password"
	legacyPwKeyData  = "legacy exported key material 32b"
)

// TestDecryptWithPassword_ReadsLegacyExport asserts a password-encrypted key
// export written before AES-GCM nonce generation moved inside the module
// boundary still imports.
func TestDecryptWithPassword_ReadsLegacyExport(t *testing.T) {
	blob, err := hex.DecodeString(legacyPwBlobHex)
	require.NoError(t, err)

	got, err := decryptWithPassword(blob, []byte(legacyPwPassword))
	require.NoError(t, err)
	assert.Equal(t, legacyPwKeyData, string(got))
}
