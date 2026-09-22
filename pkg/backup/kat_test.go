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

package backup

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Golden blob produced by the PRE-CHANGE encryptData: a hand-rolled 12-byte
// nonce passed to cipher.NewGCM's Seal, with the nonce prepended. Fixed bytes
// captured from that implementation, which the current code cannot regenerate
// -- a round trip through the new writer and reader would agree with itself
// even if both were wrong, and every backup ever taken would be unreadable.
const (
	legacyBackupKeyHex  = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	legacyBackupBlobHex = "a0a1a2a3a4a5a6a7a8a9aaabc5aa58971d563c71bd6e60a2fa25f3da154b8c1d04a7cec31921b3b19bd7872d42d1809ad0"
	legacyBackupPayload = "legacy backup payload"
)

// TestDecryptData_ReadsKnownAnswerBackup asserts an encrypted backup written
// before AES-GCM nonce generation moved inside the module boundary still
// restores.
func TestDecryptData_ReadsKnownAnswerBackup(t *testing.T) {
	adapter, err := NewFileBackupAdapter(t.TempDir())
	require.NoError(t, err)

	key, err := hex.DecodeString(legacyBackupKeyHex)
	require.NoError(t, err)
	blob, err := hex.DecodeString(legacyBackupBlobHex)
	require.NoError(t, err)

	got, err := adapter.decryptData(blob, key)
	require.NoError(t, err)
	assert.Equal(t, legacyBackupPayload, string(got))
}
