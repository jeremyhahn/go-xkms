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
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// updateGolden rewrites the golden backup file: go test ./pkg/backup -run TestGolden -update
var updateGolden = flag.Bool("update", false, "rewrite testdata golden files")

const (
	goldenBackupFile   = "backup-v3.golden.json"
	goldenDeviceName   = "golden-device"
	goldenEntryID      = "golden-entry"
	goldenKeyFirstByte = 0x01
)

// goldenKey is the fixed raw key the golden backup is sealed under.
func goldenKey(t *testing.T) *Key {
	t.Helper()
	material := make([]byte, KeySize)
	for i := range material {
		material[i] = byte(goldenKeyFirstByte + i)
	}
	key, err := NewRawKey(material)
	require.NoError(t, err)
	return key
}

// TestGoldenBackup_Version3Decrypts pins the version 3 stored format:
// AES-256-GCM, a 12-byte nonce kept beside the ciphertext, and the
// envelope header as additional data. A change to any of them makes
// this committed file undecryptable.
func TestGoldenBackup_Version3Decrypts(t *testing.T) {
	path := filepath.Join("testdata", goldenBackupFile)
	svc, err := NewService(&Config{DeviceName: goldenDeviceName},
		WithPasswords(&mockPasswordReader{passwords: []*PasswordInfo{{
			ID:       goldenEntryID,
			Name:     "golden",
			Username: "alice",
		}}}),
	)
	require.NoError(t, err)

	if *updateGolden {
		eb, err := svc.CreateBackup(goldenKey(t))
		require.NoError(t, err)
		raw, err := json.MarshalIndent(eb, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll("testdata", 0o755))
		require.NoError(t, os.WriteFile(path, append(raw, '\n'), 0o644))
	}

	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var eb EncryptedBackup
	require.NoError(t, json.Unmarshal(raw, &eb))

	assert.Equal(t, BackupMagic, eb.Magic)
	assert.Equal(t, 3, eb.Version)
	assert.Nil(t, eb.KDF)
	assert.Len(t, eb.Nonce, gcmNonceSize)

	archive, err := svc.DecryptBackup(&eb, goldenKey(t))
	require.NoError(t, err)
	defer archive.Destroy()
	assert.Equal(t, goldenDeviceName, archive.Manifest.DeviceName)
	assert.Equal(t, BackupVersion, archive.Manifest.Version)
	require.Len(t, archive.Passwords, 1)
	assert.Equal(t, goldenEntryID, archive.Passwords[0].ID)
	assert.Equal(t, "alice", archive.Passwords[0].Username)
}

// TestGoldenBackup_TamperedNonceRefused flips one nonce byte of the golden
// file and checks the GCM tag no longer verifies.
func TestGoldenBackup_TamperedNonceRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", goldenBackupFile))
	require.NoError(t, err)
	var eb EncryptedBackup
	require.NoError(t, json.Unmarshal(raw, &eb))
	require.Len(t, eb.Nonce, gcmNonceSize)
	eb.Nonce[0] ^= 0xff

	svc, err := NewService(&Config{DeviceName: goldenDeviceName})
	require.NoError(t, err)
	archive, err := svc.DecryptBackup(&eb, goldenKey(t))
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}
