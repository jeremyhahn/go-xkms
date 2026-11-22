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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPINFileRefusesGroupOrOtherAccess is #2325 (5): a PIN file another
// user or group can read is refused, as the pkcs11 config check refuses
// one, and the error never carries the PIN.
func TestPINFileRefusesGroupOrOtherAccess(t *testing.T) {
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		path := filepath.Join(t.TempDir(), "pin")
		require.NoError(t, os.WriteFile(path, []byte(testFollowupPIN+"\n"), 0o600))
		require.NoError(t, os.Chmod(path, mode))

		secret, err := srkUserPINSource.secretFromFile(path)
		require.ErrorIs(t, err, ErrPINInputFilePermissions, "mode %o", mode)
		assert.Nil(t, secret)
		assert.NotContains(t, err.Error(), testFollowupPIN)
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		path := filepath.Join(t.TempDir(), "pin")
		require.NoError(t, os.WriteFile(path, []byte(testFollowupPIN+"\n"), 0o600))
		require.NoError(t, os.Chmod(path, mode))

		secret, err := srkUserPINSource.secretFromFile(path)
		require.NoError(t, err, "mode %o", mode)
		assert.Equal(t, testFollowupPIN, string(secret))
	}
}

// TestPINFileFirstLineWipesWholeBuffer is #2325 (5): the parser returns
// the first line as its own copy and wipes the whole read buffer,
// including the lines after the PIN.
func TestPINFileFirstLineWipesWholeBuffer(t *testing.T) {
	data := []byte(testFollowupPIN + "\r\nsecond line\n")
	secret, err := srkUserPINSource.pinFromFileData(data)
	require.NoError(t, err)
	assert.Equal(t, testFollowupPIN, string(secret))
	assert.Equal(t, make([]byte, len(data)), data, "the whole read buffer is wiped")

	empty := []byte("\nsecond line\n")
	secret, err = srkUserPINSource.pinFromFileData(empty)
	require.ErrorIs(t, err, ErrPINInputFileEmpty)
	assert.Nil(t, secret)
	assert.True(t, bytes.Equal(make([]byte, len(empty)), empty), "the buffer is wiped on error too")
}
