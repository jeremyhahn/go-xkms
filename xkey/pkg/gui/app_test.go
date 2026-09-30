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

package gui

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveBrowsersDir_Success verifies the happy path resolves to
// $HOME/.xkey/browsers.
func TestResolveBrowsersDir_Success(t *testing.T) {
	t.Setenv("HOME", "/home/test-user")

	dir, err := resolveBrowsersDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/home/test-user", ".xkey", "browsers"), dir)
}

// TestResolveBrowsersDir_NoHomeDirectory verifies that a user home
// directory that cannot be resolved is reported as an error instead of
// silently producing a browsers directory rooted at an empty path (which
// NewApp previously did via `home, _ := os.UserHomeDir()`).
func TestResolveBrowsersDir_NoHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")

	_, err := resolveBrowsersDir()
	assert.Error(t, err)
}

func TestParseFirmwareVersion_ValidSemver(t *testing.T) {
	result := ParseFirmwareVersion("1.2.3")
	assert.Equal(t, uint32(10203), result)
}

func TestParseFirmwareVersion_ZeroVersion(t *testing.T) {
	result := ParseFirmwareVersion("0.0.0")
	assert.Equal(t, uint32(0), result)
}

func TestParseFirmwareVersion_DevVersion(t *testing.T) {
	result := ParseFirmwareVersion("dev")
	assert.Equal(t, uint32(0), result)
}

func TestParseFirmwareVersion_PartialVersion(t *testing.T) {
	result := ParseFirmwareVersion("1.2")
	assert.Equal(t, uint32(0), result)
}
