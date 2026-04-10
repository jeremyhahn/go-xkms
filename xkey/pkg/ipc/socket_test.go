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

package ipc

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultSocketPath_WithXDGRuntimeDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path := DefaultSocketPath()

	expected := filepath.Join(dir, "xkey", "xkey.sock")
	assert.Equal(t, expected, path)
}

func TestDefaultSocketPath_WithoutXDGRuntimeDir(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := DefaultSocketPath()

	expected := filepath.Join("/tmp", fmt.Sprintf("xkey-%d", os.Getuid()), "xkey.sock")
	assert.Equal(t, expected, path)
}

func TestDefaultSocketPath_ReturnsAbsolutePath(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := DefaultSocketPath()
	assert.True(t, filepath.IsAbs(path), "socket path must be absolute")
}

func TestDefaultSocketPath_EndsWithSocketName(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	path := DefaultSocketPath()
	assert.Equal(t, "xkey.sock", filepath.Base(path))
}

func TestDefaultSocketPath_XDGContainsXkeyDir(t *testing.T) {
	dir := "/run/user/1000"
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path := DefaultSocketPath()
	assert.Contains(t, path, "xkey")
	assert.Equal(t, filepath.Join(dir, "xkey", "xkey.sock"), path)
}

func TestDefaultSocketPath_FallbackContainsUID(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := DefaultSocketPath()
	uid := os.Getuid()
	assert.Contains(t, path, fmt.Sprintf("xkey-%d", uid))
}

func TestEffectiveUID_ReturnsCurrentUID_WhenNotRoot(t *testing.T) {
	// When not running as root, effectiveUID should return os.Getuid()
	// regardless of SUDO_UID being set
	t.Setenv("SUDO_UID", "1000")

	uid := effectiveUID()

	// Unless running as root (uid 0), SUDO_UID is ignored
	if os.Getuid() != 0 {
		assert.Equal(t, os.Getuid(), uid)
	}
}

func TestEffectiveUID_IgnoresInvalidSUDO_UID(t *testing.T) {
	t.Setenv("SUDO_UID", "not-a-number")

	uid := effectiveUID()

	// Invalid SUDO_UID should be ignored, return actual UID
	assert.Equal(t, os.Getuid(), uid)
}

func TestEffectiveUID_IgnoresEmptySUDO_UID(t *testing.T) {
	t.Setenv("SUDO_UID", "")

	uid := effectiveUID()

	assert.Equal(t, os.Getuid(), uid)
}
