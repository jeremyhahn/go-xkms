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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// clearInstanceEnv isolates DefaultSocketPath from XKEY_IPC_SOCKET and
// XKEY_HOME so a test controls exactly which resolution strategy fires,
// regardless of what the ambient environment happens to have set.
func clearInstanceEnv(t *testing.T) {
	t.Helper()
	t.Setenv(EnvSocketPath, "")
	t.Setenv(xhome.EnvHome, "")
}

func TestDefaultSocketPath_WithXDGRuntimeDir(t *testing.T) {
	clearInstanceEnv(t)
	dir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path := DefaultSocketPath()

	expected := filepath.Join(dir, "xkey", "xkey.sock")
	assert.Equal(t, expected, path)
}

func TestDefaultSocketPath_WithoutXDGRuntimeDir(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := DefaultSocketPath()

	expected := filepath.Join("/tmp", fmt.Sprintf("xkey-%d", os.Getuid()), "xkey.sock")
	assert.Equal(t, expected, path)
}

func TestDefaultSocketPath_ReturnsAbsolutePath(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := DefaultSocketPath()
	assert.True(t, filepath.IsAbs(path), "socket path must be absolute")
}

func TestDefaultSocketPath_EndsWithSocketName(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")

	path := DefaultSocketPath()
	assert.Equal(t, "xkey.sock", filepath.Base(path))
}

func TestDefaultSocketPath_XDGContainsXkeyDir(t *testing.T) {
	clearInstanceEnv(t)
	dir := "/run/user/1000"
	t.Setenv("XDG_RUNTIME_DIR", dir)

	path := DefaultSocketPath()
	assert.Contains(t, path, "xkey")
	assert.Equal(t, filepath.Join(dir, "xkey", "xkey.sock"), path)
}

func TestDefaultSocketPath_FallbackContainsUID(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", "")

	path := DefaultSocketPath()
	uid := os.Getuid()
	assert.Contains(t, path, fmt.Sprintf("xkey-%d", uid))
}

func TestDefaultSocketPath_EnvSocketOverridesEverything(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv(EnvSocketPath, "/tmp/explicit.sock")
	t.Setenv(xhome.EnvHome, t.TempDir())
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	path := DefaultSocketPath()
	assert.Equal(t, "/tmp/explicit.sock", path)
}

func TestDefaultSocketPath_WithXKEYHomeDerivesInstanceSocket(t *testing.T) {
	clearInstanceEnv(t)
	home := t.TempDir()
	t.Setenv(xhome.EnvHome, home)
	// XDG_RUNTIME_DIR must be ignored once XKEY_HOME is the authority.
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	path := DefaultSocketPath()

	expected := filepath.Join(home, "run", "xkey.sock")
	assert.Equal(t, expected, path)
}

func TestDefaultSocketPath_TwoHomesResolveToDistinctSockets(t *testing.T) {
	clearInstanceEnv(t)
	homeA := filepath.Join(t.TempDir(), "instance-a")
	homeB := filepath.Join(t.TempDir(), "instance-b")

	t.Setenv(xhome.EnvHome, homeA)
	pathA := DefaultSocketPath()

	t.Setenv(xhome.EnvHome, homeB)
	pathB := DefaultSocketPath()

	assert.NotEqual(t, pathA, pathB, "two distinct instance homes must not share a socket")
}

func TestDefaultSocketPath_LongHomeFallsBackToHashedRuntimePath(t *testing.T) {
	clearInstanceEnv(t)
	runtimeDir := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	// A home path deep enough that <home>/run/xkey.sock would overflow
	// AF_UNIX's sun_path buffer.
	longHome := filepath.Join(t.TempDir(), strings.Repeat("a-very-long-instance-name-segment", 4))
	t.Setenv(xhome.EnvHome, longHome)

	path := DefaultSocketPath()

	assert.True(t, len(path) <= maxUnixSocketPathLen || filepath.Dir(filepath.Dir(path)) == runtimeDir,
		"long home must fall back under the runtime dir instead of a too-long direct path")
	assert.Contains(t, path, runtimeDir)
	assert.Equal(t, "xkey.sock", filepath.Base(path))
}

func TestDefaultSocketPath_LongHomesDoNotCollide(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())

	base := t.TempDir()
	longHomeA := filepath.Join(base, strings.Repeat("instance-a-long-segment", 4))
	longHomeB := filepath.Join(base, strings.Repeat("instance-b-long-segment", 4))

	t.Setenv(xhome.EnvHome, longHomeA)
	pathA := DefaultSocketPath()

	t.Setenv(xhome.EnvHome, longHomeB)
	pathB := DefaultSocketPath()

	assert.NotEqual(t, pathA, pathB)
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
