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
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/internal/testsupport"

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
	home := testsupport.SocketDir(t)
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

func TestDefaultSocketPath_WithoutXDGRuntimeDirUsesPerUserDir(t *testing.T) {
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_UID", "")

	path := DefaultSocketPath()

	assert.True(t, filepath.IsAbs(path), "socket path must be absolute")
	assert.False(t, strings.HasPrefix(path, "/tmp/xkey-"), "must not fall back to a shared /tmp directory")
	want, err := runtimeDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(want, "xkey", "xkey.sock"), path)
}

func TestDefaultSocketPath_UnresolvableHomeReturnsEmpty(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Setenv("TMPDIR", "")
	}
	clearInstanceEnv(t)
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("HOME", "")
	t.Setenv("SUDO_UID", "")

	assert.Empty(t, DefaultSocketPath(), "no per-user location must yield no path, not a shared one")
}

// fixedHome returns a home-directory resolver that always yields dir.
func fixedHome(dir string) func() (string, error) {
	return func() (string, error) { return dir, nil }
}

// envMap returns a getenv function backed by m.
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// notSudo is the sudo resolver of a process not running as root via sudo.
func notSudo() (int, bool) { return 0, false }

// sudoAs returns the sudo resolver of a root process started by uid.
func sudoAs(uid int) func() (int, bool) {
	return func() (int, bool) { return uid, true }
}

// noFiles is an lstat for an empty file system.
func noFiles(name string) (fs.FileInfo, error) {
	return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrNotExist}
}

// fakeDir is an fs.FileInfo for a file owned by uid, carrying the
// syscall.Stat_t that fileOwner reads.
type fakeDir struct {
	name string
	mode fs.FileMode
	uid  int
}

func (d fakeDir) Name() string       { return filepath.Base(d.name) }
func (d fakeDir) Size() int64        { return 0 }
func (d fakeDir) Mode() fs.FileMode  { return d.mode }
func (d fakeDir) ModTime() time.Time { return time.Time{} }
func (d fakeDir) IsDir() bool        { return d.mode.IsDir() }
func (d fakeDir) Sys() any           { return &syscall.Stat_t{Uid: uint32(d.uid)} }

// filesystem returns an lstat backed by entries; any other path does not
// exist.
func filesystem(entries ...fakeDir) func(string) (fs.FileInfo, error) {
	return func(name string) (fs.FileInfo, error) {
		for _, e := range entries {
			if e.name == name {
				return e, nil
			}
		}
		return noFiles(name)
	}
}

func TestRuntimeDirFor(t *testing.T) {
	tests := []struct {
		name string
		goos string
		env  map[string]string
		want string
	}{
		{"linux prefers XDG_RUNTIME_DIR", "linux", map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}, "/run/user/1000"},
		{"linux falls back to ~/.xkey/run", "linux", nil, "/home/alice/.xkey/run"},
		{"linux ignores TMPDIR", "linux", map[string]string{"TMPDIR": "/tmp"}, "/home/alice/.xkey/run"},
		{"freebsd falls back to ~/.xkey/run", "freebsd", nil, "/home/alice/.xkey/run"},
		{"darwin prefers XDG_RUNTIME_DIR", "darwin", map[string]string{"XDG_RUNTIME_DIR": "/run/x", "TMPDIR": "/var/folders/ab/T/"}, "/run/x"},
		{"darwin uses per-user TMPDIR", "darwin", map[string]string{"TMPDIR": "/var/folders/ab/cd/T/"}, "/var/folders/ab/cd/T"},
		{"darwin falls back to ~/Library/Caches", "darwin", nil, "/home/alice/Library/Caches"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runtimeDirFor(tt.goos, envMap(tt.env), fixedHome("/home/alice"), notSudo, noFiles)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuntimeDirFor_SudoUsesInvokingUsersRunDir(t *testing.T) {
	// sudo stripped XDG_RUNTIME_DIR; the invoking user's session still has
	// /run/user/1000, which is where that user's clients look.
	lstat := filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeDir | 0o700, uid: 1000})

	for _, goos := range []string{"linux", "freebsd", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			got, err := runtimeDirFor(goos, envMap(nil), fixedHome("/home/alice"), sudoAs(1000), lstat)
			require.NoError(t, err)
			assert.Equal(t, "/run/user/1000", got)
		})
	}
}

func TestRuntimeDirFor_SudoKeepsFallbackWhenRunDirUnusable(t *testing.T) {
	tests := []struct {
		name  string
		lstat func(string) (fs.FileInfo, error)
	}{
		{"missing", noFiles},
		{"owned by another user", filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeDir | 0o700, uid: 1001})},
		// Root is trusted for a socket directory in general, but this one
		// must belong to the invoking user or it is not that user's session
		// directory.
		{"owned by root", filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeDir | 0o700, uid: 0})},
		{"group accessible", filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeDir | 0o750, uid: 1000})},
		{"symbolic link", filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeSymlink | 0o777, uid: 1000})},
		{"not a directory", filesystem(fakeDir{name: "/run/user/1000", mode: 0o700, uid: 1000})},
		{"stat fails", func(string) (fs.FileInfo, error) { return nil, fs.ErrPermission }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := runtimeDirFor("linux", envMap(nil), fixedHome("/home/alice"), sudoAs(1000), tt.lstat)
			require.NoError(t, err)
			assert.Equal(t, "/home/alice/.xkey/run", got)
		})
	}
}

func TestRuntimeDirFor_XDGRuntimeDirWinsOverSudo(t *testing.T) {
	lstat := filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeDir | 0o700, uid: 1000})
	env := envMap(map[string]string{"XDG_RUNTIME_DIR": "/run/user/0"})

	got, err := runtimeDirFor("linux", env, fixedHome("/home/alice"), sudoAs(1000), lstat)
	require.NoError(t, err)
	assert.Equal(t, "/run/user/0", got)
}

func TestRuntimeDirFor_NotSudoIgnoresRunUser(t *testing.T) {
	// Without sudo there is no invoking user to serve: a valid
	// /run/user/<uid> is not consulted and the home fallback stands.
	lstat := filesystem(fakeDir{name: "/run/user/1000", mode: fs.ModeDir | 0o700, uid: 1000})

	got, err := runtimeDirFor("linux", envMap(nil), fixedHome("/home/alice"), notSudo, lstat)
	require.NoError(t, err)
	assert.Equal(t, "/home/alice/.xkey/run", got)
}

func TestRuntimeDirFor_NoHomeIsRefused(t *testing.T) {
	homeErr := errors.New("no home")
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos+" error", func(t *testing.T) {
			_, err := runtimeDirFor(goos, envMap(nil), func() (string, error) { return "", homeErr }, notSudo, noFiles)
			assert.ErrorIs(t, err, ErrSocketPathUnresolved)
			assert.ErrorIs(t, err, homeErr)
		})
		t.Run(goos+" empty", func(t *testing.T) {
			_, err := runtimeDirFor(goos, envMap(nil), fixedHome(""), notSudo, noFiles)
			assert.ErrorIs(t, err, ErrSocketPathUnresolved)
		})
	}
}

func TestEffectiveHomeDir_UsesHOMEWhenNotSudo(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("unit tests must not run as root")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SUDO_UID", "4242")
	t.Setenv("SUDO_GID", "4242")

	// SUDO_UID is only honoured for a root process.
	got, err := effectiveHomeDir()
	require.NoError(t, err)
	assert.Equal(t, home, got)
}

func TestEffectiveHomeDir_NoHOMEFails(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("SUDO_UID", "")

	_, err := effectiveHomeDir()
	assert.Error(t, err)
}
