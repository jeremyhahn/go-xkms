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

package nativemsg

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// --- GenerateLauncherScript ---

func TestGenerateLauncherScript_WritesExecutableScriptPinnedToHome(t *testing.T) {
	home := &xhome.Home{Root: t.TempDir()}
	binary := filepath.Join(t.TempDir(), "xkey")
	require.NoError(t, os.WriteFile(binary, []byte("#!/bin/sh\n"), 0755))

	launcherPath, err := GenerateLauncherScript(home, binary)
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(home.Root, "run", "extension-host-launcher.sh"), launcherPath)

	info, statErr := os.Stat(launcherPath)
	require.NoError(t, statErr)
	assert.NotZero(t, info.Mode()&0100, "launcher script must be executable by its owner")

	contents, readErr := os.ReadFile(launcherPath)
	require.NoError(t, readErr)
	script := string(contents)
	assert.Contains(t, script, "export XKEY_HOME=")
	assert.Contains(t, script, home.Root)
	assert.Contains(t, script, binary)
	assert.Contains(t, script, "extension host")
}

func TestGenerateLauncherScript_NilHomeReturnsError(t *testing.T) {
	_, err := GenerateLauncherScript(nil, "/usr/local/bin/xkey")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLauncherNilHome))
}

func TestGenerateLauncherScript_OverwritesOnRepeatedCalls(t *testing.T) {
	home := &xhome.Home{Root: t.TempDir()}

	first, err := GenerateLauncherScript(home, "/usr/local/bin/xkey-old")
	require.NoError(t, err)

	second, err := GenerateLauncherScript(home, "/usr/local/bin/xkey-new")
	require.NoError(t, err)

	assert.Equal(t, first, second, "the launcher path is stable across regenerations")

	contents, readErr := os.ReadFile(second)
	require.NoError(t, readErr)
	assert.Contains(t, string(contents), "xkey-new")
	assert.NotContains(t, string(contents), "xkey-old", "a stale binary path must not survive regeneration")
}

// TestGenerateLauncherScript_ExecPinsXKEYHome actually runs the generated
// launcher (substituting a tiny script for the real xkey binary) and proves
// the process it starts sees XKEY_HOME set to this instance's home and is
// invoked with "extension host" — the acceptance property behind
// --profile-dir: a manifest that points at this launcher can only ever start
// a host bound to one instance.
func TestGenerateLauncherScript_ExecPinsXKEYHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("launcher scripts are POSIX shell, not exercised on windows")
	}

	home := &xhome.Home{Root: t.TempDir()}

	// Stand-in for the real xkey binary: report what it was invoked with.
	fakeBinary := filepath.Join(t.TempDir(), "fake-xkey")
	fakeScript := "#!/bin/sh\necho \"HOME=$XKEY_HOME ARGS=$*\"\n"
	require.NoError(t, os.WriteFile(fakeBinary, []byte(fakeScript), 0755))

	launcherPath, err := GenerateLauncherScript(home, fakeBinary)
	require.NoError(t, err)

	out, runErr := exec.Command(launcherPath).Output()
	require.NoError(t, runErr)

	assert.Contains(t, string(out), "HOME="+home.Root)
	assert.Contains(t, string(out), "ARGS=extension host")
}

// --- InstallProfileManifest ---

func TestInstallProfileManifest_WritesManifestUnderProfileDir(t *testing.T) {
	home := &xhome.Home{Root: t.TempDir()}
	profileDir := t.TempDir()
	binary := filepath.Join(t.TempDir(), "xkey")

	manifestPath, err := InstallProfileManifest(home, binary, profileDir)
	require.NoError(t, err)

	expectedPath := filepath.Join(profileDir, "NativeMessagingHosts", manifestFileName)
	assert.Equal(t, expectedPath, manifestPath)

	data, readErr := os.ReadFile(manifestPath)
	require.NoError(t, readErr)

	var m Manifest
	require.NoError(t, json.Unmarshal(data, &m))
	assert.Equal(t, NativeHostName, m.Name)
	assert.Equal(t, filepath.Join(home.Root, "run", "extension-host-launcher.sh"), m.Path)
	assert.NotEmpty(t, m.AllowedOrigins)
}

func TestInstallProfileManifest_NilHomeReturnsError(t *testing.T) {
	_, err := InstallProfileManifest(nil, "/usr/local/bin/xkey", t.TempDir())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLauncherNilHome))
}

// --- UninstallProfileManifest ---

func TestUninstallProfileManifest_RemovesInstalledManifest(t *testing.T) {
	home := &xhome.Home{Root: t.TempDir()}
	profileDir := t.TempDir()

	_, err := InstallProfileManifest(home, filepath.Join(t.TempDir(), "xkey"), profileDir)
	require.NoError(t, err)

	require.NoError(t, UninstallProfileManifest(profileDir))

	_, statErr := os.Stat(filepath.Join(profileDir, "NativeMessagingHosts", manifestFileName))
	assert.True(t, os.IsNotExist(statErr))
}

func TestUninstallProfileManifest_MissingManifestReturnsNotFound(t *testing.T) {
	err := UninstallProfileManifest(t.TempDir())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrManifestNotFound))
}

// --- Two instances, two profiles: isolation ---

func TestInstallProfileManifest_TwoInstancesGetDistinctLaunchers(t *testing.T) {
	homeA := &xhome.Home{Root: t.TempDir()}
	homeB := &xhome.Home{Root: t.TempDir()}
	profileA := t.TempDir()
	profileB := t.TempDir()
	binary := filepath.Join(t.TempDir(), "xkey")

	manifestA, err := InstallProfileManifest(homeA, binary, profileA)
	require.NoError(t, err)
	manifestB, err := InstallProfileManifest(homeB, binary, profileB)
	require.NoError(t, err)

	dataA, err := os.ReadFile(manifestA)
	require.NoError(t, err)
	dataB, err := os.ReadFile(manifestB)
	require.NoError(t, err)

	var mA, mB Manifest
	require.NoError(t, json.Unmarshal(dataA, &mA))
	require.NoError(t, json.Unmarshal(dataB, &mB))

	assert.NotEqual(t, mA.Path, mB.Path, "each profile's manifest must launch its own instance's launcher")
}
