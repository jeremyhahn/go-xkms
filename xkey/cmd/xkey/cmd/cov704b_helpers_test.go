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
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/luks"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// useXKeyHomeFallback clears the resolved home and every LUKS path flag, so
// the volume constructors fall back to xhome.Resolve, and points XKEY_HOME
// at a fresh directory. It returns that directory.
func useXKeyHomeFallback(t *testing.T) string {
	t.Helper()
	isolateLUKSFlags(t)
	resolvedHome = nil
	sealPath, sealMountPoint = "", ""
	lockPath, lockMountPoint = "", ""
	unsealPath, unsealMountPoint = "", ""
	wipePath, wipeMountPoint = "", ""

	root := t.TempDir()
	t.Setenv(xhome.EnvHome, root)
	return root
}

// breakXKeyHome points XKEY_HOME at a regular file, so xhome.Resolve can
// neither use nor create it.
func breakXKeyHome(t *testing.T) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	t.Setenv(xhome.EnvHome, file)
}

// assertBarrierRunnerReportsUnresolvableHome checks that a barrier command
// with no data directory override fails on an unresolvable xkey home
// instead of falling back to some other directory.
func assertBarrierRunnerReportsUnresolvableHome(t *testing.T, run func(*cobra.Command, []string) error) {
	t.Helper()
	isolateBarrier(t)
	barrierDataDir = ""
	breakXKeyHome(t)
	pipeBarrier(t, "correct-horse", "correct-horse")

	out, err := runBarrierCmd(t, run)
	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
	assert.NotContains(t, out, "successfully")
}

// closeStdin replaces os.Stdin with a closed pipe, so every read from it
// fails with os.ErrClosed rather than io.EOF.
func closeStdin(t *testing.T) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, w.Close())
	require.NoError(t, r.Close())

	previous := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = previous })
}

// assertVolumeFallsBackToXKeyHome checks that a volume constructor with no
// resolved home and no path flags places the volume in the xhome defaults.
func assertVolumeFallsBackToXKeyHome(t *testing.T, create func() (*luks.Volume, error)) {
	t.Helper()
	home := &xhome.Home{Root: useXKeyHomeFallback(t)}

	vol, err := create()
	require.NoError(t, err)
	assert.Equal(t, home.LUKSPath(), vol.LUKSPath)
	assert.Equal(t, home.MountPoint(), vol.MountPoint)
}

// assertVolumeReportsUnresolvableHome checks that a volume constructor with
// no resolved home reports an xhome failure instead of guessing a path.
func assertVolumeReportsUnresolvableHome(t *testing.T, create func() (*luks.Volume, error)) {
	t.Helper()
	useXKeyHomeFallback(t)
	breakXKeyHome(t)

	vol, err := create()
	var resolveErr *xhome.ResolveError
	require.ErrorAs(t, err, &resolveErr)
	assert.Nil(t, vol)
}
