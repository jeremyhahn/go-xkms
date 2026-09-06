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

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// isolateDataDirSources neutralises every source the shared data-dir
// resolver consults beyond its flag argument, so tests control exactly
// one row of the resolution truth table at a time.
func isolateDataDirSources(t *testing.T) {
	t.Helper()

	previousViper := viper.Get("data_dir")
	viper.Set("data_dir", "")
	t.Setenv("XKEY_DATA_DIR", "")
	t.Setenv(xhome.EnvHome, "")
	xhome.ResetRoot()

	t.Cleanup(func() {
		viper.Set("data_dir", previousViper)
		xhome.ResetRoot()
	})
}

// --- resolveDataDir truth table ---

func TestResolveDataDir_FlagWins(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv("XKEY_DATA_DIR", "/env/should/lose")
	viper.Set("data_dir", "/viper/should/lose")

	got, err := resolveDataDir("/flag//dir")
	require.NoError(t, err)
	assert.Equal(t, "/flag/dir", got, "flag must win and be cleaned")
}

func TestResolveDataDir_EnvBeatsViper(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv("XKEY_DATA_DIR", "/env/wins/")
	viper.Set("data_dir", "/viper/loses")

	got, err := resolveDataDir("")
	require.NoError(t, err)
	assert.Equal(t, "/env/wins", got, "env must win and be cleaned")
}

func TestResolveDataDir_ViperFallback(t *testing.T) {
	isolateDataDirSources(t)
	viper.Set("data_dir", "/viper/./dir")

	got, err := resolveDataDir("")
	require.NoError(t, err)
	assert.Equal(t, "/viper/dir", got)
}

func TestResolveDataDir_XHomeFallbackCreatesDataDir(t *testing.T) {
	isolateDataDirSources(t)
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)

	got, err := resolveDataDir("")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "data"), got,
		"the fallback must carry the data segment (issue #295)")

	info, err := os.Stat(got)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestResolveDataDir_UnresolvableHomeErrors(t *testing.T) {
	isolateDataDirSources(t)

	// XKEY_HOME nested under a regular file cannot be created.
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker-file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))
	t.Setenv(xhome.EnvHome, filepath.Join(blocker, "nested"))

	_, err := resolveDataDir("")
	require.Error(t, err)
}

// --- resolveDataDirExisting truth table ---

func TestResolveDataDirExisting_FlagWins(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv("XKEY_DATA_DIR", "/env/should/lose")
	viper.Set("data_dir", "/viper/should/lose")

	got, err := resolveDataDirExisting("/flag//dir")
	require.NoError(t, err)
	assert.Equal(t, "/flag/dir", got)
}

func TestResolveDataDirExisting_EnvBeatsViper(t *testing.T) {
	isolateDataDirSources(t)
	t.Setenv("XKEY_DATA_DIR", "/env/wins/")
	viper.Set("data_dir", "/viper/loses")

	got, err := resolveDataDirExisting("")
	require.NoError(t, err)
	assert.Equal(t, "/env/wins", got)
}

func TestResolveDataDirExisting_XHomeFallbackDoesNotCreate(t *testing.T) {
	isolateDataDirSources(t)
	root := t.TempDir()
	xhome.SetRoot(root)
	t.Cleanup(xhome.ResetRoot)

	got, err := resolveDataDirExisting("")
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(root, "data"), got)

	_, statErr := os.Stat(got)
	assert.True(t, os.IsNotExist(statErr),
		"a read-path resolution must not create the data directory")
}

func TestResolveDataDirExisting_NothingResolvableErrors(t *testing.T) {
	isolateDataDirSources(t)

	// XKEY_HOME set but absent: ResolveExisting refuses to create it.
	t.Setenv(xhome.EnvHome, filepath.Join(t.TempDir(), "missing"))

	_, err := resolveDataDirExisting("")
	require.ErrorIs(t, err, xhome.ErrHomeNotResolved)
}
