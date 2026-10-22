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

package gui

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// TestInitializeDataDir_ResolvesHomeWhenUnset verifies an App without a
// preset data directory resolves it from the xKey home.
func TestInitializeDataDir_ResolvesHomeWhenUnset(t *testing.T) {
	app := newMinimalApp(t)
	app.dataDir = ""
	t.Cleanup(xkmssdk.Reset)

	require.NoError(t, app.initializeDataDir())

	home, err := xhome.Resolve()
	require.NoError(t, err)
	assert.Equal(t, home.DataDir(), app.dataDir)
	assert.DirExists(t, app.dataDir)
}

// TestInitializeDataDir_UnusableHomeFailsTyped verifies an xKey home that
// cannot be created fails initialization with ErrDataDirInit, carrying the
// resolver's error, and opens no store.
func TestInitializeDataDir_UnusableHomeFailsTyped(t *testing.T) {
	app := newMinimalApp(t)
	app.dataDir = ""

	notADir := filepath.Join(t.TempDir(), "home-is-a-file")
	require.NoError(t, os.WriteFile(notADir, []byte("x"), 0o600))
	t.Setenv(xhome.EnvHome, notADir)

	err := app.initializeDataDir()

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrDataDirInit))
	var resolveErr *xhome.ResolveError
	assert.True(t, errors.As(err, &resolveErr), "the resolver's error must be the cause")
	assert.Empty(t, app.dataDir)
	assert.False(t, app.dataDirInit)
}
