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

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// TestWriteHexKeyFileAtomic_MkdirFails proves a parent directory that cannot
// be created (here, because a path component is already a plain file) is
// reported as an error rather than panicking or silently dropping the key.
func TestWriteHexKeyFileAtomic_MkdirFails(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	// blocker is a file, so MkdirAll(filepath.Dir(path)) — which must create
	// blocker/child — fails with ENOTDIR.
	path := filepath.Join(blocker, "child", "key.hex")

	err := writeHexKeyFileAtomic(path, []byte("deadbeef"))
	require.Error(t, err)
}

// TestWriteHexKeyFileAtomic_WriteFails proves a write failure at the
// temp-file stage (here, because the temp path is already a directory) is
// reported as an error, and that no file is left at the final path since the
// atomic rename never runs.
func TestWriteHexKeyFileAtomic_WriteFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.hex")
	// Pre-occupy the final path with a directory so the key cannot replace it.
	require.NoError(t, os.Mkdir(path, 0700))

	err := writeHexKeyFileAtomic(path, []byte("deadbeef"))
	require.Error(t, err)
	info, statErr := os.Stat(path)
	require.NoError(t, statErr)
	require.True(t, info.IsDir(), "a failed write must leave the final path untouched")
}

// plantDanglingSymlink makes path a symlink to a file that does not exist.
// Reading the key through it reports "not exist", so the custody code takes
// the generate-and-persist branch, and the atomic writer then refuses to
// write a secret through a symlink. Unlike a read-only directory, this fault
// holds for root, which CI runs as.
func plantDanglingSymlink(t *testing.T, path string) {
	t.Helper()
	target := filepath.Join(t.TempDir(), "missing")
	require.NoError(t, os.Symlink(target, path))
}

// TestNoiseKeyCustody_NoBarrierFileWriteFails proves loadOrPersistNoiseStaticKeyFile
// wraps a write failure into *ErrFileWrite rather than returning a bare or
// swallowed error.
func TestNoiseKeyCustody_NoBarrierFileWriteFails(t *testing.T) {
	if !noiseRunnable() {
		requireNoiseRefused(t, newMinimalServer(t, &config.Config{}))
		return
	}

	dataDir := t.TempDir()
	plantDanglingSymlink(t, filepath.Join(dataDir, noiseStaticKeyFileName))

	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: dataDir}}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	key, err := s.loadNoiseStaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err)
	var writeErr *ErrFileWrite
	require.ErrorAs(t, err, &writeErr)
	require.ErrorIs(t, err, fsutil.ErrSymlinkTarget)
}

// TestP256KeyCustody_NoBarrierFileWriteFails is
// TestNoiseKeyCustody_NoBarrierFileWriteFails's P-256 counterpart.
func TestP256KeyCustody_NoBarrierFileWriteFails(t *testing.T) {
	dataDir := t.TempDir()
	plantDanglingSymlink(t, filepath.Join(dataDir, p256StaticKeyFileName))

	cfg := &config.Config{Datastore: config.DatastoreConfig{Path: dataDir}}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	key, err := s.loadP256StaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err)
	var writeErr *ErrFileWrite
	require.ErrorAs(t, err, &writeErr)
	require.ErrorIs(t, err, fsutil.ErrSymlinkTarget)
}
