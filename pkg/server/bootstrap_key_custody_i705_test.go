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
	// Pre-occupy the ".tmp" staging path with a directory so os.WriteFile
	// cannot write the staged content there.
	require.NoError(t, os.Mkdir(path+".tmp", 0700))

	err := writeHexKeyFileAtomic(path, []byte("deadbeef"))
	require.Error(t, err)
	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "a failed write must not leave a file at the final path")
}

// TestNoiseKeyCustody_NoBarrierFileWriteFails proves loadOrPersistNoiseStaticKeyFile
// wraps a write failure into *ErrFileWrite rather than returning a bare or
// swallowed error, using the same ".tmp path occupied" fault as
// TestWriteHexKeyFileAtomic_WriteFails.
func TestNoiseKeyCustody_NoBarrierFileWriteFails(t *testing.T) {
	if !noiseRunnable() {
		requireNoiseRefused(t, newMinimalServer(t, &config.Config{}))
		return
	}

	dataDir := t.TempDir()
	tmpPath := filepath.Join(dataDir, noiseStaticKeyFileName+".tmp")
	require.NoError(t, os.Mkdir(tmpPath, 0700))

	cfg := &config.Config{Storage: config.StorageConfig{Path: dataDir}}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	key, err := s.loadNoiseStaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err)
	var writeErr *ErrFileWrite
	require.ErrorAs(t, err, &writeErr)
}

// TestP256KeyCustody_NoBarrierFileWriteFails is
// TestNoiseKeyCustody_NoBarrierFileWriteFails's P-256 counterpart.
func TestP256KeyCustody_NoBarrierFileWriteFails(t *testing.T) {
	dataDir := t.TempDir()
	tmpPath := filepath.Join(dataDir, p256StaticKeyFileName+".tmp")
	require.NoError(t, os.Mkdir(tmpPath, 0700))

	cfg := &config.Config{Storage: config.StorageConfig{Path: dataDir}}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	key, err := s.loadP256StaticKey()
	if key != nil {
		key.Destroy()
	}
	require.Error(t, err)
	var writeErr *ErrFileWrite
	require.ErrorAs(t, err, &writeErr)
}
