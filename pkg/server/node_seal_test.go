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

package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// dirContainsBytes walks dir and reports whether any regular file's contents
// contain needle — used to assert that a sentinel written to the data plane is
// (or is not) present in the clear on disk.
func dirContainsBytes(t *testing.T, dir string, needle []byte) bool {
	t.Helper()
	found := false
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(data, needle) {
			found = true
		}
		return nil
	})
	require.NoError(t, err)
	return found
}

// qrdbBarrierConfig returns a minimal config that hosts the embedded qrdb node
// (Storage.Backend="qrdb") with the barrier enabled, so the node-seal flip can
// engage.
func qrdbBarrierConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := createMinimalConfig(t)
	cfg.Storage = config.StorageConfig{
		Backend: "qrdb",
		Path:    t.TempDir(),
		QRDB:    config.QRDBConfig{Transport: "embedded"},
	}
	return cfg
}

// TestNodeSealFlip_PassphraseAutoUnseal verifies that an embedded-qrdb
// deployment with the barrier enabled and a boot passphrase engages the flip:
// the node's own barrier is adopted and auto-unseals unattended, so the data
// plane (and every backend key store over it) is encrypted at rest.
func TestNodeSealFlip_PassphraseAutoUnseal(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:    true,
		Strategy:   "passphrase",
		Passphrase: "test-node-seal-boot-secret",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.True(t, server.nodeSealEnabled, "the node-seal flip should engage for qrdb + barrier + passphrase")
	require.NotNil(t, server.Barrier(), "the adopted node barrier must be non-nil")
	assert.False(t, server.Barrier().IsSealed(),
		"the node barrier must auto-unseal with the boot passphrase (unattended)")
}

// TestNodeSealFlip_NoCredsKeepsOwnBarrier verifies the gate: with the barrier
// enabled but NO boot credentials, the flip does NOT engage — xkms keeps its
// own barrier (which stays sealed until an operator unseals via the API), so
// interactive-unseal deployments behave exactly as before.
func TestNodeSealFlip_NoCredsKeepsOwnBarrier(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:  true,
		Strategy: "passphrase",
		// No passphrase: no auto-unseal creds → flip must not engage.
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.False(t, server.nodeSealEnabled, "the flip must not engage without boot credentials")
	require.NotNil(t, server.Barrier(), "xkms's own barrier is still constructed")
	assert.True(t, server.Barrier().IsSealed(),
		"xkms's own barrier is sealed until an operator unseals it (interactive)")
}

// TestNodeSealFlip_DisabledForFileStorage verifies the flip never engages for
// non-qrdb storage (no embedded node to flip to), even with the barrier
// enabled — the default, unchanged path.
func TestNodeSealFlip_DisabledForFileStorage(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t) // file storage
	cfg.Barrier = config.BarrierConfig{
		Enabled:    true,
		Strategy:   "passphrase",
		Passphrase: "irrelevant-for-file-storage",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.False(t, server.nodeSealEnabled, "the flip only applies to embedded qrdb storage")
	require.NotNil(t, server.Barrier(), "xkms's own barrier backs file-storage deployments")
}

// TestNodeSealFlip_EncryptsDataPlaneAtRest is the load-bearing security
// assertion: a value written to the data plane with the flip engaged must be
// encrypted on disk (the node's encfs wraps the PebbleDB data plane). The
// control — the same value with seal disabled — is present in the clear,
// proving the assertion methodology detects plaintext.
func TestNodeSealFlip_EncryptsDataPlaneAtRest(t *testing.T) {
	sentinel := []byte("SENTINEL_PLAINTEXT_do_not_find_me_on_disk_9f3a2b")

	writeSentinel := func(t *testing.T, cfg *config.Config) string {
		t.Helper()
		xkms.Reset()
		t.Cleanup(xkms.Reset)
		server, err := New(cfg)
		require.NoError(t, err)
		store, err := server.CreateStorage("sentinel")
		require.NoError(t, err)
		require.NoError(t, store.Put(context.Background(), "k", sentinel))
		// Shutdown flushes the node's PebbleDB (and its encfs-wrapped files) so
		// the on-disk scan sees the persisted state.
		require.NoError(t, server.Shutdown())
		return cfg.Storage.Path
	}

	t.Run("encrypted when flip engaged", func(t *testing.T) {
		cfg := qrdbBarrierConfig(t)
		cfg.Barrier = config.BarrierConfig{
			Enabled: true, Strategy: "passphrase", Passphrase: "at-rest-boot-secret",
		}
		dir := writeSentinel(t, cfg)
		assert.False(t, dirContainsBytes(t, dir, sentinel),
			"with the node-barrier flip the sentinel MUST be encrypted on disk")
	})

	t.Run("plaintext control when barrier disabled", func(t *testing.T) {
		cfg := qrdbBarrierConfig(t)
		cfg.Barrier = config.BarrierConfig{Enabled: false}
		dir := writeSentinel(t, cfg)
		assert.True(t, dirContainsBytes(t, dir, sentinel),
			"control: with the barrier disabled the data plane is plaintext on disk")
	})
}
