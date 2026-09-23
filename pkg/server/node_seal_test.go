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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

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

// TestNodeSealFlip_NoneStrategyAutoUnseal verifies that an embedded-qrdb
// deployment with the barrier enabled and the explicit "none" strategy
// engages the flip unattended: the node's own barrier is adopted with no
// operator input, matching go-qrdb's own "none" auto-init-or-unseal path.
// "none" is deliberately unencrypted, so this proves adoption/auto-unseal
// plumbing, not encryption-at-rest — see
// TestNodeSealFlip_EncryptsDataPlaneAtRest for that.
func TestNodeSealFlip_NoneStrategyAutoUnseal(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:  true,
		Strategy: "none",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.True(t, server.nodeSealEnabled, "the node-seal flip should engage for qrdb + barrier + strategy none")
	require.NotNil(t, server.Barrier(), "the adopted node barrier must be non-nil")
	assert.False(t, server.Barrier().IsSealed(), "strategy none auto-unseals unattended")
}

// TestNodeSealFlip_PassphraseEngagesFlipAndBlocksForOperator verifies the
// qrdb-aligned two-phase boot (go-xkms#653 approved item 2): "passphrase"
// IS wired to the qrdb node's own barrier (BarrierConfig.NodeFlipWired), so
// the flip engages, but there is no config-sourced secret to auto-unseal
// with — go-qrdb's own node seal subsystem leaves the node sealed and
// Server.New blocks inside initializeQRDBStorage on the sealed-window
// listener (mirroring cmd/qrdbd's initSealSubsystem -> awaitUnseal) until an
// operator drives `xkmsctl barrier unseal` or the equivalent API call, or
// the configured timeout elapses. A short SealedWindowTimeout bounds this
// test to that timeout path rather than actually driving a client through
// the listener (TestServeSealedWindow_SealedNodeProceedsAfterUnseal already
// proves the unseal-completes-boot half directly against the SDK).
func TestNodeSealFlip_PassphraseEngagesFlipAndBlocksForOperator(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{
		Enabled:             true,
		Strategy:            "passphrase",
		SealedWindowTimeout: "500ms",
	}

	done := make(chan struct {
		server *Server
		err    error
	}, 1)
	go func() {
		server, err := New(cfg)
		done <- struct {
			server *Server
			err    error
		}{server, err}
	}()

	select {
	case result := <-done:
		if result.server != nil {
			defer func() { _ = result.server.Shutdown() }()
		}
		require.Error(t, result.err, "New must not complete boot without an operator unseal")
		var canceled *qrdbsdk.SealedWindowCanceledError
		assert.True(t, errors.As(result.err, &canceled),
			"error must unwrap to *qrdbsdk.SealedWindowCanceledError (timeout), got %v", result.err)
	case <-time.After(15 * time.Second):
		t.Fatal("New must return once the sealed-window timeout elapses, not hang")
	}
}

// TestNodeSealFlip_DisabledForFileStorage verifies the flip never engages for
// non-qrdb storage (no embedded node to flip to), even with the barrier
// enabled — the default, unchanged path.
func TestNodeSealFlip_DisabledForFileStorage(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := createMinimalConfig(t) // file storage
	cfg.Barrier = config.BarrierConfig{
		Enabled:  true,
		Strategy: "passphrase",
	}

	server, err := New(cfg)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown() }()

	assert.False(t, server.nodeSealEnabled, "the flip only applies to embedded qrdb storage")
	require.NotNil(t, server.Barrier(), "xkms's own barrier backs file-storage deployments")
}

// nodeSealSentinel is written to the data plane and then searched for on disk.
var nodeSealSentinel = []byte("SENTINEL_PLAINTEXT_do_not_find_me_on_disk_9f3a2b")

func writeNodeSealSentinel(t *testing.T, cfg *config.Config, sentinel []byte) string {
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

// TestNodeSealFlip_EncryptsDataPlaneAtRest is the control for the at-rest
// encryption assertion: with the barrier disabled, the sentinel is present in
// the clear, which proves the on-disk scan detects plaintext. The engaged case,
// where the sentinel must be encrypted, needs the TPM simulator and lives in
// node_seal_simulator_test.go.
func TestNodeSealFlip_EncryptsDataPlaneAtRest(t *testing.T) {
	sentinel := nodeSealSentinel

	t.Run("plaintext control when barrier disabled", func(t *testing.T) {
		cfg := qrdbBarrierConfig(t)
		cfg.Barrier = config.BarrierConfig{Enabled: false}
		dir := writeNodeSealSentinel(t, cfg, sentinel)
		assert.True(t, dirContainsBytes(t, dir, sentinel),
			"control: with the barrier disabled the data plane is plaintext on disk")
	})
}

// TestResolveNodeSeal_TPM2EmptyStoragePathFailsClosed is the regression test
// for go-xkms#609: a qrdb + barrier + tpm2 deployment with an unconfigured
// storage path (e.g. an embedded caller that never ran config.Config.Validate,
// which is what go-trusted-platform's embedded server does today) must fail
// closed with a typed error instead of resolving the TPM2 seal key directory
// relative to the process's working directory. The failure must occur before
// any TPM probe, so this test needs no TPM simulator.
func TestResolveNodeSeal_TPM2EmptyStoragePathFailsClosed(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	_, statErr := os.Stat(filepath.Join(wd, "tpm2-keys"))
	require.True(t, os.IsNotExist(statErr), "precondition: no stray tpm2-keys dir in the working directory")

	s := newMinimalServer(t, &config.Config{
		Storage: config.StorageConfig{
			Backend: "qrdb",
			Path:    "", // never configured -- must not become cwd-relative
			QRDB:    config.QRDBConfig{Transport: "embedded"},
		},
		Barrier: config.BarrierConfig{
			Enabled:  true,
			Strategy: "tpm2",
		},
	})

	sealErr := s.resolveNodeSeal()
	require.Error(t, sealErr)
	assert.False(t, s.nodeSealEnabled)

	var nodeErr *NodeSealError
	require.True(t, errors.As(sealErr, &nodeErr), "error must unwrap to *NodeSealError, got %v", sealErr)

	var cfgErr *ErrConfigRequired
	require.True(t, errors.As(sealErr, &cfgErr), "error must unwrap to *ErrConfigRequired, got %v", sealErr)
	assert.Equal(t, "storage.path", cfgErr.Field)

	_, statErr = os.Stat(filepath.Join(wd, "tpm2-keys"))
	assert.True(t, os.IsNotExist(statErr), "resolving the node seal must never create tpm2-keys under the working directory")
}
