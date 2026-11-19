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
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/seal"
	"github.com/jeremyhahn/go-qrdb/pkg/seal/encfs"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
)

// Issue #2290: after a reboot of an embedded node (passphrase barrier, local
// pebble behind encfs) the unseal succeeded and boot completion failed with
// "pebble: error when replaying WAL: encfs: block authentication failed".
// These tests drive the same path on real storage: a sealed boot, an unseal
// through the barrier service (which rotates the AEAD epoch), boot
// completion, writes, and an unclean stop (the data directory is copied
// while the node is still open, as a SIGKILL or power cut leaves it).

const walRebootPassphrase = "correct-horse-battery-staple"

func walRebootConfig(dataDir string) *qrdbsdk.DaemonConfig {
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = dataDir
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "pebble"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = true
	cfg.Seal.Strategy = "passphrase"
	return cfg
}

// walRebootFirstBoot initialises the barrier and storage in dataDir and
// returns the open, unsealed node.
func walRebootFirstBoot(t *testing.T, dataDir string) *qrdbnode.Node {
	t.Helper()
	node, err := qrdbnode.NewStandaloneNode(context.Background(), walRebootConfig(dataDir), nil,
		qrdbnode.WithLogger(slog.Default()),
		qrdbnode.WithSealPassphrase([]byte(walRebootPassphrase)),
		serviceprincipal.Option())
	require.NoError(t, err)
	require.False(t, node.IsSealed(), "first boot must auto-unseal")
	return node
}

// walRebootUnsealBoot boots dataDir sealed, unseals it the way the sealed
// window does (BarrierUnseal, then node.Unseal to complete the boot) and
// returns the node and the boot-completion error.
func walRebootUnsealBoot(t *testing.T, dataDir string) (*qrdbnode.Node, error) {
	t.Helper()
	ctx := context.Background()
	node, err := qrdbnode.NewStandaloneNode(ctx, walRebootConfig(dataDir), nil,
		qrdbnode.WithLogger(slog.Default()),
		serviceprincipal.Option())
	require.NoError(t, err)
	require.True(t, node.IsSealed(), "a reboot without a passphrase must come up sealed")
	svc := node.Services()
	require.NotNil(t, svc)
	require.NotNil(t, svc.Barrier)
	require.NoError(t, svc.Barrier.BarrierUnseal(ctx, []byte(walRebootPassphrase)))
	return node, node.Unseal(ctx, seal.Credentials{})
}

func walRebootBackend(node *qrdbnode.Node) *qrdbstorage.Backend {
	s := &Server{qrdbNode: node}
	return qrdbstorage.NewBackend(node.Client().KV(), s.storageCallContext()...)
}

func walRebootPut(t *testing.T, node *qrdbnode.Node, run, n int) {
	t.Helper()
	b := walRebootBackend(node)
	for i := 0; i < n; i++ {
		k, v := walRebootRecord(run, i)
		require.NoError(t, b.Put(context.Background(), k, v))
	}
}

func walRebootRecord(run, i int) (string, []byte) {
	return fmt.Sprintf("xkms/wal2290/r%d/k%04d", run, i),
		[]byte(fmt.Sprintf("run-%d-record-%d-%0200d", run, i, i))
}

func walRebootCheck(t *testing.T, node *qrdbnode.Node, runs, n int) {
	t.Helper()
	b := walRebootBackend(node)
	for run := 0; run < runs; run++ {
		for i := 0; i < n; i++ {
			k, want := walRebootRecord(run, i)
			got, err := b.Get(context.Background(), k)
			require.NoError(t, err, "record %s", k)
			require.Equal(t, want, got, "record %s", k)
		}
	}
}

// walRebootCrashCopy copies src to a fresh directory while the node that
// owns src is still open: the copy is the state an unclean stop leaves.
func walRebootCrashCopy(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	require.NoError(t, filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(target, fi.Mode().Perm()|0o700)
		}
		if !fi.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fi.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close()
			return err
		}
		return out.Close()
	}))
	return dst
}

const walRebootRecords = 64

// (1) Unclean stop after synced writes, then a sealed reboot and unseal.
func TestWALReboot_UncleanStopReopensIntact(t *testing.T) {
	dir := t.TempDir()
	node := walRebootFirstBoot(t, dir)
	walRebootPut(t, node, 0, walRebootRecords)
	crashed := walRebootCrashCopy(t, dir)
	require.NoError(t, node.Close())

	node, err := walRebootUnsealBoot(t, crashed)
	t.Cleanup(func() { _ = node.Close() })
	require.NoError(t, err, "boot completion after unseal")
	walRebootCheck(t, node, 1, walRebootRecords)
}

// (2) The board's sequence: several reboots, each unseal rotating the
// barrier AEAD epoch, writes between them, unclean stops throughout.
func TestWALReboot_EpochRotationAcrossUncleanRestarts(t *testing.T) {
	dir := t.TempDir()
	node := walRebootFirstBoot(t, dir)
	walRebootPut(t, node, 0, walRebootRecords)
	dir = walRebootCrashCopy(t, dir)
	require.NoError(t, node.Close())

	const runs = 4
	for run := 1; run < runs; run++ {
		var err error
		node, err = walRebootUnsealBoot(t, dir)
		require.NoError(t, err, "boot completion after unseal, restart %d", run)
		walRebootCheck(t, node, run, walRebootRecords)
		walRebootPut(t, node, run, walRebootRecords)
		dir = walRebootCrashCopy(t, dir)
		require.NoError(t, node.Close())
	}

	node, err := walRebootUnsealBoot(t, dir)
	t.Cleanup(func() { _ = node.Close() })
	require.NoError(t, err, "boot completion after unseal, final restart")
	walRebootCheck(t, node, runs, walRebootRecords)
}

// (2b) The same with clean stops between the epoch rotations and an
// unclean stop only at the end: the WAL replayed fine after its last write
// and only failed on a later boot.
func TestWALReboot_CleanRestartsThenUncleanStop(t *testing.T) {
	dir := t.TempDir()
	node := walRebootFirstBoot(t, dir)
	walRebootPut(t, node, 0, walRebootRecords)
	require.NoError(t, node.Close())

	const runs = 4
	for run := 1; run < runs; run++ {
		var err error
		node, err = walRebootUnsealBoot(t, dir)
		require.NoError(t, err, "boot completion after unseal, restart %d", run)
		walRebootCheck(t, node, run, walRebootRecords)
		if run < runs-1 {
			walRebootPut(t, node, run, walRebootRecords)
			require.NoError(t, node.Close())
		}
	}
	// Last run: no new writes (the board's WAL was idle for an hour), then
	// an unclean stop and two more reboots.
	dir = walRebootCrashCopy(t, dir)
	require.NoError(t, node.Close())
	for i := 0; i < 2; i++ {
		var err error
		node, err = walRebootUnsealBoot(t, dir)
		require.NoError(t, err, "boot completion after unseal, idle restart %d", i)
		walRebootCheck(t, node, runs-1, walRebootRecords)
		dir = walRebootCrashCopy(t, dir)
		require.NoError(t, node.Close())
	}
}

// walRebootDamageWAL changes the length of the main store's newest WAL by
// delta bytes: a negative delta tears the tail (the trailing encfs block
// loses bytes), a positive one zero-extends it, both of which an unclean
// power cut can leave behind.
func walRebootDamageWAL(t *testing.T, dataDir string, delta int64) {
	t.Helper()
	logs, err := filepath.Glob(filepath.Join(dataDir, "pebble", "*.log"))
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	w := logs[len(logs)-1]
	fi, err := os.Stat(w)
	require.NoError(t, err)
	require.NoError(t, os.Truncate(w, fi.Size()+delta))
}

// (2c) A torn or zero-extended WAL tail must not make the store
// unopenable: pebble tolerates a torn tail of its own WAL, and only the
// last unsynced record may be lost. On the board this is the exact error.
func TestWALReboot_DamagedTailReplays(t *testing.T) {
	for _, delta := range []int64{-1, -100, 1, 4096} {
		t.Run(fmt.Sprintf("delta=%d", delta), func(t *testing.T) {
			dir := t.TempDir()
			node := walRebootFirstBoot(t, dir)
			walRebootPut(t, node, 0, walRebootRecords)
			require.NoError(t, node.Close())
			walRebootDamageWAL(t, dir, delta)

			node, err := walRebootUnsealBoot(t, dir)
			t.Cleanup(func() { _ = node.Close() })
			require.NoError(t, err, "boot completion after unseal with a damaged WAL tail")
			walRebootCheck(t, node, 1, walRebootRecords-1)
		})
	}
}

// (3) A boot-completion failure after the unseal is reported precisely:
// the sealed window returns a QRDBNodeError naming the stage, and the
// encfs cause stays reachable with errors.Is.
func TestWALReboot_BootCompletionFailureIsPrecise(t *testing.T) {
	dir := t.TempDir()
	node := walRebootFirstBoot(t, dir)
	walRebootPut(t, node, 0, walRebootRecords)
	require.NoError(t, node.Close())
	walRebootDamageWAL(t, dir, -1)

	node, err := qrdbnode.NewStandaloneNode(context.Background(), walRebootConfig(dir), nil,
		qrdbnode.WithLogger(slog.Default()), serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	require.True(t, node.IsSealed())

	s := testSealedWindowServer(t, createMinimalConfig(t))
	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()
	require.NoError(t, node.Services().Barrier.BarrierUnseal(context.Background(), []byte(walRebootPassphrase)))

	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveSealedWindow did not return after the barrier was unsealed")
	}
	if err == nil {
		return // the damaged tail replayed: nothing to report
	}
	var nodeErr *QRDBNodeError
	require.ErrorAs(t, err, &nodeErr)
	require.Equal(t, "complete boot after sealed window", nodeErr.Stage)
	require.ErrorIs(t, err, encfs.ErrAuthFailed)
}
