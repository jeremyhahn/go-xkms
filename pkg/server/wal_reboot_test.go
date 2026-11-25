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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/seal"
	"github.com/jeremyhahn/go-qrdb/pkg/seal/encfs"
	qrdbpebble "github.com/jeremyhahn/go-qrdb/pkg/storage/pebble"
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

// walRebootStoreBytes is the size on disk of the main store's WAL and
// sstables: what a crash copy of dataDir would carry.
func walRebootStoreBytes(t *testing.T, dataDir string) int64 {
	t.Helper()
	var total int64
	for _, pattern := range []string{"*.log", "*.sst"} {
		files, err := filepath.Glob(filepath.Join(dataDir, "pebble", pattern))
		require.NoError(t, err)
		for _, f := range files {
			fi, err := os.Stat(f)
			require.NoError(t, err)
			total += fi.Size()
		}
	}
	return total
}

// walRebootSyncedPut writes n records of run and makes them durable before
// any crash copy is taken. qrdb v0.51.0-alpha exposes no WAL sync on the
// embedded node (its standalone pebble opens with SyncWrites=false and no
// write mode syncs the WAL), so the durability boundary is a clean Close,
// which syncs the WAL. The boundary is verified on disk: the store's bytes
// grew past what they were before the writes. The node is then rebooted
// sealed and unsealed (rotating the epoch) and returned running, so a crash
// copy taken from it stops a process whose records are all synced.
func walRebootSyncedPut(t *testing.T, node *qrdbnode.Node, dataDir string, run, n int) *qrdbnode.Node {
	t.Helper()
	before := walRebootStoreBytes(t, dataDir)
	walRebootPut(t, node, run, n)
	require.NoError(t, node.Close())
	require.Greater(t, walRebootStoreBytes(t, dataDir), before,
		"run %d: the records must be on disk before the crash copy", run)
	node, err := walRebootUnsealBoot(t, dataDir)
	require.NoError(t, err, "run %d: boot completion after the synced close", run)
	return node
}

const walRebootRecords = 64

// (1) Unclean stop after synced writes, then a sealed reboot and unseal.
func TestWALReboot_UncleanStopReopensIntact(t *testing.T) {
	dir := t.TempDir()
	node := walRebootFirstBoot(t, dir)
	node = walRebootSyncedPut(t, node, dir, 0, walRebootRecords)
	crashed := walRebootCrashCopy(t, dir)
	require.NoError(t, node.Close())

	node, err := walRebootUnsealBoot(t, crashed)
	t.Cleanup(func() { _ = node.Close() })
	require.NoError(t, err, "boot completion after unseal")
	walRebootCheck(t, node, 1, walRebootRecords)
}

// (1b) Acknowledged but unsynced writes: every Put returned nil, then the
// process stops uncleanly with no sync. The node's KV Put returns before
// pebble syncs the WAL (encfs holds the tail in memory), so these records
// are lost today; this is a separate reproduction from (1), which covers
// records past a durability boundary.
func TestWALReboot_UnsyncedAcknowledgedWritesSurviveUncleanStop(t *testing.T) {
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
	node = walRebootSyncedPut(t, node, dir, 0, walRebootRecords)
	dir = walRebootCrashCopy(t, dir)
	require.NoError(t, node.Close())

	const runs = 4
	for run := 1; run < runs; run++ {
		var err error
		node, err = walRebootUnsealBoot(t, dir)
		require.NoError(t, err, "boot completion after unseal, restart %d", run)
		walRebootCheck(t, node, run, walRebootRecords)
		node = walRebootSyncedPut(t, node, dir, run, walRebootRecords)
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
// unopenable: a durable prefix (run 0, synced by a clean Close and a
// reboot, then read back) is followed by an unsynced tail (run 1) whose full
// encfs blocks reach disk, the crash copy's newest WAL is damaged, and the
// replay must boot with all of run 0 and a gap-free prefix of run 1. encfs
// authenticates up to 4096 plaintext bytes per block, so a damaged trailing
// block may drop several tail records. On the board this is the exact error.
func TestWALReboot_DamagedTailReplays(t *testing.T) {
	for _, delta := range []int64{-1, -100, 1, 4096} {
		t.Run(fmt.Sprintf("delta=%d", delta), func(t *testing.T) {
			dir := t.TempDir()
			node := walRebootFirstBoot(t, dir)
			node = walRebootSyncedPut(t, node, dir, 0, walRebootRecords)
			// The durable prefix is the records read back after the synced reboot.
			walRebootCheck(t, node, 1, walRebootRecords)

			walRebootPut(t, node, 1, walRebootTailRecords)
			crashed := walRebootCrashCopy(t, dir)
			require.NoError(t, node.Close())
			require.Greater(t, walRebootNewestWALSize(t, crashed), int64(133+2*4124),
				"the crash copy's WAL must hold encfs blocks for the damage to land in")
			walRebootDamageWAL(t, crashed, delta)

			node, err := walRebootUnsealBoot(t, crashed)
			t.Cleanup(func() { _ = node.Close() })
			require.NoError(t, err, "boot completion after unseal with a damaged WAL tail")
			walRebootCheck(t, node, 1, walRebootRecords)
			walRebootSurvivingPrefix(t, node, 1, walRebootTailRecords)
		})
	}
}

// walRebootTailRecords spans several 32 KiB pebble log blocks, so full encfs
// blocks of the unsynced tail reach disk before the crash copy.
const walRebootTailRecords = 512

// walRebootNewestWALSize is the on-disk size of the main store's newest WAL.
func walRebootNewestWALSize(t *testing.T, dataDir string) int64 {
	t.Helper()
	logs, err := filepath.Glob(filepath.Join(dataDir, "pebble", "*.log"))
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	fi, err := os.Stat(logs[len(logs)-1])
	require.NoError(t, err)
	return fi.Size()
}

// walRebootSurvivingPrefix requires the records of run that replayed to be a
// prefix of the written order with the written values, and returns its length.
func walRebootSurvivingPrefix(t *testing.T, node *qrdbnode.Node, run, n int) int {
	t.Helper()
	b := walRebootBackend(node)
	survived, lost := 0, false
	for i := 0; i < n; i++ {
		k, want := walRebootRecord(run, i)
		got, err := b.Get(context.Background(), k)
		if err != nil {
			lost = true
			continue
		}
		require.False(t, lost, "record %s replayed after an earlier record was lost", k)
		require.Equal(t, want, got, "record %s", k)
		survived++
	}
	return survived
}

// walRebootTestKEK wraps encfs file keys with AES-256-GCM under a random key.
type walRebootTestKEK struct{ aead cipher.AEAD }

func newWALRebootTestKEK(t *testing.T) walRebootTestKEK {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	aead, err := cipher.NewGCM(block)
	require.NoError(t, err)
	return walRebootTestKEK{aead: aead}
}

func (k walRebootTestKEK) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (k walRebootTestKEK) Decrypt(ciphertext []byte) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("wrapped key too short")
	}
	return k.aead.Open(nil, ciphertext[:n], ciphertext[n:], nil)
}

func walRebootOpenEncryptedStore(t *testing.T, dir string, kek walRebootTestKEK) (*qrdbpebble.PebbleStorage, error) {
	t.Helper()
	cfg := qrdbpebble.TestConfig(dir)
	cfg.SyncWrites = true
	cfg.FS = encfs.New(nil, kek)
	return qrdbpebble.New(cfg)
}

func walRebootReadWAL(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	logs, err := filepath.Glob(filepath.Join(dir, "*.log"))
	require.NoError(t, err)
	require.Len(t, logs, 1)
	b, err := os.ReadFile(logs[0])
	require.NoError(t, err)
	return logs[0], b
}

// (2d) A synced write leaves a partial encfs block on disk; the next synced
// write rewrites that same block in place with a fresh nonce. A power cut
// that persists only part of the rewrite must not lose the records the first
// Sync made durable.
func TestWALReboot_SyncedPrefixSurvivesTornPartialBlockOverwrite(t *testing.T) {
	dir := t.TempDir()
	kek := newWALRebootTestKEK(t)
	store, err := walRebootOpenEncryptedStore(t, dir, kek)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	const synced, more = 4, 4
	for i := 0; i < synced; i++ {
		k, v := walRebootRecord(0, i)
		require.NoError(t, store.Set([]byte(k), v))
	}
	_, first := walRebootReadWAL(t, dir)
	for i := synced; i < synced+more; i++ {
		k, v := walRebootRecord(0, i)
		require.NoError(t, store.Set([]byte(k), v))
	}
	walPath, second := walRebootReadWAL(t, dir)
	require.Greater(t, len(second), len(first), "the second Sync must extend the WAL")
	require.Less(t, len(second)-len(first), 4096, "both Syncs must land in the same partial block")

	crashed := walRebootCrashCopy(t, dir)
	require.NoError(t, store.Close())
	// The rewrite reached disk up to split; the rest of the block is still the first Sync's.
	split := len(first) - 100
	torn := append(append([]byte(nil), second[:split]...), first[split:]...)
	require.NoError(t, os.WriteFile(filepath.Join(crashed, filepath.Base(walPath)), torn, 0o600))

	reopened, err := walRebootOpenEncryptedStore(t, crashed, kek)
	require.NoError(t, err, "replay after a torn overwrite of the synced partial block")
	t.Cleanup(func() { _ = reopened.Close() })
	for i := 0; i < synced; i++ {
		k, want := walRebootRecord(0, i)
		got, err := reopened.Get([]byte(k))
		require.NoError(t, err, "synced record %s", k)
		require.Equal(t, want, got, "synced record %s", k)
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
	walRebootCorruptInteriorWALBlock(t, dir)

	node, err := qrdbnode.NewStandaloneNode(context.Background(), walRebootConfig(dir), nil,
		qrdbnode.WithLogger(slog.Default()), serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { _ = node.Close() })
	require.True(t, node.IsSealed())

	// Unseal only once serveSealedWindow has passed its IsSealed check and
	// is opening the window: unsealing earlier makes it return nil at once
	// without ever completing the boot.
	s := testSealedWindowServer(t, createMinimalConfig(t))
	entered := make(chan struct{})
	s.logger = slog.New(&walRebootSignalHandler{
		Handler: slog.Default().Handler(),
		match:   "opening the sealed-window listener",
		signal:  func() { close(entered) },
		once:    &sync.Once{},
	})
	done := make(chan error, 1)
	go func() { done <- s.serveSealedWindow(node) }()
	select {
	case <-entered:
	case err = <-done:
		t.Fatalf("serveSealedWindow returned %v before opening the sealed window", err)
	case <-time.After(10 * time.Second):
		t.Fatal("serveSealedWindow did not open the sealed window")
	}
	require.NoError(t, node.Services().Barrier.BarrierUnseal(context.Background(), []byte(walRebootPassphrase)))

	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serveSealedWindow did not return after the barrier was unsealed")
	}
	require.Error(t, err, "a corrupt interior WAL block must fail boot completion")
	var nodeErr *QRDBNodeError
	require.ErrorAs(t, err, &nodeErr)
	require.Equal(t, node.IsSealed(), nodeErr.Resealed)
	require.Equal(t, "complete boot after sealed window", nodeErr.Stage)
	require.ErrorIs(t, err, encfs.ErrAuthFailed)
}

// walRebootCorruptInteriorWALBlock flips one byte in the middle of the main
// store's newest WAL, inside a full encfs block that is not the trailing
// one. Unlike a torn tail, this is corruption no WAL replay may tolerate, so
// boot completion fails the same way before and after the encfs tail fix.
func walRebootCorruptInteriorWALBlock(t *testing.T, dataDir string) {
	t.Helper()
	logs, err := filepath.Glob(filepath.Join(dataDir, "pebble", "*.log"))
	require.NoError(t, err)
	require.NotEmpty(t, logs)
	w := logs[len(logs)-1]
	f, err := os.OpenFile(w, os.O_RDWR, 0)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	fi, err := f.Stat()
	require.NoError(t, err)
	// 133-byte header plus at least two 4124-byte blocks: the middle byte
	// then sits in a full block ahead of the trailing one.
	require.Greater(t, fi.Size(), int64(133+2*4124), "the WAL must hold full blocks")
	off := fi.Size() / 2
	b := make([]byte, 1)
	_, err = f.ReadAt(b, off)
	require.NoError(t, err)
	b[0] ^= 0xff
	_, err = f.WriteAt(b, off)
	require.NoError(t, err)
}

// walRebootSignalHandler calls signal once, on the first record whose
// message contains match, then passes every record on.
type walRebootSignalHandler struct {
	slog.Handler
	match  string
	signal func()
	once   *sync.Once
}

func (h *walRebootSignalHandler) Handle(ctx context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.match) {
		h.once.Do(h.signal)
	}
	return h.Handler.Handle(ctx, r)
}

func (h *walRebootSignalHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.Handler = h.Handler.WithAttrs(attrs)
	return &c
}

func (h *walRebootSignalHandler) WithGroup(name string) slog.Handler {
	c := *h
	c.Handler = h.Handler.WithGroup(name)
	return &c
}
