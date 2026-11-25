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

//go:build wal_repro

package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-qrdb/pkg/seal/encfs"
	qrdbpebble "github.com/jeremyhahn/go-qrdb/pkg/storage/pebble"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/require"
)

// Red reproductions of go-qrdb encfs WAL defects, built only with the
// wal_repro tag until the pinned go-qrdb carries the fixes.

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
