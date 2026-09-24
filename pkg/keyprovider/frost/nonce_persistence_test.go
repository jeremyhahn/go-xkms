//go:build frost

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

package frost

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
)

// TestNonceTracker_SurvivesRestart proves that a used-nonce marker recorded
// through a durable, on-disk storage.Backend is still there after that
// backend is closed and reopened at the same path — the same shape as
// xkmsd's own restart: pkg/server's backend_frost.go leaves
// frost.Config.NonceStorage nil so nonce tracking rides GetNonceStorage's
// fallback to PublicStorage, which pkg/server.initFrostBackend builds with
// s.createStorageAt(backends.frost.public_path) — a durable backend
// (pebble/file/qrdb) in every production deployment, never "memory". This
// test stands in for that durability with pkg/storage/file directly, so it
// needs neither a full *server.Server nor the qrdb storage stack to prove
// the point: nonce-reuse detection does not reset just because the process
// restarted.
func TestNonceTracker_SurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "frost-nonces")
	const keyID = "restart-key"
	commitment := []byte("restart-persistence-commitment")

	// "Boot 1": mark the nonce used, then close storage the same way server
	// shutdown does.
	store1, err := file.New(dir)
	require.NoError(t, err)
	tracker1 := NewNonceTracker(store1)
	require.NoError(t, tracker1.MarkUsed(keyID, commitment))
	require.NoError(t, store1.Close())

	// "Boot 2": reopen the identical on-disk path — nothing in this process
	// carries state between the two; only the filesystem does — and confirm
	// the marker survived.
	store2, err := file.New(dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store2.Close() })
	tracker2 := NewNonceTracker(store2)

	used, err := tracker2.IsUsed(keyID, commitment)
	require.NoError(t, err)
	assert.True(t, used, "nonce marker must survive a storage close/reopen (simulated restart)")

	err = tracker2.MarkUsed(keyID, commitment)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNonceAlreadyUsed, "reusing the same nonce after restart must still be refused")
}
