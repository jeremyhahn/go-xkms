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
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
)

// newFileNonceTracker opens a NonceTracker over an on-disk store at dir,
// composed the way xkmsctl composes its FROST store: a storage.Backend
// adapted to a go-qrdb KVStore and handed to a DAO factory.
func newFileNonceTracker(t *testing.T, dir string) (*NonceTracker, storage.Backend) {
	t.Helper()
	backend, err := file.New(dir)
	require.NoError(t, err)
	kv, err := kvadapter.New(backend)
	require.NoError(t, err)
	tracker, err := NewNonceTracker(dao.NewStoreFactory(kv))
	require.NoError(t, err)
	return tracker, backend
}

// TestNonceTracker_SurvivesRestart proves a nonce claim is durable: after the
// store is closed and reopened at the same path, with nothing carried over in
// process memory, the same nonce is still refused.
func TestNonceTracker_SurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "frost")
	const keyID = "restart-key"
	commitment := []byte("restart-persistence-commitment")

	// "Boot 1": claim the nonce, then close the store as shutdown does.
	tracker1, backend1 := newFileNonceTracker(t, dir)
	require.NoError(t, tracker1.Claim(context.Background(), keyID, 1, "session-1", commitment))
	require.NoError(t, backend1.Close())

	// "Boot 2": only the filesystem carries state between the two.
	tracker2, backend2 := newFileNonceTracker(t, dir)
	t.Cleanup(func() { require.NoError(t, backend2.Close()) })

	err := tracker2.Claim(context.Background(), keyID, 1, "session-2", commitment)
	requireNonceReuse(t, err, keyID)
	require.NoError(t, tracker2.Claim(context.Background(), keyID, 1, "session-2", []byte("fresh-commitment")))
}
