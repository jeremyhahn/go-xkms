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

package xkms

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/compose"
)

// TestOpenDatastore_StandaloneMemoryEngine proves the SDK re-export opens a
// working datastore for an embedder that never imports pkg/config or
// pkg/datastore directly, and that DatastoreStorage's backend writes through
// to the datastore's client. Engine "memory" still requires a Path: go-qrdb
// roots the node's on-disk state under it regardless of the primary KV
// engine.
func TestOpenDatastore_StandaloneMemoryEngine(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ds, err := OpenDatastore(ctx, DatastoreConfig{Engine: "memory", Path: t.TempDir()}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, ds.Close()) })

	backend, err := DatastoreStorage(ds.DAOFactory())
	require.NoError(t, err)
	require.NoError(t, backend.Put(ctx, "k", []byte("v")))

	got, err := ds.Client().KVStore().Get(ctx, "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

// TestOpenDatastore_UnsupportedMode proves an unrecognized DatastoreConfig
// mode is rejected with a typed error rather than silently defaulting.
func TestOpenDatastore_UnsupportedMode(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, err := OpenDatastore(context.Background(), DatastoreConfig{Mode: "carrier-pigeon"}, logger)
	require.Error(t, err)
}

// TestOpenDatastore_MissingPath proves a standalone datastore with no Path
// is rejected rather than silently opening a throwaway location.
func TestOpenDatastore_MissingPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, err := OpenDatastore(context.Background(), DatastoreConfig{Engine: "memory"}, logger)
	require.Error(t, err)
}

// TestDatastoreStorage_RejectsNilFactory proves a missing DAO factory is
// refused with a typed error and no backend.
func TestDatastoreStorage_RejectsNilFactory(t *testing.T) {
	backend, err := DatastoreStorage(nil)
	assert.True(t, backend == nil, "a refusal must return a nil interface, not a typed nil")
	assert.ErrorIs(t, err, compose.ErrNilDAOFactory)
}
