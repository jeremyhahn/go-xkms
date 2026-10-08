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

package datastore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type note struct {
	ID   uint64 `json:"id"`
	Text string `json:"text"`
}

func (n *note) EntityID() uint64      { return n.ID }
func (n *note) SetEntityID(id uint64) { n.ID = id }

func newNote() *note { return &note{} }

// openTestDatastore opens a standalone, memory-engine datastore for a test
// and registers its Close with t.Cleanup.
func openTestDatastore(t *testing.T, cfg *config.Config) *Datastore {
	t.Helper()
	ds, err := Open(context.Background(), cfg, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, ds.Close()) })
	return ds
}

func memoryConfig(t *testing.T) *config.Config {
	return &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
}

// saveNote saves a note through a DAO the datastore's factory builds for
// database and returns its ID, proving the factory reaches a working store.
func saveNote(t *testing.T, ds *Datastore, database, entityType, text string) uint64 {
	t.Helper()
	notes, err := dao.New(ds.DAOFactory(), database, entityType, newNote)
	require.NoError(t, err)
	saved := &note{Text: text}
	require.NoError(t, notes.Save(t.Context(), saved))
	return saved.ID
}

// loadNote reads a note back through a DAO the datastore's factory builds.
func loadNote(t *testing.T, ds *Datastore, database, entityType string, id uint64) string {
	t.Helper()
	notes, err := dao.New(ds.DAOFactory(), database, entityType, newNote)
	require.NoError(t, err)
	got, err := notes.Get(t.Context(), id)
	require.NoError(t, err)
	return got.Text
}

// TestOpen_StandaloneYieldsClientAndDAOFactory proves an embedded datastore
// hands out a working go-qrdb client and a DAO factory whose DAOs persist
// through it. Engine "memory" still requires Datastore.Path: go-qrdb roots
// the node's on-disk state under it regardless of the primary KV engine.
func TestOpen_StandaloneYieldsClientAndDAOFactory(t *testing.T) {
	ctx := t.Context()
	ds := openTestDatastore(t, memoryConfig(t))

	kv := ds.Client().KV()
	require.NoError(t, kv.Put(ctx, "probe", []byte("v")))
	got, err := kv.Get(ctx, "probe")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)

	id := saveNote(t, ds, "", "notes", "standalone")
	assert.Equal(t, "standalone", loadNote(t, ds, "", "notes", id))
}

// TestOpen_StandaloneMissingPath proves Datastore.Path is required for
// standalone mode regardless of Engine, matching config.Validate's own
// requirement for a caller that never ran Validate.
func TestOpen_StandaloneMissingPath(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory"},
	}

	ds, err := Open(context.Background(), cfg, testLogger())
	assert.Nil(t, ds)
	var pathErr *embeddednode.ErrDatastorePathRequired
	require.ErrorAs(t, err, &pathErr)
}

// TestOpen_StandaloneDefaultModeIsStandalone proves an empty Mode defaults to
// "standalone", matching config.Validate's own default.
func TestOpen_StandaloneDefaultModeIsStandalone(t *testing.T) {
	ds := openTestDatastore(t, &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	})
	assert.NotNil(t, ds.Client())
	assert.NotNil(t, ds.DAOFactory())
}

// TestHealthCheck_ReportsTheClientsHealth proves HealthCheck answers as a
// go-qrdb SDK readiness check: healthy on an open node, and unhealthy once
// the node is closed.
func TestHealthCheck_ReportsTheClientsHealth(t *testing.T) {
	ds, err := Open(context.Background(), memoryConfig(t), testLogger())
	require.NoError(t, err)

	checker := qrdbsdk.NewHealthChecker()
	checker.RegisterCheck(HealthCheckName, ds.HealthCheck)

	results := checker.Ready(t.Context())
	require.Len(t, results, 1)
	assert.Equal(t, HealthCheckName, results[0].Name)
	assert.Equal(t, qrdbsdk.HealthCheckStatusHealthy, results[0].Status)

	require.NoError(t, ds.Close())
	got := ds.HealthCheck(t.Context())
	assert.Equal(t, qrdbsdk.HealthCheckStatusUnhealthy, got.Status)
}

// TestOpen_RejectsBadConfig proves Open refuses a missing or malformed
// configuration with a typed error before building anything.
func TestOpen_RejectsBadConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		ds, err := Open(context.Background(), nil, testLogger())
		assert.Nil(t, ds)
		assert.ErrorIs(t, err, ErrNilConfig)
	})

	t.Run("unsupported mode", func(t *testing.T) {
		ds, err := Open(context.Background(), &config.Config{
			Datastore: config.DatastoreConfig{Mode: "carrier-pigeon"},
		}, testLogger())
		assert.Nil(t, ds)
		var modeErr *ErrUnsupportedDatastoreMode
		require.ErrorAs(t, err, &modeErr)
		assert.Equal(t, "carrier-pigeon", modeErr.Mode)
	})

	t.Run("unsupported remote transport", func(t *testing.T) {
		ds, err := Open(context.Background(), &config.Config{
			Datastore: config.DatastoreConfig{
				Mode:   "remote",
				Remote: config.DatastoreRemoteConfig{Transport: "ftp"},
			},
		}, testLogger())
		assert.Nil(t, ds)
		var openErr *ErrOpenDatastore
		require.ErrorAs(t, err, &openErr)
		assert.Equal(t, "remote", openErr.Mode)
		var unsupported *ErrUnsupportedStorageBackend
		require.ErrorAs(t, err, &unsupported)
	})
}

// TestNew_BorrowsTheClient proves a Datastore built over a caller's client
// serves the same data and leaves the client open on Close: the caller
// owns it.
func TestNew_BorrowsTheClient(t *testing.T) {
	owner := openTestDatastore(t, memoryConfig(t))
	id := saveNote(t, owner, "", "notes", "shared")

	borrowed, err := New(owner.Client(), owner.cfg)
	require.NoError(t, err)
	assert.Equal(t, "shared", loadNote(t, borrowed, "", "notes", id))

	require.NoError(t, borrowed.Close())
	assert.Equal(t, "shared", loadNote(t, owner, "", "notes", id),
		"closing the borrowing datastore must not close the owner's client")
}

func TestNew_RejectsNilClient(t *testing.T) {
	ds, err := New(nil, config.DatastoreConfig{})
	assert.Nil(t, ds)
	assert.ErrorIs(t, err, ErrNilClient)
}

// TestErrorTypes exercises each wrapping error's message and Unwrap.
func TestErrorTypes(t *testing.T) {
	cause := errors.New("boom")
	wrapping := map[string]interface {
		error
		Unwrap() error
	}{
		"open":   &ErrOpenDatastore{Mode: "standalone", Err: cause},
		"dial":   &ErrDialRemote{Transport: "rest", Address: "kms.example.com", Err: cause},
		"ensure": &ErrEnsureDatabase{Name: "oidc", Err: cause},
		"scope":  &ErrDatabaseScope{Name: "oidc", Err: cause},
	}
	for name, err := range wrapping {
		t.Run(name, func(t *testing.T) {
			assert.Contains(t, err.Error(), "boom")
			assert.Same(t, cause, err.Unwrap())
		})
	}

	assert.Contains(t, (&ErrUnsupportedStorageBackend{Backend: "redis"}).Error(), "redis")
	assert.Contains(t, (&ErrUnsupportedDatastoreMode{Mode: "teleport"}).Error(), "teleport")
}
