package server

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newNoDatabaseServer returns a server whose datastore has no database
// plane, so every feature DAO open fails.
func newNoDatabaseServer(t *testing.T) *Server {
	t.Helper()
	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)
	ds, err := datastore.New(client, config.DatastoreConfig{})
	require.NoError(t, err)

	s := newMinimalServer(t, &config.Config{})
	s.datastore.Store(ds)
	return s
}

func TestInitializeKeyVersionStore_DatabaseUnavailable(t *testing.T) {
	s := newNoDatabaseServer(t)

	err := s.initializeKeyVersionStore()
	var scopeErr *datastore.ErrDatabaseScope
	require.ErrorAs(t, err, &scopeErr)
	assert.Nil(t, s.keyVersions)
}

func TestInitializePasswordStore_DatabaseUnavailable(t *testing.T) {
	s := newNoDatabaseServer(t)

	err := s.initializePasswordStore()
	var scopeErr *datastore.ErrDatabaseScope
	require.ErrorAs(t, err, &scopeErr)
}

// TestEnsureSSHClient_DatabaseUnavailable proves the SSH subsystem stays off,
// with the cause logged, when its database cannot be opened.
func TestEnsureSSHClient_DatabaseUnavailable(t *testing.T) {
	var logs bytes.Buffer
	s := newNoDatabaseServer(t)
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	s.xkmsService = &xkms.XKMSService{}

	assert.Nil(t, s.ensureSSHClient())
	assert.Contains(t, logs.String(), "Failed to open the SSH database")
}

func TestCAStorage_WithoutStorageFails(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})

	backend, err := s.caStorage("certs")
	assert.Nil(t, backend)
	var createErr *ErrStorageCreate
	require.ErrorAs(t, err, &createErr)
	assert.Equal(t, "CA storage certs", createErr.Resource)
}
