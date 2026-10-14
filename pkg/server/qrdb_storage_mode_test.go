package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
)

func TestInitializeQRDBStorage_UnsupportedModeFails(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{Mode: "sideways"},
	})

	err := s.initializeQRDBStorage()
	var modeErr *datastore.ErrUnsupportedDatastoreMode
	require.ErrorAs(t, err, &modeErr)
	assert.Equal(t, "sideways", modeErr.Mode)
	assert.Nil(t, s.datastore)
}

// TestInitializeQRDBStorage_RemoteDialFailureWraps names a transport the
// remote factory does not know, so the dial fails before any I/O.
func TestInitializeQRDBStorage_RemoteDialFailureWraps(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Datastore: config.DatastoreConfig{
			Mode:   "remote",
			Remote: config.DatastoreRemoteConfig{Transport: "carrier-pigeon"},
		},
	})

	err := s.initializeQRDBStorage()
	var createErr *ErrStorageCreate
	require.ErrorAs(t, err, &createErr)
	assert.Equal(t, "remote datastore", createErr.Resource)
	var unsupported *datastore.ErrUnsupportedStorageBackend
	assert.ErrorAs(t, err, &unsupported)
	assert.Nil(t, s.datastore)
}
