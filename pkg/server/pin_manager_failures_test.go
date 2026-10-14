package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// TestInitializePINManager_EmptyDatastorePathFails guards go-xkms#666: with
// no datastore path the PIN directory would resolve to the filesystem root.
func TestInitializePINManager_EmptyDatastorePathFails(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		PIN: config.PINConfig{Enabled: true, Strategy: "software"},
	})

	err := s.initializePINManager()
	var required *ErrConfigRequired
	require.ErrorAs(t, err, &required)
	assert.Equal(t, "datastore.path", required.Field)
	assert.Nil(t, s.pinManager)
}

func TestSoftwarePINProvider_Storage(t *testing.T) {
	store, err := softwarePINProvider{dir: t.TempDir()}.Storage()
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestSoftwarePINProvider_StorageUnderAFileFails(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o600))

	store, err := softwarePINProvider{dir: filepath.Join(blocker, "pin")}.Storage()
	assert.Nil(t, store)
	var createErr *ErrStorageCreate
	require.ErrorAs(t, err, &createErr)
	assert.Equal(t, "PIN state directory", createErr.Resource)
}
