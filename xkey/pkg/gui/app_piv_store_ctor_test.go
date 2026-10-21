package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// A namespaced PIV store keeps its certificates under backends/<name>/, out
// of sight of the root store built on the same backend.
func TestNewNamespacedPIVStore_IsolatesFromRootStore(t *testing.T) {
	backend := xkmssdk.NewStorageMemory()
	root, err := newPIVFileStore(backend)
	require.NoError(t, err)
	ns, err := newNamespacedPIVStore(backend, "tpm2")
	require.NoError(t, err)

	require.NoError(t, ns.Store(xkmssdk.PIVSlotAuthentication, newPIVTestCert(t)))

	got, err := ns.Retrieve(xkmssdk.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.NotNil(t, got)
	rootSlots, err := root.List()
	require.NoError(t, err)
	assert.Empty(t, rootSlots, "the root store must not see a namespaced certificate")
}

// Without a storage backend neither constructor builds a store.
func TestPIVStoreConstructors_NilBackendFails(t *testing.T) {
	store, err := newPIVFileStore(nil)
	assert.Error(t, err)
	assert.Nil(t, store)

	store, err = newNamespacedPIVStore(nil, "tpm2")
	assert.Error(t, err)
	assert.Nil(t, store)
}
