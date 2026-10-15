package gui

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// TestApp_LocalKeyStore_IsolatesPIVForEveryXKMSBackend verifies that a key
// backend the barrier-backed local key store brings up from the unified
// config, and that the GUI registry does not know about, still gets its own
// PIV store: certificates stored through it stay out of the software store.
func TestApp_LocalKeyStore_IsolatesPIVForEveryXKMSBackend(t *testing.T) {
	resetPIVManager(t)
	app := newWiredApp(t)

	ucfg, err := config.Load()
	require.NoError(t, err)
	ucfg.Backends.Local = append(ucfg.Backends.Local, config.LocalBackendConfig{
		ID:       "tpm2-sim",
		Category: "tpm2",
		Name:     "Simulated TPM",
		TPM2:     &config.TPM2BackendConfig{Simulator: true},
	})
	require.NoError(t, config.Save(ucfg))

	// The unsealed barrier backs both PIV and the key datastore, as in
	// initializeDataDir.
	barrier := xkmssdk.NewStorageMemory()
	store, backend, ok := initLocalPIV(lifecycleTestLogger(), t.TempDir(), barrier,
		[]string{"software"}, app.backendRegistry,
		func(string) (xkmssdk.StorageBackend, error) { return nil, errOpenStoreRefused })
	require.True(t, ok)
	app.pivFileStore, app.pivStorageBE = store, backend

	app.initLocalKeyStore(barrier)
	t.Cleanup(xkmssdk.Reset)
	require.Contains(t, xkmssdk.Backends(), "tpm2", "precondition: the config brings up a tpm2 xkms backend")

	storePIVCert(t, "tpm2")

	assert.True(t, slotHasCert(t, "tpm2", xkmssdk.PIVSlotAuthentication))
	assert.False(t, slotHasCert(t, "software", xkmssdk.PIVSlotAuthentication),
		"a tpm2 certificate must not appear in the software store")
}
