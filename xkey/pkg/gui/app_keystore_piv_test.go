//go:build tpm_simulator

package gui

// These tests bring up an xkms tpm2 backend over the in-process TPM 2.0
// simulator, which is linked in only by the tpm_simulator build tag.

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

// TestApp_LocalKeyStore_SharesTheGUITPMWithTheXKMSTPM2Backend verifies the
// xkms tpm2 backend brought up by the local key store is switched to the
// GUI's own TPM: a second TPM connection computes policies against its own
// PCR config and every seal/unseal through it fails with TPM_RC_POLICY_FAIL.
// unsealingTPM is a TPM that reports it cannot seal, so the seal service's
// default selection passes over the tpm2 backend that shares it.
type unsealingTPM struct {
	closingTPM
}

func (*unsealingTPM) CanSeal() bool { return false }

func TestApp_LocalKeyStore_SharesTheGUITPMWithTheXKMSTPM2Backend(t *testing.T) {
	app, guiTPM := tpm2SimKeyStoreApp(t)

	backend, err := xkmssdk.GetBackend("tpm2")
	require.NoError(t, err, "precondition: the config brings up a tpm2 xkms backend")
	concrete, ok := backend.KeyProvider().(*xkmssdk.TPM2Backend)
	require.True(t, ok)
	assert.Same(t, guiTPM, concrete.TPM(), "the tpm2 backend must use the GUI's TPM")

	// The accessor was released: the TPM is still available to the GUI.
	acquired, err := app.tpmAccessor.Acquire()
	require.NoError(t, err)
	app.tpmAccessor.Release()
	assert.Same(t, guiTPM, acquired)
}

// tpm2SimKeyStoreApp returns an app whose unified config adds a simulated
// tpm2 backend and whose local key store is initialized, so the xkms tpm2
// backend is registered over the GUI's TPM.
func tpm2SimKeyStoreApp(t *testing.T) (*App, *unsealingTPM) {
	t.Helper()
	resetPIVManager(t)
	guiTPM := &unsealingTPM{}
	app := fakeTPMApp(t, guiTPM)

	ucfg, err := config.Load()
	require.NoError(t, err)
	ucfg.Backends.Local = append(ucfg.Backends.Local, config.LocalBackendConfig{
		ID:       "tpm2-sim",
		Category: "tpm2",
		Name:     "Simulated TPM",
		TPM2:     &config.TPM2BackendConfig{Simulator: true},
	})
	require.NoError(t, config.Save(ucfg))

	app.initLocalKeyStore(xkmssdk.NewStorageMemory())
	t.Cleanup(xkmssdk.Reset)
	return app, guiTPM
}
