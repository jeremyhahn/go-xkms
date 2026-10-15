package gui

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// newPIVReadyApp returns a wired App whose data directory, and so its local
// PIV storage, is initialised.
func newPIVReadyApp(t *testing.T) *App {
	t.Helper()
	resetPIVManager(t)
	app := newWiredApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	require.NotNil(t, app.pivStorageBE, "precondition: local PIV storage is up")
	// startup hands services their context; the backend list counts keys
	// through the key service.
	app.keyService.SetContext(context.Background())
	return app
}

// storePIVCert imports cert into the authentication slot of backend.
func storePIVCert(t *testing.T, backend string) {
	t.Helper()
	require.NoError(t, xkmssdk.StorePIVCertificate(context.Background(), &xkmssdk.StorePIVCertificateRequest{
		Backend:     backend,
		Slot:        xkmssdk.PIVSlotAuthentication.String(),
		Certificate: newPIVTestCert(t).Raw,
		Format:      "der",
	}))
}

// TestApp_ConfigureTPM2Backend_PIVStoreMatchesRestart verifies that a TPM
// backend configured at runtime gets the PIV store it will have after a
// restart: isolated from the software store, shared with its category, and
// persisted under the category namespace so its certificates survive the
// restart.
func TestApp_ConfigureTPM2Backend_PIVStoreMatchesRestart(t *testing.T) {
	app := newPIVReadyApp(t)

	require.NoError(t, app.adminService.ConfigureBackend("tpm2", map[string]string{
		"id": "tpm-lab", "name": "Lab TPM", "device": "/dev/tpmrm0",
	}))
	storePIVCert(t, "tpm-lab")

	assert.True(t, slotHasCert(t, "tpm2", xkmssdk.PIVSlotAuthentication),
		"the backend and its category share one store")
	assert.False(t, slotHasCert(t, "software", xkmssdk.PIVSlotAuthentication),
		"a TPM certificate must not leak into the software store")

	// Restart: rebuild the PIV manager from the same storage and registry.
	xkmssdk.XKMSResetPIV()
	_, _, ok := initLocalPIV(lifecycleTestLogger(), t.TempDir(), app.pivStorageBE,
		[]string{"software", "tpm-lab"}, app.backendRegistry,
		func(string) (xkmssdk.StorageBackend, error) { return nil, errOpenStoreRefused })
	require.True(t, ok)
	assert.True(t, slotHasCert(t, "tpm-lab", xkmssdk.PIVSlotAuthentication),
		"a certificate stored before the restart must still be there after it")
}

// TestApp_ConfigureBackend_WithoutPIVStorage verifies that configuring a
// backend before local PIV storage exists still succeeds.
func TestApp_ConfigureBackend_WithoutPIVStorage(t *testing.T) {
	app := newWiredApp(t)
	require.Nil(t, app.pivStorageBE, "precondition: the data directory is not initialised")

	require.NoError(t, app.adminService.ConfigureBackend("tpm2", map[string]string{"id": "tpm-lab"}))

	info, err := app.adminService.GetBackendInfo("tpm-lab")
	require.NoError(t, err)
	assert.True(t, info.Capabilities.PIV, "the backend list must show the new backend as PIV-capable")
}

// TestApp_ConfigureBackend_PIVManagerDown verifies that a PIV store the
// manager refuses does not fail the configuration: the backend is saved and
// can still pick up a store on demand later.
func TestApp_ConfigureBackend_PIVManagerDown(t *testing.T) {
	app := newPIVReadyApp(t)
	xkmssdk.XKMSResetPIV()

	require.NoError(t, app.adminService.ConfigureBackend("tpm2", map[string]string{"id": "tpm-lab"}))

	_, err := app.adminService.GetBackendInfo("tpm-lab")
	assert.NoError(t, err)
}

// TestApp_ConfigurePKCS11Backend_LeavesPIVStoreToConnectHook verifies that
// configuring a PKCS#11 backend registers no file store under the shared
// "pkcs11" name: that name is reserved for the token's on-device store,
// which the connect hook registers.
func TestApp_ConfigurePKCS11Backend_LeavesPIVStoreToConnectHook(t *testing.T) {
	app := newPIVReadyApp(t)

	require.NoError(t, app.adminService.ConfigureBackend("pkcs11", map[string]string{
		"id": "hsm-lab", "library_path": "/usr/lib/softhsm/libsofthsm2.so",
	}))
	storePIVCert(t, "hsm-lab")

	assert.False(t, slotHasCert(t, "pkcs11", xkmssdk.PIVSlotAuthentication),
		"the shared pkcs11 name must not be bound to the configured backend's file store")
}

// TestApp_PIVUnknownBackendUsesRawID verifies that PIV operations on a
// backend neither the registry nor the backend list knows fall back to the
// raw backend ID, which gets its own isolated store.
func TestApp_PIVUnknownBackendUsesRawID(t *testing.T) {
	app := newPIVReadyApp(t)
	storePIVCert(t, "software")

	app.pivService.SetBackend("ghost-backend")
	slots, err := app.pivService.GetSlots()
	require.NoError(t, err)
	require.NotEmpty(t, slots)
	for _, slot := range slots {
		assert.False(t, slot.HasCert, "slot %s of an unknown backend must be empty", slot.Slot)
	}
}
