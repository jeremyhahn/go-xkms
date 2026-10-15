//go:build pkcs11

package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

const (
	softHSMTokenLabel = "xkey-gui-token"
	softHSMSOPIN      = "87654321"
	softHSMUserPIN    = "12345678"
)

// isolatedSoftHSM points SoftHSM2 at a token directory private to the test
// and returns the SoftHSM2 module path.
func isolatedSoftHSM(t *testing.T) string {
	t.Helper()

	lib := os.Getenv("SOFTHSM2_LIB")
	if lib == "" {
		for _, candidate := range []string{
			"/usr/lib/softhsm/libsofthsm2.so",
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
			"/usr/lib64/softhsm/libsofthsm2.so",
			"/usr/local/lib/softhsm/libsofthsm2.so",
		} {
			if _, err := os.Stat(candidate); err == nil {
				lib = candidate
				break
			}
		}
	}
	require.NotEmpty(t, lib, "libsofthsm2.so not found; install softhsm2 or set SOFTHSM2_LIB")

	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	require.NoError(t, os.Mkdir(tokenDir, 0o750))
	conf := filepath.Join(root, "softhsm2.conf")
	contents := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
		tokenDir)
	require.NoError(t, os.WriteFile(conf, []byte(contents), 0o600))
	t.Setenv("SOFTHSM2_CONF", conf)

	return lib
}

// newSoftHSMApp returns a fully wired App with its data directory
// initialised and a freshly initialised SoftHSM token registered through
// the PKCS#11 service, plus the module's library path, the module ID and
// the token's slot ID.
func newSoftHSMApp(t *testing.T) (*App, string, string, uint) {
	t.Helper()

	lib := isolatedSoftHSM(t)
	app := newWiredApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	// Finalize the module so the next test can initialise SoftHSM afresh.
	t.Cleanup(func() { assert.NoError(t, app.pkcs11Service.Close()) })

	moduleID, err := app.pkcs11Service.RegisterModule(lib, "SoftHSM2")
	require.NoError(t, err)

	slots, err := app.pkcs11Service.GetModuleSlots(moduleID)
	require.NoError(t, err)
	require.NotEmpty(t, slots)
	require.NoError(t, app.pkcs11Service.InitializeToken(
		moduleID, slots[0].SlotID, softHSMTokenLabel, softHSMSOPIN, softHSMUserPIN))

	// SoftHSM moves an initialised token to a new slot ID.
	slots, err = app.pkcs11Service.RefreshSlots(moduleID)
	require.NoError(t, err)
	for _, slot := range slots {
		if slot.Label == softHSMTokenLabel {
			return app, lib, moduleID, slot.SlotID
		}
	}
	t.Fatalf("initialised token %q not found in slots %+v", softHSMTokenLabel, slots)
	return nil, "", "", 0
}

// TestApp_PKCS11Connect_RegistersXKMSBackend verifies the connect hook: a
// successful token connect registers the token as the "pkcs11" xkms backend,
// a reconnect replaces the backend
// rather than failing on the duplicate, and a disconnect is accepted.
func TestApp_PKCS11Connect_RegistersXKMSBackend(t *testing.T) {
	app, _, moduleID, slotID := newSoftHSMApp(t)

	_, err := xkmssdk.GetBackend("pkcs11")
	require.Error(t, err, "precondition: no pkcs11 backend before the token connects")

	require.NoError(t, app.pkcs11Service.Connect(moduleID, slotID, softHSMUserPIN, softHSMSOPIN))
	first, err := xkmssdk.GetBackend("pkcs11")
	require.NoError(t, err, "connecting a token must register it as the pkcs11 xkms backend")
	require.NotNil(t, first)

	require.NoError(t, app.pkcs11Service.Disconnect(moduleID, slotID))
	require.NoError(t, app.pkcs11Service.Connect(moduleID, slotID, softHSMUserPIN, ""))
	second, err := xkmssdk.GetBackend("pkcs11")
	require.NoError(t, err, "a reconnect must leave a pkcs11 backend registered")
	assert.NotSame(t, first, second, "a reconnect must replace the stale backend")

	require.NoError(t, app.pkcs11Service.Disconnect(moduleID, slotID))
}

// TestApp_RegisterPKCS11XKMSBackend_WrongPINRegistersNothing verifies that
// a token whose login fails is never registered as an xkms backend.
func TestApp_RegisterPKCS11XKMSBackend_WrongPINRegistersNothing(t *testing.T) {
	app, lib, _, slotID := newSoftHSMApp(t)

	app.registerPKCS11XKMSBackend(lib, slotID, "00000000", "", softHSMTokenLabel)

	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "a failed token login must not register a backend")
}

// TestApp_RegisterPKCS11XKMSBackend_XKMSNotInitialized verifies that a
// token cannot be registered before the xkms runtime is up.
func TestApp_RegisterPKCS11XKMSBackend_XKMSNotInitialized(t *testing.T) {
	lib := isolatedSoftHSM(t)
	app := newWiredApp(t)
	xkmssdk.Reset()
	t.Cleanup(xkmssdk.Reset)

	app.registerPKCS11XKMSBackend(lib, 0, softHSMUserPIN, "", softHSMTokenLabel)

	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err)
}
