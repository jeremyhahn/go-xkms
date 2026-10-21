//go:build pkcs11

package gui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
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

// A connected token is offered to FIDO2 as a key backend under its module ID,
// and its disconnect withdraws it again.
func TestApp_PKCS11Connect_OffersTokenToFIDO2UntilDisconnect(t *testing.T) {
	app, _, moduleID, slotID := newSoftHSMApp(t)
	require.NotNil(t, app.fido2KeyBackend, "precondition: initializeDataDir builds the FIDO2 key backend")

	require.NoError(t, app.pkcs11Service.Connect(moduleID, slotID, softHSMUserPIN, softHSMSOPIN))
	assert.Contains(t, app.fido2KeyBackend.Backends(), xkmssdk.BackendType(moduleID),
		"a connected token must be offered to FIDO2 under its module ID")

	require.NoError(t, app.pkcs11Service.Disconnect(moduleID, slotID))
	assert.NotContains(t, app.fido2KeyBackend.Backends(), xkmssdk.BackendType(moduleID),
		"a disconnected token must no longer be offered to FIDO2")
}

// With the barrier unsealed, a connected token's certificates are stored in
// the barrier datastore under keys/certs/, never in session-only memory.
func TestApp_PKCS11Connect_BarrierActiveStoresCertsInBarrier(t *testing.T) {
	app, _, moduleID, slotID := newSoftHSMApp(t)
	require.NoError(t, app.barrierService.Initialize("test-password", "passphrase"))
	barrier := app.barrierService.GetBackend()
	require.NotNil(t, barrier, "precondition: the barrier must be unsealed")

	require.NoError(t, app.pkcs11Service.Connect(moduleID, slotID, softHSMUserPIN, softHSMSOPIN))
	t.Cleanup(func() { assert.NoError(t, app.pkcs11Service.Disconnect(moduleID, slotID)) })

	backend, err := xkmssdk.GetBackend("pkcs11")
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, backend.CertStorage().SaveCert(ctx, "routed", newPIVTestCert(t)))

	stored, err := barrier.List(ctx, "keys/certs/")
	require.NoError(t, err)
	assert.NotEmpty(t, stored, "the certificate must land in the barrier datastore")
}

// TestApp_RegisterPKCS11XKMSBackend_WrongPINRegistersNothing verifies that
// a token whose login fails is never registered as an xkms backend.
func TestApp_RegisterPKCS11XKMSBackend_WrongPINRegistersNothing(t *testing.T) {
	app, lib, _, slotID := newSoftHSMApp(t)

	app.registerPKCS11XKMSBackend(lib, slotID, "00000000", "", softHSMTokenLabel)

	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "a failed token login must not register a backend")
}

// A YubiKey refuses key generation and certificate writes to a CKU_USER-only
// session, so registration without the management key (SO PIN) is refused at
// the boundary, before the library is loaded.
func TestApp_RegisterPKCS11XKMSBackend_YubiKeyWithoutSOPINRegistersNothing(t *testing.T) {
	app, lib, _, slotID := newSoftHSMApp(t)
	// A working module under a YubiKey name: only the refusal keeps it out.
	yubiKeyNamedLib := filepath.Join(t.TempDir(), "libykcs11.so")
	require.NoError(t, os.Symlink(lib, yubiKeyNamedLib))

	app.registerPKCS11XKMSBackend(yubiKeyNamedLib, slotID, softHSMUserPIN, "", softHSMTokenLabel)

	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "a YubiKey backend without the SO PIN must not register")
}

func TestApp_RegisterPKCS11XKMSBackend_MissingLibraryRegistersNothing(t *testing.T) {
	app, _, _, slotID := newSoftHSMApp(t)

	app.registerPKCS11XKMSBackend(filepath.Join(t.TempDir(), "absent.so"), slotID, softHSMUserPIN, softHSMSOPIN, "")

	_, err := xkmssdk.GetBackend("pkcs11")
	assert.Error(t, err, "a library that cannot be loaded must not register a backend")
}

// Startup restores every PKCS#11 module the unified config lists: a module
// that fails to load does not stop the ones after it, and restoring never
// rewrites the config it was read from.
func TestApp_RestorePKCS11Modules_RestoresConfiguredModule(t *testing.T) {
	lib := isolatedSoftHSM(t)
	t.Setenv("HOME", t.TempDir())
	app := newWiredApp(t)
	t.Cleanup(func() { assert.NoError(t, app.pkcs11Service.Close()) })

	cfgDir := t.TempDir()
	config.SetConfigDir(cfgDir)
	t.Cleanup(config.ResetConfigDir)
	cfgPath := filepath.Join(cfgDir, "xkey.yaml")
	yaml := fmt.Sprintf(`
backends:
  local:
    - id: broken
      category: pkcs11
      name: "Broken"
      pkcs11:
        library_path: %s
    - id: token1
      category: pkcs11
      name: "SoftHSM2"
      pkcs11:
        library_path: %s
`, filepath.Join(t.TempDir(), "absent.so"), lib)
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))

	app.restorePKCS11Modules()

	var restored bool
	for _, m := range app.pkcs11Service.ListModules() {
		if m.LibraryPath == lib {
			restored = true
			assert.NotEmpty(t, m.Slots, "a restored module must expose its slots")
		}
	}
	assert.True(t, restored, "the loadable module must be restored despite the broken entry before it")

	after, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	assert.Equal(t, yaml, string(after), "restoring modules must not rewrite the config")
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
