package gui

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/fido2/keybackend"
)

var (
	errHookManagerNoRefresh    = errors.New("hook manager: refresh unsupported")
	errHookManagerNoConnection = errors.New("hook manager: no connection")
	errHookManagerUnsupported  = errors.New("hook manager: unsupported")
)

const (
	hookModuleID = "hook-module"
	hookSlotID   = uint(3)
)

// hookManager is a PKCS#11 manager holding one module with one initialised
// token, so PKCS11Service.Connect and Disconnect reach the App's connect and
// disconnect hooks without loading a PKCS#11 library. conn is what
// GetConnection returns; a nil conn reports no connection.
type hookManager struct {
	conn *xkmssdk.PKCS11Connection
}

func (m *hookManager) module() *xkmssdk.PKCS11ModuleInfo {
	return &xkmssdk.PKCS11ModuleInfo{
		ID:          hookModuleID,
		LibraryPath: "/opt/hook/libhookpkcs11.so",
		Slots: []xkmssdk.PKCS11SlotInfo{
			{SlotID: hookSlotID, Label: "hook-token", TokenPresent: true, Initialized: true},
		},
	}
}

func (m *hookManager) IsAvailable() bool { return true }
func (m *hookManager) RegisterModule(string, string) (string, error) {
	return "", errHookManagerUnsupported
}
func (m *hookManager) UnregisterModule(string) error { return errHookManagerUnsupported }
func (m *hookManager) RefreshSlots(string) ([]xkmssdk.PKCS11SlotInfo, error) {
	return nil, errHookManagerNoRefresh
}
func (m *hookManager) GetModule(string) (*xkmssdk.PKCS11ModuleInfo, error) { return m.module(), nil }
func (m *hookManager) ListModules() []xkmssdk.PKCS11ModuleInfo {
	return []xkmssdk.PKCS11ModuleInfo{*m.module()}
}
func (m *hookManager) ListTokens() []xkmssdk.PKCS11TokenInfo { return nil }
func (m *hookManager) InitializeToken(string, uint, string, string, string) error {
	return errHookManagerUnsupported
}
func (m *hookManager) TestLogin(string, uint, string) error { return nil }
func (m *hookManager) Connect(string, uint, string, string) (xkmssdk.PKCS11ManagerBackend, error) {
	return nil, nil
}
func (m *hookManager) Disconnect(string, uint) error { return nil }
func (m *hookManager) GetConnection(string, uint) (*xkmssdk.PKCS11Connection, error) {
	if m.conn == nil {
		return nil, errHookManagerNoConnection
	}
	return m.conn, nil
}
func (m *hookManager) ListConnections() []*xkmssdk.PKCS11Connection { return nil }
func (m *hookManager) Close() error                                 { return nil }

// newHookApp returns a wired App with xkms initialised, an empty FIDO2
// composite backend and the given manager behind its PKCS#11 service.
func newHookApp(t *testing.T, m *hookManager) *App {
	t.Helper()
	app := newWiredApp(t)
	require.NoError(t, app.initializeDataDir())
	t.Cleanup(xkmssdk.Reset)
	app.fido2KeyBackend = keybackend.NewCompositeBackend(xkmssdk.BackendTypeSoftware)
	app.pkcs11Service.SetManager(m)
	return app
}

// A connected token whose session the manager cannot hand back is not
// offered to FIDO2, and its disconnect is accepted.
func TestApp_PKCS11ConnectHook_NoManagerConnectionRegistersNothing(t *testing.T) {
	app := newHookApp(t, &hookManager{})

	require.NoError(t, app.pkcs11Service.Connect(hookModuleID, hookSlotID, "123456", "010203"))

	assert.NotContains(t, app.fido2KeyBackend.Backends(), xkmssdk.BackendType(hookModuleID))

	require.NoError(t, app.pkcs11Service.Disconnect(hookModuleID, hookSlotID))
	assert.NotContains(t, app.fido2KeyBackend.Backends(), xkmssdk.BackendType(hookModuleID))
}

// A connection whose PKCS#11 context cannot back an on-device PIV store still
// completes, and without a registered "pkcs11" xkms backend the token is not offered to
// FIDO2.
func TestApp_PKCS11ConnectHook_ConnectionWithoutBackendSkipsFIDO2(t *testing.T) {
	app := newHookApp(t, &hookManager{conn: &xkmssdk.PKCS11Connection{
		ModuleID: hookModuleID,
		SlotID:   hookSlotID,
	}})

	require.NoError(t, app.pkcs11Service.Connect(hookModuleID, hookSlotID, "123456", "010203"))

	assert.NotContains(t, app.fido2KeyBackend.Backends(), xkmssdk.BackendType(hookModuleID))
}
