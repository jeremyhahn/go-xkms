// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock manager for PKCS#11 service tests
// ---------------------------------------------------------------------------

// pkcs11MockManager implements manager.Manager for unit tests.
type pkcs11MockManager struct {
	available            bool
	closeErr             error
	registerFn           func(libraryPath, displayName string) (string, error)
	unregisterFn         func(moduleID string) error
	refreshSlotsFn       func(moduleID string) ([]manager.SlotInfo, error)
	getModuleFn          func(moduleID string) (*manager.ModuleInfo, error)
	listModulesResult    []manager.ModuleInfo
	listTokensResult     []manager.TokenInfo
	initializeTokenFn    func(moduleID string, slotID uint, label, soPin, userPin string) error
	testLoginFn          func(moduleID string, slotID uint, userPin string) error
	connectFn            func(moduleID string, slotID uint, userPin, soPin string) (manager.Backend, error)
	disconnectFn         func(moduleID string, slotID uint) error
	getConnectionFn      func(moduleID string, slotID uint) (*manager.Connection, error)
	listConnectionResult []*manager.Connection
}

func (m *pkcs11MockManager) IsAvailable() bool { return m.available }
func (m *pkcs11MockManager) Close() error      { return m.closeErr }
func (m *pkcs11MockManager) RegisterModule(libraryPath, displayName string) (string, error) {
	if m.registerFn != nil {
		return m.registerFn(libraryPath, displayName)
	}
	return "", errors.New("not configured")
}
func (m *pkcs11MockManager) UnregisterModule(moduleID string) error {
	if m.unregisterFn != nil {
		return m.unregisterFn(moduleID)
	}
	return nil
}
func (m *pkcs11MockManager) RefreshSlots(moduleID string) ([]manager.SlotInfo, error) {
	if m.refreshSlotsFn != nil {
		return m.refreshSlotsFn(moduleID)
	}
	return nil, errors.New("not configured")
}
func (m *pkcs11MockManager) GetModule(moduleID string) (*manager.ModuleInfo, error) {
	if m.getModuleFn != nil {
		return m.getModuleFn(moduleID)
	}
	return nil, errors.New("module not found")
}
func (m *pkcs11MockManager) ListModules() []manager.ModuleInfo {
	return m.listModulesResult
}
func (m *pkcs11MockManager) ListTokens() []manager.TokenInfo {
	return m.listTokensResult
}
func (m *pkcs11MockManager) InitializeToken(moduleID string, slotID uint, label, soPin, userPin string) error {
	if m.initializeTokenFn != nil {
		return m.initializeTokenFn(moduleID, slotID, label, soPin, userPin)
	}
	return nil
}
func (m *pkcs11MockManager) TestLogin(moduleID string, slotID uint, userPin string) error {
	if m.testLoginFn != nil {
		return m.testLoginFn(moduleID, slotID, userPin)
	}
	return nil
}
func (m *pkcs11MockManager) Connect(moduleID string, slotID uint, userPin, soPin string) (manager.Backend, error) {
	if m.connectFn != nil {
		return m.connectFn(moduleID, slotID, userPin, soPin)
	}
	return nil, errors.New("not configured")
}
func (m *pkcs11MockManager) Disconnect(moduleID string, slotID uint) error {
	if m.disconnectFn != nil {
		return m.disconnectFn(moduleID, slotID)
	}
	return nil
}
func (m *pkcs11MockManager) GetConnection(moduleID string, slotID uint) (*manager.Connection, error) {
	if m.getConnectionFn != nil {
		return m.getConnectionFn(moduleID, slotID)
	}
	return nil, errors.New("no connection")
}
func (m *pkcs11MockManager) ListConnections() []*manager.Connection {
	return m.listConnectionResult
}

// newPKCS11ServiceWithMock creates a PKCS11Service wired to the given mock manager.
func newPKCS11ServiceWithMock(mock *pkcs11MockManager) *PKCS11Service {
	svc := NewPKCS11Service()
	svc.SetManager(mock)
	svc.SetContext(context.Background())
	return svc
}

// ---------------------------------------------------------------------------
// SetRegistry / SetContext / GetManager / SetManager
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_SetRegistry(t *testing.T) {
	svc := NewPKCS11Service()
	reg := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(reg)
	assert.Equal(t, reg, svc.registry)
}

func TestPKCS11Service_Coverage_SetRegistry_Nil(t *testing.T) {
	svc := NewPKCS11Service()
	svc.SetRegistry(nil)
	assert.Nil(t, svc.registry)
}

func TestPKCS11Service_Coverage_IsAvailable_True(t *testing.T) {
	mock := &pkcs11MockManager{available: true}
	svc := newPKCS11ServiceWithMock(mock)
	assert.True(t, svc.IsAvailable())
}

func TestPKCS11Service_Coverage_IsAvailable_False(t *testing.T) {
	mock := &pkcs11MockManager{available: false}
	svc := newPKCS11ServiceWithMock(mock)
	assert.False(t, svc.IsAvailable())
}

func TestPKCS11Service_Coverage_IsAvailable_NilManager(t *testing.T) {
	svc := &PKCS11Service{}
	assert.False(t, svc.IsAvailable())
}

func TestPKCS11Service_Coverage_Close_WithMock(t *testing.T) {
	mock := &pkcs11MockManager{closeErr: nil}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Close()
	assert.NoError(t, err)
}

func TestPKCS11Service_Coverage_Close_Error(t *testing.T) {
	closeErr := errors.New("close failed")
	mock := &pkcs11MockManager{closeErr: closeErr}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Close()
	assert.ErrorIs(t, err, closeErr)
}

// ---------------------------------------------------------------------------
// isSoftHSM2Module
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_IsSoftHSM2Module(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"softhsm lowercase", "/usr/lib/softhsm/libsofthsm2.so", true},
		{"softhsm uppercase", "/usr/lib/SoftHSM/libSoftHSM2.so", true},
		{"not softhsm", "/usr/lib/opencryptoki/libopencryptoki.so", false},
		{"empty path", "", false},
		{"softhsm in dir only", "/softhsm/libother.so", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isSoftHSM2Module(tc.path))
		})
	}
}

// ---------------------------------------------------------------------------
// convertModule / convertSlots with data
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_ConvertModule(t *testing.T) {
	mod := &manager.ModuleInfo{
		ID:          "mod-1",
		DisplayName: "Test Module",
		LibraryPath: "/usr/lib/test.so",
		State:       manager.ModuleStateLoaded,
		ErrorMsg:    "some error",
		Slots: []manager.SlotInfo{
			{
				SlotID:          0,
				Label:           "Token A",
				Serial:          "SER001",
				Manufacturer:    "TestMFG",
				Model:           "Model1",
				TokenPresent:    true,
				Initialized:     true,
				HardwareVersion: "1.0",
				FirmwareVersion: "2.3",
			},
		},
	}
	result := convertModule(mod)
	require.NotNil(t, result)
	assert.Equal(t, "mod-1", result.ID)
	assert.Equal(t, "Test Module", result.DisplayName)
	assert.Equal(t, "/usr/lib/test.so", result.LibraryPath)
	assert.Equal(t, "loaded", result.State)
	assert.Equal(t, "some error", result.ErrorMsg)
	require.Len(t, result.Slots, 1)
	assert.Equal(t, uint(0), result.Slots[0].SlotID)
	assert.Equal(t, "Token A", result.Slots[0].Label)
	assert.Equal(t, "SER001", result.Slots[0].Serial)
	assert.Equal(t, "TestMFG", result.Slots[0].Manufacturer)
	assert.Equal(t, "Model1", result.Slots[0].Model)
	assert.True(t, result.Slots[0].TokenPresent)
	assert.True(t, result.Slots[0].Initialized)
	assert.Equal(t, "1.0", result.Slots[0].HardwareVersion)
	assert.Equal(t, "2.3", result.Slots[0].FirmwareVersion)
}

func TestPKCS11Service_Coverage_ConvertSlots_Multiple(t *testing.T) {
	slots := []manager.SlotInfo{
		{SlotID: 0, Label: "A", TokenPresent: true},
		{SlotID: 1, Label: "B", TokenPresent: false},
		{SlotID: 2, Label: "C", Initialized: true},
	}
	result := convertSlots(slots)
	require.Len(t, result, 3)
	assert.Equal(t, "A", result[0].Label)
	assert.True(t, result[0].TokenPresent)
	assert.Equal(t, "B", result[1].Label)
	assert.False(t, result[1].TokenPresent)
	assert.Equal(t, "C", result[2].Label)
	assert.True(t, result[2].Initialized)
}

// ---------------------------------------------------------------------------
// RegisterModule with mock
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_RegisterModule_ManagerError(t *testing.T) {
	regErr := errors.New("register failed")
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "", regErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.RegisterModule("/path/to/lib.so", "Test")
	assert.ErrorIs(t, err, regErr)
}

func TestPKCS11Service_Coverage_RegisterModuleFromConfig_NilManager(t *testing.T) {
	svc := &PKCS11Service{}
	_, err := svc.RegisterModuleFromConfig("id", "/path/to/lib.so", "Test")
	assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
}

func TestPKCS11Service_Coverage_RegisterModuleFromConfig_EmptyPath(t *testing.T) {
	mock := &pkcs11MockManager{}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.RegisterModuleFromConfig("id", "", "Test")
	assert.ErrorIs(t, err, ErrPKCS11ModuleRequired)
}

func TestPKCS11Service_Coverage_RegisterModuleFromConfig_ManagerError(t *testing.T) {
	regErr := errors.New("register failed")
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "", regErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.RegisterModuleFromConfig("id", "/path/to/lib.so", "Test")
	assert.ErrorIs(t, err, regErr)
}

func TestPKCS11Service_Coverage_RegisterModuleFromConfig_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		registerFn: func(path, name string) (string, error) {
			return "restored-id", nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	id, err := svc.RegisterModuleFromConfig("orig-id", "/path/to/lib.so", "Restored")
	require.NoError(t, err)
	assert.Equal(t, "restored-id", id)
}

// ---------------------------------------------------------------------------
// UnregisterModule
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_UnregisterModule_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		unregisterFn: func(_ string) error { return nil },
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.UnregisterModule("mod-1")
	assert.NoError(t, err)
}

func TestPKCS11Service_Coverage_UnregisterModule_Error(t *testing.T) {
	unregErr := errors.New("unregister failed")
	mock := &pkcs11MockManager{
		unregisterFn: func(_ string) error { return unregErr },
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.UnregisterModule("mod-1")
	assert.ErrorIs(t, err, unregErr)
}

// ---------------------------------------------------------------------------
// RefreshSlots
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_RefreshSlots_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		refreshSlotsFn: func(_ string) ([]manager.SlotInfo, error) {
			return []manager.SlotInfo{
				{SlotID: 0, Label: "Slot A"},
				{SlotID: 1, Label: "Slot B"},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	slots, err := svc.RefreshSlots("mod-1")
	require.NoError(t, err)
	require.Len(t, slots, 2)
	assert.Equal(t, "Slot A", slots[0].Label)
}

func TestPKCS11Service_Coverage_RefreshSlots_Error(t *testing.T) {
	refreshErr := errors.New("refresh failed")
	mock := &pkcs11MockManager{
		refreshSlotsFn: func(_ string) ([]manager.SlotInfo, error) {
			return nil, refreshErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.RefreshSlots("mod-1")
	assert.ErrorIs(t, err, refreshErr)
}

// ---------------------------------------------------------------------------
// GetModule
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_GetModule_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID:          "mod-1",
				DisplayName: "Test",
				State:       manager.ModuleStateLoaded,
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	mod, err := svc.GetModule("mod-1")
	require.NoError(t, err)
	require.NotNil(t, mod)
	assert.Equal(t, "mod-1", mod.ID)
}

func TestPKCS11Service_Coverage_GetModule_Error(t *testing.T) {
	getErr := errors.New("not found")
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return nil, getErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.GetModule("mod-1")
	assert.ErrorIs(t, err, getErr)
}

// ---------------------------------------------------------------------------
// ListModules with data
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_ListModules_WithData(t *testing.T) {
	mock := &pkcs11MockManager{
		listModulesResult: []manager.ModuleInfo{
			{
				ID:          "mod-1",
				DisplayName: "Module One",
				LibraryPath: "/usr/lib/one.so",
				State:       manager.ModuleStateLoaded,
			},
			{
				ID:          "mod-2",
				DisplayName: "Module Two",
				LibraryPath: "/usr/lib/two.so",
				State:       manager.ModuleStateError,
				ErrorMsg:    "load failed",
			},
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	modules := svc.ListModules()
	require.Len(t, modules, 2)
	assert.Equal(t, "mod-1", modules[0].ID)
	assert.Equal(t, "loaded", modules[0].State)
	assert.Equal(t, "mod-2", modules[1].ID)
	assert.Equal(t, "error", modules[1].State)
	assert.Equal(t, "load failed", modules[1].ErrorMsg)
}

// ---------------------------------------------------------------------------
// ListTokens with data
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_ListTokens_WithData(t *testing.T) {
	mock := &pkcs11MockManager{
		listTokensResult: []manager.TokenInfo{
			{
				ModuleID:     "mod-1",
				ModuleName:   "Module One",
				SlotID:       0,
				Label:        "Token A",
				Manufacturer: "MFG",
				Model:        "Model1",
				Serial:       "SER001",
				Initialized:  true,
				Connected:    false,
			},
			{
				ModuleID:     "mod-1",
				ModuleName:   "Module One",
				SlotID:       1,
				Label:        "Token B",
				Manufacturer: "MFG",
				Model:        "Model2",
				Serial:       "SER002",
				Initialized:  true,
				Connected:    true,
			},
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	tokens := svc.ListTokens()
	require.Len(t, tokens, 2)
	assert.Equal(t, "Token A", tokens[0].Label)
	assert.False(t, tokens[0].Connected)
	assert.Equal(t, "Token B", tokens[1].Label)
	assert.True(t, tokens[1].Connected)
	assert.Equal(t, "SER002", tokens[1].Serial)
}

// ---------------------------------------------------------------------------
// InitializeToken with mock manager
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_InitializeToken_GetModuleError(t *testing.T) {
	modErr := errors.New("module not found")
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return nil, modErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.InitializeToken("mod-1", 0, "label", "sopin", "userpin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "module not found")
}

func TestPKCS11Service_Coverage_InitializeToken_NoSlots(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{ID: "mod-1", Slots: nil}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.InitializeToken("mod-1", 0, "label", "sopin", "userpin")
	assert.ErrorIs(t, err, ErrPKCS11NoSlotsAvailable)
}

func TestPKCS11Service_Coverage_InitializeToken_SlotNotFound(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 5, Label: "Other Slot"},
				},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.InitializeToken("mod-1", 99, "label", "sopin", "userpin")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPKCS11SlotNotFound)
}

func TestPKCS11Service_Coverage_InitializeToken_ManagerError(t *testing.T) {
	initErr := errors.New("init failed")
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, Label: "Slot 0", TokenPresent: true},
				},
			}, nil
		},
		initializeTokenFn: func(_ string, _ uint, _, _, _ string) error {
			return initErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.InitializeToken("mod-1", 0, "label", "sopin", "userpin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token initialization failed")
}

func TestPKCS11Service_Coverage_InitializeToken_Success(t *testing.T) {
	var capturedModuleID string
	var capturedSlotID uint
	var capturedLabel string
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, Label: "Slot 0", TokenPresent: true},
				},
			}, nil
		},
		initializeTokenFn: func(moduleID string, slotID uint, label, _, _ string) error {
			capturedModuleID = moduleID
			capturedSlotID = slotID
			capturedLabel = label
			return nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.InitializeToken("mod-1", 0, "MyToken", "sopin", "userpin")
	assert.NoError(t, err)
	assert.Equal(t, "mod-1", capturedModuleID)
	assert.Equal(t, uint(0), capturedSlotID)
	assert.Equal(t, "MyToken", capturedLabel)
}

// ---------------------------------------------------------------------------
// GetModuleSlots
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_GetModuleSlots_NilManager(t *testing.T) {
	svc := &PKCS11Service{}
	_, err := svc.GetModuleSlots("mod-1")
	assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
}

func TestPKCS11Service_Coverage_GetModuleSlots_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, Label: "Slot 0"},
					{SlotID: 1, Label: "Slot 1"},
				},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	slots, err := svc.GetModuleSlots("mod-1")
	require.NoError(t, err)
	require.Len(t, slots, 2)
	assert.Equal(t, "Slot 0", slots[0].Label)
	assert.Equal(t, "Slot 1", slots[1].Label)
}

func TestPKCS11Service_Coverage_GetModuleSlots_Error(t *testing.T) {
	modErr := errors.New("not found")
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return nil, modErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.GetModuleSlots("mod-1")
	assert.ErrorIs(t, err, modErr)
}

// ---------------------------------------------------------------------------
// Connect with mock
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_Connect_GetModuleError(t *testing.T) {
	modErr := errors.New("module not found")
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return nil, modErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 0, "pin", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "module not found")
}

func TestPKCS11Service_Coverage_Connect_NoSlots(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{ID: "mod-1", Slots: nil}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 0, "pin", "")
	assert.ErrorIs(t, err, ErrPKCS11NoSlotsAvailable)
}

func TestPKCS11Service_Coverage_Connect_SlotNotFound_WithAvailable(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true},
					{SlotID: 1, TokenPresent: false, Initialized: false},
				},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 99, "pin", "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPKCS11SlotNotFound)
	assert.Contains(t, err.Error(), "available initialized slots")
}

func TestPKCS11Service_Coverage_Connect_SlotNotFound_NoneInitialized(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: false, Initialized: false},
				},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 99, "pin", "")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrPKCS11SlotNotFound)
	assert.Contains(t, err.Error(), "none initialized")
}

func TestPKCS11Service_Coverage_Connect_NoTokenPresent(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: false, Initialized: false},
				},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 0, "pin", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no token present")
}

func TestPKCS11Service_Coverage_Connect_NotInitialized(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: false},
				},
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 0, "pin", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestPKCS11Service_Coverage_Connect_ManagerConnectError(t *testing.T) {
	connErr := errors.New("connection failed")
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true},
				},
			}, nil
		},
		connectFn: func(_ string, _ uint, _, _ string) (manager.Backend, error) {
			return nil, connErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 0, "pin", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection failed")
}

func TestPKCS11Service_Coverage_Connect_Success_WithRegistry(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true, Label: "MyToken"},
				},
			}, nil
		},
		connectFn: func(_ string, _ uint, _, _ string) (manager.Backend, error) {
			return nil, nil
		},
	}

	reg := backendregistry.NewMemoryRegistry()
	rb := &backendregistry.RegisteredBackend{
		ID:       "mod-1",
		Category: backendregistry.CategoryPKCS11,
		Location: backendregistry.LocationLocal,
	}
	require.NoError(t, reg.Register(rb))

	svc := newPKCS11ServiceWithMock(mock)
	svc.SetRegistry(reg)

	err := svc.Connect("mod-1", 0, "pin", "")
	assert.NoError(t, err)

	got, getErr := reg.Get("mod-1")
	require.NoError(t, getErr)
	assert.Equal(t, backendregistry.StateReady, got.State())
	assert.Equal(t, "0", got.Metadata["connected_slot"])
}

func TestPKCS11Service_Coverage_Connect_Success_NoRegistry(t *testing.T) {
	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true},
				},
			}, nil
		},
		connectFn: func(_ string, _ uint, _, _ string) (manager.Backend, error) {
			return nil, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Connect("mod-1", 0, "pin", "")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Disconnect with mock
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_Disconnect_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		disconnectFn: func(_ string, _ uint) error { return nil },
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Disconnect("mod-1", 0)
	assert.NoError(t, err)
}

func TestPKCS11Service_Coverage_Disconnect_Error(t *testing.T) {
	discErr := errors.New("disconnect failed")
	mock := &pkcs11MockManager{
		disconnectFn: func(_ string, _ uint) error { return discErr },
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.Disconnect("mod-1", 0)
	assert.ErrorIs(t, err, discErr)
}

func TestPKCS11Service_Coverage_Disconnect_WithRegistry(t *testing.T) {
	mock := &pkcs11MockManager{
		disconnectFn: func(_ string, _ uint) error { return nil },
	}

	reg := backendregistry.NewMemoryRegistry()
	rb := &backendregistry.RegisteredBackend{
		ID:       "mod-1",
		Category: backendregistry.CategoryPKCS11,
		Location: backendregistry.LocationLocal,
	}
	rb.SetState(backendregistry.StateReady)
	require.NoError(t, reg.Register(rb))

	svc := newPKCS11ServiceWithMock(mock)
	svc.SetRegistry(reg)

	err := svc.Disconnect("mod-1", 0)
	assert.NoError(t, err)

	got, getErr := reg.Get("mod-1")
	require.NoError(t, getErr)
	assert.Equal(t, backendregistry.StateOffline, got.State())
}

// ---------------------------------------------------------------------------
// GetConnection with mock
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_GetConnection_Success(t *testing.T) {
	mock := &pkcs11MockManager{
		getConnectionFn: func(_ string, _ uint) (*manager.Connection, error) {
			return &manager.Connection{
				ModuleID:   "mod-1",
				SlotID:     0,
				TokenLabel: "MyToken",
			}, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	conn, err := svc.GetConnection("mod-1", 0)
	require.NoError(t, err)
	require.NotNil(t, conn)
	assert.Equal(t, "mod-1", conn.ModuleID)
	assert.Equal(t, uint(0), conn.SlotID)
	assert.Equal(t, "MyToken", conn.TokenLabel)
}

func TestPKCS11Service_Coverage_GetConnection_Error(t *testing.T) {
	connErr := errors.New("no connection")
	mock := &pkcs11MockManager{
		getConnectionFn: func(_ string, _ uint) (*manager.Connection, error) {
			return nil, connErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.GetConnection("mod-1", 0)
	assert.ErrorIs(t, err, connErr)
}

// ---------------------------------------------------------------------------
// ListConnections with data
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_ListConnections_WithData(t *testing.T) {
	mock := &pkcs11MockManager{
		listConnectionResult: []*manager.Connection{
			{ModuleID: "mod-1", SlotID: 0, TokenLabel: "Token A"},
			{ModuleID: "mod-2", SlotID: 1, TokenLabel: "Token B"},
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	connections := svc.ListConnections()
	require.Len(t, connections, 2)
	assert.Equal(t, "Token A", connections[0].TokenLabel)
	assert.Equal(t, "Token B", connections[1].TokenLabel)
}

// ---------------------------------------------------------------------------
// TestConnection
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_TestConnection_NilManager(t *testing.T) {
	svc := &PKCS11Service{}
	err := svc.TestConnection("/path/to/lib.so", 0, "pin")
	assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
}

func TestPKCS11Service_Coverage_TestConnection_EmptyPath(t *testing.T) {
	mock := &pkcs11MockManager{}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.TestConnection("", 0, "pin")
	assert.ErrorIs(t, err, ErrPKCS11ModuleRequired)
}

func TestPKCS11Service_Coverage_TestConnection_EmptyPIN(t *testing.T) {
	mock := &pkcs11MockManager{}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.TestConnection("/path/to/lib.so", 0, "")
	assert.ErrorIs(t, err, ErrPKCS11UserPINRequired)
}

func TestPKCS11Service_Coverage_TestConnection_RegisterFails(t *testing.T) {
	regErr := errors.New("register failed")
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "", regErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.TestConnection("/path/to/lib.so", 0, "pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to register module")
}

func TestPKCS11Service_Coverage_TestConnection_LoginFails(t *testing.T) {
	loginErr := errors.New("login failed")
	var unregistered bool
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "test-mod", nil
		},
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "test-mod",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true},
				},
			}, nil
		},
		testLoginFn: func(_ string, _ uint, _ string) error {
			return loginErr
		},
		unregisterFn: func(_ string) error {
			unregistered = true
			return nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.TestConnection("/path/to/lib.so", 0, "pin")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection test failed")
	assert.True(t, unregistered, "module should be unregistered after test")
}

func TestPKCS11Service_Coverage_TestConnection_Success(t *testing.T) {
	var unregistered bool
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "test-mod", nil
		},
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "test-mod",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true},
				},
			}, nil
		},
		testLoginFn: func(_ string, _ uint, _ string) error {
			return nil
		},
		unregisterFn: func(_ string) error {
			unregistered = true
			return nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	err := svc.TestConnection("/path/to/lib.so", 0, "pin")
	assert.NoError(t, err)
	assert.True(t, unregistered, "module should be unregistered after test")
}

// ---------------------------------------------------------------------------
// ProbeSlots
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_ProbeSlots_NilManager(t *testing.T) {
	svc := &PKCS11Service{}
	_, err := svc.ProbeSlots("/path/to/lib.so")
	assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
}

func TestPKCS11Service_Coverage_ProbeSlots_EmptyPath(t *testing.T) {
	mock := &pkcs11MockManager{}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.ProbeSlots("")
	assert.ErrorIs(t, err, ErrPKCS11ModuleRequired)
}

func TestPKCS11Service_Coverage_ProbeSlots_RegisterFails(t *testing.T) {
	regErr := errors.New("register failed")
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "", regErr
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.ProbeSlots("/path/to/lib.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to probe module")
}

func TestPKCS11Service_Coverage_ProbeSlots_GetModuleFails(t *testing.T) {
	modErr := errors.New("module error")
	var unregistered bool
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "probe-mod", nil
		},
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return nil, modErr
		},
		unregisterFn: func(_ string) error {
			unregistered = true
			return nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	_, err := svc.ProbeSlots("/path/to/lib.so")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get module info")
	assert.True(t, unregistered, "module should be unregistered after probe failure")
}

func TestPKCS11Service_Coverage_ProbeSlots_Success(t *testing.T) {
	var unregistered bool
	mock := &pkcs11MockManager{
		registerFn: func(_, _ string) (string, error) {
			return "probe-mod", nil
		},
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "probe-mod",
				Slots: []manager.SlotInfo{
					{SlotID: 0, Label: "Slot 0", TokenPresent: true, Initialized: true},
					{SlotID: 1, Label: "Slot 1", TokenPresent: false, Initialized: false},
				},
			}, nil
		},
		unregisterFn: func(_ string) error {
			unregistered = true
			return nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)
	slots, err := svc.ProbeSlots("/path/to/lib.so")
	require.NoError(t, err)
	require.Len(t, slots, 2)
	assert.Equal(t, "Slot 0", slots[0].Label)
	assert.True(t, slots[0].TokenPresent)
	assert.Equal(t, "Slot 1", slots[1].Label)
	assert.False(t, slots[1].TokenPresent)
	assert.True(t, unregistered, "module should be unregistered after probe")
}

// ---------------------------------------------------------------------------
// Error sentinel uniqueness (additional sentinel errors)
// ---------------------------------------------------------------------------

func TestPKCS11Service_Coverage_AdditionalErrors(t *testing.T) {
	errs := []error{
		ErrPKCS11NoSlotsAvailable,
		ErrPKCS11SlotNotFound,
		ErrPKCS11ConfigPersistFailed,
	}
	seen := make(map[string]bool)
	for _, err := range errs {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
		assert.NotEmpty(t, msg)
	}
}
