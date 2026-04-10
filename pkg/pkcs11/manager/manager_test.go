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

package manager

import (
	"log/slog"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModuleState_String(t *testing.T) {
	tests := []struct {
		name  string
		state ModuleState
		want  string
	}{
		{"Unloaded", ModuleStateUnloaded, "unloaded"},
		{"Loaded", ModuleStateLoaded, "loaded"},
		{"Error", ModuleStateError, "error"},
		{"Unknown", ModuleState(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.state.String())
		})
	}
}

func TestConnectionID(t *testing.T) {
	tests := []struct {
		moduleID string
		slotID   uint
		want     string
	}{
		{"pkcs11-softhsm", 0, "pkcs11-softhsm:0"},
		{"pkcs11-softhsm", 1, "pkcs11-softhsm:1"},
		{"pkcs11-ykcs11", 42, "pkcs11-ykcs11:42"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, connectionID(tt.moduleID, tt.slotID))
		})
	}
}

func TestConnection_ConnectionID(t *testing.T) {
	conn := &Connection{
		ModuleID: "pkcs11-softhsm",
		SlotID:   5,
	}
	assert.Equal(t, "pkcs11-softhsm:5", conn.ConnectionID())
}

func TestDeriveModuleID(t *testing.T) {
	// Note: filepath.Base is platform-specific for path separators.
	// We only test Unix-style paths here as they work on all platforms.
	tests := []struct {
		path string
		want string
	}{
		{"/usr/lib/libsofthsm2.so", "pkcs11-libsofthsm2"},
		{"/usr/lib/libykcs11.so", "pkcs11-libykcs11"},
		{"/Library/OpenSC/lib/opensc-pkcs11.so", "pkcs11-opensc-pkcs11"},
		{"/opt/homebrew/lib/libykcs11.dylib", "pkcs11-libykcs11"},
		// Windows paths would need platform-specific tests
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, DeriveModuleID(tt.path))
		})
	}
}

func TestProbeModulePaths(t *testing.T) {
	// This test just verifies the function doesn't panic
	// Actual results depend on the system
	paths := ProbeModulePaths()
	t.Logf("Found %d PKCS#11 modules on %s", len(paths), runtime.GOOS)
}

func TestProbeModulesWithNames(t *testing.T) {
	// This test just verifies the function doesn't panic
	modules := ProbeModulesWithNames()
	t.Logf("Found %d PKCS#11 modules with names", len(modules))

	for _, m := range modules {
		t.Logf("  %s: %s", m.DisplayName, m.LibraryPath)
	}
}

func TestCommonModulePaths_AllPlatformsHaveEntries(t *testing.T) {
	// Verify that common platforms have module paths defined
	for _, platform := range []string{"linux", "darwin", "windows"} {
		paths, ok := CommonModulePaths[platform]
		assert.True(t, ok, "CommonModulePaths should have entries for %s", platform)
		assert.NotEmpty(t, paths, "CommonModulePaths[%s] should not be empty", platform)
	}
}

func TestSuggestModuleName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/usr/lib/softhsm/libsofthsm2.so", "SoftHSM2"},
		{"/usr/lib/libykcs11.so", "YubiKey"},
		{"/usr/lib/opensc-pkcs11.so", "OpenSC"},
		{"/usr/lib/libnitrokey.so", "Nitrokey"},
		{"/usr/lib/libeToken.so", "SafeNet eToken"},
		{"/usr/lib/libunknown.so", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, suggestModuleName(tt.path))
		})
	}
}

func TestFileExists(t *testing.T) {
	// Create a temp file
	f, err := os.CreateTemp("", "pkcs11-test-*")
	require.NoError(t, err)
	tempPath := f.Name()
	_ = f.Close()
	defer func() { _ = os.Remove(tempPath) }()

	assert.True(t, fileExists(tempPath), "temp file should exist")
	assert.False(t, fileExists("/nonexistent/path/to/file.so"), "nonexistent path should not exist")
	assert.False(t, fileExists(os.TempDir()), "directory should not pass fileExists")
}

func TestWithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	opt := WithLogger(logger)

	o := &options{}
	opt(o)

	assert.Equal(t, logger, o.logger)
}

func TestUintToString(t *testing.T) {
	tests := []struct {
		n    uint
		want string
	}{
		{0, "0"},
		{1, "1"},
		{10, "10"},
		{42, "42"},
		{100, "100"},
		{12345, "12345"},
		{4294967295, "4294967295"}, // max uint32
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, uintToString(tt.n))
		})
	}
}

func TestFindString(t *testing.T) {
	tests := []struct {
		haystack string
		needle   string
		want     int
	}{
		{"hello world", "world", 6},
		{"hello world", "hello", 0},
		{"hello world", "xyz", -1},
		{"hello", "hello world", -1}, // needle longer than haystack
		{"", "x", -1},
		{"x", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.haystack+"/"+tt.needle, func(t *testing.T) {
			assert.Equal(t, tt.want, findString(tt.haystack, tt.needle))
		})
	}
}

// TestNew_StubImplementation tests that New() returns a valid manager
// even when PKCS#11 is not available (stub implementation).
func TestNew_StubImplementation(t *testing.T) {
	mgr := New()
	require.NotNil(t, mgr)

	// Operations should either work or return ErrPKCS11Disabled
	modules := mgr.ListModules()
	assert.Empty(t, modules)

	tokens := mgr.ListTokens()
	assert.Empty(t, tokens)

	connections := mgr.ListConnections()
	assert.Empty(t, connections)

	// Close should always succeed
	err := mgr.Close()
	assert.NoError(t, err)
}

func TestSlotInfo_Fields(t *testing.T) {
	slot := SlotInfo{
		SlotID:          0,
		Label:           "Test Token",
		Serial:          "ABC123",
		Manufacturer:    "Test Manufacturer",
		Model:           "Test Model",
		TokenPresent:    true,
		Initialized:     true,
		HardwareVersion: "1.0",
		FirmwareVersion: "2.0",
	}

	assert.Equal(t, uint(0), slot.SlotID)
	assert.Equal(t, "Test Token", slot.Label)
	assert.Equal(t, "ABC123", slot.Serial)
	assert.Equal(t, "Test Manufacturer", slot.Manufacturer)
	assert.Equal(t, "Test Model", slot.Model)
	assert.True(t, slot.TokenPresent)
	assert.True(t, slot.Initialized)
	assert.Equal(t, "1.0", slot.HardwareVersion)
	assert.Equal(t, "2.0", slot.FirmwareVersion)
}

func TestModuleInfo_Fields(t *testing.T) {
	mod := ModuleInfo{
		ID:          "pkcs11-softhsm",
		DisplayName: "SoftHSM2",
		LibraryPath: "/usr/lib/softhsm/libsofthsm2.so",
		State:       ModuleStateLoaded,
		Slots:       []SlotInfo{{SlotID: 0}},
		ErrorMsg:    "",
	}

	assert.Equal(t, "pkcs11-softhsm", mod.ID)
	assert.Equal(t, "SoftHSM2", mod.DisplayName)
	assert.Equal(t, "/usr/lib/softhsm/libsofthsm2.so", mod.LibraryPath)
	assert.Equal(t, ModuleStateLoaded, mod.State)
	assert.Len(t, mod.Slots, 1)
	assert.Empty(t, mod.ErrorMsg)
}

func TestTokenInfo_Fields(t *testing.T) {
	token := TokenInfo{
		ModuleID:     "pkcs11-softhsm",
		ModuleName:   "SoftHSM2",
		SlotID:       0,
		Label:        "Test Token",
		Manufacturer: "Test",
		Model:        "Test",
		Serial:       "ABC123",
		Initialized:  true,
		Connected:    false,
	}

	assert.Equal(t, "pkcs11-softhsm", token.ModuleID)
	assert.Equal(t, "SoftHSM2", token.ModuleName)
	assert.Equal(t, uint(0), token.SlotID)
	assert.Equal(t, "Test Token", token.Label)
	assert.True(t, token.Initialized)
	assert.False(t, token.Connected)
}

func TestErrors(t *testing.T) {
	// Verify error values are unique
	errors := []error{
		ErrPKCS11Disabled,
		ErrManagerClosed,
		ErrModuleNotFound,
		ErrModuleAlreadyLoaded,
		ErrModuleLoadFailed,
		ErrModuleInitFailed,
		ErrModuleFinalizeFailed,
		ErrInvalidLibraryPath,
		ErrSlotNotFound,
		ErrTokenNotPresent,
		ErrTokenNotInitialized,
		ErrSessionOpenFailed,
		ErrSessionCloseFailed,
		ErrLoginFailed,
		ErrLogoutFailed,
		ErrTokenInitFailed,
		ErrPINInitFailed,
		ErrConnectionNotFound,
		ErrConnectionAlreadyExists,
		ErrInvalidPIN,
	}

	seen := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}
