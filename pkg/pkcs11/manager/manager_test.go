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
