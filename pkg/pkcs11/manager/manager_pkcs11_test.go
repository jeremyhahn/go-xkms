//go:build pkcs11

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
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the real PKCS#11 manager against a SoftHSM2 token that is
// created inside t.TempDir(). SOFTHSM2_CONF is redirected per test, so nothing
// is written outside the test's temporary directory and the host's own SoftHSM
// token store is never read or modified.

const (
	testSOPIN   = "87654321"
	testUserPIN = "1234"
)

// softhsmLibrary locates libsofthsm2.so, skipping nothing: if SoftHSM2 is not
// installed the test fails loudly, because the pkcs11 build tag is only used in
// environments (devcontainer, CI) where SoftHSM2 is a declared dependency.
func softhsmLibrary(t *testing.T) string {
	t.Helper()

	if env := os.Getenv("SOFTHSM2_LIB"); env != "" {
		if fileExists(env) {
			return env
		}
		t.Fatalf("SOFTHSM2_LIB=%s does not point at a file", env)
	}

	candidates := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}

	t.Fatalf("libsofthsm2.so not found in %v; install softhsm2 or set SOFTHSM2_LIB", candidates)
	return ""
}

// newIsolatedManager builds a manager backed by a private SoftHSM token store
// under t.TempDir() and registers the SoftHSM module in it. The returned slot
// holds an uninitialized token, which is the state a freshly inserted device
// presents.
func newIsolatedManager(t *testing.T) (Manager, string, uint) {
	t.Helper()

	lib := softhsmLibrary(t)

	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	require.NoError(t, os.Mkdir(tokenDir, 0o750))

	conf := filepath.Join(root, "softhsm2.conf")
	contents := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
		tokenDir)
	require.NoError(t, os.WriteFile(conf, []byte(contents), 0o600))

	// t.Setenv restores the previous value automatically and forbids parallel
	// tests, which is exactly the isolation this needs.
	t.Setenv("SOFTHSM2_CONF", conf)

	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := New(WithLogger(quiet))
	t.Cleanup(func() { _ = mgr.Close() })

	moduleID, err := mgr.RegisterModule(lib, "SoftHSM2")
	require.NoError(t, err, "registering the SoftHSM module must succeed")

	info, err := mgr.GetModule(moduleID)
	require.NoError(t, err)
	require.NotEmpty(t, info.Slots, "SoftHSM always exposes at least one free slot")

	return mgr, moduleID, info.Slots[0].SlotID
}

// initToken initialises the token in the given slot with the shared test PINs.
func initToken(t *testing.T, mgr Manager, moduleID string, slotID uint, label string) {
	t.Helper()
	require.NoError(t, mgr.InitializeToken(moduleID, slotID, label, testSOPIN, testUserPIN))
}

// TestManager_IsAvailableWithPKCS11Tag pins the counterpart of the stub's
// IsAvailable: a binary built with -tags pkcs11 must advertise support.
func TestManager_IsAvailableWithPKCS11Tag(t *testing.T) {
	mgr, _, _ := newIsolatedManager(t)

	assert.True(t, mgr.IsAvailable())
}

// TestManager_RegisterModule_RejectsBadLibraryPaths verifies the path guard
// runs before dlopen. Passing an arbitrary path straight to dlopen is how a
// malformed config turns into a crash inside C code instead of a Go error.
func TestManager_RegisterModule_RejectsBadLibraryPaths(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := New(WithLogger(quiet))
	t.Cleanup(func() { _ = mgr.Close() })

	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"empty path", ""},
		{"nonexistent file", filepath.Join(dir, "no-such-module.so")},
		{"directory instead of file", dir},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := mgr.RegisterModule(tt.path, "bad")
			require.ErrorIs(t, err, ErrInvalidLibraryPath)
			assert.Empty(t, id)
		})
	}
}

// TestManager_RegisterModule_EnumeratesSlots verifies a freshly registered
// module reports its slots with a token present but not yet initialized. This
// is the state the enrollment UI branches on to offer "initialize token".
func TestManager_RegisterModule_EnumeratesSlots(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)

	info, err := mgr.GetModule(moduleID)
	require.NoError(t, err)

	assert.Equal(t, ModuleStateLoaded, info.State)
	assert.Equal(t, "SoftHSM2", info.DisplayName)
	assert.Empty(t, info.ErrorMsg)

	var slot *SlotInfo
	for i := range info.Slots {
		if info.Slots[i].SlotID == slotID {
			slot = &info.Slots[i]
		}
	}
	require.NotNil(t, slot)

	assert.True(t, slot.TokenPresent, "SoftHSM presents a token in its free slot")
	assert.False(t, slot.Initialized, "a fresh token must not report itself initialized")
	assert.Contains(t, slot.Manufacturer, "SoftHSM")
	assert.NotEmpty(t, slot.FirmwareVersion, "firmware version is surfaced in the device list")
}

// TestManager_RegisterModule_RejectsDuplicate verifies loading the same library
// twice is refused. A second C_Initialize on an already-initialized library
// corrupts the first context's state, so this guard protects live sessions.
func TestManager_RegisterModule_RejectsDuplicate(t *testing.T) {
	mgr, _, _ := newIsolatedManager(t)

	id, err := mgr.RegisterModule(softhsmLibrary(t), "SoftHSM2 again")
	require.ErrorIs(t, err, ErrModuleAlreadyLoaded)
	assert.Empty(t, id)

	assert.Len(t, mgr.ListModules(), 1, "the duplicate must not be recorded")
}

// TestManager_GetModule_ReturnsDefensiveCopy verifies callers cannot mutate the
// manager's internal slot table through the returned ModuleInfo. The GUI hands
// this struct to a view layer that sorts and rewrites it, and aliasing would
// corrupt the manager's view of the hardware.
func TestManager_GetModule_ReturnsDefensiveCopy(t *testing.T) {
	mgr, moduleID, _ := newIsolatedManager(t)

	first, err := mgr.GetModule(moduleID)
	require.NoError(t, err)
	require.NotEmpty(t, first.Slots)

	first.Slots[0].Label = "tampered"
	first.Slots[0].Initialized = true
	first.DisplayName = "tampered"

	second, err := mgr.GetModule(moduleID)
	require.NoError(t, err)

	assert.NotEqual(t, "tampered", second.Slots[0].Label)
	assert.False(t, second.Slots[0].Initialized)
	assert.Equal(t, "SoftHSM2", second.DisplayName)
}

// TestManager_GetModule_UnknownID verifies an unknown module ID is rejected
// rather than returning a zero-valued ModuleInfo the caller would misread.
func TestManager_GetModule_UnknownID(t *testing.T) {
	mgr, _, _ := newIsolatedManager(t)

	info, err := mgr.GetModule("pkcs11-does-not-exist")
	require.ErrorIs(t, err, ErrModuleNotFound)
	assert.Nil(t, info)
}

// TestManager_InitializeToken_RejectsInvalidInput covers every guard that runs
// before the destructive C_InitToken call. C_InitToken erases the token, so
// these checks are the last line of defence against wiping the wrong device.
func TestManager_InitializeToken_RejectsInvalidInput(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)

	tests := []struct {
		name     string
		moduleID string
		slotID   uint
		soPin    string
		userPin  string
		wantErr  error
	}{
		{"unknown module", "pkcs11-nope", slotID, testSOPIN, testUserPIN, ErrModuleNotFound},
		{"unknown slot", moduleID, 9999, testSOPIN, testUserPIN, ErrSlotNotFound},
		{"so pin too short", moduleID, slotID, "123", testUserPIN, ErrInvalidPIN},
		{"so pin too long", moduleID, slotID, string(make([]byte, 33)), testUserPIN, ErrInvalidPIN},
		{"user pin too short", moduleID, slotID, testSOPIN, "1", ErrInvalidPIN},
		{"user pin too long", moduleID, slotID, testSOPIN, string(make([]byte, 33)), ErrInvalidPIN},
		{"empty so pin", moduleID, slotID, "", testUserPIN, ErrInvalidPIN},
		{"empty user pin", moduleID, slotID, testSOPIN, "", ErrInvalidPIN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.InitializeToken(tt.moduleID, tt.slotID, "label", tt.soPin, tt.userPin)
			require.ErrorIs(t, err, tt.wantErr)
		})
	}

	// None of the rejected attempts may have touched the token.
	info, err := mgr.GetModule(moduleID)
	require.NoError(t, err)
	assert.False(t, info.Slots[0].Initialized,
		"a rejected InitializeToken must leave the token untouched")
}

// TestManager_InitializeToken_MarksTokenInitialized verifies the happy path
// leaves the token labelled, initialized and immediately visible in ListTokens
// without requiring an explicit refresh.
func TestManager_InitializeToken_MarksTokenInitialized(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)

	initToken(t, mgr, moduleID, slotID, "xkms-unit-token")

	tokens := mgr.ListTokens()
	require.NotEmpty(t, tokens)

	var found *TokenInfo
	for i := range tokens {
		if tokens[i].Label == "xkms-unit-token" {
			found = &tokens[i]
		}
	}
	require.NotNil(t, found, "the initialized token must appear in ListTokens: %+v", tokens)

	assert.True(t, found.Initialized)
	assert.False(t, found.Connected, "no session has been opened yet")
	assert.Equal(t, moduleID, found.ModuleID)
	assert.Equal(t, "SoftHSM2", found.ModuleName)
	assert.NotEmpty(t, found.Serial, "an initialized token is assigned a serial number")
}

// TestManager_RefreshSlots verifies hot-plug re-enumeration picks up state that
// changed underneath the manager, and that an unknown module is rejected.
func TestManager_RefreshSlots(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)

	before, err := mgr.RefreshSlots(moduleID)
	require.NoError(t, err)
	require.NotEmpty(t, before)

	initToken(t, mgr, moduleID, slotID, "refresh-token")

	after, err := mgr.RefreshSlots(moduleID)
	require.NoError(t, err)

	var slot *SlotInfo
	for i := range after {
		if after[i].SlotID == slotID {
			slot = &after[i]
		}
	}
	require.NotNil(t, slot)
	assert.True(t, slot.Initialized)
	assert.Equal(t, "refresh-token", slot.Label)

	t.Run("unknown module", func(t *testing.T) {
		slots, err := mgr.RefreshSlots("pkcs11-nope")
		require.ErrorIs(t, err, ErrModuleNotFound)
		assert.Nil(t, slots)
	})
}

// TestManager_TestLogin_RequiresInitializedToken verifies a PIN check against a
// blank token is refused with a specific error instead of a generic login
// failure, so the UI can offer "initialize" rather than "wrong PIN".
func TestManager_TestLogin_RequiresInitializedToken(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)

	err := mgr.TestLogin(moduleID, slotID, testUserPIN)
	require.ErrorIs(t, err, ErrTokenNotInitialized)
}

// TestManager_TestLogin_CorrectAndWrongPIN is the core authentication check:
// the correct PIN must be accepted and a wrong PIN must be rejected with
// ErrLoginFailed. A regression that swallowed the C_Login error would turn the
// PIN prompt into decoration.
func TestManager_TestLogin_CorrectAndWrongPIN(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "login-token")

	t.Run("correct pin succeeds", func(t *testing.T) {
		require.NoError(t, mgr.TestLogin(moduleID, slotID, testUserPIN))
	})

	t.Run("wrong pin is rejected", func(t *testing.T) {
		err := mgr.TestLogin(moduleID, slotID, "9999")
		require.ErrorIs(t, err, ErrLoginFailed)
	})

	t.Run("correct pin still works after a failed attempt", func(t *testing.T) {
		require.NoError(t, mgr.TestLogin(moduleID, slotID, testUserPIN),
			"a single wrong PIN must not lock the token")
	})

	t.Run("unknown module", func(t *testing.T) {
		require.ErrorIs(t, mgr.TestLogin("pkcs11-nope", slotID, testUserPIN), ErrModuleNotFound)
	})

	t.Run("unknown slot", func(t *testing.T) {
		require.ErrorIs(t, mgr.TestLogin(moduleID, 9999, testUserPIN), ErrSlotNotFound)
	})
}

// TestManager_TestLogin_NeverFailsOpenUnderRepeatedWrongPINs is a brute-force
// guard on the manager's own login path: no number of consecutive wrong PINs
// may ever cause a wrong PIN to be accepted, and the underlying PKCS#11 return
// code must be preserved in the error detail so an operator can tell
// CKR_PIN_INCORRECT apart from CKR_PIN_LOCKED.
//
// Note on scope: SoftHSM2 is a software token and implements no anti-hammering,
// so it returns CKR_PIN_INCORRECT indefinitely and never transitions to
// CKR_PIN_LOCKED. The device-side lockout transition is therefore not
// observable here and requires real hardware (YubiKey PIV, Nitrokey HSM) to
// exercise; see the hardware integration suite. What this test does pin is that
// the manager never invents a success of its own.
func TestManager_TestLogin_NeverFailsOpenUnderRepeatedWrongPINs(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "bruteforce-token")

	for i := 0; i < 10; i++ {
		err := mgr.TestLogin(moduleID, slotID, "9999")
		require.ErrorIs(t, err, ErrLoginFailed, "wrong PIN accepted on attempt %d", i+1)
		require.Contains(t, err.Error(), "CKR_PIN_INCORRECT",
			"the PKCS#11 return code must survive into the error detail")
	}

	// The manager must not have latched any state that changes the verdict for
	// the genuine PIN.
	require.NoError(t, mgr.TestLogin(moduleID, slotID, testUserPIN))
}

// TestManager_Connect_RequiresInitializedToken verifies a connection attempt to
// a blank token is refused before any session is opened.
func TestManager_Connect_RequiresInitializedToken(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)

	backend, err := mgr.Connect(moduleID, slotID, testUserPIN, testSOPIN)
	require.ErrorIs(t, err, ErrTokenNotInitialized)
	assert.Nil(t, backend)
	assert.Empty(t, mgr.ListConnections(), "a failed Connect must not leak a connection")
}

// TestManager_Connect_WrongPINLeaksNothing verifies a failed login closes the
// session it opened and records no connection. A leaked session handle would
// eventually exhaust the token's session limit.
func TestManager_Connect_WrongPINLeaksNothing(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "connect-token")

	backend, err := mgr.Connect(moduleID, slotID, "9999", testSOPIN)
	require.ErrorIs(t, err, ErrLoginFailed)
	assert.Nil(t, backend)

	assert.Empty(t, mgr.ListConnections())

	conn, err := mgr.GetConnection(moduleID, slotID)
	require.ErrorIs(t, err, ErrConnectionNotFound)
	assert.Nil(t, conn)
}

// TestManager_ConnectDisconnectLifecycle covers the full session lifecycle:
// connect, observe the connection is tracked and reflected in ListTokens,
// refuse a duplicate connect, then disconnect and observe it is gone.
func TestManager_ConnectDisconnectLifecycle(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "lifecycle-token")

	backend, err := mgr.Connect(moduleID, slotID, testUserPIN, testSOPIN)
	require.NoError(t, err)
	require.NotNil(t, backend)

	conn, err := mgr.GetConnection(moduleID, slotID)
	require.NoError(t, err)
	assert.Equal(t, "lifecycle-token", conn.TokenLabel)
	assert.Equal(t, moduleID+":"+uintToString(slotID), conn.ConnectionID())
	assert.NotNil(t, conn.P11Ctx, "the raw context is reused by PIV cert storage")

	assert.Len(t, mgr.ListConnections(), 1)

	// The token listing must now mark this token as connected.
	var connected bool
	for _, tok := range mgr.ListTokens() {
		if tok.SlotID == slotID && tok.ModuleID == moduleID {
			connected = tok.Connected
		}
	}
	assert.True(t, connected, "an open connection must be reflected in ListTokens")

	t.Run("duplicate connect is refused", func(t *testing.T) {
		dup, err := mgr.Connect(moduleID, slotID, testUserPIN, testSOPIN)
		require.ErrorIs(t, err, ErrConnectionAlreadyExists)
		assert.Nil(t, dup)
		assert.Len(t, mgr.ListConnections(), 1, "the refused attempt must not add a connection")
	})

	require.NoError(t, mgr.Disconnect(moduleID, slotID))

	assert.Empty(t, mgr.ListConnections())
	_, err = mgr.GetConnection(moduleID, slotID)
	assert.ErrorIs(t, err, ErrConnectionNotFound)

	t.Run("second disconnect is refused", func(t *testing.T) {
		require.ErrorIs(t, mgr.Disconnect(moduleID, slotID), ErrConnectionNotFound)
	})
}

// TestManager_Connect_UnknownModuleAndSlot verifies the lookup guards on the
// Connect path reject unknown identifiers.
func TestManager_Connect_UnknownModuleAndSlot(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "guard-token")

	t.Run("unknown module", func(t *testing.T) {
		backend, err := mgr.Connect("pkcs11-nope", slotID, testUserPIN, testSOPIN)
		require.ErrorIs(t, err, ErrModuleNotFound)
		assert.Nil(t, backend)
	})

	t.Run("unknown slot", func(t *testing.T) {
		backend, err := mgr.Connect(moduleID, 9999, testUserPIN, testSOPIN)
		require.ErrorIs(t, err, ErrSlotNotFound)
		assert.Nil(t, backend)
	})
}

// TestManager_UnregisterModule_ClosesConnections verifies unregistering a
// module tears down the sessions it owns. Leaving them behind would keep the
// token logged in after the operator removed the module from the UI.
func TestManager_UnregisterModule_ClosesConnections(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "unregister-token")

	_, err := mgr.Connect(moduleID, slotID, testUserPIN, testSOPIN)
	require.NoError(t, err)
	require.Len(t, mgr.ListConnections(), 1)

	require.NoError(t, mgr.UnregisterModule(moduleID))

	assert.Empty(t, mgr.ListConnections(), "unregistering must close the module's connections")
	assert.Empty(t, mgr.ListModules())
	assert.Empty(t, mgr.ListTokens())

	_, err = mgr.GetModule(moduleID)
	assert.ErrorIs(t, err, ErrModuleNotFound)

	t.Run("second unregister is refused", func(t *testing.T) {
		require.ErrorIs(t, mgr.UnregisterModule(moduleID), ErrModuleNotFound)
	})
}

// TestManager_OperationsAfterClose verifies every fallible operation refuses to
// run once the manager is closed. After Close the underlying C contexts have
// been destroyed, so proceeding would dereference freed memory.
func TestManager_OperationsAfterClose(t *testing.T) {
	mgr, moduleID, slotID := newIsolatedManager(t)
	initToken(t, mgr, moduleID, slotID, "closed-token")

	_, err := mgr.Connect(moduleID, slotID, testUserPIN, testSOPIN)
	require.NoError(t, err)

	require.NoError(t, mgr.Close())

	// Close releases every tracked resource.
	assert.Empty(t, mgr.ListConnections())
	assert.Empty(t, mgr.ListModules())
	assert.Empty(t, mgr.ListTokens())

	t.Run("RegisterModule", func(t *testing.T) {
		_, err := mgr.RegisterModule(softhsmLibrary(t), "SoftHSM2")
		require.ErrorIs(t, err, ErrManagerClosed)
	})
	t.Run("UnregisterModule", func(t *testing.T) {
		require.ErrorIs(t, mgr.UnregisterModule(moduleID), ErrManagerClosed)
	})
	t.Run("RefreshSlots", func(t *testing.T) {
		_, err := mgr.RefreshSlots(moduleID)
		require.ErrorIs(t, err, ErrManagerClosed)
	})
	t.Run("GetModule", func(t *testing.T) {
		_, err := mgr.GetModule(moduleID)
		require.ErrorIs(t, err, ErrManagerClosed)
	})
	t.Run("InitializeToken", func(t *testing.T) {
		err := mgr.InitializeToken(moduleID, slotID, "l", testSOPIN, testUserPIN)
		require.ErrorIs(t, err, ErrManagerClosed)
	})
	t.Run("TestLogin", func(t *testing.T) {
		require.ErrorIs(t, mgr.TestLogin(moduleID, slotID, testUserPIN), ErrManagerClosed)
	})
	t.Run("Connect", func(t *testing.T) {
		_, err := mgr.Connect(moduleID, slotID, testUserPIN, testSOPIN)
		require.ErrorIs(t, err, ErrManagerClosed)
	})
	t.Run("Disconnect", func(t *testing.T) {
		require.ErrorIs(t, mgr.Disconnect(moduleID, slotID), ErrManagerClosed)
	})
	t.Run("GetConnection", func(t *testing.T) {
		_, err := mgr.GetConnection(moduleID, slotID)
		require.ErrorIs(t, err, ErrManagerClosed)
	})
	t.Run("Close is idempotent", func(t *testing.T) {
		require.NoError(t, mgr.Close())
	})
}
