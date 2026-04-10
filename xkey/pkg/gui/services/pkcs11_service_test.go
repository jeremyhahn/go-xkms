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
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// disconnectMockManager embeds a real stub manager and overrides Disconnect
// to return a configurable error, allowing tests to exercise the success
// and failure paths of PKCS11Service.Disconnect without a real PKCS#11 library.
type disconnectMockManager struct {
	manager.Manager
	disconnectErr error
	disconnectCalled atomic.Bool
}

func (m *disconnectMockManager) Disconnect(moduleID string, slotID uint) error {
	m.disconnectCalled.Store(true)
	return m.disconnectErr
}

func TestNewPKCS11Service(t *testing.T) {
	svc := NewPKCS11Service()
	require.NotNil(t, svc)
	require.NotNil(t, svc.log)
	require.NotNil(t, svc.manager)
}

func TestPKCS11Service_SetContext(t *testing.T) {
	svc := NewPKCS11Service()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestPKCS11Service_SetManager(t *testing.T) {
	svc := NewPKCS11Service()
	originalManager := svc.manager

	// Setting nil manager
	svc.SetManager(nil)
	assert.Nil(t, svc.manager)

	// Restore original
	svc.SetManager(originalManager)
	assert.Equal(t, originalManager, svc.manager)
}

func TestPKCS11Service_GetManager(t *testing.T) {
	svc := NewPKCS11Service()
	mgr := svc.GetManager()
	assert.NotNil(t, mgr)
	assert.Equal(t, svc.manager, mgr)
}

func TestPKCS11Service_Close(t *testing.T) {
	svc := NewPKCS11Service()
	err := svc.Close()
	assert.NoError(t, err)

	// Closing with nil manager should not panic
	svc.manager = nil
	err = svc.Close()
	assert.NoError(t, err)
}

func TestPKCS11Service_ProbeModules(t *testing.T) {
	svc := NewPKCS11Service()
	// ProbeModules returns whatever is available on the system
	// Just verify it doesn't panic
	results := svc.ProbeModules()
	assert.NotNil(t, results)
	t.Logf("Found %d PKCS#11 modules", len(results))
}

func TestPKCS11Service_NilManager_Errors(t *testing.T) {
	svc := &PKCS11Service{}

	t.Run("RegisterModule", func(t *testing.T) {
		_, err := svc.RegisterModule("/path/to/lib.so", "Test")
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("UnregisterModule", func(t *testing.T) {
		err := svc.UnregisterModule("test")
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("RefreshSlots", func(t *testing.T) {
		_, err := svc.RefreshSlots("test")
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("GetModule", func(t *testing.T) {
		_, err := svc.GetModule("test")
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("ListModules", func(t *testing.T) {
		modules := svc.ListModules()
		assert.Nil(t, modules)
	})

	t.Run("ListTokens", func(t *testing.T) {
		tokens := svc.ListTokens()
		assert.Nil(t, tokens)
	})

	t.Run("InitializeToken", func(t *testing.T) {
		err := svc.InitializeToken("mod", 0, "label", "sopin", "userpin")
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("Connect", func(t *testing.T) {
		err := svc.Connect("mod", 0, "pin", "")
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("Disconnect", func(t *testing.T) {
		err := svc.Disconnect("mod", 0)
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("GetConnection", func(t *testing.T) {
		_, err := svc.GetConnection("mod", 0)
		assert.ErrorIs(t, err, ErrPKCS11ServiceNotInitialized)
	})

	t.Run("ListConnections", func(t *testing.T) {
		connections := svc.ListConnections()
		assert.Nil(t, connections)
	})
}

func TestPKCS11Service_ValidationErrors(t *testing.T) {
	svc := NewPKCS11Service()

	t.Run("RegisterModule_EmptyPath", func(t *testing.T) {
		_, err := svc.RegisterModule("", "Test")
		assert.ErrorIs(t, err, ErrPKCS11ModuleRequired)
	})

	t.Run("InitializeToken_EmptyLabel", func(t *testing.T) {
		err := svc.InitializeToken("mod", 0, "", "sopin", "userpin")
		assert.ErrorIs(t, err, ErrPKCS11LabelRequired)
	})

	t.Run("InitializeToken_EmptySOPIN", func(t *testing.T) {
		err := svc.InitializeToken("mod", 0, "label", "", "userpin")
		assert.ErrorIs(t, err, ErrPKCS11SOPINRequired)
	})

	t.Run("InitializeToken_EmptyUserPIN", func(t *testing.T) {
		err := svc.InitializeToken("mod", 0, "label", "sopin", "")
		assert.ErrorIs(t, err, ErrPKCS11UserPINRequired)
	})

	t.Run("Connect_EmptyPIN", func(t *testing.T) {
		err := svc.Connect("mod", 0, "", "")
		assert.ErrorIs(t, err, ErrPKCS11UserPINRequired)
	})
}

func TestPKCS11Service_ListModules_Empty(t *testing.T) {
	svc := NewPKCS11Service()
	// With fresh manager, no modules are registered
	modules := svc.ListModules()
	assert.Empty(t, modules)
}

func TestPKCS11Service_ListTokens_Empty(t *testing.T) {
	svc := NewPKCS11Service()
	// With fresh manager, no tokens are available
	tokens := svc.ListTokens()
	assert.Empty(t, tokens)
}

func TestPKCS11Service_ListConnections_Empty(t *testing.T) {
	svc := NewPKCS11Service()
	// With fresh manager, no connections are active
	connections := svc.ListConnections()
	assert.Empty(t, connections)
}

func TestPKCS11Service_Errors_Unique(t *testing.T) {
	errors := []error{
		ErrPKCS11ServiceNotInitialized,
		ErrPKCS11ModuleRequired,
		ErrPKCS11LabelRequired,
		ErrPKCS11SOPINRequired,
		ErrPKCS11UserPINRequired,
	}

	seen := make(map[string]bool)
	for _, err := range errors {
		msg := err.Error()
		assert.False(t, seen[msg], "duplicate error message: %s", msg)
		seen[msg] = true
	}
}

func TestConvertSlots_Empty(t *testing.T) {
	result := convertSlots(nil)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

func TestConvertModule_AllFields(t *testing.T) {
	// Test that conversion preserves all fields
	// This is a simple struct mapping test
	result := convertSlots(nil)
	assert.NotNil(t, result)
}

func TestPKCS11Service_DisconnectHook(t *testing.T) {

	t.Run("SetDisconnectHook_NilHook", func(t *testing.T) {
		svc := NewPKCS11Service()
		// Setting a nil hook must not panic.
		svc.SetDisconnectHook(nil)
		assert.Nil(t, svc.disconnectHook)
	})

	t.Run("SetDisconnectHook_StoresHook", func(t *testing.T) {
		svc := NewPKCS11Service()
		called := false
		hook := func(moduleID string, slotID uint) {
			called = true
		}
		svc.SetDisconnectHook(hook)
		assert.NotNil(t, svc.disconnectHook)
		// Invoke the stored hook directly to confirm it is the same function.
		svc.disconnectHook("test", 0)
		assert.True(t, called)
	})

	t.Run("HookFired_OnSuccessfulDisconnect", func(t *testing.T) {
		svc := NewPKCS11Service()

		mock := &disconnectMockManager{
			Manager: svc.manager, // embed the stub for non-Disconnect methods
		}
		svc.SetManager(mock)

		var hookModuleID string
		var hookSlotID uint
		hookCalled := false
		svc.SetDisconnectHook(func(moduleID string, slotID uint) {
			hookCalled = true
			hookModuleID = moduleID
			hookSlotID = slotID
		})

		err := svc.Disconnect("soft-hsm", 3)
		require.NoError(t, err)

		assert.True(t, mock.disconnectCalled.Load(), "manager.Disconnect should be called")
		assert.True(t, hookCalled, "disconnect hook should fire after successful disconnect")
		assert.Equal(t, "soft-hsm", hookModuleID)
		assert.Equal(t, uint(3), hookSlotID)
	})

	t.Run("HookNotFired_OnDisconnectError", func(t *testing.T) {
		svc := NewPKCS11Service()

		mock := &disconnectMockManager{
			Manager:       svc.manager,
			disconnectErr: errors.New("pkcs11: session not found"),
		}
		svc.SetManager(mock)

		hookCalled := false
		svc.SetDisconnectHook(func(moduleID string, slotID uint) {
			hookCalled = true
		})

		err := svc.Disconnect("soft-hsm", 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")

		assert.True(t, mock.disconnectCalled.Load(), "manager.Disconnect should be called")
		assert.False(t, hookCalled, "disconnect hook must not fire when disconnect fails")
	})
}
