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
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockModuleInfo is a small helper for building a xkms.PKCS11ModuleInfo with
// the slots these tests exercise.
func mockModuleInfo(moduleID string, slots ...xkms.PKCS11SlotInfo) *xkms.PKCS11ModuleInfo {
	return &xkms.PKCS11ModuleInfo{
		ID:          moduleID,
		DisplayName: "Mock Module",
		LibraryPath: "/mock/libpkcs11.so",
		State:       xkms.PKCS11ModuleStateLoaded,
		Slots:       slots,
	}
}

// TestPKCS11Service_RegisterModule_SyncsSlotBackends verifies that a
// successful RegisterModule auto-registers a backend for every slot that
// has a token present, carrying its label, manufacturer, model, and
// serial -- and skips slots with no token present.
func TestPKCS11Service_RegisterModule_SyncsSlotBackends(t *testing.T) {
	mod := mockModuleInfo("mod-1",
		xkms.PKCS11SlotInfo{
			SlotID: 0, TokenPresent: true, Initialized: true,
			Label: "Token A", Manufacturer: "Acme HSM", Model: "A100", Serial: "SN-A",
		},
		xkms.PKCS11SlotInfo{
			SlotID: 1, TokenPresent: false,
		},
	)

	mock := &pkcs11MockManager{
		available: true,
		registerFn: func(libraryPath, displayName string) (string, error) {
			return "mod-1", nil
		},
		getModuleFn: func(moduleID string) (*xkms.PKCS11ModuleInfo, error) {
			require.Equal(t, "mod-1", moduleID)
			return mod, nil
		},
	}

	svc := newPKCS11ServiceWithMock(mock)
	registry := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(registry)

	moduleID, err := svc.RegisterModule("/mock/libpkcs11.so", "Mock Module")
	require.NoError(t, err)
	require.Equal(t, "mod-1", moduleID)

	rb, err := registry.Get(slotBackendID("mod-1", 0))
	require.NoError(t, err, "the slot with a token present must be registered")
	assert.Equal(t, "Token A", rb.DisplayName)
	assert.Equal(t, "Acme HSM", rb.Metadata["token_manufacturer"])
	assert.Equal(t, "A100", rb.Metadata["token_model"])
	assert.Equal(t, "SN-A", rb.Metadata["token_serial"])
	assert.Equal(t, "/mock/libpkcs11.so", rb.Metadata["library_path"])

	_, err = registry.Get(slotBackendID("mod-1", 1))
	assert.ErrorIs(t, err, backendregistry.ErrBackendNotFound,
		"a slot with no token present must not get a backend")
}

// TestPKCS11Service_SyncSlotBackends_OneSlotFailsToRegister verifies that a
// single slot failing to register in the backend registry -- the moral
// equivalent of a slot that fails to open, surfaced through the same
// registry.Register error path -- does not abort registration of the
// module's other slots, and does not fail the overall RegisterModule call.
// This mirrors pkcs11mgr's original behavior of logging and continuing.
func TestPKCS11Service_SyncSlotBackends_OneSlotFailsToRegister(t *testing.T) {
	mod := mockModuleInfo("mod-1",
		xkms.PKCS11SlotInfo{SlotID: 0, TokenPresent: true, Label: "Good Slot"},
		xkms.PKCS11SlotInfo{SlotID: 1, TokenPresent: true, Label: "Colliding Slot"},
	)

	mock := &pkcs11MockManager{
		available: true,
		registerFn: func(libraryPath, displayName string) (string, error) {
			return "mod-1", nil
		},
		getModuleFn: func(moduleID string) (*xkms.PKCS11ModuleInfo, error) {
			return mod, nil
		},
	}

	svc := newPKCS11ServiceWithMock(mock)
	registry := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(registry)

	// Pre-populate the registry with a backend under the exact ID that slot
	// 1 would use, but in a category syncSlotBackends does not clear before
	// re-registering, so Register() collides for that slot only.
	collidingID := slotBackendID("mod-1", 1)
	require.NoError(t, registry.Register(&backendregistry.RegisteredBackend{
		ID:          collidingID,
		Location:    backendregistry.LocationLocal,
		Category:    backendregistry.CategoryXKMS,
		DisplayName: "Pre-existing unrelated backend",
	}))

	moduleID, err := svc.RegisterModule("/mock/libpkcs11.so", "Mock Module")
	require.NoError(t, err, "one slot failing to register must not fail RegisterModule")
	require.Equal(t, "mod-1", moduleID)

	rb, err := registry.Get(slotBackendID("mod-1", 0))
	require.NoError(t, err, "the non-colliding slot must still be registered")
	assert.Equal(t, "Good Slot", rb.DisplayName)

	// The pre-existing entry must be untouched -- still its original category.
	rb, err = registry.Get(collidingID)
	require.NoError(t, err)
	assert.Equal(t, backendregistry.CategoryXKMS, rb.Category)
	assert.Equal(t, "Pre-existing unrelated backend", rb.DisplayName)
}

// TestPKCS11Service_UnregisterModule_RemovesSlotBackends verifies the
// "token removed" direction end-to-end through the service: unregistering a
// module removes every slot backend it owns from the registry.
func TestPKCS11Service_UnregisterModule_RemovesSlotBackends(t *testing.T) {
	mod := mockModuleInfo("mod-1",
		xkms.PKCS11SlotInfo{SlotID: 0, TokenPresent: true, Label: "Token A"},
	)

	var unregisterCalled bool
	mock := &pkcs11MockManager{
		available: true,
		registerFn: func(libraryPath, displayName string) (string, error) {
			return "mod-1", nil
		},
		getModuleFn: func(moduleID string) (*xkms.PKCS11ModuleInfo, error) {
			return mod, nil
		},
		unregisterFn: func(moduleID string) error {
			unregisterCalled = true
			return nil
		},
	}

	svc := newPKCS11ServiceWithMock(mock)
	registry := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(registry)

	moduleID, err := svc.RegisterModule("/mock/libpkcs11.so", "Mock Module")
	require.NoError(t, err)

	_, err = registry.Get(slotBackendID(moduleID, 0))
	require.NoError(t, err)

	require.NoError(t, svc.UnregisterModule(moduleID))
	assert.True(t, unregisterCalled)

	_, err = registry.Get(slotBackendID(moduleID, 0))
	assert.ErrorIs(t, err, backendregistry.ErrBackendNotFound)
}

// TestPKCS11Service_SyncSlotBackends_NilRegistryIsNoOp verifies that when no
// registry has been configured, RegisterModule still succeeds and neither
// registers nor panics attempting to reach a nil registry.
func TestPKCS11Service_SyncSlotBackends_NilRegistryIsNoOp(t *testing.T) {
	mod := mockModuleInfo("mod-1",
		xkms.PKCS11SlotInfo{SlotID: 0, TokenPresent: true, Label: "Token A"},
	)

	mock := &pkcs11MockManager{
		available: true,
		registerFn: func(libraryPath, displayName string) (string, error) {
			return "mod-1", nil
		},
		getModuleFn: func(moduleID string) (*xkms.PKCS11ModuleInfo, error) {
			return mod, nil
		},
	}

	svc := newPKCS11ServiceWithMock(mock)
	require.Nil(t, svc.registry)

	moduleID, err := svc.RegisterModule("/mock/libpkcs11.so", "Mock Module")
	require.NoError(t, err)
	assert.Equal(t, "mod-1", moduleID)

	require.NoError(t, svc.UnregisterModule(moduleID))
}
