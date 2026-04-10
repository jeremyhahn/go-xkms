//go:build !pkcs11

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

package pkcs11mgr

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_ReturnsStub(t *testing.T) {
	t.Parallel()

	mgr := NewManager()
	require.NotNil(t, mgr)
	_, ok := mgr.(*StubManager)
	assert.True(t, ok, "NewManager should return *StubManager without pkcs11 build tag")
}

func TestNewManager_WithOptions(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	registry := backendregistry.NewMemoryRegistry()

	mgr := NewManager(
		WithLogger(logger),
		WithRegistry(registry),
	)
	require.NotNil(t, mgr)
	_, ok := mgr.(*StubManager)
	assert.True(t, ok, "NewManager should return *StubManager even with options")
}

func TestStubManager_ImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ Manager = (*StubManager)(nil)
}

func TestStubManager_RegisterModule(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	id, err := mgr.RegisterModule("/usr/lib/libpkcs11.so", "test")
	assert.Equal(t, "", id)
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_UnregisterModule(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	err := mgr.UnregisterModule("test-module")
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_RefreshSlots(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	slots, err := mgr.RefreshSlots("test-module")
	assert.Nil(t, slots)
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_GetModule(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	info, err := mgr.GetModule("test-module")
	assert.Nil(t, info)
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_ListModules(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	modules := mgr.ListModules()
	require.NotNil(t, modules, "ListModules should return empty slice, not nil")
	assert.Empty(t, modules)
}

func TestStubManager_OpenSession(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	handle, err := mgr.OpenSession("test-module", 0, "1234")
	assert.Nil(t, handle)
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_CloseSession(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	err := mgr.CloseSession(&SessionHandle{ModuleID: "test", SlotID: 0, Handle: 1})
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_CloseSession_NilHandle(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	err := mgr.CloseSession(nil)
	assert.True(t, errors.Is(err, ErrPKCS11NotCompiled))
}

func TestStubManager_Close(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	err := mgr.Close()
	assert.NoError(t, err, "Close on stub should succeed")
}

func TestStubManager_Close_Idempotent(t *testing.T) {
	t.Parallel()

	mgr := &StubManager{}
	require.NoError(t, mgr.Close())
	require.NoError(t, mgr.Close())
}

func TestErrPKCS11NotCompiled_Message(t *testing.T) {
	t.Parallel()

	assert.Contains(t, ErrPKCS11NotCompiled.Error(), "PKCS#11 support not compiled")
	assert.Contains(t, ErrPKCS11NotCompiled.Error(), "pkcs11mgr:")
	assert.Contains(t, ErrPKCS11NotCompiled.Error(), "-tags pkcs11")
}
