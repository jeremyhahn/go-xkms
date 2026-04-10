// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package services

import (
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/manager"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConnect_PassesSOPIN verifies that PKCS11Service.Connect forwards the
// Security Officer PIN (management key) through to the underlying manager.
// This is required for YubiKey PIV slots where key generation demands
// CKU_SO authentication rather than the user PIN.
func TestConnect_PassesSOPIN(t *testing.T) {
	var capturedUserPin, capturedSoPin string
	var called atomic.Bool

	mock := &pkcs11MockManager{
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true, Label: "YubiKey PIV"},
				},
			}, nil
		},
		connectFn: func(_ string, _ uint, userPin, soPin string) (manager.Backend, error) {
			capturedUserPin = userPin
			capturedSoPin = soPin
			called.Store(true)
			return nil, nil
		},
	}
	svc := newPKCS11ServiceWithMock(mock)

	err := svc.Connect("mod-1", 0, "123456", "0102030405060708")
	require.NoError(t, err)
	require.True(t, called.Load(), "manager.Connect was not called")
	assert.Equal(t, "123456", capturedUserPin)
	assert.Equal(t, "0102030405060708", capturedSoPin)
}

// TestTestConnection_ReusesRegisteredModule verifies that a successful
// TestConnection retains the module registration so a subsequent
// RegisterModule call returns the same module ID without paying the
// C_Initialize cost a second time.
func TestTestConnection_ReusesRegisteredModule(t *testing.T) {
	var registerCount atomic.Int32

	mock := &pkcs11MockManager{
		registerFn: func(libraryPath, _ string) (string, error) {
			registerCount.Add(1)
			return "mod-1", nil
		},
		getModuleFn: func(_ string) (*manager.ModuleInfo, error) {
			return &manager.ModuleInfo{
				ID: "mod-1",
				Slots: []manager.SlotInfo{
					{SlotID: 0, TokenPresent: true, Initialized: true, Label: "YubiKey PIV"},
				},
			}, nil
		},
		testLoginFn: func(_ string, _ uint, _ string) error {
			return nil
		},
		unregisterFn: func(_ string) error {
			t.Fatal("UnregisterModule must not be called on TestConnection success")
			return nil
		},
	}
	// Redirect HOME/XDG to a tmp dir so persistModule never touches the real user config.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))

	svc := newPKCS11ServiceWithMock(mock)

	// Use a non-SoftHSM path to skip the softhsm2 config side effect.
	libPath := "/tmp/unit-test-libykcs11-nonexistent.so"
	require.NoError(t, svc.TestConnection(libPath, 0, "123456"))
	assert.Equal(t, int32(1), registerCount.Load())

	// Subsequent RegisterModule for the same library should reuse the
	// existing registration — manager.RegisterModule should NOT be called again.
	moduleID, err := svc.RegisterModule(libPath, "Reused Module")
	require.NoError(t, err)
	assert.Equal(t, "mod-1", moduleID)
	assert.Equal(t, int32(1), registerCount.Load(),
		"RegisterModule should reuse the pre-tested module without re-initializing")
}
