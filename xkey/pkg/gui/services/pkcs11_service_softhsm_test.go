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

package services

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/backendregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive PKCS11Service against a real SoftHSM2 token created
// inside t.TempDir(), following the isolation pattern established by
// pkg/pkcs11/manager's SoftHSM tests: SOFTHSM2_CONF is redirected per test
// so nothing is written outside the test's temporary directory and the
// host's own SoftHSM token store is never read or modified.

const (
	softHSMTestSOPIN   = "87654321"
	softHSMTestUserPIN = "1234"
)

// softhsmLibrary locates libsofthsm2.so, failing loudly if it is not
// installed: the pkcs11 build tag is only used in environments
// (devcontainer, CI) where SoftHSM2 is a declared dependency.
func softhsmLibrary(t *testing.T) string {
	t.Helper()

	if env := os.Getenv("SOFTHSM2_LIB"); env != "" {
		if _, err := os.Stat(env); err == nil {
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
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}

	t.Fatalf("libsofthsm2.so not found in %v; install softhsm2 or set SOFTHSM2_LIB", candidates)
	return ""
}

// newIsolatedPKCS11Service builds a PKCS11Service wrapping the real sdk/go
// manager, backed by a private SoftHSM token store under t.TempDir(), with
// a fresh MemoryRegistry wired in via SetRegistry. The returned slot holds
// an uninitialized token, which is the state a freshly inserted device
// presents.
func newIsolatedPKCS11Service(t *testing.T) (*PKCS11Service, *backendregistry.MemoryRegistry, string, uint) {
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

	// t.Setenv restores the previous value automatically and forbids
	// parallel tests, which is exactly the isolation this needs.
	t.Setenv("SOFTHSM2_CONF", conf)

	svc := NewPKCS11Service()
	svc.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(registry)
	t.Cleanup(func() { _ = svc.Close() })

	moduleID, err := svc.RegisterModule(lib, "SoftHSM2")
	require.NoError(t, err, "registering the SoftHSM module must succeed")

	slots, err := svc.GetModuleSlots(moduleID)
	require.NoError(t, err)
	require.NotEmpty(t, slots, "SoftHSM always exposes at least one free slot")

	return svc, registry, moduleID, slots[0].SlotID
}

// TestPKCS11Service_RegisterModule_RegistersSlotBackend verifies that
// registering a module with a SoftHSM2 slot auto-registers a per-slot
// backend in the registry, carrying token metadata (manufacturer, firmware
// version) even before the token is initialized -- the state a freshly
// inserted device presents.
func TestPKCS11Service_RegisterModule_RegistersSlotBackend(t *testing.T) {
	_, registry, moduleID, slotID := newIsolatedPKCS11Service(t)

	backendID := slotBackendID(moduleID, slotID)
	rb, err := registry.Get(backendID)
	require.NoError(t, err, "RegisterModule must register a backend for the present token")

	assert.Equal(t, backendregistry.CategoryPKCS11, rb.Category)
	assert.Equal(t, backendregistry.LocationLocal, rb.Location)
	assert.Equal(t, backendregistry.StateReady, rb.State())
	assert.True(t, rb.HasCapability(backendregistry.CapSigning))
	assert.True(t, rb.HasCapability(backendregistry.CapEncryption))
	assert.True(t, rb.HasCapability(backendregistry.CapPIV))
	assert.False(t, rb.HasCapability(backendregistry.CapFIDO2),
		"PKCS#11 slot backends never advertise FIDO2")

	assert.Equal(t, moduleID, rb.Metadata["module_id"])
	assert.Equal(t, fmt.Sprintf("%d", slotID), rb.Metadata["slot_id"])
	assert.Contains(t, rb.Metadata["token_manufacturer"], "SoftHSM")
	assert.NotEmpty(t, rb.Metadata["firmware_version"])
}

// TestPKCS11Service_InitializeToken_UpdatesSlotBackendMetadata verifies
// that labeling and initializing a token immediately updates the slot
// backend's metadata (label, serial) in the registry, without requiring a
// separate RefreshSlots call.
func TestPKCS11Service_InitializeToken_UpdatesSlotBackendMetadata(t *testing.T) {
	svc, registry, moduleID, slotID := newIsolatedPKCS11Service(t)

	err := svc.InitializeToken(moduleID, slotID, "xkey-unit-token", softHSMTestSOPIN, softHSMTestUserPIN)
	require.NoError(t, err)

	backendID := slotBackendID(moduleID, slotID)
	rb, err := registry.Get(backendID)
	require.NoError(t, err)

	assert.Equal(t, "xkey-unit-token", rb.DisplayName)
	assert.Equal(t, "xkey-unit-token", rb.Metadata["token_label"])
	assert.NotEmpty(t, rb.Metadata["token_serial"])
}

// TestPKCS11Service_UnregisterModule_RemovesBackendWhenTokenNotPresent
// verifies the "token removed" direction against the real manager: once a
// module is unregistered, its slot backends must be dropped from the
// registry rather than leaving stale entries behind. UnregisterModule
// stands in for a token being pulled at runtime, since SoftHSM2 does not
// support ejecting a token from a running process; from the registry's
// point of view a slot backend exists only while its module reports the
// token present, and both paths remove it the same way.
func TestPKCS11Service_UnregisterModule_RemovesBackendWhenTokenNotPresent(t *testing.T) {
	svc, registry, moduleID, slotID := newIsolatedPKCS11Service(t)

	backendID := slotBackendID(moduleID, slotID)
	_, err := registry.Get(backendID)
	require.NoError(t, err, "the slot backend must exist while the token is present")

	require.NoError(t, svc.UnregisterModule(moduleID))

	_, err = registry.Get(backendID)
	assert.ErrorIs(t, err, backendregistry.ErrBackendNotFound,
		"unregistering the module must remove its slot backends")
}

// TestPKCS11Service_RegisterModule_InvalidLibraryPath_LeavesRegistryEmpty is
// the error path counterpart of RegistersSlotBackend above: a library path
// that never reaches slot enumeration (the real-hardware equivalent of a
// slot that fails to open) must surface an error and leave the registry
// untouched, rather than registering a partial or zero-valued backend.
func TestPKCS11Service_RegisterModule_InvalidLibraryPath_LeavesRegistryEmpty(t *testing.T) {
	svc := NewPKCS11Service()
	svc.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	registry := backendregistry.NewMemoryRegistry()
	svc.SetRegistry(registry)
	t.Cleanup(func() { _ = svc.Close() })

	dir := t.TempDir()
	badLib := filepath.Join(dir, "does-not-exist.so")

	moduleID, err := svc.RegisterModule(badLib, "bad module")
	require.Error(t, err)
	assert.Empty(t, moduleID)

	assert.Empty(t, registry.List(), "a failed module registration must not leave any slot backend behind")
}

// TestPKCS11Service_RegisterModule_SkipsRegistryOperationsWithoutRegistry
// verifies that syncSlotBackends is a no-op when no registry is configured,
// so PKCS11Service remains usable without the GUI wiring a registry in.
func TestPKCS11Service_RegisterModule_SkipsRegistryOperationsWithoutRegistry(t *testing.T) {
	lib := softhsmLibrary(t)

	root := t.TempDir()
	tokenDir := filepath.Join(root, "tokens")
	require.NoError(t, os.Mkdir(tokenDir, 0o750))
	conf := filepath.Join(root, "softhsm2.conf")
	contents := fmt.Sprintf(
		"directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n",
		tokenDir)
	require.NoError(t, os.WriteFile(conf, []byte(contents), 0o600))
	t.Setenv("SOFTHSM2_CONF", conf)

	svc := NewPKCS11Service()
	svc.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { _ = svc.Close() })

	// No SetRegistry call: svc.registry stays nil.
	moduleID, err := svc.RegisterModule(lib, "SoftHSM2")
	require.NoError(t, err, "registration must succeed even without a registry configured")
	assert.NotEmpty(t, moduleID)
}
