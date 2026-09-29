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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file targets *XKMSService methods that are only reachable through
// direct method calls (as opposed to the package-level free functions of the
// same name, which already have coverage): SetSPIFFETrustDomain/
// SPIFFETrustDomain, TenantService, LookupBackend, LookupDefaultBackend,
// BackendNames, CanSealDirect, and the
// package-level UnregisterBackend.

func TestXKMSService_SetSPIFFETrustDomain(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	assert.Empty(t, svc.SPIFFETrustDomain())

	svc.SetSPIFFETrustDomain("spiffe://example.org")
	assert.Equal(t, "spiffe://example.org", svc.SPIFFETrustDomain())

	// Empty trust domain disables SPIFFE SAN synthesis.
	svc.SetSPIFFETrustDomain("")
	assert.Empty(t, svc.SPIFFETrustDomain())
}

func TestXKMSService_TenantService_NilByDefault(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	assert.Nil(t, svc.TenantService())
}

func TestXKMSService_TenantService_ReturnsWiredInstance(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	fake := &fakeTenantServicer{}
	svc.SetTenantService(fake)

	assert.Same(t, fake, svc.TenantService())
}

func TestXKMSService_LookupBackend_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, err := svc.LookupBackend("software")
	require.NoError(t, err)
	assert.Same(t, software, b)
}

func TestXKMSService_LookupBackend_NotFound(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.LookupBackend("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestXKMSService_LookupBackend_InvalidName(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.LookupBackend("../evil")
	require.Error(t, err)
}

func TestXKMSService_LookupDefaultBackend_Success(t *testing.T) {
	software, _ := setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	b, err := svc.LookupDefaultBackend()
	require.NoError(t, err)
	assert.Same(t, software, b)
}

func TestXKMSService_LookupDefaultBackend_NoDefaultConfigured(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	software := newMockKeyStore("software")
	err := Initialize(&ServiceConfig{
		Backends: map[string]Backend{"software": software},
		// DefaultBackend left empty is impossible via Initialize (it picks
		// the first backend), so exercise the empty-default branch directly
		// by clearing it on the singleton after construction.
	})
	require.NoError(t, err)

	svc, err := Get()
	require.NoError(t, err)
	svc.defaultBackend = ""

	_, err = svc.LookupDefaultBackend()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoDefaultBackend)
}

func TestXKMSService_LookupDefaultBackend_DefaultMissingFromMap(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// Simulate the default backend having been unregistered out from under
	// the service without clearing defaultBackend.
	svc.mu.Lock()
	delete(svc.backends, svc.defaultBackend)
	svc.mu.Unlock()

	_, err = svc.LookupDefaultBackend()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestXKMSService_BackendNames(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	names := svc.BackendNames()
	assert.ElementsMatch(t, []string{"software", "pkcs11"}, names)
}

func TestXKMSService_BackendNames_Empty(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	software := newMockKeyStore("software")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": software},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, err := Get()
	require.NoError(t, err)
	svc.mu.Lock()
	svc.backends = map[string]Backend{}
	svc.mu.Unlock()

	assert.Empty(t, svc.BackendNames())
}

func TestXKMSService_CanSealDirect_ExplicitBackend(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	sealer := newMockKeyStoreWithSealer("software", "software")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": sealer},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, err := Get()
	require.NoError(t, err)

	assert.True(t, svc.CanSealDirect("software"))
}

func TestXKMSService_CanSealDirect_DefaultBackend(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	sealer := newMockKeyStoreWithSealer("software", "software")
	err := Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": sealer},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, err := Get()
	require.NoError(t, err)

	// No backend name argument -> falls back to the default backend.
	assert.True(t, svc.CanSealDirect())
}

func TestXKMSService_CanSealDirect_UnknownBackendReturnsFalse(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	// mockKeyStore (plain, no sealer configured) cannot seal.
	assert.False(t, svc.CanSealDirect())
	assert.False(t, svc.CanSealDirect("nonexistent"))
}

func TestUnregisterBackend_RemovesRegisteredBackend(t *testing.T) {
	setupService(t)

	_, err := GetBackend("software")
	require.NoError(t, err)

	UnregisterBackend("software")

	_, err = GetBackend("software")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackendNotFound)
}

func TestUnregisterBackend_NotInitialized_NoPanic(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	// Must be a safe no-op when the service singleton has not been
	// initialized.
	UnregisterBackend("software")
}

func TestUnregisterBackend_UnknownName_NoPanic(t *testing.T) {
	setupService(t)

	// Deleting a name that was never registered is a harmless no-op.
	UnregisterBackend("does-not-exist")
}
