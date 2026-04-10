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

//go:build pkcs11

package keybackend

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// pkcs11LibYKCS11 is the backend type for the YubiKey PKCS#11 module.
	pkcs11LibYKCS11 types.BackendType = "pkcs11-libykcs11"
)

// TestCompositeRegisterPKCS11Backend verifies that a PKCS#11 backend can be
// registered in the composite and discovered via Backend() and Backends().
func TestCompositeRegisterPKCS11Backend(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -8},
		SupportsExport:      true,
		SupportsImport:      true,
	})
	cb.Register(types.BackendTypeSoftware, sw)

	initialCount := len(cb.Backends())

	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -35},
		HardwareBacked:      true,
		SupportsAttestation: true,
	})
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)

	// Backend("pkcs11-libykcs11") returns non-nil.
	got := cb.Backend(pkcs11LibYKCS11)
	require.NotNil(t, got, "Backend(%q) must not be nil after registration", pkcs11LibYKCS11)

	// Backends() includes the new entry.
	allBackends := cb.Backends()
	found := false
	for _, bt := range allBackends {
		if bt == pkcs11LibYKCS11 {
			found = true
			break
		}
	}
	assert.True(t, found, "Backends() must include %q", pkcs11LibYKCS11)

	// Backend count increased by exactly one.
	assert.Equal(t, initialCount+1, len(allBackends),
		"registering pkcs11-libykcs11 should increase backend count by 1")
}

// TestCompositeRegisterPKCS11Backend_NilLookupBeforeRegister verifies that
// looking up a PKCS#11 backend before registration returns nil.
func TestCompositeRegisterPKCS11Backend_NilLookupBeforeRegister(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	got := cb.Backend(pkcs11LibYKCS11)
	assert.Nil(t, got, "Backend(%q) must be nil before registration", pkcs11LibYKCS11)
}

// TestCompositeSetDefaultToPKCS11 verifies that after SetDefault to a PKCS#11
// backend, GenerateCredentialKey routes to that backend instead of software.
func TestCompositeSetDefaultToPKCS11(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7},
	})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -35},
		HardwareBacked:      true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)

	cb.SetDefault(pkcs11LibYKCS11)

	credID := []byte("pkcs11-cred-001")
	handle, pubKey, err := cb.GenerateCredentialKey(-7, credID)
	require.NoError(t, err)
	require.NotNil(t, handle)
	require.NotEmpty(t, pubKey)

	// The PKCS#11 mock must have been called, not the software one.
	assert.Equal(t, int32(1), pkcs11Backend.generateCalled.Load(),
		"PKCS#11 backend GenerateCredentialKey must be called")
	assert.Equal(t, int32(0), sw.generateCalled.Load(),
		"software backend GenerateCredentialKey must not be called")

	// The returned handle must identify the PKCS#11 backend.
	assert.Equal(t, pkcs11LibYKCS11, handle.BackendID(),
		"handle.BackendID() must be %q", pkcs11LibYKCS11)
}

// TestCompositeSetDefaultToPKCS11_ImportAlsoRoutes verifies that ImportPrivateKey
// also routes to the PKCS#11 backend when it is the default.
func TestCompositeSetDefaultToPKCS11_ImportAlsoRoutes(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{SupportsImport: true})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		SupportsImport: true,
		HardwareBacked: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)
	cb.SetDefault(pkcs11LibYKCS11)

	handle, err := cb.ImportPrivateKey([]byte("cred-import"), -7, []byte("pkcs8-data"))
	require.NoError(t, err)

	assert.Equal(t, pkcs11LibYKCS11, handle.BackendID())
	assert.Equal(t, int32(1), pkcs11Backend.importCalled.Load())
	assert.Equal(t, int32(0), sw.importCalled.Load())
}

// TestCompositeSignRoutesToCorrectBackend verifies that Sign routes to the
// PKCS#11 backend when the KeyHandle has BackendID = "pkcs11-libykcs11".
func TestCompositeSignRoutesToCorrectBackend(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		HardwareBacked: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)

	handle := &mockKeyHandle{
		credentialID: []byte("pkcs11-cred-sign"),
		algorithm:    -7,
		backendType:  pkcs11LibYKCS11,
	}

	sig, err := cb.Sign(handle, -7, []byte("challenge-data"))
	require.NoError(t, err)
	assert.Equal(t, "signature-from-"+string(pkcs11LibYKCS11), string(sig))

	assert.Equal(t, int32(1), pkcs11Backend.signCalled.Load(),
		"PKCS#11 backend Sign must be called")
	assert.Equal(t, int32(0), sw.signCalled.Load(),
		"software backend Sign must not be called")
}

// TestCompositeSignRoutesToCorrectBackend_SoftwareHandle verifies that a
// handle targeting "software" still routes to the software backend even when
// PKCS#11 is the default.
func TestCompositeSignRoutesToCorrectBackend_SoftwareHandle(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		HardwareBacked: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)
	cb.SetDefault(pkcs11LibYKCS11)

	handle := &mockKeyHandle{
		credentialID: []byte("sw-cred"),
		algorithm:    -7,
		backendType:  types.BackendTypeSoftware,
	}

	sig, err := cb.Sign(handle, -7, []byte("data"))
	require.NoError(t, err)
	assert.Equal(t, "signature-from-software", string(sig))
	assert.Equal(t, int32(1), sw.signCalled.Load())
	assert.Equal(t, int32(0), pkcs11Backend.signCalled.Load())
}

// TestCompositeDefaultFallsBackToSoftware verifies that setting the default
// to a non-existent PKCS#11 backend causes GenerateCredentialKey to fail, and
// that the software backend remains available for explicit routing.
func TestCompositeDefaultFallsBackToSoftware(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7},
	})
	cb.Register(types.BackendTypeSoftware, sw)

	// SetDefault to a backend that is not registered.
	cb.SetDefault(types.BackendType("pkcs11-nonexistent"))

	// GenerateCredentialKey should fail because the default is missing.
	_, _, err := cb.GenerateCredentialKey(-7, []byte("cred-fallback"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendNotFound),
		"expected ErrBackendNotFound, got %v", err)

	// Software backend was never called.
	assert.Equal(t, int32(0), sw.generateCalled.Load(),
		"software backend must not be called when it is not the default")

	// Direct operations via a software-tagged handle still work.
	handle := &mockKeyHandle{
		credentialID: []byte("sw-cred"),
		algorithm:    -7,
		backendType:  types.BackendTypeSoftware,
	}
	sig, err := cb.Sign(handle, -7, []byte("data"))
	require.NoError(t, err)
	assert.NotEmpty(t, sig)
	assert.Equal(t, int32(1), sw.signCalled.Load())
}

// TestCompositeDefaultFallsBackToSoftware_RestoreDefault verifies that after
// a failed SetDefault, restoring the default to software recovers generation.
func TestCompositeDefaultFallsBackToSoftware_RestoreDefault(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	cb.Register(types.BackendTypeSoftware, sw)

	cb.SetDefault(types.BackendType("pkcs11-nonexistent"))
	_, _, err := cb.GenerateCredentialKey(-7, []byte("cred"))
	require.Error(t, err)

	// Restore default.
	cb.SetDefault(types.BackendTypeSoftware)

	handle, pubKey, err := cb.GenerateCredentialKey(-7, []byte("cred-restored"))
	require.NoError(t, err)
	require.NotNil(t, handle)
	require.NotEmpty(t, pubKey)
	assert.Equal(t, types.BackendTypeSoftware, handle.BackendID())
}

// TestCompositeUnregisterPKCS11 verifies that unregistering the PKCS#11 backend
// removes it from the composite and causes operations targeting it to fail.
func TestCompositeUnregisterPKCS11(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		HardwareBacked: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)
	cb.SetDefault(pkcs11LibYKCS11)

	// Verify it is registered.
	require.NotNil(t, cb.Backend(pkcs11LibYKCS11))

	// Unregister.
	cb.Unregister(pkcs11LibYKCS11)

	// Backend lookup returns nil.
	assert.Nil(t, cb.Backend(pkcs11LibYKCS11),
		"Backend(%q) must be nil after Unregister", pkcs11LibYKCS11)

	// Backends() no longer includes it.
	for _, bt := range cb.Backends() {
		assert.NotEqual(t, pkcs11LibYKCS11, bt,
			"Backends() must not include %q after Unregister", pkcs11LibYKCS11)
	}

	// GenerateCredentialKey fails because the default is now missing.
	_, _, err := cb.GenerateCredentialKey(-7, []byte("cred-after-unregister"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendNotFound),
		"expected ErrBackendNotFound, got %v", err)
}

// TestCompositeUnregisterPKCS11_SignWithStaleHandle verifies that Sign fails
// when the PKCS#11 backend has been unregistered but a handle still references it.
func TestCompositeUnregisterPKCS11_SignWithStaleHandle(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		HardwareBacked: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)

	// Create a handle targeting PKCS#11 before unregistration.
	handle := &mockKeyHandle{
		credentialID: []byte("stale-cred"),
		algorithm:    -7,
		backendType:  pkcs11LibYKCS11,
	}

	cb.Unregister(pkcs11LibYKCS11)

	_, err := cb.Sign(handle, -7, []byte("data"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendNotFound))
}

// TestCompositeCapabilitiesMergePKCS11 verifies that capabilities from a
// PKCS#11 backend are correctly merged with those from a software backend.
func TestCompositeCapabilitiesMergePKCS11(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -8},
		SupportsExport:      true,
		SupportsImport:      true,
		HardwareBacked:      false,
		SupportsAttestation: false,
	})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -35, -36},
		SupportsExport:      false,
		SupportsImport:      false,
		HardwareBacked:      true,
		SupportsAttestation: true,
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)

	caps := cb.Capabilities()

	// Algorithms are the deduplicated union: -7, -8, -35, -36.
	algSet := make(map[int]struct{})
	for _, alg := range caps.SupportedAlgorithms {
		algSet[alg] = struct{}{}
	}
	assert.Len(t, algSet, 4, "expected 4 unique algorithms in the merged set")

	for _, want := range []int{-7, -8, -35, -36} {
		_, ok := algSet[want]
		assert.True(t, ok, "merged SupportedAlgorithms must include %d", want)
	}

	// Boolean OR across backends.
	assert.True(t, caps.HardwareBacked, "HardwareBacked should be true (PKCS#11 is hardware-backed)")
	assert.True(t, caps.SupportsExport, "SupportsExport should be true (software supports export)")
	assert.True(t, caps.SupportsImport, "SupportsImport should be true (software supports import)")
	assert.True(t, caps.SupportsAttestation, "SupportsAttestation should be true (PKCS#11 supports attestation)")
}

// TestCompositeCapabilitiesMergePKCS11_NoDuplicateAlgorithms verifies that
// overlapping algorithm IDs between software and PKCS#11 are deduplicated.
func TestCompositeCapabilitiesMergePKCS11_NoDuplicateAlgorithms(t *testing.T) {
	cb := NewCompositeBackend(types.BackendTypeSoftware)

	sw := newMockBackend("software", FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -8, -35},
	})
	pkcs11Backend := newMockBackend(string(pkcs11LibYKCS11), FIDO2KeyCapabilities{
		SupportedAlgorithms: []int{-7, -35, -36},
	})

	cb.Register(types.BackendTypeSoftware, sw)
	cb.Register(pkcs11LibYKCS11, pkcs11Backend)

	caps := cb.Capabilities()

	// Count occurrences of each algorithm.
	algCount := make(map[int]int)
	for _, alg := range caps.SupportedAlgorithms {
		algCount[alg]++
	}

	for alg, count := range algCount {
		assert.Equal(t, 1, count, "algorithm %d appears %d times, expected 1", alg, count)
	}
	assert.Len(t, caps.SupportedAlgorithms, 4,
		"expected exactly 4 unique algorithms: -7, -8, -35, -36")
}
