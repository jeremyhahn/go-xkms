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

package backendregistry

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBackendState_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		state    BackendState
		expected string
	}{
		{"uninitialized", StateUninitialized, "uninitialized"},
		{"ready", StateReady, "ready"},
		{"sealed", StateSealed, "sealed"},
		{"locked", StateLocked, "locked"},
		{"error", StateError, "error"},
		{"offline", StateOffline, "offline"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.state.String())
		})
	}
}

func TestBackendState_String_Unknown(t *testing.T) {
	t.Parallel()
	unknownState := BackendState(999)
	assert.Equal(t, "unknown", unknownState.String())

	negativeState := BackendState(-1)
	assert.Equal(t, "unknown", negativeState.String())
}

func TestBackendCategory_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cat      BackendCategory
		expected string
	}{
		{"software", CategorySoftware, "software"},
		{"tpm2", CategoryTPM2, "tpm2"},
		{"pkcs11", CategoryPKCS11, "pkcs11"},
		{"xkms", CategoryXKMS, "xkms"},
		{"phone", CategoryPhone, "phone"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.cat.String())
		})
	}
}

func TestBackendCategory_String_Unknown(t *testing.T) {
	t.Parallel()
	unknown := BackendCategory("nonexistent")
	assert.Equal(t, "unknown", unknown.String())
}

func TestBackendLocation_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		loc      BackendLocation
		expected string
	}{
		{"local", LocationLocal, "local"},
		{"remote", LocationRemote, "remote"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.loc.String())
		})
	}
}

func TestBackendLocation_String_Unknown(t *testing.T) {
	t.Parallel()
	unknown := BackendLocation("cloud")
	assert.Equal(t, "unknown", unknown.String())
}

func TestCapability_String(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cap      Capability
		expected string
	}{
		{"fido2", CapFIDO2, "fido2"},
		{"piv", CapPIV, "piv"},
		{"oath", CapOATH, "oath"},
		{"passwords", CapPasswords, "passwords"},
		{"signing", CapSigning, "signing"},
		{"sealing", CapSealing, "sealing"},
		{"attestation", CapAttestation, "attestation"},
		{"encryption", CapEncryption, "encryption"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, tc.cap.String())
		})
	}
}

func TestCapability_String_Unknown(t *testing.T) {
	t.Parallel()
	unknown := Capability("teleportation")
	assert.Equal(t, "unknown", unknown.String())
}

func TestRegisteredBackend_State(t *testing.T) {
	t.Parallel()

	b := &RegisteredBackend{
		ID:       "test-backend",
		Category: CategorySoftware,
		Location: LocationLocal,
	}

	// Default state should be uninitialized (zero value).
	assert.Equal(t, StateUninitialized, b.State())

	// Set to ready and verify.
	b.SetState(StateReady)
	assert.Equal(t, StateReady, b.State())

	// Set to sealed and verify.
	b.SetState(StateSealed)
	assert.Equal(t, StateSealed, b.State())

	// Set to locked and verify.
	b.SetState(StateLocked)
	assert.Equal(t, StateLocked, b.State())

	// Set to error and verify.
	b.SetState(StateError)
	assert.Equal(t, StateError, b.State())

	// Set to offline and verify.
	b.SetState(StateOffline)
	assert.Equal(t, StateOffline, b.State())
}

func TestRegisteredBackend_State_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	b := &RegisteredBackend{
		ID:       "concurrent-state",
		Category: CategoryTPM2,
		Location: LocationLocal,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			b.SetState(StateReady)
			b.SetState(StateSealed)
		}
	}()

	for i := 0; i < 1000; i++ {
		_ = b.State()
	}
	<-done

	// Final state should be one of the valid states.
	state := b.State()
	assert.True(t, state == StateReady || state == StateSealed,
		"expected ready or sealed, got %s", state.String())
}

func TestRegisteredBackend_HasCapability(t *testing.T) {
	t.Parallel()

	b := &RegisteredBackend{
		ID:       "cap-test",
		Category: CategorySoftware,
		Location: LocationLocal,
		Capabilities: map[Capability]bool{
			CapSigning:    true,
			CapEncryption: true,
			CapFIDO2:      false,
		},
	}

	assert.True(t, b.HasCapability(CapSigning))
	assert.True(t, b.HasCapability(CapEncryption))
	assert.False(t, b.HasCapability(CapFIDO2), "explicitly false capability should return false")
	assert.False(t, b.HasCapability(CapPIV), "absent capability should return false")
	assert.False(t, b.HasCapability(CapAttestation), "absent capability should return false")
}

func TestRegisteredBackend_HasCapability_NilMap(t *testing.T) {
	t.Parallel()

	b := &RegisteredBackend{
		ID:           "nil-caps",
		Category:     CategorySoftware,
		Location:     LocationLocal,
		Capabilities: nil,
	}

	assert.False(t, b.HasCapability(CapSigning))
	assert.False(t, b.HasCapability(CapFIDO2))
	assert.False(t, b.HasCapability(CapEncryption))
}

func TestValidCategories(t *testing.T) {
	t.Parallel()

	expected := []BackendCategory{
		CategorySoftware, CategoryTPM2, CategoryPKCS11, CategoryXKMS, CategoryPhone,
	}
	assert.Equal(t, len(expected), len(ValidCategories),
		"ValidCategories should contain exactly %d entries", len(expected))

	for _, cat := range expected {
		_, ok := ValidCategories[cat]
		assert.True(t, ok, "ValidCategories should contain %q", cat)
	}
}

func TestValidLocations(t *testing.T) {
	t.Parallel()

	expected := []BackendLocation{LocationLocal, LocationRemote}
	assert.Equal(t, len(expected), len(ValidLocations),
		"ValidLocations should contain exactly %d entries", len(expected))

	for _, loc := range expected {
		_, ok := ValidLocations[loc]
		assert.True(t, ok, "ValidLocations should contain %q", loc)
	}
}

func TestValidCapabilities(t *testing.T) {
	t.Parallel()

	expected := []Capability{
		CapFIDO2, CapPIV, CapOATH, CapPasswords,
		CapSigning, CapSealing, CapAttestation, CapEncryption,
	}
	assert.Equal(t, len(expected), len(ValidCapabilities),
		"ValidCapabilities should contain exactly %d entries", len(expected))

	for _, cap := range expected {
		_, ok := ValidCapabilities[cap]
		assert.True(t, ok, "ValidCapabilities should contain %q", cap)
	}
}
