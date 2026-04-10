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

//go:build integration && pkcs11

package keybackend

import (
	"os"
	"testing"

	pkcs11backend "github.com/jeremyhahn/go-xkms/pkg/backend/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	pivpkcs11 "github.com/jeremyhahn/go-xkms/pkg/pivcert/pkcs11"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	registerBackend(backendEntry{
		name:     "pkcs11",
		skip:     skipIfNoSoftHSM,
		adapter:  newPKCS11Adapter,
		hardware: true,
	})
}

// skipIfNoSoftHSM skips the test if SoftHSM is not available.
func skipIfNoSoftHSM(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/lib/softhsm/libsofthsm2.so"); err != nil {
		t.Skip("SoftHSM not available")
	}
}

// newPKCS11Adapter creates a BackendAdapter backed by a real PKCS#11 backend using SoftHSM.
func newPKCS11Adapter(t *testing.T) *BackendAdapter {
	t.Helper()
	config := &pkcs11backend.Config{
		Library:     "/usr/lib/softhsm/libsofthsm2.so",
		TokenLabel:  "e2e-piv-test",
		PIN:         "123456",
		KeyStorage:  storage.NewMemory(),
		CertStorage: storage.NewMemory(),
	}
	backend, err := pkcs11backend.NewBackend(config)
	require.NoError(t, err)
	err = backend.Login()
	require.NoError(t, err)
	t.Cleanup(func() { backend.Close() })
	return NewBackendAdapter(backend, types.BackendTypePKCS11)
}

// ---------------------------------------------------------------------------
// SlotModel helpers
// ---------------------------------------------------------------------------

// newPKCS11AdapterWithSlotModel creates a BackendAdapter backed by SoftHSM
// with a PIVSlotModel attached for auto-allocation testing.
func newPKCS11AdapterWithSlotModel(t *testing.T) (*BackendAdapter, pivcert.SlotModel) {
	t.Helper()
	skipIfNoSoftHSM(t)

	adapter := newPKCS11Adapter(t)

	// Extract the session pool from the PKCS#11 backend via type assertion.
	p11Backend, ok := adapter.provider.(*pkcs11backend.Backend)
	require.True(t, ok, "adapter.provider should be *pkcs11backend.Backend")

	pool := p11Backend.Pool()
	require.NotNil(t, pool, "PKCS#11 backend pool must not be nil after Login")

	sm, err := pivpkcs11.NewPIVSlotModel(pool)
	require.NoError(t, err, "NewPIVSlotModel should succeed against SoftHSM")

	adapter.SetSlotModel(sm)
	return adapter, sm
}

// ---------------------------------------------------------------------------
// Test: SlotModel_AutoAllocation
// ---------------------------------------------------------------------------

func TestPKCS11_SlotModel_AutoAllocation(t *testing.T) {
	skipIfNoSoftHSM(t)

	adapter, sm := newPKCS11AdapterWithSlotModel(t)

	// Record available slots before generating credentials.
	availBefore, err := sm.AvailableSlots()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(availBefore), 2,
		"need at least 2 available slots for this test")

	// Generate first credential key — should auto-allocate a retired slot.
	credID1 := randomCredentialID(t)
	handle1, pubCOSE1, err := adapter.GenerateCredentialKey(COSEAlgES256, credID1)
	require.NoError(t, err)
	require.NotNil(t, handle1)
	require.NotEmpty(t, pubCOSE1)
	t.Cleanup(func() { _ = adapter.DeleteKey(handle1) })

	// Generate second credential key — should allocate a DIFFERENT slot.
	credID2 := randomCredentialID(t)
	handle2, pubCOSE2, err := adapter.GenerateCredentialKey(COSEAlgES256, credID2)
	require.NoError(t, err)
	require.NotNil(t, handle2)
	require.NotEmpty(t, pubCOSE2)
	t.Cleanup(func() { _ = adapter.DeleteKey(handle2) })

	// Both credentials must be independently signable.
	testData := []byte("auto-allocation signing test")

	sig1, err := adapter.Sign(handle1, COSEAlgES256, testData)
	require.NoError(t, err)
	require.NotEmpty(t, sig1)
	verifySignature(t, pubCOSE1, COSEAlgES256, testData, sig1)

	sig2, err := adapter.Sign(handle2, COSEAlgES256, testData)
	require.NoError(t, err)
	require.NotEmpty(t, sig2)
	verifySignature(t, pubCOSE2, COSEAlgES256, testData, sig2)

	// After generation + auto-refresh, at least 2 more slots should be occupied.
	availAfter, err := sm.AvailableSlots()
	require.NoError(t, err)
	assert.LessOrEqual(t, len(availAfter), len(availBefore)-2,
		"generating 2 credential keys should occupy at least 2 more slots")
}

// ---------------------------------------------------------------------------
// Test: SlotModel_DeleteFreesSlot
// ---------------------------------------------------------------------------

func TestPKCS11_SlotModel_DeleteFreesSlot(t *testing.T) {
	skipIfNoSoftHSM(t)

	adapter, sm := newPKCS11AdapterWithSlotModel(t)

	// Generate a credential key (auto-allocated into a slot).
	credID := randomCredentialID(t)
	handle, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Count available slots after generation.
	availAfterGen, err := sm.AvailableSlots()
	require.NoError(t, err)

	// Delete the key.
	err = adapter.DeleteKey(handle)
	require.NoError(t, err)

	// Refresh the slot model after deletion.
	err = sm.Refresh()
	require.NoError(t, err)

	// Count available slots after deletion — should be 1 more.
	availAfterDel, err := sm.AvailableSlots()
	require.NoError(t, err)
	assert.Equal(t, len(availAfterGen)+1, len(availAfterDel),
		"deleting a credential key should free exactly 1 slot")
}

// ---------------------------------------------------------------------------
// Test: SlotModel_OccupancyTracking
// ---------------------------------------------------------------------------

func TestPKCS11_SlotModel_OccupancyTracking(t *testing.T) {
	skipIfNoSoftHSM(t)

	adapter, sm := newPKCS11AdapterWithSlotModel(t)

	// The SoftHSM e2e-piv-test token may have pre-existing keys from the
	// setup script. Verify the slot model detects at least the currently
	// occupied slots.
	occupiedBefore, err := sm.OccupiedSlots()
	require.NoError(t, err)

	// All available slots reported must not appear in occupied.
	availBefore, err := sm.AvailableSlots()
	require.NoError(t, err)

	occupiedSet := make(map[pivcert.PIVSlot]struct{}, len(occupiedBefore))
	for _, s := range occupiedBefore {
		occupiedSet[s] = struct{}{}
	}
	for _, s := range availBefore {
		_, conflict := occupiedSet[s]
		assert.False(t, conflict,
			"slot %s reported as both available and occupied", s)
	}

	// Total slots = occupied + available.
	allSlots := sm.AllSlots()
	assert.Equal(t, len(allSlots), len(occupiedBefore)+len(availBefore),
		"occupied + available must equal total slot count")

	// Generate a key with explicit PIVSlot via the provider directly.
	// Use a retired slot that is currently available.
	require.NotEmpty(t, availBefore, "need at least 1 available slot")
	targetSlot := availBefore[0]

	// Verify slot is not occupied before generation.
	isOccBefore, err := sm.IsOccupied(targetSlot)
	require.NoError(t, err)
	assert.False(t, isOccBefore, "target slot %s should be available before generation", targetSlot)

	// Generate a credential key using the adapter (will auto-allocate).
	credID := randomCredentialID(t)
	handle, _, err := adapter.GenerateCredentialKey(COSEAlgES256, credID)
	require.NoError(t, err)
	require.NotNil(t, handle)
	t.Cleanup(func() { _ = adapter.DeleteKey(handle) })

	// Refresh and verify the allocated slot is now occupied.
	err = sm.Refresh()
	require.NoError(t, err)

	occupiedAfter, err := sm.OccupiedSlots()
	require.NoError(t, err)
	assert.Equal(t, len(occupiedBefore)+1, len(occupiedAfter),
		"occupied slot count should increase by 1 after key generation")

	// Verify SlotOccupancy returns detailed info for an occupied slot.
	occupiedAfterSet := make(map[pivcert.PIVSlot]struct{}, len(occupiedAfter))
	for _, s := range occupiedAfter {
		occupiedAfterSet[s] = struct{}{}
	}

	// Find the newly occupied slot (present in after but not before).
	var newlyOccupied pivcert.PIVSlot
	for _, s := range occupiedAfter {
		if _, wasBefore := occupiedSet[s]; !wasBefore {
			newlyOccupied = s
			break
		}
	}
	require.NotEmpty(t, string(newlyOccupied),
		"should find exactly 1 newly occupied slot")

	info, err := sm.SlotOccupancy(newlyOccupied)
	require.NoError(t, err)
	assert.True(t, info.Occupied, "SlotOccupancy.Occupied must be true for generated key")
	assert.NotEmpty(t, info.Name, "SlotOccupancy.Name must not be empty")
	assert.NotEmpty(t, info.KeyAlgorithm, "SlotOccupancy.KeyAlgorithm must not be empty for occupied slot")
}
