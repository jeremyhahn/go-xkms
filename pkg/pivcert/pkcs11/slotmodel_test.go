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

package pkcs11

import (
	"encoding/asn1"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	p11 "github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	slotModelSoftHSMLib   = "/usr/lib/softhsm/libsofthsm2.so"
	slotModelSoftHSMToken = "e2e-piv-test"
	slotModelSoftHSMPIN   = "123456"
)

// skipIfNoSoftHSMSlotModel skips when SoftHSM is not installed.
// Named distinctly to avoid redeclaration with the integration test file.
func skipIfNoSoftHSMSlotModel(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(slotModelSoftHSMLib); err != nil {
		t.Skip("SoftHSM not available at", slotModelSoftHSMLib)
	}
}

// newSlotModelTestPool creates a standalonePool for unit tests against SoftHSM.
func newSlotModelTestPool(t *testing.T) *standalonePool {
	t.Helper()

	ctx := p11.New(slotModelSoftHSMLib)
	require.NotNil(t, ctx, "load SoftHSM library")

	err := ctx.Initialize()
	if err != nil {
		// Already initialized is fine in a multi-test process.
		if !isPKCS11Error(err, p11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			t.Fatalf("PKCS#11 Initialize: %v", err)
		}
	}

	cfg := &pivcert.PKCS11StorageConfig{
		LibraryPath: slotModelSoftHSMLib,
		TokenLabel:  slotModelSoftHSMToken,
		PIN:         slotModelSoftHSMPIN,
		SlotID:      -1,
	}
	slotID, err := resolveSlot(ctx, cfg)
	require.NoError(t, err, "resolve SoftHSM slot")

	pool, err := newSessionPool(ctx, slotID, slotModelSoftHSMPIN, 2)
	require.NoError(t, err, "create session pool")

	t.Cleanup(func() {
		pool.Close()
		ctx.Finalize()
		ctx.Destroy()
	})

	return pool
}

// parseOIDString converts a dotted OID string (e.g., "1.2.840.10045.3.1.7")
// to an asn1.ObjectIdentifier.
func parseOIDString(s string) asn1.ObjectIdentifier {
	parts := strings.Split(s, ".")
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		oid[i] = v
	}
	return oid
}

// TestPIVSlotModel_NilPool verifies that NewPIVSlotModel rejects a nil pool.
func TestPIVSlotModel_NilPool(t *testing.T) {
	_, err := NewPIVSlotModel(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, pivcert.ErrInvalidConfig)
}

// TestPIVSlotModel_AllSlots verifies that AllSlots returns the full 25-slot set.
func TestPIVSlotModel_AllSlots(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	all := model.AllSlots()
	assert.Len(t, all, 25, "AllSlots must return 25 PIV slots (4 primary + 1 attestation + 20 retired)")
}

// TestPIVSlotModel_Refresh_FindsPreloadedKeys verifies that Refresh discovers
// the pre-provisioned PIV keys on the SoftHSM e2e-piv-test token. The token
// has private keys with CKA_IDs 0x01-0x04 mapped to slots 9a, 9c, 9d, 9e.
func TestPIVSlotModel_Refresh_FindsPreloadedKeys(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	occupied, err := model.OccupiedSlots()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(occupied), 4,
		"SoftHSM e2e-piv-test token should have at least 4 occupied slots (9a-9e)")
}

// TestPIVSlotModel_IsOccupied checks known-occupied and likely-free slots.
func TestPIVSlotModel_IsOccupied(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	// Slot 9a (CKA_ID 0x01) should be occupied.
	occ, err := model.IsOccupied(pivcert.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.True(t, occ, "slot 9a must be occupied on e2e-piv-test token")

	// Invalid slot must return error.
	_, err = model.IsOccupied(pivcert.PIVSlot("zz"))
	assert.ErrorIs(t, err, pivcert.ErrInvalidSlot)
}

// TestPIVSlotModel_AvailableSlots verifies count consistency.
func TestPIVSlotModel_AvailableSlots(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	all := model.AllSlots()
	available, err := model.AvailableSlots()
	require.NoError(t, err)
	occupied, err := model.OccupiedSlots()
	require.NoError(t, err)

	assert.Equal(t, len(all), len(available)+len(occupied),
		"AllSlots = AvailableSlots + OccupiedSlots")
}

// TestPIVSlotModel_NextAvailable_PrefersRetired verifies that NextAvailable
// returns a retired slot (82-95) rather than a primary slot when retired slots
// are free.
func TestPIVSlotModel_NextAvailable_PrefersRetired(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	slot, err := model.NextAvailable()
	require.NoError(t, err)

	assert.True(t, slot.IsRetiredSlot(),
		"NextAvailable should prefer retired slots; got %s", slot)
}

// TestPIVSlotModel_SlotOccupancy verifies occupancy info for a known-occupied
// slot (9a) and a known-free slot.
func TestPIVSlotModel_SlotOccupancy(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	// Occupied slot 9a.
	info, err := model.SlotOccupancy(pivcert.PIVSlotAuthentication)
	require.NoError(t, err)
	assert.Equal(t, pivcert.PIVSlotAuthentication, info.Slot)
	assert.Equal(t, "PIV Authentication", info.Name)
	assert.True(t, info.Occupied, "slot 9a must be occupied")
	assert.NotEmpty(t, info.KeyAlgorithm, "occupied slot must report an algorithm")
	assert.NotEmpty(t, info.Description)

	// Invalid slot.
	_, err = model.SlotOccupancy(pivcert.PIVSlot("zz"))
	assert.ErrorIs(t, err, pivcert.ErrInvalidSlot)
}

// TestPIVSlotModel_SlotOccupancy_FreeSlot verifies that an unoccupied slot
// reports correctly.
func TestPIVSlotModel_SlotOccupancy_FreeSlot(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	// Find a free slot to test.
	available, err := model.AvailableSlots()
	require.NoError(t, err)
	if len(available) == 0 {
		t.Skip("all slots occupied, cannot test free slot occupancy")
	}

	info, err := model.SlotOccupancy(available[0])
	require.NoError(t, err)
	assert.False(t, info.Occupied, "available slot should not be occupied")
	assert.Empty(t, info.KeyAlgorithm, "free slot should have no algorithm")
	assert.False(t, info.HasCert, "free slot should have no certificate")
}

// TestPIVSlotModel_Refresh_Idempotent verifies that calling Refresh multiple
// times produces consistent results.
func TestPIVSlotModel_Refresh_Idempotent(t *testing.T) {
	skipIfNoSoftHSMSlotModel(t)

	pool := newSlotModelTestPool(t)
	model, err := NewPIVSlotModel(pool)
	require.NoError(t, err)

	occ1, err := model.OccupiedSlots()
	require.NoError(t, err)

	require.NoError(t, model.Refresh())

	occ2, err := model.OccupiedSlots()
	require.NoError(t, err)

	assert.Equal(t, len(occ1), len(occ2), "Refresh must be idempotent")
}

// TestDecodeCKKeyType verifies the CKA_KEY_TYPE byte-to-uint decoder.
func TestDecodeCKKeyType(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  uint
	}{
		{"empty", nil, ^uint(0)},
		{"CKK_RSA single byte", []byte{0x00}, p11.CKK_RSA},
		{"CKK_EC single byte", []byte{0x03}, p11.CKK_EC},
		{"CKK_RSA multi-byte", []byte{0x00, 0x00, 0x00, 0x00}, p11.CKK_RSA},
		{"CKK_EC multi-byte", []byte{0x00, 0x00, 0x00, 0x03}, p11.CKK_EC},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeCKKeyType(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestECCurveFromOID verifies OID-to-curve-name decoding.
func TestECCurveFromOID(t *testing.T) {
	tests := []struct {
		name string
		oid  string
		want string
	}{
		{"P-256", "1.2.840.10045.3.1.7", "P-256"},
		{"P-384", "1.3.132.0.34", "P-384"},
		{"P-521", "1.3.132.0.35", "P-521"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oid := parseOIDString(tt.oid)
			require.NotNil(t, oid)
			der, err := asn1.Marshal(oid)
			require.NoError(t, err)
			got := ecCurveFromOID(der)
			assert.Equal(t, tt.want, got)
		})
	}

	// Unrecognized / garbage input.
	assert.Empty(t, ecCurveFromOID(nil))
	assert.Empty(t, ecCurveFromOID([]byte{0xff, 0xff}))
}
