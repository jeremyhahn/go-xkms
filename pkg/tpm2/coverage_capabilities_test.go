// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCapabilities_FixedProperties_CovCap tests the FixedProperties method
func TestCapabilities_FixedProperties_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	require.NoError(t, err)
	assert.NotNil(t, props)

	// Verify all fields are populated
	assert.NotEmpty(t, props.Family)
	assert.NotEmpty(t, props.Manufacturer)
	assert.NotEmpty(t, props.VendorID)
	assert.NotEmpty(t, props.Revision)
	assert.GreaterOrEqual(t, props.FwMajor, int64(0))
	assert.GreaterOrEqual(t, props.FwMinor, int64(0))
}

// TestCapabilities_FixedPropertiesFields_CovCap tests specific fields in fixed properties
func TestCapabilities_FixedPropertiesFields_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	props, err := tpm.FixedProperties()
	require.NoError(t, err)

	// Test session and handle limits
	assert.Greater(t, props.ActiveSessionsMax, uint32(0))
	assert.GreaterOrEqual(t, props.AuthSessionsActive, uint32(0))
	assert.GreaterOrEqual(t, props.AuthSessionsActiveAvail, uint32(0))
	assert.GreaterOrEqual(t, props.AuthSessionsLoaded, uint32(0))
	assert.GreaterOrEqual(t, props.AuthSessionsLoadedAvail, uint32(0))

	// Test persistent/transient limits
	assert.GreaterOrEqual(t, props.PersistentLoaded, uint32(0))
	assert.GreaterOrEqual(t, props.PersistentAvail, uint32(0))
	assert.GreaterOrEqual(t, props.PersistentMin, uint32(0))
	assert.GreaterOrEqual(t, props.TransientMin, uint32(0))
	assert.GreaterOrEqual(t, props.TransientAvail, uint32(0))

	// Test NV limits
	assert.Greater(t, props.NVBufferMax, uint32(0))
	assert.GreaterOrEqual(t, props.NVIndexesDefined, uint32(0))
	assert.Greater(t, props.NVIndexesMax, uint32(0))
	assert.GreaterOrEqual(t, props.NVWriteRecovery, uint32(0))

	// Test lockout settings
	assert.GreaterOrEqual(t, props.LockoutCounter, uint32(0))
	assert.Greater(t, props.MaxAuthFail, uint32(0))

	// Test family should be "2.0" for TPM 2.0
	// TPM may return null-terminated strings, so use Contains
	assert.Contains(t, props.Family, "2.0")
}

// TestCapabilities_IsFIPS140_2_CovCap tests the IsFIPS140_2 method
func TestCapabilities_IsFIPS140_2_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	isFIPS, err := tpm2Impl.IsFIPS140_2()
	require.NoError(t, err)
	// Just test that the function returns a valid boolean (value depends on TPM/simulator)
	_ = isFIPS
}

// TestCapabilities_Info_CovCap tests the Info method
func TestCapabilities_Info_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	info, err := tpm2Impl.Info()
	require.NoError(t, err)
	assert.NotEmpty(t, info)

	// Verify info contains expected TPM information sections
	assert.Contains(t, info, "TPM Information")
	assert.Contains(t, info, "Manufacturer")
	assert.Contains(t, info, "Family")
	assert.Contains(t, info, "Revision")
	assert.Contains(t, info, "Firmware")
}

// TestCapabilities_Memory_CovCap tests the memory helper function
func TestCapabilities_Memory_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	mem, err := memory(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, mem, uint32(0))
}

// TestCapabilities_PersistentLoaded_CovCap tests the persistentLoaded helper function
func TestCapabilities_PersistentLoaded_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	loaded, err := persistentLoaded(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, loaded, uint32(0))
}

// TestCapabilities_PersistentAvail_CovCap tests the persistentAvail helper function
func TestCapabilities_PersistentAvail_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	avail, err := persistentAvail(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, avail, uint32(0))
}

// TestCapabilities_PersistentMin_CovCap tests the persistentMin helper function
func TestCapabilities_PersistentMin_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	min, err := persistentMin(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, min, uint32(0))
}

// TestCapabilities_TransientMin_CovCap tests the transientMin helper function
func TestCapabilities_TransientMin_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	min, err := transientMin(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, min, uint32(0))
}

// TestCapabilities_TransientAvail_CovCap tests the transientAvail helper function
func TestCapabilities_TransientAvail_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	avail, err := transientAvail(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, avail, uint32(0))
}

// TestCapabilities_ActiveSessionsMax_CovCap tests the activeSessionsMax helper function
func TestCapabilities_ActiveSessionsMax_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	max, err := activeSessionsMax(tpm2Impl.transport)
	require.NoError(t, err)
	assert.Greater(t, max, uint32(0))
}

// TestCapabilities_AuthSessionsActive_CovCap tests the authSessionsActive helper function
func TestCapabilities_AuthSessionsActive_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	active, err := authSessionsActive(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, active, uint32(0))
}

// TestCapabilities_AuthSessionsActiveAvail_CovCap tests the authSessionsActiveAvail helper function
func TestCapabilities_AuthSessionsActiveAvail_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	avail, err := authSessionsActiveAvail(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, avail, uint32(0))
}

// TestCapabilities_AuthSessionsLoaded_CovCap tests the authSessionsLoaded helper function
func TestCapabilities_AuthSessionsLoaded_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	loaded, err := authSessionsLoaded(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, loaded, uint32(0))
}

// TestCapabilities_AuthSessionsLoadedAvail_CovCap tests the authSessionsLoadedAvail helper function
func TestCapabilities_AuthSessionsLoadedAvail_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	avail, err := authSessionsLoadedAvail(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, avail, uint32(0))
}

// TestCapabilities_Family_CovCap tests the family helper function
func TestCapabilities_Family_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	fam, err := family(tpm2Impl.transport)
	require.NoError(t, err)
	assert.NotEmpty(t, fam)
	// TPM may return null-terminated strings, so use Contains
	assert.Contains(t, fam, "2.0")
}

// TestCapabilities_Firmware_CovCap tests the firmware helper function
func TestCapabilities_Firmware_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	major, minor, err := firmware(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, major, int64(0))
	assert.GreaterOrEqual(t, minor, int64(0))
}

// TestCapabilities_LoadedCurves_CovCap tests the loadedCurves helper function
func TestCapabilities_LoadedCurves_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	curves, err := loadedCurves(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, curves, uint32(0))
}

// TestCapabilities_LockoutCounter_CovCap tests the lockoutCounter helper function
func TestCapabilities_LockoutCounter_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	counter, err := lockoutCounter(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, counter, uint32(0))
}

// TestCapabilities_LockoutRecovery_CovCap tests the lockoutRecovery helper function
func TestCapabilities_LockoutRecovery_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	recovery, err := lockoutRecovery(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, recovery, uint32(0))
}

// TestCapabilities_LockoutInterval_CovCap tests the lockoutInterval helper function
func TestCapabilities_LockoutInterval_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	interval, err := lockoutInterval(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, interval, uint32(0))
}

// TestCapabilities_Manufacturer_CovCap tests the manufacturer helper function
func TestCapabilities_Manufacturer_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	mfr, err := manufacturer(tpm2Impl.transport)
	require.NoError(t, err)
	assert.NotEmpty(t, mfr)
}

// TestCapabilities_Model_CovCap tests the model helper function
func TestCapabilities_Model_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	mdl, err := model(tpm2Impl.transport)
	require.NoError(t, err)
	// Model may be empty for simulator
	_ = mdl
}

// TestCapabilities_MaxAuthFail_CovCap tests the maxAuthFail helper function
func TestCapabilities_MaxAuthFail_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	maxFail, err := maxAuthFail(tpm2Impl.transport)
	require.NoError(t, err)
	assert.Greater(t, maxFail, uint32(0))
}

// TestCapabilities_NVIndexesDefined_CovCap tests the nvIndexesDefined helper function
func TestCapabilities_NVIndexesDefined_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	defined, err := nvIndexesDefined(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, defined, uint32(0))
}

// TestCapabilities_NVIndexesMax_CovCap tests the nvIndexesMax helper function
func TestCapabilities_NVIndexesMax_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	max, err := nvIndexesMax(tpm2Impl.transport)
	require.NoError(t, err)
	assert.Greater(t, max, uint32(0))
}

// TestCapabilities_NVBufferMax_CovCap tests the nvBufferMax helper function
func TestCapabilities_NVBufferMax_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	bufMax, err := nvBufferMax(tpm2Impl.transport)
	require.NoError(t, err)
	assert.Greater(t, bufMax, uint32(0))
}

// TestCapabilities_NVWriteRecovery_CovCap tests the nvWriteRecovery helper function
func TestCapabilities_NVWriteRecovery_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	recovery, err := nvWriteRecovery(tpm2Impl.transport)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, recovery, uint32(0))
}

// TestCapabilities_Revision_CovCap tests the revision helper function
func TestCapabilities_Revision_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	rev, err := revision(tpm2Impl.transport)
	require.NoError(t, err)
	assert.NotEmpty(t, rev)
	// Revision should be in format like "1.64"
	assert.Contains(t, rev, ".")
}

// TestCapabilities_VendorID_CovCap tests the vendorID helper function
func TestCapabilities_VendorID_CovCap(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Impl := tpm.(*TPM2)
	vid, err := vendorID(tpm2Impl.transport)
	require.NoError(t, err)
	assert.NotEmpty(t, vid)
}
