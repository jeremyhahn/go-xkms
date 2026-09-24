// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-xkms/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// There are two BackendType enumerations in this repository -- this package's
// and pkg/types' -- and they do not hold the same values. A backend added to
// one and not the other is accepted by whichever half the caller happens to
// reach and refused by the other, which is a failure that appears at one call
// site and not at the one next to it.
func TestBackendAVRIsValidInThisPackagesEnum(t *testing.T) {
	assert.True(t, BackendAVR.IsValid())
	assert.Equal(t, "avr", BackendAVR.String())
	assert.Equal(t, string(types.BackendTypeAVR), BackendAVR.String(),
		"the two BackendType enumerations must spell it the same way")
}

// A key ID naming the avr backend has to parse back to it. The string in a key
// ID is the backend type verbatim, so the two directions are one fact.
func TestAVRKeyIDRoundTrip(t *testing.T) {
	bt, err := keyIDToBackendType("avr")
	require.NoError(t, err)

	assert.Equal(t, types.BackendTypeAVR, bt)
	assert.Equal(t, "avr", backendTypeToKeyIDString(bt))
}

// backendTypeToStoreType defaults to StoreSoftware, so a backend with no entry
// does not fail -- it silently records a hardware key as a software one. That
// is the shape of defect this test exists to prevent for the backends that
// hold keys outside this process.
func TestBackendTypeToStoreTypeDoesNotCallHardwareSoftware(t *testing.T) {
	tests := []struct {
		backend types.BackendType
		store   types.StoreType
	}{
		{types.BackendTypeAVR, types.StoreAVR},
		{types.BackendTypePhone, types.StorePhone},
		{types.BackendTypeTPM2, types.StoreTPM2},
		{types.BackendTypePKCS11, types.StorePKCS11},
	}

	for _, tt := range tests {
		t.Run(string(tt.backend), func(t *testing.T) {
			got := backendTypeToStoreType(tt.backend)
			assert.Equal(t, tt.store, got)
			assert.NotEqual(t, types.StoreSoftware, got,
				"a key that lives outside this process is not in the software store")
		})
	}
}
