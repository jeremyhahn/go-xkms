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

package backend

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestCapabilitiesSupportsImportExport verifies that the software
// capabilities constructor does not advertise import/export.
func TestCapabilitiesSupportsImportExport(t *testing.T) {
	caps := types.NewSoftwareCapabilities()
	assert.False(t, caps.SupportsImportExport())
}

// TestSecurityLevel_Ordering verifies that security levels are properly ordered
func TestSecurityLevel_Ordering(t *testing.T) {
	// SecurityLevel should be: Low < Medium < High < VeryHigh
	assert.True(t, types.SecurityLevelLow < types.SecurityLevelMedium,
		"Low should be less than Medium")
	assert.True(t, types.SecurityLevelMedium < types.SecurityLevelHigh,
		"Medium should be less than High")
	assert.True(t, types.SecurityLevelHigh < types.SecurityLevelVeryHigh,
		"High should be less than VeryHigh")

	// Expected backend security level assignments:
	// - Software: Low (0) - keys on disk
	// - Cloud KMS (AWS/GCP/Azure/Vault): Medium (1) - network-dependent
	// - PKCS#11: High (2) - local HSM
	// - TPM 2.0: VeryHigh (3) - hardware-bound, non-exportable
}
