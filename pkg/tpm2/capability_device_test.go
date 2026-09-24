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

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
)

// TestDeviceCapabilities_CurveNames verifies CurveNames renders every curve
// the device reports, sorted, using the same human-readable names
// AlgorithmNames uses for algorithms -- the pairing an error message like
// CurveNotSupportedError.Supported depends on.
func TestDeviceCapabilities_CurveNames(t *testing.T) {
	caps := &DeviceCapabilities{
		curves: map[tpm2.TPMECCCurve]struct{}{
			tpm2.TPMECCNistP256: {},
			tpm2.TPMECCNistP384: {},
		},
	}
	got := caps.CurveNames()
	assert.Equal(t, []string{"NIST P-256", "NIST P-384"}, got)
}

// TestDeviceCapabilities_CurveNames_Empty verifies an empty capability set
// renders as an empty (not nil-panicking) list.
func TestDeviceCapabilities_CurveNames_Empty(t *testing.T) {
	caps := &DeviceCapabilities{}
	assert.Empty(t, caps.CurveNames())
}

// TestAlgorithmName_FallsBackToHexForUnknownAlgorithm verifies a caller
// building an error message for a vendor extension or an algorithm added to
// the TCG registry after this build still gets a name rather than an empty
// string.
func TestAlgorithmName_FallsBackToHexForUnknownAlgorithm(t *testing.T) {
	unknown := tpm2.TPMAlgID(0xBEEF)
	assert.Equal(t, "0xBEEF", algorithmName(unknown))
}

// TestAlgorithmName_KnownAlgorithmUsesRegisteredName is the companion case:
// an algorithm this package does know about must render its human name, not
// the fallback hex form.
func TestAlgorithmName_KnownAlgorithmUsesRegisteredName(t *testing.T) {
	assert.Equal(t, "RSA", algorithmName(tpm2.TPMAlgRSA))
}

// TestCurveName_FallsBackToHexForUnknownCurve mirrors
// TestAlgorithmName_FallsBackToHexForUnknownAlgorithm for ECC curve IDs.
func TestCurveName_FallsBackToHexForUnknownCurve(t *testing.T) {
	unknown := tpm2.TPMECCCurve(0xBEEF)
	assert.Equal(t, "0xBEEF", curveName(unknown))
}

// TestCurveName_KnownCurveUsesRegisteredName is the companion case for a
// curve this package does know about.
func TestCurveName_KnownCurveUsesRegisteredName(t *testing.T) {
	assert.Equal(t, "NIST P-256", curveName(tpm2.TPMECCNistP256))
}
