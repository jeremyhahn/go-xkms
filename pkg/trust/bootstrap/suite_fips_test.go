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

//go:build fips

package bootstrap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Under the fips build tag go-truststrap compiles out its X25519 DH, so the
// Noise suite cannot run and EnsureSuiteAvailable must refuse it at
// CONSTRUCTION -- typed, naming the suite and the approved alternative --
// rather than letting the failure surface at key generation or per connection
// at dispatch (go-trusted-platform#209).
func TestEnsureSuiteAvailable_NoiseRefusedUnderFIPSTag(t *testing.T) {
	err := EnsureSuiteAvailable(SuiteNoiseNK)
	require.Error(t, err, "a fips build must not report the Noise suite as available")
	assert.ErrorIs(t, err, ErrSuiteUnavailable)
	assert.Contains(t, err.Error(), "SuiteP256AESGCM",
		"the refusal must name the approved alternative, or it is not actionable")
}

// And the approved suite must still work under the tag -- otherwise a FIPS
// build has no bootstrap at all, which is the defect being fixed.
func TestEnsureSuiteAvailable_P256AvailableUnderFIPSTag(t *testing.T) {
	require.NoError(t, EnsureSuiteAvailable(SuiteP256AESGCM))
}
