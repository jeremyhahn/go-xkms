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

//go:build !fips

package bootstrap

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/stretchr/testify/require"
)

// Without the fips build tag, go-truststrap compiles its X25519 DH in, so the
// Noise suite is available and EnsureSuiteAvailable must say so. Paired with
// suite_fips_test.go, which asserts the opposite under the tag: together they
// pin that the answer is derived from the build rather than guessed.
func TestEnsureSuiteAvailable_NoiseAvailableWithoutFIPSTag(t *testing.T) {
	err := EnsureSuiteAvailable(SuiteNoiseNK)
	// Without the fips tag, Noise is still refused at run time under
	// GODEBUG=fips140=only, because the module rejects X25519.
	if !fipstest.OutsideFIPSAfterRefusal(t, err, ErrNoiseFIPSUnsupported) {
		require.ErrorIs(t, err, ErrSuiteUnavailable)
		return
	}
	require.NoError(t, err)
}
