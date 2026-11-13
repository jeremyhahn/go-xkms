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

package attesttest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

// noiseOutsideFIPS reports whether the calling test can run a Noise session in
// this process. The Noise static key is X25519, which crypto/ecdh refuses
// under GODEBUG=fips140=only (owner ruling 116: refuse what the stdlib
// refuses), so there it asserts the typed refusal, re-runs the test under
// fips140=off and returns false; the caller then returns.
func noiseOutsideFIPS(t *testing.T) bool {
	t.Helper()
	_, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
	if !fipstest.OutsideFIPSAfterRefusal(t, err, bootstrap.ErrNoiseFIPSUnsupported) {
		return false
	}
	require.NoError(t, err)
	return true
}
