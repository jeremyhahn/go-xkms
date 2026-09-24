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

package usb

import (
	"crypto/fips140"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/require"
)

// requireStaticKey generates a Noise static key pair for a test that needs
// one to exercise the USB transport's pairing/handshake behavior, and
// reports whether the caller can continue using it.
//
// The USB transport's Noise Protocol handshake (xkey/pkg/pairing) is
// hard-wired to Curve25519 -- Noise's "25519" DH function, the same
// primitive the Noise Protocol Framework specification names -- with no
// FIPS-approved substitute offered at this layer (NIST P-256/P-384 are not
// part of the standard Noise 25519/448 pattern this protocol implements).
// pairing.GenerateStaticKey refuses outright under GODEBUG=fips140=only, so
// this asserts that refusal and reports ok=false instead of letting the
// caller dereference a nil key. Making the USB transport FIPS-capable would
// mean redesigning its handshake pattern around an approved curve, which is
// an architecture decision for go-xkms#23's follow-up, not one this test
// suite makes unilaterally.
func requireStaticKey(t *testing.T) (*pairing.StaticKey, bool) {
	t.Helper()
	key, err := pairing.GenerateStaticKey()
	if err != nil {
		if fips140.Enforced() {
			require.Error(t, err, "Noise Curve25519 static key generation must be refused under GODEBUG=fips140=only")
			return nil, false
		}
		require.NoError(t, err)
		return nil, false
	}
	return key, true
}
