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

package nativemsg

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// x25519OutsideFIPS reports whether the calling test can run the X25519
// session handshake in this process. crypto/ecdh refuses X25519 under
// GODEBUG=fips140=only (owner ruling 116: refuse what the stdlib refuses), so
// there it asserts NewSessionCrypto's typed refusal, re-runs the test under
// fips140=off and returns false; the caller then returns.
func x25519OutsideFIPS(t *testing.T) bool {
	t.Helper()
	_, _, err := NewSessionCrypto()
	if err != nil {
		require.ErrorIs(t, err, ErrHandshakeFailed)
	}
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
		return false
	}
	require.NoError(t, err)
	return true
}
