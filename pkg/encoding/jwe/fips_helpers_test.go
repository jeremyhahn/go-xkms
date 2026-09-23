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

package jwe

import (
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireJWE runs a JWE encrypt operation for a test that needs the result
// to exercise further behavior (decryption, header extraction, and so on),
// and reports whether the caller can continue using it.
//
// Every content-encryption algorithm this package exposes (A128/192/256GCM,
// the *GCMKW key-management family) goes through
// github.com/go-jose/go-jose/v4, which builds its GCM cipher.AEAD with
// cipher.NewGCM -- the arbitrary-IV constructor -- rather than
// cipher.NewGCMWithRandomNonce (symmetric.go); "RSA-OAEP" (as opposed to
// "RSA-OAEP-256") also resolves to a SHA-1 OAEP digest per RFC 7518 §4.4.
// Both are refused under GODEBUG=fips140=only. go-jose is a third-party
// dependency outside the Go Cryptographic Module boundary this repository
// does not own and cannot patch without an approved architecture change --
// see docs/fips/README.md "AEAD construction" and "Panics the stdlib raises
// instead of an error" -- so this asserts the refusal instead of skipping
// the test.
func requireJWE(t *testing.T, encrypt func() (string, error)) (string, bool) {
	t.Helper()
	jweString, err := encrypt()
	if err != nil {
		if fips140.Enforced() {
			require.Error(t, err, "JWE encryption must be refused under GODEBUG=fips140=only")
			return "", false
		}
		require.NoError(t, err)
		return "", false
	}
	return jweString, true
}
