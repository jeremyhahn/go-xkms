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

package wrapping

import (
	"crypto/fips140"
	"testing"

	"github.com/stretchr/testify/require"
)

// requireWrap runs a wrap/unwrap operation for a test that needs the result
// to exercise further behavior, and reports whether the caller can continue
// using it.
//
// backend.WrappingAlgorithmRSAES_OAEP_SHA_1 and
// WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1 use SHA-1 as the RSA-OAEP hash
// (RFC 8017 -- their names say so), which crypto/rsa refuses under
// GODEBUG=fips140=only. Both are deliberately retained for legacy PKCS#11
// wrap interop; see docs/fips/README.md.
func requireWrap(t *testing.T, wrap func() ([]byte, error)) ([]byte, bool) {
	t.Helper()
	wrapped, err := wrap()
	if err != nil {
		if fips140.Enforced() {
			require.Error(t, err, "SHA-1 RSA-OAEP wrap must be refused under GODEBUG=fips140=only")
			return nil, false
		}
		require.NoError(t, err)
		return nil, false
	}
	return wrapped, true
}
