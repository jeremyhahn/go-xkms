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

package staticpw

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aesgcm"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

func TestHKDFKey_DerivesAnAESKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, PasskeySecretLength)
	key, err := hkdfKey(secret, []byte("salt"), recoveryHKDFInfo)
	require.NoError(t, err)
	assert.Len(t, key, aesgcm.KeySize)

	other, err := hkdfKey(secret, []byte("salt"), passkeyHKDFInfo)
	require.NoError(t, err)
	assert.NotEqual(t, key, other, "the info string separates the factors' keys")
}

// TestHKDFKey_ShortSecret proves a secret under 112 bits -- a mistyped
// recovery code, say -- is a *VaultCryptoError under fips140=only, where the
// module refuses it, rather than a panic, and derives a key outside it.
func TestHKDFKey_ShortSecret(t *testing.T) {
	key, err := hkdfKey([]byte("NOTTHECODE"), []byte("salt"), recoveryHKDFInfo)
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
		var crypto *VaultCryptoError
		require.ErrorAs(t, err, &crypto)
		assert.Equal(t, "hkdf", crypto.Op)
		return
	}
	require.NoError(t, err)
	assert.Len(t, key, aesgcm.KeySize)
}
