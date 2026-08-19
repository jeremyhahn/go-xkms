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

package aesgcm

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncryptWithAAD_NonceIsModuleGenerated verifies that the nonce comes from
// inside the FIPS module boundary rather than from a caller-visible source.
//
// This replaces a pair of tests that swapped crypto/rand.Reader for a failing
// reader to exercise the "nonce generation failed" branch. That branch no
// longer exists: SP 800-38D / CMVP IG C.H require the GCM IV be generated
// inside the module, so EncryptWithAAD uses cipher.NewGCMWithRandomNonce and
// there is no externally reachable random source left to fail. What is still
// worth asserting is the observable consequence -- the nonce is fresh per
// call, and the wire format did not change.
func TestEncryptWithAAD_NonceIsModuleGenerated(t *testing.T) {
	key := make([]byte, KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	plaintext := []byte("payload")
	first, err := EncryptWithAAD(key, plaintext, []byte("aad"))
	require.NoError(t, err)
	second, err := EncryptWithAAD(key, plaintext, []byte("aad"))
	require.NoError(t, err)

	// Same key, same plaintext, same AAD: a fresh nonce is the only reason
	// these differ, and they must differ.
	assert.NotEqual(t, first, second, "nonce must be fresh on every call")
	assert.NotEqual(t, first[:NonceSize], second[:NonceSize], "prepended nonce must differ")

	// [nonce:12][ciphertext][tag:16] -- unchanged from the hand-rolled layout.
	assert.Len(t, first, len(plaintext)+Overhead)

	round, err := DecryptWithAAD(key, first, []byte("aad"))
	require.NoError(t, err)
	assert.Equal(t, plaintext, round)
}
