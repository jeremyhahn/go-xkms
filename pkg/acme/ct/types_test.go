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

package ct

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyToLogID(t *testing.T) {
	t.Run("ECDSA P256", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		logID, err := KeyToLogID(&key.PublicKey)
		require.NoError(t, err)

		// Log ID should be 32 bytes (SHA-256)
		assert.Equal(t, 32, len(logID))

		// Same key should produce same ID
		logID2, err := KeyToLogID(&key.PublicKey)
		require.NoError(t, err)
		assert.Equal(t, logID, logID2)
	})

	t.Run("RSA 2048", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		logID, err := KeyToLogID(&key.PublicKey)
		require.NoError(t, err)

		assert.Equal(t, 32, len(logID))

		// Same key should produce same ID
		logID2, err := KeyToLogID(&key.PublicKey)
		require.NoError(t, err)
		assert.Equal(t, logID, logID2)
	})

	t.Run("different keys produce different IDs", func(t *testing.T) {
		key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		logID1, err := KeyToLogID(&key1.PublicKey)
		require.NoError(t, err)

		logID2, err := KeyToLogID(&key2.PublicKey)
		require.NoError(t, err)

		assert.NotEqual(t, logID1, logID2)
	})

	t.Run("invalid key type", func(t *testing.T) {
		// Pass an invalid key type that can't be marshaled
		var invalidKey crypto.PublicKey = "not a valid key"

		_, err := KeyToLogID(invalidKey)
		assert.Error(t, err)
	})

	t.Run("nil key", func(t *testing.T) {
		_, err := KeyToLogID(nil)
		assert.Error(t, err)
	})
}

func TestECDSAPublicKeyToLogID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	logID, err := ECDSAPublicKeyToLogID(&key.PublicKey)
	require.NoError(t, err)

	// Should be same as generic KeyToLogID
	logID2, err := KeyToLogID(&key.PublicKey)
	require.NoError(t, err)

	assert.Equal(t, logID, logID2)
}

func TestOIDs(t *testing.T) {
	// Verify OID values match RFC 6962
	assert.Equal(t, []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}, []int(OIDPrecertPoison))
	assert.Equal(t, []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, []int(OIDSCTList))

	// Alias should be same
	assert.True(t, OIDSCTList.Equal(OIDSignedCertificateTimestampList))
}

func TestSignatureAlgorithmConstants(t *testing.T) {
	// Verify constants match RFC 6962 values
	assert.Equal(t, SignatureAlgorithm(0), SignatureAlgorithmAnonymous)
	assert.Equal(t, SignatureAlgorithm(1), SignatureAlgorithmRSA)
	assert.Equal(t, SignatureAlgorithm(2), SignatureAlgorithmDSA)
	assert.Equal(t, SignatureAlgorithm(3), SignatureAlgorithmECDSA)
}

func TestHashAlgorithmConstants(t *testing.T) {
	// Verify constants match RFC 5246/6962 values
	assert.Equal(t, HashAlgorithm(0), HashAlgorithmNone)
	assert.Equal(t, HashAlgorithm(1), HashAlgorithmMD5)
	assert.Equal(t, HashAlgorithm(2), HashAlgorithmSHA1)
	assert.Equal(t, HashAlgorithm(3), HashAlgorithmSHA224)
	assert.Equal(t, HashAlgorithm(4), HashAlgorithmSHA256)
	assert.Equal(t, HashAlgorithm(5), HashAlgorithmSHA384)
	assert.Equal(t, HashAlgorithm(6), HashAlgorithmSHA512)
}

func TestVersionConstants(t *testing.T) {
	// RFC 6962 defines version 0 as V1
	assert.Equal(t, Version(0), V1)
}

func TestLogEntryTypeConstants(t *testing.T) {
	assert.Equal(t, LogEntryType(0), X509LogEntryType)
	assert.Equal(t, LogEntryType(1), PrecertLogEntryType)
}
