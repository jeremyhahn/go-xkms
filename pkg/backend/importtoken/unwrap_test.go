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

package importtoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var allWrappingAlgorithms = []backend.WrappingAlgorithm{
	backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
	backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
	backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
	backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
}

// wrapForAlgorithm wraps keyMaterial with the wrapping library function that
// matches algorithm, mirroring the switch every ImportBackend's WrapKey
// runs.
func wrapForAlgorithm(t *testing.T, algorithm backend.WrappingAlgorithm, pub *rsa.PublicKey, keyMaterial []byte) []byte {
	t.Helper()
	switch algorithm {
	case backend.WrappingAlgorithmRSAES_OAEP_SHA_1, backend.WrappingAlgorithmRSAES_OAEP_SHA_256:
		wrapped, err := wrapping.WrapRSAOAEP(keyMaterial, pub, algorithm)
		require.NoError(t, err)
		return wrapped
	case backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256:
		wrapped, err := wrapping.WrapRSAAES(keyMaterial, pub, algorithm)
		require.NoError(t, err)
		return wrapped
	default:
		t.Fatalf("unsupported test algorithm %s", algorithm)
		return nil
	}
}

// TestUnwrap_RoundTrip verifies every supported wrapping algorithm
// round-trips through Unwrap when the requested algorithm matches the
// algorithm the wrapping keypair was issued for.
func TestUnwrap_RoundTrip(t *testing.T) {
	for _, algorithm := range allWrappingAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			priv := generateTestRSAKey(t)
			sealed, err := NewSealedRSAKey(priv)
			require.NoError(t, err)
			defer sealed.Destroy()

			keyMaterial := []byte("0123456789abcdef0123456789abcdef")
			wrapped := wrapForAlgorithm(t, algorithm, &priv.PublicKey, keyMaterial)

			unwrapped, err := Unwrap(sealed, algorithm, algorithm, wrapped)
			require.NoError(t, err)
			assert.Equal(t, keyMaterial, unwrapped)
		})
	}
}

// TestUnwrap_AlgorithmMismatchRefused verifies a requested algorithm that
// does not match the algorithm the token was issued for is refused before
// the wrapping key's enclave is ever opened -- the ciphertext here is
// deliberately garbage, so a successful unwrap could only mean the mismatch
// check was skipped.
func TestUnwrap_AlgorithmMismatchRefused(t *testing.T) {
	priv := generateTestRSAKey(t)
	sealed, err := NewSealedRSAKey(priv)
	require.NoError(t, err)
	defer sealed.Destroy()

	_, err = Unwrap(sealed, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, backend.WrappingAlgorithmRSAES_OAEP_SHA_1, []byte("not a valid ciphertext"))
	require.Error(t, err)

	var mismatch *AlgorithmMismatchError
	require.True(t, errors.As(err, &mismatch), "expected *AlgorithmMismatchError, got %T: %v", err, err)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, mismatch.Issued)
	assert.Equal(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_1, mismatch.Requested)
	assert.True(t, errors.Is(err, backend.ErrInvalidAlgorithm))
}

// TestUnwrap_BadCiphertextUniformError verifies every algorithm reports the
// same *errs.Wrapped shape for corrupt ciphertext, rather than leaking which
// internal step failed through a distinguishable error type.
func TestUnwrap_BadCiphertextUniformError(t *testing.T) {
	for _, algorithm := range allWrappingAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			priv := generateTestRSAKey(t)
			sealed, err := NewSealedRSAKey(priv)
			require.NoError(t, err)
			defer sealed.Destroy()

			_, err = Unwrap(sealed, algorithm, algorithm, []byte("not a valid ciphertext"))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "failed to unwrap key")
		})
	}
}

// TestUnwrap_NonRSAEnclaveReportsInvalidKeyType verifies a sealed enclave
// that decodes to a non-RSA key is translated to backend.ErrInvalidKeyType,
// the same sentinel every backend's UnwrapKey has always reported for this
// case.
func TestUnwrap_NonRSAEnclaveReportsInvalidKeyType(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	secret, err := secure.NewSecret(der)
	require.NoError(t, err)
	sealed := NewSealedRSAKeyFromSecret(secret, nil)
	defer sealed.Destroy()

	_, err = Unwrap(sealed, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, []byte("irrelevant"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrapping key is not RSA")
	assert.True(t, errors.Is(err, backend.ErrInvalidKeyType))
}

// TestEntry_Unwrap_NilReceiver verifies Entry.Unwrap tolerates a nil
// receiver rather than panicking.
func TestEntry_Unwrap_NilReceiver(t *testing.T) {
	var entry *Entry
	_, err := entry.Unwrap(backend.WrappingAlgorithmRSAES_OAEP_SHA_256, []byte("irrelevant"))
	require.Error(t, err)
	var unavailable *UnavailableError
	assert.True(t, errors.As(err, &unavailable))
}

// TestEntry_Unwrap_RoundTrip verifies Entry.Unwrap delegates to Unwrap with
// its own Key and Algorithm.
func TestEntry_Unwrap_RoundTrip(t *testing.T) {
	priv := generateTestRSAKey(t)
	sealed, err := NewSealedRSAKey(priv)
	require.NoError(t, err)
	entry := &Entry{Key: sealed, Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256}
	defer entry.Destroy()

	keyMaterial := []byte("0123456789abcdef0123456789abcdef")
	wrapped := wrapForAlgorithm(t, backend.WrappingAlgorithmRSAES_OAEP_SHA_256, &priv.PublicKey, keyMaterial)

	unwrapped, err := entry.Unwrap(backend.WrappingAlgorithmRSAES_OAEP_SHA_256, wrapped)
	require.NoError(t, err)
	assert.Equal(t, keyMaterial, unwrapped)
}

// TestEntry_Destroy_NilReceiver verifies Destroy tolerates a nil receiver.
func TestEntry_Destroy_NilReceiver(t *testing.T) {
	var entry *Entry
	assert.NotPanics(t, entry.Destroy)
}
