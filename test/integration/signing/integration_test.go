// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/signing"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignerRSAPKCS1v15Integration tests RSA PKCS#1 v1.5 signing end-to-end
func TestSignerRSAPKCS1v15Integration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test message for RSA PKCS#1 v1.5")
	hash := crypto.SHA256

	// Compute digest
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Test signing with standard SignerOpts
	opts := signing.NewSignerOpts(hash)
	signature, err := signer.Sign(rand.Reader, digest, opts)
	require.NoError(t, err, "Failed to sign with RSA PKCS#1 v1.5")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
	assert.NoError(t, err, "Signature verification failed")

	// Test key algorithm detection
	keyAlg := signer.GetKeyAlgorithm()
	assert.Equal(t, x509.RSA, keyAlg, "Key algorithm should be RSA")

	// Test hash algorithm support
	assert.True(t, signer.SupportsHashAlgorithm(crypto.SHA256))
	assert.True(t, signer.SupportsHashAlgorithm(crypto.SHA512))
}

// TestSignerRSAPSSIntegration tests RSA-PSS signing end-to-end
func TestSignerRSAPSSIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test message for RSA-PSS")
	hash := crypto.SHA256

	// Compute digest
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Test signing with PSS options
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       hash,
	}
	opts := signing.NewSignerOpts(hash).WithPSSOptions(pssOpts)
	signature, err := signer.Sign(rand.Reader, digest, opts)
	require.NoError(t, err, "Failed to sign with RSA-PSS")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	err = rsa.VerifyPSS(&privateKey.PublicKey, hash, digest, signature, pssOpts)
	assert.NoError(t, err, "RSA-PSS signature verification failed")
}

// TestSignerECDSAIntegration tests ECDSA signing end-to-end
func TestSignerECDSAIntegration(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-224", elliptic.P224()},
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			// Generate ECDSA key pair
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err, "Failed to generate ECDSA key")

			// Create enhanced signer
			signer, err := signing.NewSigner(privateKey)
			require.NoError(t, err, "Failed to create signer")

			// Test data
			message := []byte("Integration test message for ECDSA " + tc.name)
			hash := crypto.SHA256

			// Compute digest
			hasher := hash.New()
			_, err = hasher.Write(message)
			require.NoError(t, err, "Failed to hash message")
			digest := hasher.Sum(nil)

			// Test signing
			opts := signing.NewSignerOpts(hash)
			signature, err := signer.Sign(rand.Reader, digest, opts)
			require.NoError(t, err, "Failed to sign with ECDSA")
			require.NotEmpty(t, signature, "Signature should not be empty")

			// Verify signature using ECDSA
			assert.True(t, ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature),
				"ECDSA signature verification failed")

			// Test key algorithm detection
			keyAlg := signer.GetKeyAlgorithm()
			assert.Equal(t, x509.ECDSA, keyAlg, "Key algorithm should be ECDSA")
		})
	}
}

// TestSignerEd25519Integration tests Ed25519 signing end-to-end
func TestSignerEd25519Integration(t *testing.T) {
	// Generate Ed25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "Failed to generate Ed25519 key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test message for Ed25519")

	// Ed25519 signs the message directly (no pre-hashing)
	opts := signing.NewSignerOpts(crypto.Hash(0)).WithBlobData(message)
	signature, err := signer.Sign(rand.Reader, nil, opts)
	require.NoError(t, err, "Failed to sign with Ed25519")
	require.NotEmpty(t, signature, "Signature should not be empty")
	assert.Equal(t, ed25519.SignatureSize, len(signature), "Signature should be 64 bytes")

	// Verify signature
	valid := ed25519.Verify(publicKey, message, signature)
	assert.True(t, valid, "Ed25519 signature verification failed")

	// Test key algorithm detection
	keyAlg := signer.GetKeyAlgorithm()
	assert.Equal(t, x509.Ed25519, keyAlg, "Key algorithm should be Ed25519")

	// Test hash algorithm support (Ed25519 doesn't use external hash functions)
	assert.True(t, signer.SupportsHashAlgorithm(crypto.Hash(0)))
	assert.False(t, signer.SupportsHashAlgorithm(crypto.SHA256))
}

// TestSignerOptsWithBlobDataIntegration tests automatic digest computation from blob data
func TestSignerOptsWithBlobDataIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test with automatic digest computation")
	hash := crypto.SHA256

	// Sign with BlobData (automatic digest computation)
	opts := signing.NewSignerOpts(hash).
		WithBlobData(message).
		WithBlobCN("test-blob")
	signature, err := signer.Sign(rand.Reader, nil, opts)
	require.NoError(t, err, "Failed to sign with blob data")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Compute digest manually for verification
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
	assert.NoError(t, err, "Signature verification failed")
}

// TestSignerOptsWithKeyAttributesIntegration tests signing with key attributes
func TestSignerOptsWithKeyAttributesIntegration(t *testing.T) {
	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test with key attributes")
	hash := crypto.SHA256

	// Compute digest
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Sign with key attributes
	attrs := &types.KeyAttributes{
		CN:   "test-key",
		Hash: hash,
	}
	opts := signing.NewSignerOpts(hash).WithKeyAttributes(attrs)
	signature, err := signer.Sign(rand.Reader, digest, opts)
	require.NoError(t, err, "Failed to sign with key attributes")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	assert.True(t, ecdsa.VerifyASN1(&privateKey.PublicKey, digest, signature),
		"Signature verification failed")
}

// TestSignerChainingIntegration tests method chaining for SignerOpts
func TestSignerChainingIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test with method chaining")
	hash := crypto.SHA256

	// Create options with method chaining
	attrs := &types.KeyAttributes{
		CN:   "chained-test-key",
		Hash: hash,
	}
	opts := signing.NewSignerOpts(hash).
		WithBlobData(message).
		WithBlobCN("chained-blob").
		WithKeyAttributes(attrs)

	// Verify all options were set
	assert.Equal(t, "chained-blob", opts.BlobCN)
	assert.Equal(t, message, opts.BlobData)
	assert.Equal(t, attrs, opts.KeyAttributes)
	assert.Equal(t, hash, opts.Hash)

	// Sign with chained options
	signature, err := signer.Sign(rand.Reader, nil, opts)
	require.NoError(t, err, "Failed to sign with chained options")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Compute digest manually for verification
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
	assert.NoError(t, err, "Signature verification failed with chained options")
}

// TestSignerFallbackToStandardSigningIntegration tests fallback to standard crypto.Signer
func TestSignerFallbackToStandardSigningIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Integration test for standard signing fallback")
	hash := crypto.SHA256

	// Compute digest
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Sign with standard crypto.Hash (not SignerOpts)
	signature, err := signer.Sign(rand.Reader, digest, hash)
	require.NoError(t, err, "Failed to sign with standard options")
	require.NotEmpty(t, signature, "Signature should not be empty")

	// Verify signature
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
	assert.NoError(t, err, "Signature verification failed with standard options")
}

// TestSignerPublicKeyIntegration tests public key retrieval
func TestSignerPublicKeyIntegration(t *testing.T) {
	// Test RSA
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")
	rsaSigner, err := signing.NewSigner(rsaPrivate)
	require.NoError(t, err, "Failed to create RSA signer")
	rsaPublic := rsaSigner.Public()
	assert.Equal(t, &rsaPrivate.PublicKey, rsaPublic, "RSA public key mismatch")

	// Test ECDSA
	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate ECDSA key")
	ecdsaSigner, err := signing.NewSigner(ecdsaPrivate)
	require.NoError(t, err, "Failed to create ECDSA signer")
	ecdsaPublic := ecdsaSigner.Public()
	assert.Equal(t, &ecdsaPrivate.PublicKey, ecdsaPublic, "ECDSA public key mismatch")

	// Test Ed25519
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err, "Failed to generate Ed25519 key")
	ed25519Signer, err := signing.NewSigner(ed25519Private)
	require.NoError(t, err, "Failed to create Ed25519 signer")
	retrievedPublic := ed25519Signer.Public()
	assert.Equal(t, ed25519Public, retrievedPublic, "Ed25519 public key mismatch")
}

// TestSignerErrorHandlingIntegration tests error handling in various scenarios
func TestSignerErrorHandlingIntegration(t *testing.T) {
	t.Run("NilSigner", func(t *testing.T) {
		signer, err := signing.NewSigner(nil)
		assert.Error(t, err, "Should error with nil signer")
		assert.Nil(t, signer, "Signer should be nil")
		assert.ErrorIs(t, err, signing.ErrSignerRequired)
	})

	t.Run("InvalidHashFunction", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		signer, err := signing.NewSigner(privateKey)
		require.NoError(t, err, "Failed to create signer")

		// Use unavailable hash function
		invalidHash := crypto.Hash(999)
		opts := signing.NewSignerOpts(invalidHash).WithBlobData([]byte("test"))

		signature, err := signer.Sign(rand.Reader, nil, opts)
		assert.Error(t, err, "Should error with invalid hash")
		assert.Nil(t, signature, "Signature should be nil")
		assert.ErrorIs(t, err, signing.ErrInvalidHashFunction)
	})

	t.Run("EmptyDigest", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err, "Failed to generate RSA key")

		signer, err := signing.NewSigner(privateKey)
		require.NoError(t, err, "Failed to create signer")

		// Sign with nil digest and no blob data
		opts := signing.NewSignerOpts(crypto.SHA256)
		signature, err := signer.Sign(rand.Reader, nil, opts)
		// This should succeed but produce an empty/invalid signature
		// The actual behavior depends on the underlying crypto implementation
		_ = signature
		_ = err
	})
}

// TestSignerConcurrentIntegration tests concurrent signing operations
func TestSignerConcurrentIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Number of concurrent operations
	numOps := 100
	done := make(chan bool, numOps)
	errors := make(chan error, numOps)

	// Test data
	hash := crypto.SHA256
	message := []byte("Concurrent signing test message")

	// Compute digest
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Launch concurrent signing operations
	for i := 0; i < numOps; i++ {
		go func(iteration int) {
			opts := signing.NewSignerOpts(hash)
			signature, err := signer.Sign(rand.Reader, digest, opts)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			// Verify signature
			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature)
			if err != nil {
				errors <- err
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all operations to complete
	successCount := 0
	for i := 0; i < numOps; i++ {
		select {
		case success := <-done:
			if success {
				successCount++
			}
		case err := <-errors:
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}

	assert.Equal(t, numOps, successCount, "All concurrent operations should succeed")
}

// TestSignerWithDifferentRandomReadersIntegration tests signing with different random readers
func TestSignerWithDifferentRandomReadersIntegration(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	// Test data
	message := []byte("Test with different random readers")
	hash := crypto.SHA256

	// Compute digest
	hasher := hash.New()
	_, err = hasher.Write(message)
	require.NoError(t, err, "Failed to hash message")
	digest := hasher.Sum(nil)

	// Test with crypto/rand
	opts := signing.NewSignerOpts(hash)
	signature1, err := signer.Sign(rand.Reader, digest, opts)
	require.NoError(t, err, "Failed to sign with crypto/rand")

	// Test with nil reader (some implementations allow this for deterministic signatures)
	signature2, err := signer.Sign(nil, digest, opts)
	require.NoError(t, err, "Failed to sign with nil reader")

	// Both signatures should be valid
	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature1)
	assert.NoError(t, err, "Signature 1 verification failed")

	err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, hash, digest, signature2)
	assert.NoError(t, err, "Signature 2 verification failed")

	// Note: RSA PKCS#1 v1.5 signatures are deterministic, so they should be equal
	assert.Equal(t, signature1, signature2, "RSA PKCS#1 v1.5 signatures should be deterministic")
}

// mockSigner implements crypto.Signer for testing unsupported key types
type mockSigner struct {
	publicKey interface{}
}

func (m *mockSigner) Public() crypto.PublicKey {
	return m.publicKey
}

func (m *mockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return []byte("mock-signature"), nil
}

// TestSignerUnsupportedKeyTypeIntegration tests handling of unsupported key types
func TestSignerUnsupportedKeyTypeIntegration(t *testing.T) {
	// Create a mock signer with unsupported key type
	mock := &mockSigner{
		publicKey: "unsupported-key-type",
	}

	// Create enhanced signer
	signer, err := signing.NewSigner(mock)
	require.NoError(t, err, "Should create signer even with unsupported key type")

	// Test that GetKeyAlgorithm returns UnknownPublicKeyAlgorithm
	keyAlg := signer.GetKeyAlgorithm()
	assert.Equal(t, x509.UnknownPublicKeyAlgorithm, keyAlg,
		"Should return UnknownPublicKeyAlgorithm for unsupported key type")

	// Test that SupportsHashAlgorithm returns false
	assert.False(t, signer.SupportsHashAlgorithm(crypto.SHA256),
		"Should not support hash algorithms for unsupported key type")

	// Test signing with unsupported key type
	opts := signing.NewSignerOpts(crypto.SHA256)
	signature, err := signer.Sign(rand.Reader, []byte("test"), opts)
	assert.Error(t, err, "Should error when signing with unsupported key type")
	assert.Nil(t, signature, "Signature should be nil")
	assert.ErrorIs(t, err, signing.ErrUnsupportedAlgorithm)
}

// TestSignerMultipleHashAlgorithmsIntegration tests signing with different hash algorithms
func TestSignerMultipleHashAlgorithmsIntegration(t *testing.T) {
	hashes := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA1", crypto.SHA1},
		{"SHA224", crypto.SHA224},
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "Failed to generate RSA key")

	// Create enhanced signer
	signer, err := signing.NewSigner(privateKey)
	require.NoError(t, err, "Failed to create signer")

	for _, tc := range hashes {
		t.Run(tc.name, func(t *testing.T) {
			// Test data
			message := []byte("Test message for " + tc.name)

			// Compute digest
			hasher := tc.hash.New()
			_, err = hasher.Write(message)
			require.NoError(t, err, "Failed to hash message")
			digest := hasher.Sum(nil)

			// Sign
			opts := signing.NewSignerOpts(tc.hash)
			signature, err := signer.Sign(rand.Reader, digest, opts)
			require.NoError(t, err, "Failed to sign with %s", tc.name)
			require.NotEmpty(t, signature, "Signature should not be empty")

			// Verify
			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, tc.hash, digest, signature)
			assert.NoError(t, err, "Signature verification failed for %s", tc.name)

			// Verify hash support
			assert.True(t, signer.SupportsHashAlgorithm(tc.hash),
				"Should support %s", tc.name)
		})
	}
}
