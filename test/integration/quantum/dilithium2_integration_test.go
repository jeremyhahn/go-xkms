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

//go:build integration && quantum

package quantum_test

import (
	"crypto/rand"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/quantum/dilithium2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDilithium2Integration_KeyGeneration tests key pair generation
func TestDilithium2Integration_KeyGeneration(t *testing.T) {
	d, err := dilithium2.New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	// Verify key sizes match expected Dilithium2 parameters
	assert.Equal(t, d.PublicKeyLength(), len(pubKey), "Public key size mismatch")

	secretKey := d.ExportSecretKey()
	assert.Equal(t, d.SecretKeyLength(), len(secretKey), "Secret key size mismatch")

	// ML-DSA-44 specific sizes (from NIST FIPS 204 standard)
	// Note: Sizes may vary slightly from draft Dilithium2 spec
	assert.Greater(t, len(pubKey), 1000, "ML-DSA-44 public key should be >1000 bytes")
	assert.Greater(t, len(secretKey), 2000, "ML-DSA-44 secret key should be >2000 bytes")
}

// TestDilithium2Integration_SignatureWorkflow tests complete sign/verify workflow
func TestDilithium2Integration_SignatureWorkflow(t *testing.T) {
	d, err := dilithium2.New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	testCases := []struct {
		name    string
		message []byte
	}{
		// Note: Empty messages cause panic in liboqs-go, so we skip that case
		{"Small message", []byte("Hello, Quantum World!")},
		{"Medium message", make([]byte, 1024)},
		{"Large message", make([]byte, 1024*1024)}, // 1MB
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.message) > 100 {
				_, err := rand.Read(tc.message)
				require.NoError(t, err)
			}

			signature, err := d.Sign(tc.message)
			require.NoError(t, err)
			assert.NotEmpty(t, signature)

			// Verify signature size is within expected bounds
			assert.LessOrEqual(t, len(signature), d.SignatureLength(),
				"Signature exceeds maximum length")

			// Verify signature
			valid, err := d.Verify(tc.message, signature, pubKey)
			require.NoError(t, err)
			assert.True(t, valid, "Signature should be valid")
		})
	}
}

// TestDilithium2Integration_MultipleSignatures tests signing multiple messages
func TestDilithium2Integration_MultipleSignatures(t *testing.T) {
	d, err := dilithium2.New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	numSignatures := 100
	signatures := make([][]byte, numSignatures)
	messages := make([][]byte, numSignatures)

	// Generate and sign multiple messages
	for i := 0; i < numSignatures; i++ {
		messages[i] = []byte(fmt.Sprintf("Message %d for signing", i))
		sig, err := d.Sign(messages[i])
		require.NoError(t, err)
		signatures[i] = sig
	}

	// Verify all signatures
	for i := 0; i < numSignatures; i++ {
		valid, err := d.Verify(messages[i], signatures[i], pubKey)
		require.NoError(t, err)
		assert.True(t, valid, "Signature %d should be valid", i)
	}

	// Verify cross-signature failure (signature from message i shouldn't verify message j)
	valid, err := d.Verify(messages[0], signatures[1], pubKey)
	require.NoError(t, err)
	assert.False(t, valid, "Different message/signature pairs should not verify")
}

// TestDilithium2Integration_KeyPersistence tests key export functionality
func TestDilithium2Integration_KeyPersistence(t *testing.T) {
	// Generate original key pair
	d1, err := dilithium2.New()
	require.NoError(t, err)
	defer d1.Clean()

	pubKey, err := d1.GenerateKeyPair()
	require.NoError(t, err)

	// Export the secret key
	secretKey := d1.ExportSecretKey()
	require.NotEmpty(t, secretKey)
	t.Logf("Secret key export successful: %d bytes", len(secretKey))

	// Sign with original key
	message := []byte("Persistence test message")
	signature1, err := d1.Sign(message)
	require.NoError(t, err)

	// Sign same message again to show consistency
	signature2, err := d1.Sign(message)
	require.NoError(t, err)

	// Both signatures should verify with public key
	valid1, err := d1.Verify(message, signature1, pubKey)
	require.NoError(t, err)
	assert.True(t, valid1, "First signature should verify")

	valid2, err := d1.Verify(message, signature2, pubKey)
	require.NoError(t, err)
	assert.True(t, valid2, "Second signature should verify")

	// Exported secret key should be consistent
	exportedKey2 := d1.ExportSecretKey()
	assert.Equal(t, secretKey, exportedKey2, "Exported secret key should be consistent")

	// Verify key sizes are correct
	assert.Equal(t, d1.SecretKeyLength(), len(secretKey), "Secret key size should match")
	assert.Equal(t, d1.PublicKeyLength(), len(pubKey), "Public key size should match")
}

// TestDilithium2Integration_InvalidSignatures tests rejection of invalid signatures
func TestDilithium2Integration_InvalidSignatures(t *testing.T) {
	d, err := dilithium2.New()
	require.NoError(t, err)
	defer d.Clean()

	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)

	message := []byte("Original message")
	signature, err := d.Sign(message)
	require.NoError(t, err)

	// Test modified message
	modifiedMessage := []byte("Modified message")
	valid, err := d.Verify(modifiedMessage, signature, pubKey)
	if err == nil {
		assert.False(t, valid, "Modified message should not verify")
	}

	// Test corrupted signature (flip bits)
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[0] ^= 0xFF
	corruptedSig[len(corruptedSig)/2] ^= 0xFF
	corruptedSig[len(corruptedSig)-1] ^= 0xFF

	valid, err = d.Verify(message, corruptedSig, pubKey)
	if err == nil {
		assert.False(t, valid, "Corrupted signature should not verify")
	}

	// Test wrong public key
	d2, err := dilithium2.New()
	require.NoError(t, err)
	defer d2.Clean()

	wrongPubKey, err := d2.GenerateKeyPair()
	require.NoError(t, err)

	valid, err = d.Verify(message, signature, wrongPubKey)
	if err == nil {
		assert.False(t, valid, "Wrong public key should not verify")
	}
}

// TestDilithium2Integration_ConcurrentOperations tests thread safety
func TestDilithium2Integration_ConcurrentOperations(t *testing.T) {
	numGoroutines := 50
	opsPerGoroutine := 10

	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines*opsPerGoroutine*2)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			d, err := dilithium2.New()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: New() failed: %w", id, err)
				return
			}
			defer d.Clean()

			pubKey, err := d.GenerateKeyPair()
			if err != nil {
				errors <- fmt.Errorf("goroutine %d: GenerateKeyPair() failed: %w", id, err)
				return
			}

			for j := 0; j < opsPerGoroutine; j++ {
				message := []byte(fmt.Sprintf("Goroutine %d Message %d", id, j))
				signature, err := d.Sign(message)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: Sign() failed: %w", id, j, err)
					continue
				}

				valid, err := d.Verify(message, signature, pubKey)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: Verify() failed: %w", id, j, err)
					continue
				}

				if !valid {
					errors <- fmt.Errorf("goroutine %d op %d: signature verification failed", id, j)
				}
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}

	assert.Equal(t, 0, errorCount, "Expected no concurrent operation errors")
}

// TestDilithium2Integration_Performance measures performance characteristics
func TestDilithium2Integration_Performance(t *testing.T) {
	d, err := dilithium2.New()
	require.NoError(t, err)
	defer d.Clean()

	// Measure key generation
	start := time.Now()
	pubKey, err := d.GenerateKeyPair()
	require.NoError(t, err)
	keyGenTime := time.Since(start)
	t.Logf("Key generation time: %v", keyGenTime)

	// Measure signing performance
	message := make([]byte, 1024) // 1KB message
	_, err = rand.Read(message)
	require.NoError(t, err)

	numIterations := 100
	start = time.Now()
	var signatures [][]byte
	for i := 0; i < numIterations; i++ {
		sig, err := d.Sign(message)
		require.NoError(t, err)
		signatures = append(signatures, sig)
	}
	signTime := time.Since(start)
	t.Logf("Signing: %v total, %v per operation", signTime, signTime/time.Duration(numIterations))

	// Measure verification performance
	start = time.Now()
	for i := 0; i < numIterations; i++ {
		_, err := d.Verify(message, signatures[i], pubKey)
		require.NoError(t, err)
	}
	verifyTime := time.Since(start)
	t.Logf("Verification: %v total, %v per operation", verifyTime, verifyTime/time.Duration(numIterations))

	// Performance assertions (reasonable bounds)
	assert.Less(t, keyGenTime, 100*time.Millisecond, "Key generation should be under 100ms")
	avgSignTime := signTime / time.Duration(numIterations)
	assert.Less(t, avgSignTime, 10*time.Millisecond, "Signing should be under 10ms per operation")
	avgVerifyTime := verifyTime / time.Duration(numIterations)
	assert.Less(t, avgVerifyTime, 10*time.Millisecond, "Verification should be under 10ms per operation")
}

// TestDilithium2Integration_Details verifies algorithm details are correct
func TestDilithium2Integration_Details(t *testing.T) {
	d, err := dilithium2.New()
	require.NoError(t, err)
	defer d.Clean()

	details := d.Details()

	// ML-DSA-44 is the NIST standard name for Dilithium2
	assert.Equal(t, "ML-DSA-44", details.Name)
	assert.Greater(t, details.LengthPublicKey, 1000)
	assert.Greater(t, details.LengthSecretKey, 2000)
	assert.Greater(t, details.MaxLengthSignature, 2000)

	// Verify helper methods match details
	assert.Equal(t, details.LengthPublicKey, d.PublicKeyLength())
	assert.Equal(t, details.LengthSecretKey, d.SecretKeyLength())
	assert.Equal(t, details.MaxLengthSignature, d.SignatureLength())

	t.Logf("ML-DSA-44 (Dilithium2) parameters:")
	t.Logf("  Public key: %d bytes", details.LengthPublicKey)
	t.Logf("  Secret key: %d bytes", details.LengthSecretKey)
	t.Logf("  Max signature: %d bytes", details.MaxLengthSignature)
}

// TestDilithium2Integration_DocumentSigning simulates real-world document signing
func TestDilithium2Integration_DocumentSigning(t *testing.T) {
	// Simulate a document signing authority
	authority, err := dilithium2.New()
	require.NoError(t, err)
	defer authority.Clean()

	authorityPubKey, err := authority.GenerateKeyPair()
	require.NoError(t, err)

	// Store authority's secret key for persistence
	authoritySecretKey := authority.ExportSecretKey()

	// Simulate documents to sign
	documents := []struct {
		name    string
		content []byte
	}{
		{"Contract", []byte("Legal contract between parties A and B...")},
		{"Certificate", []byte("This certifies that...")},
		{"Firmware", make([]byte, 10240)}, // 10KB firmware blob
	}

	signedDocs := make(map[string][]byte)

	// Sign all documents
	for _, doc := range documents {
		if len(doc.content) > 100 {
			_, err := rand.Read(doc.content)
			require.NoError(t, err)
		}

		signature, err := authority.Sign(doc.content)
		require.NoError(t, err)
		signedDocs[doc.name] = signature

		t.Logf("Document %s: %d bytes, signature: %d bytes",
			doc.name, len(doc.content), len(signature))
	}

	// Simulate authority restart (recreate from stored key)
	authority.Clean()
	authority2, err := dilithium2.Create(authoritySecretKey)
	require.NoError(t, err)
	defer authority2.Clean()

	// Verify all documents with recreated authority
	for _, doc := range documents {
		valid, err := authority2.Verify(doc.content, signedDocs[doc.name], authorityPubKey)
		require.NoError(t, err)
		assert.True(t, valid, "Document %s should verify after authority restart", doc.name)
	}

	// Simulate third-party verification (only has public key)
	verifier, err := dilithium2.New()
	require.NoError(t, err)
	defer verifier.Clean()

	for _, doc := range documents {
		valid, err := verifier.Verify(doc.content, signedDocs[doc.name], authorityPubKey)
		require.NoError(t, err)
		assert.True(t, valid, "Third-party should verify document %s", doc.name)
	}
}

// TestDilithium2Integration_MultipleKeyPairs tests multiple independent key pairs
func TestDilithium2Integration_MultipleKeyPairs(t *testing.T) {
	numPairs := 10
	signers := make([]*dilithium2.Dilithium2, numPairs)
	pubKeys := make([][]byte, numPairs)

	// Generate multiple key pairs
	for i := 0; i < numPairs; i++ {
		d, err := dilithium2.New()
		require.NoError(t, err)
		defer d.Clean()

		pubKey, err := d.GenerateKeyPair()
		require.NoError(t, err)

		signers[i] = d
		pubKeys[i] = pubKey
	}

	// Each signer signs a unique message
	message := []byte("Shared message for all signers")
	signatures := make([][]byte, numPairs)

	for i := 0; i < numPairs; i++ {
		sig, err := signers[i].Sign(message)
		require.NoError(t, err)
		signatures[i] = sig
	}

	// Verify each signature only validates with its own public key
	for i := 0; i < numPairs; i++ {
		for j := 0; j < numPairs; j++ {
			valid, err := signers[i].Verify(message, signatures[i], pubKeys[j])
			if err == nil {
				if i == j {
					assert.True(t, valid, "Signer %d's signature should verify with own key", i)
				} else {
					assert.False(t, valid, "Signer %d's signature should NOT verify with signer %d's key", i, j)
				}
			}
		}
	}
}
