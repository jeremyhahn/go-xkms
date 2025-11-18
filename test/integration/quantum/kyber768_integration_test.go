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

	"github.com/jeremyhahn/go-keychain/pkg/quantum/kyber768"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestKyber768Integration_KeyGeneration tests key pair generation
func TestKyber768Integration_KeyGeneration(t *testing.T) {
	k, err := kyber768.New()
	require.NoError(t, err)
	defer k.Clean()

	pubKey, err := k.GenerateKeyPair()
	require.NoError(t, err)

	// Verify key sizes match expected Kyber768 parameters
	assert.Equal(t, k.PublicKeyLength(), len(pubKey), "Public key size mismatch")

	secretKey := k.ExportSecretKey()
	assert.Equal(t, k.SecretKeyLength(), len(secretKey), "Secret key size mismatch")

	// ML-KEM-768 specific sizes (from NIST FIPS 203 standard)
	// Note: Sizes may vary slightly from draft Kyber768 spec
	assert.Greater(t, len(pubKey), 1000, "ML-KEM-768 public key should be >1000 bytes")
	assert.Greater(t, len(secretKey), 2000, "ML-KEM-768 secret key should be >2000 bytes")
}

// TestKyber768Integration_EncapsulationWorkflow tests complete encapsulation/decapsulation
func TestKyber768Integration_EncapsulationWorkflow(t *testing.T) {
	// Alice generates key pair
	alice, err := kyber768.New()
	require.NoError(t, err)
	defer alice.Clean()

	alicePubKey, err := alice.GenerateKeyPair()
	require.NoError(t, err)

	// Bob encapsulates a secret for Alice
	bob, err := kyber768.New()
	require.NoError(t, err)
	defer bob.Clean()

	ciphertext, bobSharedSecret, err := bob.Encapsulate(alicePubKey)
	require.NoError(t, err)

	// Verify sizes
	assert.Equal(t, alice.CiphertextLength(), len(ciphertext), "Ciphertext size mismatch")
	assert.Equal(t, alice.SharedSecretLength(), len(bobSharedSecret), "Shared secret size mismatch")

	// ML-KEM-768 specific sizes
	assert.Greater(t, len(ciphertext), 1000, "ML-KEM-768 ciphertext should be >1000 bytes")
	assert.Equal(t, 32, len(bobSharedSecret), "ML-KEM-768 shared secret should be 32 bytes")

	// Alice decapsulates to recover shared secret
	aliceSharedSecret, err := alice.Decapsulate(ciphertext)
	require.NoError(t, err)

	// Both parties should have identical shared secrets
	assert.Equal(t, bobSharedSecret, aliceSharedSecret,
		"Alice and Bob should have identical shared secrets")
}

// TestKyber768Integration_MultipleEncapsulations tests multiple encapsulations
func TestKyber768Integration_MultipleEncapsulations(t *testing.T) {
	// Receiver generates key pair
	receiver, err := kyber768.New()
	require.NoError(t, err)
	defer receiver.Clean()

	receiverPubKey, err := receiver.GenerateKeyPair()
	require.NoError(t, err)

	numSenders := 100
	ciphertexts := make([][]byte, numSenders)
	senderSecrets := make([][]byte, numSenders)

	// Multiple senders encapsulate for same receiver
	for i := 0; i < numSenders; i++ {
		sender, err := kyber768.New()
		require.NoError(t, err)

		ct, secret, err := sender.Encapsulate(receiverPubKey)
		require.NoError(t, err)

		ciphertexts[i] = ct
		senderSecrets[i] = secret
		sender.Clean()
	}

	// Receiver decapsulates all
	for i := 0; i < numSenders; i++ {
		receiverSecret, err := receiver.Decapsulate(ciphertexts[i])
		require.NoError(t, err)
		assert.Equal(t, senderSecrets[i], receiverSecret,
			"Shared secret %d should match", i)
	}

	// Verify all shared secrets are unique (due to randomness in encapsulation)
	uniqueSecrets := make(map[string]bool)
	for i := 0; i < numSenders; i++ {
		secretStr := string(senderSecrets[i])
		assert.False(t, uniqueSecrets[secretStr],
			"Shared secrets should be unique (secret %d is duplicate)", i)
		uniqueSecrets[secretStr] = true
	}
}

// TestKyber768Integration_KeyPersistence tests key export functionality
func TestKyber768Integration_KeyPersistence(t *testing.T) {
	// Generate key pair
	k1, err := kyber768.New()
	require.NoError(t, err)
	defer k1.Clean()

	pubKey, err := k1.GenerateKeyPair()
	require.NoError(t, err)

	secretKey := k1.ExportSecretKey()
	assert.NotEmpty(t, secretKey, "Secret key should be exportable")

	// Verify key can be used for encapsulation/decapsulation
	sender, err := kyber768.New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertext, senderSecret, err := sender.Encapsulate(pubKey)
	require.NoError(t, err)

	// Decapsulate with original key (not recreated)
	receiverSecret, err := k1.Decapsulate(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, senderSecret, receiverSecret,
		"Secret key holder should decapsulate correctly")

	// Verify secret key is consistent
	exportedAgain := k1.ExportSecretKey()
	assert.Equal(t, secretKey, exportedAgain, "Exported key should be consistent")

	t.Logf("Secret key export successful: %d bytes", len(secretKey))
}

// TestKyber768Integration_InvalidCiphertexts tests rejection of invalid inputs
func TestKyber768Integration_InvalidCiphertexts(t *testing.T) {
	k, err := kyber768.New()
	require.NoError(t, err)
	defer k.Clean()

	_, err = k.GenerateKeyPair()
	require.NoError(t, err)

	// Test empty ciphertext
	_, err = k.Decapsulate([]byte{})
	assert.Error(t, err, "Empty ciphertext should fail")

	// Test truncated ciphertext
	truncated := make([]byte, 100)
	_, err = k.Decapsulate(truncated)
	assert.Error(t, err, "Truncated ciphertext should fail")

	// Test oversized ciphertext
	oversized := make([]byte, 2000)
	_, err = rand.Read(oversized)
	require.NoError(t, err)
	_, err = k.Decapsulate(oversized)
	assert.Error(t, err, "Oversized ciphertext should fail")
}

// TestKyber768Integration_WrongKeyDecapsulation tests decapsulation with wrong key
func TestKyber768Integration_WrongKeyDecapsulation(t *testing.T) {
	// Alice's key
	alice, err := kyber768.New()
	require.NoError(t, err)
	defer alice.Clean()

	alicePubKey, err := alice.GenerateKeyPair()
	require.NoError(t, err)

	// Bob's key
	bob, err := kyber768.New()
	require.NoError(t, err)
	defer bob.Clean()

	_, err = bob.GenerateKeyPair()
	require.NoError(t, err)

	// Sender encapsulates for Alice
	sender, err := kyber768.New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertext, senderSecret, err := sender.Encapsulate(alicePubKey)
	require.NoError(t, err)

	// Alice should decapsulate correctly
	aliceSecret, err := alice.Decapsulate(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, senderSecret, aliceSecret)

	// Bob should get different secret (KEM property - implicit rejection)
	bobSecret, err := bob.Decapsulate(ciphertext)
	// Kyber uses implicit rejection, so decapsulation succeeds but gives different secret
	if err == nil {
		assert.NotEqual(t, senderSecret, bobSecret,
			"Wrong key should produce different shared secret")
	}
}

// TestKyber768Integration_ConcurrentOperations tests thread safety
func TestKyber768Integration_ConcurrentOperations(t *testing.T) {
	// Shared receiver
	receiver, err := kyber768.New()
	require.NoError(t, err)
	defer receiver.Clean()

	receiverPubKey, err := receiver.GenerateKeyPair()
	require.NoError(t, err)

	numGoroutines := 50
	opsPerGoroutine := 10

	var wg sync.WaitGroup
	results := make(chan struct {
		ciphertext []byte
		secret     []byte
	}, numGoroutines*opsPerGoroutine)
	errors := make(chan error, numGoroutines*opsPerGoroutine)

	// Concurrent senders
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < opsPerGoroutine; j++ {
				sender, err := kyber768.New()
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: New() failed: %w", id, j, err)
					continue
				}

				ct, secret, err := sender.Encapsulate(receiverPubKey)
				sender.Clean()
				if err != nil {
					errors <- fmt.Errorf("goroutine %d op %d: Encapsulate() failed: %w", id, j, err)
					continue
				}

				results <- struct {
					ciphertext []byte
					secret     []byte
				}{ct, secret}
			}
		}(i)
	}

	wg.Wait()
	close(results)
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Logf("Concurrent operation error: %v", err)
		errorCount++
	}
	assert.Equal(t, 0, errorCount, "Expected no concurrent operation errors")

	// Verify all encapsulations
	successCount := 0
	for result := range results {
		receiverSecret, err := receiver.Decapsulate(result.ciphertext)
		if err != nil {
			t.Logf("Decapsulation failed: %v", err)
			continue
		}
		assert.Equal(t, result.secret, receiverSecret)
		successCount++
	}

	expectedOps := numGoroutines * opsPerGoroutine
	assert.Equal(t, expectedOps, successCount, "All encapsulations should be decapsulated")
}

// TestKyber768Integration_Performance measures performance characteristics
func TestKyber768Integration_Performance(t *testing.T) {
	k, err := kyber768.New()
	require.NoError(t, err)
	defer k.Clean()

	// Measure key generation
	start := time.Now()
	pubKey, err := k.GenerateKeyPair()
	require.NoError(t, err)
	keyGenTime := time.Since(start)
	t.Logf("Key generation time: %v", keyGenTime)

	numIterations := 100

	// Measure encapsulation performance
	start = time.Now()
	ciphertexts := make([][]byte, numIterations)
	sharedSecrets := make([][]byte, numIterations)

	for i := 0; i < numIterations; i++ {
		sender, err := kyber768.New()
		require.NoError(t, err)

		ct, secret, err := sender.Encapsulate(pubKey)
		require.NoError(t, err)
		ciphertexts[i] = ct
		sharedSecrets[i] = secret
		sender.Clean()
	}
	encapTime := time.Since(start)
	t.Logf("Encapsulation: %v total, %v per operation",
		encapTime, encapTime/time.Duration(numIterations))

	// Measure decapsulation performance
	start = time.Now()
	for i := 0; i < numIterations; i++ {
		secret, err := k.Decapsulate(ciphertexts[i])
		require.NoError(t, err)
		assert.Equal(t, sharedSecrets[i], secret)
	}
	decapTime := time.Since(start)
	t.Logf("Decapsulation: %v total, %v per operation",
		decapTime, decapTime/time.Duration(numIterations))

	// Performance assertions
	assert.Less(t, keyGenTime, 100*time.Millisecond, "Key generation should be under 100ms")
	avgEncapTime := encapTime / time.Duration(numIterations)
	assert.Less(t, avgEncapTime, 10*time.Millisecond, "Encapsulation should be under 10ms")
	avgDecapTime := decapTime / time.Duration(numIterations)
	assert.Less(t, avgDecapTime, 10*time.Millisecond, "Decapsulation should be under 10ms")
}

// TestKyber768Integration_Details verifies algorithm details are correct
func TestKyber768Integration_Details(t *testing.T) {
	k, err := kyber768.New()
	require.NoError(t, err)
	defer k.Clean()

	details := k.Details()

	// ML-KEM-768 is the NIST standard name for Kyber768
	assert.Equal(t, "ML-KEM-768", details.Name)
	assert.Greater(t, details.LengthPublicKey, 1000)
	assert.Greater(t, details.LengthSecretKey, 2000)
	assert.Greater(t, details.LengthCiphertext, 1000)
	assert.Equal(t, 32, details.LengthSharedSecret) // Always 32 bytes

	// Verify helper methods match details
	assert.Equal(t, details.LengthPublicKey, k.PublicKeyLength())
	assert.Equal(t, details.LengthSecretKey, k.SecretKeyLength())
	assert.Equal(t, details.LengthCiphertext, k.CiphertextLength())
	assert.Equal(t, details.LengthSharedSecret, k.SharedSecretLength())

	t.Logf("ML-KEM-768 (Kyber768) parameters:")
	t.Logf("  Public key: %d bytes", details.LengthPublicKey)
	t.Logf("  Secret key: %d bytes", details.LengthSecretKey)
	t.Logf("  Ciphertext: %d bytes", details.LengthCiphertext)
	t.Logf("  Shared secret: %d bytes", details.LengthSharedSecret)
}

// TestKyber768Integration_KeyExchangeScenario simulates real-world key exchange
func TestKyber768Integration_KeyExchangeScenario(t *testing.T) {
	// Server generates long-term key pair
	server, err := kyber768.New()
	require.NoError(t, err)
	defer server.Clean()

	serverPubKey, err := server.GenerateKeyPair()
	require.NoError(t, err)

	// Verify server's secret key is exportable
	serverSecretKey := server.ExportSecretKey()
	assert.NotEmpty(t, serverSecretKey, "Server secret key should be exportable")

	// Simulate multiple client connections
	numClients := 10
	clientSecrets := make([][]byte, numClients)
	ciphertexts := make([][]byte, numClients)

	for i := 0; i < numClients; i++ {
		client, err := kyber768.New()
		require.NoError(t, err)

		ct, secret, err := client.Encapsulate(serverPubKey)
		require.NoError(t, err)

		ciphertexts[i] = ct
		clientSecrets[i] = secret
		client.Clean()

		t.Logf("Client %d established shared secret (first 8 bytes): %x", i, secret[:8])
	}

	// Server processes all client key exchanges (without restart)
	for i := 0; i < numClients; i++ {
		serverSecret, err := server.Decapsulate(ciphertexts[i])
		require.NoError(t, err)

		assert.Equal(t, clientSecrets[i], serverSecret,
			"Server should derive same secret as client %d", i)
	}

	t.Logf("Server successfully processed %d client key exchanges", numClients)
}

// TestKyber768Integration_HybridEncryption simulates hybrid encryption workflow
func TestKyber768Integration_HybridEncryption(t *testing.T) {
	// This test simulates using Kyber for key establishment
	// followed by symmetric encryption (not implemented here, just the KEM part)

	// Receiver generates KEM key pair
	receiver, err := kyber768.New()
	require.NoError(t, err)
	defer receiver.Clean()

	receiverPubKey, err := receiver.GenerateKeyPair()
	require.NoError(t, err)

	// Sender wants to send encrypted message
	sender, err := kyber768.New()
	require.NoError(t, err)
	defer sender.Clean()

	// Step 1: Encapsulate to get shared secret
	ciphertext, senderKey, err := sender.Encapsulate(receiverPubKey)
	require.NoError(t, err)

	// Step 2: Sender would use senderKey for symmetric encryption (AES-GCM)
	// message := []byte("Secret message")
	// encryptedMessage := AES_GCM_Encrypt(senderKey, message)

	// Step 3: Send (ciphertext, encryptedMessage) to receiver

	// Step 4: Receiver decapsulates to recover shared secret
	receiverKey, err := receiver.Decapsulate(ciphertext)
	require.NoError(t, err)

	// Step 5: Keys match - receiver can decrypt
	assert.Equal(t, senderKey, receiverKey, "Both parties have same key for symmetric encryption")

	// Verify key is suitable for AES-256
	assert.Equal(t, 32, len(receiverKey), "Shared secret should be 32 bytes (256 bits) for AES-256")
}

// TestKyber768Integration_MultiPartyKeyExchange tests key exchange with multiple receivers
func TestKyber768Integration_MultiPartyKeyExchange(t *testing.T) {
	numReceivers := 5
	receivers := make([]*kyber768.Kyber768, numReceivers)
	receiverPubKeys := make([][]byte, numReceivers)

	// Generate key pairs for all receivers
	for i := 0; i < numReceivers; i++ {
		k, err := kyber768.New()
		require.NoError(t, err)
		defer k.Clean()

		pubKey, err := k.GenerateKeyPair()
		require.NoError(t, err)

		receivers[i] = k
		receiverPubKeys[i] = pubKey
	}

	// Sender encapsulates for each receiver
	sender, err := kyber768.New()
	require.NoError(t, err)
	defer sender.Clean()

	ciphertexts := make([][]byte, numReceivers)
	senderSecrets := make([][]byte, numReceivers)

	for i := 0; i < numReceivers; i++ {
		ct, secret, err := sender.Encapsulate(receiverPubKeys[i])
		require.NoError(t, err)
		ciphertexts[i] = ct
		senderSecrets[i] = secret
	}

	// Each receiver decapsulates their ciphertext
	for i := 0; i < numReceivers; i++ {
		receiverSecret, err := receivers[i].Decapsulate(ciphertexts[i])
		require.NoError(t, err)

		assert.Equal(t, senderSecrets[i], receiverSecret,
			"Receiver %d should get correct shared secret", i)

		// Verify receivers can't decrypt other receivers' ciphertexts correctly
		for j := 0; j < numReceivers; j++ {
			if i != j {
				wrongSecret, err := receivers[i].Decapsulate(ciphertexts[j])
				if err == nil {
					assert.NotEqual(t, senderSecrets[j], wrongSecret,
						"Receiver %d should NOT decrypt receiver %d's ciphertext correctly", i, j)
				}
			}
		}
	}
}
