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

package rfc8555

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateNonce tests cryptographically secure nonce generation
func TestGenerateNonce(t *testing.T) {
	nonce, err := common.GenerateNonce(16)
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)

	// Verify it's base64url encoded
	_, decodeErr := base64.RawURLEncoding.DecodeString(nonce)
	assert.NoError(t, decodeErr)
}

// TestGenerateNonce_Uniqueness tests that nonces are unique
func TestGenerateNonce_Uniqueness(t *testing.T) {
	numNonces := 1000
	nonces := make(map[string]bool)

	for i := 0; i < numNonces; i++ {
		nonce, err := common.GenerateNonce(16)
		require.NoError(t, err)

		// Check for duplicates
		assert.False(t, nonces[nonce], "Duplicate nonce generated")
		nonces[nonce] = true
	}

	assert.Len(t, nonces, numNonces)
}

// TestGenerateNonce_Base64URLEncoding tests proper base64url encoding
func TestGenerateNonce_Base64URLEncoding(t *testing.T) {
	nonce, err := common.GenerateNonce(16)
	require.NoError(t, err)

	// Should not contain standard base64 characters not in URL-safe variant
	assert.NotContains(t, nonce, "+")
	assert.NotContains(t, nonce, "/")
	assert.NotContains(t, nonce, "=") // No padding

	// Should be valid base64url
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	require.NoError(t, err)
	assert.NotEmpty(t, decoded)
}

// TestGenerateNonce_Length tests nonce generation with different lengths
func TestGenerateNonce_Length(t *testing.T) {
	testCases := []struct {
		name       string
		byteLength int
	}{
		{"8 bytes", 8},
		{"16 bytes", 16},
		{"32 bytes", 32},
		{"64 bytes", 64},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nonce, err := common.GenerateNonce(tc.byteLength)
			require.NoError(t, err)

			// Decode to verify length
			decoded, err := base64.RawURLEncoding.DecodeString(nonce)
			require.NoError(t, err)
			assert.Equal(t, tc.byteLength, len(decoded))
		})
	}
}

// TestNonceStore_Creation tests nonce store initialization
func TestNonceStore_Creation(t *testing.T) {
	ttl := 5 * time.Minute
	store := common.NewNonceStore(ttl)

	assert.NotNil(t, store)
}

// TestNonceStore_AddAndValidate tests adding and validating nonces
func TestNonceStore_AddAndValidate(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	nonce, err := common.GenerateNonce(16)
	require.NoError(t, err)

	// Add nonce
	store.Add(nonce)

	// Validate nonce (should exist and be consumed)
	exists := store.Exists(nonce)
	assert.True(t, exists, "Nonce should exist on first use")

	// Try to use again (should fail - single use)
	exists = store.Exists(nonce)
	assert.False(t, exists, "Nonce should not exist after first use")
}

// TestNonceStore_SingleUse tests nonce single-use requirement
func TestNonceStore_SingleUse(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	nonce := "test-single-use-nonce"
	store.Add(nonce)

	// First validation should succeed
	valid1 := store.Exists(nonce)
	assert.True(t, valid1)

	// Second validation should fail (already consumed)
	valid2 := store.Exists(nonce)
	assert.False(t, valid2)

	// Third validation should still fail
	valid3 := store.Exists(nonce)
	assert.False(t, valid3)
}

// TestNonceStore_ExpirationBehavior tests nonce TTL expiration
func TestNonceStore_ExpirationBehavior(t *testing.T) {
	// Use short TTL for testing
	ttl := 200 * time.Millisecond
	store := common.NewNonceStore(ttl)

	nonce := "test-expiring-nonce"
	store.Add(nonce)

	// Should be valid immediately
	time.Sleep(50 * time.Millisecond)
	valid1 := store.Exists(nonce)
	assert.True(t, valid1)

	// Add another nonce that will expire
	nonce2 := "test-expiring-nonce-2"
	store.Add(nonce2)

	// Wait for expiration
	time.Sleep(250 * time.Millisecond)

	// Should be expired
	valid2 := store.Exists(nonce2)
	assert.False(t, valid2)
}

// TestNonceStore_MissingNonce tests checking for non-existent nonce
func TestNonceStore_MissingNonce(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	// Check nonce that was never added
	exists := store.Exists("never-added-nonce")
	assert.False(t, exists)
}

// TestNonceStore_MultipleNonces tests managing multiple nonces
func TestNonceStore_MultipleNonces(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	nonces := make([]string, 10)
	for i := 0; i < 10; i++ {
		nonce, err := common.GenerateNonce(16)
		require.NoError(t, err)

		nonces[i] = nonce
		store.Add(nonce)
	}

	// All nonces should be valid
	for _, nonce := range nonces {
		exists := store.Exists(nonce)
		assert.True(t, exists)
	}

	// None should be valid after first use
	for _, nonce := range nonces {
		exists := store.Exists(nonce)
		assert.False(t, exists)
	}
}

// TestNonceStore_ThreadSafety tests thread-safe nonce operations
func TestNonceStore_ThreadSafety(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	// Add and validate nonces concurrently
	done := make(chan bool)
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		go func() {
			nonce, err := common.GenerateNonce(16)
			require.NoError(t, err)

			// Add nonce
			store.Add(nonce)

			// Validate nonce
			exists := store.Exists(nonce)
			assert.True(t, exists)

			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// TestNonceStore_Sweep tests automatic nonce cleanup
func TestNonceStore_Sweep(t *testing.T) {
	// Use short TTL to test sweep
	ttl := 100 * time.Millisecond
	store := common.NewNonceStore(ttl)

	// Add multiple nonces
	for i := 0; i < 5; i++ {
		nonce, err := common.GenerateNonce(16)
		require.NoError(t, err)
		store.Add(nonce)
	}

	// Wait for expiration and sweep
	time.Sleep(200 * time.Millisecond)

	// Add a fresh nonce
	freshNonce, err := common.GenerateNonce(16)
	require.NoError(t, err)
	store.Add(freshNonce)

	// Fresh nonce should be valid
	exists := store.Exists(freshNonce)
	assert.True(t, exists)
}

// TestNonceValidation_RFC8555Compliance tests nonce validation per RFC 8555
func TestNonceValidation_RFC8555Compliance(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	// Test 1: Server must provide fresh nonce via HEAD/GET to newNonce
	nonce1, err := common.GenerateNonce(16)
	require.NoError(t, err)
	store.Add(nonce1)

	// Test 2: Client must include nonce in JWS protected header
	// (Simulated by checking nonce exists before use)
	exists := store.Exists(nonce1)
	assert.True(t, exists)

	// Test 3: Nonce must be consumed after successful validation
	exists = store.Exists(nonce1)
	assert.False(t, exists, "Nonce should be consumed after first use")

	// Test 4: Server must reject invalid nonces
	invalidNonce := "invalid-nonce-not-added"
	exists = store.Exists(invalidNonce)
	assert.False(t, exists)
}

// TestNonce_EmptyString tests handling of empty nonce
func TestNonce_EmptyString(t *testing.T) {
	store := common.NewNonceStore(5 * time.Minute)

	// Add empty string
	store.Add("")

	// Should be able to check for empty string
	exists := store.Exists("")
	assert.True(t, exists)

	// Should be consumed
	exists = store.Exists("")
	assert.False(t, exists)
}
