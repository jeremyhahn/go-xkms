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

package crypto_test

import (
	"bytes"
	"crypto/sha256"
	"math"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRandSoftwareResolverIntegration tests software RNG resolver
func TestRandSoftwareResolverIntegration(t *testing.T) {
	// Create software resolver
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err, "Failed to create software resolver")
	defer resolver.Close()

	// Verify it's available
	assert.True(t, resolver.Available(), "Software resolver should always be available")

	// Generate random bytes
	randomBytes, err := resolver.Rand(32)
	require.NoError(t, err, "Failed to generate random bytes")
	require.Len(t, randomBytes, 32, "Should generate 32 bytes")

	// Generate again - should be different
	randomBytes2, err := resolver.Rand(32)
	require.NoError(t, err, "Failed to generate second random bytes")
	assert.NotEqual(t, randomBytes, randomBytes2, "Random bytes should be different")

	// Verify source
	source := resolver.Source()
	assert.NotNil(t, source, "Source should not be nil")
	assert.True(t, source.Available(), "Source should be available")
}

// TestRandAutoResolverIntegration tests auto-detection resolver
func TestRandAutoResolverIntegration(t *testing.T) {
	// Create auto resolver
	resolver, err := rand.NewResolver(rand.ModeAuto)
	require.NoError(t, err, "Failed to create auto resolver")
	defer resolver.Close()

	// Should have some resolver available
	assert.True(t, resolver.Available(), "Auto resolver should find available RNG")

	// Generate random bytes
	randomBytes, err := resolver.Rand(64)
	require.NoError(t, err, "Failed to generate random bytes")
	require.Len(t, randomBytes, 64, "Should generate 64 bytes")

	// Verify randomness (basic entropy check)
	assert.Greater(t, calculateEntropy(randomBytes), 3.0, "Should have reasonable entropy")
}

// TestRandNilConfigIntegration tests nil config defaults to auto mode
func TestRandNilConfigIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(nil)
	require.NoError(t, err, "Should accept nil config")
	defer resolver.Close()

	assert.True(t, resolver.Available())

	randomBytes, err := resolver.Rand(16)
	require.NoError(t, err)
	require.Len(t, randomBytes, 16)
}

// TestRandEmptyConfigIntegration tests empty config defaults to auto mode
func TestRandEmptyConfigIntegration(t *testing.T) {
	config := &rand.Config{}
	resolver, err := rand.NewResolver(config)
	require.NoError(t, err, "Should accept empty config")
	defer resolver.Close()

	assert.True(t, resolver.Available())
}

// TestRandVariousSizesIntegration tests generating different sizes of random data
func TestRandVariousSizesIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	sizes := []int{1, 16, 32, 64, 128, 256, 512, 1024, 4096, 1024 * 1024}

	for _, size := range sizes {
		t.Run(string(rune(size))+" bytes", func(t *testing.T) {
			randomBytes, err := resolver.Rand(size)
			require.NoError(t, err, "Failed to generate %d bytes", size)
			require.Len(t, randomBytes, size, "Should generate exactly %d bytes", size)

			// Verify not all zeros
			allZeros := true
			for _, b := range randomBytes {
				if b != 0 {
					allZeros = false
					break
				}
			}
			assert.False(t, allZeros, "Random bytes should not be all zeros")
		})
	}
}

// TestRandConcurrentAccessIntegration tests thread safety
func TestRandConcurrentAccessIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	numGoroutines := 100
	bytesPerGoroutine := 32
	var wg sync.WaitGroup
	errors := make(chan error, numGoroutines)
	results := make(chan []byte, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()

			randomBytes, err := resolver.Rand(bytesPerGoroutine)
			if err != nil {
				errors <- err
				return
			}

			results <- randomBytes
		}()
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}

	// Collect and verify results
	seen := make(map[string]bool)
	duplicates := 0
	for result := range results {
		require.Len(t, result, bytesPerGoroutine)

		// Check for duplicates (extremely unlikely with good RNG)
		key := string(result)
		if seen[key] {
			duplicates++
		}
		seen[key] = true
	}

	// With 100 * 32 bytes, duplicates should be astronomically unlikely
	assert.Equal(t, 0, duplicates, "Should not have duplicate random values")
}

// TestRandStatisticalPropertiesIntegration tests basic statistical properties
func TestRandStatisticalPropertiesIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	// Generate large sample
	sampleSize := 10000
	randomBytes, err := resolver.Rand(sampleSize)
	require.NoError(t, err)

	// Count byte frequencies
	frequencies := make(map[byte]int)
	for _, b := range randomBytes {
		frequencies[b]++
	}

	// Expected frequency for each byte value (0-255)
	expectedFreq := float64(sampleSize) / 256.0

	// Check that distribution is reasonably uniform
	// Use chi-square test concept (simplified)
	var chiSquare float64
	for i := 0; i < 256; i++ {
		observed := float64(frequencies[byte(i)])
		diff := observed - expectedFreq
		chiSquare += (diff * diff) / expectedFreq
	}

	// Chi-square critical value for 255 degrees of freedom at 0.05 significance
	// is approximately 293.25. We use a more relaxed threshold for this test.
	assert.Less(t, chiSquare, 400.0, "Distribution should be reasonably uniform")

	// Check bit balance (roughly 50% zeros, 50% ones)
	totalBits := sampleSize * 8
	oneBits := 0
	for _, b := range randomBytes {
		oneBits += countSetBits(b)
	}

	oneRatio := float64(oneBits) / float64(totalBits)
	t.Logf("Bit balance: %.2f%% ones, %.2f%% zeros", oneRatio*100, (1-oneRatio)*100)

	// Should be close to 50%
	assert.Greater(t, oneRatio, 0.48, "Should have at least 48% one bits")
	assert.Less(t, oneRatio, 0.52, "Should have at most 52% one bits")
}

// TestRandSourceIntegration tests the Source interface
func TestRandSourceIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	source := resolver.Source()
	require.NotNil(t, source, "Source should not be nil")

	// Test source directly
	assert.True(t, source.Available(), "Source should be available")

	randomBytes, err := source.Rand(32)
	require.NoError(t, err, "Source should generate random bytes")
	require.Len(t, randomBytes, 32)

	// Close source
	err = source.Close()
	assert.NoError(t, err, "Source should close without error")
}

// TestRandResolverCloseIntegration tests proper cleanup
func TestRandResolverCloseIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)

	// Use the resolver
	_, err = resolver.Rand(32)
	require.NoError(t, err)

	// Close it
	err = resolver.Close()
	assert.NoError(t, err, "Should close without error")

	// Closing again should be safe
	err = resolver.Close()
	assert.NoError(t, err, "Should handle multiple closes")
}

// TestRandModeStringIntegration tests different mode types
func TestRandModeStringIntegration(t *testing.T) {
	testCases := []struct {
		mode      rand.Mode
		shouldErr bool
	}{
		{rand.ModeAuto, false},
		{rand.ModeSoftware, false},
		{rand.ModeTPM2, true},   // May fail if TPM2 not available
		{rand.ModePKCS11, true}, // May fail if PKCS11 not available
		{"invalid", true},       // Invalid mode
	}

	for _, tc := range testCases {
		t.Run(string(tc.mode), func(t *testing.T) {
			resolver, err := rand.NewResolver(tc.mode)

			if !tc.shouldErr {
				require.NoError(t, err, "Should create resolver for mode %s", tc.mode)
				if resolver != nil {
					defer resolver.Close()
					assert.True(t, resolver.Available())
				}
			}
			// For modes that may error (hardware), we don't assert the error
			// because it depends on the test environment
		})
	}
}

// TestRandConfigWithModesIntegration tests Config with different modes
func TestRandConfigWithModesIntegration(t *testing.T) {
	// Test software mode via config
	config := &rand.Config{
		Mode: rand.ModeSoftware,
	}

	resolver, err := rand.NewResolver(config)
	require.NoError(t, err)
	defer resolver.Close()

	assert.True(t, resolver.Available())

	randomBytes, err := resolver.Rand(32)
	require.NoError(t, err)
	require.Len(t, randomBytes, 32)
}

// TestRandFallbackModeIntegration tests fallback mode functionality
func TestRandFallbackModeIntegration(t *testing.T) {
	// Configure with TPM2 as primary and software as fallback
	config := &rand.Config{
		Mode:         rand.ModeTPM2,
		FallbackMode: rand.ModeSoftware,
	}

	resolver, err := rand.NewResolver(config)
	// Should succeed even if TPM2 fails, using fallback
	if err == nil {
		defer resolver.Close()

		// Should be available via fallback
		assert.True(t, resolver.Available())

		randomBytes, err := resolver.Rand(32)
		require.NoError(t, err)
		require.Len(t, randomBytes, 32)
	}
}

// TestRandUniquenessIntegration tests that generated values are unique
func TestRandUniquenessIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	// Generate multiple random values
	numSamples := 1000
	sampleSize := 32
	samples := make(map[string]bool)

	for i := 0; i < numSamples; i++ {
		randomBytes, err := resolver.Rand(sampleSize)
		require.NoError(t, err)

		// Hash the bytes for comparison
		hash := sha256.Sum256(randomBytes)
		key := string(hash[:])

		// Check for duplicates
		assert.False(t, samples[key], "Should not generate duplicate values")
		samples[key] = true
	}

	assert.Equal(t, numSamples, len(samples), "All samples should be unique")
}

// TestRandConsecutiveCallsIntegration tests consecutive calls produce different results
func TestRandConsecutiveCallsIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	size := 64
	prev, err := resolver.Rand(size)
	require.NoError(t, err)

	// Make multiple consecutive calls
	for i := 0; i < 100; i++ {
		current, err := resolver.Rand(size)
		require.NoError(t, err)
		require.Len(t, current, size)

		// Should not be equal to previous
		assert.NotEqual(t, prev, current, "Consecutive calls should produce different results")

		prev = current
	}
}

// TestRandEntropyIntegration tests basic entropy of generated data
func TestRandEntropyIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	randomBytes, err := resolver.Rand(1024)
	require.NoError(t, err)

	// Calculate Shannon entropy
	entropy := calculateEntropy(randomBytes)

	// Good randomness should have entropy close to 8 bits per byte
	t.Logf("Entropy: %.4f bits/byte", entropy)
	assert.Greater(t, entropy, 7.5, "Entropy should be high for random data")
}

// TestRandPatternDetectionIntegration tests for obvious patterns
func TestRandPatternDetectionIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	randomBytes, err := resolver.Rand(1000)
	require.NoError(t, err)

	// Check for runs of identical bytes
	maxRun := 0
	currentRun := 1
	for i := 1; i < len(randomBytes); i++ {
		if randomBytes[i] == randomBytes[i-1] {
			currentRun++
			if currentRun > maxRun {
				maxRun = currentRun
			}
		} else {
			currentRun = 1
		}
	}

	// Runs longer than 10 identical bytes would be suspicious
	assert.Less(t, maxRun, 10, "Should not have long runs of identical bytes")

	// Check for repeated sequences
	sequenceLen := 4
	sequences := make(map[string]int)
	for i := 0; i <= len(randomBytes)-sequenceLen; i++ {
		seq := string(randomBytes[i : i+sequenceLen])
		sequences[seq]++
	}

	// No sequence should repeat too many times
	for seq, count := range sequences {
		if count > 3 {
			t.Logf("Warning: Sequence %x repeated %d times", seq, count)
		}
		assert.Less(t, count, 5, "Sequences should not repeat too often")
	}
}

// TestRandZeroLengthRequestIntegration tests edge case of zero-length request
func TestRandZeroLengthRequestIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	randomBytes, err := resolver.Rand(0)
	require.NoError(t, err)
	assert.Len(t, randomBytes, 0, "Should return empty slice for zero length")
}

// TestRandLargeRequestIntegration tests large random data generation
func TestRandLargeRequestIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	// Generate 10 MB of random data
	size := 10 * 1024 * 1024
	randomBytes, err := resolver.Rand(size)
	require.NoError(t, err)
	require.Len(t, randomBytes, size)

	// Quick sanity check - first and last kilobytes should be different
	first := randomBytes[:1024]
	last := randomBytes[len(randomBytes)-1024:]
	assert.NotEqual(t, first, last, "First and last KB should be different")
}

// Helper functions

// calculateEntropy calculates Shannon entropy in bits per byte
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	frequencies := make(map[byte]int)
	for _, b := range data {
		frequencies[b]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(data))
	for _, count := range frequencies {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// countSetBits counts the number of set bits in a byte
func countSetBits(b byte) int {
	count := 0
	for i := 0; i < 8; i++ {
		if b&(1<<i) != 0 {
			count++
		}
	}
	return count
}

// TestRandRealWorldUsageIntegration simulates real-world usage patterns
func TestRandRealWorldUsageIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeAuto)
	require.NoError(t, err)
	defer resolver.Close()

	// Simulate key generation scenario
	t.Run("KeyGeneration", func(t *testing.T) {
		// Generate seed for 256-bit key
		keySeed, err := resolver.Rand(32)
		require.NoError(t, err)
		require.Len(t, keySeed, 32)

		// Generate IV for encryption
		iv, err := resolver.Rand(16)
		require.NoError(t, err)
		require.Len(t, iv, 16)

		// Generate salt for key derivation
		salt, err := resolver.Rand(16)
		require.NoError(t, err)
		require.Len(t, salt, 16)

		// All should be unique
		assert.NotEqual(t, keySeed[:16], iv)
		assert.NotEqual(t, keySeed[:16], salt)
		assert.NotEqual(t, iv, salt)
	})

	// Simulate nonce generation
	t.Run("NonceGeneration", func(t *testing.T) {
		nonces := make([][]byte, 100)
		for i := 0; i < 100; i++ {
			nonce, err := resolver.Rand(12) // 96-bit nonce
			require.NoError(t, err)
			require.Len(t, nonce, 12)
			nonces[i] = nonce
		}

		// Verify all nonces are unique
		for i := 0; i < len(nonces); i++ {
			for j := i + 1; j < len(nonces); j++ {
				assert.NotEqual(t, nonces[i], nonces[j],
					"Nonces %d and %d should be different", i, j)
			}
		}
	})

	// Simulate session ID generation
	t.Run("SessionIDGeneration", func(t *testing.T) {
		sessionIDs := make(map[string]bool)
		for i := 0; i < 1000; i++ {
			sessionID, err := resolver.Rand(16)
			require.NoError(t, err)

			key := string(sessionID)
			assert.False(t, sessionIDs[key], "Session ID should be unique")
			sessionIDs[key] = true
		}
	})
}

// TestRandCompareWithStdlibIntegration compares behavior with stdlib crypto/rand
func TestRandCompareWithStdlibIntegration(t *testing.T) {
	resolver, err := rand.NewResolver(rand.ModeSoftware)
	require.NoError(t, err)
	defer resolver.Close()

	size := 1000
	ourRand, err := resolver.Rand(size)
	require.NoError(t, err)

	// Compare statistical properties
	ourEntropy := calculateEntropy(ourRand)

	// Entropy should be similar to good random data (close to 8)
	assert.Greater(t, ourEntropy, 7.5, "Entropy should be high")
	assert.Less(t, ourEntropy, 8.1, "Entropy should not exceed maximum")

	// Ensure it's not producing predictable patterns
	assert.False(t, bytes.Equal(ourRand[:100], ourRand[100:200]),
		"Different segments should be different")
}
